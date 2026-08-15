# -*- coding: utf-8 -*-
"""Пул прокси: SQLite-кэш (схема §13), роли (§5), refresh с merge.

Ключ записи — uid = provider:ext_id (не IP: при продлении/замене IP меняется).
Пропавшие из выдачи провайдера записи помечаются gone=1, но НЕ удаляются:
при недоступности API работаем на кэше (§10), креды всех известных прокси локально.
Роль записи pool никогда не меняет сам — только владелец (роль chrome защищена).
"""
import datetime
import json
import os
import sqlite3

ROLES = ("auto", "chrome", "vpn-ru", "vpn-node1", "reserve", "off")

# ProxyLine — статический резерв (§5: «сюда кладём ProxyLine»), PROXY6 — авто-пул.
DEFAULT_ROLE = {"proxyline": "reserve", "proxy6": "auto"}

# Схема §13. money в фазе 1 только создаётся (записи — фаза 2).
# session — таблица панели (фаза 4), здесь не нужна.
_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS proxy(
        uid TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        ext_id TEXT NOT NULL,
        ip TEXT, host TEXT,
        port_http INTEGER, port_socks5 INTEGER,
        user TEXT, password TEXT,
        country TEXT, ip_version INTEGER,
        kind TEXT, date_end TEXT, descr TEXT,
        role TEXT NOT NULL DEFAULT 'auto',
        note TEXT DEFAULT '',
        gone INTEGER NOT NULL DEFAULT 0,
        last_probe_at TEXT,
        probe_ok INTEGER, socks_ok INTEGER, http_ok INTEGER, tg_ok INTEGER,
        exit_ip TEXT, exit_cc TEXT,
        latency_ms INTEGER, score REAL,
        fail_count INTEGER NOT NULL DEFAULT 0,
        cooldown_until TEXT, last_used_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS event(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        server TEXT, actor TEXT,
        action TEXT NOT NULL,
        from_uid TEXT, to_uid TEXT,
        result TEXT, detail TEXT, src_ip TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS money(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        provider TEXT, op TEXT,
        uid TEXT, price REAL, currency TEXT,
        balance_after TEXT, order_id TEXT, descr TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS setting(
        key TEXT PRIMARY KEY,
        value TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_proxy_provider ON proxy(provider)",
    "CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts)",
]

SCHEMA_VERSION = "1"

# Поля, которые обновляет refresh (остальные — роль/проба/счётчики — сохраняются)
_REFRESH_FIELDS = ("ip", "host", "port_http", "port_socks5", "user", "password",
                   "country", "ip_version", "kind", "date_end", "descr")


def now_iso():
    return datetime.datetime.now().replace(microsecond=0).isoformat(sep=" ")


# Колонки, добавленные после первого релиза. CREATE TABLE IF NOT EXISTS их в живую
# базу не принесёт, поэтому досыпаем ALTER'ом (сверяясь с pragma — идемпотентно).
_ADD_COLUMNS = (
    ("proxy", "exit_cc_alt", "TEXT"),     # страна по второй geoip-базе (2026-08-15)
    ("proxy", "geo_agree", "INTEGER"),    # 1 — базы сошлись, 0 — разошлись
)


def migrate(conn):
    """Идемпотентная миграция: повторный вызов ничего не ломает и не теряет."""
    for stmt in _SCHEMA:
        conn.execute(stmt)
    for table, col, typ in _ADD_COLUMNS:
        have = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
        if col not in have:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
    conn.execute("INSERT OR IGNORE INTO setting(key, value) VALUES('schema_version', ?)",
                 (SCHEMA_VERSION,))
    conn.commit()


class Pool:
    def __init__(self, db_path, server="dev"):
        self.db_path = db_path
        self.server = server
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        existed = os.path.exists(db_path)
        # check_same_thread=False: веб-панель обрабатывает запросы в потоках
        # ThreadingHTTPServer; доступ к conn там сериализуется общим локом.
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # Панель (сервис) и агент (cron/сторож/кнопка) держат БД одновременно —
        # busy_timeout гасит краткие «database is locked» при кросс-процессном доступе.
        self.conn.execute("PRAGMA busy_timeout=5000")
        migrate(self.conn)
        if not existed:
            try:
                os.chmod(db_path, 0o600)  # §13: state.db 0600 (на Windows — no-op)
            except OSError:
                pass

    def close(self):
        self.conn.close()

    # ---------- события ----------
    def log_event(self, action, actor="user", from_uid=None, to_uid=None,
                  result="", detail="", src_ip=""):
        self.conn.execute(
            "INSERT INTO event(ts, server, actor, action, from_uid, to_uid, result, detail, src_ip)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (now_iso(), self.server, actor, action, from_uid, to_uid, result, detail, src_ip))
        self.conn.commit()

    # ---------- пул ----------
    def refresh(self, providers, actor="user"):
        """Слить пул со всех провайдеров. Ошибка одного не роняет остальных.

        merge: новые — insert (роль по DEFAULT_ROLE), существующие — update
        только полей _REFRESH_FIELDS (роль/проба/счётчики нетронуты), пропавшие
        у УСПЕШНО опрошенного провайдера — gone=1. Провайдер с ошибкой
        не трогается вообще (работаем на кэше, §10).
        """
        summary = {"providers": {}, "errors": {}}
        for name, prov in providers.items():
            try:
                items = prov.list()
            except Exception as e:
                summary["errors"][name] = str(e)
                continue
            seen = []
            added = updated = 0
            for it in items:
                uid = "%s:%s" % (it["provider"], it["ext_id"])
                seen.append(uid)
                row = self.conn.execute("SELECT uid FROM proxy WHERE uid=?", (uid,)).fetchone()
                if row:
                    sets = ", ".join("%s=?" % f for f in _REFRESH_FIELDS)
                    self.conn.execute(
                        "UPDATE proxy SET %s, gone=0 WHERE uid=?" % sets,
                        tuple(it.get(f) for f in _REFRESH_FIELDS) + (uid,))
                    updated += 1
                else:
                    self.conn.execute(
                        "INSERT INTO proxy(uid, provider, ext_id, %s, role, gone)"
                        " VALUES(%s)" % (", ".join(_REFRESH_FIELDS),
                                         ",".join("?" * (3 + len(_REFRESH_FIELDS) + 2))),
                        (uid, it["provider"], it["ext_id"])
                        + tuple(it.get(f) for f in _REFRESH_FIELDS)
                        + (DEFAULT_ROLE.get(name, "auto"), 0))
                    added += 1
            # пропавшие: только у этого провайдера, только при успешном list()
            qmarks = ",".join("?" * len(seen)) or "''"
            cur = self.conn.execute(
                "UPDATE proxy SET gone=1 WHERE provider=? AND uid NOT IN (%s)" % qmarks,
                (name, *seen))
            summary["providers"][name] = {
                "total": len(items), "added": added, "updated": updated,
                "gone": cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0,
            }
        self.conn.commit()
        self.log_event("pool-refresh", actor=actor,
                       result="ok" if not summary["errors"] else "partial",
                       detail=json.dumps(summary, ensure_ascii=False))
        return summary

    def list(self, include_gone=False, include_off=True):
        q = "SELECT * FROM proxy"
        cond = []
        if not include_gone:
            cond.append("gone=0")
        if not include_off:
            cond.append("role != 'off'")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY (score IS NULL), score DESC, uid"
        return [dict(r) for r in self.conn.execute(q).fetchall()]

    def get(self, uid):
        row = self.conn.execute("SELECT * FROM proxy WHERE uid=?", (uid,)).fetchone()
        return dict(row) if row else None

    def set_role(self, uid, role):
        if role not in ROLES:
            raise ValueError("Неизвестная роль %r, допустимо: %s" % (role, "|".join(ROLES)))
        self.conn.execute("UPDATE proxy SET role=? WHERE uid=?", (role, uid))
        self.conn.commit()

    def candidates(self, server_role=None):
        """Кандидаты для probe/apply: не gone, роль не off/chrome
        (chrome занят расширением владельца — автоматика его не трогает, §5)."""
        rows = self.list(include_gone=False)
        out = [r for r in rows if r["role"] not in ("off", "chrome")]
        if server_role:
            pinned = [r for r in out if r["role"] == server_role]
            rest = [r for r in out if r["role"] != server_role]
            out = pinned + rest
        return out

    def record_probe(self, uid, res):
        """Записать результат пробы (см. probe.probe): счётчик fail растёт при
        провале и сбрасывается при успехе."""
        row = self.get(uid)
        if not row:
            return
        fail_count = 0 if res.get("ok") else int(row.get("fail_count") or 0) + 1
        self.conn.execute(
            "UPDATE proxy SET last_probe_at=?, probe_ok=?, socks_ok=?, http_ok=?, tg_ok=?,"
            " exit_ip=?, exit_cc=?, exit_cc_alt=?, geo_agree=?, latency_ms=?, score=?,"
            " fail_count=? WHERE uid=?",
            (now_iso(), 1 if res.get("ok") else 0,
             1 if res.get("socks_ok") else 0, 1 if res.get("http_ok") else 0,
             1 if res.get("tg_ok") else 0,
             res.get("exit_ip"), res.get("exit_cc"), res.get("exit_cc_alt"),
             None if res.get("geo_agree") is None else (1 if res.get("geo_agree") else 0),
             res.get("latency_ms"), res.get("score"), fail_count, uid))
        self.conn.commit()

    def mark_used(self, uid):
        self.conn.execute("UPDATE proxy SET last_used_at=? WHERE uid=?", (now_iso(), uid))
        self.conn.commit()

    def upsert_proxy(self, norm, role=None):
        """Вставить/обновить один нормализованный прокси (после buy, до pool-refresh).

        Роль ставится только при INSERT (или если задана явно) — у существующей
        записи роль/проба/счётчики не трогаются (как в refresh)."""
        uid = "%s:%s" % (norm["provider"], norm["ext_id"])
        row = self.conn.execute("SELECT uid FROM proxy WHERE uid=?", (uid,)).fetchone()
        if row:
            sets = ", ".join("%s=?" % f for f in _REFRESH_FIELDS)
            self.conn.execute("UPDATE proxy SET %s, gone=0 WHERE uid=?" % sets,
                              tuple(norm.get(f) for f in _REFRESH_FIELDS) + (uid,))
            if role:
                self.conn.execute("UPDATE proxy SET role=? WHERE uid=?", (role, uid))
        else:
            r = role or DEFAULT_ROLE.get(norm["provider"], "auto")
            self.conn.execute(
                "INSERT INTO proxy(uid, provider, ext_id, %s, role, gone) VALUES(%s)"
                % (", ".join(_REFRESH_FIELDS), ",".join("?" * (3 + len(_REFRESH_FIELDS) + 2))),
                (uid, norm["provider"], norm["ext_id"])
                + tuple(norm.get(f) for f in _REFRESH_FIELDS) + (r, 0))
        self.conn.commit()
        return uid

    def set_date_end(self, uid, date_end):
        if date_end:
            self.conn.execute("UPDATE proxy SET date_end=? WHERE uid=?", (date_end, uid))
            self.conn.commit()

    # ---------- деньги (§13: отдельная таблица money) ----------
    def record_money(self, provider, op, uid, price, currency,
                     balance_after=None, order_id=None, descr=None):
        """Одна трата -> таблица money (§6.2/§13): buy|prolong|delete."""
        self.conn.execute(
            "INSERT INTO money(ts, provider, op, uid, price, currency, balance_after, order_id, descr)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (now_iso(), provider, op, uid, price, currency,
             None if balance_after is None else str(balance_after),
             None if order_id is None else str(order_id), descr))
        self.conn.commit()

    def buys_today(self, day=None):
        """Сколько ПОКУПОК (op=buy) за сегодня — для лимита ≤3/сутки (§6.2).
        Считается по локальной БД сервера (см. оговорку о глобальности в money.py)."""
        day = day or datetime.date.today().isoformat()
        return self.conn.execute(
            "SELECT COUNT(*) FROM money WHERE op='buy' AND ts LIKE ?", (day + "%",)).fetchone()[0]

    def spent_today(self, currency, day=None):
        """Сумма трат (buy+prolong) за сегодня в валюте — для лимита ≤N/сутки (§6.2)."""
        day = day or datetime.date.today().isoformat()
        v = self.conn.execute(
            "SELECT COALESCE(SUM(price),0) FROM money"
            " WHERE op IN ('buy','prolong') AND currency=? AND ts LIKE ?",
            (currency, day + "%")).fetchone()[0]
        return float(v or 0.0)

    # ---------- настройки автомата (§8) ----------
    def get_setting(self, key, default=None):
        row = self.conn.execute("SELECT value FROM setting WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key, value):
        self.conn.execute("INSERT OR REPLACE INTO setting(key, value) VALUES(?, ?)",
                          (key, None if value is None else str(value)))
        self.conn.commit()

    def prolonged_today(self, uid):
        """Продлевали ли этот прокси сегодня — защита от повторов автопродления.

        Крон может сработать дважды (ручной запуск + расписание), а деньги списываются
        каждый раз: без этой проверки один и тот же якорь продлевался бы по кругу.
        """
        day = datetime.datetime.now().strftime("%Y-%m-%d")
        row = self.conn.execute(
            "SELECT 1 FROM money WHERE op='prolong' AND uid=? AND ts LIKE ? LIMIT 1",
            (uid, day + "%")).fetchone()
        return bool(row)

    # ---------- последняя проба выхода (для дашборда) ----------
    def set_egress(self, v):
        """Запомнить результат `apply.verify_egress()`.

        Проба живая и небыстрая (curl через tun0), поэтому дашборд её сам не делает —
        он показывает последний известный результат. Пишут сюда все, кто пробу и так
        выполняет: панель (кнопка «Проверить выход», apply, rollback) и агент (§8).
        """
        if not v:
            return
        self.set_setting("egress_ip", v.get("egress_ip") or "")
        self.set_setting("egress_cc", v.get("exit_cc") or "")
        self.set_setting("egress_ok", "1" if v.get("ok") else "0")
        self.set_setting("egress_tg", v.get("tg_code") if v.get("tg_code") is not None else "")
        self.set_setting("egress_why", v.get("why") or "")
        self.set_setting("egress_at", now_iso())

    def get_egress(self):
        """Последняя известная проба выхода или None, если её ещё не делали."""
        ip = self.get_setting("egress_ip")
        at = self.get_setting("egress_at")
        if not at:
            return None
        try:    # возраст считаем здесь: у сервера и браузера могут быть разные часовые пояса
            age = int((datetime.datetime.now() - datetime.datetime.fromisoformat(at)).total_seconds())
        except (ValueError, TypeError):
            age = None
        return {"egress": ip or None, "egress_cc": self.get_setting("egress_cc") or None,
                "egress_ok": self.get_setting("egress_ok") == "1",
                "egress_tg": self.get_setting("egress_tg") or None,
                "egress_why": self.get_setting("egress_why") or "",
                "egress_at": at, "egress_age": age}

    # ---------- пульс агента (§6.3) ----------
    def heartbeat(self, ts=None):
        """Отметить успешный цикл агента (healthcheck пульса §6.3)."""
        self.set_setting("agent_heartbeat", ts or now_iso())

    def last_heartbeat(self):
        return self.get_setting("agent_heartbeat")

    # ---------- cooldown провалившегося прокси (§8: 10м→30м→2ч) ----------
    def set_cooldown(self, uid, seconds):
        until = (datetime.datetime.now() + datetime.timedelta(seconds=int(seconds))
                 ).replace(microsecond=0).isoformat(sep=" ")
        self.conn.execute("UPDATE proxy SET cooldown_until=? WHERE uid=?", (until, uid))
        self.conn.commit()
        return until

    def clear_cooldown(self, uid):
        self.conn.execute("UPDATE proxy SET cooldown_until=NULL WHERE uid=?", (uid,))
        self.conn.commit()

    def bump_fail(self, uid):
        """Увеличить счётчик провалов (для apply-провала: проба прошла, но кандидат
        мёртв через tun0 — record_probe его не считает). -> новый fail_count."""
        self.conn.execute("UPDATE proxy SET fail_count=COALESCE(fail_count,0)+1 WHERE uid=?", (uid,))
        self.conn.commit()
        row = self.conn.execute("SELECT fail_count FROM proxy WHERE uid=?", (uid,)).fetchone()
        return int(row[0]) if row else 0

    def reserve_count(self, server_role=None, current_host=None, now=None):
        """Сколько тёплых резервов (§6.5 N+1): проба ок, не текущий, не на cooldown."""
        now = now or now_iso()
        n = 0
        for r in self.rotation_candidates(server_role, exclude_host=current_host, now=now):
            if r.get("probe_ok") and r.get("score") is not None:
                n += 1
        return n

    def rotation_candidates(self, server_role=None, exclude_host=None, now=None):
        """Кандидаты для ROTATING: как candidates(), но БЕЗ тех, кто на cooldown,
        и без текущего (мёртвого) upstream. Порядок score сохраняется."""
        now = now or now_iso()
        out = []
        for r in self.candidates(server_role):
            cu = r.get("cooldown_until")
            if cu and str(cu) > now:      # ISO-строки одного формата сравнимы лексикографически
                continue
            if exclude_host and r["host"] == exclude_host:
                continue
            out.append(r)
        return out

    def rotations_last_hour(self, actions=("rotate", "replenish")):
        """Сколько успешных авто-замен за последний час — лимит ≤3/час (§8)."""
        cutoff = (datetime.datetime.now() - datetime.timedelta(hours=1)
                  ).replace(microsecond=0).isoformat(sep=" ")
        qmarks = ",".join("?" * len(actions))
        return self.conn.execute(
            "SELECT COUNT(*) FROM event WHERE actor='auto' AND result='ok'"
            " AND ts>=? AND action IN (%s)" % qmarks,
            (cutoff, *actions)).fetchone()[0]
