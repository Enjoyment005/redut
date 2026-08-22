# -*- coding: utf-8 -*-
"""Пул прокси: SQLite-кэш (схема §13), роли (§5), refresh с merge.

Ключ записи — uid = provider:ext_id (не IP: при продлении/замене IP меняется).
Пропавшие из выдачи провайдера записи помечаются gone=1, но НЕ удаляются:
при недоступности API работаем на кэше (§10), креды всех известных прокси локально.
Исключение (П7-2, 1.6.0): провайдер, у которого УДАЛИЛИ КЛЮЧ, выбывает целиком —
его строки удаляются из пула (см. purge_provider), потому что управлять ими больше
нечем, а «пропал» на весь кабинет захламлял панель навсегда (жалоба владельца 18.08).
Держится только строка боевого канала — до планового переключения (states.switch_
from_provider). gone=1 остаётся мягкой меткой для ЖИВОГО провайдера: его выдача
может мигнуть (пагинация, сбой на стороне API), и запись вернётся с ролью и историей.
Роль записи pool никогда не меняет сам — только владелец (исключение: успешный
apply переводит off->auto, иначе боевой канал невидим подсчёту резерва).

Ролей две (П9, 1.3.0): auto — распоряжается автоматика, off — не трогать
(бывшие chrome/reserve/vpn-* мигрируются, см. _migrate_roles_v2).
"""
import datetime
import json
import os
import shutil
import sqlite3

ROLES = ("auto", "off")

DEFAULT_ROLE = {"proxyline": "auto", "proxy6": "auto", "proxywing": "auto"}

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
    # Журнал замеров (E1, 1.3.0): record_probe ПЕРЕТИРАЕТ строку proxy, поэтому
    # «сколько раз падал за неделю» без этой таблицы спросить не у кого.
    # Фактическая (exit_cc) и паспортная (country) страны — раздельно, без подмен;
    # strategy — аудит-метка контекста записи (пробы от стратегии не зависят, П5).
    """CREATE TABLE IF NOT EXISTS probe_log(
        id INTEGER PRIMARY KEY,
        ts TEXT NOT NULL,
        uid TEXT NOT NULL,
        provider TEXT NOT NULL,
        exit_cc TEXT,
        country TEXT,
        geo_agree INTEGER,
        ok INTEGER NOT NULL,
        latency_ms INTEGER, tg_ok INTEGER,
        disq TEXT,
        is_current INTEGER NOT NULL DEFAULT 0,
        strategy TEXT NOT NULL
    )""",
    # Обучение стабильности (F8, П6): агрегат поверх probe_log + событий, retention
    # его НЕ трогает. Ключ — ПАСПОРТНАЯ страна покупки (bonus применяется к стране,
    # которую покупаем; агрегация по фактической при перепроданных диапазонах
    # разъехалась бы с ключом покупки). Фактическая страна и geo_agree остаются в
    # probe_log — это диагностика провайдера, не ключ.
    """CREATE TABLE IF NOT EXISTS stability(
        provider TEXT NOT NULL,
        country TEXT NOT NULL,
        probes_ok INTEGER NOT NULL DEFAULT 0,
        probes_fail INTEGER NOT NULL DEFAULT 0,
        battle_drops INTEGER NOT NULL DEFAULT 0,
        battle_seconds INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        PRIMARY KEY(provider, country)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_proxy_provider ON proxy(provider)",
    "CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts)",
    "CREATE INDEX IF NOT EXISTS idx_probe_log_ts ON probe_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_probe_log_pc ON probe_log(provider, country)",
]

# Retention (E1): сырьё probe_log — 90 дней; event — 180 (это и security-журнал:
# логины с src_ip, key-set/key-del — 180 дней аудита признаём достаточными, ревью);
# money НЕ трогаем — финансовая история вечная.
PROBE_LOG_KEEP_DAYS = 90
EVENT_KEEP_DAYS = 180

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


def migrate(conn, db_path=None):
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
    _migrate_roles_v2(conn, db_path)


_OLD_ROLES = ("chrome", "reserve", "vpn-ru", "vpn-node1", "vpn-node2")


def _migrate_roles_v2(conn, db_path):
    """П9: свести роли к двум — auto|off. Однократно, под маркером roles_v2
    (migrate() исполняется и панелью, и каждым тиком крона — скан не гоняем).

    chrome -> off  (смысл «прокси занят, автоматике не трогать» сохраняется);
    reserve / vpn-* -> auto (резерв и так брался из пула, привязка к серверу мертва).

    Перед UPDATE — снапшот state.db -> state.db.pre-roles-v2 силами самой миграции:
    путь самообновления бэкапит дерево и config.json, но НЕ state.db (update.py),
    а миграция необратима. Не вышло снять снапшот — миграцию откладываем до
    следующего коннекта (mixed-режим с ролью chrome в БД опаснее задержки).

    BEGIN IMMEDIATE (ревью 1.3.0): проверка маркера, снапшот и UPDATE — под одним
    писательским локом. Иначе два процесса (панель + тик крона) на первом коннекте
    к немигрированной базе могли снять снапшот параллельно с чужим UPDATE — копия
    захватила бы уже мигрированные роли. До первой записи файл на диске нетронут,
    поэтому copyfile под RESERVED-локом даёт честный до-миграционный слепок.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        return          # соседний процесс уже мигрирует — повторим при следующем коннекте
    try:
        if conn.execute("SELECT value FROM setting WHERE key='roles_v2'").fetchone():
            conn.execute("ROLLBACK")
            return
        qmarks = ",".join("?" * len(_OLD_ROLES))
        n_old = conn.execute("SELECT COUNT(*) FROM proxy WHERE role IN (%s)" % qmarks,
                             _OLD_ROLES).fetchone()[0]
        snap = ""
        if n_old and db_path and os.path.exists(db_path):
            dst = db_path + ".pre-roles-v2"
            if not os.path.exists(dst):
                try:
                    shutil.copyfile(db_path, dst)
                except OSError:
                    conn.execute("ROLLBACK")   # без снапшота не мигрируем
                    return
            snap = dst
        cur = conn.execute(
            "UPDATE proxy SET role=CASE WHEN role='chrome' THEN 'off' ELSE 'auto' END"
            " WHERE role IN (%s)" % qmarks, _OLD_ROLES)
        n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        if n:
            conn.execute(
                "INSERT INTO event(ts, server, actor, action, result, detail)"
                " VALUES(?,?,?,?,?,?)",
                (now_iso(), None, "auto", "role-migrate", "ok",
                 "роли v2 (П9): chrome->off, reserve/vpn-*->auto — %d строк%s"
                 % (n, ("; снапшот %s" % os.path.basename(snap)) if snap else "")))
        conn.execute("INSERT OR REPLACE INTO setting(key, value) VALUES('roles_v2', '1')")
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        raise


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
        migrate(self.conn, db_path)
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
    def refresh(self, providers, actor="user", active=None, keep_hosts=None):
        """Слить пул со всех провайдеров. Ошибка одного не роняет остальных.

        merge: новые — insert (роль по DEFAULT_ROLE), существующие — update
        только полей _REFRESH_FIELDS (роль/проба/счётчики нетронуты), пропавшие
        у УСПЕШНО опрошенного провайдера — gone=1. Провайдер с ошибкой
        не трогается вообще (работаем на кэше, §10).

        active (П7, 🔴 C2): множество провайдеров, у которых ЕСТЬ ключ на диске.
        Строки провайдеров вне этого множества УДАЛЯЮТСЯ из пула (П7-2, 1.6.0:
        без ключа их никто не опросит, не продлит и не проверит — раньше они
        помечались gone и висели в панели навсегда). Ориентир — именно ключи,
        а НЕ переданный словарь providers: refresh зовётся с подмножеством
        {"proxy6": …} после каждой покупки, и уборка «кого нет в словаре»
        похоронила бы весь пул второго провайдера. None — уборку не делать
        (subset-вызовы постпокупки). Ошибка list() уборку не включает: признак —
        состав ключей, не доступность API.

        keep_hosts (П7-2): хосты, которые удалять нельзя, — боевой канал. Его
        строка остаётся с gone=1 (панель видит, на чём сидит канал), пока
        плановое переключение не уведёт трафик к живому провайдеру.
        """
        summary = {"providers": {}, "errors": {}, "stale": {}}
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
        if active is not None:
            known = {r[0] for r in self.conn.execute("SELECT DISTINCT provider FROM proxy")}
            for name in sorted(known - set(active)):
                r = self.purge_provider(name, keep_hosts=keep_hosts)
                if r["deleted"]:
                    summary["stale"][name] = r["deleted"]
        self.conn.commit()
        self.log_event("pool-refresh", actor=actor,
                       result="ok" if not summary["errors"] else "partial",
                       detail=json.dumps(summary, ensure_ascii=False))
        return summary

    def purge_provider(self, name, keep_hosts=None):
        """П7-2 (1.6.0): провайдер без ключа выбывает целиком — его строки удаляются.

        Мягкая метка gone тут не годится: без ключа записи некому воскресить, и
        «пропал» висел в панели вечно (жалоба владельца 18.08). История замеров
        (probe_log), деньги (money) и обучение (stability) остаются — это журнал,
        а не пул; вернётся ключ — refresh вставит прокси заново.

        keep_hosts — хосты, которые удалять нельзя (боевой канал: правило «держать
        IP» на время манёвра). Такие строки помечаются gone=1 и живут до планового
        переключения (states.switch_from_provider), после которого их добьёт
        либо само переключение, либо следующий refresh.
        -> {"deleted": n, "kept": m}
        """
        keep = [h for h in (keep_hosts or ()) if h]
        if keep:
            qm = ",".join("?" * len(keep))
            cur = self.conn.execute(
                "DELETE FROM proxy WHERE provider=? AND host NOT IN (%s)" % qm,
                (name, *keep))
        else:
            cur = self.conn.execute("DELETE FROM proxy WHERE provider=?", (name,))
        deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        kept = 0
        if keep:
            qm = ",".join("?" * len(keep))
            cur = self.conn.execute(
                "UPDATE proxy SET gone=1 WHERE provider=? AND host IN (%s)" % qm,
                (name, *keep))
            kept = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        self.conn.commit()
        return {"deleted": deleted, "kept": kept}

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

    def candidates(self):
        """Кандидаты для probe/apply: не gone, роль не off (П9: ролей две — auto|off)."""
        rows = self.list(include_gone=False)
        return [r for r in rows if r["role"] != "off"]

    def record_probe(self, uid, res, is_current=False, strategy="", background=False):
        """Записать результат пробы (см. probe.probe): счётчик fail растёт при
        провале и сбрасывается при успехе. Плюс строка в probe_log (E1) —
        история замеров, которую перетирание строки proxy не убивает.

        background=True (F5, крон): провал засчитывается в fail_count только
        ВТОРЫМ подряд — одиночный сетевой чих ночью раньше накачивал счётчик
        всему пулу, а при fail_count>=3 любой провал в ротации давал сразу 2 ч
        cooldown -> «пул исчерпан» -> REPLENISH/EMERGENCY при живых прокси.
        Успешная проба заодно снимает активный cooldown (раньше снятие было
        только при успешной ротации)."""
        row = self.get(uid)
        if not row:
            return
        if res.get("ok"):
            fail_count = 0
        elif background and row.get("probe_ok") != 0:
            fail_count = int(row.get("fail_count") or 0)   # первый чих — не считаем
        else:
            fail_count = int(row.get("fail_count") or 0) + 1
        geo = (None if res.get("geo_agree") is None
               else (1 if res.get("geo_agree") else 0))
        self.conn.execute(
            "UPDATE proxy SET last_probe_at=?, probe_ok=?, socks_ok=?, http_ok=?, tg_ok=?,"
            " exit_ip=?, exit_cc=?, exit_cc_alt=?, geo_agree=?, latency_ms=?, score=?,"
            " fail_count=? WHERE uid=?",
            (now_iso(), 1 if res.get("ok") else 0,
             1 if res.get("socks_ok") else 0, 1 if res.get("http_ok") else 0,
             1 if res.get("tg_ok") else 0,
             res.get("exit_ip"), res.get("exit_cc"), res.get("exit_cc_alt"),
             geo, res.get("latency_ms"), res.get("score"), fail_count, uid))
        if res.get("ok"):
            # F5: живой прокси не должен досиживать старый cooldown
            self.conn.execute("UPDATE proxy SET cooldown_until=NULL WHERE uid=?", (uid,))
        self.conn.execute(
            "INSERT INTO probe_log(ts, uid, provider, exit_cc, country, geo_agree, ok,"
            " latency_ms, tg_ok, disq, is_current, strategy)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), uid, row["provider"], res.get("exit_cc"), row.get("country"),
             geo, 1 if res.get("ok") else 0, res.get("latency_ms"),
             1 if res.get("tg_ok") else 0, res.get("disqualified"),
             1 if is_current else 0, strategy or ""))
        self.conn.commit()
        # F8: счётчики обучения — по ПАСПОРТНОЙ стране (ключ покупки)
        self.stability_bump_probe(row["provider"], row.get("country"), res.get("ok"))

    def prune(self, now=None):
        """Retention (E1): probe_log > 90 дн и event > 180 дн — DELETE; money вечно.

        Не чаще раза в сутки (отметка prune_last в setting) — зовётся из цикла
        `pool-refresh --probe`, чтобы не дёргать DELETE каждый прогон.
        -> {'probe_log': n, 'event': m} или None, если сегодня уже чистили."""
        now = now or datetime.datetime.now()
        day = now.strftime("%Y-%m-%d")
        if self.get_setting("prune_last") == day:
            return None
        cut_p = (now - datetime.timedelta(days=PROBE_LOG_KEEP_DAYS)
                 ).replace(microsecond=0).isoformat(sep=" ")
        cut_e = (now - datetime.timedelta(days=EVENT_KEEP_DAYS)
                 ).replace(microsecond=0).isoformat(sep=" ")
        a = self.conn.execute("DELETE FROM probe_log WHERE ts < ?", (cut_p,)).rowcount
        b = self.conn.execute("DELETE FROM event WHERE ts < ?", (cut_e,)).rowcount
        self.set_setting("prune_last", day)      # заодно коммитит DELETE'ы
        return {"probe_log": a if a and a > 0 else 0, "event": b if b and b > 0 else 0}

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

    # ---------- обучение стабильности (F8, П6) ----------
    def _stability_bump(self, provider, country, ok=0, fail=0, drops=0, seconds=0):
        """Одно приращение агрегата пары (provider, паспортная страна)."""
        c = (str(country or "").strip().lower())
        if not provider or not c:
            return          # без паспортной страны ключа нет — не пишем
        now = now_iso()
        self.conn.execute(
            "INSERT INTO stability(provider, country, probes_ok, probes_fail,"
            " battle_drops, battle_seconds, first_seen, last_seen)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(provider, country) DO UPDATE SET"
            " probes_ok=probes_ok+excluded.probes_ok,"
            " probes_fail=probes_fail+excluded.probes_fail,"
            " battle_drops=battle_drops+excluded.battle_drops,"
            " battle_seconds=battle_seconds+excluded.battle_seconds,"
            " last_seen=excluded.last_seen",
            (provider, c, int(ok), int(fail), int(drops), int(seconds), now, now))
        self.conn.commit()

    def stability_bump_probe(self, provider, country, ok):
        self._stability_bump(provider, country, ok=1 if ok else 0, fail=0 if ok else 1)

    def stability_bump_drop(self, provider, country):
        """Боевой канал пары оборвался (ротация по proxy_fault/watchdog)."""
        self._stability_bump(provider, country, drops=1)

    def stability_bump_battle(self, provider, country, seconds):
        """Приращение времени «в бою» (источник — egress-mark, cap у вызывающего)."""
        if seconds and seconds > 0:
            self._stability_bump(provider, country, seconds=int(seconds))

    def stability_get(self, provider, country):
        c = (str(country or "").strip().lower())
        row = self.conn.execute(
            "SELECT * FROM stability WHERE provider=? AND country=?",
            (provider, c)).fetchone()
        return dict(row) if row else None

    def stability_all(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM stability ORDER BY provider, country").fetchall()]

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

    def reserve_count(self, current_host=None, now=None):
        """Сколько тёплых резервов (§6.5 N+1): проба ок, не текущий, не на cooldown."""
        now = now or now_iso()
        n = 0
        for r in self.rotation_candidates(exclude_host=current_host, now=now):
            if r.get("probe_ok") and r.get("score") is not None:
                n += 1
        return n

    def rotation_candidates(self, exclude_host=None, now=None):
        """Кандидаты для ROTATING: как candidates(), но БЕЗ тех, кто на cooldown,
        и без текущего (мёртвого) upstream. Порядок score сохраняется."""
        now = now or now_iso()
        out = []
        for r in self.candidates():
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
