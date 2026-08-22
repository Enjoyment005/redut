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
import math
import os
import shutil
import sqlite3
import random
import re
import threading
import time
import uuid

ROLES = ("auto", "off")

OPERATION_PHASES = (
    "planned", "probing", "staged", "applied", "verifying",
    "committed", "rolled_back", "failed",
)
OPERATION_TERMINAL_PHASES = ("committed", "rolled_back", "failed")
_OPERATION_TRANSITIONS = {
    "planned": {"probing", "staged", "failed"},
    "probing": {"staged", "failed"},
    "staged": {"applied", "rolled_back", "failed"},
    "applied": {"verifying", "rolled_back", "failed"},
    "verifying": {"committed", "rolled_back", "failed"},
    "committed": set(),
    "rolled_back": set(),
    "failed": set(),
}

DEFAULT_ROLE = {"proxyline": "auto", "proxy6": "auto", "proxywing": "auto"}
DECISION_ACTIONS = frozenset({
    "strategy-apply", "rotate", "replenish", "retune", "provider-switch",
    "switch-provider", "emergency", "panel-emergency", "panel-rotate",
    "selection-reconcile", "selection-mode", "manual-failover", "explicit-apply",
    "health-quorum", "suspect", "rotating", "degraded", "frozen_net", "self-heal",
    "buy-postcheck", "auto-prolong",
    "proxy-fault",
})


class PoolDBError(Exception):
    """Классифицированная ошибка state.db."""


class PoolBusy(PoolDBError):
    pass


class PoolCorrupt(PoolDBError):
    pass


class PoolStorageError(PoolDBError):
    pass


def classify_db_error(error):
    code = getattr(error, "sqlite_errorcode", None)
    base = (code & 0xff) if isinstance(code, int) else None
    text = str(error).lower()
    if base in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or "locked" in text:
        return PoolBusy(str(error))
    if (base in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)
            or "malformed" in text or "not a database" in text):
        return PoolCorrupt(str(error))
    if (base in (sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_READONLY,
                 sqlite3.SQLITE_CANTOPEN)
            or "disk is full" in text or "readonly database" in text
            or "disk i/o error" in text or "unable to open database file" in text):
        return PoolStorageError(str(error))
    return PoolDBError(str(error))

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
        exit_ip TEXT, exit_cc TEXT, asn TEXT,
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
        result TEXT, detail TEXT, src_ip TEXT,
        payload_json TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS money(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        provider TEXT, op TEXT,
        uid TEXT, price REAL, currency TEXT,
        balance_after TEXT, order_id TEXT, descr TEXT
    )""",
    # Денежная сага: intent фиксируется ДО необратимого вызова провайдера.
    # submitted не повторяется вслепую после kill/reboot — следующий процесс
    # сначала подтверждает результат read-only запросом и лишь затем коммитит ledger.
    """CREATE TABLE IF NOT EXISTS spend_operation(
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        provider TEXT NOT NULL,
        uid TEXT,
        descr TEXT,
        phase TEXT NOT NULL,
        request_json TEXT NOT NULL,
        quote_price REAL NOT NULL,
        currency TEXT NOT NULL,
        balance_before TEXT,
        idempotency_key TEXT NOT NULL UNIQUE,
        requested_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT,
        error TEXT,
        result_json TEXT
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
    # Learning v2: дневные затухающие buckets. Старый stability остаётся как
    # миграционный/аудитный агрегат и продолжает заполняться параллельно.
    """CREATE TABLE IF NOT EXISTS learning_bucket(
        day TEXT NOT NULL,
        level TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        family TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        uid TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        probes_ok INTEGER NOT NULL DEFAULT 0,
        probes_fail INTEGER NOT NULL DEFAULT 0,
        tg_ok INTEGER NOT NULL DEFAULT 0,
        tg_fail INTEGER NOT NULL DEFAULT 0,
        geo_ok INTEGER NOT NULL DEFAULT 0,
        geo_fail INTEGER NOT NULL DEFAULT 0,
        latency_sum REAL NOT NULL DEFAULT 0,
        latency_count INTEGER NOT NULL DEFAULT 0,
        battle_drops INTEGER NOT NULL DEFAULT 0,
        battle_seconds INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(day, level, provider, family, country, uid, asn)
    )""",
    """CREATE TABLE IF NOT EXISTS shadow_decision(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        server TEXT,
        formula_version TEXT NOT NULL,
        mode TEXT NOT NULL,
        strategy TEXT NOT NULL DEFAULT '',
        current_uid TEXT,
        recommended_uid TEXT,
        candidate_count INTEGER NOT NULL DEFAULT 0,
        scores_json TEXT NOT NULL,
        context TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS exploration_decision(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        server TEXT,
        selected_uid TEXT,
        eligible_count INTEGER NOT NULL DEFAULT 0,
        result TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL DEFAULT ''
    )""",
    # P0 reliability: восстанавливаемый журнал действий, пересекающих границы
    # SQLite/config.json/sing-box/маршрутов. desired_state хранится каноническим
    # JSON, чтобы один idempotency_key нельзя было незаметно переиспользовать для
    # другого намерения.
    """CREATE TABLE IF NOT EXISTS operation(
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        desired_state TEXT NOT NULL,
        phase TEXT NOT NULL,
        from_uid TEXT, to_uid TEXT,
        before_checksum TEXT, after_checksum TEXT,
        requested_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT,
        error TEXT,
        idempotency_key TEXT NOT NULL UNIQUE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_proxy_provider ON proxy(provider)",
    "CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts)",
    "CREATE INDEX IF NOT EXISTS idx_probe_log_ts ON probe_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_learning_bucket_day ON learning_bucket(day)",
    "CREATE INDEX IF NOT EXISTS idx_shadow_decision_ts ON shadow_decision(ts)",
    "CREATE INDEX IF NOT EXISTS idx_exploration_decision_ts ON exploration_decision(ts)",
    "CREATE INDEX IF NOT EXISTS idx_probe_log_pc ON probe_log(provider, country)",
    "CREATE INDEX IF NOT EXISTS idx_operation_phase ON operation(phase, updated_at)",
    "CREATE INDEX IF NOT EXISTS idx_spend_operation_phase"
    " ON spend_operation(phase, updated_at)",
]

# Retention (E1): сырьё probe_log — 90 дней; event — 180 (это и security-журнал:
# логины с src_ip, key-set/key-del — 180 дней аудита признаём достаточными, ревью);
# money НЕ трогаем — финансовая история вечная.
PROBE_LOG_KEEP_DAYS = 90
EVENT_KEEP_DAYS = 180

SCHEMA_VERSION = "6"

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
    ("proxy", "asn", "TEXT"),             # learning v2: ASN exit-IP
    ("event", "payload_json", "TEXT"),    # structured decision diagnostics
    ("spend_operation", "result_json", "TEXT"),  # replay after commit-before-return kill
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
    # Версия монотонна: старый бинарник не должен маскировать будущую схему,
    # понижая 999 до своей 2. Некорректный маркер тоже не переписываем молча.
    conn.execute(
        "UPDATE setting SET value=? WHERE key='schema_version'"
        " AND value<>'' AND value NOT GLOB '*[^0-9]*'"
        " AND CAST(value AS INTEGER) < ?",
        (SCHEMA_VERSION, int(SCHEMA_VERSION)))
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
            old_rows = conn.execute(
                "SELECT uid,role FROM proxy WHERE role IN (%s) ORDER BY uid" % qmarks,
                _OLD_ROLES).fetchall()
            snapshot_valid = False
            if os.path.exists(dst):
                check = None
                try:
                    check = sqlite3.connect("file:%s?mode=ro" % dst.replace("\\", "/"),
                                            uri=True)
                    healthy = check.execute("PRAGMA quick_check").fetchone()[0] == "ok"
                    saved = check.execute(
                        "SELECT uid,role FROM proxy WHERE role IN (%s) ORDER BY uid" % qmarks,
                        _OLD_ROLES).fetchall()
                    snapshot_valid = healthy and saved == [(r["uid"], r["role"])
                                                           for r in old_rows]
                except sqlite3.Error:
                    snapshot_valid = False
                finally:
                    if check is not None:
                        check.close()
            if not snapshot_valid:
                tmp = None
                try:
                    # copyfile(main) теряет committed страницы из активного WAL.
                    # serialize() снимает согласованный образ этой connection под
                    # уже удерживаемым BEGIN IMMEDIATE до необратимого UPDATE.
                    image = conn.serialize()
                    tmp = dst + ".tmp-%s" % uuid.uuid4().hex
                    with open(tmp, "wb") as f:
                        f.write(image)
                        f.flush()
                        os.fsync(f.fileno())
                    try:
                        os.chmod(tmp, 0o600)
                    except OSError:
                        pass
                    os.replace(tmp, dst)
                    tmp = None
                    try:
                        os.chmod(dst, 0o600)
                    except OSError:
                        pass
                except OSError:
                    conn.execute("ROLLBACK")   # без снапшота не мигрируем
                    return
                finally:
                    if tmp:
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass
            else:
                try:
                    os.chmod(dst, 0o600)
                except OSError:
                    pass
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
        self._tx_lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        existed = os.path.exists(db_path)
        # check_same_thread=False: веб-панель обрабатывает запросы в потоках
        # ThreadingHTTPServer; доступ к conn там сериализуется общим локом.
        try:
            self.conn = sqlite3.connect(db_path, timeout=5.0, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            # Панель (сервис) и агент (cron/сторож/кнопка) держат БД одновременно —
            # busy_timeout гасит краткие «database is locked» при кросс-процессном доступе.
            self.conn.execute("PRAGMA busy_timeout=5000")
            migrate(self.conn, db_path)
            # Несколько процессов читают state.db постоянно. WAL не блокирует читателей
            # писателем; FULL подтверждает durable commit до возврата вызывающему.
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
            self.conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as e:
            if hasattr(self, "conn"):
                self.conn.close()
            raise classify_db_error(e) from e
        except BaseException:
            if hasattr(self, "conn"):
                self.conn.close()
            raise
        if not existed:
            try:
                os.chmod(db_path, 0o600)  # §13: state.db 0600 (на Windows — no-op)
            except OSError:
                pass

    def close(self):
        self.conn.close()

    def run_transaction(self, callback, immediate=True, attempts=6):
        """Выполнить только DB-callback атомарно; busy повторяется с jitter."""
        with self._tx_lock:
            if self.conn.in_transaction:
                raise PoolDBError("run_transaction нельзя вкладывать в активную транзакцию")
            tries = max(1, int(attempts or 1))
            for attempt in range(tries):
                try:
                    self.conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                    result = callback(self.conn)
                    self.conn.commit()
                    return result
                except sqlite3.Error as e:
                    try:
                        self.conn.rollback()
                    except sqlite3.Error:
                        pass
                    classified = classify_db_error(e)
                    if isinstance(classified, PoolBusy) and attempt + 1 < tries:
                        time.sleep(min(0.25, 0.01 * (2 ** attempt)) + random.uniform(0, 0.01))
                        continue
                    raise classified from e
                except BaseException:
                    try:
                        self.conn.rollback()
                    except sqlite3.Error:
                        pass
                    raise

    # ---------- события ----------
    @staticmethod
    def _json_safe(value):
        if isinstance(value, dict):
            return {str(key): Pool._json_safe(child) for key, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [Pool._json_safe(child) for child in value]
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        return str(value)

    def log_event(self, action, actor="user", from_uid=None, to_uid=None,
                  result="", detail="", src_ip="", payload=None):
        if payload is None and action in DECISION_ACTIONS:
            payload = {"strategy": "", "mode": "", "score_breakdown": [],
                       "freshness": {}, "margin": None, "exclusions": [],
                       "reason": detail or result or action}
        payload_json = (json.dumps(self._json_safe(payload), ensure_ascii=False,
                                   sort_keys=True, separators=(",", ":"), allow_nan=False)
                        if payload is not None else None)
        def write(conn):
            conn.execute(
                "INSERT INTO event(ts, server, actor, action, from_uid, to_uid, result, detail,"
                " src_ip,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (now_iso(), self.server, actor, action, from_uid, to_uid, result, detail,
                 src_ip, payload_json))
        self.run_transaction(write)

    def events(self, limit=100):
        with self._tx_lock:
            rows = self.conn.execute(
                "SELECT * FROM event ORDER BY id DESC LIMIT ?",
                (max(1, min(10000, int(limit))),)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            raw_payload = item.pop("payload_json", None)
            try:
                item["decision"] = (json.loads(
                    raw_payload,
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError("невалидная JSON-константа: %s" % value)))
                    if raw_payload else None)
            except (TypeError, ValueError, RecursionError):
                item["decision"] = None
            out.append(item)
        return out

    def observe_provider_errors(self, providers, actor="auto"):
        """Bind typed, secret-free provider failures to this pool's local audit log."""
        def observer(provider, operation, error):
            kind = getattr(getattr(error, "kind", None), "value",
                           getattr(error, "kind", None)) or "unknown"
            retry_after = getattr(error, "retry_after", None)
            payload = {"provider": str(provider or "")[:64],
                       "operation": str(operation or "")[:96],
                       "kind": str(kind)[:32],
                       "retry_after": retry_after}
            self.log_event("provider-api", actor=actor, result=str(kind)[:32],
                           detail=json.dumps(self._json_safe(payload), ensure_ascii=False,
                                             sort_keys=True, allow_nan=False))
        for provider in (providers or {}).values():
            setter = getattr(provider, "set_error_observer", None)
            if callable(setter):
                setter(observer)
        return providers

    # ---------- журнал operation saga ----------
    @staticmethod
    def _operation_dict(row):
        if row is None:
            return None
        out = dict(row)
        try:
            out["desired_state"] = json.loads(
                out["desired_state"],
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("невалидная JSON-константа: %s" % value)))
        except (TypeError, ValueError):
            # Повреждённая БД не должна скрывать строку от recovery/диагностики.
            out["desired_state_invalid"] = True
        return out

    @staticmethod
    def _operation_payload(kind, requested_by, desired_state, from_uid, to_uid):
        if not str(kind or "").strip():
            raise ValueError("operation.kind обязателен")
        if not str(requested_by or "").strip():
            raise ValueError("operation.requested_by обязателен")
        try:
            desired_json = json.dumps(desired_state, ensure_ascii=False,
                                      sort_keys=True, separators=(",", ":"),
                                      allow_nan=False)
        except (TypeError, ValueError) as e:
            raise ValueError("operation.desired_state не сериализуется: %s" % e)
        return (str(kind).strip(), str(requested_by).strip(), desired_json,
                from_uid or None, to_uid or None)

    def get_operation(self, operation_id=None, idempotency_key=None):
        """Вернуть операцию по id или idempotency key (ровно один обязателен)."""
        if bool(operation_id) == bool(idempotency_key):
            raise ValueError("укажите ровно один operation_id или idempotency_key")
        if operation_id:
            row = self.conn.execute("SELECT * FROM operation WHERE id=?",
                                    (operation_id,)).fetchone()
        else:
            row = self.conn.execute("SELECT * FROM operation WHERE idempotency_key=?",
                                    (idempotency_key,)).fetchone()
        return self._operation_dict(row)

    def latest_operation_by_key_prefix(self, base_key):
        """Новейшая saga семейства `base` / `base:<attempt nonce>`."""
        base = str(base_key or "").strip()
        if not base:
            raise ValueError("base_key обязателен")
        row = self.conn.execute(
            "SELECT * FROM operation WHERE idempotency_key=?"
            " OR idempotency_key LIKE ? ORDER BY rowid DESC LIMIT 1",
            (base, base + ":%"),).fetchone()
        return self._operation_dict(row)

    def begin_operation(self, kind, requested_by, desired_state, idempotency_key,
                        from_uid=None, to_uid=None, before_checksum=""):
        """Создать PLANNED или вернуть точный идемпотентный повтор.

        Переиспользование ключа для иного намерения — подтверждённый конфликт,
        а не молчаливый успех. Создание operation и audit-event коммитятся вместе.
        """
        key = str(idempotency_key or "").strip()
        if not key:
            raise ValueError("operation.idempotency_key обязателен")
        payload = self._operation_payload(kind, requested_by, desired_state,
                                          from_uid, to_uid)
        now = now_iso()
        operation_id = uuid.uuid4().hex
        def write(conn):
            # INSERT OR IGNORE делает точный конкурентный повтор идемпотентным:
            # второй процесс ждёт первого писателя, затем читает его строку.
            cur = conn.execute(
                "INSERT OR IGNORE INTO operation(id,kind,requested_by,desired_state,phase,"
                "from_uid,to_uid,before_checksum,requested_at,updated_at,idempotency_key)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (operation_id, payload[0], payload[1], payload[2], "planned",
                 payload[3], payload[4], before_checksum or None, now, now, key))
            if cur.rowcount == 0:
                existing = conn.execute(
                    "SELECT * FROM operation WHERE idempotency_key=?", (key,)).fetchone()
                have = (existing["kind"], existing["requested_by"],
                        existing["desired_state"], existing["from_uid"], existing["to_uid"])
                if have != payload:
                    raise ValueError("operation.idempotency_key уже связан с другим намерением")
                out = self._operation_dict(existing)
                out["created"] = False
                return out
            conn.execute(
                "INSERT INTO event(ts,server,actor,action,from_uid,to_uid,result,detail)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (now, self.server, payload[1], "operation", payload[3], payload[4],
                  "planned", "%s:%s" % (payload[0], operation_id)))
            return None
        existing = self.run_transaction(write)
        if existing is not None:
            return existing
        out = self.get_operation(operation_id=operation_id)
        out["created"] = True
        return out

    def transition_operation(self, operation_id, phase, error=None,
                             before_checksum=None, after_checksum=None):
        """Атомарно перевести saga в следующую фазу и записать audit-event.

        Повтор уже записанной фазы идемпотентен. Терминальные фазы неизменяемы;
        недопустимые скачки отклоняются до записи.
        """
        if phase not in OPERATION_PHASES:
            raise ValueError("неизвестная фаза operation: %s" % phase)
        def write(conn):
            row = conn.execute("SELECT * FROM operation WHERE id=?",
                                    (operation_id,)).fetchone()
            if row is None:
                raise KeyError("operation не найдена: %s" % operation_id)
            current = row["phase"]
            if current == phase:
                return self._operation_dict(row)
            # Recovery обязан уметь безопасно терминализировать строку с
            # повреждённой/будущей фазой, сохранив исходную фазу в audit-event.
            repair_unknown = current not in _OPERATION_TRANSITIONS and phase == "failed"
            if not repair_unknown and (
                    current not in _OPERATION_TRANSITIONS
                    or phase not in _OPERATION_TRANSITIONS[current]):
                raise ValueError("недопустимый переход operation: %s -> %s" % (current, phase))
            now = now_iso()
            finished_at = now if phase in OPERATION_TERMINAL_PHASES else None
            new_error = str(error) if error is not None else row["error"]
            new_before = before_checksum if before_checksum is not None else row["before_checksum"]
            new_after = after_checksum if after_checksum is not None else row["after_checksum"]
            conn.execute(
                "UPDATE operation SET phase=?,before_checksum=?,after_checksum=?,"
                "updated_at=?,finished_at=?,error=? WHERE id=?",
                (phase, new_before or None, new_after or None, now, finished_at,
                 new_error or None, operation_id))
            conn.execute(
                "INSERT INTO event(ts,server,actor,action,from_uid,to_uid,result,detail)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (now, self.server, row["requested_by"], "operation", row["from_uid"],
                 row["to_uid"], phase, "%s:%s%s%s" % (
                     row["kind"], operation_id,
                     ("; повреждённая фаза=%s" % current) if repair_unknown else "",
                      ("; " + new_error) if new_error else "")))
            return self._operation_dict(conn.execute(
                "SELECT * FROM operation WHERE id=?", (operation_id,)).fetchone())
        return self.run_transaction(write)

    def unfinished_operations(self, limit=100):
        """Старейшие незавершённые saga для startup/heartbeat recovery."""
        try:
            n = max(1, min(int(limit), 1000))
        except (TypeError, ValueError):
            n = 100
        qmarks = ",".join("?" * len(OPERATION_TERMINAL_PHASES))
        rows = self.conn.execute(
            "SELECT * FROM operation WHERE phase NOT IN (%s)"
            # rowid сохраняет порядок вставки при одинаковых секундных timestamp;
            # UUID для этого непригоден, он намеренно случаен.
            " ORDER BY requested_at,rowid LIMIT ?" % qmarks,
            OPERATION_TERMINAL_PHASES + (n,)).fetchall()
        return [self._operation_dict(row) for row in rows]

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
        self.observe_provider_errors(providers, actor=actor)
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
        stamp = now_iso()

        def write(conn):
            stored = conn.execute("SELECT * FROM proxy WHERE uid=?", (uid,)).fetchone()
            if stored is None:
                return False
            row = dict(stored)
            if res.get("ok"):
                fail_count = 0
            elif background and row.get("probe_ok") != 0:
                fail_count = int(row.get("fail_count") or 0)
            else:
                fail_count = int(row.get("fail_count") or 0) + 1
            geo = (None if res.get("geo_agree") is None
                   else (1 if res.get("geo_agree") else 0))
            # Fault/no-combo probe не видит exit-IP и потому не может получить ASN.
            # Это не означает, что последний известный ASN изменился: он нужен
            # следующей fault-ротации для attribution drop/battle.
            asn = res.get("asn") or row.get("asn")
            conn.execute(
                "UPDATE proxy SET last_probe_at=?, probe_ok=?, socks_ok=?, http_ok=?, tg_ok=?,"
                " exit_ip=?, exit_cc=?, exit_cc_alt=?, geo_agree=?, asn=?, latency_ms=?, score=?,"
                " fail_count=? WHERE uid=?",
                (stamp, 1 if res.get("ok") else 0,
                 1 if res.get("socks_ok") else 0, 1 if res.get("http_ok") else 0,
                 1 if res.get("tg_ok") else 0, res.get("exit_ip"), res.get("exit_cc"),
                 res.get("exit_cc_alt"), geo, asn, res.get("latency_ms"),
                 res.get("score"), fail_count, uid))
            if res.get("ok"):
                conn.execute("UPDATE proxy SET cooldown_until=NULL WHERE uid=?", (uid,))
            conn.execute(
                "INSERT INTO probe_log(ts, uid, provider, exit_cc, country, geo_agree, ok,"
                " latency_ms, tg_ok, disq, is_current, strategy)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (stamp, uid, row["provider"], res.get("exit_cc"), row.get("country"),
                 geo, 1 if res.get("ok") else 0, res.get("latency_ms"),
                 1 if res.get("tg_ok") else 0, res.get("disqualified"),
                 1 if is_current else 0, strategy or ""))
            self._stability_bump_conn(
                conn, row["provider"], row.get("country"),
                ok=1 if res.get("ok") else 0, fail=0 if res.get("ok") else 1,
                stamp=stamp)
            self._learning_bump_conn(conn, row, **self._learning_probe_values(res))
            return True
        return self.run_transaction(write)

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
    @staticmethod
    def _validated_money(provider, op, uid, price, currency,
                         balance_after=None, order_id=None, descr=None):
        """Нормализовать ledger-строку; buy/prolong никогда не бывают <=0/NaN."""
        operation = str(op or "").strip().lower()
        try:
            amount = float(price)
        except (TypeError, ValueError, OverflowError):
            amount = None
        code = str(currency or "").strip().upper()
        if operation in ("buy", "prolong"):
            if amount is None or not math.isfinite(amount) or amount <= 0:
                raise ValueError("цена %s должна быть конечной и положительной" % operation)
            if not re.fullmatch(r"[A-Z]{3}", code):
                raise ValueError("валюта %s некорректна" % operation)
        elif amount is not None and not math.isfinite(amount):
            raise ValueError("цена операции должна быть конечной")
        return (now_iso(), str(provider or ""), operation,
                None if uid is None else str(uid), amount, code or None,
                None if balance_after is None else str(balance_after),
                None if order_id is None else str(order_id),
                None if descr is None else str(descr))

    def record_money(self, provider, op, uid, price, currency,
                     balance_after=None, order_id=None, descr=None):
        """Одна трата -> таблица money (§6.2/§13): buy|prolong|delete."""
        values = self._validated_money(provider, op, uid, price, currency,
                                       balance_after, order_id, descr)
        self.conn.execute(
            "INSERT INTO money(ts, provider, op, uid, price, currency, balance_after, order_id, descr)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            values)
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
        rows = self.conn.execute(
            "SELECT id,price,currency FROM money"
            " WHERE op IN ('buy','prolong') AND ts LIKE ?", (day + "%",)).fetchall()
        total = 0.0
        expected = str(currency or "").strip().upper()
        for row in rows:
            try:
                amount = float(row["price"])
            except (TypeError, ValueError, OverflowError):
                amount = None
            code = str(row["currency"] or "").strip().upper()
            if (amount is None or not math.isfinite(amount) or amount <= 0
                    or not re.fullmatch(r"[A-Z]{3}", code)):
                raise PoolCorrupt("семантически повреждена строка money id=%s" % row["id"])
            if code == expected:
                total += amount
        if not math.isfinite(total) or total < 0:
            raise PoolCorrupt("семантически повреждён агрегат money")
        return total

    def begin_spend_operation(self, kind, provider, request, idempotency_key,
                              *, uid=None, descr=None, quote_price=None,
                              currency=None, balance_before=None):
        """Долговечный financial intent. Одновременно активен максимум один."""
        kind = str(kind or "").strip().lower()
        provider = str(provider or "").strip().lower()
        code = str(currency or "").strip().upper()
        try:
            quote = float(quote_price)
        except (TypeError, ValueError, OverflowError):
            quote = None
        if kind not in ("buy", "prolong") or not provider:
            raise ValueError("некорректная денежная операция")
        if quote is None or not math.isfinite(quote) or quote <= 0:
            raise ValueError("quote_price должна быть конечной и положительной")
        if not re.fullmatch(r"[A-Z]{3}", code):
            raise ValueError("валюта intent некорректна")
        payload = json.dumps(request or {}, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False)
        op_id = uuid.uuid4().hex
        stamp = now_iso()

        def write(conn):
            active = conn.execute(
                "SELECT * FROM spend_operation WHERE phase IN ('planned','submitted')"
                " ORDER BY requested_at,id LIMIT 1").fetchone()
            if active:
                return dict(active), False
            conn.execute(
                "INSERT INTO spend_operation(id,kind,provider,uid,descr,phase,request_json,"
                " quote_price,currency,balance_before,idempotency_key,requested_at,updated_at,error)"
                " VALUES(?,?,?,?,?,'planned',?,?,?,?,?,?,?,'')",
                (op_id, kind, provider, uid, descr, payload, quote, code,
                 None if balance_before is None else str(balance_before),
                 str(idempotency_key), stamp, stamp))
            return dict(conn.execute(
                "SELECT * FROM spend_operation WHERE id=?", (op_id,)).fetchone()), True
        return self.run_transaction(write)

    @staticmethod
    def _spend_item(row):
        item = dict(row)
        raw = item.pop("request_json", "")
        try:
            item["request"] = json.loads(
                raw, parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("non-finite JSON")))
            if not isinstance(item["request"], dict):
                raise ValueError("request_json is not an object")
        except (TypeError, ValueError, RecursionError):
            item["request"] = None
            item["request_invalid"] = True
        raw_result = item.pop("result_json", None)
        if raw_result:
            try:
                item["result"] = json.loads(
                    raw_result, parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError("non-finite JSON")))
                if not isinstance(item["result"], dict):
                    raise ValueError("result_json is not an object")
            except (TypeError, ValueError, RecursionError):
                item["result"] = None
                item["result_invalid"] = True
        else:
            item["result"] = None
        return item

    def pending_spend_operations(self, limit=100):
        rows = self.conn.execute(
            "SELECT * FROM spend_operation WHERE phase IN ('planned','submitted')"
            " ORDER BY requested_at,id LIMIT ?", (max(1, min(1000, int(limit))),)).fetchall()
        return [self._spend_item(row) for row in rows]

    def unacknowledged_spend_operations(self, limit=100):
        rows = self.conn.execute(
            "SELECT * FROM spend_operation WHERE phase='committed'"
            " ORDER BY requested_at,id LIMIT ?", (max(1, min(1000, int(limit))),)).fetchall()
        return [self._spend_item(row) for row in rows]

    def get_spend_operation(self, op_id):
        row = self.conn.execute(
            "SELECT * FROM spend_operation WHERE id=?", (str(op_id),)).fetchone()
        return self._spend_item(row) if row else None

    def transition_spend_operation(self, op_id, phase, error=""):
        phase = str(phase or "").strip().lower()
        if phase not in ("submitted", "failed"):
            raise ValueError("недопустимая фаза spend_operation")
        stamp = now_iso()

        def write(conn):
            row = conn.execute(
                "SELECT phase FROM spend_operation WHERE id=?", (str(op_id),)).fetchone()
            if not row:
                raise ValueError("spend_operation не найдена")
            old = row[0]
            allowed = ((old == "planned" and phase in ("submitted", "failed"))
                       or (old == "submitted" and phase == "failed"))
            if not allowed:
                if old == phase:
                    return dict(conn.execute(
                        "SELECT * FROM spend_operation WHERE id=?", (str(op_id),)).fetchone())
                raise ValueError("переход spend_operation %s -> %s запрещён" % (old, phase))
            conn.execute(
                "UPDATE spend_operation SET phase=?,updated_at=?,finished_at=?,error=? WHERE id=?",
                (phase, stamp, stamp if phase == "failed" else None,
                 str(error or "")[:1000], str(op_id)))
            return dict(conn.execute(
                "SELECT * FROM spend_operation WHERE id=?", (str(op_id),)).fetchone())
        row = self.run_transaction(write)
        return self._spend_item(row)

    def complete_spend_operation(self, op_id, money_rows, *, date_updates=None, result=None):
        """Атомарно записать ledger и committed; повторный вызов безвреден."""
        validated = [self._validated_money(
            row.get("provider"), row.get("op"), row.get("uid"), row.get("price"),
            row.get("currency"), row.get("balance_after"), row.get("order_id"),
            row.get("descr")) for row in (money_rows or [])]
        if not validated:
            raise ValueError("денежная сага не может завершиться без ledger")
        updates = [(str(date_end), str(uid)) for uid, date_end in (date_updates or [])
                   if uid and date_end]
        result_json = json.dumps(result or {}, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False)
        stamp = now_iso()

        def write(conn):
            row = conn.execute(
                "SELECT phase FROM spend_operation WHERE id=?", (str(op_id),)).fetchone()
            if not row:
                raise ValueError("spend_operation не найдена")
            if row[0] == "committed":
                return False
            if row[0] != "submitted":
                raise ValueError("завершить можно только submitted spend_operation")
            conn.executemany(
                "INSERT INTO money(ts,provider,op,uid,price,currency,balance_after,order_id,descr)"
                " VALUES(?,?,?,?,?,?,?,?,?)", validated)
            if updates:
                conn.executemany("UPDATE proxy SET date_end=? WHERE uid=?", updates)
            conn.execute(
                "UPDATE spend_operation SET phase='committed',updated_at=?,finished_at=?,error='',"
                " result_json=? WHERE id=?", (stamp, stamp, result_json, str(op_id)))
            return True
        return self.run_transaction(write)

    def acknowledge_spend_operation(self, op_id):
        """Отметить, что committed result уже был возвращён живому вызывающему."""
        stamp = now_iso()

        def write(conn):
            row = conn.execute(
                "SELECT phase FROM spend_operation WHERE id=?", (str(op_id),)).fetchone()
            if not row:
                raise ValueError("spend_operation не найдена")
            if row[0] == "acknowledged":
                return False
            if row[0] != "committed":
                raise ValueError("acknowledge допустим только после committed")
            conn.execute(
                "UPDATE spend_operation SET phase='acknowledged',updated_at=? WHERE id=?",
                (stamp, str(op_id)))
            return True
        return self.run_transaction(write)

    # ---------- настройки автомата (§8) ----------
    def get_setting(self, key, default=None):
        row = self.conn.execute("SELECT value FROM setting WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key, value):
        self.set_settings({key: value})

    def set_settings(self, values):
        """Атомарно записать несколько ключей состояния одним commit.

        Переходы автомата (например AUTO <-> MANUAL) состоят из нескольких полей;
        отдельные commit оставляли наблюдаемое наполовину записанное состояние.
        """
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO setting(key, value) VALUES(?, ?)",
                [(key, None if value is None else str(value)) for key, value in values.items()])

    def request_selection_intent(self, kind, payload, settings, actor="user",
                                 applied=False, detail=""):
        """Атомарно: новая desired revision + mode/pin + audit event."""
        if kind not in ("strategy", "manual"):
            raise ValueError("неизвестный selection intent: %s" % kind)
        payload_json = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":"), allow_nan=False)
        def write(conn):
            def number(key):
                row = conn.execute("SELECT value FROM setting WHERE key=?", (key,)).fetchone()
                try:
                    return max(0, int(row[0])) if row else 0
                except (TypeError, ValueError):
                    return 0
            revision = max(number("desired_selection_revision"),
                           number("applied_selection_revision")) + 1
            values = dict(settings or {})
            values.update({"desired_selection_revision": revision,
                           "desired_selection_kind": kind,
                           "desired_selection_payload": payload_json})
            if applied:
                values["applied_selection_revision"] = revision
            conn.executemany(
                "INSERT OR REPLACE INTO setting(key,value) VALUES(?,?)",
                [(key, None if value is None else str(value)) for key, value in values.items()])
            conn.execute(
                "INSERT INTO event(ts,server,actor,action,result,detail) VALUES(?,?,?,?,?,?)",
                (now_iso(), self.server, actor, "selection-intent", str(revision),
                 "%s; kind=%s%s" % (detail or "новое намерение", kind,
                                     "; applied" if applied else "")))
            return revision
        return self.run_transaction(write)

    def mark_selection_applied(self, revision, actor="auto", detail=""):
        """Применить только всё ещё последнюю desired revision; stale worker = no-op."""
        try:
            target = int(revision)
        except (TypeError, ValueError):
            return False
        def write(conn):
            row = conn.execute(
                "SELECT value FROM setting WHERE key='desired_selection_revision'").fetchone()
            desired = int(row[0]) if row and str(row[0]).isdigit() else 0
            if target != desired:
                return False
            row = conn.execute(
                "SELECT value FROM setting WHERE key='applied_selection_revision'").fetchone()
            applied = int(row[0]) if row and str(row[0]).isdigit() else 0
            if applied >= target:
                return True
            conn.execute(
                "INSERT OR REPLACE INTO setting(key,value)"
                " VALUES('applied_selection_revision',?)", (str(target),))
            conn.execute(
                "INSERT INTO event(ts,server,actor,action,result,detail) VALUES(?,?,?,?,?,?)",
                (now_iso(), self.server, actor, "selection-reconciled", str(target),
                 detail or "desired revision применена"))
            return True
        return self.run_transaction(write)

    def clear_strategy_override(self, revision, strategy):
        """CAS-очистка config-repair только для всё ещё текущего intent."""
        try:
            target = int(revision)
        except (TypeError, ValueError):
            return False
        def write(conn):
            rows = dict(conn.execute(
                "SELECT key,value FROM setting WHERE key IN ("
                "'desired_selection_revision','desired_selection_kind',"
                "'desired_selection_payload','selection_strategy_override')").fetchall())
            try:
                desired = int(rows.get("desired_selection_revision") or 0)
                payload = json.loads(rows.get("desired_selection_payload") or "{}")
            except (TypeError, ValueError):
                return False
            matches = (desired == target
                       and rows.get("desired_selection_kind") == "strategy"
                       and payload.get("strategy") == strategy
                       and rows.get("selection_strategy_override") == strategy)
            if not matches:
                return False
            conn.execute(
                "INSERT OR REPLACE INTO setting(key,value)"
                " VALUES('selection_strategy_override',NULL)")
            return True
        return self.run_transaction(write)

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
    @staticmethod
    def _stability_bump_conn(conn, provider, country, ok=0, fail=0, drops=0,
                             seconds=0, stamp=None):
        c = str(country or "").strip().lower()
        if not provider or not c:
            return
        stamp = stamp or now_iso()
        conn.execute(
            "INSERT INTO stability(provider, country, probes_ok, probes_fail,"
            " battle_drops, battle_seconds, first_seen, last_seen)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(provider, country) DO UPDATE SET"
            " probes_ok=probes_ok+excluded.probes_ok,"
            " probes_fail=probes_fail+excluded.probes_fail,"
            " battle_drops=battle_drops+excluded.battle_drops,"
            " battle_seconds=battle_seconds+excluded.battle_seconds,"
            " last_seen=excluded.last_seen",
            (provider, c, int(ok), int(fail), int(drops), int(seconds), stamp, stamp))

    def _stability_bump(self, provider, country, ok=0, fail=0, drops=0, seconds=0):
        """Одно приращение агрегата пары (provider, паспортная страна)."""
        return self.run_transaction(lambda conn: self._stability_bump_conn(
            conn, provider, country, ok=ok, fail=fail, drops=drops, seconds=seconds))

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

    # ---------- learning v2: дневные buckets + иерархические ключи ----------
    @staticmethod
    def _learning_keys(row, asn=""):
        provider = str((row or {}).get("provider") or "")
        family = str((row or {}).get("kind") or "")
        country = str((row or {}).get("country") or "").strip().lower()
        uid = str((row or {}).get("uid") or "")
        keys = [("global", "", "", "", "", ""),
                ("provider", provider, "", "", "", "")]
        if provider and family:
            keys.append(("provider_family", provider, family, "", "", ""))
        if provider and country:
            keys.append(("provider_country", provider, "", country, "", ""))
        if uid:
            keys.append(("uid", provider, family, country, uid, ""))
        if asn:
            keys.append(("asn", provider, family, country, "", str(asn)))
        return keys

    def _learning_bump(self, row, *, ok=0, fail=0, tg_ok=0, tg_fail=0,
                       geo_ok=0, geo_fail=0, latency_sum=0.0, latency_count=0,
                       drops=0, seconds=0, asn="", day=None):
        return self.run_transaction(lambda conn: self._learning_bump_conn(
            conn, row, ok=ok, fail=fail, tg_ok=tg_ok, tg_fail=tg_fail,
            geo_ok=geo_ok, geo_fail=geo_fail, latency_sum=latency_sum,
            latency_count=latency_count, drops=drops, seconds=seconds,
            asn=asn, day=day))

    def _learning_bump_conn(self, conn, row, *, ok=0, fail=0, tg_ok=0, tg_fail=0,
                            geo_ok=0, geo_fail=0, latency_sum=0.0, latency_count=0,
                            drops=0, seconds=0, asn="", day=None):
        day = str(day or datetime.date.today().isoformat())
        values = (int(ok), int(fail), int(tg_ok), int(tg_fail), int(geo_ok),
                  int(geo_fail), float(latency_sum), int(latency_count),
                  int(drops), int(seconds))
        for level, provider, family, country, uid, key_asn in self._learning_keys(
                row, asn=asn or (row or {}).get("asn") or ""):
            conn.execute(
                "INSERT INTO learning_bucket(day,level,provider,family,country,uid,asn,"
                " probes_ok,probes_fail,tg_ok,tg_fail,geo_ok,geo_fail,latency_sum,"
                " latency_count,battle_drops,battle_seconds)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(day,level,provider,family,country,uid,asn) DO UPDATE SET"
                " probes_ok=probes_ok+excluded.probes_ok,"
                " probes_fail=probes_fail+excluded.probes_fail,"
                " tg_ok=tg_ok+excluded.tg_ok,tg_fail=tg_fail+excluded.tg_fail,"
                " geo_ok=geo_ok+excluded.geo_ok,geo_fail=geo_fail+excluded.geo_fail,"
                " latency_sum=latency_sum+excluded.latency_sum,"
                " latency_count=latency_count+excluded.latency_count,"
                " battle_drops=battle_drops+excluded.battle_drops,"
                " battle_seconds=battle_seconds+excluded.battle_seconds",
                (day, level, provider, family, country, uid, key_asn, *values))

    @staticmethod
    def _learning_probe_values(res):
        latency = res.get("latency_ms")
        try:
            latency = float(latency)
            latency_valid = math.isfinite(latency) and latency >= 0
        except (TypeError, ValueError, OverflowError):
            latency_valid = False
            latency = 0.0
        geo, tg = res.get("geo_agree"), res.get("tg_ok")
        return {"ok": 1 if res.get("ok") else 0,
                "fail": 0 if res.get("ok") else 1,
                "tg_ok": 1 if tg is True else 0, "tg_fail": 1 if tg is False else 0,
                "geo_ok": 1 if geo is True else 0,
                "geo_fail": 1 if geo is False else 0,
                "latency_sum": latency if latency_valid else 0.0,
                "latency_count": 1 if latency_valid else 0,
                "asn": res.get("asn") or ""}

    def learning_bump_probe(self, row, res, day=None):
        values = self._learning_probe_values(res)
        values["day"] = day
        self._learning_bump(dict(row), **values)

    def learning_bump_drop(self, row, day=None):
        self._learning_bump(dict(row), drops=1, day=day)

    def learning_bump_battle(self, row, seconds, day=None):
        if seconds and seconds > 0:
            self._learning_bump(dict(row), seconds=int(seconds), day=day)

    def learning_record_drop(self, row, day=None):
        row = dict(row)
        def write(conn):
            self._stability_bump_conn(conn, row.get("provider"), row.get("country"), drops=1)
            self._learning_bump_conn(conn, row, drops=1, day=day)
        return self.run_transaction(write)

    def learning_record_battle(self, row, seconds, day=None):
        if not seconds or seconds <= 0:
            return None
        row = dict(row)
        def write(conn):
            self._stability_bump_conn(
                conn, row.get("provider"), row.get("country"), seconds=int(seconds))
            self._learning_bump_conn(conn, row, seconds=int(seconds), day=day)
        return self.run_transaction(write)

    def learning_buckets(self, level=None, provider=None, family=None, country=None,
                         uid=None, asn=None, since_day=None):
        query = "SELECT * FROM learning_bucket WHERE 1=1"
        params = []
        for column, value in (("level", level), ("provider", provider),
                              ("family", family), ("country", country),
                              ("uid", uid), ("asn", asn)):
            if value is not None:
                query += " AND %s=?" % column
                params.append(str(value))
        if since_day is not None:
            query += " AND day>=?"
            params.append(str(since_day))
        query += " ORDER BY day,level,provider,family,country,uid,asn"
        return [dict(item) for item in self.conn.execute(query, params).fetchall()]

    def record_shadow_decision(self, recommendation, mode="shadow", context="", ts=None):
        """Записать рекомендацию v2, не вызывая apply/rotate/buy."""
        item = dict(recommendation or {})
        scores = json.dumps(item.get("scores") or [], ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"), allow_nan=False)
        stamp = (ts.replace(microsecond=0).isoformat(sep=" ")
                 if isinstance(ts, datetime.datetime) else str(ts or now_iso()))
        def write(conn):
            cur = conn.execute(
                "INSERT INTO shadow_decision(ts,server,formula_version,mode,strategy,"
                " current_uid,recommended_uid,candidate_count,scores_json,context)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (stamp, self.server, str(item.get("formula_version") or ""), str(mode),
                 str(item.get("strategy") or ""), item.get("current_uid"),
                 item.get("recommended_uid"), int(item.get("candidate_count") or 0),
                 scores, str(context or "")))
            return cur.lastrowid
        decision_id = self.run_transaction(write)
        return self.shadow_decisions(decision_id=decision_id)[0]

    def shadow_decisions(self, decision_id=None, since=None, limit=1000):
        query = "SELECT * FROM shadow_decision WHERE 1=1"
        params = []
        if decision_id is not None:
            query += " AND id=?"
            params.append(int(decision_id))
        if since is not None:
            query += " AND ts>=?"
            params.append(str(since))
        query += " ORDER BY ts,id LIMIT ?"
        params.append(max(1, min(10000, int(limit))))
        out = []
        for raw in self.conn.execute(query, params).fetchall():
            item = dict(raw)
            item["scores"] = json.loads(item.pop("scores_json"))
            out.append(item)
        return out

    def shadow_coverage(self, formula_version, now=None, modes=None, servers=None,
                        since=None):
        current = now or datetime.datetime.now()
        if isinstance(current, datetime.date) and not isinstance(current, datetime.datetime):
            current = datetime.datetime.combine(current, datetime.time.max)
        cutoff = (current - datetime.timedelta(days=365)).date().isoformat()
        upper = current.replace(microsecond=0).isoformat(sep=" ")
        query = (
            "SELECT COUNT(DISTINCT substr(ts,1,10)),MIN(ts),MAX(ts),COUNT(*)"
            " FROM shadow_decision WHERE formula_version=? AND ts>=? AND ts<=?")
        params = [str(formula_version), cutoff, upper]
        if since is not None:
            query += " AND ts>=?"
            params.append(str(since))
        for column, values in (("mode", modes), ("server", servers)):
            values = sorted({str(item) for item in (values or []) if str(item)})
            if values:
                query += " AND %s IN (%s)" % (column, ",".join("?" * len(values)))
                params.extend(values)
        row = self.conn.execute(query, params).fetchone()
        return {"days": int(row[0] or 0), "first_at": row[1], "last_at": row[2],
                "decisions": int(row[3] or 0)}

    def shadow_qualification_at(self, formula_version, minimum_days, now=None):
        """Timestamp первой записи 30-го (или N-го) уникального shadow-дня."""
        current = now or datetime.datetime.now()
        if isinstance(current, datetime.date) and not isinstance(current, datetime.datetime):
            current = datetime.datetime.combine(current, datetime.time.max)
        cutoff = (current - datetime.timedelta(days=365)).date().isoformat()
        upper = current.replace(microsecond=0).isoformat(sep=" ")
        minimum = max(1, int(minimum_days))
        row = self.conn.execute(
            "SELECT MIN(ts) FROM shadow_decision"
            " WHERE formula_version=? AND mode='shadow' AND ts>=? AND ts<=?"
            " GROUP BY substr(ts,1,10) ORDER BY substr(ts,1,10) LIMIT 1 OFFSET ?",
            (str(formula_version), cutoff, upper, minimum - 1)).fetchone()
        return row[0] if row else None

    def claim_exploration(self, uid, current_host, max_per_day=1, eligible_count=0,
                          now=None, context="learning-v2"):
        """Атомарно зарезервировать один exploration slot только для купленного резерва."""
        stamp = (now.replace(microsecond=0).isoformat(sep=" ")
                 if isinstance(now, datetime.datetime) else str(now or now_iso()))
        day = stamp[:10]
        limit = max(0, int(max_per_day or 0))
        def write(conn):
            selected = conn.execute("SELECT * FROM proxy WHERE uid=?", (str(uid),)).fetchone()
            reason = ""
            if selected is None:
                reason = "not-in-owned-pool"
            elif selected["role"] != "auto" or int(selected["gone"] or 0):
                reason = "not-auto-reserve"
            elif not current_host or selected["host"] == current_host:
                reason = "not-a-reserve"
            elif selected["cooldown_until"] and str(selected["cooldown_until"]) > stamp:
                reason = "cooldown"
            used = conn.execute(
                "SELECT COUNT(*) FROM exploration_decision"
                " WHERE result='chosen' AND substr(ts,1,10)=?", (day,)).fetchone()[0]
            if not reason and (limit <= 0 or used >= limit):
                reason = "daily-limit"
            result = "denied" if reason else "chosen"
            cur = conn.execute(
                "INSERT INTO exploration_decision(ts,server,selected_uid,eligible_count,"
                " result,reason,context) VALUES(?,?,?,?,?,?,?)",
                (stamp, self.server, str(uid), int(eligible_count or 0), result,
                 reason, str(context or "")))
            return {"id": cur.lastrowid, "ts": stamp, "server": self.server,
                    "selected_uid": str(uid), "eligible_count": int(eligible_count or 0),
                    "result": result, "reason": reason, "context": str(context or "")}
        return self.run_transaction(write)

    def exploration_history(self, since=None, limit=1000):
        query, params = "SELECT * FROM exploration_decision WHERE 1=1", []
        if since is not None:
            query += " AND ts>=?"
            params.append(str(since))
        query += " ORDER BY ts,id LIMIT ?"
        params.append(max(1, min(10000, int(limit))))
        return [dict(row) for row in self.conn.execute(query, params).fetchall()]

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
