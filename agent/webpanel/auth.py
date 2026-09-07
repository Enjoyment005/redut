# -*- coding: utf-8 -*-
"""Аутентификация панели на stdlib (§11): пароль + TOTP + recovery, сессии, антибрут, CSRF.

Никаких pip-зависимостей:
  пароль   — hashlib.scrypt (соль + параметры в хеше);
  TOTP     — RFC 6238 (hmac-sha1), окно ±1 шаг (±30 c) под уехавшие часы;
  recovery — 10 одноразовых кодов, хранятся sha256-хешами;
  сессии   — secrets.token_urlsafe, cookie httpOnly+Secure+SameSite=Strict, TTL 12 ч;
  антибрут — счётчик неудач по IP, порог -> бан на время (нарастающе);
  CSRF     — токен на сессию, сверяется на всех POST.

secrets.json (0600) содержит блок "admin":
  {"admin": {"pw": "scrypt$...", "totp": "<base32-seed>", "recovery": ["sha256", ...]}}
Сессии и бан-счётчики — в state.db (таблицы session, loginfail).
"""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
import threading
import time

SESSION_TTL = 12 * 3600
COOKIE_NAME = "vpnpsid"
BRUTE_MAX_FAILS = 5           # неудач подряд с одного IP
BRUTE_BASE_BAN = 15 * 60      # базовый бан (сек), растёт с числом волн
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1               # ±1 шаг

# Every in-process and cross-process writer of secrets.json uses this lock
# contract.  The thread lock is required on Windows/dev where fcntl is absent;
# the adjacent lock file serialises vpn-panel, setup_admin and other POSIX
# processes on the node.
_SECRETS_WRITER_LOCK = threading.RLock()


@contextlib.contextmanager
def secrets_writer(secrets_path):
    path = os.path.abspath(secrets_path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    lock_path = path + ".lock"
    with _SECRETS_WRITER_LOCK:
        lock_file = open(lock_path, "a+", encoding="ascii")
        try:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            if os.name == "posix":
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if os.name == "posix":
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            lock_file.close()


def _read_secrets_unlocked(secrets_path):
    try:
        with open(secrets_path, encoding="utf-8") as source:
            data = json.load(source)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError("secrets.json root must be an object")
    return data


def _write_secrets_unlocked(secrets_path, data):
    parent = os.path.dirname(os.path.abspath(secrets_path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".secrets.", dir=parent)
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as target:
            fd = -1
            json.dump(data, target, ensure_ascii=False, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp, secrets_path)
        try:
            os.chmod(secrets_path, 0o600)
        except OSError:
            pass
        try:
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Directory fsync is unavailable on Windows and some filesystems.
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def write_secrets_atomic(secrets_path, data):
    """Replace secrets.json durably under the common writer lock."""
    with secrets_writer(secrets_path):
        _write_secrets_unlocked(secrets_path, data)


def update_secrets_atomic(secrets_path, transform):
    """Read, transform and replace secrets.json as one serialised operation.

    ``transform`` receives the current dictionary and returns the replacement.
    It may raise to abort without touching the file.
    """
    with secrets_writer(secrets_path):
        data = _read_secrets_unlocked(secrets_path)
        replacement = transform(data)
        if not isinstance(replacement, dict):
            raise ValueError("secrets transform must return an object")
        _write_secrets_unlocked(secrets_path, replacement)
        return replacement


def bootstrap_secret_valid(bootstrap_path, supplied, now=None):
    """Validate the SSH-only one-time panel bootstrap secret."""
    if not supplied:
        return False
    now = float(time.time() if now is None else now)
    try:
        with secrets_writer(bootstrap_path):
            with open(bootstrap_path, encoding="utf-8") as source:
                record = json.load(source)
    except (OSError, ValueError, TypeError):
        return False
    if not isinstance(record, dict) or record.get("used"):
        return False
    try:
        expires = float(record.get("expires") or 0)
    except (TypeError, ValueError):
        return False
    digest = hashlib.sha256(str(supplied).encode("utf-8")).hexdigest()
    stored = str(record.get("secret_sha256") or "")
    return expires >= now and len(stored) == 64 and hmac.compare_digest(stored, digest)


def consume_bootstrap_secret(bootstrap_path):
    """Make a bootstrap secret unusable after the admin commit is durable."""
    with secrets_writer(bootstrap_path):
        try:
            os.unlink(bootstrap_path)
        except FileNotFoundError:
            return
        parent = os.path.dirname(os.path.abspath(bootstrap_path)) or "."
        try:
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


# ------------------------------------------------------------- пароль (scrypt)
def hash_password(password, *, n=2 ** 14, r=8, p=1):
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, base64.b64encode(salt).decode(),
                                      base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expect = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=int(n), r=int(r), p=int(p), dklen=len(expect))
        return hmac.compare_digest(dk, expect)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------- TOTP (RFC6238)
def totp_new_seed():
    return base64.b32encode(os.urandom(20)).decode("ascii")


def _totp_at(seed_b32, counter):
    key = base64.b32decode(seed_b32, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_verify(seed_b32, code, now=None):
    """Проверка кода в окне ±TOTP_WINDOW шагов (уехавшие часы, §10)."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = int(now if now is not None else time.time())
    counter = now // TOTP_STEP
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if hmac.compare_digest(_totp_at(seed_b32, counter + delta), code):
            return True
    return False


def totp_uri(seed_b32, label, issuer="vpn-panel"):
    """otpauth:// для добавления в Google Authenticator / Aegis (ключ вводится вручную)."""
    from urllib.parse import quote
    return ("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d"
            % (quote(issuer), quote(label), seed_b32, quote(issuer), TOTP_DIGITS, TOTP_STEP))


# ---------------------------------------------------------------- recovery-коды
def gen_recovery_codes(n=10):
    """-> (list_plain, list_hashes). Plain показываем один раз, храним хеши."""
    plain = ["-".join(secrets.token_hex(2) for _ in range(2)) for _ in range(n)]  # xxxx-xxxx
    return plain, [hashlib.sha256(code.encode()).hexdigest() for code in plain]


def recovery_match(code, hashes):
    """-> индекс совпавшего хеша или -1 (одноразовость обеспечивает вызывающий)."""
    h = hashlib.sha256((code or "").strip().encode()).hexdigest()
    for i, stored in enumerate(hashes):
        if stored and hmac.compare_digest(stored, h):
            return i
    return -1


# --------------------------------------------------------------------- сессии
def new_session_token():
    return secrets.token_urlsafe(32)


def new_csrf_token():
    return secrets.token_urlsafe(24)


class AuthStore:
    """Сессии и антибрут в state.db. Схема создаётся идемпотентно."""

    def __init__(self, conn):
        self.conn = conn
        conn.execute("""CREATE TABLE IF NOT EXISTS session(
            token TEXT PRIMARY KEY, created REAL, expires REAL, src_ip TEXT, csrf TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS loginfail(
            src_ip TEXT PRIMARY KEY, fails INTEGER, banned_until REAL, waves INTEGER DEFAULT 0)""")
        conn.commit()

    # -- сессии --
    def create_session(self, src_ip, now=None):
        now = now if now is not None else time.time()
        token, csrf = new_session_token(), new_csrf_token()
        self.conn.execute("INSERT INTO session(token, created, expires, src_ip, csrf) VALUES(?,?,?,?,?)",
                          (token, now, now + SESSION_TTL, src_ip, csrf))
        self.conn.commit()
        return token, csrf

    def get_session(self, token, now=None):
        if not token:
            return None
        now = now if now is not None else time.time()
        row = self.conn.execute("SELECT token, expires, src_ip, csrf FROM session WHERE token=?",
                                (token,)).fetchone()
        if not row:
            return None
        if row[1] < now:
            self.destroy_session(token)
            return None
        return {"token": row[0], "expires": row[1], "src_ip": row[2], "csrf": row[3]}

    def destroy_session(self, token):
        self.conn.execute("DELETE FROM session WHERE token=?", (token,))
        self.conn.commit()

    def gc(self, now=None):
        now = now if now is not None else time.time()
        self.conn.execute("DELETE FROM session WHERE expires < ?", (now,))
        self.conn.commit()

    # -- антибрут --
    def is_banned(self, src_ip, now=None):
        now = now if now is not None else time.time()
        row = self.conn.execute("SELECT banned_until FROM loginfail WHERE src_ip=?", (src_ip,)).fetchone()
        if row and row[0] and row[0] > now:
            return int(row[0] - now)
        return 0

    def record_fail(self, src_ip, now=None):
        """-> (fails, ban_seconds|0). При достижении порога — бан, счётчик неудач сбрасывается."""
        now = now if now is not None else time.time()
        row = self.conn.execute("SELECT fails, waves FROM loginfail WHERE src_ip=?", (src_ip,)).fetchone()
        fails = (row[0] if row else 0) + 1
        waves = row[1] if row else 0
        ban = 0
        if fails >= BRUTE_MAX_FAILS:
            waves += 1
            ban = BRUTE_BASE_BAN * waves        # нарастающий бан
            self.conn.execute(
                "INSERT INTO loginfail(src_ip, fails, banned_until, waves) VALUES(?,?,?,?) "
                "ON CONFLICT(src_ip) DO UPDATE SET fails=0, banned_until=?, waves=?",
                (src_ip, 0, now + ban, waves, now + ban, waves))
        else:
            self.conn.execute(
                "INSERT INTO loginfail(src_ip, fails, banned_until, waves) VALUES(?,?,?,?) "
                "ON CONFLICT(src_ip) DO UPDATE SET fails=?",
                (src_ip, fails, 0, waves, fails))
        self.conn.commit()
        return fails, ban

    def record_success(self, src_ip):
        self.conn.execute("DELETE FROM loginfail WHERE src_ip=?", (src_ip,))
        self.conn.commit()


def consume_recovery_code(conn, secrets_path, code):
    """Проверить recovery-код и вычеркнуть его (одноразовость). -> bool.

    Мутирует secrets.json на диске (os.replace) — вычеркнутый код становится "".
    """
    matched = [False]

    def consume(data):
        admin = data.get("admin") or {}
        hashes = list(admin.get("recovery") or [])
        idx = recovery_match(code, hashes)
        if idx < 0:
            return data
        hashes[idx] = ""
        admin = dict(admin)
        admin["recovery"] = hashes
        data = dict(data)
        data["admin"] = admin
        matched[0] = True
        return data

    # Re-read only after taking the lock.  Therefore exactly one concurrent
    # caller can observe and consume a non-empty hash.
    update_secrets_atomic(secrets_path, consume)
    return matched[0]
