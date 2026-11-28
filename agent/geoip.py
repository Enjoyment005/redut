"""Shared GeoIP cache for the panel, cron and both contours; no VPN dependency."""
import contextlib
import email.utils
import ipaddress
import json
import math
import pathlib
import re
import sqlite3
import subprocess
import time
import uuid

CACHE_PATH = "/var/lib/vpn-panel/geoip.sqlite3"
TTL = 6 * 3600
FAIL_TTL = 300
REQUEST_TIMEOUT = 6
LOOKUP_TIMEOUT = 15
DAILY_BUDGET = 950  # Rolling 24 hours; leave room below the keyless 1000/day limit.
MAX_BODY = 65536
SOURCES = ("ip2location", "ipwho.is")
URLS = {"ip2location": "https://api.ip2location.io/?ip=%s",
        "ipwho.is": "https://ipwho.is/%s"}
FIELDS = ("cc", "region", "city", "tz", "isp", "org", "asn", "asname",
          "ptr", "mobile", "proxy", "hosting", "lat", "lon", "src",
          "geo_checked_at", "geo_status", "geo_sources")


def _ip(value):
    try:
        addr = ipaddress.ip_address(value)
        return str(addr) if addr.is_global else None
    except (ValueError, TypeError):
        return None


def _text(value):
    return value.strip()[:200] if isinstance(value, str) and value.strip() else None


def _coord(value, limit):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
        return number if math.isfinite(number) and abs(number) <= limit else None
    except (ValueError, TypeError, OverflowError):
        return None


def parse(source, data, ip):
    """Accept only a successful response for the requested public IP."""
    if not isinstance(data, dict) or data.get("error") or _ip(data.get("ip")) != ip:
        return None
    cc = _text(data.get("country_code"))
    if not cc or not re.fullmatch(r"[A-Za-z]{2}", cc) or cc.upper() in ("ZZ", "XX"):
        return None
    if source == "ip2location":
        asn, name = data.get("asn"), _text(data.get("as"))
        out = {"cc": cc.lower(), "region": _text(data.get("region_name")),
               "city": _text(data.get("city_name")), "tz": _text(data.get("time_zone")),
               "isp": None, "org": name, "asname": name}
    elif source == "ipwho.is" and data.get("success") is True:
        conn = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        zone = data.get("timezone") if isinstance(data.get("timezone"), dict) else {}
        asn = conn.get("asn")
        out = {"cc": cc.lower(), "region": _text(data.get("region")),
               "city": _text(data.get("city")), "tz": _text(zone.get("id")),
               "isp": _text(conn.get("isp")), "org": _text(conn.get("org")),
               "asname": _text(conn.get("org"))}
    else:
        return None
    asn = str(asn or "").upper().removeprefix("AS")
    out.update(asn="AS" + asn if asn.isdigit() and 0 < int(asn) <= 4294967295 else None,
               lat=_coord(data.get("latitude"), 90), lon=_coord(data.get("longitude"), 180),
               src=source, ptr=None, mobile=None, proxy=None, hosting=None)
    # Free IP2Location detects open proxies only. False is not proof of "not a VPN".
    if source == "ip2location" and data.get("is_proxy") is True:
        out["proxy"] = True
    return out


def _retry_seconds(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            seconds = email.utils.parsedate_to_datetime(value).timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            return 86400
    return min(7 * 86400, max(60, seconds)) if math.isfinite(seconds) else 86400


def _request(source, ip, timeout):
    """curl gives DNS/connect/body one total deadline; redirects/proxies are disabled."""
    try:
        result = subprocess.run([
            "curl", "-q", "-sS", "--noproxy", "*", "--proto", "=https",
            "--connect-timeout", str(min(3, timeout)), "--max-time", str(timeout),
            "--max-filesize", str(MAX_BODY), "--dump-header", "-",
            "--user-agent", "REDUT GeoIP/1.0", "--header", "Accept: application/json",
            URLS[source] % ip], capture_output=True, timeout=timeout + 1)
        if result.returncode or len(result.stdout) > MAX_BODY + 8192:
            return None, "unavailable", 0
        head, body = result.stdout.split(b"\r\n\r\n", 1)
        status = int(head.splitlines()[0].split()[1])
        if status == 429:
            headers = {k.strip().lower(): v.strip() for line in head.decode("ascii", "replace").splitlines()[1:]
                       if ":" in line for k, v in [line.split(":", 1)]}
            return None, "rate-limited", _retry_seconds(headers.get("retry-after"))
        if status != 200 or len(body) > MAX_BODY:
            return None, "unavailable", 0
        parsed = parse(source, json.loads(body), ip)
        return parsed, "ok" if parsed else "invalid-response", 0
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError, TypeError):
        return None, "unavailable", 0


@contextlib.contextmanager
def _database():
    path = pathlib.Path(CACHE_PATH)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=0.3)
    try:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS answer (
                source TEXT, ip TEXT, body TEXT, checked REAL DEFAULT 0,
                expires REAL DEFAULT 0, lease TEXT, lease_until REAL DEFAULT 0,
                PRIMARY KEY(source, ip));
            CREATE TABLE IF NOT EXISTS service (
                source TEXT PRIMARY KEY, failures INTEGER, retry_at REAL);
            CREATE TABLE IF NOT EXISTS request (source TEXT, at REAL);
            CREATE INDEX IF NOT EXISTS request_source_time ON request(source, at);
        """)
        yield conn
    finally:
        conn.close()


def _claim(source, ip, refresh_since=None, cached_only=False):
    """Reserve a request and its quota in one short transaction, never during HTTP."""
    with _database() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        now = time.time()
        row = conn.execute("SELECT * FROM answer WHERE source=? AND ip=?", (source, ip)).fetchone()
        if (row and 0 <= now - row["checked"] < TTL and row["expires"] > now
                and (refresh_since is None or row["checked"] >= refresh_since)):
            try:
                data = json.loads(row["body"]) if row["body"] else None
                if data is None or (isinstance(data, dict) and data.get("src") == source
                                    and re.fullmatch(r"[a-z]{2}", str(data.get("cc", "")))):
                    return "hit", data
            except (ValueError, TypeError):
                pass
        if cached_only:
            return "skip", None
        if row and row["lease_until"] > now:
            return "wait", None
        state = conn.execute("SELECT * FROM service WHERE source=?", (source,)).fetchone()
        if state and state["retry_at"] > now:
            return "skip", None
        conn.execute("DELETE FROM request WHERE at <= ?", (now - 86400,))
        used = conn.execute("SELECT count(*) FROM request WHERE source=?", (source,)).fetchone()[0]
        if used >= DAILY_BUDGET:
            return "skip", None
        token = uuid.uuid4().hex
        conn.execute("DELETE FROM answer WHERE expires < ? AND lease_until < ?", (now - 86400, now))
        conn.execute("INSERT INTO request VALUES (?, ?)", (source, now))
        conn.execute("INSERT INTO answer (source,ip,lease,lease_until) VALUES (?,?,?,?) "
                     "ON CONFLICT(source,ip) DO UPDATE SET lease=excluded.lease,lease_until=excluded.lease_until",
                     (source, ip, token, now + REQUEST_TIMEOUT + 3))
        return "fetch", token


def _store(source, ip, token, data, status, retry):
    now = time.time()
    if data:
        data = dict(data, geo_checked_at=now)
    with _database() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT body,checked,expires FROM answer WHERE source=? AND ip=? AND lease=?",
                           (source, ip, token)).fetchone()
        if not data and old and old[0] and 0 <= now - old[1] < TTL and old[2] > now:
            # A failed forced recheck cannot erase still-valid evidence,
            # especially a known blocked country. It does not extend its TTL.
            updated = conn.execute("UPDATE answer SET lease=NULL,lease_until=0 WHERE source=? AND ip=? AND lease=?",
                                   (source, ip, token))
        else:
            updated = conn.execute(
                "UPDATE answer SET body=?, checked=?, expires=?, lease=NULL, lease_until=0 "
                "WHERE source=? AND ip=? AND lease=?",
                (json.dumps(data) if data else None, now, now + (TTL if data else FAIL_TTL), source, ip, token))
        if updated.rowcount:
            state = conn.execute("SELECT failures, retry_at FROM service WHERE source=?", (source,)).fetchone()
            failures = 0 if data else (state[0] if state else 0) + 1
            cooldown = retry if status == "rate-limited" else (min(300, 60 * failures) if failures else 0)
            # Another in-flight request may have received 429. A success cannot
            # cancel that source-wide Retry-After interval.
            retry_at = max(now + cooldown, state[1] if state else 0)
            conn.execute("INSERT OR REPLACE INTO service VALUES (?,?,?)", (source, failures, retry_at))
    return data


def _source(source, ip, deadline, refresh=False, cached_only=False):
    started = time.time() if refresh else None
    try:
        while True:
            action, value = _claim(source, ip, started, cached_only)
            if action in ("hit", "skip"):
                return value
            remaining = deadline - time.monotonic()
            if action == "fetch":
                if remaining <= 0:
                    return _store(source, ip, value, None, "unavailable", 0)
                data, status, retry = _request(source, ip, min(REQUEST_TIMEOUT, remaining))
                return _store(source, ip, value, data, status, retry)
            if remaining <= 0:
                return None
            time.sleep(min(0.05, remaining))
    except (OSError, sqlite3.Error):
        # Without a shared quota store, fail closed for HTTP, not for VPN health.
        return None


def _result(first, second):
    empty = {"cc": None, "alt": None, "agree": True, "status": "unavailable", "intel": None}
    chosen = first or second
    if not chosen:
        return empty
    agree = not (first and second and first["cc"] != second["cc"])
    status = ("confirmed" if agree else "conflict") if first and second else "single-source"
    intel = dict(chosen, geo_status=status,
                 geo_sources={d["src"]: d["cc"] for d in (first, second) if d})
    return {"cc": chosen["cc"], "alt": second["cc"] if first and second else None,
            "agree": agree, "status": status, "intel": intel}


def cached(ip):
    """Read current metadata for status/pool without HTTP, writes or quota usage."""
    ip = _ip(ip)
    answers = {}
    if ip:
        try:
            uri = pathlib.Path(CACHE_PATH).resolve().as_uri() + '?mode=ro'
            with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=0.1)) as conn:
                now = time.time()
                for source, body in conn.execute(
                        'SELECT source,body FROM answer WHERE ip=? AND checked<=? AND checked>? AND expires>?',
                        (ip, now, now - TTL, now)):
                    data = json.loads(body) if body else None
                    if (source in SOURCES and isinstance(data, dict) and data.get('src') == source
                            and re.fullmatch(r'[a-z]{2}', str(data.get('cc', '')))):
                        answers[source] = data
        except (OSError, sqlite3.Error, ValueError, TypeError):
            pass
    return _result(*(answers.get(source) for source in SOURCES))


def lookup(ip, consensus=False, refresh=False):
    """One selected country/city record plus evidence; unavailable is not a VPN fault."""
    ip = _ip(ip)
    if not ip:
        return _result(None, None)
    deadline = time.monotonic() + LOOKUP_TIMEOUT
    first = _source(SOURCES[0], ip, deadline, refresh=refresh)
    second = _source(SOURCES[1], ip, deadline, refresh=refresh,
                     cached_only=bool(first and not consensus))
    return _result(first, second)
