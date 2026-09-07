"""Canonical base compatibility and DNS admission shared by install paths."""

import sys

BASE_CONTRACT_MARKER = "# REDUT_BASE_CONTRACT=2"
BASE_RUNTIME_FILES = (
    "/usr/local/bin/singbox-watchdog.sh",
    "/usr/local/bin/singbox-post.sh",
    "/usr/local/bin/vpn-boot-setup.sh",
    "/usr/local/bin/server_cleanup.sh",
)


DNS_PREFLIGHT_PROGRAM = """import json, os, sqlite3, subprocess, sys
config_path = "/etc/vpn-panel/config.json"
default_db = "/var/lib/vpn-panel/state.db"
installed = os.path.lexists("/opt/vpn-panel/VERSION")
config_exists = os.path.lexists(config_path)
if config_exists:
    try:
        with open(config_path, encoding="utf-8") as source:
            config = json.load(source)
    except Exception as error:
        sys.exit("installed config is unreadable: %s" % type(error).__name__)
    db = config.get("db") or default_db
    if not isinstance(db, str) or not os.path.isabs(db):
        sys.exit("installed config has invalid DNS database path")
else:
    if installed:
        sys.exit("installed node has no readable config")
    db = default_db
probe = subprocess.run(
    ["systemctl", "is-active", "redut-dns-rescue"], capture_output=True,
    text=True, timeout=10)
raw = (probe.stdout or probe.stderr or "").strip().splitlines()[-1:] or [""]
load_probe = subprocess.run(
    ["systemctl", "show", "redut-dns-rescue", "-p", "LoadState", "--value"],
    capture_output=True, text=True, timeout=10)
load = load_probe.stdout.strip()
if load == "not-found":
    state = "not-found"
elif load == "loaded" and raw[0] in ("active", "inactive", "failed",
                                      "activating", "deactivating"):
    state = raw[0]
else:
    sys.exit("DNS Rescue unit state is unreadable")
if not config_exists and state != "not-found":
    sys.exit("loaded DNS unit has no readable config")
if state not in ("inactive", "failed", "not-found"):
    sys.exit("DNS Rescue unit is active or transitional: %s" % state)
if os.path.lexists(db) and not os.path.isfile(db):
    sys.exit("DNS state database exists but is not a readable regular file")
if not os.path.isfile(db):
    if state != "not-found":
        sys.exit("installed DNS unit has no readable state database")
    phase = "idle"
else:
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=2.0)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='dns_rescue_state'").fetchone()
            if exists:
                row = conn.execute(
                    "SELECT phase FROM dns_rescue_state WHERE singleton=1").fetchone()
                if not row or not isinstance(row[0], str) or not row[0].strip():
                    sys.exit("DNS Rescue state singleton/phase is missing")
                phase = row[0]
            else:
                phase = None
        finally:
            conn.close()
    except Exception as error:
        sys.exit("DNS state database is unreadable: %s" % type(error).__name__)
    if phase is None and state != "not-found":
        sys.exit("DNS Rescue state table is missing for an installed unit")
if phase is None:
    phase = "idle"
if phase != "idle":
    sys.exit("DNS Rescue generation is not idle (phase=%s unit=%s)" % (phase, state))
print("REDUT_DNS_PREFLIGHT_OK")
"""


def remote_check_command():
    checks = ["grep -Fqx %s %s" % (_quote(BASE_CONTRACT_MARKER), _quote(path))
              for path in BASE_RUNTIME_FILES]
    return " && ".join(checks) + " && echo REDUT_BASE_CONTRACT_OK"


def remote_dns_preflight_command():
    """Early remote check; fresh hosts may not have Python installed yet."""
    fresh = (
        '[ "$(systemctl show redut-dns-rescue -p LoadState --value 2>/dev/null)" '
        '= not-found ] '
        '&& [ ! -e /etc/vpn-panel/config.json ] && [ ! -L /etc/vpn-panel/config.json ] '
        '&& [ ! -e /opt/vpn-panel/VERSION ] && [ ! -L /opt/vpn-panel/VERSION ] '
        '&& [ ! -e /var/lib/vpn-panel/state.db ] && [ ! -L /var/lib/vpn-panel/state.db ]')
    return (
        "if %s; then echo REDUT_DNS_PREFLIGHT_OK; "
        "elif command -v python3 >/dev/null 2>&1; then python3 -c %s; "
        "else echo 'installed Redut state requires python3 preflight' >&2; exit 1; fi"
        % (fresh, _quote(DNS_PREFLIGHT_PROGRAM)))


def _quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


if __name__ == "__main__":
    if sys.argv[1:] != ["--dns-preflight"]:
        raise SystemExit("usage: base_manifest.py --dns-preflight")
    exec(DNS_PREFLIGHT_PROGRAM, {})
