#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup_admin.py — создать/пересоздать учётку админа панели (§11).

Генерирует пароль (или берёт --password), TOTP-seed и 10 recovery-кодов, кладёт в
secrets.json блок "admin" (pw=scrypt-хеш, totp=base32-seed, recovery=sha256-хеши) и
печатает секреты ОДИН РАЗ — сохрани их. Пароль/коды в открытом виде на диск не пишутся.

  python3 webpanel/setup_admin.py                       # /etc/vpn-panel/secrets.json
  python3 webpanel/setup_admin.py --secrets ../.secrets.local.json --label dev --force
  python3 webpanel/setup_admin.py --password 'своя-фраза'
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webpanel import auth  # noqa: E402

DEFAULT_SECRETS = "/etc/vpn-panel/secrets.json"
DEFAULT_CONFIG = "/etc/vpn-panel/config.json"
DEFAULT_STATE_DB = "/var/lib/vpn-panel/state.db"
PANEL_UNIT = "vpn-panel"


def restart_panel(secrets_path):
    """Перезапустить панель после смены секретов. -> True, если перезапустили.

    Панель кэширует secrets в памяти (server.App._load_secrets) и после сброса
    принимает СТАРЫЙ пароль, пока её не перезапустят — живой случай 19.08 на node1.
    Рестартуем только боевой файл узла и только активный юнит: dev-файл (--secrets)
    живую панель не трогает, а незапущенной панели кэшировать нечего. Любая ошибка
    -> False, main() печатает прежнее напоминание.
    """
    if os.name != "posix":
        return False
    try:
        if os.path.realpath(secrets_path) != os.path.realpath(DEFAULT_SECRETS):
            return False
        p = subprocess.run(["systemctl", "is-active", PANEL_UNIT],
                           capture_output=True, text=True, timeout=10)
        if (p.stdout or "").strip() != "active":
            return False
        p = subprocess.run(["systemctl", "restart", PANEL_UNIT],
                           capture_output=True, text=True, timeout=60)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolve_state_db(secrets_path, explicit=None):
    if explicit:
        return os.path.abspath(explicit)
    candidates = []
    env_config = os.environ.get("VPN_PANEL_CONFIG")
    if env_config:
        candidates.append(env_config)
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(secrets_path)), "config.json"))
    if os.path.realpath(secrets_path) == os.path.realpath(DEFAULT_SECRETS):
        candidates.append(DEFAULT_CONFIG)
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as source:
                value = json.load(source).get("db")
            if isinstance(value, str) and value.strip():
                return os.path.abspath(value)
        except (OSError, ValueError, AttributeError):
            pass
    if os.path.realpath(secrets_path) == os.path.realpath(DEFAULT_SECRETS):
        return DEFAULT_STATE_DB
    return os.path.join(os.path.dirname(os.path.abspath(secrets_path)), "state.db")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--secrets", default=DEFAULT_SECRETS)
    ap.add_argument("--label", default="vpn-panel", help="метка для TOTP (обычно имя сервера)")
    ap.add_argument("--password", help="задать пароль (иначе сгенерируется)")
    ap.add_argument("--force", action="store_true", help="перезаписать существующего админа")
    ap.add_argument("--state-db", help="точный state.db панели (по умолчанию из config.json)")
    a = ap.parse_args(argv)

    import secrets as _s
    password = a.password or _s.token_urlsafe(12)
    seed = auth.totp_new_seed()
    recovery_plain, recovery_hashes = auth.gen_recovery_codes(10)
    password_hash = auth.hash_password(password)

    state_db = resolve_state_db(a.secrets, a.state_db)
    os.makedirs(os.path.dirname(state_db) or ".", exist_ok=True)
    conn = sqlite3.connect(state_db, timeout=30)
    try:
        store = auth.AuthStore(conn)
        auth.write_admin_credentials_atomic(a.secrets, {"admin": {
            "pw": password_hash, "totp": seed, "recovery": recovery_hashes,
        }}, store, force=a.force)
    finally:
        conn.close()
    auth.consume_bootstrap_secret(
        os.path.join(os.path.dirname(os.path.abspath(a.secrets)), "bootstrap.json"))

    print("=" * 60)
    print("АДМИН ПАНЕЛИ НАСТРОЕН — сохрани эти данные, они больше не покажутся")
    print("=" * 60)
    if not a.password:
        print("Пароль:       %s" % password)
    else:
        print("Пароль:       (задан вручную)")
    print("TOTP-seed:    %s   (ключ для Google Authenticator / Aegis, тип «время»)" % seed)
    print("otpauth URI:  %s" % auth.totp_uri(seed, a.label))
    print("Recovery-коды (одноразовые, 10 шт.):")
    for i, code in enumerate(recovery_plain, 1):
        print("   %2d. %s" % (i, code))
    print("=" * 60)
    if restart_panel(a.secrets):
        print("Файл: %s (0600). vpn-panel перезапущена — вход сразу по новым данным." % a.secrets)
    else:
        print("Файл: %s (0600). Перезапусти vpn-panel, если работает." % a.secrets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
