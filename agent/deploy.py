#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deploy.py — штатный деплой vpn-agent (+ веб-панель) на сервер по SSH (paramiko).

Раскладывает по путям §13/§14:
  /opt/vpn-panel/{agent.py,pool.py,probe.py,apply.py,providers/,webpanel/}
  /etc/vpn-panel/{config.json(root 0644), secrets.json(0600)}
  /var/lib/vpn-panel/{state.db, cfg/}
  /usr/local/bin/vpn-agent            (обёртка над agent.py)
  /etc/systemd/system/vpn-panel.service   (--with-panel)

НЕ трогает sing-box/upstream: только файлы + init БД. Живую смену upstream делает
сам агент (apply/rollback), не деплой.

Секреты провайдеров берёт из panel/.secrets.local.json (локально, не в репо).
Пароли SSH — как в scripts/set_upstream.py.

Примеры:
  python deploy.py node1                 # агент на node1
  python deploy.py node1 --with-panel    # агент + веб-панель + systemd
  python deploy.py ru --dry-run          # показать план, не заливать
  python deploy.py ru --with-panel --clean --keep-config   # обновить код на живом узле:
                                         # config.json и secrets.json не трогаем

Обновление УЗЛА, поставленного `setup.sh` со своим профилем (так поставлен node2):
только `--keep-config` — иначе SERVERS ниже перезапишет ему server/role/subnet, а роль
это привязка прокси в пуле. Плюс `--clean`, чтобы не перетереть secrets.json, который
владелец заполнил в мастере /setup (ключ провайдера, 2FA, SMTP).
"""
import argparse
import contextlib
import hashlib
import json
import os
import secrets
import shlex
import stat
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = os.path.abspath(os.path.join(PANEL_DIR, os.pardir, "install"))
if INSTALL_DIR not in sys.path:
    sys.path.insert(0, INSTALL_DIR)
from base_manifest import (DNS_PREFLIGHT_PROGRAM as REMOTE_DNS_PREFLIGHT_PROGRAM,
                           remote_check_command, remote_dns_preflight_command)  # noqa: E402

try:
    import paramiko
except ImportError:
    sys.exit("Нужен paramiko: pip install paramiko")

# host, [пароли], серверный конфиг агента (§16)
SERVERS = {}


def _load_servers():
    """Список серверов — из servers.json рядом с этим файлом (в репозиторий НЕ кладём).

    Формат — см. servers.example.json. Пароли/хосты держим вне кода: так их
    невозможно случайно закоммитить, а сам файл легко положить в менеджер секретов.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "servers.json")
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SERVERS.update(_load_servers())
# Прежнее имя цели — чтобы старые команды не отвалились. Условно: в публичной
# сборке SERVERS приходит из servers.json, и безусловный алиас ронял бы импорт
# модуля KeyError'ом у пользователя без ключа "node2" (найдено на ревью Ф0).
if "node2" in SERVERS:
    SERVERS["ru"] = SERVERS["node2"]

BASE_CONFIG = {
    "singbox_config": "/etc/sing-box/config.json",
    "boot_script": "/usr/local/bin/vpn-boot-setup.sh",
    # ПОЛНЫЙ путь обязателен: агент запускается из cron, где PATH урезан до
    # /usr/bin:/bin, а бинарь лежит в /usr/local/bin. С коротким именем
    # subprocess падал с [Errno 2] -> «sing-box check забраковал кандидата»,
    # ротация не могла применить НИ ОДИН прокси и уводила узел в EMERGENCY (15.08).
    "singbox_bin": "/usr/local/bin/sing-box",
    "lock": "/run/vpn-agent.lock",
}

# Рамки трат и страны (§6.1/§6.2). Пишутся в /etc/vpn-panel/config.json (root:root
# 0644). ⚠️ Правятся ТОЛЬКО по SSH, из веба недоступны. При редеплое НЕ
# перетираются, если владелец уже настроил их на сервере (см. main()).
MONEY_CONFIG = {
    "money": {
        "buy_enabled": True, "delete_enabled": False,
        "max_buys_per_day": 3, "max_spend_per_day": 300,
        "max_price_per_buy": 150, "min_balance_reserve": 300,
        "buy_period_days": 7, "buy_version": 4, "currency": "RUB",
    },
    "countries": {
        # ЧЁРНЫЙ СПИСОК — «никогда»: Россия, Украина, Беларусь зашиты в коде
        # (country.BLACKLIST_CC) и отсюда не убираются. Здесь можно только
        # ДОБАВИТЬ страны, которые не хочешь покупать вообще.
        "blacklist": [],
        # Белого списка стран больше нет (приёмка №7, 17.08): страны оценивает
        # внутренний рейтинг (country.reputation), порядок «ближние первыми» —
        # константа providers.base.DEFAULT_COUNTRY_ORDER; вручную можно купить
        # любую страну вне чёрного списка. Старый ключ countries.whitelist в
        # конфигах узлов просто игнорируется.
        # СТРАТЕГИЯ (17.08): насколько сильно страна влияет на выбор. Переключается
        # в панели, значения — country.STRATEGIES. По умолчанию speed; к нему же
        # возвращается ручной канал после подтверждённого отказа.
        "strategy": "speed",
    },
    # Свежесть измерений и гистерезис проактивной смены стратегии. Аварийная
    # ротация при подтверждённом отказе эти ограничения не использует.
    "health": {
        "fresh_seconds": 7200, "stale_seconds": 86400,
        "switch_margin": 15, "min_hold_time": 1800,
        "max_latency_regression": 500,
        "quorum_window_seconds": 60, "quorum_min_targets": 2,
    },
    # Learning v2 только считает shadow-рекомендации. owner_approved — readiness
    # gate для будущего canary; actuator на этом релизе намеренно не подключён.
    "learning": {"mode": "shadow", "shadow_min_days": 30,
                 "owner_approved": False, "canary_servers": [],
                 "exploration_enabled": False, "exploration_rate": 0.05,
                 "exploration_max_per_day": 1,
                 "exploration_purchase_budget_per_day": 0.0},
    # Автопродление «якоря» (решение владельца 15.08). Продление и покупка стоят
    # одинаково (4 ₽/сутки), но новый IP — холодный: перелогины, капчи, проверки
    # оплаты. Поэтому здоровый боевой адрес держим, а ротация — аварийная мера.
    "auto_prolong": {
        "enabled": True,
        "days_before": 3,      # продлеваем за 3 дня до конца, не в последний час
        "period_days": 30,     # 120 ₽ — влезает в лимит max_price_per_buy=150
    },
    # Самообновление с GitHub (vpn/UPDATE-PLAN.md): auto переключается в панели,
    # окно/частота/repo — по SSH. При редеплое блок НЕ перетирается (см. main).
    "update": {"auto": True, "window": "04:00-06:00", "repo": "Enjoyment005/redut"},
    # Обучение стабильности (F8, 1.3.0): порог — по объёму данных, не календарный.
    # Вклад пары (провайдер, страна) в выбор покупки начинается с min_probes/min_days,
    # полный вес — к full_probes/full_days. Правится только по SSH.
    "stability": {"min_probes": 300, "min_days": 21, "full_probes": 1000, "full_days": 60},
}

OPT = "/opt/vpn-panel"
# update.py — ПЕРВЫМ: agent.py его импортирует, и на живом узле между заливкой
# файлов есть окно, где тик крона (pool-refresh/heartbeat) поймал бы ImportError.
AGENT_FILES = ["update.py", "config_store.py", "config_schema.py", "health.py", "learning.py",
               "metrics.py", "replay.py",
               "dns_probe.py", "dns_evidence.py", "dns_runtime.py", "dns_rescue.py",
               "agent.py", "pool.py", "probe.py", "apply.py", "money.py", "proxywing_orders.py", "proxyline_orders.py",
               "auto_purchase.py", "states.py", "alerts.py", "country.py",
               "providers/__init__.py", "providers/base.py",
               "providers/proxyline.py", "providers/proxy6.py", "providers/proxywing.py"]
# sysinfo.py — ДО server.py: тот его импортирует, окно между копиями на живом
# узле не должно ловить ImportError при рестарте панели (случай node1 19.08)
PANEL_FILES = ["webpanel/__init__.py", "webpanel/auth.py", "webpanel/sysinfo.py",
               "webpanel/hygiene.py",
               "webpanel/server.py", "webpanel/views.py", "webpanel/setup_admin.py",
               "webpanel/clients.py", "webpanel/qrcode.py"]

WRAPPER = "#!/bin/bash\nexec python3 /opt/vpn-panel/agent.py \"$@\"\n"


def gen_cert_cmd(host):
    """Self-signed по IP (Let's Encrypt не используем — доступ по IP, не по домену).

    IP в subjectAltName обязателен: браузеры для доступа по IP игнорируют CN.
    Срок 10 лет — авто-продления нет, протухать незачем.
    """
    return ("openssl req -x509 -newkey rsa:2048 -nodes "
            "-keyout /etc/vpn-panel/panel.key -out /etc/vpn-panel/panel.crt "
            "-days 3650 -subj '/CN=%s' -addext 'subjectAltName=IP:%s' 2>&1; "
            "chmod 600 /etc/vpn-panel/panel.key" % (host, host))

PANEL_SERVICE = """[Unit]
Description=vpn-panel (stdlib web UI over vpn-agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vpn-panel/webpanel/server.py
Restart=always
RestartSec=3
# Панель работает от root: apply/rollback правят /etc/sing-box и маршруты.
# Ограничители ущерба — в приложении (лимиты вне веба, тумблеры, TOTP).
MemoryMax=512M
TasksMax=64
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"""


def connect(host, pwds):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last = None
    for pw in pwds:
        try:
            c.connect(host, username="root", password=pw, timeout=25,
                      allow_agent=False, look_for_keys=False)
            return c
        except Exception as e:
            last = e
    raise SystemExit("SSH к %s недоступен: %s" % (host, last))


def run_result(c, cmd, t=180):
    _, o, e = c.exec_command(cmd, timeout=t)
    stdout = o.read().decode("utf-8", "replace")
    stderr = e.read().decode("utf-8", "replace")
    rc = o.channel.recv_exit_status()
    return rc, (stdout + stderr).strip()


def run(c, cmd, t=180):
    return run_result(c, cmd, t=t)[1]


def activate_panel(c, port, wait_s=20):
    """Require both successful systemd activation and a ready HTTPS endpoint."""
    rc, detail = run_result(
        c, "systemctl daemon-reload && systemctl enable vpn-panel && "
           "systemctl restart vpn-panel && systemctl is-active vpn-panel")
    if rc != 0 or detail.strip().splitlines()[-1:] != ["active"]:
        raise SystemExit("панель не запущена: %s" % (detail or "rc=%s" % rc))
    deadline = time.monotonic() + wait_s
    while True:
        rc, detail = run_result(
            c, "curl -fsk --max-time 5 https://127.0.0.1:%d/healthz" % int(port), t=10)
        if rc == 0 and detail.strip() == "ok":
            return
        if time.monotonic() >= deadline:
            raise SystemExit("панель не прошла HTTPS /healthz: %s"
                             % (detail or "rc=%s" % rc))
        time.sleep(1)


def _remove_own_staging(sftp, path):
    """Best-effort removal of only our root-owned private regular staging file."""
    try:
        attrs = sftp.lstat(path)
        if (stat.S_ISREG(attrs.st_mode)
                and stat.S_IMODE(attrs.st_mode) == 0o600
                and getattr(attrs, "st_uid", None) == 0):
            sftp.remove(path)
    except Exception:
        pass


def _write_secret_staging(sftp, path, data):
    """Create an exclusive 0600 regular file before writing the first secret byte."""
    target = None
    try:
        target = sftp.open(path, "wx")
        # FSETSTAT/FSTAT apply to the inode that this handle will write.  A
        # path-based chmod/lstat pair would check a replaceable directory entry.
        target.chmod(0o600)
        attrs = target.stat()
        if (not stat.S_ISREG(attrs.st_mode)
                or stat.S_IMODE(attrs.st_mode) != 0o600
                or getattr(attrs, "st_uid", None) != 0):
            raise OSError("secret staging has unsafe type, owner or mode")
        target.write(data)
        target.flush()
    except Exception:
        if target is not None:
            try:
                target.close()
            except Exception:
                pass
        _remove_own_staging(sftp, path)
        raise
    else:
        target.close()


SECRET_WRITER_PROGRAM = """import json, os, stat, sys, tempfile, time
p, s, keep_admin = sys.argv[1:4]
directory = os.path.dirname(p) or "."
def read_private(path, missing_ok=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        attrs = os.fstat(source.fileno())
        if (not stat.S_ISREG(attrs.st_mode) or stat.S_IMODE(attrs.st_mode) != 0o600
                or attrs.st_uid != 0):
            raise OSError("secret source has unsafe type, owner or mode")
        return json.load(source)
def cleanup_stale():
    merge_prefix = "." + os.path.basename(p) + ".redut-secrets-merge-"
    prefixes = (os.path.basename(p) + ".deploy-", merge_prefix)
    cutoff = time.time() - 3600
    for name in os.listdir(directory):
        candidate = os.path.join(directory, name)
        if candidate == s or not name.startswith(prefixes):
            continue
        try:
            attrs = os.lstat(candidate)
            if (stat.S_ISREG(attrs.st_mode) and attrs.st_uid == 0
                    and stat.S_IMODE(attrs.st_mode) == 0o600 and attrs.st_mtime < cutoff):
                os.unlink(candidate)
        except FileNotFoundError:
            pass
cleanup_stale()
new = read_private(s)
if not isinstance(new, dict):
    raise ValueError("secret payload must be a JSON object")
if keep_admin == "1":
    cur = read_private(p, missing_ok=True)
    if not isinstance(cur, dict):
        raise ValueError("existing secrets must be a JSON object")
    new["admin"] = cur["admin"] if cur.get("admin") else new.get("admin")
    if new.get("admin") is None:
        new.pop("admin", None)
directory = os.path.dirname(p) or "."
merge_prefix = "." + os.path.basename(p) + ".redut-secrets-merge-"
fd, out = tempfile.mkstemp(prefix=merge_prefix, dir=directory)
opened = True
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        opened = False
        json.dump(new, target, ensure_ascii=False, indent=2)
        target.write("\\n")
        target.flush()
        os.fsync(target.fileno())
    with open(out, encoding="utf-8") as check:
        attrs = os.fstat(check.fileno())
        if stat.S_IMODE(attrs.st_mode) != 0o600 or json.load(check) != new:
            raise OSError("secret staging verification failed")
    os.replace(out, p)
    out = None
    os.chmod(p, 0o600)
    attrs = os.lstat(p)
    if not stat.S_ISREG(attrs.st_mode) or stat.S_IMODE(attrs.st_mode) != 0o600 or attrs.st_uid != 0:
        raise OSError("installed secret has unsafe type, owner or mode")
    with open(p, encoding="utf-8") as check:
        if json.load(check) != new:
            raise OSError("installed secret verification failed")
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    os.unlink(s)
    print("REDUT_SECRET_WRITE_OK")
finally:
    if opened:
        os.close(fd)
    if out is not None:
        try:
            os.unlink(out)
        except FileNotFoundError:
            pass
"""


def put_secret_atomic(c, sftp, path, data, preserve_admin=False):
    """Upload a 0600 secret through the same adjacent writer lock as panel."""
    incoming = json.loads(data)
    if not isinstance(incoming, dict):
        raise ValueError("secret payload must be a JSON object")
    tmp = path + ".deploy-" + secrets.token_hex(8)
    complete = False
    try:
        _write_secret_staging(sftp, tmp, data)
        inner = "python3 -c %s %s %s %s" % (
            shlex.quote(SECRET_WRITER_PROGRAM), shlex.quote(path), shlex.quote(tmp),
            "1" if preserve_admin else "0")
        command = "flock -w 30 %s.lock sh -c %s" % (shlex.quote(path), shlex.quote(inner))
        rc, output = run_result(c, command)
        if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_SECRET_WRITE_OK"]:
            detail = output if output else "remote writer returned rc=%s without success marker" % rc
            raise SystemExit("не удалось атомарно записать %s: %s" % (path, detail))
        complete = True
    finally:
        if not complete:
            _remove_own_staging(sftp, tmp)


def put_config_atomic(c, sftp, path, data, preserve_keys):
    """Merge owner settings and replace config through the deployed common writer."""
    incoming = json.loads(data)
    if not isinstance(incoming, dict):
        raise ValueError("config payload must be a JSON object")
    tmp = path + ".deploy-config-" + secrets.token_hex(8)
    complete = False
    try:
        _write_secret_staging(sftp, tmp, data)
        program = """import json, os, sys
sys.path.insert(0, sys.argv[1])
import config_store
p, s = sys.argv[2:4]
preserve = json.loads(sys.argv[4])
incoming = json.load(open(s, encoding="utf-8"))
if not isinstance(incoming, dict):
    raise ValueError("config payload must be a JSON object")
def merge(current):
    result = dict(incoming)
    for key in preserve:
        if isinstance(current.get(key), dict) and current[key]:
            result[key] = current[key]
    return result
written = config_store.update({"_source": p}, merge, create=True)
with open(p, encoding="utf-8") as check:
    if json.load(check) != written:
        raise OSError("installed config verification failed")
os.unlink(s)
print("REDUT_CONFIG_WRITE_OK")
"""
        inner = "python3 -c %s %s %s %s %s" % (
            shlex.quote(program), shlex.quote(OPT), shlex.quote(path), shlex.quote(tmp),
            shlex.quote(json.dumps(list(preserve_keys))))
        rc, output = run_result(c, inner)
        if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_CONFIG_WRITE_OK"]:
            detail = output if output else "remote writer returned rc=%s without success marker" % rc
            raise SystemExit("не удалось атомарно записать %s: %s" % (path, detail))
        complete = True
    finally:
        if not complete:
            _remove_own_staging(sftp, tmp)


@contextlib.contextmanager
def remote_panel_config_upgrade_barrier(c, enabled):
    """Stop a legacy panel while the first common-lock config merge is performed."""
    rc, state = run_result(c, "systemctl is-active vpn-panel") if enabled else (1, "")
    was_running = rc == 0 and state.strip().splitlines()[-1:] in (["active"], ["activating"])
    if was_running:
        stop_rc, detail = run_result(c, "systemctl stop vpn-panel")
        if stop_rc != 0:
            raise SystemExit("не удалось остановить старую панель перед config merge: %s" % detail)
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        if was_running:
            try:
                start_rc, detail = run_result(c, "systemctl start vpn-panel")
            except Exception as error:
                if not failed:
                    raise
                print("  ⚠️ не удалось восстановить панель после ошибки config merge: %s" % error)
            else:
                if start_rc != 0:
                    message = "не удалось восстановить панель после config merge: %s" % detail
                    if not failed:
                        raise SystemExit(message)
                    print("  ⚠️ " + message)


def acquire_remote_network_lock(c):
    """Hold the node-wide non-reentrant lock on a dedicated SSH channel.

    Keeping stdin open keeps `cat` (and therefore fd 9) alive while SFTP and
    systemd files are replaced through other channels on the same connection.
    """
    command = ("bash -c 'exec 9>/run/vpn-agent.lock; "
               "flock -n 9 || { echo REDUT_LOCK_BUSY; exit 75; }; "
               "echo REDUT_LOCKED; cat >/dev/null'")
    stdin, stdout, stderr = c.exec_command(command, timeout=30)
    stdout.channel.settimeout(30)
    marker = stdout.readline().strip()
    if marker != "REDUT_LOCKED":
        detail = stderr.read().decode("utf-8", "replace").strip()
        raise SystemExit("vpn-agent занят; удалённый деплой отложен%s" %
                         ((": " + detail) if detail else ""))
    return stdin


def remote_dns_preflight(c):
    rc, output = run_result(c, remote_dns_preflight_command(), t=30)
    if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_DNS_PREFLIGHT_OK"]:
        raise SystemExit("удалённый DNS Rescue preflight не подтверждён: %s"
                         % (output or "rc=%s" % rc))
    return True


def require_remote_base_contract(c):
    rc, output = run_result(c, remote_check_command(), t=30)
    if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_BASE_CONTRACT_OK"]:
        raise SystemExit(
            "базовые watchdog/post/boot/cleanup несовместимы; "
            "сначала выполни полный UPDATE=1 setup.sh")
    return True


def build_config(name):
    cfg = dict(BASE_CONFIG)
    cfg.update(SERVERS[name]["config"])
    cfg.update(MONEY_CONFIG)   # дефолтные рамки трат/страны (§6.2)
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("server", choices=SERVERS)
    ap.add_argument("--with-panel", action="store_true", help="деплой веб-панели + systemd unit")
    ap.add_argument("--panel-port", type=int, default=8443, help="порт панели (дефолт 8443)")
    ap.add_argument("--regen-cert", action="store_true", help="перевыпустить self-signed cert (SAN=IP)")
    ap.add_argument("--clean", action="store_true",
                    help="чистая установка: секреты (провайдеры/SMTP/2FA/пароль) вводит владелец "
                         "в мастере панели /setup, а не сеются из .secrets.local.json")
    ap.add_argument("--keep-config", action="store_true",
                    help="не трогать /etc/vpn-panel/config.json на узле. Нужен для узлов, "
                         "поставленных setup.sh со своим профилем (node2: server=node2, "
                         "role=vpn-node2): запись SERVERS здесь сбила бы им имя и роль, "
                         "а роль — это привязка прокси в пуле")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    secrets_path = os.path.join(PANEL_DIR, ".secrets.local.json")
    if not a.clean and not os.path.isfile(secrets_path):
        sys.exit("Нет %s — положи ключи провайдеров (не в репо), либо запусти с --clean" % secrets_path)
    cfg = build_config(a.server)
    files = AGENT_FILES + (PANEL_FILES if a.with_panel else [])

    print("=== ДЕПЛОЙ %s (%s) ===" % (a.server, SERVERS[a.server]["host"]))
    print("config.json:\n" + json.dumps(cfg, ensure_ascii=False, indent=2))
    print("файлы (%d): %s" % (len(files), ", ".join(files)))
    if a.with_panel:
        print("панель: vpn-panel.service, порт %d (self-signed TLS)" % a.panel_port)
    if a.dry_run:
        print("\n[dry-run] ничего не залито.")
        return 0

    with contextlib.ExitStack() as resources:
        return _deploy(a, cfg, files, resources)


def _deploy(a, cfg, files, resources):
    """Every exit releases SFTP, the remote network lock and its SSH transport."""
    c = connect(SERVERS[a.server]["host"], SERVERS[a.server]["pw"])
    resources.callback(c.close)
    print("\negress ДО:", run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25),
          "| sing-box:", run(c, "systemctl is-active sing-box"))

    deploy_lock = acquire_remote_network_lock(c)
    resources.callback(deploy_lock.close)
    remote_dns_preflight(c)
    require_remote_base_contract(c)

    # --keep-config means the live file owns the panel port. Resolve and
    # validate it while the network lock is held and before the first upload
    # or other durable remote mutation; otherwise a malformed config can leave
    # a partially replaced application behind and only then abort.
    if a.keep_config and a.with_panel:
        rc, port = run_result(
            c, "python3 -c \"import json; print(json.load(open("
               "'/etc/vpn-panel/config.json')).get('panel_port') or 8443)\"")
        if rc != 0 or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise SystemExit("не удалось прочитать действующий порт панели: %s" % port)
        a.panel_port = int(port)

    if not a.with_panel:
        panel_rc, panel_state = run_result(
            c,
            "if [ \"$(systemctl show -p LoadState --value vpn-panel 2>/dev/null)\" = loaded ] "
            "|| [ -f /opt/vpn-panel/webpanel/server.py ]; then "
            "grep -Fq 'config_store.save_update_auto' /opt/vpn-panel/webpanel/server.py "
            "2>/dev/null || { echo REDUT_LEGACY_PANEL; exit 42; }; fi")
        if panel_rc != 0 or "REDUT_LEGACY_PANEL" in panel_state.splitlines():
            sys.exit("установлена старая vpn-panel; повтори деплой с --with-panel")

    run(c, "mkdir -p %s/providers %s/webpanel /var/lib/vpn-panel/cfg && "
           "install -d -o root -g root -m 0700 /etc/vpn-panel" % (OPT, OPT))
    run(c, "chmod 700 /var/lib/vpn-panel")
    identity_state = run(
        c, "(command -v conntrack >/dev/null 2>&1 || "
           "(apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y conntrack)) && "
           "(getent group redut-dns >/dev/null 2>&1 || groupadd --system redut-dns) && "
           "(id -u redut-dns >/dev/null 2>&1 || useradd --system --gid redut-dns "
           "--home-dir /var/lib/redut-dns-rescue --shell /usr/sbin/nologin redut-dns) && "
           "install -d -o root -g redut-dns -m 0750 /etc/redut-dns-rescue && "
           "install -d -o redut-dns -g redut-dns -m 0700 "
           "/var/lib/redut-dns-rescue /run/redut-dns-rescue && echo REDUT_DNS_IDENTITY_OK")
    if "REDUT_DNS_IDENTITY_OK" not in identity_state.splitlines():
        sys.exit("не удалось подготовить системную учётку redut-dns")
    sftp = c.open_sftp()
    resources.callback(sftp.close)
    for rel in files:
        sftp.put(os.path.join(PANEL_DIR, rel.replace("/", os.sep)), OPT + "/" + rel)
    # Версия узла (vpn/UPDATE-PLAN.md Ф0): её показывают панель и `vpn-agent status`,
    # с ней сверяется self-update. Без копии узел «не знает», что на нём работает.
    ver_src = os.path.join(PANEL_DIR, os.pardir, "VERSION")
    if os.path.isfile(ver_src):
        sftp.put(ver_src, OPT + "/VERSION")
    else:
        print("  ⚠️ нет %s — версия узла останется неизвестной" % ver_src)
    # §6.2: лимиты трат правит владелец по SSH — редеплой их НЕ перетирает.
    if a.keep_config:
        print("  config.json: оставлен как есть (--keep-config)")
    else:
        final_cfg = {**cfg, "panel_port": a.panel_port}
        preserve = ("money", "countries", "auto_prolong", "update", "stability", "learning",
                    "dns_rescue")
        # A prior interrupted deploy may have replaced server.py while the old
        # process kept running.  Always restart an active compatible payload.
        with remote_panel_config_upgrade_barrier(c, True):
            put_config_atomic(c, sftp, "/etc/vpn-panel/config.json",
                              json.dumps(final_cfg, ensure_ascii=False, indent=2) + "\n", preserve)
        print("  config.json: настроенные владельцем блоки сохранены под общим writer lock")
    # secrets.json: в чистой установке НЕ сеем (владелец введёт всё в мастере /setup);
    # иначе ключи провайдеров + SMTP берём из локального файла, а admin-блок (заведён на
    # сервере) сохраняем — иначе каждый деплой выбивал бы вход. Аналогично money/countries.
    bootstrap_secret = ""
    if a.clean:
        raw_sec = run(c, "cat /etc/vpn-panel/secrets.json 2>/dev/null").strip()
        if raw_sec:
            try:
                srv_sec = json.loads(raw_sec)
            except (TypeError, ValueError) as exc:
                raise SystemExit(
                    "Серверный /etc/vpn-panel/secrets.json повреждён; "
                    "автоматическая перезапись запрещена: %s" % exc
                )
            if not isinstance(srv_sec, dict):
                raise SystemExit(
                    "Серверный /etc/vpn-panel/secrets.json имеет неверный формат; "
                    "автоматическая перезапись запрещена"
                )
        else:
            srv_sec = {}
        if srv_sec.get("admin"):
            print("  secrets.json: оставлен как есть (уже настроен через /setup)")
        else:
            # Сохраняем уже введённые provider/SMTP поля: отсутствие admin означает,
            # что bootstrap всё ещё нужен, но не разрешает уничтожать остальные secrets.
            if not raw_sec:
                put_secret_atomic(c, sftp, "/etc/vpn-panel/secrets.json", "{}\n",
                                  preserve_admin=True)
            bootstrap_secret = secrets.token_urlsafe(32)
            now = time.time()
            bootstrap = {"version": 1, "created": now, "expires": now + 24 * 3600,
                         "used": False,
                         "secret_sha256": hashlib.sha256(
                             bootstrap_secret.encode("utf-8")).hexdigest()}
            put_secret_atomic(c, sftp, "/etc/vpn-panel/bootstrap.json",
                              json.dumps(bootstrap, ensure_ascii=False, indent=2) + "\n")
            print("  admin не настроен — мастер /setup завершит защищённый первый вход")
    else:
        with open(secrets_path, encoding="utf-8") as fh:
            merged_secrets = json.load(fh)
        raw_sec = run(c, "cat /etc/vpn-panel/secrets.json 2>/dev/null").strip()
        if raw_sec:
            try:
                srv_sec = json.loads(raw_sec)
            except ValueError:
                srv_sec = {}
            if srv_sec.get("admin"):
                merged_secrets["admin"] = srv_sec["admin"]
                print("  secrets.json: сохранён admin-блок с сервера (пароль/TOTP/recovery)")
        put_secret_atomic(c, sftp, "/etc/vpn-panel/secrets.json",
                          json.dumps(merged_secrets, ensure_ascii=False, indent=2) + "\n",
                          preserve_admin=True)
        print("  secrets.json: SMTP-алерты %s" % ("настроены" if merged_secrets.get("smtp") else "НЕ заданы"))
    with sftp.open("/usr/local/bin/vpn-agent", "w") as f:
        f.write(WRAPPER)
    sftp.chmod("/usr/local/bin/vpn-agent", 0o755)
    if a.with_panel:
        with sftp.open("/etc/systemd/system/vpn-panel.service", "w") as f:
            f.write(PANEL_SERVICE)
    template_dir = os.path.join(PANEL_DIR, os.pardir, "install", "templates")
    for unit_name in ("redut-dns-rescue.service",
                      "redut-dns-rescue-watchdog.service",
                      "redut-dns-rescue-watchdog.timer"):
        unit_src = os.path.join(template_dir, unit_name)
        if not os.path.isfile(unit_src):
            sys.exit("нет systemd-шаблона %s" % unit_src)
        sftp.put(unit_src, "/etc/systemd/system/" + unit_name)
        sftp.chmod("/etc/systemd/system/" + unit_name, 0o644)
    # install/install.sh owns the one canonical watchdog template.  deploy.py
    # must not replace it with a second developer-tree implementation.
    timer_state = run(c, "systemctl daemon-reload && "
                         "systemctl enable --now redut-dns-rescue-watchdog.timer && "
                         "systemctl is-active redut-dns-rescue-watchdog.timer")
    if timer_state.strip().splitlines()[-1:] != ["active"]:
        sys.exit("DNS Rescue watchdog timer не запущен: %s" % timer_state)

    # Кроны (идемпотентно, расписание E2 1.3.0): сторож */2; списки провайдеров */30
    # (без проб); ПОЛНЫЙ прогон проб — раз в 2 ч (было */6 МИНУТ: молотилка 240
    # прогонов/сутки, перекрывавшихся сами с собой, — дока при этом обещала «раз в
    # 6 часов»); лёгкая метка egress для дашборда — */5; пульс ежечасно (§6.3/§6.5)
    crons = ["*/2 * * * * /usr/local/bin/singbox-watchdog.sh",
             "*/30 * * * * /usr/local/bin/vpn-agent pool-refresh",
             "17 */2 * * * /usr/local/bin/vpn-agent pool-refresh --probe",
             "*/5 * * * * /usr/local/bin/vpn-agent egress-mark",
             "0 * * * * /usr/local/bin/vpn-agent heartbeat-check",
             # раз в сутки утром: продлить боевой «якорь» до истечения (§6.3).
             # Смена IP стоит столько же, сколько продление, но новый адрес холодный —
             # прогретый бережём, ротация остаётся аварийной мерой.
             "30 6 * * * /usr/local/bin/vpn-agent auto-prolong",
             # раз в сутки: сверить версию с маяком GitHub; при auto=вкл и ночном
             # окне — обновиться (окно/jitter считает агент, vpn/UPDATE-PLAN.md)
             "41 4 * * * /usr/local/bin/vpn-agent self-update --cron"]
    # Маркер 'vpn-agent pool-refresh' НАМЕРЕННО шире, чем 'pool-refresh --probe':
    # он накрывает и СТАРУЮ строку */6 c --probe, и новую без — иначе после
    # самообновления 1.2.0→1.3.0 старая шестиминутная молотилка осталась бы рядом
    # с новой (🟠 ревью E2).
    strip = ("crontab -l 2>/dev/null | grep -v singbox-watchdog "
             "| grep -v 'vpn-agent pool-refresh' | grep -v 'vpn-agent egress-mark' "
             "| grep -v 'vpn-agent heartbeat-check' "
             "| grep -v 'vpn-agent auto-prolong' | grep -v 'vpn-agent self-update'")
    add = "; ".join("echo '%s'" % ln for ln in crons)
    run(c, "( %s; %s ) | crontab -" % (strip, add))
    print("cron:", run(c, "crontab -l 2>/dev/null | grep -E 'watchdog|vpn-agent' | tr '\\n' '|'"))

    # /opt/redut-src — цель ОТКАТА самообновления. Дерево без режима UPDATE (сборки
    # до 1.2.0) откат не запустит (защита в update.py) — узел останется без отката.
    stale = run(c, "test -f /opt/redut-src/setup.sh && ! grep -q UPDATE /opt/redut-src/setup.sh "
                   "&& echo stale || true").strip()
    if stale == "stale":
        print("  ⚠️ /opt/redut-src — сборка без режима UPDATE (до 1.2.0): автооткат самообновления")
        print("     её не запустит. Обнови дерево: на узле `UPDATE=1 bash <(curl … setup.sh)`,")
        print("     либо перезалей исходники свежего тега в /opt/redut-src.")

    print("\nинициализация БД:", run(c, "vpn-agent pool-refresh", t=180).replace("\n", " | "))
    print("\n" + run(c, "vpn-agent status", t=60))

    if a.with_panel:
        host = SERVERS[a.server]["host"]
        # self-signed cert (если ещё нет, либо --regen-cert) + запуск сервиса
        if a.regen_cert or run(c, "test -f /etc/vpn-panel/panel.crt && echo yes") != "yes":
            run(c, gen_cert_cmd(host))
        print("cert SHA-256:", run(c, "openssl x509 -in /etc/vpn-panel/panel.crt "
                                      "-noout -fingerprint -sha256 2>/dev/null | cut -d= -f2"))
        adminfp = run(c, "test -f /etc/vpn-panel/secrets.json && python3 -c "
                         "\"import json;print('admin' in json.load(open('/etc/vpn-panel/secrets.json')))\"")
        if a.clean and adminfp.strip() != "True":
            print("\nℹ️ Чистая установка — открой мастер первого входа:")
            print("   https://%s:%d/setup  (провайдер PROXY6, 2FA-QR, пароль, почта)" % (host, a.panel_port))
            print("   Одноразовый bootstrap-код из SSH (24 часа): %s" % bootstrap_secret)
        elif adminfp.strip() != "True":
            print("\n⚠️ Админ ещё не настроен. На сервере выполни:")
            print("   python3 /opt/vpn-panel/webpanel/setup_admin.py")
            print("   (сгенерирует пароль + TOTP + recovery, покажет один раз)")
        activate_panel(c, a.panel_port)
        print("\nпанель: active, HTTPS /healthz: ok")
        print("URL: https://%s:%d/" % (SERVERS[a.server]["host"], a.panel_port))

    print("\negress ПОСЛЕ:", run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25),
          "| sing-box:", run(c, "systemctl is-active sing-box"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
