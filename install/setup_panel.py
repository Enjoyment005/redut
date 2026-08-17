# -*- coding: utf-8 -*-
"""setup_panel.py — установка агента и веб-панели ПРЯМО НА СЕРВЕРЕ (без SSH).

    python3 install/setup_panel.py --src ./agent --port 8443

Зачем отдельно от `deploy.py`: тот раскатывает панель с рабочей машины по SSH
(paramiko) и удобен, когда узлов несколько. Но человеку, который просто хочет
себе узел, ставить Python и paramiko на ноутбук незачем — он заходит на свой
сервер и запускает одну команду. Этот скрипт делает ровно то же самое, только
локально: копирует файлы, пишет конфиг, выпускает сертификат, ставит юнит и кроны.

Идемпотентен: повторный запуск не теряет `secrets.json` (учётку и ключи, заведённые
в мастере), не перетирает настроенные владельцем блоки конфига и не плодит кроны.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OPT = "/opt/vpn-panel"
ETC = "/etc/vpn-panel"
VAR = "/var/lib/vpn-panel"

# update.py — ПЕРВЫМ: agent.py его импортирует, и на живом узле между копиями
# файлов есть окно, где тик крона (pool-refresh/heartbeat) поймал бы ImportError.
AGENT_FILES = ["update.py", "agent.py", "pool.py", "probe.py", "apply.py", "money.py",
               "states.py", "alerts.py", "country.py",
               "providers/__init__.py", "providers/base.py",
               "providers/proxyline.py", "providers/proxy6.py"]
PANEL_FILES = ["webpanel/__init__.py", "webpanel/auth.py", "webpanel/server.py",
               "webpanel/views.py", "webpanel/setup_admin.py",
               "webpanel/clients.py", "webpanel/qrcode.py"]

WRAPPER = "#!/bin/bash\nexec python3 %s/agent.py \"$@\"\n" % OPT

PANEL_SERVICE = """[Unit]
Description=vpn-panel (stdlib web UI over vpn-agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# -u: не буферизовать stdout, иначе логи фоновых потоков (подбор первого канала после
# мастера) застревают в буфере и не видны в journalctl (найдено на приёмке 15.08, снос №5).
ExecStart=/usr/bin/python3 -u %s/webpanel/server.py
Restart=always
RestartSec=3
# Панель работает от root: apply/rollback правят /etc/sing-box и маршруты.
# Ограничители ущерба — в приложении (лимиты вне веба, тумблеры, TOTP).

[Install]
WantedBy=multi-user.target
""" % OPT

# Рамки трат и страны — те же, что в deploy.py (§6.1/§6.2). Правятся только по SSH.
DEFAULTS = {
    "money": {
        "buy_enabled": True, "delete_enabled": False,
        "max_buys_per_day": 3, "max_spend_per_day": 300,
        "max_price_per_buy": 150, "min_balance_reserve": 300,
        "buy_period_days": 7, "buy_version": 4, "currency": "RUB",
    },
    "countries": {
        "blacklist": [],
        # белого списка больше нет (приёмка №7): страны оценивает внутренний рейтинг,
        # вручную можно купить любую вне чёрного списка; старый ключ whitelist
        # в конфигах существующих узлов игнорируется.
        # насколько сильно страна влияет на выбор; переключается в панели
        # (country.STRATEGIES: reputation | balanced | speed)
        "strategy": "reputation",
    },
    "auto_prolong": {"enabled": True, "days_before": 3, "period_days": 30},
    # Самообновление с GitHub (vpn/UPDATE-PLAN.md): auto переключается в панели,
    # окно/частота/repo — по SSH (repo подменяют только для обкатки на форке, Р9).
    "update": {"auto": True, "window": "04:00-06:00", "repo": "Enjoyment005/redut"},
    # Обучение стабильности (F8, 1.3.0): порог по объёму данных; правится по SSH.
    "stability": {"min_probes": 300, "min_days": 21, "full_probes": 1000, "full_days": 60},
}

# Расписание E2 (1.3.0): списки провайдеров */30 (без проб); полный прогон проб —
# раз в 2 ч (было */6 МИНУТ — молотилка, перекрывавшая сама себя); лёгкая метка
# egress (*/5) держит дашборд свежим.
CRONS = [
    "*/2 * * * * /usr/local/bin/singbox-watchdog.sh",
    "*/30 * * * * /usr/local/bin/vpn-agent pool-refresh",
    "17 */2 * * * /usr/local/bin/vpn-agent pool-refresh --probe",
    "*/5 * * * * /usr/local/bin/vpn-agent egress-mark",
    "0 * * * * /usr/local/bin/vpn-agent heartbeat-check",
    "30 6 * * * /usr/local/bin/vpn-agent auto-prolong",
    # раз в сутки: сверить версию с маяком GitHub; при auto=вкл и ночном окне —
    # обновиться (jitter и окно считает сам агент, vpn/UPDATE-PLAN.md Ф1/Ф3)
    "41 4 * * * /usr/local/bin/vpn-agent self-update --cron",
]
# Маркер 'vpn-agent pool-refresh' НАМЕРЕННО шире 'pool-refresh --probe': накрывает
# и старую строку */6 с --probe (самообновление 1.2.0→1.3.0 обязано её убрать,
# иначе молотилка удвоится — 🟠 ревью E2), и новую без проб.
CRON_MARK = ("singbox-watchdog", "vpn-agent pool-refresh", "vpn-agent egress-mark",
             "vpn-agent heartbeat-check", "vpn-agent auto-prolong", "vpn-agent self-update")


def sh(cmd, check=False):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and p.returncode != 0:
        sys.exit("команда упала: %s\n%s%s" % (cmd, p.stdout, p.stderr))
    return (p.stdout + p.stderr).strip()


def detect_net():
    route = sh("ip route show default")
    m = re.search(r"default via (\S+) dev (\S+)", route or "")
    if not m:
        sys.exit("не определить шлюз/интерфейс (ip route: %r)" % route)
    gw, wan = m.group(1), m.group(2)
    ip = sh("ip -4 -o addr show dev %s scope global | awk '{print $4}' | cut -d/ -f1 | head -1" % wan)
    return {"gw": gw, "wan": wan, "server_ip": ip.strip()}


def copy_files(src, with_panel=True):
    files = AGENT_FILES + (PANEL_FILES if with_panel else [])
    for rel in files:
        s = os.path.join(src, rel.replace("/", os.sep))
        if not os.path.isfile(s):
            sys.exit("нет файла %s — проверь --src (ожидалась папка agent/)" % s)
        d = os.path.join(OPT, rel)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy2(s, d)
    return len(files)


def copy_version(src):
    """Копия VERSION из корня репозитория -> /opt/vpn-panel/VERSION.

    По ней узел знает, какая сборка на нём РЕАЛЬНО работает: её показывают панель
    и `vpn-agent status`, с ней сверяется самообновление (vpn/UPDATE-PLAN.md Ф0).
    Раньше версия не копировалась вовсе — узел мог годами жить с панелью одной
    сборки при исходниках другой, и по самому узлу этого было не видно."""
    ver = os.path.join(os.path.dirname(os.path.abspath(src)), "VERSION")
    if not os.path.isfile(ver):
        print("  ⚠️ рядом с %s нет VERSION — версия узла останется неизвестной" % src)
        return None
    shutil.copy2(ver, os.path.join(OPT, "VERSION"))
    with open(ver, encoding="utf-8") as f:
        return f.read().strip() or None


def write_config(name, net, port, subnet, wg_port, dnsmasq):
    """Конфиг агента. Блоки, настроенные владельцем, сохраняем как есть."""
    cfg = {
        "singbox_config": "/etc/sing-box/config.json",
        "boot_script": "/usr/local/bin/vpn-boot-setup.sh",
        # ПОЛНЫЙ путь: агент запускается из cron, где PATH = /usr/bin:/bin,
        # а бинарь лежит в /usr/local/bin. С коротким именем проверка конфига
        # падает и выглядит как «плохой канал» — узел уходит в аварийный режим.
        "singbox_bin": "/usr/local/bin/sing-box",
        "lock": "/run/vpn-agent.lock",
        "server": name, "role": "vpn-%s" % name, "subnet": subnet,
        "gw": net["gw"], "wan": net["wan"], "has_dnsmasq": bool(dnsmasq),
        "server_ip": net["server_ip"], "wg_port": wg_port,
        "dns": (subnet.split("/")[0].rsplit(".", 1)[0] + ".1") if dnsmasq else "1.1.1.1",
        "panel_port": port,
    }
    cfg.update(DEFAULTS)
    path = os.path.join(ETC, "config.json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                old = json.load(f)
            for k in ("money", "countries", "auto_prolong", "update", "stability"):
                if isinstance(old.get(k), dict) and old[k]:
                    cfg[k] = old[k]
                    print("  config.json: сохранён настроенный блок '%s'" % k)
        except (ValueError, OSError):
            pass
    # Атомарно (tmp + replace): kill/питание посреди записи оставили бы усечённый
    # config.json — не стартует ни панель, ни агент, ни самообновление (ревью 17.08).
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def ensure_secrets():
    """Пустой secrets.json ({} или нет файла) = панель уйдёт в мастер первого входа.
    Настроенный (есть блок admin) не трогаем. Возвращает True, если мастер ещё впереди —
    по этому флагу setup.sh печатает адрес /setup и предупреждение о первом входе.
    (Раньше «{}» считался настроенной панелью, и повторный запуск до мастера писал
    «панель уже настроена» — найдено на приёмке 15.08.)"""
    path = os.path.join(ETC, "secrets.json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(raw) if raw.strip() else {}
        except (ValueError, OSError):
            print("  secrets.json: не разобрать как JSON — оставлен как есть")
            return False
        if isinstance(data, dict) and data.get("admin"):
            print("  secrets.json: оставлен как есть (панель уже настроена)")
            return False
        if data:
            print("  secrets.json: оставлен как есть (учётка панели ещё не заведена — мастер впереди)")
            return True
    with open(path, "w", encoding="utf-8") as f:
        f.write("{}\n")
    os.chmod(path, 0o600)
    return True


def ensure_cert(host, regen=False):
    crt, key = os.path.join(ETC, "panel.crt"), os.path.join(ETC, "panel.key")
    if os.path.isfile(crt) and not regen:
        return sh("openssl x509 -in %s -noout -fingerprint -sha256 | cut -d= -f2" % crt)
    # Самоподписанный по IP: доступ идёт по адресу, не по домену, поэтому
    # Let's Encrypt неприменим. IP в subjectAltName обязателен — браузеры
    # для доступа по IP игнорируют CN. Срок 10 лет: продлевать нечем и незачем.
    sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s -days 3650 "
       "-subj '/CN=%s' -addext 'subjectAltName=IP:%s'" % (key, crt, host, host), check=True)
    os.chmod(key, 0o600)
    return sh("openssl x509 -in %s -noout -fingerprint -sha256 | cut -d= -f2" % crt)


def install_units(with_panel):
    with open("/usr/local/bin/vpn-agent", "w", encoding="utf-8", newline="\n") as f:
        f.write(WRAPPER)
    os.chmod("/usr/local/bin/vpn-agent", 0o755)
    if with_panel:
        with open("/etc/systemd/system/vpn-panel.service", "w", encoding="utf-8", newline="\n") as f:
            f.write(PANEL_SERVICE)
        sh("systemctl daemon-reload")
        sh("systemctl enable vpn-panel >/dev/null 2>&1")
        sh("systemctl restart vpn-panel")


def _panel_https_ok(port, tries=6):
    """Панель отвечает 'ok' по HTTPS на /healthz? (проверка TLS после старта, снос №6)."""
    import time
    for _ in range(tries):
        out = sh("curl -sk --max-time 5 https://127.0.0.1:%d/healthz" % port)
        if out.strip() == "ok":
            return True
        time.sleep(1)
    return False


def install_crons():
    cur = sh("crontab -l 2>/dev/null")
    keep = [ln for ln in cur.splitlines()
            if ln.strip() and not any(m in ln for m in CRON_MARK)]
    new = "\n".join(keep + CRONS) + "\n"
    p = subprocess.run(["crontab", "-"], input=new, text=True, capture_output=True)
    if p.returncode != 0:
        print("  ⚠️ кроны не установлены: %s" % (p.stderr or "").strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default="agent", help="папка с кодом агента/панели (по умолчанию ./agent)")
    ap.add_argument("--name", default="node1", help="имя узла")
    ap.add_argument("--port", type=int, default=8443, help="порт панели")
    ap.add_argument("--subnet", default="10.8.0.0/24", help="клиентская подсеть")
    ap.add_argument("--wg-port", type=int, default=51820)
    ap.add_argument("--dnsmasq", action="store_true")
    ap.add_argument("--no-panel", action="store_true", help="только агент, без веб-панели")
    ap.add_argument("--regen-cert", action="store_true")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("нужен root")
    with_panel = not a.no_panel

    for d in (OPT, os.path.join(OPT, "providers"), os.path.join(OPT, "webpanel"),
              ETC, os.path.join(VAR, "cfg")):
        os.makedirs(d, exist_ok=True)
    os.chmod(VAR, 0o700)

    net = detect_net()
    print("  сеть: интерфейс %s, шлюз %s, адрес %s" % (net["wan"], net["gw"], net["server_ip"]))
    n = copy_files(a.src, with_panel)
    ver = copy_version(a.src)
    print("  скопировано файлов: %d%s" % (n, ("  (сборка Редут %s)" % ver) if ver else ""))
    write_config(a.name, net, a.port, a.subnet, a.wg_port, a.dnsmasq)
    fresh = ensure_secrets()

    # СЕРТИФИКАТ — ДО старта панели (исправлено 15.08, снос №6). Раньше cert выпускался ПОСЛЕ
    # install_units, и на чистой установке панель успевала подняться без panel.crt -> уходила
    # в HTTP-фолбэк («работаю без TLS»): пароль и TOTP шли открытым текстом, а verify по https
    # не отвечал. Теперь cert есть до первого старта, панель всегда поднимается по HTTPS.
    fp = ensure_cert(net["server_ip"], a.regen_cert) if with_panel else ""

    install_units(with_panel)
    install_crons()
    sh("vpn-agent pool-refresh >/dev/null 2>&1")   # создать БД

    if with_panel:
        # Страховка от гонки старта: панель должна отвечать по HTTPS. Если поднялась по HTTP
        # (cert появился в момент старта) — один рестарт, теперь cert гарантированно на месте.
        if not _panel_https_ok(a.port):
            print("  панель поднялась без TLS — перезапускаю с сертификатом")
            sh("systemctl restart vpn-panel")
            _panel_https_ok(a.port, tries=10)
        print("  панель: %s (%s)" % (sh("systemctl is-active vpn-panel"),
                                     "https ok" if _panel_https_ok(a.port) else "TLS НЕ поднялся"))
    print(json.dumps({"panel_port": a.port, "server_ip": net["server_ip"],
                      "cert_fp": fp, "fresh_setup": fresh}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
