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
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))

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
        # в панели, значения — country.STRATEGIES: reputation (по умолчанию),
        # balanced, speed (решают замеры). Старое значение whitelist падает на дефолт.
        "strategy": "reputation",
    },
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
AGENT_FILES = ["update.py", "agent.py", "pool.py", "probe.py", "apply.py", "money.py",
               "states.py", "alerts.py", "country.py",
               "providers/__init__.py", "providers/base.py",
               "providers/proxyline.py", "providers/proxy6.py"]
PANEL_FILES = ["webpanel/__init__.py", "webpanel/auth.py", "webpanel/server.py",
               "webpanel/views.py", "webpanel/setup_admin.py",
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


def run(c, cmd, t=180):
    _, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


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

    c = connect(SERVERS[a.server]["host"], SERVERS[a.server]["pw"])
    print("\negress ДО:", run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25),
          "| sing-box:", run(c, "systemctl is-active sing-box"))

    run(c, "mkdir -p %s/providers %s/webpanel /etc/vpn-panel /var/lib/vpn-panel/cfg" % (OPT, OPT))
    run(c, "chmod 700 /var/lib/vpn-panel")
    sftp = c.open_sftp()
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
        existing = {}
        raw = run(c, "cat /etc/vpn-panel/config.json 2>/dev/null").strip()
        if raw:
            try:
                existing = json.loads(raw)
            except ValueError:
                existing = {}
        final_cfg = {**cfg, "panel_port": a.panel_port}
        for k in ("money", "countries", "auto_prolong", "update", "stability"):
            if isinstance(existing.get(k), dict) and existing[k]:
                final_cfg[k] = existing[k]
                print("  config.json: сохранён настроенный владельцем блок '%s' (§6.2)" % k)
        with sftp.open("/etc/vpn-panel/config.json", "w") as f:
            json.dump(final_cfg, f, ensure_ascii=False, indent=2)
        sftp.chmod("/etc/vpn-panel/config.json", 0o644)
    # secrets.json: в чистой установке НЕ сеем (владелец введёт всё в мастере /setup);
    # иначе ключи провайдеров + SMTP берём из локального файла, а admin-блок (заведён на
    # сервере) сохраняем — иначе каждый деплой выбивал бы вход. Аналогично money/countries.
    if a.clean:
        raw_sec = run(c, "cat /etc/vpn-panel/secrets.json 2>/dev/null").strip()
        if raw_sec and raw_sec not in ("{}", ""):
            print("  secrets.json: оставлен как есть (уже настроен через /setup)")
        else:
            with sftp.open("/etc/vpn-panel/secrets.json", "w") as f:
                f.write("{}")
            sftp.chmod("/etc/vpn-panel/secrets.json", 0o600)
            print("  secrets.json: пустой — мастер /setup заполнит (провайдеры/2FA/пароль/SMTP)")
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
        with sftp.open("/etc/vpn-panel/secrets.json", "w") as f:
            json.dump(merged_secrets, f, ensure_ascii=False, indent=2)
        sftp.chmod("/etc/vpn-panel/secrets.json", 0o600)
        print("  secrets.json: SMTP-алерты %s" % ("настроены" if merged_secrets.get("smtp") else "НЕ заданы"))
    with sftp.open("/usr/local/bin/vpn-agent", "w") as f:
        f.write(WRAPPER)
    sftp.chmod("/usr/local/bin/vpn-agent", 0o755)
    if a.with_panel:
        with sftp.open("/etc/systemd/system/vpn-panel.service", "w") as f:
            f.write(PANEL_SERVICE)
    # Фаза 3: сторож с перевешенной веткой «upstream мёртв» -> vpn-agent rotate (§1/§8)
    wd_src = os.path.join(PANEL_DIR, os.pardir, "singbox", "singbox-watchdog.sh")
    if os.path.isfile(wd_src):
        with open(wd_src, encoding="utf-8") as fh:
            wd_data = fh.read().replace("\r\n", "\n")
        with sftp.open("/usr/local/bin/singbox-watchdog.sh", "w") as f:
            f.write(wd_data)
        sftp.chmod("/usr/local/bin/singbox-watchdog.sh", 0o755)
    sftp.close()

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
        elif adminfp.strip() != "True":
            print("\n⚠️ Админ ещё не настроен. На сервере выполни:")
            print("   python3 /opt/vpn-panel/webpanel/setup_admin.py")
            print("   (сгенерирует пароль + TOTP + recovery, покажет один раз)")
        run(c, "systemctl daemon-reload && systemctl enable vpn-panel 2>/dev/null")
        print("\nпанель:", run(c, "systemctl restart vpn-panel; sleep 1; systemctl is-active vpn-panel"))
        print("URL: https://%s:%d/" % (SERVERS[a.server]["host"], a.panel_port))

    print("\negress ПОСЛЕ:", run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25),
          "| sing-box:", run(c, "systemctl is-active sing-box"))
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
