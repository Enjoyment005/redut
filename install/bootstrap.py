#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bootstrap.py — «одна команда»: с голого Debian 13 до рабочего VPN-узла + панель.

    python vpn/install/bootstrap.py --host <IP> --pw <root_pw> --name node1

Оркестратор с dev-машины (paramiko, как panel/deploy.py). Делает:
  1. SSH root+пароль, автоопределение gw/wan/внешнего IP (ip route show default);
  2. заливка templates/ + install.sh + params.sh в /opt/vpn-install/;
  3. запуск install.sh (идемпотентная база: пакеты, sing-box 1.11.7, wg, sing-box
     config, self-heal, vpn-boot-setup с §11 RETURN, microsocks, iptables, кроны);
  4. забор клиентских .conf в vpn/install/clients/<name>/;
  5. панель/агент — через panel/deploy.py <name> --with-panel (переиспользуем, не дублируем);
  6. setup_admin.py — учётка панели (пароль/TOTP/recovery, печать один раз);
  7. финальный verify (§6) и итоговая сводка.

Идемпотентно: повторный запуск не ломает и не дублирует. --dry-run печатает план.
Дефолты — профиль node1 (profiles.py). Новый сервер по той же схеме = только --host/--pw.
"""
import argparse
import os
import re
import secrets
import stat
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir))   # корень репозитория
PANEL_DIR = os.path.join(REPO, "agent")                 # агент + веб-панель
TPL_DIR = os.path.join(HERE, "templates")
REMOTE = "/opt/vpn-install"

sys.path.insert(0, HERE)
import profiles  # noqa: E402
from base_manifest import remote_check_command, remote_dns_preflight_command  # noqa: E402

try:
    import paramiko
except ImportError:
    sys.exit("Нужен paramiko: pip install paramiko")


def _shq(v):
    return "'" + str(v).replace("'", "'\\''") + "'"


# ─────────────────────────── SSH helpers ────────────────────────────────
def connect(host, pwds, timeout=25):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last = None
    for pw in pwds:
        try:
            c.connect(host, username="root", password=pw, timeout=timeout,
                      allow_agent=False, look_for_keys=False)
            return c
        except Exception as e:
            last = e
    raise SystemExit("SSH к %s недоступен: %s" % (host, last))


def run(c, cmd, t=120):
    _, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def run_result(c, cmd, t=120):
    """Return remote rc and combined output for fail-closed contract checks."""
    _, stdout, stderr = c.exec_command(cmd, timeout=t)
    output = (stdout.read().decode("utf-8", "replace")
              + stderr.read().decode("utf-8", "replace")).strip()
    return stdout.channel.recv_exit_status(), output


def remote_dns_preflight(c):
    """Reject an unsafe installed generation before touching staging files."""
    rc, output = run_result(c, remote_dns_preflight_command(), t=30)
    if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_DNS_PREFLIGHT_OK"]:
        raise SystemExit("удалённый DNS Rescue preflight не подтверждён: %s"
                         % (output or "rc=%s" % rc))
    return True


def run_stream(c, cmd, t=1800, prefix="    "):
    """Выполнить и стримить вывод построчно. Возвращает (rc, полный_вывод)."""
    _, stdout, _ = c.exec_command(cmd + " 2>&1", timeout=t, get_pty=False)
    lines = []
    for line in iter(stdout.readline, ""):
        sys.stdout.write(prefix + line)
        sys.stdout.flush()
        lines.append(line)
    rc = stdout.channel.recv_exit_status()
    return rc, "".join(lines)


def sftp_put_text(sftp, local_path, remote_path, mode=0o644):
    """Залить текстовый файл, нормализовав CRLF->LF (репо на Windows)."""
    with open(local_path, "rb") as f:
        data = f.read().replace(b"\r\n", b"\n")
    with sftp.open(remote_path, "w") as f:
        f.write(data)
    sftp.chmod(remote_path, mode)


def sftp_write_text(sftp, content, remote_path, mode=0o644):
    with sftp.open(remote_path, "w") as f:
        f.write(content.replace("\r\n", "\n"))
    sftp.chmod(remote_path, mode)


def _remove_own_secret_staging(sftp, path):
    """Remove only a proven root-owned private regular staging file."""
    try:
        attrs = sftp.lstat(path)
        if (stat.S_ISREG(attrs.st_mode)
                and stat.S_IMODE(attrs.st_mode) == 0o600
                and getattr(attrs, "st_uid", None) == 0):
            sftp.remove(path)
    except Exception:
        pass


def _write_secret_staging(sftp, path, content):
    """Create and prove 0600 on our handle before the first secret byte."""
    target = None
    try:
        target = sftp.open(path, "wx")
        target.chmod(0o600)
        attrs = target.stat()
        if (not stat.S_ISREG(attrs.st_mode)
                or stat.S_IMODE(attrs.st_mode) != 0o600
                or getattr(attrs, "st_uid", None) != 0):
            raise OSError("bootstrap secret staging has unsafe type, owner or mode")
        target.write(content.replace("\r\n", "\n"))
        target.flush()
    except Exception:
        if target is not None:
            try:
                target.close()
            except Exception:
                pass
        _remove_own_secret_staging(sftp, path)
        raise
    else:
        target.close()


def render_params_preview(p, net):
    """Return the params structure without putting credentials in logs."""
    hidden = {"UP_PASS", "MICROSOCKS_PASS"}
    lines = []
    for line in profiles.render_params(p, net).splitlines():
        key, separator, _value = line.partition("=")
        if separator and key in hidden:
            line = "%s='<redacted>'" % key
        lines.append(line)
    return "\n".join(lines) + "\n"


# ─────────────────────────── параметры / профиль ─────────────────────────
def parse_clients(spec, subnet):
    """--clients: N or names, assigned from network offset 2 onward."""
    return profiles.parse_clients(spec, subnet)


def build(args):
    overrides = {}
    if args.subnet:
        overrides["subnet"] = args.subnet
    if args.panel_port:
        overrides["panel_port"] = args.panel_port
    if args.dnsmasq is not None:
        overrides["dnsmasq"] = args.dnsmasq
    if args.clients:
        subnet = args.subnet or profiles.PROFILES[args.profile or args.name]["subnet"]
        overrides["clients"] = parse_clients(args.clients, subnet)
    if args.upstream:
        parts = args.upstream.split(":")
        if len(parts) != 5:
            sys.exit("--upstream = host:socks:http:user:pass")
        overrides["upstream"] = {"host": parts[0], "socks": int(parts[1]),
                                 "http": int(parts[2]), "user": parts[3], "pass": parts[4]}
        # канал назвали явно — он перебьёт тот, что уже стоит на узле (install.sh §5)
        overrides["upstream_forced"] = True
    p = profiles.build_profile(args.profile or args.name, args.host, args.pw, overrides)
    p["name"] = args.name
    p["role"] = "vpn-%s" % args.name
    return p


def detect_net(c, p, args):
    route = run(c, "ip route show default")
    m = re.search(r"default via (\S+) dev (\S+)", route or "")
    gw = args.gw or (m.group(1) if m else None)
    wan = args.wan or (m.group(2) if m else None)
    if not (gw and wan):
        sys.exit("Не определить gw/wan (ip route: %r). Задай --gw/--wan." % route)
    server_ip = run(c, "ip -4 -o addr show dev %s scope global | awk '{print $4}' | "
                       "cut -d/ -f1 | head -1" % wan).strip() or p["host"]
    return {"gw": gw, "wan": wan, "server_ip": server_ip}


# ─────────────────────────── заливка + install.sh ────────────────────────
def upload(c, p, net):
    sftp = c.open_sftp()
    rc, output = run_result(
        c,
        "umask 077; mkdir -p {0}/templates {0}/clients && chmod 700 {0} && "
        "test \"$(stat -c '%a:%U:%F' {0})\" = '700:root:directory' && "
        "echo REDUT_BOOTSTRAP_DIR_OK".format(REMOTE))
    if rc != 0 or output.strip().splitlines()[-1:] != ["REDUT_BOOTSTRAP_DIR_OK"]:
        sftp.close()
        raise SystemExit("private bootstrap staging directory не подтверждён: %s"
                         % (output or "rc=%s" % rc))
    n = 0
    for root, _, files in os.walk(TPL_DIR):
        rel = os.path.relpath(root, TPL_DIR)
        if rel != ".":
            run(c, "mkdir -p %s/templates/%s" % (REMOTE, rel.replace(os.sep, "/")))
        for fn in files:
            lp = os.path.join(root, fn)
            sub = fn if rel == "." else "%s/%s" % (rel.replace(os.sep, "/"), fn)
            sftp_put_text(sftp, lp, "%s/templates/%s" % (REMOTE, sub), 0o644)
            n += 1
    sftp_put_text(sftp, os.path.join(HERE, "install.sh"), "%s/install.sh" % REMOTE, 0o755)
    sftp_put_text(sftp, os.path.join(HERE, "base_manifest.py"),
                  "%s/base_manifest.py" % REMOTE, 0o644)
    params_path = "%s/params.sh" % REMOTE
    params_stage = "%s/.params.sh.bootstrap-%s" % (REMOTE, secrets.token_hex(16))
    try:
        _write_secret_staging(sftp, params_stage, profiles.render_params(p, net))
        # OpenSSH's atomic overwrite extension prevents a partially written
        # params.sh from becoming visible on reconnect or process death.
        sftp.posix_rename(params_stage, params_path)
        attrs = sftp.lstat(params_path)
        if (not stat.S_ISREG(attrs.st_mode)
                or stat.S_IMODE(attrs.st_mode) != 0o600
                or getattr(attrs, "st_uid", None) != 0):
            raise OSError("installed params.sh has unsafe type, owner or mode")
    except Exception:
        _remove_own_secret_staging(sftp, params_stage)
        sftp.close()
        raise
    sftp.close()
    print("  залито: %d шаблонов + install.sh + base_manifest.py + params.sh -> %s"
          % (n, REMOTE))


def fetch_clients(c, p):
    outdir = os.path.join(HERE, "clients", p["name"])
    os.makedirs(outdir, exist_ok=True)
    sftp = c.open_sftp()
    saved = []
    for cl in p["clients"]:
        rp = "/etc/wireguard/clients/%s.conf" % cl["name"]
        lp = os.path.join(outdir, "%s.conf" % cl["name"])
        try:
            sftp.get(rp, lp)
            saved.append(lp)
        except IOError:
            print("  ⚠️ не найден %s на сервере" % rp)
    sftp.close()
    return saved


# ─────────────────────────── панель через deploy.py ──────────────────────
def deploy_panel(p, net, args):
    """Переиспользуем panel/deploy.py: инъекция SERVERS + вызов main([...--with-panel])."""
    clean = not args.seed_secrets
    if not clean and not os.path.isfile(os.path.join(PANEL_DIR, ".secrets.local.json")):
        print("  ⚠️ нет panel/.secrets.local.json — пропускаю панель (или запусти без --seed-secrets).")
        return False
    sys.path.insert(0, PANEL_DIR)
    import deploy  # noqa: E402
    deploy.SERVERS[p["name"]] = {
        "host": p["host"], "pw": [p["root_pw"]],
        "config": {"server": p["name"], "role": p["role"], "subnet": p["subnet"],
                   "gw": net["gw"], "wan": net["wan"], "has_dnsmasq": bool(p.get("dnsmasq")),
                   # для веб-управления клиентскими конфигами (эндпоинт + DNS в .conf):
                   "server_ip": net["server_ip"], "wg_port": p["wg_port"],
                   "dns": (p["wg_ip"] if p.get("dnsmasq") else "1.1.1.1")},
    }
    argv = [p["name"], "--with-panel", "--panel-port", str(p["panel_port"])]
    if clean:
        argv.append("--clean")
    if args.regen_cert:
        argv.append("--regen-cert")
    print("\n=== ПАНЕЛЬ/АГЕНТ (panel/deploy.py %s) ===" % " ".join(argv))
    return deploy.main(argv) == 0


def ensure_admin(c, p, args):
    """setup_admin.py на сервере, если admin ещё не заведён. Печатает креды один раз."""
    exists = run(c, "test -f /etc/vpn-panel/secrets.json && python3 -c "
                    "\"import json;print('admin' in json.load(open('/etc/vpn-panel/secrets.json')))\" "
                    "2>/dev/null")
    if exists.strip() == "True":
        print("  admin панели уже настроен — сохранён (креды не меняются).")
        return None
    cmd = "cd /opt/vpn-panel && python3 webpanel/setup_admin.py --label %s" % p["name"]
    if args.panel_pw:
        cmd += " --password %s" % _shq(args.panel_pw)
    out = run(c, cmd, t=60)
    run(c, "systemctl restart vpn-panel 2>/dev/null")
    return out


# ─────────────────────────── verify (§6) ─────────────────────────────────
def verify(c, p, net, with_panel):
    print("\n=== VERIFY (§6) ===")
    probs, warns = [], []

    def ok(t):
        print("  [OK]   %s" % t)

    def bad(t):
        print("  [FAIL] %s" % t)
        probs.append(t)

    def warn(t):
        print("  [WARN] %s" % t)
        warns.append(t)

    ver = run(c, "/usr/local/bin/sing-box version 2>/dev/null | awk '/version/{print $NF; exit}'")
    (ok if ver == p["singbox_version"] else bad)("sing-box %s (ждём %s)" % (ver or "нет", p["singbox_version"]))

    svcs = ["wg-quick@wg0", "sing-box", "microsocks", "vpn-boot-setup"]
    if with_panel:
        svcs.append("vpn-panel")
    for s in svcs:
        st = run(c, "systemctl is-active %s" % s)
        (ok if st == "active" else bad)("%s: %s" % (s, st))

    mm = run(c, "ip route show table middleman")
    (ok if "default dev tun0" in mm else bad)("middleman default -> tun0 (%s)" % mm.replace("\n", "; "))

    rule = run(c, "ip rule show | grep -c 'fwmark 0x64 lookup middleman'")
    (ok if rule not in ("", "0") else bad)("ip rule fwmark 0x64 -> middleman")

    egress = run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25)
    up = p["upstream"]["host"]
    if egress == up:
        ok("egress(tun0) = upstream %s" % egress)
    elif egress and egress != net["server_ip"]:
        warn("egress(tun0) = %s (не свой IP, но и не заявленный upstream %s)" % (egress, up))
    else:
        bad("egress(tun0) = %s (ждали upstream %s)" % (egress or "пусто", up))

    peers = run(c, "wg show wg0 peers | wc -l")
    (ok if peers.isdigit() and int(peers) >= 1 else bad)("wg0 пиров: %s" % peers)

    # §11 RETURN выше MARK, без дублей MASQUERADE
    pr = run(c, "iptables -t mangle -S PREROUTING")
    lines = pr.splitlines()
    idx_mark = next((i for i, l in enumerate(lines) if "MARK --set" in l), -1)
    ret_self = next((i for i, l in enumerate(lines) if ("-d %s/32" % net["server_ip"]) in l and "RETURN" in l), -1)
    ret_sub = next((i for i, l in enumerate(lines)
                    if ("-d %s" % p["subnet"]) in l and "RETURN" in l), -1)
    if ret_self >= 0 and ret_sub >= 0 and idx_mark >= 0 and ret_self < idx_mark and ret_sub < idx_mark:
        ok("§11 RETURN (сам сервер + подсеть) ВЫШЕ MARK 0x64")
    else:
        bad("§11 RETURN не на месте/не выше MARK (self=%d sub=%d mark=%d)" % (ret_self, ret_sub, idx_mark))

    masq = run(c, "iptables -t nat -S POSTROUTING | grep -c -- '-s %s .*MASQUERADE'" % p["subnet"])
    if masq == "1":
        ok("MASQUERADE ровно 1 (без дублей)")
    else:
        warn("MASQUERADE правил: %s (ждали 1)" % masq)

    # SOCKS5 :1080 слушает весь интернет — пароль-заглушка из репозитория недопустим (снос №4, 15.08)
    ms = run(c, "grep -ci CHANGE_ME /etc/microsocks.env /etc/systemd/system/microsocks.service 2>/dev/null | "
                "awk -F: '{s+=$2} END{print s+0}'; test -f /etc/microsocks.env && echo env-ok")
    if "env-ok" in ms and ms.split()[0] == "0":
        ok("microsocks: креды свои (/etc/microsocks.env, без заглушки)")
    else:
        bad("microsocks: заглушка CHANGE_ME в кредах или нет /etc/microsocks.env (%s)" % ms.replace("\n", " "))

    if with_panel:
        hz_rc, hz = run_result(
            c, "curl -fsk --max-time 10 https://127.0.0.1:%d/healthz" % p["panel_port"])
        (ok if hz_rc == 0 and hz.strip() == "ok" else bad)(
            "панель /healthz: %s" % (hz or "rc=%s" % hz_rc))
        adm = run(c, "python3 -c \"import json;print('admin' in json.load(open('/etc/vpn-panel/secrets.json')))\" 2>/dev/null")
        (ok if adm.strip() == "True" else warn)("admin панели настроен")

    print("  ── итог: %d проблем, %d предупреждений" % (len(probs), len(warns)))
    return probs, warns


# ─────────────────────────── main ────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="IP нового сервера (root SSH)")
    ap.add_argument("--pw", required=True, help="root-пароль SSH")
    ap.add_argument("--name", default="node1", help="имя/роль узла (роль = vpn-<name>)")
    ap.add_argument("--profile", help="базовый профиль (по умолчанию = --name, иначе node1)")
    ap.add_argument("--subnet", help="переопределить подсеть (напр. 10.8.0.0/24)")
    ap.add_argument("--clients", help="число (client1..N) или список имён через запятую")
    ap.add_argument("--upstream", help="host:socks:http:user:pass (иначе из профиля)")
    ap.add_argument("--panel-port", type=int, help="порт панели (дефолт 8443)")
    ap.add_argument("--panel-pw", help="пароль панели (иначе сгенерируется setup_admin)")
    ap.add_argument("--wan", help="переопределить WAN-интерфейс (иначе автоопределение)")
    ap.add_argument("--gw", help="переопределить шлюз (иначе автоопределение)")
    ap.add_argument("--dnsmasq", dest="dnsmasq", action="store_true", default=None, help="включить dnsmasq")
    ap.add_argument("--no-dnsmasq", dest="dnsmasq", action="store_false", help="выключить dnsmasq (дефолт)")
    ap.add_argument("--no-panel", action="store_true", help="только база, без веб-панели/агента")
    ap.add_argument("--skip-base", action="store_true", help="пропустить install.sh (только панель/verify)")
    ap.add_argument("--regen-cert", action="store_true", help="перевыпустить cert панели")
    ap.add_argument("--seed-secrets", action="store_true",
                    help="пре-сид секретов из panel/.secrets.local.json + setup_admin (авто-режим). "
                         "По умолчанию — ЧИСТАЯ установка: провайдер/2FA/пароль/почту вводит владелец "
                         "в мастере первого входа https://<host>:<port>/setup")
    ap.add_argument("--dry-run", action="store_true", help="показать план, не заливать")
    a = ap.parse_args(argv)
    if a.profile is None:
        a.profile = a.name if a.name in profiles.PROFILES else "node1"

    p = build(a)
    print("=== BOOTSTRAP узла '%s' (%s) ===" % (p["name"], p["host"]))
    print("  профиль=%s subnet=%s wg_port=%s singbox=%s dnsmasq=%s panel_port=%s" % (
        a.profile, p["subnet"], p["wg_port"], p["singbox_version"],
        bool(p.get("dnsmasq")), p["panel_port"]))
    print("  upstream=%s:%s/%s  клиенты=%s" % (
        p["upstream"]["host"], p["upstream"]["socks"], p["upstream"]["http"],
        ", ".join("%s@%s" % (c["name"], c["addr"]) for c in p["clients"])))

    if a.dry_run:
        # для dry-run покажем детект вживую (read-only), затем params
        c = connect(p["host"], [p["root_pw"]])
        net = detect_net(c, p, a)
        c.close()
        print("  автоопределено: wan=%s gw=%s server_ip=%s" % (net["wan"], net["gw"], net["server_ip"]))
        print("\n--- params.sh (секреты скрыты) ---\n" + render_params_preview(p, net))
        print("[dry-run] ничего не залито/не изменено.")
        return 0

    c = connect(p["host"], [p["root_pw"]])
    try:
        net = detect_net(c, p, a)
        print("  автоопределено: wan=%s gw=%s server_ip=%s" % (net["wan"], net["gw"], net["server_ip"]))
        # Fast read-only admission before staging upload. install.sh repeats the
        # same canonical check under /run/vpn-agent.lock immediately before
        # its first live mutation, closing the race after this early check.
        remote_dns_preflight(c)

        if a.skip_base:
            rc, output = run_result(c, remote_check_command())
            if (rc != 0
                    or output.strip().splitlines()[-1:] != ["REDUT_BASE_CONTRACT_OK"]):
                raise SystemExit(
                    "--skip-base запрещён: базовые watchdog/post/boot/cleanup "
                    "не имеют актуального manifest; запусти без --skip-base")

        if not a.skip_base:
            print("\n=== ЗАЛИВКА + install.sh ===")
            upload(c, p, net)
            rc, _ = run_stream(c, "bash %s/install.sh" % REMOTE, t=1800)
            if rc != 0:
                raise SystemExit(
                    "install.sh завершился с кодом %d; bootstrap остановлен до deploy/verify"
                    % rc)
            saved = fetch_clients(c, p)
            for s in saved:
                print("  клиентский конфиг: %s" % os.path.relpath(s, REPO))

        admin_out = None
        panel_ok = False
        if not a.no_panel:
            panel_ok = deploy_panel(p, net, a)
            if not panel_ok:
                raise SystemExit("панель/агент не установлены; bootstrap не завершён")
            if panel_ok and a.seed_secrets:      # чистая установка: admin заводит мастер /setup
                admin_out = ensure_admin(c, p, a)

        probs, warns = verify(c, p, net, with_panel=(not a.no_panel and panel_ok))

        # ── Итог ──
        print("\n" + "=" * 64)
        print("ИТОГ BOOTSTRAP узла '%s' (%s)" % (p["name"], p["host"]))
        print("=" * 64)
        egress = run(c, "curl -s --max-time 15 --interface tun0 https://api.ipify.org", t=25)
        print("egress(tun0): %s" % (egress or "ПУСТО"))
        outdir = os.path.join(HERE, "clients", p["name"])
        print("клиентские .conf: %s" % os.path.relpath(outdir, REPO))
        if not a.no_panel and panel_ok:
            print("панель: https://%s:%d/" % (p["host"], p["panel_port"]))
            fp = run(c, "openssl x509 -in /etc/vpn-panel/panel.crt -noout -fingerprint -sha256 "
                        "2>/dev/null | cut -d= -f2")
            if fp:
                print("cert SHA-256: %s" % fp)
            if a.seed_secrets:
                print("\n" + admin_out if admin_out else "admin панели: сохранён с прошлого прогона.")
            else:
                prov = run(c, "python3 -c \"import json;print('admin' in json.load("
                              "open('/etc/vpn-panel/secrets.json')))\" 2>/dev/null").strip()
                if prov == "True":
                    print("панель уже настроена (мастер /setup пройден) — вход пароль+TOTP.")
                else:
                    print("\n⚙️  ПЕРВЫЙ ВХОД — мастер настройки: https://%s:%d/setup" % (p["host"], p["panel_port"]))
                    print("    Задаёт: провайдер PROXY6 (приоритет), 2FA-QR, пароль, почта. Открой сразу.")
        if probs:
            print("\n❌ Проблемы verify (%d): %s" % (len(probs), "; ".join(probs)))
        else:
            print("\n✅ verify зелёный%s." % (" (%d предупр.)" % len(warns) if warns else ""))
        print("Тест ребутом (§7.2): reboot -> всё должно подняться само. Идемпотентность: повторный прогон.")
        return 1 if probs else 0
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
