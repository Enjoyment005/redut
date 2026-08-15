# -*- coding: utf-8 -*-
"""Применение кандидата и откат (§9). Исполняется НА сервере.

Порядок apply:
  1. flock (не даём двум ротациям пересечься)
  2. бэкап в кольцо /var/lib/vpn-panel/cfg/YYYYMMDD-HHMMSS.json (держим 10)
  3. пересборка outbound'ов ИЗ ШАБЛОНА (§7.3): socks-out предпочитает SOCKS5
     с фолбэком на type:"http"; http-tg наоборот. Теги НЕ переименовываются
     (на них ссылаются route.rules и dns.detour). При socks->http лишний
     "version":"5" не переживает пересборку. route.final="socks-out" — явно.
     В HTTP-режиме основного — правило «UDP 443 -> reject» (HTTP-прокси не
     умеет UDP, QUIC иначе висит), в SOCKS5-режиме правило снимается.
  4. sing-box check -c кандидата ДО каких-либо изменений live
  5. anti-loop маршрут нового IP via шлюз, старый убирается
  6. правка /usr/local/bin/vpn-boot-setup.sh (переживает ребут)
  7. systemctl restart sing-box; ждать carrier tun0
  8. VERIFY: curl --interface tun0 -> IP есть, страна не в жёстком блоке, TG-проба
  9. провал -> откат конфига из кольца + маршруты + рестарт
 10. событие в журнал

Патчи конфига — json.load/dump + os.replace; boot-скрипт — re.sub в Python
(никакого sed/shell, §15). Все команды — subprocess списком аргументов.
"""
import contextlib
import copy
import json
import os
import re
import shutil
import subprocess
import time

import probe as probe_mod

try:
    import fcntl
except ImportError:      # Windows-дев: flock не нужен (apply тут не выполняется)
    fcntl = None

VERIFY_TIMEOUT = 15


class ApplyError(Exception):
    pass


# ---------------------------------------------------------------- flock (§9.1)
class Flock:
    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        if fcntl is None:
            return self
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            raise ApplyError("Другой процесс агента уже меняет конфиг (flock %s занят)" % self.path)
        return self

    def __exit__(self, *exc):
        if self.fh:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_UN)
            except OSError:
                pass
            self.fh.close()


@contextlib.contextmanager
def _maybe_lock(server_cfg, held):
    """Взять flock, ЕСЛИ его ещё не держит вызывающий. states.rotate берёт lock
    на весь цикл диагностики и передаёт _locked=True — тогда apply/rollback не
    берут его повторно (LOCK_NB на второй fd в том же процессе конфликтует)."""
    if held:
        yield
    else:
        with Flock(server_cfg.get("lock") or "/run/vpn-agent.lock"):
            yield


# ------------------------------------------------------- чистые функции патча
def build_outbound(kind, tag, host, port, user, password):
    """Outbound целиком из шаблона. У http-outbound поля version нет вовсе."""
    ob = {"type": kind, "tag": tag, "server": host, "server_port": int(port),
          "username": user, "password": password}
    if kind == "socks":
        ob["version"] = "5"
    return ob


def choose_outbounds(host, user, password, socks_port, http_port):
    """§7.3: тип каждого outbound подбирается независимо, теги не меняются.

    -> (socks_out, http_tg, reject_quic)
    """
    if not socks_port and not http_port:
        raise ApplyError("Ни одна комбинация порт×протокол не работает — применять нечего")
    socks_out = (build_outbound("socks", "socks-out", host, socks_port, user, password)
                 if socks_port else
                 build_outbound("http", "socks-out", host, http_port, user, password))
    http_tg = (build_outbound("http", "http-tg", host, http_port, user, password)
               if http_port else
               build_outbound("socks", "http-tg", host, socks_port, user, password))
    reject_quic = socks_out["type"] == "http"
    return socks_out, http_tg, reject_quic


def _lst(v):
    return v if isinstance(v, list) else ([] if v is None else [v])


def is_quic_reject(rule):
    return (rule.get("action") == "reject" and "udp" in _lst(rule.get("network"))
            and 443 in _lst(rule.get("port")))


def patch_config(cfg, socks_out, http_tg, reject_quic):
    """Чистая пересборка конфига (не мутирует вход) — тестируется без сервера.

    Outbound заменяется ЦЕЛИКОМ по тегу (старый "version" не переживёт
    socks->http), route.final прописывается явно, правило UDP443 идемпотентно.
    """
    c = copy.deepcopy(cfg)
    outs = c.setdefault("outbounds", [])
    at_tag = {o.get("tag"): i for i, o in enumerate(outs)}
    for ob in (socks_out, http_tg):
        tag = ob["tag"]
        if tag in at_tag:
            outs[at_tag[tag]] = ob
        else:
            outs.append(ob)

    route = c.setdefault("route", {})
    route["final"] = "socks-out"   # явный дефолт вместо хрупкого «первый в массиве»
    rules = route.setdefault("rules", [])
    rules[:] = [r for r in rules if not is_quic_reject(r)]  # идемпотентность
    if reject_quic:
        at = 0                     # сразу после DNS-правил, до всех остальных
        for i, r in enumerate(rules):
            if (r.get("protocol") == "dns" or r.get("outbound") == "dns-out"
                    or r.get("action") in ("hijack-dns", "sniff", "resolve")):
                at = i + 1
        rules.insert(at, {"action": "reject", "network": ["udp"], "port": [443]})
    return c


def current_upstream(cfg):
    """IP текущего socks-out (для anti-loop чистки и определения «текущего»)."""
    for o in cfg.get("outbounds", []):
        if o.get("tag") == "socks-out":
            return o.get("server") or ""
    return ""


# ------------------------------------------------------------- работа с диском
def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json_replace(obj, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def backup_ring(cfg_path, ring_dir, keep=10):
    """Кольцо бэкапов из keep штук, не один .bak (§9.2)."""
    os.makedirs(ring_dir, exist_ok=True)
    name = time.strftime("%Y%m%d-%H%M%S") + ".json"
    dst = os.path.join(ring_dir, name)
    shutil.copyfile(cfg_path, dst)
    ring = sorted(f for f in os.listdir(ring_dir) if re.fullmatch(r"\d{8}-\d{6}\.json", f))
    for old in ring[:-keep]:
        os.unlink(os.path.join(ring_dir, old))
    return dst


def newest_backup(ring_dir):
    if not os.path.isdir(ring_dir):
        return None
    ring = sorted(f for f in os.listdir(ring_dir) if re.fullmatch(r"\d{8}-\d{6}\.json", f))
    return os.path.join(ring_dir, ring[-1]) if ring else None


# ------------------------------------------------------------- команды системы
def run_cmd(args, timeout=40):
    """Команда СПИСКОМ аргументов (§15). -> (rc, stdout+stderr)"""
    try:
        p = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, str(e)


def singbox_check(singbox_bin, path):
    # sing-box check пишет WARN в stderr при rc=0 — судим только по коду возврата
    return run_cmd([singbox_bin, "check", "-c", path])


def wait_tun0(timeout=30):
    for _ in range(timeout):
        try:
            with open("/sys/class/net/tun0/carrier") as f:
                if f.read().strip() == "1":
                    return True
        except OSError:
            pass
        time.sleep(1)
    return False


def antiloop_replace(new_ip, old_ip, gw, wan):
    """ip route replace <new>/32 via gw dev wan; маршрут старого убрать (§9.5)."""
    if not (gw and wan):
        return "нет gw/wan в конфиге — anti-loop пропущен"
    run_cmd(["ip", "route", "replace", "%s/32" % new_ip, "via", gw, "dev", wan])
    if old_ip and probe_mod.is_ipv4(old_ip) and old_ip != new_ip:
        run_cmd(["ip", "route", "del", "%s/32" % old_ip])
    return "anti-loop: %s/32 via %s dev %s" % (new_ip, gw, wan)


def patch_boot_script(path, old_ip, new_ip):
    """Замена IP в vpn-boot-setup.sh — re.sub + os.replace, не sed (§15)."""
    if old_ip == new_ip or not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new_text = re.sub(re.escape(old_ip), new_ip, text)
    if new_text == text:
        return False
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new_text)
    shutil.copymode(path, tmp)
    os.replace(tmp, path)
    return True


def verify_egress(expect_host=None):
    """§9.8: IP через tun0 есть, страна не в жёстком блоке, TG отвечает через tun0."""
    rc, ip = run_cmd(["curl", "-s", "--max-time", str(VERIFY_TIMEOUT),
                      "--interface", "tun0", probe_mod.IPIFY_URL], timeout=VERIFY_TIMEOUT + 10)
    ip = ip.strip()
    out = {"egress_ip": ip if probe_mod.looks_like_ip(ip) else None,
           "exit_cc": None, "tg_code": None, "ok": False, "why": ""}
    if not out["egress_ip"]:
        out["why"] = "egress через tun0 пуст"
        return out
    out["exit_cc"] = probe_mod.geo_country(out["egress_ip"])
    if out["exit_cc"] in probe_mod.HARD_BLOCK_CC:
        out["why"] = "страна выхода %s в жёстком блоке" % out["exit_cc"]
        return out
    rc, code = run_cmd(["curl", "-s", "--max-time", str(VERIFY_TIMEOUT), "--interface", "tun0",
                        "-o", "/dev/null", "-w", "%{http_code}", probe_mod.TG_URL],
                       timeout=VERIFY_TIMEOUT + 10)
    out["tg_code"] = code if rc == 0 else "000"
    if not (code.isdigit() and 200 <= int(code) <= 499):
        out["why"] = "Telegram-проба через tun0 не прошла (код %s)" % (code or "000")
        return out
    out["ok"] = True
    return out


def restart_singbox():
    run_cmd(["systemctl", "restart", "sing-box"], timeout=60)
    time.sleep(3)
    rc, act = run_cmd(["systemctl", "is-active", "sing-box"])
    return act.strip() == "active"


# ------------------------------------------------------------------ оркестрация
def stage_candidate(server_cfg, proxy_row, probe_res):
    """Собрать конфиг-кандидат во временный файл (live не тронут).

    -> (stage_path, new_cfg, socks_out, http_tg, reject_quic)
    """
    host = proxy_row.get("host") or proxy_row.get("ip")
    if not probe_mod.is_ipv4(host):
        raise ApplyError("host %r не IPv4 — отклонено валидацией (§15)" % host)
    for p in (probe_res.get("socks_port"), probe_res.get("http_port")):
        if p is not None and not (1 <= int(p) <= 65535):
            raise ApplyError("порт %r вне 1..65535 — отклонено валидацией (§15)" % p)
    socks_out, http_tg, reject_quic = choose_outbounds(
        host, proxy_row.get("user") or "", proxy_row.get("password") or "",
        probe_res.get("socks_port"), probe_res.get("http_port"))
    live = load_json(server_cfg["singbox_config"])
    new_cfg = patch_config(live, socks_out, http_tg, reject_quic)
    stage = server_cfg.get("stage_path") or (server_cfg["singbox_config"] + ".stage")
    dump_json_replace(new_cfg, stage)
    return stage, new_cfg, socks_out, http_tg, reject_quic


def apply_candidate(server_cfg, proxy_row, probe_res, log=print, _locked=False):
    """Живое применение по §9 (без dry-run). Возвращает dict с итогом.

    Вызывающий обязан заранее прогнать probe и убедиться, что кандидат не
    дисквалифицирован. Здесь — только механика применения и отката.
    _locked=True: flock уже держит вызывающий (states.rotate) — не брать повторно.
    """
    cfg_path = server_cfg["singbox_config"]
    ring_dir = server_cfg["ring"]
    boot_script = server_cfg.get("boot_script") or "/usr/local/bin/vpn-boot-setup.sh"
    # только ПОЛНЫЙ путь: агента дёргает cron, где PATH = /usr/bin:/bin, а бинарь
    # в /usr/local/bin. С коротким именем subprocess падает [Errno 2], это читается
    # как «кандидат не прошёл проверку» — и узел уезжает в EMERGENCY (случай 15.08).
    singbox_bin = server_cfg.get("singbox_bin") or "/usr/local/bin/sing-box"
    new_ip = proxy_row.get("host") or proxy_row.get("ip")

    with _maybe_lock(server_cfg, _locked):
        live = load_json(cfg_path)
        old_ip = current_upstream(live)

        stage, new_cfg, socks_out, http_tg, reject_quic = stage_candidate(
            server_cfg, proxy_row, probe_res)
        rc, out = singbox_check(singbox_bin, stage)
        if rc != 0:
            os.unlink(stage)
            raise ApplyError("sing-box check забраковал кандидата (live не тронут):\n%s" % out)
        log("  sing-box check (кандидат): OK")

        backup = backup_ring(cfg_path, ring_dir)
        log("  бэкап: %s (кольцо из 10)" % backup)

        os.replace(stage, cfg_path)
        rc, out = singbox_check(singbox_bin, cfg_path)
        if rc != 0:  # паранойя: вернуть как было, live рестартов ещё не было
            shutil.copyfile(backup, cfg_path)
            raise ApplyError("sing-box check не прошёл после установки — конфиг возвращён:\n%s" % out)

        log("  " + antiloop_replace(new_ip, old_ip, server_cfg.get("gw"), server_cfg.get("wan")))
        if patch_boot_script(boot_script, old_ip, new_ip):
            log("  vpn-boot-setup.sh: %s -> %s" % (old_ip, new_ip))

        def rollback(why):
            log("  ОТКАТ: %s" % why)
            shutil.copyfile(backup, cfg_path)
            antiloop_replace(old_ip, new_ip, server_cfg.get("gw"), server_cfg.get("wan"))
            patch_boot_script(boot_script, new_ip, old_ip)
            ok = restart_singbox()
            wait_tun0()
            v = verify_egress()
            raise ApplyError("%s\nОткат выполнен: config <- %s, anti-loop <- %s, sing-box %s, egress=%s"
                             % (why, os.path.basename(backup), old_ip,
                                "active" if ok else "НЕ ПОДНЯЛСЯ", v.get("egress_ip")))

        if not restart_singbox():
            rc, jr = run_cmd(["journalctl", "-u", "sing-box", "-n", "15", "--no-pager"])
            log(jr)
            rollback("sing-box не поднялся после рестарта")
        if not wait_tun0():
            rollback("tun0 не получил carrier за 30 с")

        v = verify_egress()
        log("  verify: egress=%s cc=%s tg=%s" % (v["egress_ip"], v["exit_cc"], v["tg_code"]))
        if not v["ok"]:
            rollback("verify: " + v["why"])

        return {"ok": True, "old_ip": old_ip, "new_ip": new_ip, "backup": backup,
                "socks_out": socks_out, "http_tg": http_tg, "reject_quic": reject_quic,
                "verify": v}


def rollback_from_ring(server_cfg, backup_path=None, log=print, _locked=False):
    """Откат на бэкап из кольца (по умолчанию самый свежий) + маршруты + verify.
    _locked=True: flock уже держит вызывающий (states.rotate) — не брать повторно."""
    cfg_path = server_cfg["singbox_config"]
    ring_dir = server_cfg["ring"]
    boot_script = server_cfg.get("boot_script") or "/usr/local/bin/vpn-boot-setup.sh"
    singbox_bin = server_cfg.get("singbox_bin") or "sing-box"

    backup = backup_path or newest_backup(ring_dir)
    if not backup or not os.path.isfile(backup):
        raise ApplyError("В кольце %s нет бэкапов — откатывать не из чего" % ring_dir)

    with _maybe_lock(server_cfg, _locked):
        bad_ip = current_upstream(load_json(cfg_path))
        good_ip = current_upstream(load_json(backup))
        rc, out = singbox_check(singbox_bin, backup)
        if rc != 0:
            raise ApplyError("Бэкап %s не проходит sing-box check:\n%s" % (backup, out))
        shutil.copyfile(backup, cfg_path)
        log("  config.json <- %s" % os.path.basename(backup))
        if probe_mod.is_ipv4(good_ip):
            log("  " + antiloop_replace(good_ip, bad_ip, server_cfg.get("gw"), server_cfg.get("wan")))
            if patch_boot_script(boot_script, bad_ip, good_ip):
                log("  vpn-boot-setup.sh: %s -> %s" % (bad_ip, good_ip))
        if not restart_singbox():
            raise ApplyError("sing-box не поднялся после отката — нужен ручной разбор")
        wait_tun0()
        v = verify_egress()
        log("  verify: egress=%s cc=%s tg=%s" % (v["egress_ip"], v["exit_cc"], v["tg_code"]))
        return {"ok": v["ok"], "backup": backup, "bad_ip": bad_ip, "good_ip": good_ip, "verify": v}
