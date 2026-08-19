#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpn-agent — CLI ядра: status | list | probe [uid] | pool-refresh [--probe|--probe-new]
| apply <uid> [--dry-run] | rollback  (фаза 1)
| buy [--country] | prolong <uid> --days N | drop <uid>  (фаза 2 — деньги §6)
| rotate | emergency on|off | heartbeat-check  (фаза 3 — автоматика §8).

Команды с деньгами требуют явного --yes и проходят гейты §6.2/§6.4 (money.py).
rotate — машина состояний §8 (диагностика по порядку -> RETUNE/ROTATING/
REPLENISH/EMERGENCY), шлёт письма-алерты (alerts.py); зовётся сторожем и вручную.

Исполняется НА сервере (Debian 13, только stdlib + системный curl); на
Windows работает dev-режим (пул/проба/dry-run без серверных операций).

Конфиг сервера (§16): /etc/vpn-panel/config.json ->
config.local.json рядом с agent.py -> dev-дефолты.
Секреты: /etc/vpn-panel/secrets.json (0600) -> .secrets.local.json рядом.
"""
import argparse
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PANEL_DIR)

import apply as apply_mod           # noqa: E402
import country as country_mod       # noqa: E402
import money as money_mod           # noqa: E402
import pool as pool_mod             # noqa: E402
import probe as probe_mod           # noqa: E402
import states as states_mod         # noqa: E402
import alerts as alerts_mod         # noqa: E402
import update as update_mod         # noqa: E402
from providers import make_providers, ProviderError  # noqa: E402

ETC_CONFIG = "/etc/vpn-panel/config.json"
ETC_SECRETS = "/etc/vpn-panel/secrets.json"

DEV_DEFAULTS = {
    "server": "dev",
    "role": None,                   # роль пула этого сервера: vpn-ru | vpn-node1
    "subnet": None, "gw": None, "wan": None, "has_dnsmasq": False,
    "db": os.path.join(PANEL_DIR, "state.db"),
    "ring": os.path.join(PANEL_DIR, "cfg"),
    "singbox_config": "/etc/sing-box/config.json",
    "boot_script": "/usr/local/bin/vpn-boot-setup.sh",
    "singbox_bin": "sing-box",
    "lock": "/run/vpn-agent.lock",
}

SERVER_DEFAULTS = {
    "db": "/var/lib/vpn-panel/state.db",
    "ring": "/var/lib/vpn-panel/cfg",
}


def load_config(path=None):
    cfg = dict(DEV_DEFAULTS)
    src = "dev-дефолты"
    for candidate in ([path] if path else [ETC_CONFIG, os.path.join(PANEL_DIR, "config.local.json")]):
        if candidate and os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as f:
                loaded = json.load(f)
            if candidate == ETC_CONFIG:
                cfg.update(SERVER_DEFAULTS)   # серверные пути §13/§14
            cfg.update(loaded)
            src = candidate
            break
    cfg["_source"] = src
    return cfg


def load_secrets():
    for candidate in (ETC_SECRETS, os.path.join(PANEL_DIR, ".secrets.local.json")):
        if os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as f:
                return json.load(f), candidate
    return {}, None


def open_pool(cfg):
    return pool_mod.Pool(cfg["db"], server=cfg.get("server") or "dev")


def read_singbox(cfg):
    try:
        return apply_mod.load_json(cfg["singbox_config"])
    except (OSError, ValueError):
        return None


def fmt_flag(v):
    return {None: "·", 1: "+", 0: "−", True: "+", False: "−"}.get(v, str(v))


def fmt_days(date_end):
    d = probe_mod.days_left(date_end)
    return "—" if d is None else "%.0fд" % d


# ------------------------------------------------------------------- команды
def cmd_status(cfg, args):
    print("=== vpn-agent status ===")
    print("сервер: %s  роль пула: %s  конфиг: %s" % (cfg.get("server"), cfg.get("role"), cfg["_source"]))
    print("сборка: Редут %s" % (update_mod.node_version() or "? (VERSION не найден — узел ставился до Ф0)"))
    print("subnet=%s gw=%s wan=%s dnsmasq=%s" % (cfg.get("subnet"), cfg.get("gw"),
                                                 cfg.get("wan"), cfg.get("has_dnsmasq")))
    sb = read_singbox(cfg)
    if sb:
        for o in sb.get("outbounds", []):
            if o.get("tag") in ("socks-out", "http-tg"):
                print("  %-9s -> %-5s %s:%s" % (o["tag"], o.get("type"), o.get("server"), o.get("server_port")))
        final = (sb.get("route") or {}).get("final")
        quic = any(apply_mod.is_quic_reject(r) for r in (sb.get("route") or {}).get("rules", []))
        print("  route.final=%s  UDP443-reject=%s" % (final or "НЕ ЗАДАН (первый в массиве!)", quic))
    else:
        print("  sing-box конфиг %s недоступен (dev-режим?)" % cfg["singbox_config"])
    if os.name == "posix":
        rc, act = apply_mod.run_cmd(["systemctl", "is-active", "sing-box"])
        print("  sing-box: %s" % (act or "?"))
        v = apply_mod.verify_egress()
        print("  egress tun0: ip=%s cc=%s tg=%s -> %s"
              % (v["egress_ip"], v["exit_cc"], v["tg_code"], "OK" if v["ok"] else "ПЛОХО: " + v["why"]))
    p = open_pool(cfg)
    rows = p.list(include_gone=True)
    alive = [r for r in rows if not r["gone"]]
    print("пул: %d записей (%d живых, %d gone)" % (len(rows), len(alive), len(rows) - len(alive)))
    by = {}
    for r in rows:
        key = (r["provider"], r["role"])
        by[key] = by.get(key, 0) + 1
    for (prov, role), n in sorted(by.items()):
        print("  %-10s %-10s %d" % (prov, role, n))
    # автомат состояний (§8) + пульс (§6.3)
    st = p.get_setting("automat_state") or "OK"
    extra = ""
    if st == states_mod.EMERGENCY:
        extra = "  ⛔ авария с %s" % (p.get_setting("emergency_since") or "?")
    elif p.get_setting("automat_frozen") == "1":
        extra = "  (автоматика на паузе FROZEN)"
    print("автомат: %s%s" % (st, extra))
    hb = p.last_heartbeat()
    hb_age = states_mod.age_seconds(hb)
    print("пульс агента: %s%s" % (hb or "нет",
          "" if hb_age is None else "  (%.1f ч назад)" % (hb_age / 3600.0)))
    p.close()
    return 0


def cmd_list(cfg, args):
    p = open_pool(cfg)
    rows = p.list(include_gone=args.all)
    if not rows:
        print("Пул пуст — сначала: agent.py pool-refresh")
        p.close()
        return 0
    cur = apply_mod.current_upstream(read_singbox(cfg) or {})
    print("%-16s %-2s %-21s %-9s %5s  %-3s%-3s%-3s %-6s %-5s %s"
          % ("uid", "cc", "host:socks/http", "роль", "score", "s5", "ht", "tg", "конец", "проба", ""))
    for r in rows:
        mark = " <== ТЕКУЩИЙ" if cur and r["host"] == cur else (" (gone)" if r["gone"] else "")
        ports = "%s:%s/%s" % (r["host"], r["port_socks5"] or "—", r["port_http"] or "—")
        print("%-16s %-2s %-21s %-9s %5s  %-3s%-3s%-3s %-6s %-5s%s"
              % (r["uid"], r["country"] or "??", ports, r["role"],
                 "—" if r["score"] is None else r["score"],
                 fmt_flag(r["socks_ok"]), fmt_flag(r["http_ok"]), fmt_flag(r["tg_ok"]),
                 fmt_days(r["date_end"]),
                 (r["last_probe_at"] or "")[5:10] or "нет", mark))
    p.close()
    return 0


def cmd_pool_refresh(cfg, args):
    secrets, src = load_secrets()
    providers = make_providers(secrets)
    if not providers:
        print("Нет ключей провайдеров (secrets: %s)" % (src or "не найден"))
        return 1
    p = open_pool(cfg)
    current_host = apply_mod.current_upstream(read_singbox(cfg) or {})
    # active = провайдеры с ключом на диске (make_providers создаёт адаптер только при
    # ключе) — строки осиротевших провайдеров удаляются из пула (П7-2), кроме боевого
    summary = p.refresh(providers, actor="user", active=set(providers),
                        keep_hosts={current_host} if current_host else None)
    for name, s in summary["providers"].items():
        print("%-10s: всего %d, новых %d, обновлено %d, gone %d"
              % (name, s["total"], s["added"], s["updated"], s["gone"]))
    for name, n in (summary.get("stale") or {}).items():
        print("%-10s: ключа больше нет — %d строк удалено из пула" % (name, n))
    for name, err in summary["errors"].items():
        print("%-10s: ОШИБКА — %s" % (name, err))
    for name, prov in providers.items():
        if name in summary["errors"]:
            continue
        try:
            b = prov.balance()
            # держим баланс в setting свежим — панель читает его отсюда (раньше
            # писал только веб, и до первого клика «Обновить пул» баланс пустовал)
            money_mod.store_balance(p, name, b)
            print("%-10s: баланс %s %s" % (name, b.get("balance"), b.get("currency")))
        except ProviderError as e:
            print("%-10s: баланс недоступен — %s" % (name, e))
    p.heartbeat()   # §6.3: pool-refresh — тоже успешный цикл агента

    # Метка живого выхода для дашборда. Без этого она обновлялась только кнопкой,
    # apply/rollback и диагностикой ротации — то есть после самопочинки в панели
    # продолжала висеть СТАРАЯ ошибка (случай 15.08: авария снята в 09:56, а панель
    # ещё полчаса показывала «цепочка нарушена» с меткой 09:30).
    try:
        v = apply_mod.verify_egress()
        p.set_egress(v)
        # DEGRADED от автоматики + снятие залипших SUSPECT/DEGRADED: сторож в этих
        # сценариях rotate не зовёт (его проверка — ipify), синхронизируем здесь
        states_mod.sync_degraded_state(p, v, alerter=_make_alerter(cfg, secrets))
    except Exception as e:
        print("egress-метка не обновлена (не критично): %s" % e)

    # П7-2: боевой канал сидит на провайдере без ключа (ключ удалили, а переключение
    # тогда не удалось или было на паузе) — пробуем увести его по стратегии каждым
    # тиком, пока не получится. При живом канале rotate этого не сделает никогда.
    row = next((r for r in p.list(include_gone=True) if r["host"] == current_host),
               None) if current_host else None
    if row is not None and row["provider"] not in providers:
        r = states_mod.switch_from_provider(cfg, providers, p, _make_alerter(cfg, secrets),
                                            row["provider"], log=print, actor="auto",
                                            reason="pool-refresh")
        print("боевой у провайдера без ключа (%s): %s" % (row["provider"], r["detail"]))

    if getattr(args, "probe_new", False) and not getattr(args, "probe", False):
        # смена ключа из панели (§12 /api/key): проверить сразу ТОЛЬКО новые
        # каналы; при --probe не дублируем — полный прогон ниже покроет и их
        probe_new_channels(p, cfg, providers, current_host)

    if getattr(args, "probe", False):
        # cron раз в 2 ч (E2): держим кандидатов проверенными заранее (§6.0) + N+1 (§6.5)
        rows = p.candidates()
        ok = 0
        for row in rows:
            res = _probe_one(p, cfg, providers, row, current_host, background=True)
            ok += 1 if res["ok"] else 0
        print("проба кандидатов: %d/%d ok" % (ok, len(rows)))
        alerter = _make_alerter(cfg, secrets)
        rr = states_mod.ensure_reserve(cfg, providers, p, alerter, print, "auto")
        if rr.get("bought"):
            print("N+1: докуплен резерв (%s)" % (rr.get("uids") or rr.get("reason")))
        else:
            print("N+1: резерв в норме (%s)" % (rr.get("have", "?")))
        pr = p.prune()          # retention E1: probe_log 90 дн / event 180 дн, раз в сутки
        if pr:
            print("retention: probe_log −%d, event −%d" % (pr["probe_log"], pr["event"]))
    p.close()
    return 1 if summary["errors"] and not summary["providers"] else 0


def cmd_egress_mark(cfg, args):
    """Лёгкая метка выхода для дашборда (E2): ОДИН ipify-curl через tun0, без
    Telegram. Крон каждые 5 мин — дашборд считает метку старше 15 мин протухшей.

    «Зелёный маяк» = связь есть; здоровье Telegram — отдельная забота (полный
    verify пишут pool-refresh раз в 30 мин, кнопка панели, apply и диагностика
    ротации). Инвариант «никогда RU-выход» держим и здесь: geoip — дёшево."""
    if os.name != "posix":
        print("egress-mark доступен только на сервере (tun0)")
        return 1
    p = open_pool(cfg)
    rc, ip = apply_mod.run_cmd(["curl", "-s", "--max-time", "10", "--interface", "tun0",
                                probe_mod.IPIFY_URL], timeout=20)
    ip = (ip or "").strip()
    v = {"egress_ip": ip if probe_mod.looks_like_ip(ip) else None,
         "exit_cc": None, "tg_code": None, "ok": False, "why": ""}
    if v["egress_ip"]:
        v["exit_cc"] = probe_mod.geo_country(v["egress_ip"])
        if v["exit_cc"] in probe_mod.HARD_BLOCK_CC:
            v["why"] = "страна выхода %s в жёстком блоке" % v["exit_cc"]
        else:
            v["ok"] = True
    else:
        v["why"] = "egress через tun0 пуст"
    p.set_egress(v)
    # лёгкая метка TG не меряет: только снимает залипший SUSPECT при живом выходе
    states_mod.sync_degraded_state(p, v, light=True)
    if v["ok"]:
        # F8: время «в бою» пары боевого канала — приращением от прошлой живой метки
        # (cap 10 мин: перерывы связи и простои узла временем боя не считаются)
        host = apply_mod.current_upstream(read_singbox(cfg) or {})
        row = next((r for r in p.list(include_gone=True) if r["host"] == host), None) if host else None
        delta = states_mod.age_seconds(p.get_setting("battle_mark_at"))
        if row is not None and delta is not None:
            p.stability_bump_battle(row["provider"], row.get("country"), min(int(delta), 600))
        p.set_setting("battle_mark_at", pool_mod.now_iso())
    print("egress-mark: ip=%s cc=%s -> %s"
          % (v["egress_ip"] or "—", v["exit_cc"] or "??", "ok" if v["ok"] else v["why"]))
    p.close()
    return 0


def _probe_one(p, cfg, providers, row, current_host, background=False):
    """Проба одной записи + запись в БД. -> результат probe

    background=True — фоновый крон-прогон (F5): одиночный провал не инкрементит
    fail_count, см. pool.record_probe."""
    check_cb = None
    prov = providers.get(row["provider"])
    if prov is not None and prov.caps.get("check"):
        check_cb = lambda: prov.check(row["ext_id"])  # noqa: E731
    res = probe_mod.probe(row, provider_check=check_cb)
    is_cur = row["host"] == current_host
    res["score"] = probe_mod.score(row, res, is_current=is_cur, cfg=cfg)
    p.record_probe(row["uid"], res, is_current=is_cur, strategy=country_mod.strategy(cfg),
                   background=background)
    return res


def probe_new_channels(p, cfg, providers, current_host, log=print):
    """Проба каналов, которых ещё НИ РАЗУ не проверяли (жалоба владельца 19.08).

    Панель зовёт через `pool-refresh --probe-new` сразу после смены/добавления
    ключа: каналы нового кабинета уже в пуле, но без пробы они висят в таблице
    «не проверялся», а превью стратегий и автоматика видят их слепыми — до
    двухчасового крона проверка не случалась вовсе. Перебор — в порядке текущей
    стратегии (как ротация); уже проверенные каналы не перегоняются, денег не
    тратит (докупка N+1 остаётся дорожкой --probe). -> (ok, всего_новых)."""
    fresh = states_mod.rank_candidates(
        [r for r in p.candidates() if not r.get("last_probe_at")], cfg)
    ok = 0
    for row in fresh:
        res = _probe_one(p, cfg, providers, row, current_host, background=True)
        ok += 1 if res["ok"] else 0
    if fresh:
        p.log_event("probe-new", actor="auto", result="%d/%d ok" % (ok, len(fresh)),
                    detail="новые каналы проверены по текущей стратегии (после смены ключа)")
    log("проверка новых каналов: %d/%d ok" % (ok, len(fresh)))
    return ok, len(fresh)


def cmd_probe(cfg, args):
    p = open_pool(cfg)
    secrets, _ = load_secrets()
    providers = make_providers(secrets)
    current_host = apply_mod.current_upstream(read_singbox(cfg) or {})
    if args.uid:
        row = p.get(args.uid)
        if not row:
            print("uid %s не найден в пуле (agent.py pool-refresh?)" % args.uid)
            p.close()
            return 1
        rows = [row]
    else:
        rows = p.candidates()
        if not rows:
            print("Кандидатов нет (пул пуст или все off/gone)")
            p.close()
            return 0
    ok_count = 0
    for row in rows:
        res = _probe_one(p, cfg, providers, row, current_host)
        ok_count += 1 if res["ok"] else 0
        matrix = " ".join("%s=%s" % (k, "ip" if v else "—") for k, v in sorted(res["matrix"].items()))
        extra = ""
        if res["disqualified"]:
            extra = "  ДИСКВАЛИФИКАЦИЯ: %s" % res["disqualified"]
        print("%-16s %-4s score=%-6s exit=%-15s cc=%-2s tg=%s lat=%sms  [%s]%s"
              % (row["uid"], "OK" if res["ok"] else "FAIL",
                 res["score"] if res["score"] is not None else "—",
                 res["exit_ip"] or "—", res["exit_cc"] or "??",
                 fmt_flag(res["tg_ok"]), res["latency_ms"] or "—", matrix, extra))
    p.log_event("probe", actor="user", result="%d/%d ok" % (ok_count, len(rows)))
    p.close()
    return 0


def cmd_apply(cfg, args):
    p = open_pool(cfg)
    row = p.get(args.uid)
    if not row:
        print("uid %s не найден в пуле" % args.uid)
        p.close()
        return 1
    secrets, _ = load_secrets()
    providers = make_providers(secrets)
    sb = read_singbox(cfg)
    if sb is None:
        print("sing-box конфиг %s недоступен — apply невозможен" % cfg["singbox_config"])
        p.close()
        return 1
    current_host = apply_mod.current_upstream(sb)

    print("=== Проба кандидата %s (%s) ===" % (row["uid"], row["host"]))
    res = _probe_one(p, cfg, providers, row, current_host)
    for (pp, proto) in sorted((k.split("/")[0], k.split("/")[1]) for k in res["matrix"]):
        v = res["matrix"]["%s/%s" % (pp, proto)]
        print("  порт %-6s %-6s -> %s" % (pp, proto.upper(), v or "нет"))
    if res["disqualified"] or not res["ok"]:
        print("❌ Кандидат дисквалифицирован: %s — ничего не применяю"
              % (res["disqualified"] or "проба не прошла"))
        p.close()
        return 1
    print("  exit=%s cc=%s tg=%s latency=%sms score=%s"
          % (res["exit_ip"], res["exit_cc"], fmt_flag(res["tg_ok"]), res["latency_ms"], res["score"]))

    socks_out, http_tg, reject_quic = apply_mod.choose_outbounds(
        row["host"], row["user"] or "", row["password"] or "",
        res["socks_port"], res["http_port"])
    def mode(o):
        return ("SOCKS5" if o["type"] == "socks" else "HTTP") + " :%s" % o["server_port"]
    print("  socks-out (весь трафик) -> %s%s" % (mode(socks_out),
          "   (фолбэк по типу: SOCKS5 мёртв)" if socks_out["type"] == "http" else ""))
    print("  http-tg   (Telegram)    -> %s%s" % (mode(http_tg),
          "   (фолбэк по типу: HTTP мёртв)" if http_tg["type"] == "socks" else ""))
    print("  UDP 443 -> reject: %s" % ("ДА (HTTP-режим)" if reject_quic else "нет (SOCKS5-режим)"))

    if args.dry_run:
        stage, new_cfg, *_ = apply_mod.stage_candidate(cfg, row, res)
        import shutil
        if shutil.which(cfg.get("singbox_bin") or "sing-box"):
            rc, out = apply_mod.singbox_check(cfg.get("singbox_bin") or "sing-box", stage)
            if rc != 0:
                os.unlink(stage)
                print("❌ sing-box check забраковал кандидата:\n%s" % out)
                p.close()
                return 1
            print("  sing-box check (кандидат): OK")
        else:
            print("  ⚠️ sing-box бинарь недоступен — check пропущен (dev)")
        shown = {"outbounds": [o for o in new_cfg["outbounds"] if o.get("tag") in ("socks-out", "http-tg")],
                 "route": new_cfg.get("route")}
        print("\n[dry-run] итоговые outbound'ы и route:\n" + json.dumps(shown, indent=2, ensure_ascii=False))
        os.unlink(stage)
        print("\n[dry-run] изменения НЕ применены.")
        p.close()
        return 0

    if os.name != "posix":
        print("Живой apply возможен только на сервере (Linux)")
        p.close()
        return 1
    try:
        r = apply_mod.apply_candidate(cfg, row, res)
    except apply_mod.ApplyError as e:
        p.log_event("apply", actor="user", to_uid=row["uid"], result="fail", detail=str(e))
        print("❌ %s" % e)
        p.close()
        return 1
    p.mark_used(row["uid"])
    if row["role"] == "off":
        # П9: успешный apply переводит off->auto — боевой канал должен быть виден
        # selectable_candidates и подсчёту резерва
        p.set_role(row["uid"], "auto")
        p.log_event("role", actor="auto", to_uid=row["uid"], result="auto",
                    detail="успешный apply переводит off->auto (П9)")
    p.log_event("apply", actor="user", from_uid=None, to_uid=row["uid"], result="ok",
                detail=json.dumps({"old_ip": r["old_ip"], "new_ip": r["new_ip"],
                                   "verify": r["verify"]}, ensure_ascii=False))
    print("✅ Применён %s: %s -> %s, egress=%s (%s), tg=%s"
          % (row["uid"], r["old_ip"], r["new_ip"], r["verify"]["egress_ip"],
             r["verify"]["exit_cc"], r["verify"]["tg_code"]))
    p.close()
    return 0


def cmd_rollback(cfg, args):
    if os.name != "posix":
        print("rollback возможен только на сервере (Linux)")
        return 1
    p = open_pool(cfg)
    try:
        r = apply_mod.rollback_from_ring(cfg, backup_path=args.backup)
    except apply_mod.ApplyError as e:
        p.log_event("rollback", actor="user", result="fail", detail=str(e))
        print("❌ %s" % e)
        p.close()
        return 1
    p.log_event("rollback", actor="user", result="ok" if r["ok"] else "verify-fail",
                detail=json.dumps({"backup": r["backup"], "bad_ip": r["bad_ip"],
                                   "good_ip": r["good_ip"]}, ensure_ascii=False))
    print(("✅" if r["ok"] else "⚠️") + " Откат: %s -> %s (бэкап %s), verify %s"
          % (r["bad_ip"], r["good_ip"], os.path.basename(r["backup"]),
             "OK" if r["ok"] else "НЕ ПРОШЁЛ: " + r["verify"]["why"]))
    p.close()
    return 0 if r["ok"] else 1


# ------------------------------------------------------------- деньги (§6, фаза 2)
def _providers_and_pool(cfg):
    secrets, _ = load_secrets()
    return make_providers(secrets), open_pool(cfg)


def _balance_num(prov):
    try:
        return money_mod._num((prov.balance() or {}).get("balance"))
    except Exception:
        return None


def _postbuy_check(cfg, p, providers, bought):
    """§6.1 постфактум: подтянуть паспорт (getproxy) и прогнать пробу на РЕАЛЬНУЮ
    страну выхода. Выход в жёстком блоке СНГ -> off + алерт, не используем."""
    prov = providers.get("proxy6")
    if prov is not None:
        try:
            p.refresh({"proxy6": prov})   # getproxy: полные паспортные поля новых uid
        except Exception:
            pass
    current_host = apply_mod.current_upstream(read_singbox(cfg) or {})
    out = []
    for pxy in bought:
        uid = "%s:%s" % (pxy["provider"], pxy["ext_id"])
        row = p.get(uid) or dict(pxy, uid=uid)
        res = _probe_one(p, cfg, providers, row, current_host)
        blocked = (res.get("exit_cc") in probe_mod.HARD_BLOCK_CC
                   or str(res.get("disqualified") or "").startswith("blocked-cc"))
        if blocked:
            p.set_role(uid, "off")
            p.log_event("buy-postcheck", actor="user", to_uid=uid, result="blocked-cc",
                        detail="реальный выход cc=%s в жёстком блоке §6.1 -> off, не используем"
                        % res.get("exit_cc"))
        out.append((uid, res, blocked))
    return out


def cmd_buy(cfg, args):
    providers, p = _providers_and_pool(cfg)
    prov = providers.get("proxy6")
    if prov is None:
        print("Нет ключа PROXY6 — покупка недоступна")
        p.close()
        return 1
    lim = money_mod.limits(cfg)
    period = args.period or lim["buy_period_days"]
    version = int(lim["buy_version"])
    country = (args.country or "").strip().lower()
    # страну назвали руками — запрещаем только чёрный список; не назвали — идём по оценке
    if country and country_mod.is_blocked(country, cfg):
        print("Страна %s в чёрном списке — не покупаем никогда (§6.1)" % country)
        p.close()
        return 1
    if country and not country_mod.auto_allowed(country, True, cfg):
        print("⚠️ %s: %s. Покупаю, потому что страну указал ты явно."
              % (country, country_mod.explain(country)))
    chosen = [country] if country else money_mod.buy_candidates(cfg, pool=p)

    # рынок: первая страна белого списка с наличием (getcount), цена — getprice
    pick = avail = None
    for cc in chosen:
        try:
            n = prov.getcount(cc, version)
        except ProviderError as e:
            print("  getcount %s: %s" % (cc, e))
            continue
        if n > 0:
            pick, avail = cc, n
            break
        print("  %s: нет в наличии (0)" % cc)
    if not pick:
        print("Нет прокси version=%d в наличии ни в одной стране белого списка" % version)
        p.close()
        return 1

    try:
        pre = money_mod.preflight_buy(p, prov, cfg, country=pick, period=period,
                                      count=1, version=version)
    except money_mod.SpendDenied as e:
        print("❌ Гейт трат: %s" % e)
        p.close()
        return 1
    bal = pre["balance_before"]
    print("Выбрано: %s (в наличии %s), период %d дн, version=%d" % (pick, avail, period, version))
    print("Цена: %.2f %s · баланс %s -> ~%.2f · лимиты: ≤%.0f/покупка, ≤%.0f/сутки, остаток ≥%.0f"
          % (pre["price"], pre["currency"], bal, (bal or 0) - pre["price"],
             lim["max_price_per_buy"], lim["max_spend_per_day"], lim["min_balance_reserve"]))
    if args.dry_run:
        print("[dry-run] гейты пройдены, покупка НЕ выполнена.")
        p.close()
        return 0
    if not args.yes:
        print("РЕАЛЬНАЯ ТРАТА. Для подтверждения покупки добавь --yes.")
        p.close()
        return 2
    try:
        r = money_mod.plan_and_buy(p, prov, cfg, country=pick, period=period, count=1,
                                   version=version, server=cfg.get("server"), actor="user")
    except money_mod.SpendDenied as e:
        print("❌ Гейт трат: %s" % e)
        p.close()
        return 1
    uids = ", ".join("%s:%s" % (x["provider"], x["ext_id"]) for x in r["proxies"])
    print("✅ Куплено: %s · цена %.2f %s · order=%s · баланс=%s%s"
          % (uids, r["price"], r["currency"], r["order_id"], r["balance_after"],
             "  (ВОССТАНОВЛЕНО по descr)" if r["recovered"] else ""))
    print("Проба постфактум — реальная страна выхода (§6.1):")
    for uid, res, blocked in _postbuy_check(cfg, p, providers, r["proxies"]):
        print("  %s: exit=%s cc=%s tg=%s score=%s%s"
              % (uid, res.get("exit_ip") or "—", res.get("exit_cc") or "??",
                 fmt_flag(res.get("tg_ok")), res.get("score"),
                 "  ⛔ ВЫХОД В БЛОКЕ -> off" if blocked else "  ✅ страна ок"))
    p.close()
    return 0


def cmd_prolong(cfg, args):
    providers, p = _providers_and_pool(cfg)
    row = p.get(args.uid)
    if not row:
        print("uid %s не найден в пуле" % args.uid)
        p.close()
        return 1
    prov = providers.get(row["provider"])
    if prov is None or not prov.caps.get("prolong"):
        print("Провайдер %s не умеет продление" % row["provider"])
        p.close()
        return 1
    if not args.yes:
        print("РЕАЛЬНАЯ ТРАТА (продление %s на %d дн). Для подтверждения добавь --yes." % (args.uid, args.days))
        p.close()
        return 2
    try:
        r = money_mod.prolong_with_limits(p, prov, cfg, row=row, days=args.days, actor="user")
    except money_mod.SpendDenied as e:
        print("❌ Гейт трат: %s" % e)
        p.close()
        return 1
    print("✅ Продлён %s на %d дн · цена %s %s · баланс=%s · date_end=%s"
          % (r["uid"], r["days"], r["price"], r["currency"], r["balance_after"], r["date_end"]))
    p.close()
    return 0


def cmd_drop(cfg, args):
    providers, p = _providers_and_pool(cfg)
    row = p.get(args.uid)
    if not row:
        print("uid %s не найден в пуле" % args.uid)
        p.close()
        return 1
    prov = providers.get(row["provider"])
    if prov is None or not prov.caps.get("delete"):
        print("Провайдер %s не умеет удаление (только PROXY6)" % row["provider"])
        p.close()
        return 1
    current_host = apply_mod.current_upstream(read_singbox(cfg) or {})
    pchk = None
    try:
        pchk = prov.check(row["ext_id"])
    except ProviderError as e:
        print("  check провайдера недоступен: %s" % e)

    if args.experiment:
        # Приёмочный эксперимент §6.4: намеренно удаляем ЗДОРОВЫЙ свежекупленный
        # прокси, чтобы измерить возврат средств. Health-гейты §6.4 п.1–2 не
        # применяем (на то он и эксперимент), но «текущий upstream» защищён.
        if current_host and row["host"] == current_host:
            print("Это ТЕКУЩИЙ upstream — эксперимент на нём запрещён")
            p.close()
            return 1
        if not args.yes:
            print("ЭКСПЕРИМЕНТ §6.4: удалит РЕАЛЬНЫЙ прокси %s и измерит возврат. Добавь --yes." % args.uid)
            p.close()
            return 2
        bal_before = _balance_num(prov)
        end_before = row.get("date_end")
        n = money_mod.delete_and_record(p, prov, row, actor="user", currency="RUB",
                                        note="приёмочный эксперимент §6.4 (возврат средств)")
        import time
        time.sleep(3)
        bal_after = _balance_num(prov)
        refund = None if (bal_before is None or bal_after is None) else round(bal_after - bal_before, 2)
        p.log_event("delete-experiment", actor="user", from_uid=row["uid"], result="done",
                    detail=json.dumps({"deleted": n, "date_end": end_before,
                                       "balance_before": bal_before, "balance_after": bal_after,
                                       "refund": refund}, ensure_ascii=False))
        print("✅ Удалено %d · баланс %s -> %s · ВОЗВРАТ = %s RUB (date_end был %s)"
              % (n, bal_before, bal_after, refund, end_before))
        print("   Вывод: %s" % ("средства ВЕРНУЛИСЬ — можно удалять сразу после смерти прокси"
                                 if refund and refund > 0 else
                                 "возврата НЕТ (или ~0) — оставшиеся дни теряются, удаляем только труп у date_end"))
        p.close()
        return 0

    ok, reason = money_mod.can_delete(row, cfg, current_host=current_host, provider_check=pchk)
    if not ok:
        print("❌ Удаление запрещено гейтом §6.4: %s" % reason)
        p.close()
        return 1
    if not args.yes:
        print("Удаление %s проходит гейты §6.4 (%s). Для подтверждения добавь --yes." % (args.uid, reason))
        p.close()
        return 2
    n = money_mod.delete_and_record(p, prov, row, actor="user", currency="RUB")
    print("✅ Удалено %d (%s)" % (n, args.uid))
    p.close()
    return 0


# ------------------------------------------------------- автоматика (§8, фаза 3)
def _make_mask(secrets):
    """Маска секретов для тела писем/логов (§15): ключи провайдеров, SMTP-пароль."""
    vals = []
    for v in (secrets or {}).values():
        if isinstance(v, dict):
            for kk in ("api_key", "password"):
                if v.get(kk):
                    vals.append(str(v[kk]))
    vals = [x for x in vals if len(x) >= 6]   # не маскируем короткие/пустые
    def mask(text):
        t = str(text)
        for x in vals:
            t = t.replace(x, "****")
        return t
    return mask


def _make_alerter(cfg, secrets):
    return alerts_mod.make_alerter(secrets, cfg, log=lambda m: print("  [alert] %s" % m),
                                   mask=_make_mask(secrets))


def cmd_rotate(cfg, args):
    secrets, _ = load_secrets()
    providers = make_providers(secrets)
    p = open_pool(cfg)
    alerter = _make_alerter(cfg, secrets)
    # F3: кнопка панели (--reason panel) — тоже человек: rotations_last_hour считает
    # только actor='auto', ручные запуски в антифлаппинг-лимит не попадают
    reason = args.reason or "manual"
    actor = "user" if reason in ("manual", "panel") else "auto"
    r = states_mod.rotate(cfg, providers, p, alerter, reason=reason, actor=actor,
                          log=print, force=args.force)
    print("=> состояние: %s · действие: %s\n   %s" % (r["state"], r["action"], r["detail"]))
    p.close()
    # OK/FROZEN/FROZEN_NET — не ошибки процесса; EMERGENCY/None — ненулевой код
    return 0 if r["state"] in (states_mod.OK, states_mod.FROZEN, states_mod.FROZEN_NET) else 1


def cmd_auto_prolong(cfg, args):
    """Продлить боевой прокси до истечения (§6.3). Крон раз в сутки."""
    secrets, _ = load_secrets()
    providers = make_providers(secrets)
    p = open_pool(cfg)
    alerter = _make_alerter(cfg, secrets)
    ap = states_mod.auto_prolong_cfg(cfg)
    print("автопродление: %s, порог %s дн, период %s дн, охват: боевой"
          % ("включено" if ap["enabled"] else "ВЫКЛЮЧЕНО",
             ap["days_before"], ap["period_days"]))
    r = states_mod.auto_prolong(cfg, providers, p, alerter, log=print, actor="auto")
    if r.get("skipped"):
        print("  пропуск: %s" % r["skipped"])
    elif not r.get("prolonged"):
        print("  продлевать нечего — до истечения ещё далеко")
    p.close()
    return 0 if r.get("ok") else 1


def cmd_emergency(cfg, args):
    secrets, _ = load_secrets()
    p = open_pool(cfg)
    alerter = _make_alerter(cfg, secrets)
    if os.name != "posix":
        print("⚠️ Маршруты аварийного режима меняются только на сервере (Linux); ставлю только флаг.")
    r = states_mod.set_emergency(cfg, p, alerter, on=(args.state == "on"), log=print, actor="user")
    print("Аварийный режим: %s (состояние автомата: %s)"
          % ("ВКЛючён — прямой выход через WAN" if args.state == "on" else "выключен", r["state"]))
    p.close()
    return 0


def cmd_switch_provider(cfg, args):
    """П7-2: увести боевой канал с провайдера, у которого удалили ключ.

    Зовёт панель транзиентным юнитом сразу после удаления ключа (redut-switch);
    ретраи — pool-refresh. Канал живой, поэтому rotate не годится («делать нечего») —
    здесь путь «В бой»: кандидаты по стратегии, проба, apply с verify и автооткатом."""
    secrets, _ = load_secrets()
    providers = make_providers(secrets)
    p = open_pool(cfg)
    name = args.from_provider
    if name in providers:
        print("У %s есть ключ — переключение не требуется" % name)
        p.close()
        return 0
    r = states_mod.switch_from_provider(cfg, providers, p, _make_alerter(cfg, secrets),
                                        name, log=print, actor="user",
                                        reason=args.reason or "key-removed")
    print("=> %s" % r["detail"])
    p.close()
    return 0 if r["ok"] else 1


def cmd_self_update(cfg, args):
    """Система обновлений (vpn/UPDATE-PLAN.md).

    По умолчанию (и с --check) только сверяет узел с маяком VERSION на GitHub и пишет
    состояние/событие/письмо. --apply — скачать и установить (бэкап, verify, откат).
    --cron — режим планировщика: jitter -> check -> в окно и при включённом авто — apply."""
    if (args.apply_now or args.cron) and os.name != "posix":
        print("Применение обновления меняет живой узел — только на сервере (Linux). "
              "На dev-машине доступна только проверка: self-update --check.")
        return 1
    secrets, _ = load_secrets()
    p = open_pool(cfg)
    alerter = _make_alerter(cfg, secrets)
    log = lambda m: print("  %s" % m)   # noqa: E731 — стиль лога агента
    try:
        if args.cron:
            r = update_mod.cron_tick(cfg, pool=p, alerter=alerter, log=log)
            c = r["check"]
            if c["error"]:
                print("Проверка не удалась: %s" % c["error"])
                return 0        # сетевые беды — не авария крона, повтор завтра
            if r["applied"] is not None:
                a = r["applied"]
                print("Итог: %s" % ("обновлён до %s" % a["to"] if a["ok"]
                                    else "провал (%s), откат %s" % (a["why"], a["rolled_back"])))
                return 0 if a["ok"] else 1
            print("Обновление не применялось%s." % (": %s" % r["skip"] if r["skip"] else
                                                    " (новых версий нет)"))
            return 0
        if args.apply_now:
            r = update_mod.apply(cfg, pool=p, alerter=alerter, log=log,
                                 target=args.to_version, manual=True,
                                 force=getattr(args, "force_apply", False))
            if r["ok"]:
                print("Узел обновлён: Редут %s -> %s." % (r["from"] or "?", r["to"]))
                return 0
            print("Обновление не применено: %s%s"
                  % (r["why"], " (откат выполнен)" if r["rolled_back"] else ""))
            return 1
        r = update_mod.check(cfg, pool=p, alerter=alerter, log=log)
        if r["error"]:
            print("Проверка не удалась: %s" % r["error"])
            return 1
        if r["newer"] and r["bad"]:
            print("Версия %s есть, но в чёрном списке (обновление на неё уже проваливалось) — "
                  "автоматика её не тронет; руками: self-update --apply --version %s"
                  % (r["remote"], r["remote"]))
        elif r["newer"]:
            print("Доступно обновление: Редут %s -> %s (поставить: self-update --apply)."
                  % (r["local"] or "?", r["remote"]))
        else:
            print("Обновлений нет (узел %s, маяк %s)." % (r["local"] or "?", r["remote"]))
        return 0
    finally:
        p.close()


def cmd_heartbeat_check(cfg, args):
    secrets, _ = load_secrets()
    p = open_pool(cfg)
    alerter = _make_alerter(cfg, secrets)
    r = states_mod.heartbeat_check(p, alerter)
    if r["stale"]:
        print("⚠️ Пульс агента устарел (%.1f ч)%s"
              % (r["age_h"], " — письмо отправлено" if r.get("alerted") else " (уже уведомляли)"))
    else:
        print("Пульс агента свеж%s" % ("" if r["age_h"] is None else " (%.1f ч назад)" % r["age_h"]))
    p.close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vpn-agent", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="путь к config.json (дефолт: %s)" % ETC_CONFIG)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="состояние сервера и пула")
    sp = sub.add_parser("list", help="пул из кэша")
    sp.add_argument("--all", action="store_true", help="включая gone")
    sp = sub.add_parser("pool-refresh", help="обновить пул у провайдеров (merge, gone; cron */30 мин)")
    sp.add_argument("--probe", action="store_true",
                    help="+ проба кандидатов, резерв N+1, retention (cron раз в 2 ч)")
    sp.add_argument("--probe-new", dest="probe_new", action="store_true",
                    help="+ проба только НОВЫХ (ещё не проверявшихся) каналов — "
                         "панель зовёт после смены ключа провайдера; денег не тратит")
    sub.add_parser("egress-mark",
                   help="лёгкая метка выхода для дашборда: ipify через tun0, без TG (cron */5 мин)")
    sp = sub.add_parser("probe", help="проба кандидата/всех кандидатов")
    sp.add_argument("uid", nargs="?", help="uid=provider:id; без uid — все кандидаты")
    sp = sub.add_parser("apply", help="применить кандидата (проба -> §9)")
    sp.add_argument("uid")
    sp.add_argument("--dry-run", action="store_true", help="проба+сборка+check, без применения")
    sp = sub.add_parser("rollback", help="откат на бэкап из кольца")
    sp.add_argument("--backup", help="конкретный файл кольца (дефолт: самый свежий)")
    sp = sub.add_parser("buy", help="⚠️ купить прокси (PROXY6, деньги §6.2)")
    sp.add_argument("--country", help="страна iso2, любая вне чёрного списка (по умолч. — лучшая по рейтингу)")
    sp.add_argument("--period", type=int, help="период, дней (дефолт из config.money.buy_period_days)")
    sp.add_argument("--dry-run", action="store_true", help="показать рынок+гейты, не покупать")
    sp.add_argument("--yes", action="store_true", help="подтвердить РЕАЛЬНУЮ трату")
    sp = sub.add_parser("prolong", help="⚠️ продлить прокси (деньги §6.3)")
    sp.add_argument("uid", help="uid=provider:id")
    sp.add_argument("--days", type=int, required=True, help="на сколько дней")
    sp.add_argument("--yes", action="store_true", help="подтвердить РЕАЛЬНУЮ трату")
    sp = sub.add_parser("drop", help="⚠️ удалить прокси (необратимо, гейты §6.4)")
    sp.add_argument("uid", help="uid=provider:id")
    sp.add_argument("--yes", action="store_true", help="подтвердить необратимое удаление")
    sp.add_argument("--experiment", action="store_true",
                    help="приёмочный эксперимент §6.4: удалить здоровый прокси и измерить возврат")
    sp = sub.add_parser("rotate", help="машина состояний §8: диагностика -> RETUNE/ROTATING/REPLENISH/EMERGENCY")
    sp.add_argument("--reason", help="источник вызова (watchdog/cron); без него — ручной запуск (обходит лимит замен)")
    sp.add_argument("--force", action="store_true", help="игнорировать паузу FROZEN и тайминг аварии")
    sp = sub.add_parser("emergency", help="аварийный режим вкл/выкл (прямой выход через WAN §8)")
    sp.add_argument("state", choices=["on", "off"])
    sp = sub.add_parser("switch-provider",
                        help="П7-2: увести боевой канал с провайдера без ключа (после удаления ключа)")
    sp.add_argument("--from", dest="from_provider", required=True,
                    help="провайдер, с которого уходим (proxy6|proxyline)")
    sp.add_argument("--reason", help="источник вызова (панель пишет key-removed)")
    sub.add_parser("heartbeat-check", help="проверить пульс агента (§6.3); письмо, если нет цикла >24ч")
    sub.add_parser("auto-prolong", help="⚠️ продлить боевой прокси до истечения (§6.3, деньги; крон раз в сутки)")
    sp = sub.add_parser("self-update", help="обновления с GitHub (UPDATE-PLAN): проверить маяк / применить")
    sp.add_argument("--check", action="store_true", help="только сверить версии (поведение по умолчанию)")
    sp.add_argument("--apply", dest="apply_now", action="store_true",
                    help="скачать и установить (бэкап -> UPDATE=1 setup.sh -> verify -> откат при провале)")
    sp.add_argument("--version", dest="to_version",
                    help="какую версию ставить (по умолчанию — свежая с маяка; строго новее узла)")
    sp.add_argument("--force", dest="force_apply", action="store_true",
                    help="вместе с --apply: переустановить ТУ ЖЕ версию заново (лечение узла); "
                         "даунгрейд запрещён и с этим флагом")
    sp.add_argument("--cron", action="store_true",
                    help="режим планировщика: jitter -> check -> apply при авто+окне (крон 04:41)")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    handlers = {"status": cmd_status, "list": cmd_list, "pool-refresh": cmd_pool_refresh,
                "probe": cmd_probe, "apply": cmd_apply, "rollback": cmd_rollback,
                "buy": cmd_buy, "prolong": cmd_prolong, "drop": cmd_drop,
                "rotate": cmd_rotate, "emergency": cmd_emergency,
                "switch-provider": cmd_switch_provider,
                "heartbeat-check": cmd_heartbeat_check, "auto-prolong": cmd_auto_prolong,
                "self-update": cmd_self_update, "egress-mark": cmd_egress_mark}
    try:
        return handlers[args.cmd](cfg, args)
    except ProviderError as e:
        print("Ошибка провайдера: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
