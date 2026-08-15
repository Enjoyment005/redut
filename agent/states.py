# -*- coding: utf-8 -*-
"""states.py — машина состояний агента (§8) и автоматика.

Лестница решений (§6.0): RETUNE (0 ₽) -> ROTATING (0 ₽) -> REPLENISH (деньги) ->
EMERGENCY (прямой выход). Диагностика (§8) идёт СТРОГО ПО ПОРЯДКУ:

  1. сеть сервера жива?  (прямой curl мимо прокси)
        нет -> FROZEN_NET: НИЧЕГО не менять, НЕ ПОКУПАТЬ, алерт.
        Без этого шага первый же обрыв у хостера заставил бы агента перебрать
        и «сжечь» весь пул, а теперь ещё и накупить прокси (§8, §19).
  2. egress через tun0 жив?  да -> OK (чинить нечего; при выходе из аварии — снять).
     sing-box / tun0 / маршрут middleman в порядке?  нет -> self-heal (рестарт).
  3. текущий прокси жив по ДРУГОМУ протоколу?  да -> RETUNE (§7.3): сменить только
        тип outbound, IP не трогать (без нового anti-loop, без сгоревших дней).
  4. значит виноват прокси -> ROTATING (перебор пула) -> REPLENISH (покупка) ->
        EMERGENCY (прямой выход через WAN вместо чёрной дыры в мёртвый tun0).

Лимиты (§8): ≤3 замены/час · ≤5 кандидатов/цикл · ≤3 покупки/сутки (money.py) ·
экспоненциальный cooldown на провалившийся прокси (10м→30м→2ч) · flock от гонки
«cron + кнопка». Весь цикл — под ОДНИМ flock; apply/rollback вызываются с
_locked=True (второй flock в том же процессе конфликтует).

Исполняется НА сервере (Linux). На Windows-dev большинство шагов — no-op:
чистые решения (decide/cooldown_seconds) тестируются без сервера.
"""
import datetime
import os

import apply as apply_mod
import money as money_mod
import probe as probe_mod
from providers import ProviderError

# --- состояния (§8) ---
OK = "OK"
SUSPECT = "SUSPECT"
DEGRADED = "DEGRADED"
ROTATING = "ROTATING"
REPLENISH = "REPLENISH"
EMERGENCY = "EMERGENCY"
FROZEN_NET = "FROZEN_NET"     # сеть сервера легла — автоматика заморожена
FROZEN = "FROZEN"            # ручная пауза автоматики из панели (обслуживание)

# --- лимиты (§8) ---
MAX_REPLACEMENTS_PER_HOUR = 3
MAX_CANDIDATES_PER_CYCLE = 5
EMERGENCY_RETRY_SEC = 15 * 60           # повтор попытки раз в 15 мин
HEARTBEAT_STALE_HOURS = 24              # §6.3: нет цикла >24ч -> письмо
COOLDOWN_STEPS = {1: 600, 2: 1800}      # 10 мин -> 30 мин -> (иначе) 2 ч
COOLDOWN_MAX = 2 * 3600

# Флаг аварийного режима для СТОРОЖА (singbox-watchdog.sh): пока он есть, сторож
# НЕ трогает sing-box/tun0/маршрут middleman (иначе вернул бы default в мёртвый
# tun0 и убил бы прямой выход), только даёт агенту повторить попытку. Путь в /run —
# переживает только до ребута, а после ребута vpn-boot-setup ставит tun0-маршрут,
# и обычная диагностика при первом же вызове поднимет автомат заново.
EMERGENCY_FLAG = "/run/vpn-agent-emergency"
# ТОЛЬКО полный путь: агента дёргает cron с PATH=/usr/bin:/bin, а iptables лежит в
# /usr/sbin — короткое имя из крона даёт [Errno 2], и emergency_on «добавлял» MASQUERADE
# только в логе (найдено 15.08 на приёмке публичной сборки; тот же класс, что и sing-box §12.4).
IPTABLES = "/usr/sbin/iptables"

# Прямые проверки живости сети (мимо прокси). -k: 1.1.1.1/8.8.8.8 по IP без валид. cert.
NET_CHECK_URLS = ("https://api.ipify.org", "https://1.1.1.1", "https://8.8.8.8")


# --------------------------------------------------------- чистые решения (тест)
def cooldown_seconds(fail_count):
    """Экспоненциальный cooldown провалившегося прокси (§8): 1->10м, 2->30м, ≥3->2ч."""
    return COOLDOWN_STEPS.get(int(fail_count or 0), COOLDOWN_MAX)


def decide(net_alive, egress_ok, singbox_ok):
    """Шаги 1-2 лестницы (§8) как чистая функция — порядок критичен, тестируется.

    -> 'frozen_net' | 'ok' | 'self_heal' | 'proxy_fault'
    """
    if not net_alive:
        return "frozen_net"          # шаг 1 — раньше всего, иначе сожжём пул
    if egress_ok:
        return "ok"                  # выход через tun0 жив — чинить нечего
    if not singbox_ok:
        return "self_heal"           # шаг 2 — виноват sing-box/tun0/маршрут
    return "proxy_fault"             # шаги 3-4 — разбираемся с прокси


def age_seconds(iso_str, now=None):
    """Возраст метки now_iso ('YYYY-MM-DD HH:MM:SS') в секундах, или None."""
    if not iso_str:
        return None
    now = now or datetime.datetime.now()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return (now - datetime.datetime.strptime(str(iso_str), fmt)).total_seconds()
        except ValueError:
            continue
    return None


def _now_iso():
    return datetime.datetime.now().replace(microsecond=0).isoformat(sep=" ")


# ------------------------------------------------------------- проверки сервера
def net_alive(cfg, log):
    """Шаг 1 (§8): жива ли сеть сервера — прямой curl МИМО прокси. Любой ответ
    (HTTP-код != 000) от любого таргета -> сеть жива. Мёртвая сеть -> FROZEN_NET."""
    if os.name != "posix":
        return True, "dev"          # локально считаем сеть живой (rotate тут no-op)
    for url in (cfg.get("net_check_urls") or NET_CHECK_URLS):
        rc, out = apply_mod.run_cmd(
            ["curl", "-sk", "--max-time", "6", "-o", os.devnull, "-w", "%{http_code}", url],
            timeout=12)
        code = (out or "").strip()[-3:]
        if rc == 0 and code and code != "000":
            return True, url
    return False, None


def singbox_health(cfg):
    """Шаг 2 (§8): sing-box active + tun0 carrier + маршрут middleman default."""
    rc, act = apply_mod.run_cmd(["systemctl", "is-active", "sing-box"])
    active = act.strip() == "active"
    tun0 = False
    try:
        with open("/sys/class/net/tun0/carrier") as f:
            tun0 = f.read().strip() == "1"
    except OSError:
        pass
    rc, route = apply_mod.run_cmd(["ip", "route", "show", "table", "middleman"])
    route_ok = "default dev tun0" in (route or "")
    return {"active": active, "tun0": tun0, "route_ok": route_ok,
            "ok": active and tun0 and route_ok}


def try_self_heal(cfg, log):
    """Шаг 2: чинит существующий watchdog делает то же — рестарт sing-box +
    восстановление маршрута middleman. -> healthy?"""
    log("  self-heal: рестарт sing-box + маршрут middleman")
    apply_mod.run_cmd(["ip", "route", "replace", "default", "dev", "tun0", "table", "middleman"])
    apply_mod.restart_singbox()
    apply_mod.wait_tun0()
    return singbox_health(cfg)["ok"]


# ----------------------------------------------------------- работа с текущим
def _outbound_of(sb, tag):
    for o in sb.get("outbounds", []):
        if o.get("tag") == tag:
            return (o.get("type"), o.get("server_port"))
    return (None, None)


def _mode(type_port):
    t, p = type_port
    return "%s :%s" % ("SOCKS5" if t == "socks" else "HTTP" if t == "http" else t, p)


def _pool_row_by_host(pool, host):
    if not host:
        return None
    for r in pool.list(include_gone=True):
        if r["host"] == host:
            return r
    return None


def _row_from_sb(sb, host):
    """Синтетическая запись из live-конфига, если upstream не из пула (ручной)."""
    socks = http = None
    user = pw = ""
    for o in sb.get("outbounds", []):
        if o.get("tag") in ("socks-out", "http-tg"):
            user = o.get("username") or user
            pw = o.get("password") or pw
            if o.get("type") == "socks":
                socks = o.get("server_port")
            elif o.get("type") == "http":
                http = o.get("server_port")
    return {"uid": "live:%s" % host, "provider": "live", "ext_id": host, "host": host,
            "ip": host, "port_socks5": socks, "port_http": http, "user": user,
            "password": pw, "role": "auto", "fail_count": 0, "kind": "dedicated",
            "ip_version": 4, "date_end": None}


def _check_cb(providers, row):
    prov = providers.get(row.get("provider"))
    if prov is not None and prov.caps.get("check"):
        return lambda: prov.check(row["ext_id"])
    return None


def _probe(pool, providers, row, current_host):
    res = probe_mod.probe(row, provider_check=_check_cb(providers, row))
    res["score"] = probe_mod.score(row, res, is_current=(row.get("host") == current_host))
    if pool.get(row["uid"]):
        pool.record_probe(row["uid"], res)
    return res


def _cooldown_after_fail(pool, uid, log):
    fc = int((pool.get(uid) or {}).get("fail_count") or 1)
    secs = cooldown_seconds(fc)
    pool.set_cooldown(uid, secs)
    log("  cooldown %s: %d мин (провал #%d)" % (uid, secs // 60, fc))


# ============================================================ ОРКЕСТРАЦИЯ
def rotate(cfg, providers, pool, alerter, reason="manual", actor="auto",
           log=print, force=False):
    """Точка входа автоматики (§8). Возвращает dict(state, action, detail).

    Один flock на весь цикл; при занятом locke — мягкий выход (кто-то уже правит).
    """
    pool.heartbeat()                                   # §6.3: цикл агента прошёл
    result = {"state": None, "action": None, "detail": "", "ok": False}

    if pool.get_setting("automat_frozen") == "1" and not force:
        return _state(pool, result, FROZEN, "manual-pause",
                      "автоматика на паузе (FROZEN) — пропускаю")
    if os.name != "posix":
        result.update(state=pool.get_setting("automat_state") or OK, action="noop",
                      detail="rotate доступен только на сервере (Linux)")
        return result

    state_before = pool.get_setting("automat_state") or OK
    # EMERGENCY: повтор не чаще 15 мин (§8), иначе watchdog долбил бы каждые 2 мин
    if state_before == EMERGENCY and not force:
        restore_emergency_routes(cfg, pool, log, actor)
        last = pool.get_setting("emergency_last_retry")
        age = age_seconds(last)
        if age is not None and age < EMERGENCY_RETRY_SEC:
            return _state(pool, result, EMERGENCY, "emergency-wait",
                          "аварийный режим: до следующей попытки %d с" % (EMERGENCY_RETRY_SEC - age))

    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _rotate_locked(cfg, providers, pool, alerter, reason, actor, log,
                                  result, state_before)
    except apply_mod.ApplyError as e:
        # flock занят — другой процесс (кнопка/cron) уже правит конфиг. Не наша очередь.
        return _state(pool, result, state_before, "locked", "flock занят: %s" % e)


def _rotate_locked(cfg, providers, pool, alerter, reason, actor, log, result, state_before):
    if state_before == EMERGENCY:
        pool.set_setting("emergency_last_retry", _now_iso())

    # --- ШАГ 1: сеть сервера жива? ---
    alive, via = net_alive(cfg, log)
    egress = apply_mod.verify_egress()
    pool.set_egress(egress)          # дашборд показывает эту метку, сам пробу не гоняет
    sb_h = singbox_health(cfg)
    d = decide(alive, egress["ok"], sb_h["ok"])
    log("диагностика (§8): сеть=%s egress=%s sing-box=%s -> %s"
        % ("жива" if alive else "МЕРТВА", "ok" if egress["ok"] else "нет",
           "ok" if sb_h["ok"] else "нет", d))

    if d == "frozen_net":
        first = state_before != FROZEN_NET
        pool.log_event("frozen_net", actor=actor, result="on",
                       detail="сеть сервера недоступна — ничего не меняю, не покупаю")
        if first:
            alerter.frozen_net(detail="прямой curl мимо прокси не проходит (%s)" % reason)
        return _state(pool, result, FROZEN_NET, "frozen_net",
                      "сеть сервера мертва — заморожено, покупок нет")

    if d == "ok":
        # выход через tun0 жив. Если были в аварии — снять её.
        if state_before == EMERGENCY:
            _leave_emergency(cfg, pool, alerter, egress, log, actor)
        return _state(pool, result, OK, "noop", "egress жив (%s) — делать нечего" % egress["egress_ip"])

    if d == "self_heal":
        if try_self_heal(cfg, log) and apply_mod.verify_egress()["ok"]:
            pool.log_event("self-heal", actor=actor, result="ok", detail="sing-box/tun0 восстановлены")
            if state_before == EMERGENCY:
                _leave_emergency(cfg, pool, alerter, apply_mod.verify_egress(), log, actor)
            return _state(pool, result, OK, "self-heal", "sing-box восстановлен")
        log("  self-heal не помог — вероятно, виноват прокси, иду дальше")

    # --- ШАГ 3: RETUNE (текущий прокси жив по другому протоколу) ---
    rt = try_retune(cfg, providers, pool, alerter, log, actor)
    if rt.get("ok"):
        if state_before == EMERGENCY:
            _leave_emergency(cfg, pool, alerter, rt.get("verify") or apply_mod.verify_egress(), log, actor)
        return _state(pool, result, OK, "retune", rt.get("detail", "RETUNE ок"))

    # --- ШАГ 4: ROTATING ---
    if pool.rotations_last_hour() >= MAX_REPLACEMENTS_PER_HOUR and not (reason == "manual"):
        log("  лимит замен ≤%d/час исчерпан — в аварийный режим до охлаждения"
            % MAX_REPLACEMENTS_PER_HOUR)
        _enter_emergency(cfg, pool, alerter,
                         "лимит замен ≤%d/час исчерпан (антифлаппинг §8)" % MAX_REPLACEMENTS_PER_HOUR,
                         log, actor, state_before)
        return _state(pool, result, EMERGENCY, "rate-limited", "лимит замен/час — авария")

    rot = try_rotating(cfg, providers, pool, alerter, log, actor)
    if rot.get("ok"):
        if state_before == EMERGENCY:
            _leave_emergency(cfg, pool, alerter, rot["verify"], log, actor)
        ensure_reserve(cfg, providers, pool, alerter, log, actor)   # N+1: докупить в фоне (§6.5)
        return _state(pool, result, OK, "rotate", rot.get("detail", "ротация ок"))

    # --- ШАГ 4b: REPLENISH (покупка) ---
    rep = try_replenish(cfg, providers, pool, alerter, log, actor)
    if rep.get("ok"):
        if state_before == EMERGENCY:
            _leave_emergency(cfg, pool, alerter, rep["verify"], log, actor)
        return _state(pool, result, OK, "replenish", rep.get("detail", "докупка ок"))

    # --- EMERGENCY ---
    _enter_emergency(cfg, pool, alerter, rep.get("reason") or "живых кандидатов нет и купить нельзя",
                     log, actor, state_before)
    return _state(pool, result, EMERGENCY, "emergency", rep.get("reason") or "авария")


# ------------------------------------------------------------------- RETUNE §7.3
def try_retune(cfg, providers, pool, alerter, log, actor):
    sb = apply_mod.load_json(cfg["singbox_config"])
    host = apply_mod.current_upstream(sb)
    if not host:
        return {"ok": False, "why": "нет текущего upstream"}
    cur_socks = _outbound_of(sb, "socks-out")
    cur_tg = _outbound_of(sb, "http-tg")
    row = _pool_row_by_host(pool, host) or _row_from_sb(sb, host)
    res = _probe(pool, providers, row, host)
    if res.get("disqualified") or not res.get("ok"):
        return {"ok": False, "why": "текущий прокси не проксирует ни по одному протоколу"}
    try:
        socks_out, http_tg, _ = apply_mod.choose_outbounds(
            host, row.get("user") or "", row.get("password") or "",
            res.get("socks_port"), res.get("http_port"))
    except apply_mod.ApplyError:
        return {"ok": False, "why": "нет рабочей комбинации порт×протокол"}
    changed = (socks_out["type"] != cur_socks[0] or socks_out["server_port"] != cur_socks[1]
               or http_tg["type"] != cur_tg[0] or http_tg["server_port"] != cur_tg[1])
    if not changed:
        return {"ok": False, "why": "конфиг уже оптимален — RETUNE ничего не даст"}
    log("  RETUNE: %s  %s -> %s (IP не меняется)"
        % (host, _mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"]))))
    try:
        r = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True)
    except apply_mod.ApplyError as e:
        pool.log_event("retune", actor=actor, to_uid=row["uid"], result="fail", detail=str(e))
        return {"ok": False, "why": "RETUNE не применился: %s" % e}
    pool.log_event("retune", actor=actor, to_uid=row["uid"], result="ok",
                   detail="%s -> %s (IP=%s без смены)"
                   % (_mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"])), host))
    alerter.retuned(host=host, old_mode=_mode(cur_socks),
                    new_mode=_mode((socks_out["type"], socks_out["server_port"])), uid=row["uid"])
    return {"ok": True, "verify": r["verify"],
            "detail": "RETUNE %s -> %s на %s"
            % (_mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"])), host)}


# ------------------------------------------------------------------- ROTATING
def try_rotating(cfg, providers, pool, alerter, log, actor):
    sb = apply_mod.load_json(cfg["singbox_config"])
    host = apply_mod.current_upstream(sb)
    cands = pool.rotation_candidates(cfg.get("role"), exclude_host=host)
    if not cands:
        log("  ROTATING: проверенных кандидатов нет (все off/gone/на cooldown)")
        return {"ok": False, "exhausted": True}
    tried = 0
    for row in cands:
        if tried >= MAX_CANDIDATES_PER_CYCLE:
            log("  ROTATING: лимит ≤%d кандидатов/цикл — стоп" % MAX_CANDIDATES_PER_CYCLE)
            break
        if row["role"] == "chrome":
            continue
        tried += 1
        res = _probe(pool, providers, row, host)
        if res.get("disqualified") or not res.get("ok"):
            _cooldown_after_fail(pool, row["uid"], log)
            continue
        try:
            r = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True)
        except apply_mod.ApplyError as e:
            pool.bump_fail(row["uid"])
            _cooldown_after_fail(pool, row["uid"], log)
            pool.log_event("rotate", actor=actor, to_uid=row["uid"], result="fail", detail=str(e))
            continue
        pool.mark_used(row["uid"])
        pool.clear_cooldown(row["uid"])
        pool.log_event("rotate", actor=actor, from_uid=None, to_uid=row["uid"], result="ok",
                       detail="%s -> %s egress=%s cc=%s (перебрано %d)"
                       % (host, r["new_ip"], r["verify"]["egress_ip"], r["verify"]["exit_cc"], tried))
        alerter.rotated(old_ip=host, new_ip=r["new_ip"], uid=row["uid"],
                        egress=r["verify"]["egress_ip"], cc=r["verify"]["exit_cc"],
                        tg_code=r["verify"]["tg_code"], score=res.get("score"), candidates_tried=tried)
        return {"ok": True, "uid": row["uid"], "new_ip": r["new_ip"], "verify": r["verify"],
                "detail": "ротация %s -> %s (%s)" % (host, r["new_ip"], row["uid"])}
    return {"ok": False, "exhausted": False, "tried": tried}


# ------------------------------------------------------------------- REPLENISH
def try_replenish(cfg, providers, pool, alerter, log, actor):
    prov = providers.get("proxy6")
    if prov is None or not prov.caps.get("buy"):
        alerter.pool_empty(detail="нет ключа PROXY6 — докупить нечем")
        return {"ok": False, "reason": "нет провайдера с покупкой (PROXY6)"}
    lim = money_mod.limits(cfg)
    # порядок перебора задаёт умная оценка: сначала надёжные страны выхода,
    # страны с низкой репутацией автоматика не берёт вовсе (§6.1, 2026-08-15)
    wl = money_mod.buy_candidates(cfg)
    period = int(lim["buy_period_days"])
    version = int(lim["buy_version"])
    if not lim.get("buy_enabled"):
        alerter.no_funds(detail="тумблер покупок buy_enabled=false — купи руками")
        return {"ok": False, "reason": "покупки выключены тумблером (§6.2)"}

    # рынок: первая страна из ранжированного списка с наличием
    pick = avail = None
    for cc in wl:
        try:
            n = prov.getcount(cc, version)
        except ProviderError as e:
            if e.code == 105:
                alerter.api_105(detail=str(e))
                return {"ok": False, "reason": "PROXY6 105 (неверный IP)", "api105": True}
            log("  getcount %s: %s" % (cc, e))
            continue
        if n > 0:
            pick, avail = cc, n
            break
    if not pick:
        alerter.no_market(detail="проверены страны: %s" % ",".join(wl))
        return {"ok": False, "reason": "нет прокси version=%d в наличии (§10 error 300)" % version}

    log("  REPLENISH: покупаю в %s (в наличии %s), период %d дн" % (pick, avail, period))
    try:
        r = money_mod.plan_and_buy(pool, prov, cfg, country=pick, period=period, count=1,
                                   version=version, server=cfg.get("server"), actor=actor)
    except money_mod.SpendDenied as e:
        alerter.no_funds(detail=str(e))
        return {"ok": False, "reason": "гейт трат: %s" % e, "denied": True}
    except ProviderError as e:
        if e.code == 400:
            alerter.no_funds(detail=str(e))
            return {"ok": False, "reason": "денег не хватило (error 400)"}
        if e.code == 105:
            alerter.api_105(detail=str(e))
            return {"ok": False, "reason": "PROXY6 105 (неверный IP)"}
        if e.code == 300:
            alerter.no_market(detail=str(e))
            return {"ok": False, "reason": "нет в наличии (error 300)"}
        return {"ok": False, "reason": "покупка не удалась: %s" % e}

    # постфактум проверка реальной страны выхода (§6.1) + apply рабочего
    checks = postbuy_check(cfg, pool, providers, r["proxies"], actor, log)
    for uid, res, blocked in checks:
        if blocked or not res.get("ok"):
            continue
        row = pool.get(uid) or dict(uid=uid)
        try:
            ar = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True)
        except apply_mod.ApplyError as e:
            log("  куплен %s, но apply не прошёл: %s" % (uid, e))
            continue
        pool.mark_used(uid)
        pool.log_event("replenish", actor=actor, to_uid=uid, result="ok",
                       detail="куплен %s (%s %s, %s), egress=%s cc=%s"
                       % (uid, r["price"], r["currency"], pick, ar["verify"]["egress_ip"],
                          ar["verify"]["exit_cc"]))
        alerter.bought(uid=uid, price=r["price"], currency=r["currency"],
                       balance_after=r["balance_after"], country=r["country"], period=r["period"],
                       egress=ar["verify"]["egress_ip"], cc=ar["verify"]["exit_cc"],
                       recovered=r["recovered"])
        return {"ok": True, "uid": uid, "new_ip": ar["new_ip"], "verify": ar["verify"],
                "detail": "докуплен и применён %s (%s %s)" % (uid, r["price"], r["currency"])}

    # купили, но всё непригодно (вышло в блок / не пробится)
    for uid, res, blocked in checks:
        if blocked:
            alerter.blocked_cc(uid=uid, cc=res.get("exit_cc"))
    return {"ok": False, "reason": "купленный прокси непригоден (страна в блоке / не пробивается)"}


def postbuy_check(cfg, pool, providers, bought, actor, log):
    """§6.1 постфактум: подтянуть паспорт (getproxy) и проверить РЕАЛЬНУЮ страну
    выхода. Выход в жёстком блоке СНГ -> off + алерт, не используем."""
    prov = providers.get("proxy6")
    if prov is not None:
        try:
            pool.refresh({"proxy6": prov}, actor=actor)
        except Exception:
            pass
    current_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
    out = []
    for pxy in bought:
        uid = "%s:%s" % (pxy["provider"], pxy["ext_id"])
        row = pool.get(uid) or dict(pxy, uid=uid)
        res = _probe(pool, providers, row, current_host)
        blocked = (res.get("exit_cc") in probe_mod.HARD_BLOCK_CC
                   or str(res.get("disqualified") or "").startswith("blocked-cc"))
        if blocked:
            pool.set_role(uid, "off")
            pool.log_event("buy-postcheck", actor=actor, to_uid=uid, result="blocked-cc",
                           detail="реальный выход cc=%s в жёстком блоке §6.1 -> off" % res.get("exit_cc"))
        out.append((uid, res, blocked))
    return out


# ------------------------------------------------- автопродление «якоря» (§6.3)
DEFAULT_AUTO_PROLONG = {
    "enabled": True,        # тумблер: выключить — и продлевать будем только руками
    "days_before": 3,       # продлевать, когда до конца осталось не больше стольких дней
    "period_days": 30,      # на сколько продлевать за раз (у PROXY6 цена линейна: 4 ₽/сутки)
    "scope": "current",     # "current" — только боевой; "current+reserve" — ещё и резерв
}


def auto_prolong_cfg(cfg):
    m = dict(DEFAULT_AUTO_PROLONG)
    m.update((cfg or {}).get("auto_prolong") or {})
    return m


def auto_prolong(cfg, providers, pool, alerter, log=print, actor="auto"):
    """Продлить рабочий боевой прокси ДО того, как он истечёт (решение владельца 15.08).

    Зачем вообще: смена IP стоит ровно столько же, сколько продление (4 ₽/сутки),
    но новый адрес — «холодный». Прогретый IP экономит не деньги, а нервы: сервисы
    не требуют перелогинов, капч и подтверждений оплаты. Поэтому здоровый якорь
    продлеваем, а ротация остаётся аварийной мерой, а не расписанием.

    Кого трогаем: только текущий боевой (и резерв, если scope это разрешает) и только
    если он ЗДОРОВ — мёртвый продлевать бессмысленно, его заменит ротация.
    Деньги идут через те же гейты §6.2 (тумблер, потолок цены, суточный лимит, остаток).
    """
    ap = auto_prolong_cfg(cfg)
    if not ap.get("enabled"):
        return {"ok": True, "skipped": "автопродление выключено тумблером"}
    prov = providers.get("proxy6")
    if prov is None or not prov.caps.get("prolong"):
        return {"ok": False, "skipped": "нет провайдера с продлением"}

    current_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
    rows = [r for r in pool.list() if not r["gone"]]
    targets = [r for r in rows if current_host and r["host"] == current_host]
    if str(ap.get("scope")) == "current+reserve":
        targets += [r for r in rows if r["role"] == "reserve" and r not in targets]
    if not targets:
        return {"ok": True, "skipped": "боевой прокси не найден в пуле"}

    done = []
    for row in targets:
        uid = row["uid"]
        days = probe_mod.days_left(row["date_end"])
        if days is None or days > float(ap["days_before"]):
            continue                      # ещё рано — не морозим деньги заранее
        if not row["probe_ok"]:
            log("  автопродление: %s не прошёл последнюю пробу — продлевать не буду, "
                "пусть его заменит ротация" % uid)
            continue
        if pool.prolonged_today(uid):     # защита от повторов: крон может сработать не раз
            continue
        try:
            r = money_mod.prolong_with_limits(pool, prov, cfg, row=row,
                                              days=int(ap["period_days"]), actor=actor)
            log("  автопродление: %s +%s дн за %s %s (до %s)"
                % (uid, r["days"], r["price"], r["currency"], r["date_end"]))
            alerter.prolonged(uid=uid, days=r["days"], price=r["price"], currency=r["currency"],
                              balance_after=r["balance_after"], date_end=r["date_end"],
                              cc=row["exit_cc"] if "exit_cc" in row.keys() else row["country"])
            done.append({"uid": uid, "days": r["days"], "price": r["price"],
                         "date_end": r["date_end"]})
        except money_mod.SpendDenied as e:
            # Тихо промолчать нельзя: иначе якорь истечёт и мы получим холодный IP.
            log("  автопродление: %s ОТКАЗ гейта — %s" % (uid, e))
            pool.log_event("auto-prolong", actor=actor, to_uid=uid, result="denied", detail=str(e))
            alerter.prolong_failed(uid=uid, days_left=round(days, 1), reason=str(e))
        except Exception as e:
            log("  автопродление: %s ошибка провайдера — %s" % (uid, e))
            pool.log_event("auto-prolong", actor=actor, to_uid=uid, result="fail", detail=str(e))
            alerter.prolong_failed(uid=uid, days_left=round(days, 1), reason=str(e))
    return {"ok": True, "prolonged": done, "checked": [r["uid"] for r in targets]}


# ------------------------------------------------------------------- N+1 (§6.5)
def ensure_reserve(cfg, providers, pool, alerter, log, actor, min_reserve=1):
    """Держать ≥1 тёплый резерв (§6.5). Резерв ушёл в работу — докупить в фоне.
    Best-effort: ошибки/гейты глушим (докупка резерва не должна ронять цикл)."""
    try:
        sb = apply_mod.load_json(cfg["singbox_config"])
        current = apply_mod.current_upstream(sb)
        have = pool.reserve_count(cfg.get("role"), current_host=current)
        if have >= min_reserve:
            return {"ok": True, "have": have, "bought": False}
        lim = money_mod.limits(cfg)
        if not lim.get("buy_enabled"):
            log("  N+1: резерв=%d, но покупки выключены — пропускаю" % have)
            return {"ok": False, "have": have, "bought": False}
        log("  N+1: тёплых резервов %d < %d — докупаю в фоне (§6.5)" % (have, min_reserve))
        prov = providers.get("proxy6")
        if prov is None or not prov.caps.get("buy"):
            return {"ok": False, "have": have, "bought": False}
        # порядок стран — умная оценка (репутация выхода), а не просто список из конфига
        version = int(lim["buy_version"])
        pick = None
        for cc in money_mod.buy_candidates(cfg):
            try:
                if prov.getcount(cc, version) > 0:
                    pick = cc
                    break
            except ProviderError:
                continue
        if not pick:
            return {"ok": False, "have": have, "bought": False}
        r = money_mod.plan_and_buy(pool, prov, cfg, country=pick, period=int(lim["buy_period_days"]),
                                   count=1, version=version, server=cfg.get("server"), actor=actor)
        checks = postbuy_check(cfg, pool, providers, r["proxies"], actor, log)
        good = [uid for uid, res, blocked in checks if res.get("ok") and not blocked]
        for uid, res, blocked in checks:
            if blocked:
                alerter.blocked_cc(uid=uid, cc=res.get("exit_cc"))
        if good:
            alerter.bought(uid=good[0], price=r["price"], currency=r["currency"],
                           balance_after=r["balance_after"], country=r["country"],
                           period=r["period"], cc=None, recovered=r["recovered"])
        return {"ok": bool(good), "have": have, "bought": True, "uids": good}
    except money_mod.SpendDenied as e:
        log("  N+1: докупка резерва отклонена гейтом: %s" % e)
        return {"ok": False, "bought": False, "reason": str(e)}
    except Exception as e:
        log("  N+1: докупка резерва не удалась (не критично): %s" % e)
        return {"ok": False, "bought": False, "reason": str(e)}


# ------------------------------------------------------------------- EMERGENCY
def emergency_on(cfg, log=print):
    """default таблицы middleman -> прямой выход через WAN (§8): вместо чёрной
    дыры в мёртвый tun0 клиенты выходят напрямую через ens3 (с masquerade).
    Это НЕ обход блокировок (выход с российского IP), а «последний рубеж» связи."""
    if os.name != "posix":
        return False
    gw = cfg.get("gw")
    wan = cfg.get("wan") or "ens3"
    subnet = cfg.get("subnet")
    if subnet:
        rc, _ = apply_mod.run_cmd([IPTABLES, "-t", "nat", "-C", "POSTROUTING",
                                   "-s", subnet, "-o", wan, "-j", "MASQUERADE"])
        if rc != 0:      # правила ещё нет — добавляем (идемпотентно)
            rc2, out2 = apply_mod.run_cmd([IPTABLES, "-t", "nat", "-A", "POSTROUTING",
                                           "-s", subnet, "-o", wan, "-j", "MASQUERADE"])
            if rc2 == 0:
                log("  emergency: добавлен MASQUERADE %s -> %s" % (subnet, wan))
            else:
                log("  emergency: MASQUERADE %s -> %s НЕ добавлен: %s" % (subnet, wan, out2))
    if gw:
        apply_mod.run_cmd(["ip", "route", "replace", "default", "via", gw, "dev", wan, "table", "middleman"])
        log("  emergency: middleman default -> via %s dev %s (прямой выход)" % (gw, wan))
    else:
        apply_mod.run_cmd(["ip", "route", "replace", "default", "dev", wan, "table", "middleman"])
        log("  emergency: middleman default -> dev %s" % wan)
    try:
        with open(EMERGENCY_FLAG, "w") as f:
            f.write(_now_iso() + "\n")   # сигнал сторожу: не трогай маршрут
    except OSError:
        pass
    return True


def emergency_off(cfg, log=print):
    """Вернуть middleman default -> tun0 (обычный режим). MASQUERADE не снимаем —
    в норме клиентский трафик в ens3 не идёт, правило безвредно."""
    if os.name != "posix":
        return False
    apply_mod.run_cmd(["ip", "route", "replace", "default", "dev", "tun0", "table", "middleman"])
    try:
        os.unlink(EMERGENCY_FLAG)
    except OSError:
        pass
    log("  emergency off: middleman default -> tun0")
    return True


def _middleman_default():
    """Строка default-маршрута таблицы middleman ('' если нет / не Linux)."""
    rc, out = apply_mod.run_cmd(["ip", "route", "show", "table", "middleman"])
    for ln in (out or "").splitlines():
        if ln.startswith("default"):
            return ln
    return ""


def restore_emergency_routes(cfg, pool, log=print, actor="auto"):
    """Мы в EMERGENCY, но прямой выход сбит — восстановить его СРАЗУ, не дожидаясь окна
    повтора (15 мин). Два случая, оба найдены 15.08 на приёмке публичной сборки:
      • перезагрузка: флаг в /run исчез, boot-скрипт вернул middleman в мёртвый tun0
        (5 минут «чёрной дыры» после ребута);
      • переустановка/ручной запуск boot-скрипта при живом флаге: маршрут снова tun0.
    emergency_on идемпотентен; попытка выйти из аварии остаётся по расписанию.
    Возвращает True, если восстанавливали."""
    if not os.path.exists(EMERGENCY_FLAG):
        why = "после перезагрузки (флага в /run не было)"
    elif "dev tun0" in _middleman_default():
        why = "после сброса маршрута (переустановка/boot-скрипт вернули middleman в tun0)"
    else:
        return False
    if not emergency_on(cfg, log):
        return False
    log("  emergency: прямой выход восстановлен %s" % why)
    pool.log_event("emergency", actor=actor, result="restore",
                   detail="маршруты прямого выхода восстановлены %s" % why)
    return True


def _enter_emergency(cfg, pool, alerter, reason, log, actor, state_before):
    ok = emergency_on(cfg, log)
    pool.set_setting("automat_state", EMERGENCY)
    pool.set_setting("emergency_last_retry", _now_iso())
    if state_before != EMERGENCY:
        pool.set_setting("emergency_since", _now_iso())
        pool.log_event("emergency", actor=actor, result="on", detail=reason)
        alerter.emergency(reason=reason)             # письмо один раз при входе
    else:
        pool.log_event("emergency", actor=actor, result="retry", detail=reason)
    return ok


def _leave_emergency(cfg, pool, alerter, verify, log, actor):
    emergency_off(cfg, log)
    pool.set_setting("emergency_since", None)
    pool.log_event("emergency", actor=actor, result="off",
                   detail="восстановлен рабочий выход egress=%s" % (verify or {}).get("egress_ip"))
    alerter.recovered(new_ip=apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"])),
                      egress=(verify or {}).get("egress_ip"), cc=(verify or {}).get("exit_cc"))


# ------------------------------------------------------------- ручные тумблеры
def set_emergency(cfg, pool, alerter, on, log=print, actor="user"):
    """Ручное вкл/выкл аварийного режима (CLI/панель)."""
    if on:
        _enter_emergency(cfg, pool, alerter, "включён вручную", log, actor,
                         pool.get_setting("automat_state") or OK)
        return {"ok": True, "state": EMERGENCY}
    emergency_off(cfg, log)
    pool.set_setting("automat_state", OK)
    pool.set_setting("emergency_since", None)
    pool.log_event("emergency", actor=actor, result="off-manual", detail="выключен вручную")
    return {"ok": True, "state": OK}


def _state(pool, result, state, action, detail):
    pool.set_setting("automat_state", state)
    result.update(state=state, action=action, detail=detail, ok=(state == OK))
    return result


# ------------------------------------------------------------- пульс (§6.3)
def heartbeat_check(pool, alerter, stale_hours=HEARTBEAT_STALE_HOURS):
    """§6.3: нет успешного цикла агента > stale_hours -> письмо. Дедуп через
    setting, чтобы не слать одно и то же каждый час."""
    last = pool.last_heartbeat()
    age = age_seconds(last)
    if age is None or age < stale_hours * 3600:
        return {"stale": False, "age_h": None if age is None else age / 3600.0}
    already = pool.get_setting("heartbeat_alerted")
    if already == last:                # уже слали про этот самый пульс
        return {"stale": True, "alerted": False, "age_h": age / 3600.0}
    alerter.no_heartbeat(hours=age / 3600.0, last_ts=last)
    pool.set_setting("heartbeat_alerted", last)
    return {"stale": True, "alerted": True, "age_h": age / 3600.0}
