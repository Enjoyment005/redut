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
import json
import math
import os
import re
import time
import urllib.parse

import apply as apply_mod
import config_store
import country as country_mod
import health as health_mod
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

# --- режим выбора канала -------------------------------------------------
SELECTION_AUTO = "auto"
SELECTION_MANUAL = "manual"
MANUAL_FALLBACK_STRATEGY = "speed"

# --- лимиты (§8) ---
MAX_REPLACEMENTS_PER_HOUR = 3
MAX_CANDIDATES_PER_CYCLE = 5
HEARTBEAT_STALE_HOURS = 24              # §6.3: нет цикла >24ч -> письмо
COOLDOWN_STEPS = {1: 600, 2: 1800}      # 10 мин -> 30 мин -> (иначе) 2 ч
COOLDOWN_MAX = 2 * 3600

# --- пакет F (1.3.0): подтверждение отказов и backoff ---
RECHECK_DELAY_SEC = 8                   # F1: вторая попытка verify перед деструктивом
TG_ALERT_STREAK = 3                     # F1: письмо про мёртвый TG после стольких подряд
CALM_MAX_STREAK = 3                     # F2: «прокси жив, egress мёртв» -> эскалация
# F6: ретраи в EMERGENCY — backoff вместо ровных 15 мин: быстрые повторы ловят
# короткие сбои (частый случай владельца), редкие поздние не спамят. Cap 30 мин.
EMERGENCY_BACKOFF = (120, 300, 600, 900, 1800)
ALERT_DEDUP_SEC = 6 * 3600              # F7: no_funds/pool_empty/no_market ≤1 письма/6ч

# Флаг аварийного режима для СТОРОЖА (singbox-watchdog.sh): пока он есть, сторож
# НЕ трогает sing-box/tun0/маршрут middleman (иначе вернул бы default в мёртвый
# tun0 и убил бы прямой выход), только даёт агенту повторить попытку. Путь в /run —
# переживает только до ребута, а после ребута vpn-boot-setup ставит tun0-маршрут,
# и обычная диагностика при первом же вызове поднимет автомат заново.
# С 1.0.2 (снос №4, 15.08): если канал ещё НЕ выбран (UP_HOST пуст), boot-скрипт сам
# ставит прямой выход и пишет этот флаг — после ребута нет окна «чёрной дыры» до тика
# сторожа (было 143 с); restore_emergency_routes тогда видит флаг + не-tun0 и ничего не трогает.
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


def emergency_retry_delay(retry_n):
    """F6: пауза до следующего ретрая в EMERGENCY по номеру попытки (чистая, тест).

    0-я -> 2 мин, дальше 5, 10, 15 и по 30 мин (cap)."""
    try:
        n = max(0, int(retry_n or 0))
    except (TypeError, ValueError):
        n = 0
    return EMERGENCY_BACKOFF[min(n, len(EMERGENCY_BACKOFF) - 1)]


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


def selection_state(pool, cfg=None, current_host=None):
    """Единый снимок политики выбора: AUTO(strategy) или MANUAL(uid, host).

    Отсутствие ключей в старой БД означает AUTO — миграция не нужна. Стратегия
    остаётся записанной в config.json и в MANUAL служит только прогнозом: права
    переключать здоровый закреплённый канал у неё нет.
    """
    mode = pool.get_setting("selection_mode") or SELECTION_AUTO
    if mode not in (SELECTION_AUTO, SELECTION_MANUAL):
        mode = SELECTION_AUTO
    host = pool.get_setting("manual_host") if mode == SELECTION_MANUAL else None
    uid = pool.get_setting("manual_uid") if mode == SELECTION_MANUAL else None
    return {
        "mode": mode,
        "strategy": country_mod.strategy(cfg),
        "manual_uid": uid,
        "manual_host": host,
        "manual_since": (pool.get_setting("manual_since")
                         if mode == SELECTION_MANUAL else None),
        "is_current": bool(mode == SELECTION_MANUAL and host and current_host
                           and host == current_host),
    }


def selection_revision_state(pool, cfg=None):
    """Снимок устойчивого намерения выбора и отставания reconciler."""
    def number(key):
        try:
            return max(0, int(pool.get_setting(key) or 0))
        except (TypeError, ValueError):
            return 0
    desired = number("desired_selection_revision")
    applied = number("applied_selection_revision")
    kind = pool.get_setting("desired_selection_kind")
    raw = pool.get_setting("desired_selection_payload")
    try:
        payload = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        payload = {}
    if kind not in ("strategy", "manual"):
        current = selection_state(pool, cfg)
        kind = "manual" if current["mode"] == SELECTION_MANUAL else "strategy"
        payload = ({"uid": current.get("manual_uid"), "host": current.get("manual_host")}
                   if kind == "manual" else {"strategy": country_mod.strategy(cfg)})
    return {"desired": desired, "applied": applied, "pending": desired > applied,
            "kind": kind, "payload": payload}


def request_strategy_selection(pool, cfg, strategy, actor="user", reason="strategy",
                               pending_config=False):
    """Новое AUTO(strategy) намерение; applied догонит только после convergence."""
    if strategy not in country_mod.STRATEGIES:
        raise ValueError("неизвестная стратегия %r" % strategy)
    revision = pool.request_selection_intent(
        "strategy", {"strategy": strategy},
        {"selection_mode": SELECTION_AUTO, "manual_uid": None,
         "manual_host": None, "manual_since": None,
         "selection_strategy_override": strategy if pending_config else None},
        actor=actor, applied=False, detail=reason)
    return revision


def mark_selection_applied(pool, revision, actor="auto", detail=""):
    return pool.mark_selection_applied(revision, actor=actor, detail=detail)


def set_manual_selection(pool, uid, host, actor="user", reason="manual-apply"):
    """Атомарно закрепить успешно применённый человеком канал."""
    if not host:
        raise ValueError("ручной канал нельзя закрепить без host")
    was = selection_state(pool)
    manual_uid = uid or ("live:%s" % host)
    pool.request_selection_intent(
        "manual", {"uid": manual_uid, "host": host},
        {"selection_mode": SELECTION_MANUAL, "manual_uid": manual_uid,
         "manual_host": host, "manual_since": _now_iso(),
         "selection_strategy_override": None},
        actor=actor, applied=True, detail=reason)
    pool.log_event("selection-mode", actor=actor, to_uid=uid,
                   result=SELECTION_MANUAL,
                   detail="%s; закреплён %s (было %s)" % (reason, host, was["mode"]))
    return selection_state(pool, current_host=host)


def set_auto_selection(pool, cfg=None, strategy=None, actor="user", reason="strategy",
                       log_unchanged=False):
    """Снять ручную фиксацию; стратегию на диск пишет вызывающий."""
    was = selection_state(pool, cfg)
    name = strategy if strategy in country_mod.STRATEGIES else country_mod.strategy(cfg)
    pool.set_settings({
        "selection_mode": SELECTION_AUTO,
        "manual_uid": None,
        "manual_host": None,
        "manual_since": None,
    })
    if was["mode"] != SELECTION_AUTO or log_unchanged:
        pool.log_event("selection-mode", actor=actor, result=SELECTION_AUTO,
                       detail="%s; стратегия=%s (было %s)" % (reason, name, was["mode"]))
    return selection_state(pool, cfg)


def _persist_auto_strategy(cfg, pool, name, actor, reason, log, expected_manual=None):
    """Перейти в AUTO(name), не оставляя ручной канал без восстановления.

    Ошибка диска не блокирует аварийный failover: текущий процесс всё равно
    ранжирует по name, а override в БД заставит следующий цикл повторить запись.
    """
    with config_store.writer(cfg):
        if expected_manual is not None:
            current = selection_state(pool, cfg)
            current_revision = selection_revision_state(pool, cfg)["desired"]
            if (current["mode"] != SELECTION_MANUAL
                    or current.get("manual_uid") != expected_manual.get("manual_uid")
                    or current.get("manual_host") != expected_manual.get("manual_host")
                    or current_revision != expected_manual.get("revision")):
                return {"strategy": country_mod.strategy(cfg), "persist_error": "",
                        "superseded": True}
        revision = request_strategy_selection(
            pool, cfg, strategy=name, actor=actor, reason=reason, pending_config=True)
        cfg.setdefault("countries", {})["strategy"] = name
        error = ""
        try:
            config_store.save_country_strategy(cfg, name, _locked=True)
        except Exception as e:  # отказ config.json не должен превращаться в чёрную дыру
            error = "%s: %s" % (type(e).__name__, e)
            log("  стратегия %s действует в памяти, запись config.json не удалась: %s" %
                (name, error))
        else:
            pool.clear_strategy_override(revision, name)
    return {"strategy": name, "persist_error": error, "revision": revision,
            "superseded": False}


def reconcile_strategy_override(cfg, pool, log=print):
    """Дописать на диск стратегию failover, если прежняя попытка не удалась."""
    with config_store.writer(cfg):
        name = pool.get_setting("selection_strategy_override")
        if name not in country_mod.STRATEGIES:
            return False
        revision = selection_revision_state(pool, cfg)
        desired_name = ((revision.get("payload") or {}).get("strategy")
                        if revision.get("kind") == "strategy" else None)
        if revision["desired"] and desired_name != name:
            return False
        cfg.setdefault("countries", {})["strategy"] = name
        try:
            config_store.save_country_strategy(cfg, name, _locked=True)
        except Exception as e:
            log("  повтор записи стратегии %s отложен: %s" % (name, e))
            return False
        if revision["desired"]:
            if not pool.clear_strategy_override(revision["desired"], name):
                return False
        else:
            pool.set_setting("selection_strategy_override", None)
    pool.log_event("selection-mode", actor="auto", result="config-repaired",
                   detail="в config.json восстановлена стратегия %s" % name)
    return True


def release_manual_on_fault(cfg, pool, actor="auto", reason="confirmed-proxy-fault",
                            log=print):
    """MANUAL -> AUTO(speed) только после подтверждённого отказа самого прокси."""
    st = selection_state(pool, cfg)
    if st["mode"] != SELECTION_MANUAL:
        return {"released": False, "strategy": country_mod.strategy(cfg)}
    revision = selection_revision_state(pool, cfg)["desired"]
    detail = ("%s; ручной %s (%s) отказал — включаю Скорость и отклик"
              % (reason, st.get("manual_uid") or "?", st.get("manual_host") or "?"))
    expected = {"manual_uid": st.get("manual_uid"), "manual_host": st.get("manual_host"),
                "revision": revision}
    r = _persist_auto_strategy(cfg, pool, MANUAL_FALLBACK_STRATEGY, actor, detail, log,
                               expected_manual=expected)
    if r.get("superseded"):
        pool.log_event("manual-failover", actor=actor, from_uid=st.get("manual_uid"),
                       result="superseded",
                       detail=detail + "; более новое намерение владельца сохранено")
        r["released"] = False
        return r
    pool.log_event("manual-failover", actor=actor, from_uid=st.get("manual_uid"),
                   result=MANUAL_FALLBACK_STRATEGY,
                   detail=detail + (("; config error: " + r["persist_error"])
                                    if r["persist_error"] else ""))
    r["released"] = True
    return r


def finish_explicit_apply(cfg, pool, uid, host, verify=None, source="manual",
                          actor="user", log=print):
    """Зафиксировать успешный apply и нормализовать маршрут/режим выбора.

    source=manual закрепляет канал. strategy/setup/recovery оставляют AUTO. Если
    apply победил из EMERGENCY/ROTATING, прямой WAN-маршрут обязательно снимается.
    """
    state_before = pool.get_setting("automat_state") or OK
    if state_before in (EMERGENCY, ROTATING) or os.path.exists(EMERGENCY_FLAG):
        emergency_off(cfg, log)
        pool.set_settings({"emergency_since": None, "rotating_since": None,
                           "emergency_retry_n": None, "emergency_manual": None})
        pool.log_event("explicit-apply", actor=actor, to_uid=uid, result="leave-direct",
                       detail="%s: рабочий канал применён, прямой WAN-выход снят" % source)
    pool.set_setting("automat_state", OK)
    if verify:
        pool.set_egress(verify)
    if source == "manual":
        return set_manual_selection(pool, uid, host, actor=actor, reason="ручное «В бой»")
    return set_auto_selection(pool, cfg, actor=actor, reason="apply source=%s" % source)


def recover_apply_post_state(cfg, pool, operation, verify=None, log=print):
    """Довести DB-state после kill между verify и caller commit."""
    desired = operation.get("desired_state") or {}
    uid = desired.get("uid") or operation.get("to_uid")
    host = desired.get("to_host")
    source = desired.get("selection_source") or "recovery"
    row = pool.get(uid) if uid else None
    if row is not None:
        pool.mark_used(uid)
        pool.clear_cooldown(uid)
        if desired.get("promote_role") and row.get("role") == "off":
            pool.set_role(uid, "auto")
            pool.log_event("role", actor="auto", to_uid=uid, result="auto",
                           detail="saga recovery: успешный apply переводит off->auto")
    if source in ("manual", "strategy", "setup", "recovery"):
        finish_explicit_apply(cfg, pool, uid or ("live:%s" % host), host, verify,
                              source=source, actor=operation.get("requested_by") or "auto",
                              log=log)
    elif verify:
        pool.set_egress(verify)
    pool.log_event("operation-recovery", actor="auto", to_uid=uid, result="post-state",
                   detail="operation=%s source=%s" % (operation.get("id"), source))


# ------------------------------------------------------------- проверки сервера
def net_alive(cfg, log, with_evidence=False):
    """Шаг 1 (§8): жива ли сеть сервера — прямой curl МИМО прокси. Любой ответ
    (HTTP-код != 000) от любого таргета -> сеть жива. Мёртвая сеть -> FROZEN_NET."""
    if os.name != "posix":
        result = (True, "dev", [health_mod.evidence(
            "server_network", True, target="dev", via_proxy=False)])
        return result if with_evidence else result[:2]
    evidence = []
    for url in (cfg.get("net_check_urls") or NET_CHECK_URLS):
        rc, out = apply_mod.run_cmd(
            ["curl", "-sk", "--max-time", "6", "-o", os.devnull, "-w", "%{http_code}", url],
            timeout=12)
        code = (out or "").strip()[-3:]
        host = urllib.parse.urlparse(url).hostname or ""
        hostname_target = bool(host and not re.fullmatch(r"[0-9a-fA-F:.]+", host))
        if hostname_target and rc == 6:
            evidence.append(health_mod.evidence(
                "dns", False, target=host, error_kind="resolve-failed",
                via_proxy=False))
        elif hostname_target and rc == 0:
            evidence.append(health_mod.evidence(
                "dns", True, target=host, via_proxy=False))
        if rc == 0 and code and code != "000":
            evidence.append(health_mod.evidence(
                "server_network", True, target=url, via_proxy=False))
            result = (True, url, evidence)
            return result if with_evidence else result[:2]
        if rc != 6:
            evidence.append(health_mod.evidence(
                "server_network", False, target=url, via_proxy=False,
                error_kind="transport-error", detail="curl_rc=%s code=%s" % (rc, code)))
    result = (False, None, evidence)
    return result if with_evidence else result[:2]


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


def try_self_heal(cfg, log, keep_direct=False):
    """Шаг 2: рестарт sing-box + восстановление маршрута middleman. -> healthy?

    keep_direct (F6): в EMERGENCY/ROTATING маршрут WAN НЕ трогаем до победы —
    раньше каждый ретрай безусловно возвращал default в мёртвый tun0 на всё
    время попытки, и клиенты моргали минутами (node1/README §12.6). Маршрут
    вернёт _leave_direct после подтверждённого живого egress."""
    log("  self-heal: рестарт sing-box%s" % ("" if keep_direct else " + маршрут middleman"))
    if not keep_direct:
        apply_mod.run_cmd(["ip", "route", "replace", "default", "dev", "tun0", "table", "middleman"])
    apply_mod.restart_singbox()
    apply_mod.wait_tun0()
    h = singbox_health(cfg)
    return h["ok"] or (keep_direct and h["active"] and h["tun0"])


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


def _cc_of(row):
    """Страна кандидата для ранжирования: фактическая (по geoip пробы), иначе заявленная."""
    try:
        return row["exit_cc"] or row["country"]
    except (KeyError, TypeError):
        return (row.get("exit_cc") if hasattr(row, "get") else None) or \
               (row.get("country") if hasattr(row, "get") else None)


# Сколько «стоит» непробованный кандидат там, где страна не первичный ключ (стратегии
# balanced/speed). 100 — не магия: ровно с этого числа стартует probe.score, то есть
# «пока не проверили — считаем средним»: измеренный хороший его обгонит, измеренный
# плохой отстанет, а сам он попадёт в перебор раньше заведомо слабых.
UNPROBED_SCORE = 100.0
FAILED_SCORE = 0.0
DEFAULT_SWITCH_POLICY = {
    "switch_margin": 15.0,
    "min_hold_time": 1800.0,
    "max_latency_regression": 500.0,
}


def switch_policy_cfg(cfg=None):
    """Fail-safe числовая политика проактивной смены канала."""
    raw = (cfg or {}).get("health") or {}
    if not isinstance(raw, dict):
        raw = {}
    limits = {
        "switch_margin": (0.0, 1000.0),
        "min_hold_time": (0.0, 604800.0),
        "max_latency_regression": (0.0, 60000.0),
    }
    result = {}
    for key, (minimum, maximum) in limits.items():
        try:
            value = raw.get(key, DEFAULT_SWITCH_POLICY[key])
            if isinstance(value, bool):
                raise ValueError
            value = float(value)
            if not math.isfinite(value) or value < minimum or value > maximum:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            value = DEFAULT_SWITCH_POLICY[key]
        result[key] = value
    return result


def switch_decision(current_score, candidate_score, current_latency=None,
                    candidate_latency=None, last_used_at=None, current_healthy=True,
                    cfg=None, now=None):
    """Pure hysteresis gate для проактивной смены стратегии.

    Критический отказ текущего канала обходит hold-time и остальные
    ограничители. Аварийная rotate-ветка эту функцию не вызывает.
    """
    policy = switch_policy_cfg(cfg)
    if not current_healthy:
        return {"allow": True, "reason": "critical-failure", "bypass": True,
                "margin": None, "threshold": policy["switch_margin"],
                "hold_remaining": 0.0, "latency_regression": None}
    try:
        if isinstance(current_score, bool) or isinstance(candidate_score, bool):
            raise ValueError
        current_score = float(current_score)
        candidate_score = float(candidate_score)
        if not math.isfinite(current_score) or not math.isfinite(candidate_score):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        return {"allow": False, "reason": "score-unavailable", "bypass": False,
                "margin": None, "threshold": policy["switch_margin"],
                "hold_remaining": 0.0, "latency_regression": None}

    margin = candidate_score - current_score
    used_age = age_seconds(last_used_at, now=now)
    if used_age is not None:
        used_age = max(0.0, used_age)
    hold_remaining = (max(0.0, policy["min_hold_time"] - used_age)
                      if used_age is not None else 0.0)
    latency_regression = None
    try:
        if isinstance(current_latency, bool) or isinstance(candidate_latency, bool):
            raise ValueError
        if current_latency is not None and candidate_latency is not None:
            current_latency = float(current_latency)
            candidate_latency = float(candidate_latency)
            if not math.isfinite(current_latency) or not math.isfinite(candidate_latency):
                raise ValueError
            latency_regression = candidate_latency - current_latency
    except (TypeError, ValueError, OverflowError):
        latency_regression = None

    blockers = []
    if margin < policy["switch_margin"]:
        blockers.append("margin")
    if hold_remaining > 0:
        blockers.append("min-hold")
    if (latency_regression is not None
            and latency_regression > policy["max_latency_regression"]):
        blockers.append("latency-regression")
    return {"allow": not blockers,
            "reason": "+".join(blockers) if blockers else "better",
            "bypass": False, "margin": round(margin, 1),
            "threshold": policy["switch_margin"],
            "hold_remaining": round(hold_remaining, 1),
            "latency_regression": (round(latency_regression, 1)
                                   if latency_regression is not None else None)}


def rank_candidates(rows, cfg=None, current_host=None):
    """Упорядочить кандидатов для выбора канала (§7.4 + политика стран §6.1).

    Найдено на приёмке 15.08 (снос №5): первый автоматический канал ушёл в Нигерию
    (disputed) при живых Латвии/Германии/Финляндии в пуле — `rotate` брал первого,
    у кого уже была проба (score), и не сравнивал со свежими кандидатами (score=None).
    Теперь порядок перебора детерминирован и уважает политику стран:

      * страны из чёрного списка (ru/ua/by) выбрасываются — их даже не пробуем;
      * сначала — выше априорная оценка страны (Латвия перед Нигерией), даже если
        по стране кандидат ещё не пробован (score=None): его проверят при переборе;
      * при равной стране — выше фактический score пробы (проверенный рабочий вперёд).

    Это тот же вывод, что даёт полный скоринг probe.score (в него входит country.rating),
    но без требования, чтобы КАЖДЫЙ кандидат уже был пробован. rotate перебирает список
    и берёт ПЕРВОГО прошедшего живую пробу — поэтому важен именно порядок.

    **Стратегия стран (17.08)** решает, остаётся ли страна первичным ключом. При
    «репутации» и «только избранных» — да, порядок ровно тот, что описан выше. При
    «балансе» и «скорости» страна перестаёт диктовать: сортируем по сумме «вклад страны
    + результат замеров», поэтому быстрый прокси может обогнать более приличный по
    репутации. Непробованному кандидату в этом режиме засчитывается UNPROBED_SCORE —
    иначе свежекупленный прокси навсегда уступал бы любому уже измеренному и не получил
    бы шанса быть проверенным.

    **Оценка — на лету (П3, 1.3.0):** вместо колонки score из БД (посчитанной той
    стратегией, что была активна при пробе) берём probe.score_from_row под текущую.
    Явно про ключ, чтобы не удвоить вес страны: в режимах country_first ключ — пара
    (−rating, −базовая_часть_без_страны); в режимах сумм — −полная_оценка целиком
    (страна уже внутри неё). UI и автоматика видят одни и те же числа.
    """
    country_first = country_mod.strategy_info(cfg)["country_first"]
    ranked = []
    for r in rows:
        # geo_agree строки участвует в первичном ключе (ревью 1.3.0): иначе штраф
        # «базы разошлись» есть в отображаемой оценке, но не в порядке перебора,
        # и спорный IP выбирался бы раньше чистого той же страны
        geo = probe_mod._rget(r, "geo_agree")
        agree = True if geo is None else bool(geo)
        cr = country_mod.rating(_cc_of(r), agree, cfg)
        if cr is None:            # чёрный список — не выбираем и не тратим пробу
            continue
        # Превью/явная смена стратегии включают боевой канал. Его +15 stickiness
        # обязана участвовать и в РЕШЕНИИ, а не только в цифре таблицы — иначе
        # панель дёргала IP ради мизерной разницы. Ротация передаёт список без
        # текущего host, поэтому аварийный failover бонусом не затрагивается.
        full, base = probe_mod.score_from_row(
            r, cfg, is_current=bool(current_host and probe_mod._rget(r, "host") == current_host))
        if full is None and probe_mod._rget(r, "last_probe_at"):
            weight = probe_mod.freshness_weight(r, cfg)
            unknown_base = FAILED_SCORE * weight + UNPROBED_SCORE * (1.0 - weight)
            country_unknown_base = unknown_base
        else:
            unknown_base = UNPROBED_SCORE
            country_unknown_base = 0.0
        # при равных очках — кто быстрее по последнему замеру (приёмка №7: под
        # «скорость и отклик» лестница оценки квантует близкие задержки в один балл,
        # и 826 мс стояли в таблице ПОСЛЕ 925 мс просто по порядку вставки)
        lat = probe_mod._rget(r, "latency_ms")
        lat = float(lat) if lat is not None else float("inf")
        if country_first:
            key = (-(cr), -(base if base is not None else country_unknown_base), lat)
        else:
            key = (-(full if full is not None else cr + unknown_base), lat)
        ranked.append((key, r))
    ranked.sort(key=lambda t: t[0])     # только по ключу: равные сохраняют входной порядок
    return [r for _, r in ranked]


def decision_payload(cfg, mode, reason, rows=(), current_host=None, policy=None,
                     exclusions=()):
    """Без секретов: объяснимый снимок score/freshness/margin для audit/UI."""
    breakdown = []
    freshness = {}
    for row in rows or ():
        uid = str(probe_mod._rget(row, "uid") or "")
        if not uid:
            continue
        full, base = probe_mod.score_from_row(
            row, cfg, is_current=False)
        weight = probe_mod.freshness_weight(row, cfg)
        freshness[uid] = round(float(weight), 6)
        breakdown.append({
            "uid": uid, "total": full, "probe_component": base,
            "country_component": (round(full - base, 6)
                                  if full is not None and base is not None else None),
            "latency_ms": probe_mod._rget(row, "latency_ms"),
            "probe_ok": (None if probe_mod._rget(row, "probe_ok") is None
                         else bool(probe_mod._rget(row, "probe_ok"))),
        })
    policy = dict(policy or {})
    return {"strategy": country_mod.strategy(cfg), "mode": str(mode or ""),
            "score_breakdown": breakdown, "freshness": freshness,
            "margin": policy.get("margin"),
            "threshold": policy.get("threshold"),
            "exclusions": [dict(item) for item in (exclusions or ())],
            "reason": str(reason or "")}


def selectable_candidates(pool, cfg, current_host, providers=None):
    """Кандидаты, из которых МОЖНО собрать канал прямо сейчас (для ротации и для
    решения «докупать или выбрать из пула»): не gone/off, не на cooldown,
    не текущий, страна не в чёрном списке — упорядочены rank_candidates.

    providers (П7): активные адаптеры — строки провайдера без ключа не кандидаты
    (второй пояс поверх gone: продлить/проверить их всё равно нечем). Заодно
    честными становятся ensure_reserve и try_replenish."""
    rows = pool.rotation_candidates(exclude_host=current_host)
    if providers is not None:
        rows = [r for r in rows if r["provider"] in providers]
    return rank_candidates(rows, cfg)


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


def _probe(pool, providers, row, current_host, cfg=None, persist=True):
    pool.observe_provider_errors(providers, actor="auto")
    res = probe_mod.probe(row, provider_check=_check_cb(providers, row))
    is_cur = (row.get("host") == current_host)
    res["score"] = probe_mod.score(row, res, is_current=is_cur, cfg=cfg)
    if persist and pool.get(row["uid"]):
        pool.record_probe(row["uid"], res, is_current=is_cur,
                          strategy=country_mod.strategy(cfg))
    return res


def _cooldown_after_fail(pool, uid, log):
    fc = int((pool.get(uid) or {}).get("fail_count") or 1)
    secs = cooldown_seconds(fc)
    pool.set_cooldown(uid, secs)
    log("  cooldown %s: %d мин (провал #%d)" % (uid, secs // 60, fc))


def _strategy_ranked_rows(cfg, providers, pool, current_host, extra_rows=None,
                          include_stickiness=True):
    """Живой снимок пула для явного применения стратегии, включая боевой канал."""
    rows = pool.rotation_candidates()
    if providers is not None:
        rows = [r for r in rows if r["provider"] in providers]
    known_hosts = {r["host"] for r in rows}
    rows.extend(r for r in (extra_rows or []) if r.get("host") not in known_hosts)
    return rank_candidates(rows, cfg,
                           current_host=current_host if include_stickiness else None)


def _converge_strategy_locked(cfg, providers, pool, log=print, actor="user"):
    """Под общим agent-flock привести боевой канал к ПОСЛЕДНЕЙ стратегии на диске.

    Это не обычный ``apply uid``. Пока фоновое задание ждало lock, человек мог
    выбрать другую стратегию или нажать «В бой». Поэтому цель вычисляется заново,
    MANUAL имеет приоритет, а кандидат после живой пробы ещё раз сравнивается с
    текущим (+15 stickiness). Провайдер в ключе сортировки не участвует.
    """
    reconcile_strategy_override(cfg, pool, log)
    try:
        config_store.refresh_country_strategy(cfg)
    except (OSError, ValueError) as e:
        log("  strategy-converge: не перечитал config.json, использую снимок: %s" % e)
    revision = selection_revision_state(pool, cfg)
    intent_revision = (revision["desired"]
                       if revision["pending"] and revision["kind"] == "strategy" else None)
    intent_strategy = (revision.get("payload") or {}).get("strategy")
    desired = (intent_strategy if intent_revision and intent_strategy in country_mod.STRATEGIES
               else country_mod.strategy(cfg))
    if intent_revision:
        cfg.setdefault("countries", {})["strategy"] = desired

    def revision_done(detail):
        if intent_revision is None:
            return True
        override = pool.get_setting("selection_strategy_override")
        if override in country_mod.STRATEGIES:
            pool.log_event("selection-reconcile", actor=actor, result="config-pending",
                           detail="revision %s: config.json ещё не закрепил %s" %
                                  (intent_revision, override))
            return False
        return mark_selection_applied(pool, intent_revision, actor=actor, detail=detail)
    try:
        sb = apply_mod.load_json(cfg["singbox_config"])
    except (OSError, ValueError, KeyError) as e:
        return {"ok": False, "action": "config-unavailable", "detail": str(e),
                "strategy": desired, "tried": []}
    current_host = apply_mod.current_upstream(sb)
    selection = selection_state(pool, cfg, current_host)
    exclusions = []

    def emit_strategy(result, detail, rows=(), to_uid=None, policy=None):
        """Persist the decision inputs, never the proxy credentials."""
        mode = selection_state(pool, cfg, current_host)["mode"]
        pool.log_event(
            "strategy-apply", actor=actor, to_uid=to_uid, result=result, detail=detail,
            payload=decision_payload(cfg, mode, detail, rows=list(rows or ())[:10],
                                     current_host=current_host, policy=policy,
                                     exclusions=exclusions[-20:]))

    if selection["mode"] == SELECTION_MANUAL:
        detail = "ручной канал появился позже задания — стратегию не применяю"
        emit_strategy("manual-superseded", detail)
        return {"ok": True, "action": "manual-superseded", "detail": detail,
                "strategy": desired, "tried": []}

    tried = []
    # До любого проактивного сравнения измеряем stale боевой канал напрямую через
    # его proxy credentials — без переключения и разрыва текущих соединений.
    current_row = next((row for row in pool.list(include_gone=True)
                        if current_host and row["host"] == current_host), None)
    synthetic_current = current_row is None and bool(current_host)
    if synthetic_current:
        current_row = _row_from_sb(sb, current_host)
    current_extra = None
    if current_row is not None and (synthetic_current
                                    or probe_mod.freshness_weight(current_row, cfg) < 1.0):
        tried.append(current_row["uid"])
        current_res = _probe(pool, providers, current_row, current_host, cfg)
        if current_res.get("disqualified") or not current_res.get("ok"):
            exclusions.append({"uid": current_row["uid"],
                               "reason": current_res.get("disqualified") or "probe-failed"})
            _cooldown_after_fail(pool, current_row["uid"], log)
        elif synthetic_current:
            current_extra = dict(current_row)
            current_extra.update({
                "probe_ok": 1, "last_probe_at": _now_iso(),
                "latency_ms": current_res.get("latency_ms"),
                "tg_ok": current_res.get("tg_ok"),
                "socks_ok": current_res.get("socks_ok"),
                "http_ok": current_res.get("http_ok"),
                "exit_cc": current_res.get("exit_cc"),
                "geo_agree": current_res.get("geo_agree", True),
            })
    for _ in range(MAX_CANDIDATES_PER_CYCLE):
        ranked = _strategy_ranked_rows(
            cfg, providers, pool, current_host,
            extra_rows=[current_extra] if current_extra else None,
            include_stickiness=False)
        if not ranked:
            detail = "в активном пуле нет кандидатов для стратегии %s" % desired
            emit_strategy("empty", detail)
            return {"ok": False, "action": "empty", "detail": detail,
                    "strategy": desired, "tried": tried}
        top = ranked[0]
        if current_host and top["host"] == current_host:
            if (probe_mod.freshness_weight(top, cfg) < 1.0
                    or not bool(probe_mod._rget(top, "probe_ok"))):
                tried.append(top["uid"])
                res = _probe(pool, providers, top, current_host, cfg)
                if res.get("disqualified") or not res.get("ok"):
                    exclusions.append({"uid": top["uid"],
                                       "reason": res.get("disqualified") or "probe-failed"})
                    _cooldown_after_fail(pool, top["uid"], log)
                continue
            detail = "текущий %s уже лучший по %s" % (current_host, desired)
            emit_strategy("stable", detail, ranked)
            revision_done(detail)
            return {"ok": True, "action": "stable", "detail": detail,
                    "strategy": desired, "uid": top["uid"], "tried": tried}

        row = top
        tried.append(row["uid"])
        res = _probe(pool, providers, row, current_host, cfg)
        if res.get("disqualified") or not res.get("ok"):
            exclusions.append({"uid": row["uid"],
                               "reason": res.get("disqualified") or "probe-failed"})
            _cooldown_after_fail(pool, row["uid"], log)
            continue

        # Проба обновила score. Кандидат обязан остаться лучшим и после свежего
        # замера; иначе меню создавало бессмысленную ротацию по старым данным.
        try:
            config_store.refresh_country_strategy(cfg)
        except (OSError, ValueError):
            pass
        latest_revision = selection_revision_state(pool, cfg)
        latest = ((latest_revision.get("payload") or {}).get("strategy")
                  if latest_revision["kind"] == "strategy" else country_mod.strategy(cfg))
        stale_revision = (intent_revision is not None
                          and (latest_revision["desired"] != intent_revision
                               or latest_revision["kind"] != "strategy"))
        if stale_revision or latest != desired:
            detail = "задание устарело: %s/%s -> %s/%s; следующий worker применит новое" % (
                intent_revision, desired, latest_revision["desired"], latest)
            emit_strategy("stale", detail, ranked)
            return {"ok": True, "action": "stale", "detail": detail,
                    "strategy": latest, "tried": tried}
        if selection_state(pool, cfg, current_host)["mode"] == SELECTION_MANUAL:
            detail = "во время пробы включён ручной режим — переключение отменено"
            emit_strategy("manual-superseded", detail, ranked)
            return {"ok": True, "action": "manual-superseded", "detail": detail,
                    "strategy": latest, "tried": tried}
        reranked = _strategy_ranked_rows(
            cfg, providers, pool, current_host,
            extra_rows=[current_extra] if current_extra else None,
            include_stickiness=False)
        if not reranked or (current_host and reranked[0]["host"] == current_host):
            detail = "после свежей пробы текущий канал сохранил преимущество"
            emit_strategy("stable-after-probe", detail, reranked or ranked)
            revision_done(detail)
            return {"ok": True, "action": "stable-after-probe", "detail": detail,
                    "strategy": latest, "tried": tried}
        if reranked[0]["uid"] != row["uid"]:
            # За время сетевой пробы изменился пул; на следующей итерации берём
            # новый фактический top, а не применяем устаревший uid.
            exclusions.append({"uid": row["uid"], "reason": "reranked"})
            continue
        decision = None
        current_live = next((item for item in reranked
                             if current_host and item["host"] == current_host), None)
        if current_live is not None:
            current_score = probe_mod.score_from_row(current_live, cfg, is_current=False)[0]
            candidate_score = probe_mod.score_from_row(reranked[0], cfg,
                                                       is_current=False)[0]
            decision = switch_decision(
                current_score, candidate_score,
                current_latency=probe_mod._rget(current_live, "latency_ms"),
                candidate_latency=probe_mod._rget(reranked[0], "latency_ms"),
                last_used_at=probe_mod._rget(current_live, "last_used_at"),
                current_healthy=bool(probe_mod._rget(current_live, "probe_ok")),
                cfg=cfg)
            if not decision["allow"]:
                detail = (
                    "кандидат %s лучше на %.1f, порог %.1f; "
                    "hold %.0f с; регрессия latency %s мс; %s" % (
                        row["uid"], decision["margin"], decision["threshold"],
                        decision["hold_remaining"],
                        ("%.1f" % decision["latency_regression"]
                         if decision["latency_regression"] is not None else "n/a"),
                        decision["reason"]))
                emit_strategy("held", detail, reranked, to_uid=row["uid"], policy=decision)
                return {"ok": True, "action": "held", "detail": detail,
                        "strategy": latest, "uid": current_live["uid"],
                        "candidate_uid": row["uid"], "decision": decision,
                        "tried": tried}
        try:
            applied = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True,
                                                pool=pool, requested_by=actor,
                                                selection_source="strategy")
        except apply_mod.ApplyError as e:
            pool.bump_fail(row["uid"])
            _cooldown_after_fail(pool, row["uid"], log)
            exclusions.append({"uid": row["uid"], "reason": "apply-failed"})
            emit_strategy("fail", str(e), reranked, to_uid=row["uid"], policy=decision)
            continue
        pool.mark_used(row["uid"])
        pool.clear_cooldown(row["uid"])
        finish_explicit_apply(cfg, pool, row["uid"], row["host"], applied.get("verify"),
                              source="strategy", actor=actor, log=log)
        detail = "%s: %s -> %s (%s)" % (desired, current_host, row["host"], row["uid"])
        if decision is not None:
            if decision["bypass"]:
                detail += "; critical-failure bypass, порог %.1f" % decision["threshold"]
            else:
                detail += "; кандидат лучше на %.1f, порог %.1f; регрессия latency %s мс" % (
                    decision["margin"], decision["threshold"],
                    ("%.1f" % decision["latency_regression"]
                     if decision["latency_regression"] is not None else "n/a"))
        emit_strategy("ok", detail, reranked, to_uid=row["uid"], policy=decision)
        revision_done(detail)
        apply_mod.commit_operation(pool, applied)
        return {"ok": True, "action": "applied", "detail": detail,
                "strategy": desired, "uid": row["uid"], "new_ip": row["host"],
                "verify": applied.get("verify"), "decision": decision, "tried": tried}

    detail = "не удалось применить кандидатов стратегии %s: %s" % (desired, ", ".join(tried))
    emit_strategy("exhausted", detail)
    return {"ok": False, "action": "exhausted", "detail": detail,
            "strategy": desired, "tried": tried}


def converge_strategy(cfg, providers, pool, log=print, actor="user", wait_seconds=0):
    """Сходящаяся фоновая задача стратегии с ожиданием общего agent-flock.

    Несколько быстрых кликов безопасны: systemd запускает независимые workers,
    каждый после получения lock читает последнюю цель; устаревшие становятся noop.
    """
    deadline = time.monotonic() + max(0, int(wait_seconds or 0))
    while True:
        try:
            with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
                return _converge_strategy_locked(cfg, providers, pool, log=log, actor=actor)
        except apply_mod.ApplyError as e:
            if "flock" not in str(e).lower() or time.monotonic() >= deadline:
                detail = "agent занят: %s" % e
                pool.log_event("strategy-apply", actor=actor, result="locked", detail=detail)
                return {"ok": False, "action": "locked", "detail": detail,
                        "strategy": country_mod.strategy(cfg), "tried": []}
            time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))


def reconcile_desired_selection(cfg, providers, pool, log=print, actor="auto",
                                wait_seconds=0):
    """Heartbeat/pool-refresh reconciler: applied revision догоняет desired."""
    revision = selection_revision_state(pool, cfg)
    if not revision["pending"]:
        return {"ok": True, "action": "up-to-date", "revision": revision}
    if revision["kind"] == "manual":
        desired_host = (revision.get("payload") or {}).get("host")
        try:
            live_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
        except (OSError, ValueError, KeyError):
            live_host = None
        if desired_host and desired_host == live_host:
            mark_selection_applied(pool, revision["desired"], actor=actor,
                                   detail="ручной desired host уже live")
            return {"ok": True, "action": "manual-already-live",
                    "revision": selection_revision_state(pool, cfg)}
        # Никогда не применяем MANUAL без новой успешной явной probe/apply.
        return {"ok": False, "action": "manual-pending", "revision": revision}
    if os.name != "posix":
        return {"ok": False, "action": "platform-pending", "revision": revision}
    result = converge_strategy(cfg, providers, pool, log=log, actor=actor,
                               wait_seconds=wait_seconds)
    result["revision"] = selection_revision_state(pool, cfg)
    return result


# ============================================================ ОРКЕСТРАЦИЯ
def rotate(cfg, providers, pool, alerter, reason="manual", actor="auto",
           log=print, force=False):
    """Точка входа автоматики (§8). Возвращает dict(state, action, detail).

    Один flock на весь цикл; при занятом locke — мягкий выход (кто-то уже правит).
    """
    pool.observe_provider_errors(providers, actor=actor)
    pool.heartbeat()                                   # §6.3: цикл агента прошёл
    result = {"state": None, "action": None, "detail": "", "ok": False}

    if pool.get_setting("automat_frozen") == "1" and not force:
        # Пауза НЕ затирает automat_state (ревью 1.3.0): FROZEN в состоянии хоронил
        # EMERGENCY/ROTATING, и после снятия паузы прямой WAN-выход оставался
        # осиротевшим навсегда (флаг есть, а снять его некому — нарушение
        # инварианта флага). Пауза видна панели через automat_frozen; прямой
        # выход на паузе поддерживаем (ребут не должен дать чёрную дыру).
        state_now = pool.get_setting("automat_state") or OK
        if state_now in (EMERGENCY, ROTATING):
            restore_emergency_routes(cfg, pool, log, actor)
        result.update(state=state_now, action="manual-pause",
                      detail="автоматика на паузе (FROZEN) — пропускаю", ok=False)
        return result
    if os.name != "posix":
        result.update(state=pool.get_setting("automat_state") or OK, action="noop",
                      detail="rotate доступен только на сервере (Linux)")
        return result

    state_before = pool.get_setting("automat_state") or OK
    if state_before == EMERGENCY and not force:
        restore_emergency_routes(cfg, pool, log, actor)
        # F7: ручную аварию автоматика НЕ снимает — снимет только человек
        if pool.get_setting("emergency_manual") == "1":
            return _state(pool, result, EMERGENCY, "manual-emergency",
                          "авария включена вручную — автоматика её не снимает (кнопка/CLI)")
        # F6: backoff 2→5→10→15→30 мин вместо ровных 15 (watchdog долбит каждые 2 мин)
        delay = emergency_retry_delay(pool.get_setting("emergency_retry_n"))
        age = age_seconds(pool.get_setting("emergency_last_retry"))
        if age is not None and age < delay:
            return _state(pool, result, EMERGENCY, "emergency-wait",
                          "аварийный режим: до следующей попытки %d с (backoff)" % (delay - age))
    if state_before == ROTATING and not force:
        # инвариант флага: прямой выход времён перебора переживает ребут/сброс
        # маршрута так же, как аварийный; окна повтора у ROTATING нет — добираем
        # пул каждым тиком сторожа
        restore_emergency_routes(cfg, pool, log, actor)

    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _rotate_locked(cfg, providers, pool, alerter, reason, actor, log,
                                  result, state_before)
    except apply_mod.ApplyError as e:
        # flock занят — другой процесс (кнопка/cron) уже правит конфиг. Не наша очередь.
        return _state(pool, result, state_before, "locked", "flock занят: %s" % e)


def _rotate_locked(cfg, providers, pool, alerter, reason, actor, log, result, state_before):
    reconcile_strategy_override(cfg, pool, log)
    try:
        current_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
    except (OSError, ValueError, KeyError):
        current_host = None
    selection = selection_state(pool, cfg, current_host)
    if (selection["mode"] == SELECTION_MANUAL
            and selection.get("manual_host") != current_host):
        # Конфиг сменился в обход штатного explicit-apply (ручная правка/rollback
        # старой версии). Закреплять уже несуществующий host опаснее, чем честно
        # вернуться к измеряемому дефолту.
        release_manual_on_fault(cfg, pool, actor=actor,
                                reason="manual-pin-drift: live=%s" % (current_host or "none"),
                                log=log)
        selection = selection_state(pool, cfg, current_host)
    if state_before == EMERGENCY:
        pool.set_setting("emergency_last_retry", _now_iso())
        pool.set_setting("emergency_retry_n",
                         int(pool.get_setting("emergency_retry_n") or 0) + 1)

    # --- ШАГ 1: сеть сервера жива? ---
    net_result = net_alive(cfg, log, with_evidence=True)
    alive, via = net_result[:2]
    net_evidence = (net_result[2] if len(net_result) > 2 else [health_mod.evidence(
        "server_network", alive, target=via or "direct", via_proxy=False)])
    egress = apply_mod.verify_egress()
    pool.set_egress(egress)          # дашборд показывает эту метку, сам пробу не гоняет
    sb_h = singbox_health(cfg)
    in_direct = state_before in (EMERGENCY, ROTATING) or os.path.exists(EMERGENCY_FLAG)
    # F6: в прямом выходе middleman-маршрут СОЗНАТЕЛЬНО не tun0 — здоровье sing-box
    # считаем без него, иначе каждый ретрай уходил бы в self-heal и дёргал маршрут.
    sb_ok = sb_h["ok"] or (in_direct and sb_h["active"] and sb_h["tun0"])
    d = decide(alive, egress["ok"], sb_ok)
    log("диагностика (§8): сеть=%s egress=%s sing-box=%s -> %s"
        % ("жива" if alive else "МЕРТВА", "ok" if egress["ok"] else "нет",
           "ok" if sb_ok else "нет", d))

    if d == "frozen_net":
        pool.log_event("frozen_net", actor=actor, result="on",
                       detail="сеть сервера недоступна — ничего не меняю, не покупаю")
        _alert_once(pool, alerter, "frozen_net",
                    detail="прямой curl мимо прокси не проходит (%s)" % reason)
        if state_before in (EMERGENCY, ROTATING):
            # сеть легла ПОВЕРХ прямого выхода: состояние не затираем — иначе после
            # восстановления сети выход из EMERGENCY/ROTATING никогда не снимет
            # WAN-маршрут (инвариант флага, ревью 1.3.0)
            result.update(state=state_before, action="frozen_net",
                          detail="сеть сервера мертва — заморожено; прямой выход сохранён", ok=False)
            return result
        return _state(pool, result, FROZEN_NET, "frozen_net",
                      "сеть сервера мертва — заморожено, покупок нет")

    if d == "ok":
        _reset_streaks(pool)
        # выход через tun0 жив. Прямой выход снимаем по ФАКТУ (in_direct: состояние
        # ИЛИ флаг) — состояние могло быть затёрто паузой/чужим сбоем, а осиротевший
        # WAN-выход с флагом никто больше не снимет (инвариант флага, ревью 1.3.0).
        if in_direct:
            _leave_direct(cfg, pool, alerter, egress, log, actor, state_before)
        if selection["mode"] == SELECTION_MANUAL:
            return _state(pool, result, OK, "manual-watch",
                          "ручной канал %s здоров — стратегии не переключают его"
                          % (selection.get("manual_uid") or current_host))
        return _state(pool, result, OK, "noop", "egress жив (%s) — делать нечего" % egress["egress_ip"])

    # --- F1: Telegram ≠ канал: ipify через tun0 жив, мёртв только api.telegram.org ---
    if d == "proxy_fault" and egress.get("why_kind") == "tg":
        return _tg_degraded(cfg, providers, pool, alerter, result, egress, log, actor,
                            state_before, in_direct)

    if d == "self_heal":
        if (try_self_heal(cfg, log, keep_direct=in_direct)
                and apply_mod.verify_egress()["ok"]):
            pool.log_event("self-heal", actor=actor, result="ok", detail="sing-box/tun0 восстановлены")
            _reset_streaks(pool)
            if in_direct:
                _leave_direct(cfg, pool, alerter, apply_mod.verify_egress(), log, actor, state_before)
            return _state(pool, result, OK, "self-heal", "sing-box восстановлен")
        log("  self-heal не помог — вероятно, виноват прокси, иду дальше")

    # --- ШАГ 3: RETUNE (текущий прокси жив по другому протоколу) ---
    initial_evidence = list(egress.get("evidence") or []) + list(net_evidence)
    rt = try_retune(cfg, providers, pool, alerter, log, actor,
                    prior_evidence=initial_evidence)
    if rt.get("ok"):
        _reset_streaks(pool)
        if in_direct:
            _leave_direct(cfg, pool, alerter, rt.get("verify") or apply_mod.verify_egress(),
                          log, actor, state_before)
        return _state(pool, result, OK, "retune", rt.get("detail", "RETUNE ок"))
    if rt.get("external_outage"):
        decision = rt.get("health_decision") or {}
        detail = ("proxy fault не подтверждён: %s; failed_targets=%s, "
                  "success=%s, threshold=%s" % (
                      decision.get("reason"), len(decision.get("failed_targets") or []),
                      decision.get("successful_signals"), decision.get("threshold")))
        pool.log_event("health-quorum", actor=actor, result="held", detail=detail)
        if in_direct:
            _leave_direct(cfg, pool, alerter, egress, log, actor, state_before)
        return _state(pool, result, DEGRADED, "quorum-held",
                      detail + " — IP не меняю")

    # F1/F2: перед деструктивными шагами отказ должен быть ПОДТВЕРЖДЁН.
    # В EMERGENCY/ROTATING он подтверждён самим состоянием; исход «прокси жив,
    # egress мёртв даже после рестарта» (calm_failed) считается подтверждением
    # после CALM_MAX_STREAK подряд (предохранитель F2 — иначе вечное «успокойся»).
    confirmed = (state_before in (EMERGENCY, ROTATING)
                 or bool(rt.get("proxy_fault_confirmed")))
    if rt.get("calm_failed"):
        streak = int(pool.get_setting("calm_fail_streak") or 0) + 1
        pool.set_setting("calm_fail_streak", streak)
        if streak >= CALM_MAX_STREAK:
            log("  F2: «прокси жив» не лечится рестартом %d циклов подряд — эскалация в перебор" % streak)
            confirmed = True
        elif not confirmed:
            pool.log_event("suspect", actor=actor, result="calm-wait",
                           detail="прокси жив, egress мёртв после рестарта sing-box (%d/%d)"
                                  % (streak, CALM_MAX_STREAK))
            return _state(pool, result, SUSPECT, "calm-wait",
                          "прокси жив, egress мёртв после рестарта (%d/%d) — эскалация после %d подряд"
                          % (streak, CALM_MAX_STREAK, CALM_MAX_STREAK))
    else:
        pool.set_setting("calm_fail_streak", None)

    if not confirmed:
        # F1: единичный чих не запускает лестницу — вторая попытка через паузу
        pool.set_setting("automat_state", SUSPECT)
        log("  SUSPECT: первый провал verify — подтверждаю повтором через %d с (F1)" % RECHECK_DELAY_SEC)
        time.sleep(RECHECK_DELAY_SEC)
        egress2 = apply_mod.verify_egress()
        pool.set_egress(egress2)
        if egress2["ok"]:
            _reset_streaks(pool)
            if in_direct:
                _leave_direct(cfg, pool, alerter, egress2, log, actor, state_before)
            pool.log_event("suspect", actor=actor, result="flap",
                           detail="повтор verify через %d с прошёл — единичный чих, деструктив отменён"
                                  % RECHECK_DELAY_SEC)
            return _state(pool, result, OK, "flap",
                          "egress флапнул: повтор verify прошёл — ничего не ломаю")
        if egress2.get("why_kind") == "tg":
            return _tg_degraded(cfg, providers, pool, alerter, result, egress2, log, actor,
                                state_before, in_direct)

    # --- ШАГ 4: ROTATING ---
    # До этой точки дошёл только ПОДТВЕРЖДЁННЫЙ отказ самого канала: сеть сервера
    # жива, self-heal/RETUNE не помогли, повтор verify провалился. Только здесь
    # разрешено снять ручную фиксацию; единичный чих её не отменяет.
    if state_before not in (ROTATING, EMERGENCY):
        pool.log_event("proxy-fault", actor=actor, result="confirmed",
                       detail="health quorum and repeat verification confirmed proxy fault")
    manual_release = release_manual_on_fault(
        cfg, pool, actor=actor, reason="подтверждённый отказ перед ROTATING", log=log)
    if manual_release.get("released"):
        result["manual_released"] = True
        result["fallback_strategy"] = MANUAL_FALLBACK_STRATEGY
    # F3: кнопка панели (reason=panel) — ручной запуск, лимит замен её не касается
    if pool.rotations_last_hour() >= MAX_REPLACEMENTS_PER_HOUR and reason not in ("manual", "panel"):
        log("  лимит замен ≤%d/час исчерпан — в аварийный режим до охлаждения"
            % MAX_REPLACEMENTS_PER_HOUR)
        _enter_emergency(cfg, pool, alerter,
                         "лимит замен ≤%d/час исчерпан (антифлаппинг §8)" % MAX_REPLACEMENTS_PER_HOUR,
                         log, actor, state_before)
        return _state(pool, result, EMERGENCY, "rate-limited", "лимит замен/час — авария")

    rot = try_rotating(cfg, providers, pool, alerter, log, actor)
    if rot.get("ok"):
        _reset_streaks(pool)
        if in_direct:
            _leave_direct(cfg, pool, alerter, rot["verify"], log, actor, state_before)
        ensure_reserve(cfg, providers, pool, alerter, log, actor)   # N+1: из пула, не покупкой (§6.5)
        return _state(pool, result, OK, "rotate", rot.get("detail", "ротация ок"))

    # Остановились по лимиту кандидатов/цикл, в пуле ещё есть непроверенные (§8, снос №5):
    # НЕ покупаем — честный ЖЁЛТЫЙ ROTATING (F3), а не «авария». Прямой выход на время
    # перебора — СТРОГО под флагом (инвариант: сторож не вернёт default в мёртвый tun0);
    # маршрутами ROTATING управляет ровно как EMERGENCY, отличие — только UI и алерты.
    if rot.get("capped"):
        emergency_on(cfg, log)
        pool.set_setting("automat_state", ROTATING)
        if state_before != ROTATING:
            pool.set_setting("rotating_since", _now_iso())
        # повтор придёт следующим тиком сторожа (~2 мин) — окна ретрая нет
        pool.set_setting("emergency_last_retry", None)
        pool.log_event("rotating", actor=actor, result="probing",
                       detail="перебираю пул: %s из %s за цикл — добираю следующим тиком, не покупаю"
                              % (rot.get("tried"), rot.get("total")))
        return _state(pool, result, ROTATING, "pool-probing",
                      "перебор пула (%s из %s) — прямой выход на время перебора, покупка не нужна"
                      % (rot.get("tried"), rot.get("total")))

    # --- ШАГ 4b: REPLENISH (покупка — только когда пул честно исчерпан) ---
    rep = try_replenish(cfg, providers, pool, alerter, log, actor)
    if rep.get("ok"):
        _reset_streaks(pool)
        if in_direct:
            _leave_direct(cfg, pool, alerter, rep["verify"], log, actor, state_before)
        return _state(pool, result, OK, "replenish", rep.get("detail", "докупка ок"))

    # --- EMERGENCY ---
    _enter_emergency(cfg, pool, alerter, rep.get("reason") or "живых кандидатов нет и купить нельзя",
                     log, actor, state_before)
    return _state(pool, result, EMERGENCY, "emergency", rep.get("reason") or "авария")


def _reset_streaks(pool):
    """Здоровый исход цикла: обнулить стрики подозрений (F1 TG, F2 calm)."""
    pool.set_setting("tg_fail_streak", None)
    pool.set_setting("calm_fail_streak", None)


def sync_degraded_state(pool, verify, alerter=None, actor="auto", light=False):
    """Лёгкая синхронизация SUSPECT/DEGRADED вне полного цикла rotate (ревью 1.3.0).

    Сторож на здоровом по его меркам узле rotate не зовёт вовсе, поэтому:
    «мёртв только Telegram» сам по себе не выставлял DEGRADED (проверка сторожа —
    ipify, он жив), а однажды выставленные SUSPECT/DEGRADED после самоизлечения
    висели в панели бессрочно. Эту функцию зовут циклы, которые и так меряют выход:
    pool-refresh (полный verify, раз в 30 мин) и egress-mark (light=True, раз в
    5 мин — TG не меряет, поэтому только снимает SUSPECT, DEGRADED не трогает).
    Деструктива нет; EMERGENCY/ROTATING/FROZEN* не трогаем — ими правит rotate."""
    st = pool.get_setting("automat_state") or OK
    if verify.get("ok"):
        # light-метка TG не меряет: живой ipify снимает только SUSPECT; DEGRADED
        # снимается лишь полным verify (TG реально ожил)
        clearable = (SUSPECT,) if light else (SUSPECT, DEGRADED)
        if st in clearable:
            pool.set_setting("automat_state", OK)
            _reset_streaks(pool)
            return OK
        return st
    if light:
        return st
    if verify.get("why_kind") == "tg" and st in (OK, SUSPECT, DEGRADED):
        streak = int(pool.get_setting("tg_fail_streak") or 0) + 1
        pool.set_setting("tg_fail_streak", streak)
        pool.set_setting("automat_state", DEGRADED)
        if streak == TG_ALERT_STREAK and alerter is not None:
            pool.log_event("degraded", actor=actor, result="tg",
                           detail="api.telegram.org недоступен %d проверок подряд; канал (ipify) жив"
                                  % streak)
            alerter.tg_degraded(streak=streak, egress=verify.get("egress_ip"))
        return DEGRADED
    return st


def _tg_degraded(cfg, providers, pool, alerter, result, egress, log, actor, state_before,
                 in_direct=False):
    """F1: ipify через tun0 жив — канал НЕ мёртв, недоступен только api.telegram.org.

    RETUNE разрешён (мог умереть именно http-канал прокси), ротация/авария — нет:
    живой IP из-за чужого сбоя не теряем. Событие + письмо после TG_ALERT_STREAK
    подряд (один раз на стрик). Из прямого выхода выходим: канал-то жив."""
    streak = int(pool.get_setting("tg_fail_streak") or 0) + 1
    pool.set_setting("tg_fail_streak", streak)
    rt = try_retune(cfg, providers, pool, alerter, log, actor)
    if rt.get("ok"):
        _reset_streaks(pool)
        if in_direct or state_before in (EMERGENCY, ROTATING):
            _leave_direct(cfg, pool, alerter, rt.get("verify") or egress, log, actor, state_before)
        return _state(pool, result, OK, "retune", rt.get("detail", "RETUNE ок"))
    if in_direct or state_before in (EMERGENCY, ROTATING):
        _leave_direct(cfg, pool, alerter, egress, log, actor, state_before)
    if streak == TG_ALERT_STREAK:
        pool.log_event("degraded", actor=actor, result="tg",
                       detail="api.telegram.org недоступен %d проверок подряд; канал (ipify) жив"
                              % streak)
        alerter.tg_degraded(streak=streak, egress=egress.get("egress_ip"))
    return _state(pool, result, DEGRADED, "tg-degraded",
                  "канал жив (ipify %s), Telegram недоступен (%d подряд) — ротацию не делаю"
                  % (egress.get("egress_ip"), streak))


# ------------------------------------------------------------------- RETUNE §7.3
def try_retune(cfg, providers, pool, alerter, log, actor, prior_evidence=None):
    sb = apply_mod.load_json(cfg["singbox_config"])
    host = apply_mod.current_upstream(sb)
    if not host:
        return {"ok": False, "why": "нет текущего upstream"}
    cur_socks = _outbound_of(sb, "socks-out")
    cur_tg = _outbound_of(sb, "http-tg")
    row = _pool_row_by_host(pool, host) or _row_from_sb(sb, host)
    res = _probe(pool, providers, row, host, cfg, persist=False)
    if res.get("disqualified") or not res.get("ok"):
        if res.get("disqualified") in ("no-combo", "provider-check-dead+no-combo"):
            evidence = list(prior_evidence or []) + list(res.get("evidence") or [])
            decision = health_mod.proxy_fault_decision(evidence, cfg=cfg)
            if decision["proxy_fault"]:
                if pool.get(row["uid"]):
                    pool.record_probe(row["uid"], res, is_current=True,
                                      strategy=country_mod.strategy(cfg))
                return {"ok": False, "proxy_fault_confirmed": True,
                        "health_decision": decision,
                        "why": "кворум подтвердил отказ прокси: %s" % decision["reason"]}
            return {"ok": False, "external_outage": True,
                    "health_decision": decision,
                    "why": "кворум не подтвердил отказ прокси: %s" % decision["reason"]}
        if pool.get(row["uid"]):
            pool.record_probe(row["uid"], res, is_current=True,
                              strategy=country_mod.strategy(cfg))
        return {"ok": False, "why": "текущий прокси не проксирует ни по одному протоколу"}
    if pool.get(row["uid"]):
        pool.record_probe(row["uid"], res, is_current=True,
                          strategy=country_mod.strategy(cfg))
    try:
        socks_out, http_tg, _ = apply_mod.choose_outbounds(
            host, row.get("user") or "", row.get("password") or "",
            res.get("socks_port"), res.get("http_port"))
    except apply_mod.ApplyError:
        return {"ok": False, "why": "нет рабочей комбинации порт×протокол"}
    changed = (socks_out["type"] != cur_socks[0] or socks_out["server_port"] != cur_socks[1]
               or http_tg["type"] != cur_tg[0] or http_tg["server_port"] != cur_tg[1])
    if not changed:
        # F2: прокси ЖИВ (проба только что прошла), комбинация уже оптимальна —
        # значит виноват не прокси (egress флапнул / sing-box завис). Раньше это
        # был ok=False, и цикл честно шёл ЛОМАТЬ живой канал ротацией. Теперь:
        # рестарт sing-box, verify — успех цикла без ротации. Не помогло —
        # calm_failed: предохранитель в rotate() эскалирует после 3 подряд.
        log("  RETUNE: прокси жив, конфиг оптимален — рестарт sing-box без ротации (F2)")
        apply_mod.restart_singbox()
        apply_mod.wait_tun0()
        v = apply_mod.verify_egress()
        pool.set_egress(v)
        if v["ok"]:
            pool.log_event("retune", actor=actor, to_uid=row["uid"], result="calm",
                           detail="прокси жив, конфиг оптимален — egress ожил после рестарта sing-box")
            return {"ok": True, "verify": v, "calm": True,
                    "detail": "прокси жив, egress ожил после рестарта sing-box (ротация не нужна)"}
        return {"ok": False, "calm_failed": True,
                "why": "прокси жив, но egress мёртв даже после рестарта sing-box"}
    log("  RETUNE: %s  %s -> %s (IP не меняется)"
        % (host, _mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"]))))
    try:
        r = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True,
                                     pool=pool, requested_by=actor,
                                     selection_source="retune")
    except apply_mod.ApplyError as e:
        pool.log_event("retune", actor=actor, to_uid=row["uid"], result="fail", detail=str(e))
        return {"ok": False, "why": "RETUNE не применился: %s" % e}
    pool.log_event("retune", actor=actor, to_uid=row["uid"], result="ok",
                   detail="%s -> %s (IP=%s без смены)"
                   % (_mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"])), host))
    apply_mod.commit_operation(pool, r)
    alerter.retuned(host=host, old_mode=_mode(cur_socks),
                    new_mode=_mode((socks_out["type"], socks_out["server_port"])), uid=row["uid"])
    return {"ok": True, "verify": r["verify"],
            "detail": "RETUNE %s -> %s на %s"
            % (_mode(cur_socks), _mode((socks_out["type"], socks_out["server_port"])), host)}


# ------------------------------------------------------------------- ROTATING
def try_rotating(cfg, providers, pool, alerter, log, actor):
    sb = apply_mod.load_json(cfg["singbox_config"])
    host = apply_mod.current_upstream(sb)
    # Кандидаты уже упорядочены по стране+score (rank_candidates): сначала пробуем
    # надёжные страны (Латвия перед Нигерией), чёрный список выброшен (§6.1, снос №5).
    cands = selectable_candidates(pool, cfg, host, providers)
    candidate_uids = {row["uid"] for row in cands}
    exclusions = []
    now = _now_iso()
    for item in pool.list(include_gone=True):
        if item["uid"] in candidate_uids:
            continue
        if host and item.get("host") == host:
            why = "current"
        elif item.get("gone"):
            why = "gone"
        elif item.get("role") == "off":
            why = "disabled"
        elif item.get("cooldown_until") and str(item["cooldown_until"]) > now:
            why = "cooldown"
        elif providers is not None and item.get("provider") not in providers:
            why = "provider-unavailable"
        elif country_mod.rating(_cc_of(item),
                                True if item.get("geo_agree") is None
                                else bool(item.get("geo_agree")), cfg) is None:
            why = "country-blocked"
        else:
            why = "not-selectable"
        exclusions.append({"uid": item["uid"], "reason": why})

    def emit_rotate(result, detail, row=None):
        pool.log_event(
            "rotate", actor=actor, to_uid=row["uid"] if row is not None else None,
            result=result, detail=detail,
            payload=decision_payload(
                cfg, selection_state(pool, cfg, host)["mode"], detail,
                rows=cands[:10], current_host=host, exclusions=exclusions[-20:]))

    if not cands:
        detail = "пригодных кандидатов нет (все off/gone/на cooldown/в чёрном списке)"
        log("  ROTATING: " + detail)
        emit_rotate("empty", detail)
        return {"ok": False, "exhausted": True}
    tried = 0
    for row in cands:
        if tried >= MAX_CANDIDATES_PER_CYCLE:
            # Остановились по лимиту, но в пуле ещё есть НЕпробованные кандидаты. Это НЕ
            # повод покупать (решение владельца, снос №5): доберём их следующим тиком.
            detail = "лимит ≤%d кандидатов/цикл — остальные в следующем цикле" % MAX_CANDIDATES_PER_CYCLE
            log("  ROTATING: " + detail)
            emit_rotate("capped", detail)
            return {"ok": False, "exhausted": False, "capped": True,
                    "tried": tried, "total": len(cands)}
        tried += 1
        res = _probe(pool, providers, row, host, cfg)
        if res.get("disqualified") or not res.get("ok"):
            exclusions.append({"uid": row["uid"],
                               "reason": res.get("disqualified") or "probe-failed"})
            _cooldown_after_fail(pool, row["uid"], log)
            continue
        try:
            r = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True,
                                         pool=pool, requested_by=actor,
                                         selection_source="rotate")
        except apply_mod.ApplyError as e:
            pool.bump_fail(row["uid"])
            _cooldown_after_fail(pool, row["uid"], log)
            exclusions.append({"uid": row["uid"], "reason": "apply-failed"})
            emit_rotate("fail", str(e), row=row)
            continue
        pool.mark_used(row["uid"])
        pool.clear_cooldown(row["uid"])
        # F8: уходящий канал этой пары считается «оборвавшимся в бою» — ротация
        # запускается только по мёртвому каналу (ручной apply сюда не попадает)
        old_row = _pool_row_by_host(pool, host)
        if old_row is not None:
            pool.learning_record_drop(old_row)
        detail = "%s -> %s egress=%s cc=%s (перебрано %d)" % (
            host, r["new_ip"], r["verify"]["egress_ip"], r["verify"]["exit_cc"], tried)
        emit_rotate("ok", detail, row=row)
        pending_revision = selection_revision_state(pool, cfg)
        if (pending_revision["pending"] and pending_revision["kind"] == "strategy"
                and (pending_revision.get("payload") or {}).get("strategy")
                == country_mod.strategy(cfg)):
            mark_selection_applied(pool, pending_revision["desired"], actor=actor,
                                   detail="успешная fault rotation применила desired strategy")
        apply_mod.commit_operation(pool, r)
        alerter.rotated(old_ip=host, new_ip=r["new_ip"], uid=row["uid"],
                        egress=r["verify"]["egress_ip"], cc=r["verify"]["exit_cc"],
                        tg_code=r["verify"]["tg_code"], score=res.get("score"), candidates_tried=tried)
        return {"ok": True, "uid": row["uid"], "new_ip": r["new_ip"], "verify": r["verify"],
                "detail": "ротация %s -> %s (%s)" % (host, r["new_ip"], row["uid"])}
    # перебрали всех пригодных, никто не прошёл живую пробу (провалившиеся ушли на cooldown) —
    # пул честно исчерпан, только теперь допустима докупка (REPLENISH)
    emit_rotate("exhausted", "все пригодные кандидаты провалили живую пробу")
    return {"ok": False, "exhausted": True, "tried": tried}


# --------------------------------------------- переключение с провайдера (П7-2)
def switch_from_provider(cfg, providers, pool, alerter, from_provider,
                         log=print, actor="user", reason="key-removed"):
    """П7-2 (1.6.0): плановое переключение боевого канала с провайдера без ключа.

    Это НЕ лестница §8: канал ЖИВОЙ (egress работает), rotate его чинить не станет
    («делать нечего»). Но ключ провайдера удалён — продлить боевой нечем и управлять
    им панель не может, поэтому уходим по-хорошему, пока канал ещё дышит: кандидаты
    ОСТАВШИХСЯ провайдеров в порядке текущей стратегии (ровно как «В бой»), первый
    прошедший живую пробу применяется через apply_candidate (проверка -> переключение
    -> verify -> автооткат). Провал любого шага НЕ рвёт работающий канал.

    После успеха строки выбывшего провайдера добиваются purge_provider (боевой
    больше не на нём). Если живых кандидатов нет — канал остаётся, письмо владельцу
    (дедуп 6 ч), повтор при каждом pool-refresh (крон */30 мин).

    Возвращает dict(ok, switched, detail[, uid]): ok=True и switched=False —
    переключать нечего (боевой не у этого провайдера).
    """
    res = {"ok": False, "switched": False, "detail": ""}
    try:
        sb = apply_mod.load_json(cfg["singbox_config"])
    except (OSError, ValueError):
        sb = {}
    host = apply_mod.current_upstream(sb)
    cur = _pool_row_by_host(pool, host) if host else None
    if cur is None or cur.get("provider") != from_provider:
        res.update(ok=True, detail="боевой канал не у %s — переключать нечего" % from_provider)
        return res
    selection = selection_state(pool, cfg, host)
    if (selection["mode"] == SELECTION_MANUAL
            and selection.get("manual_host") == host):
        # Удаление API-ключа не равно отказу канала. Владелец явно закрепил IP —
        # продолжаем пассивно следить за ним и отпустим только при подтверждённой
        # смерти, уже в AUTO(speed). Иначе фоновый pool-refresh обходил MANUAL.
        res.update(ok=True, manual=True,
                   detail="боевой %s закреплён вручную; ключ %s удалён, но живой "
                          "канал не меняю — при отказе включится Скорость и отклик"
                          % (host, from_provider))
        return res
    if pool.get_setting("automat_frozen") == "1":
        # паузу уважаем как rotate: владелец сказал «руки прочь» — боевой держим,
        # повтор придёт со следующим pool-refresh уже после снятия паузы
        pool.log_event("provider-switch", actor=actor, result="frozen",
                       detail="боевой у %s (ключ удалён) — автоматика на паузе, жду" % from_provider)
        res.update(detail="автоматика на паузе (FROZEN) — боевой остаётся, "
                          "переключусь после снятия паузы")
        return res
    if os.name != "posix":
        res.update(detail="переключение канала доступно только на сервере (Linux)")
        return res
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _switch_locked(cfg, providers, pool, alerter, from_provider,
                                  host, cur, log, actor, reason, res)
    except apply_mod.ApplyError:
        res.update(detail="агент занят (ротация/обновление?) — переключение "
                          "повторится при следующем обновлении пула")
        return res


def _switch_locked(cfg, providers, pool, alerter, from_provider,
                   host, cur, log, actor, reason, res):
    # кандидаты уже без gone/off/cooldown/чёрного списка и упорядочены стратегией;
    # фильтр по from_provider — страховка (его строки и так удалены либо gone)
    cands = [r for r in selectable_candidates(pool, cfg, host, providers)
             if r["provider"] != from_provider]
    log("переключение с %s (%s): боевой %s, кандидатов %d"
        % (from_provider, reason, host, len(cands)))
    tried = 0
    for row in cands:
        if tried >= MAX_CANDIDATES_PER_CYCLE:
            log("  лимит ≤%d кандидатов/цикл — остальных попробует следующий pool-refresh"
                % MAX_CANDIDATES_PER_CYCLE)
            break
        tried += 1
        pres = _probe(pool, providers, row, host, cfg)
        if pres.get("disqualified") or not pres.get("ok"):
            _cooldown_after_fail(pool, row["uid"], log)
            continue
        try:
            r = apply_mod.apply_candidate(cfg, row, pres, log=log, _locked=True,
                                         pool=pool, requested_by=actor,
                                         selection_source="provider-switch")
        except apply_mod.ApplyError as e:
            pool.bump_fail(row["uid"])
            _cooldown_after_fail(pool, row["uid"], log)
            pool.log_event("provider-switch", actor=actor, to_uid=row["uid"],
                           result="fail", detail=str(e))
            continue
        pool.mark_used(row["uid"])
        pool.clear_cooldown(row["uid"])
        pool.set_egress(r.get("verify"))
        purged = pool.purge_provider(from_provider)      # боевой ушёл — добить остатки
        pool.log_event("provider-switch", actor=actor, from_uid=cur["uid"], to_uid=row["uid"],
                       result="ok",
                       detail="ключ %s удалён: %s -> %s egress=%s cc=%s; строк удалено %d"
                              % (from_provider, host, r["new_ip"], r["verify"]["egress_ip"],
                                 r["verify"]["exit_cc"], purged["deleted"]))
        apply_mod.commit_operation(pool, r)
        alerter.provider_switched(provider=from_provider, old_ip=host, new_ip=r["new_ip"],
                                  uid=row["uid"], egress=r["verify"]["egress_ip"],
                                  cc=r["verify"]["exit_cc"])
        res.update(ok=True, switched=True, uid=row["uid"],
                   detail="боевой переключён: %s -> %s (%s)" % (host, r["new_ip"], row["uid"]))
        return res
    pool.log_event("provider-switch", actor=actor, result="stuck",
                   detail="боевой остаётся у %s: живых кандидатов нет (перебрано %d)"
                          % (from_provider, tried))
    _alert_once(pool, alerter, "provider_switch_stuck",
                provider=from_provider, host=host, tried=tried)
    res.update(detail="живых кандидатов нет (перебрано %d) — боевой остаётся на %s, "
                      "повтор при следующем обновлении пула" % (tried, host))
    return res


# ------------------------------------------------------------------- REPLENISH
def _alert_once(pool, alerter, kind, period=ALERT_DEDUP_SEC, **kw):
    """F7: дедуп писем. no_funds/pool_empty/no_market шлются на каждом ретрае
    аварии — не чаще раза в period на причину (отметка в setting)."""
    key = "alert_last:%s" % kind
    age = age_seconds(pool.get_setting(key))
    if age is not None and age < period:
        return False
    getattr(alerter, kind)(**kw)
    pool.set_setting(key, _now_iso())
    return True


def try_replenish(cfg, providers, pool, alerter, log, actor):
    # ПЕРЕД ПОКУПКОЙ — всегда выбрать из уже купленного пула (жёсткое правило владельца,
    # снос №5): покупаем ТОЛЬКО когда пригодных кандидатов в пуле не осталось. Если ROTATING
    # остановился по лимиту и в пуле ещё есть непроверенные — деньги не тратим, доберём тиком.
    sb = apply_mod.load_json(cfg["singbox_config"])
    dead_host = apply_mod.current_upstream(sb)
    still = selectable_candidates(pool, cfg, dead_host, providers)
    if still:
        log("  REPLENISH: в пуле ещё %d непроверенных кандидатов — сначала пробую их, не покупаю"
            % len(still))
        return {"ok": False, "reason": "в пуле есть %d непроверенных кандидатов — покупка не нужна" % len(still),
                "have_candidates": len(still)}
    prov = providers.get("proxy6")
    if prov is None or not prov.caps.get("buy"):
        _alert_once(pool, alerter, "pool_empty", detail="нет ключа PROXY6 — докупить нечем")
        return {"ok": False, "reason": "нет провайдера с покупкой (PROXY6)"}
    lim = money_mod.limits(cfg)
    # порядок перебора задаёт умная оценка: сначала надёжные страны выхода,
    # страны с низкой репутацией автоматика не берёт вовсе (§6.1, 2026-08-15);
    # выученная стабильность пар добавляет свой бонус (F8)
    wl = money_mod.buy_candidates(cfg, pool=pool)
    period = int(lim["buy_period_days"])
    version = int(lim["buy_version"])
    if not lim.get("buy_enabled"):
        _alert_once(pool, alerter, "no_funds", detail="тумблер покупок buy_enabled=false — купи руками")
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
        _alert_once(pool, alerter, "no_market", detail="проверены страны: %s" % ",".join(wl))
        return {"ok": False, "reason": "нет прокси version=%d в наличии (§10 error 300)" % version}

    log("  REPLENISH: покупаю в %s (в наличии %s), период %d дн" % (pick, avail, period))
    try:
        r = money_mod.plan_and_buy(pool, prov, cfg, country=pick, period=period, count=1,
                                   version=version, server=cfg.get("server"), actor=actor)
    except money_mod.SpendDenied as e:
        _alert_once(pool, alerter, "no_funds", detail=str(e))
        return {"ok": False, "reason": "гейт трат: %s" % e, "denied": True}
    except ProviderError as e:
        if e.code == 400:
            _alert_once(pool, alerter, "no_funds", detail=str(e))
            return {"ok": False, "reason": "денег не хватило (error 400)"}
        if e.code == 105:
            alerter.api_105(detail=str(e))
            return {"ok": False, "reason": "PROXY6 105 (неверный IP)"}
        if e.code == 300:
            _alert_once(pool, alerter, "no_market", detail=str(e))
            return {"ok": False, "reason": "нет в наличии (error 300)"}
        return {"ok": False, "reason": "покупка не удалась: %s" % e}

    # постфактум проверка реальной страны выхода (§6.1) + apply рабочего
    checks = postbuy_check(cfg, pool, providers, r["proxies"], actor, log)
    for uid, res, blocked in checks:
        if blocked or not res.get("ok"):
            continue
        row = pool.get(uid) or dict(uid=uid)
        try:
            ar = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True,
                                          pool=pool, requested_by=actor,
                                          selection_source="replenish")
        except apply_mod.ApplyError as e:
            log("  куплен %s, но apply не прошёл: %s" % (uid, e))
            continue
        pool.mark_used(uid)
        # F8: докупка = уходящий канал пары тоже оборвался в бою
        old_row = _pool_row_by_host(pool, dead_host)
        if old_row is not None:
            pool.learning_record_drop(old_row)
        pool.log_event("replenish", actor=actor, to_uid=uid, result="ok",
                       detail="куплен %s (%s %s, %s), egress=%s cc=%s"
                       % (uid, r["price"], r["currency"], pick, ar["verify"]["egress_ip"],
                          ar["verify"]["exit_cc"]))
        apply_mod.commit_operation(pool, ar)
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
    current_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
    prov = providers.get("proxy6")
    if prov is not None:
        try:
            # keep_hosts: refresh убирает из пула всё, чего провайдер не отдал, —
            # строка боевого канала должна пережить постпокупочный опрос
            pool.refresh({"proxy6": prov}, actor=actor,
                         keep_hosts={current_host} if current_host else None)
        except Exception:
            pass
    out = []
    for pxy in bought:
        uid = "%s:%s" % (pxy["provider"], pxy["ext_id"])
        row = pool.get(uid) or dict(pxy, uid=uid)
        res = _probe(pool, providers, row, current_host, cfg)
        blocked = (res.get("exit_cc") in probe_mod.HARD_BLOCK_CC
                   or str(res.get("disqualified") or "").startswith("blocked-cc"))
        if blocked:
            pool.set_role(uid, "off")
            pool.log_event("buy-postcheck", actor=actor, to_uid=uid, result="blocked-cc",
                           detail="реальный выход cc=%s в жёстком блоке §6.1 -> off" % res.get("exit_cc"))
        out.append((uid, res, blocked))
    return out


# ------------------------------------------------- автопродление «якоря» (§6.3)
# Охват — только текущий боевой. Прежний scope "current+reserve" опирался на роль
# reserve и умер вместе с ней (П9, роли v2): ролей две — auto|off.
DEFAULT_AUTO_PROLONG = {
    "enabled": True,        # тумблер: выключить — и продлевать будем только руками
    "days_before": 3,       # продлевать, когда до конца осталось не больше стольких дней
    "period_days": 30,      # на сколько продлевать за раз (у PROXY6 цена линейна: 4 ₽/сутки)
}


def auto_prolong_cfg(cfg):
    m = dict(DEFAULT_AUTO_PROLONG)
    m.update((cfg or {}).get("auto_prolong") or {})
    return m


def notify_vanished(pool, alerter, log=print, actor="auto"):
    """Письмо о прокси, которые провайдер снял с обслуживания РАНЬШЕ конца аренды.

    Само исчезновение — рутина: pool показывает то, что провайдер отдал, и лишние
    строки убирает молча (решение владельца 22.08). Повод для письма ровно один —
    деньги: за оставшиеся дни уже заплачено, значит с провайдера причитается замена
    или возврат. Очередь ведёт pool (_queue_vanished): постпокупочный refresh зовётся
    без alerter, и без очереди повод бы потерялся вместе с удалённой строкой.
    -> {"notified": n, "seen": m}
    """
    items = pool.take_vanished_pending()
    paid = []
    for item in items:
        days = probe_mod.days_left(item.get("date_end"))
        if days is None or days <= 0:
            continue                     # аренда и так кончилась — это не потеря денег
        paid.append(dict(item, days_left=round(days, 1)))
    if not paid:
        return {"notified": 0, "seen": len(items)}
    detail = "; ".join("%s (%s, оплачено ещё %s дн)"
                       % (x.get("uid"), x.get("host") or "?", x["days_left"]) for x in paid)
    pool.log_event("proxy-vanished", actor=actor, result="paid",
                   detail="провайдер снял %d оплаченных прокси: %s" % (len(paid), detail))
    try:
        alerter.proxy_vanished(items=paid)
    except Exception as e:                # почта не должна ронять обновление пула
        log("  письмо об исчезнувших прокси не ушло: %s" % e)
    return {"notified": len(paid), "seen": len(items)}


def auto_prolong(cfg, providers, pool, alerter, log=print, actor="auto"):
    """Продлить рабочий боевой прокси ДО того, как он истечёт (решение владельца 15.08).

    Зачем вообще: смена IP стоит ровно столько же, сколько продление (4 ₽/сутки),
    но новый адрес — «холодный». Прогретый IP экономит не деньги, а нервы: сервисы
    не требуют перелогинов, капч и подтверждений оплаты. Поэтому здоровый якорь
    продлеваем, а ротация остаётся аварийной мерой, а не расписанием.

    Кого трогаем: только текущий боевой и только если он ЗДОРОВ — мёртвый
    продлевать бессмысленно, его заменит ротация.
    Деньги идут через те же гейты §6.2 (тумблер, потолок цены, суточный лимит, остаток).
    """
    pool.observe_provider_errors(providers, actor=actor)
    ap = auto_prolong_cfg(cfg)
    if not ap.get("enabled"):
        return {"ok": True, "skipped": "автопродление выключено тумблером"}

    current_host = apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"]))
    # include_gone (ревью 1.3.0): после удаления ключа строки провайдера помечены
    # gone, но боевой канал в sing-box живёт — без gone-строк главный C5-случай
    # «продлить боевой нечем» давал молчаливый skip вместо события и письма
    rows = pool.list(include_gone=True)
    targets = [r for r in rows if current_host and r["host"] == current_host]
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
        # C5: адаптер СТРОГО по провайдеру строки. Константа proxy6 при боевом от
        # другого провайдера дёргала бы prolong с ЧУЖИМ ext_id в кабинете PROXY6
        # (ext_id уникален только внутри провайдера). Нет адаптера — событие + алерт,
        # а не молчаливый skip: иначе якорь истечёт незаметно.
        prov = providers.get(row["provider"])
        if prov is None or not prov.caps.get("prolong"):
            log("  автопродление: у боевого %s нет ключа/адаптера провайдера %s — продлить нечем"
                % (uid, row["provider"]))
            pool.log_event("auto-prolong", actor=actor, to_uid=uid, result="no-provider",
                           detail="нет ключа/адаптера %s — продление невозможно" % row["provider"])
            alerter.prolong_failed(uid=uid, days_left=round(days, 1),
                                   reason="нет ключа провайдера %s — боевой истечёт без продления"
                                          % row["provider"])
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
    """Держать запас на случай смерти боевого канала. РЕЗЕРВ БЕРЁМ ИЗ ПУЛА, А НЕ ПОКУПАЕМ:
    если в пуле уже есть пригодные кандидаты (любой страны вне чёрного списка, не важно —
    пробованные или ещё нет), докупать не нужно (жёсткое правило владельца, снос №5 — раньше
    считали только ПРОБОВАННЫЕ резервы и докупали сразу после первой же ротации, хотя пул был
    полон). Покупаем только когда выбирать реально не из чего.
    Best-effort: ошибки/гейты глушим (докупка резерва не должна ронять цикл)."""
    pool.observe_provider_errors(providers, actor=actor)
    try:
        selection = selection_state(pool, cfg)
        if selection["mode"] == SELECTION_MANUAL:
            # В MANUAL допускаются пассивные refresh/probe уже купленного пула и
            # продление самого якоря, но стратегия не покупает ничего проактивно.
            log("  N+1: ручной канал закреплён — автоматическую докупку резерва пропускаю")
            return {"ok": True, "bought": False, "skipped": "manual-selection"}
        sb = apply_mod.load_json(cfg["singbox_config"])
        current = apply_mod.current_upstream(sb)
        have = len(selectable_candidates(pool, cfg, current, providers))
        if have >= min_reserve:
            log("  N+1: в пуле %d пригодных кандидатов (≥%d) — выбираю из пула, не покупаю" % (have, min_reserve))
            return {"ok": True, "have": have, "bought": False}
        lim = money_mod.limits(cfg)
        if not lim.get("buy_enabled"):
            log("  N+1: запас=%d, но покупки выключены — пропускаю" % have)
            return {"ok": False, "have": have, "bought": False}
        log("  N+1: пригодных кандидатов в пуле %d < %d — докупаю в фоне (§6.5)" % (have, min_reserve))
        prov = providers.get("proxy6")
        if prov is None or not prov.caps.get("buy"):
            return {"ok": False, "have": have, "bought": False}
        # порядок стран — умная оценка (репутация выхода + стабильность F8)
        version = int(lim["buy_version"])
        pick = None
        for cc in money_mod.buy_candidates(cfg, pool=pool):
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
    pool.set_setting("rotating_since", None)
    if state_before != EMERGENCY:
        pool.set_setting("emergency_since", _now_iso())
        pool.set_setting("emergency_retry_n", "0")   # F6: backoff с начала (2 мин)
        # авто-вход — не ручной: остаток emergency_manual от прежней ручной аварии
        # сделал бы ЭТУ аварию несгораемой для автоматики (ревью 1.3.0)
        pool.set_setting("emergency_manual", None)
        pool.log_event("emergency", actor=actor, result="on", detail=reason)
        alerter.emergency(reason=reason)             # письмо один раз при входе
    else:
        pool.log_event("emergency", actor=actor, result="retry", detail=reason)
    return ok


def _leave_direct(cfg, pool, alerter, verify, log, actor, state_before=EMERGENCY):
    """Снять прямой выход WAN — ЕДИНЫЙ путь для EMERGENCY и ROTATING (инвариант
    флага): маршрут возвращается в tun0, флаг снимается, счётчики чистятся.
    Письмо recovered — только про аварию: ROTATING входил без письма."""
    emergency_off(cfg, log)
    pool.set_setting("emergency_since", None)
    pool.set_setting("rotating_since", None)
    pool.set_setting("emergency_retry_n", None)
    pool.set_setting("emergency_manual", None)
    if state_before == ROTATING:
        pool.log_event("rotating", actor=actor, result="off",
                       detail="перебор завершён — рабочий выход egress=%s, прямой выход снят"
                              % (verify or {}).get("egress_ip"))
        return
    pool.log_event("emergency", actor=actor, result="off",
                   detail="восстановлен рабочий выход egress=%s" % (verify or {}).get("egress_ip"))
    alerter.recovered(new_ip=apply_mod.current_upstream(apply_mod.load_json(cfg["singbox_config"])),
                      egress=(verify or {}).get("egress_ip"), cc=(verify or {}).get("exit_cc"))


# ------------------------------------------------------------- ручные тумблеры
def set_emergency(cfg, pool, alerter, on, log=print, actor="user"):
    """Ручное вкл/выкл аварийного режима (CLI/панель).

    F7: ручная авария «залипает» — помечается emergency_manual, и автоматика её
    не снимает (раньше снимала на первом же живом egress). Ручное снятие пишет
    в журнал результат verify (приёмка §9 п.7): видно, что реально ожило."""
    if on:
        _enter_emergency(cfg, pool, alerter, "включён вручную", log, actor,
                         pool.get_setting("automat_state") or OK)
        pool.set_setting("emergency_manual", "1")
        return {"ok": True, "state": EMERGENCY}
    emergency_off(cfg, log)
    pool.set_setting("automat_state", OK)
    pool.set_setting("emergency_since", None)
    pool.set_setting("emergency_manual", None)
    pool.set_setting("emergency_retry_n", None)
    v = None
    if os.name == "posix":
        v = apply_mod.verify_egress()
        pool.set_egress(v)
    detail = "выключен вручную"
    if v is not None:
        detail += "; verify: " + ("egress=%s cc=%s ok" % (v["egress_ip"], v["exit_cc"])
                                  if v["ok"] else "ПРОВАЛ (%s)" % v["why"])
    pool.log_event("emergency", actor=actor, result="off-manual", detail=detail)
    return {"ok": True, "state": OK, "verify": v}


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
