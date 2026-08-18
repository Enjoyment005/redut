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
import time

import apply as apply_mod
import country as country_mod
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


def rank_candidates(rows, cfg=None):
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
        full, base = probe_mod.score_from_row(r, cfg)
        # при равных очках — кто быстрее по последнему замеру (приёмка №7: под
        # «скорость и отклик» лестница оценки квантует близкие задержки в один балл,
        # и 826 мс стояли в таблице ПОСЛЕ 925 мс просто по порядку вставки)
        lat = probe_mod._rget(r, "latency_ms")
        lat = float(lat) if lat is not None else float("inf")
        if country_first:
            key = (-(cr), -(base if base is not None else 0.0), lat)
        else:
            key = (-(full if full is not None else cr + UNPROBED_SCORE), lat)
        ranked.append((key, r))
    ranked.sort(key=lambda t: t[0])     # только по ключу: равные сохраняют входной порядок
    return [r for _, r in ranked]


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


def _probe(pool, providers, row, current_host, cfg=None):
    res = probe_mod.probe(row, provider_check=_check_cb(providers, row))
    is_cur = (row.get("host") == current_host)
    res["score"] = probe_mod.score(row, res, is_current=is_cur, cfg=cfg)
    if pool.get(row["uid"]):
        pool.record_probe(row["uid"], res, is_current=is_cur,
                          strategy=country_mod.strategy(cfg))
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
    if state_before == EMERGENCY:
        pool.set_setting("emergency_last_retry", _now_iso())
        pool.set_setting("emergency_retry_n",
                         int(pool.get_setting("emergency_retry_n") or 0) + 1)

    # --- ШАГ 1: сеть сервера жива? ---
    alive, via = net_alive(cfg, log)
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
    rt = try_retune(cfg, providers, pool, alerter, log, actor)
    if rt.get("ok"):
        _reset_streaks(pool)
        if in_direct:
            _leave_direct(cfg, pool, alerter, rt.get("verify") or apply_mod.verify_egress(),
                          log, actor, state_before)
        return _state(pool, result, OK, "retune", rt.get("detail", "RETUNE ок"))

    # F1/F2: перед деструктивными шагами отказ должен быть ПОДТВЕРЖДЁН.
    # В EMERGENCY/ROTATING он подтверждён самим состоянием; исход «прокси жив,
    # egress мёртв даже после рестарта» (calm_failed) считается подтверждением
    # после CALM_MAX_STREAK подряд (предохранитель F2 — иначе вечное «успокойся»).
    confirmed = state_before in (EMERGENCY, ROTATING)
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
def try_retune(cfg, providers, pool, alerter, log, actor):
    sb = apply_mod.load_json(cfg["singbox_config"])
    host = apply_mod.current_upstream(sb)
    if not host:
        return {"ok": False, "why": "нет текущего upstream"}
    cur_socks = _outbound_of(sb, "socks-out")
    cur_tg = _outbound_of(sb, "http-tg")
    row = _pool_row_by_host(pool, host) or _row_from_sb(sb, host)
    res = _probe(pool, providers, row, host, cfg)
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
    # Кандидаты уже упорядочены по стране+score (rank_candidates): сначала пробуем
    # надёжные страны (Латвия перед Нигерией), чёрный список выброшен (§6.1, снос №5).
    cands = selectable_candidates(pool, cfg, host, providers)
    if not cands:
        log("  ROTATING: пригодных кандидатов нет (все off/gone/на cooldown/в чёрном списке)")
        return {"ok": False, "exhausted": True}
    tried = 0
    for row in cands:
        if tried >= MAX_CANDIDATES_PER_CYCLE:
            # Остановились по лимиту, но в пуле ещё есть НЕпробованные кандидаты. Это НЕ
            # повод покупать (решение владельца, снос №5): доберём их следующим тиком.
            log("  ROTATING: лимит ≤%d кандидатов/цикл — остальные попробую в следующем цикле"
                % MAX_CANDIDATES_PER_CYCLE)
            return {"ok": False, "exhausted": False, "capped": True,
                    "tried": tried, "total": len(cands)}
        tried += 1
        res = _probe(pool, providers, row, host, cfg)
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
        # F8: уходящий канал этой пары считается «оборвавшимся в бою» — ротация
        # запускается только по мёртвому каналу (ручной apply сюда не попадает)
        old_row = _pool_row_by_host(pool, host)
        if old_row is not None:
            pool.stability_bump_drop(old_row["provider"], old_row.get("country"))
        pool.log_event("rotate", actor=actor, from_uid=None, to_uid=row["uid"], result="ok",
                       detail="%s -> %s egress=%s cc=%s (перебрано %d)"
                       % (host, r["new_ip"], r["verify"]["egress_ip"], r["verify"]["exit_cc"], tried))
        alerter.rotated(old_ip=host, new_ip=r["new_ip"], uid=row["uid"],
                        egress=r["verify"]["egress_ip"], cc=r["verify"]["exit_cc"],
                        tg_code=r["verify"]["tg_code"], score=res.get("score"), candidates_tried=tried)
        return {"ok": True, "uid": row["uid"], "new_ip": r["new_ip"], "verify": r["verify"],
                "detail": "ротация %s -> %s (%s)" % (host, r["new_ip"], row["uid"])}
    # перебрали всех пригодных, никто не прошёл живую пробу (провалившиеся ушли на cooldown) —
    # пул честно исчерпан, только теперь допустима докупка (REPLENISH)
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
            r = apply_mod.apply_candidate(cfg, row, pres, log=log, _locked=True)
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
            ar = apply_mod.apply_candidate(cfg, row, res, log=log, _locked=True)
        except apply_mod.ApplyError as e:
            log("  куплен %s, но apply не прошёл: %s" % (uid, e))
            continue
        pool.mark_used(uid)
        # F8: докупка = уходящий канал пары тоже оборвался в бою
        old_row = _pool_row_by_host(pool, dead_host)
        if old_row is not None:
            pool.stability_bump_drop(old_row["provider"], old_row.get("country"))
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
    try:
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
