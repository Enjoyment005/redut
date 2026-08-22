# -*- coding: utf-8 -*-
"""money.py — политика трат: двойной гейт (тумблер + лимит), идемпотентность
покупки, запись КАЖДОЙ траты в таблицу money (§13) и журнал (§6.2, §15, §19).

Разделение ответственности:
  providers/proxy6.py — КАК потратить (транспорт + предохранители страны/версии);
  money.py           — МОЖНО ли и СКОЛЬКО уже потрачено, и фиксация факта;
  agent.py / webpanel — оркестрация (проба постфактум §6.1, роли, гейты §6.4).

Лимиты — из config['money'] (в бою: /etc/vpn-panel/config.json, root:root 0644,
из веба НЕ правится, §6.2). Локальный дефолт — DEFAULT_LIMITS.

Идемпотентность (§6.2): buy — НЕ идемпотентная операция. Перед покупкой генерим
уникальный descr `vpnbuy-<server>-<ts>-<rnd>`. Оборвался ответ (сеть/таймаут) —
buy НЕ повторяем, а ищем `getproxy?descr=<тот же>`: прокси там => покупка прошла;
нет — можно повторить, но только с НОВЫМ descr. Без этого один таймаут = двойная
покупка.

Оговорка о глобальности лимитов (§16): оба сервера делят общий баланс, но у каждого
своя state.db. Поэтому счётчики «покупок/трат в сутки» считаются по ЛОКАЛЬНОЙ базе
сервера, а по-настоящему глобальный предохранитель — неснижаемый остаток БАЛАНСА
(баланс общий у провайдера), он сверяется по живому getprice.balance перед каждой
тратой. Кросс-серверная агрегация счётчиков — задача Фазы 3/5.
"""
import datetime
import contextlib
import json
import math
import os
import re
import secrets as _secrets
import threading

import country as country_mod
from providers.base import ProviderError, ProviderErrorKind

# Дефолтные рамки трат (§6.2). В бою перекрываются config['money'] на сервере.
# Значения консервативные под текущий баланс PROXY6 (~928 RUB на 2026-08-13).
DEFAULT_LIMITS = {
    "buy_enabled": True,       # тумблер покупок (выкл = только алерт «купи руками»)
    "delete_enabled": False,   # тумблер удаления (§6.4; по умолчанию ВЫКЛ)
    "max_buys_per_day": 3,     # ≤3 покупки/сутки
    "max_spend_per_day": 300.0,   # ≤N ₽/сутки
    "max_price_per_buy": 150.0,   # ≤M ₽/покупка (сверяем getprice ДО buy)
    "min_balance_reserve": 300.0,  # неснижаемый остаток баланса
    "buy_period_days": 7,      # период покупки в аварии (дёшево; потом prolong на 30)
    "buy_version": 4,          # только IPv4 (§2.2)
    "currency": "RUB",         # валюта PROXY6
}


class SpendDenied(Exception):
    """Гейт трат отказал (тумблер / лимит / баланс / страна). Это НЕ ошибка API —
    отличается от ProviderError, чтобы вызывающий показал причину, а не «провайдер лёг»."""


# --- Обучение стабильности (F8, П6): история -> решения о покупке -----------------
# Порог обучения — не календарный, а по ОБЪЁМУ данных: до min_probes/min_days вклад
# нулевой (незнание не наказываем и не награждаем), полный вес — к full_probes/full_days.
# Скачок на пороге мал по построению (maturity на пороге ≈ 0.1 -> бонус ≤ ±2 балла).
# Правятся по SSH через config['stability'] — как денежные лимиты.
DEFAULT_STABILITY = {
    "min_probes": 300,     # вклад начинается с этого объёма проб по паре
    "min_days": 21,        # ...и возраста пары в днях
    "full_probes": 1000,   # полный вес maturity
    "full_days": 60,
    "beta_prior": 5.0,     # β-сглаживание к 0.5: (ok+prior)/(total+2*prior)
    "bonus_scale": 40.0,   # 40*(reliability-0.5)*maturity
    "drop_penalty": 5.0,   # −5*min(drop_rate, drop_cap)
    "drop_cap": 2.0,       # обрывов в час боя, больше не наказываем
    "bonus_cap": 20.0,     # clamp ±20
}


def stability_cfg(cfg):
    """Нормализованные безопасные параметры обучения.

    Файл правится по SSH, поэтому опечатка не должна уронить покупки/панель
    делением на ноль, NaN или ``int('oops')``. Некорректное поле откатывается к
    дефолту, диапазоны зажимаются, full-порог не может быть ниже min-порога.
    """
    raw = (cfg or {}).get("stability") or {}
    if not isinstance(raw, dict):
        raw = {}

    def number(key, integer=False, minimum=0.0):
        try:
            value = float(raw.get(key, DEFAULT_STABILITY[key]))
        except (TypeError, ValueError):
            value = float(DEFAULT_STABILITY[key])
        if not math.isfinite(value):
            value = float(DEFAULT_STABILITY[key])
        value = max(float(minimum), value)
        return int(value) if integer else value

    min_probes = number("min_probes", integer=True, minimum=1)
    min_days = number("min_days", minimum=0)
    return {
        "min_probes": min_probes,
        "min_days": min_days,
        "full_probes": max(min_probes, number("full_probes", integer=True, minimum=1)),
        "full_days": max(min_days, number("full_days", minimum=1)),
        "beta_prior": number("beta_prior", minimum=0.01),
        "bonus_scale": number("bonus_scale", minimum=0),
        "drop_penalty": number("drop_penalty", minimum=0),
        "drop_cap": number("drop_cap", minimum=0),
        "bonus_cap": number("bonus_cap", minimum=0),
    }


def _days_seen(agg, now=None):
    fs = (agg or {}).get("first_seen")
    if not fs:
        return 0.0
    try:
        dt = datetime.datetime.fromisoformat(str(fs).replace(" ", "T"))
    except ValueError:
        return 0.0
    return max(0.0, ((now or datetime.datetime.now()) - dt).total_seconds() / 86400.0)


def stability_mature(agg, cfg=None, now=None):
    """Достаточно ли данных, чтобы пара (provider, страна) влияла на покупку."""
    if not agg:
        return False
    sc = stability_cfg(cfg)
    total = int(agg.get("probes_ok") or 0) + int(agg.get("probes_fail") or 0)
    return total >= int(sc["min_probes"]) and _days_seen(agg, now) >= float(sc["min_days"])


def stability_bonus(agg, cfg=None, now=None):
    """F8: бонус пары (provider, паспортная страна) к рейтингу страны при покупке.

    reliability = (ok+prior)/(total+2*prior)   — β-сглаживание: малые выборки не кричат
    drop_rate   = drops / max(battle_seconds/3600, 1)  — обрывов в час боя
    maturity    = min(1, total/full_probes) * min(1, days/full_days)
    bonus       = clamp(scale*(reliability-0.5)*maturity − penalty*min(drop_rate, cap), ±bonus_cap)
    До порога обучения — ровно 0. В оценку живых проб (probe.score) бонус НЕ идёт:
    живой замер лучше любой истории."""
    if not stability_mature(agg, cfg, now):
        return 0.0
    sc = stability_cfg(cfg)
    ok = int(agg.get("probes_ok") or 0)
    total = ok + int(agg.get("probes_fail") or 0)
    prior = float(sc["beta_prior"])
    reliability = (ok + prior) / (total + 2 * prior)
    hours = max(int(agg.get("battle_seconds") or 0) / 3600.0, 1.0)
    drop_rate = int(agg.get("battle_drops") or 0) / hours
    maturity = (min(1.0, total / float(sc["full_probes"]))
                * min(1.0, _days_seen(agg, now) / float(sc["full_days"])))
    bonus = (float(sc["bonus_scale"]) * (reliability - 0.5) * maturity
             - float(sc["drop_penalty"]) * min(drop_rate, float(sc["drop_cap"])))
    cap = float(sc["bonus_cap"])
    return round(max(-cap, min(cap, bonus)), 2)


# ------------------------------------------------------------------- настройки
def limits(cfg):
    m = dict(DEFAULT_LIMITS)
    m.update((cfg or {}).get("money") or {})
    return m


# A purchase/prolong call crosses SQLite and a remote, non-idempotent API.  The
# daily-limit read and the provider mutation therefore have to be one serialized
# critical section on a node.  The thread lock covers the panel's concurrent HTTP
# handlers (and Windows tests); flock covers independent panel/cron processes on
# the Linux node and is released automatically after kill/reboot.
_SPEND_LOCKS = {}
_SPEND_LOCKS_GUARD = threading.Lock()
# Volatile proof that a committed result reached the return boundary in this
# process.  It intentionally disappears on kill/reboot: then SQLite result_json
# is replayed instead of risking a second remote mutation.
_DELIVERED_SPEND_OPS = set()


@contextlib.contextmanager
def _spend_lock(pool):
    path = os.path.abspath(str(getattr(pool, "db_path", "state.db"))) + ".spend.lock"
    with _SPEND_LOCKS_GUARD:
        thread_lock = _SPEND_LOCKS.setdefault(path, threading.Lock())
    if not thread_lock.acquire(False):
        raise SpendDenied("другая операция покупки/продления уже выполняется на этом узле")
    fh = None
    try:
        if os.name == "posix":
            import fcntl
            try:
                fh = open(path, "a", encoding="ascii")
            except OSError as error:
                raise SpendDenied(
                    "не удалось взять безопасный лок операции трат: %s" % error) from error
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.close()
                fh = None
                raise SpendDenied(
                    "другая операция покупки/продления уже выполняется на этом узле")
        yield
    finally:
        if fh is not None:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()
        thread_lock.release()


def rank_countries(available, cfg, pool=None, provider="proxy6"):
    """«Что в продаже» глазами ЧЕЛОВЕКА: всё, кроме чёрного списка.

    Белого списка больше нет (приёмка №7): человек вручную может купить любую
    страну из продажи. Сортировка — внутренним рейтингом системы (репутация +
    выученная стабильность F8), при равном рейтинге ближние к РФ первыми
    (providers.base.DEFAULT_COUNTRY_ORDER). Никакого auto-гейта: он только
    для автоматики (см. buy_candidates)."""
    from providers.base import DEFAULT_COUNTRY_ORDER
    order = {c: i for i, c in enumerate(DEFAULT_COUNTRY_ORDER)}
    out = []
    for cc in {country_mod.norm(x) for x in (available or [])}:
        if not cc:
            continue
        r = country_mod.rating(cc, True, cfg)
        if r is None:
            continue                    # чёрный список — единственный фильтр
        b = 0.0
        if pool is not None:
            b = stability_bonus(pool.stability_get(provider, cc), cfg)
        out.append((-(r + b), order.get(cc, len(order)), cc))
    return [c for _, _, c in sorted(out)]


def buy_candidates(cfg, available=None, pool=None, provider="proxy6"):
    """Порядок перебора стран при АВТО-покупке.

    Кандидаты — внутренний порядок предпочтения системы (ближние к РФ первыми,
    providers.base.DEFAULT_COUNTRY_ORDER) плюс страны провайдера, пересортированные
    умной оценкой. Страны с оценкой ниже порога автоматика сама не покупает — их
    берут только по явной просьбе человека (rank_countries + POST /api/buy).

    pool (F8): при переданном пуле к рейтингу страны добавляется бонус выученной
    стабильности пары (provider, страна). Приоритеты не переопределяются: чёрный
    список (rating is None) отсекается ДО бонуса, auto_allowed бонусом не обходится.
    """
    pref = country_mod.preference_order(cfg)
    rest = [c for c in (available or []) if c not in pref]
    out = []
    for i, cc in enumerate(list(pref) + list(rest)):
        c = country_mod.norm(cc)
        r = country_mod.rating(c, True, cfg)
        if r is None:
            continue                    # чёрный список — до и вне бонуса
        b = 0.0
        if pool is not None:
            b = stability_bonus(pool.stability_get(provider, c), cfg)
        out.append((-(r + b), i, c))
    ranked = [c for _, _, c in sorted(out)]
    return [c for c in ranked if country_mod.auto_allowed(c, True, cfg)]


def _num(v):
    try:
        value = float(v)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _currency(v):
    value = str(v or "").strip().upper()
    return value if re.fullmatch(r"[A-Z]{3}", value) else None


_SRV_RE = re.compile(r"[^A-Za-z0-9]")


def gen_descr(server, now=None):
    """Уникальный идемпотентный тег покупки vpnbuy-<server>-<ts>-<rnd> (≤50, §6.2)."""
    now = now or datetime.datetime.now()
    srv = _SRV_RE.sub("", str(server or "srv"))[:12] or "srv"
    d = "vpnbuy-%s-%s-%s" % (srv, now.strftime("%Y%m%dT%H%M%S"), _secrets.token_hex(2)[:3])
    return d[:50]


def _safe_spent_today(pool, currency):
    """Ledger — часть safety boundary: любая semantic corruption закрывает траты."""
    try:
        spent = _num(pool.spent_today(currency))
    except Exception as error:
        raise SpendDenied("денежный ledger повреждён — траты заблокированы: %s" % error) from error
    if spent is None or spent < 0:
        raise SpendDenied("денежный ledger содержит некорректный агрегат — траты заблокированы")
    return spent


def _charge_from_response(quote_price, expected_currency, resp):
    """Провайдер уже мутирован: учитываем не меньше доверенной preflight-цены."""
    quote = _num(quote_price)
    if quote is None or quote <= 0:
        raise SpendDenied("долговечный intent содержит некорректную цену")
    response_price = _num((resp or {}).get("price"))
    response_currency = _currency((resp or {}).get("currency"))
    discrepancy = []
    if response_currency != expected_currency:
        discrepancy.append("currency")
    if response_price is None or response_price <= 0:
        discrepancy.append("price")
    charged = quote
    if response_currency == expected_currency and response_price is not None and response_price > 0:
        charged = max(quote, response_price)
    return charged, expected_currency, discrepancy


def _valid_proxies(items, provider_name=None):
    out = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict) or item.get("ext_id") in (None, ""):
            continue
        value = dict(item)
        value["provider"] = str(value.get("provider") or provider_name or "")
        if not value["provider"]:
            continue
        if provider_name and value["provider"] != provider_name:
            continue
        value["ext_id"] = str(value["ext_id"])
        out.append(value)
    return out


def _date_value(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(str(value).replace(" ", "T"))
    except (TypeError, ValueError, OverflowError):
        return None


def _ledger_rows_for_buy(op, proxies, price, response):
    count = len(proxies)
    if count < 1:
        raise SpendDenied("покупка не вернула подтверждённых proxy id")
    each = round(price / count, 8)
    amounts = [each] * count
    amounts[-1] = price - sum(amounts[:-1])
    if any(_num(value) is None or value <= 0 for value in amounts):
        raise SpendDenied("цена покупки не делится на подтверждённые proxy id")
    return [{"provider": proxy["provider"], "op": "buy",
             "uid": "%s:%s" % (proxy["provider"], proxy["ext_id"]),
             "price": amount, "currency": op["currency"],
             "balance_after": (response or {}).get("balance"),
             "order_id": (response or {}).get("order_id"), "descr": op.get("descr")}
            for proxy, amount in zip(proxies, amounts)]


def _finalize_buy(pool, op, proxies, response, *, actor, src_ip, recovered):
    price, currency, discrepancy = _charge_from_response(
        op["quote_price"], op["currency"], response)
    rows = _ledger_rows_for_buy(op, proxies, price, response)
    uids = [row["uid"] for row in rows]
    request = op.get("request") or {}
    result = "recovered" if recovered else "ok"
    output = {"ok": True, "recovered": recovered, "proxies": proxies, "price": price,
              "currency": currency, "descr": op.get("descr"),
              "order_id": (response or {}).get("order_id"),
              "balance_after": (response or {}).get("balance"),
              "period": request.get("period"), "country": request.get("country"),
              "response_discrepancy": discrepancy, "spend_operation_id": op["id"]}
    pool.complete_spend_operation(op["id"], rows, result=output)
    pool.log_event(
        "buy", actor=actor, result=result, src_ip=src_ip,
        detail=json.dumps({"country": request.get("country"),
                           "period": request.get("period"), "count": len(proxies),
                           "price": price, "currency": currency,
                           "balance_after": (response or {}).get("balance"),
                           "descr": op.get("descr"), "uids": uids,
                           "response_discrepancy": discrepancy}, ensure_ascii=False))
    _DELIVERED_SPEND_OPS.add(op["id"])
    return output


def _recover_buy(pool, op, provider, *, actor="auto", src_ip=""):
    if not op.get("descr") or op.get("request_invalid"):
        raise SpendDenied("незавершённая покупка повреждена — новая трата заблокирована")
    try:
        found = _valid_proxies(provider.find_by_descr(op["descr"]), op["provider"])
    except (ProviderError, OSError):
        found = []
    expected_count = int((op.get("request") or {}).get("count") or 0)
    if not found or expected_count < 1 or len(found) != expected_count:
        pool.log_event("buy", actor=actor, result="unconfirmed", src_ip=src_ip,
                       detail="покупка НЕ подтверждена; durable intent сохраняется (descr=%s)"
                       % op["descr"])
        raise SpendDenied(
            "предыдущая покупка descr=%s НЕ подтверждена; новая трата заблокирована"
            % op["descr"])
    response = {"price": op["quote_price"], "currency": op["currency"],
                "balance": None, "order_id": None}
    return _finalize_buy(pool, op, found, response, actor=actor,
                         src_ip=src_ip, recovered=True)


def _find_remote_proxy(provider, ext_id):
    try:
        rows = provider.list()
    except (ProviderError, OSError):
        return None
    for item in rows or []:
        if isinstance(item, dict) and str(item.get("ext_id")) == str(ext_id):
            return item
    return None


def _finalize_prolong(pool, op, response, new_end, *, actor, src_ip, recovered):
    price, currency, discrepancy = _charge_from_response(
        op["quote_price"], op["currency"], response)
    request = op.get("request") or {}
    row = {"provider": op["provider"], "op": "prolong", "uid": op.get("uid"),
           "price": price, "currency": currency,
           "balance_after": (response or {}).get("balance"),
           "order_id": (response or {}).get("order_id"), "descr": op.get("descr")}
    updates = [(op.get("uid"), str(new_end).replace(" ", "T"))] if new_end else []
    result = "recovered" if recovered else "ok"
    output = {"ok": True, "recovered": recovered, "uid": op.get("uid"),
              "days": request.get("days"), "price": price, "currency": currency,
              "balance_after": (response or {}).get("balance"), "date_end": new_end,
              "response_discrepancy": discrepancy, "spend_operation_id": op["id"]}
    pool.complete_spend_operation(
        op["id"], [row], date_updates=updates, result=output)
    pool.log_event(
        "prolong", actor=actor, to_uid=op.get("uid"), result=result, src_ip=src_ip,
        detail=json.dumps({"days": request.get("days"), "price": price,
                           "currency": currency,
                           "balance_after": (response or {}).get("balance"),
                           "date_end": new_end,
                           "response_discrepancy": discrepancy}, ensure_ascii=False))
    _DELIVERED_SPEND_OPS.add(op["id"])
    return output


def _recover_prolong(pool, op, provider, *, actor="auto", src_ip=""):
    request = op.get("request") or {}
    before = _date_value(request.get("date_before"))
    remote = _find_remote_proxy(provider, request.get("ext_id"))
    after = _date_value((remote or {}).get("date_end"))
    if before is None or after is None or after <= before:
        pool.log_event("prolong", actor=actor, to_uid=op.get("uid"),
                       result="unconfirmed", src_ip=src_ip,
                       detail="продление НЕ подтверждено; durable intent сохраняется")
        raise SpendDenied(
            "предыдущее продление %s остаётся неподтверждённым; новая трата заблокирована"
            % (op.get("uid") or request.get("ext_id")))
    response = {"price": op["quote_price"], "currency": op["currency"],
                "balance": None, "order_id": None}
    return _finalize_prolong(pool, op, response, (remote or {}).get("date_end"),
                             actor=actor, src_ip=src_ip, recovered=True)


def _reconcile_pending_locked(pool, providers, *, actor="auto", src_ip="",
                              replay_committed=True, expected_kind=None):
    results = []
    if replay_committed:
        for op in pool.unacknowledged_spend_operations():
            if op["id"] in _DELIVERED_SPEND_OPS:
                pool.acknowledge_spend_operation(op["id"])
                _DELIVERED_SPEND_OPS.discard(op["id"])
                continue
            if expected_kind and op.get("kind") != expected_kind:
                raise SpendDenied(
                    "committed результат %s ожидает возврата через соответствующую операцию; "
                    "%s пока заблокирована" % (op.get("kind"), expected_kind))
            if op.get("result_invalid") or not isinstance(op.get("result"), dict):
                raise SpendDenied(
                    "committed результат денежной операции повреждён — новая трата заблокирована")
            replay = dict(op["result"])
            replay["recovered"] = True
            replay["replayed_committed"] = True
            pool.log_event("spend-replay", actor=actor, result="recovered", src_ip=src_ip,
                           detail="committed результат воспроизведён без вызова провайдера")
            _DELIVERED_SPEND_OPS.add(op["id"])
            return [replay]
    for op in pool.pending_spend_operations():
        if op["phase"] == "planned":
            pool.transition_spend_operation(op["id"], "failed",
                                            "abandoned before provider submission")
            continue
        provider = (providers or {}).get(op["provider"])
        if provider is None:
            raise SpendDenied("нет адаптера для восстановления незавершённой траты %s"
                              % op["provider"])
        if op["kind"] == "buy":
            result = _recover_buy(pool, op, provider, actor=actor, src_ip=src_ip)
        elif op["kind"] == "prolong":
            result = _recover_prolong(pool, op, provider, actor=actor, src_ip=src_ip)
        else:
            raise SpendDenied("неизвестная незавершённая денежная операция")
        if expected_kind and op["kind"] != expected_kind:
            _DELIVERED_SPEND_OPS.discard(result.get("spend_operation_id"))
            raise SpendDenied(
                "предыдущая операция %s восстановлена, но её результат ожидает "
                "соответствующего вызова; %s пока заблокирована"
                % (op["kind"], expected_kind))
        results.append(result)
    return results


def reconcile_pending_spend(pool, providers, *, actor="auto", src_ip=""):
    """Read-only remote reconciliation + local atomic commit after restart."""
    with _spend_lock(pool):
        results = _reconcile_pending_locked(pool, providers, actor=actor, src_ip=src_ip,
                                            replay_committed=False)
        # Startup observer did not deliver these values to the money caller.
        for result in results:
            _DELIVERED_SPEND_OPS.discard(result.get("spend_operation_id"))
        return results


# --------------------------------------------------------------------- покупка
def preflight_buy(pool, provider, cfg, *, country, period=None, count=1, version=None,
                  auto=True):
    """Все гейты §6.2 ДО траты. -> dict(price, currency, balance_before, period,
    version, count, country). Отказ -> SpendDenied (ничего не потрачено).

    `auto=True` — покупает автоматика: разрешены только страны с оценкой не ниже
    порога (country.MIN_AUTO_RATING). `auto=False` — человек выбрал страну руками:
    пропускаем всё, кроме чёрного списка, но причину пишем в журнал вызывающего.
    """
    lim = limits(cfg)
    period = int(period or lim["buy_period_days"])
    version = int(version if version is not None else lim["buy_version"])
    count = int(count)
    currency = _currency(lim["currency"])
    country = (country or "").strip().lower()

    # ГЕЙТ 1 — тумблер (§6.2)
    if not lim["buy_enabled"]:
        raise SpendDenied("покупки выключены тумблером buy_enabled — только алерт «купи руками» (§6.2)")
    if currency is None:
        raise SpendDenied("валюта денежного лимита некорректна — покупка отменена")
    if count < 1 or period < 1 or period > 365:
        raise SpendDenied("count/period покупки вне безопасного диапазона")
    # ГЕЙТ СТРАНЫ (§6.1, с 2026-08-15): чёрный список — всегда «нет»; остальное —
    # по умной оценке, и только для автоматики (человеку хватает чёрного списка).
    if not country:
        raise SpendDenied("страна покупки не задана")
    if country_mod.is_blocked(country, cfg):
        raise SpendDenied("страна %r в чёрном списке — не покупаем никогда (§6.1)" % country)
    if auto and not country_mod.auto_allowed(country, True, cfg):
        raise SpendDenied("страна %r с низкой оценкой (%s) — автоматика её не покупает; "
                          "купить можно вручную из панели (§6.1)"
                          % (country, country_mod.explain(country)))
    # ГЕЙТ 2 — ≤3 покупки/сутки
    buys = pool.buys_today()
    if buys >= lim["max_buys_per_day"]:
        raise SpendDenied("лимит покупок в сутки исчерпан: %d/%d (§6.2)" % (buys, lim["max_buys_per_day"]))

    # getprice ДО buy (§6.2)
    pr = provider.getprice(count, period, version)
    price = _num(pr.get("price"))
    bal_before = _num(pr.get("balance"))
    quoted_currency = _currency(pr.get("currency"))
    if price is None or price <= 0:
        raise SpendDenied("getprice вернул некорректную цену %r — покупка отменена" % pr.get("price"))
    if quoted_currency != currency:
        raise SpendDenied("getprice вернул валюту %r вместо %s — покупка отменена"
                          % (pr.get("currency"), currency))
    if bal_before is None or bal_before < 0:
        raise SpendDenied("getprice вернул некорректный остаток %r — покупка отменена"
                          % pr.get("balance"))
    # ГЕЙТ 3 — цена одной покупки ≤ M
    if price > lim["max_price_per_buy"]:
        raise SpendDenied("цена %.2f %s > лимита %.2f/покупка (§6.2)"
                          % (price, currency, lim["max_price_per_buy"]))
    # ГЕЙТ 4 — траты за сутки + эта ≤ N
    spent = _safe_spent_today(pool, currency)
    if spent + price > lim["max_spend_per_day"]:
        raise SpendDenied("суточный лимит трат: %.2f + %.2f > %.2f %s (§6.2)"
                          % (spent, price, lim["max_spend_per_day"], currency))
    # ГЕЙТ 5 — неснижаемый остаток баланса (глобальный предохранитель, баланс общий)
    if bal_before is not None and (bal_before - price) < lim["min_balance_reserve"]:
        raise SpendDenied("баланс %.2f − %.2f < неснижаемого остатка %.2f %s (§6.2)"
                          % (bal_before, price, lim["min_balance_reserve"], currency))
    return {"price": price, "currency": currency, "balance_before": bal_before,
            "period": period, "version": version, "count": count,
            "country": country}


def plan_and_buy(pool, provider, cfg, *, country, period=None, count=1, version=None,
                 server=None, actor="auto", src_ip="", auto=True):
    """Гейты §6.2 -> идемпотентная покупка -> запись в money+журнал.

    ВАЖНО: постфактум-проба на реальную страну выхода (§6.1) — на вызывающем
    (agent/webpanel): здесь прокси только куплен и записан, но ещё НЕ одобрен.
    Возврат: dict(ok, recovered, proxies, price, currency, descr, order_id,
                  balance_after, period, country). Отказ гейта -> SpendDenied.

    `auto` — покупает автоматика (True) или человек руками из панели (False);
    от этого зависит, пускать ли страну с низкой оценкой (см. preflight_buy).
    """
    with _spend_lock(pool):
        return _plan_and_buy_locked(
            pool, provider, cfg, country=country, period=period, count=count,
            version=version, server=server, actor=actor, src_ip=src_ip, auto=auto)


def _plan_and_buy_locked(pool, provider, cfg, *, country, period=None, count=1,
                         version=None, server=None, actor="auto", src_ip="", auto=True):
    pname = str(getattr(provider, "name", "") or "")
    recovered = _reconcile_pending_locked(
        pool, {pname: provider}, actor=actor, src_ip=src_ip, expected_kind="buy")
    if recovered:
        # Один пользовательский вызов не превращается в две покупки: сначала
        # возвращаем результат прежнего durable intent.
        return recovered[0]
    pre = preflight_buy(pool, provider, cfg, country=country, period=period,
                        count=count, version=version, auto=auto)
    server = server or (cfg or {}).get("server") or "srv"
    descr = gen_descr(server)
    request = {"count": pre["count"], "period": pre["period"],
               "country": pre["country"], "version": pre["version"]}
    op, created = pool.begin_spend_operation(
        "buy", pname, request, "buy:%s" % descr, descr=descr,
        quote_price=pre["price"], currency=pre["currency"],
        balance_before=pre["balance_before"])
    if not created:
        raise SpendDenied("другая незавершённая денежная операция блокирует покупку")
    pool.transition_spend_operation(op["id"], "submitted")
    op = pool.get_spend_operation(op["id"])
    try:
        # allow_cc=None: страну уже одобрили гейты выше (чёрный список + оценка).
        # Слой провайдера всё равно перепроверит чёрный список независимо.
        resp = provider.buy(pre["count"], pre["period"], pre["country"],
                            version=pre["version"], descr=descr, allow_cc=None)
    except ProviderError as e:
        ambiguous = (getattr(e, "network", False)
                     or getattr(e, "kind", None) == ProviderErrorKind.PROTOCOL)
        if not ambiguous:
            pool.transition_spend_operation(op["id"], "failed", str(e))
            raise
        # Сеть оборвалась. buy НЕ повторяем — проверяем, не прошла ли она (§6.2).
        try:
            return _recover_buy(pool, op, provider, actor=actor, src_ip=src_ip)
        except ProviderError:
            # Защитный fallback для нестандартного адаптера; intent остаётся submitted.
            pass
        pool.log_event("buy", actor=actor, result="unconfirmed", src_ip=src_ip,
                       detail="сеть оборвалась, durable intent не подтверждён (descr=%s)" % descr)
        raise SpendDenied(
            "покупка НЕ подтверждена (descr=%s); durable intent блокирует повтор (§6.2)"
            % descr)

    proxies = _valid_proxies((resp or {}).get("proxies"), pname)
    if not proxies or len(proxies) != pre["count"]:
        pool.log_event("buy", actor=actor, result="unconfirmed", src_ip=src_ip,
                       detail="ответ buy не содержит подтверждённых proxy id; intent сохранён")
        raise SpendDenied("ответ buy не подтверждает купленные proxy id; повтор заблокирован")
    return _finalize_buy(pool, op, proxies, resp, actor=actor,
                         src_ip=src_ip, recovered=False)


# ------------------------------------------------------------------- продление
def prolong_with_limits(pool, provider, cfg, *, row, days, actor="auto", src_ip=""):
    """Продлить один прокси на days (§6.3) под гейтами трат + запись в money.

    row — запись пула (provider, ext_id, uid, descr). Для PROXY6 сверяем цену
    через getprice ДО траты; у ProxyLine getprice нет — гейтим тумблером и пишем
    цену из ответа /renew/ (валюта USD)."""
    with _spend_lock(pool):
        return _prolong_with_limits_locked(
            pool, provider, cfg, row=row, days=days, actor=actor, src_ip=src_ip)


def _prolong_with_limits_locked(pool, provider, cfg, *, row, days,
                                actor="auto", src_ip=""):
    lim = limits(cfg)
    days = int(days)
    if not (1 <= days <= 365):
        raise SpendDenied("period=%d вне 1..365 дней" % days)
    if not lim["buy_enabled"]:
        raise SpendDenied("траты выключены тумблером buy_enabled — продление недоступно (§6.2)")

    pname, ext_id, uid = row["provider"], row["ext_id"], row["uid"]
    # Пояс безопасности (ревью 1.3.0): адаптер обязан совпадать с провайдером строки —
    # ext_id уникален только внутри провайдера, чужой адаптер продлил бы чужой прокси.
    if getattr(provider, "name", None) != pname:
        raise SpendDenied("адаптер %r не совпадает с провайдером строки %r — продление отклонено"
                          % (getattr(provider, "name", None), pname))
    recovered = _reconcile_pending_locked(
        pool, {pname: provider}, actor=actor, src_ip=src_ip, expected_kind="prolong")
    if recovered:
        return recovered[0]
    price = None
    bal = None
    currency = _currency(lim["currency"] if pname == "proxy6" else "USD")
    if currency is None:
        raise SpendDenied("валюта денежного лимита некорректна — продление отменено")
    if pname == "proxy6":
        pr = provider.getprice(1, days, int(lim["buy_version"]))
        price = _num(pr.get("price"))
        bal = _num(pr.get("balance"))
        quoted_currency = _currency(pr.get("currency"))
        if price is None or price <= 0:
            raise SpendDenied("getprice вернул некорректную цену продления %r"
                              % pr.get("price"))
        if quoted_currency != currency:
            raise SpendDenied("getprice вернул валюту %r вместо %s — продление отменено"
                              % (pr.get("currency"), currency))
        if bal is None or bal < 0:
            raise SpendDenied("getprice вернул некорректный остаток %r — продление отменено"
                              % pr.get("balance"))
        if price > lim["max_price_per_buy"]:
            raise SpendDenied("цена продления %.2f %s > лимита %.2f/покупка (§6.2)"
                              % (price, currency, lim["max_price_per_buy"]))
        if _safe_spent_today(pool, currency) + price > lim["max_spend_per_day"]:
            raise SpendDenied("суточный лимит трат превышен продлением (§6.2)")
        if (bal - price) < lim["min_balance_reserve"]:
            raise SpendDenied("продление опустит баланс ниже неснижаемого остатка (§6.2)")
    else:
        # У ProxyLine нет доверенной preflight-цены: резервируем верхний лимит,
        # чтобы malformed ответ не превратил продление в бесплатное для ledger.
        price = _num(lim["max_price_per_buy"])
        if price is None or price <= 0:
            raise SpendDenied("max_price_per_buy некорректен — продление отменено")
        if _safe_spent_today(pool, currency) + price > lim["max_spend_per_day"]:
            raise SpendDenied("суточный лимит трат превышен продлением (§6.2)")

    date_before = row.get("date_end")
    if _date_value(date_before) is None:
        remote_before = _find_remote_proxy(provider, ext_id)
        date_before = (remote_before or {}).get("date_end")
    if _date_value(date_before) is None:
        raise SpendDenied("не удалось зафиксировать date_end до продления — трата отменена")

    request = {"ext_id": str(ext_id), "days": days,
               "date_before": str(date_before).replace(" ", "T")}
    idem = "prolong:%s:%s" % (uid, _secrets.token_hex(8))
    op, created = pool.begin_spend_operation(
        "prolong", pname, request, idem, uid=uid, descr=row.get("descr"),
        quote_price=price, currency=currency, balance_before=bal)
    if not created:
        raise SpendDenied("другая незавершённая денежная операция блокирует продление")
    pool.transition_spend_operation(op["id"], "submitted")
    op = pool.get_spend_operation(op["id"])
    try:
        resp = provider.prolong(ext_id, days)
    except ProviderError as error:
        ambiguous = (getattr(error, "network", False)
                     or getattr(error, "kind", None) == ProviderErrorKind.PROTOCOL)
        if not ambiguous:
            pool.transition_spend_operation(op["id"], "failed", str(error))
            raise
        return _recover_prolong(pool, op, provider, actor=actor, src_ip=src_ip)

    new_end = None
    if pname == "proxy6":
        proxy_map = (resp or {}).get("proxies")
        if isinstance(proxy_map, dict):
            target = proxy_map.get(str(ext_id)) or {}
            new_end = target.get("date_end") if isinstance(target, dict) else None
        if (_date_value(new_end) is None
                or _date_value(new_end) <= _date_value(date_before)):
            pool.log_event("prolong", actor=actor, to_uid=uid, result="unconfirmed",
                           src_ip=src_ip,
                           detail="ответ prolong не подтверждает новый date_end; intent сохранён")
            raise SpendDenied("ответ prolong не подтверждает новый date_end; повтор заблокирован")
    else:
        acknowledged = (resp or {}).get("proxies")
        if not isinstance(acknowledged, (list, tuple, set)) or str(ext_id) not in {
                str(value) for value in acknowledged}:
            pool.log_event("prolong", actor=actor, to_uid=uid, result="unconfirmed",
                           src_ip=src_ip,
                           detail="ответ prolong не подтверждает proxy id; intent сохранён")
            raise SpendDenied("ответ prolong не подтверждает proxy id; повтор заблокирован")
    return _finalize_prolong(pool, op, resp, new_end, actor=actor,
                             src_ip=src_ip, recovered=False)


# -------------------------------------------------------------------- удаление
def can_delete(row, cfg, *, current_host=None, provider_check=None, min_fail=2):
    """§6.4: удаляем ТОЛЬКО если выполнены ВСЕ условия. -> (ok: bool, reason: str).

    provider_check — результат check?ids= провайдера (True|False|None). Требуется
    именно False (труп подтверждён провайдером); True/None не проходят.
    Ролевого гейта больше нет (П9, роли v2): ролей две, off/auto оба удаляемы —
    человек в панели хозяин; остаются гейты «не боевой», провалы и check."""
    lim = limits(cfg)
    if not lim.get("delete_enabled"):
        return False, "тумблер удаления выключен (delete_enabled=false, §6.4 п.5)"
    if current_host and row.get("host") == current_host:
        return False, "это ТЕКУЩИЙ upstream — сначала замена и verify (§6.4 п.3)"
    if int(row.get("fail_count") or 0) < min_fail:
        return False, ("наша проба провалена <%d раз (fail_count=%s) (§6.4 п.1)"
                       % (min_fail, row.get("fail_count") or 0))
    if provider_check is not False:
        return False, "check провайдера не false (%r) — не удаляем (§6.4 п.2)" % (provider_check,)
    return True, "все условия §6.4 выполнены"


def store_balance(pool, name, bal):
    """Записать баланс провайдера в setting `balance:<name>` единым форматом.

    Панель показывает баланс из этой строки (GET /api/status → balances). Пишут
    сюда И крон `pool-refresh` (agent.py), И веб (кнопка/сохранение ключа) — раньше
    писал только веб, поэтому после установки/деплоя баланс висел пустым, пока
    человек не нажмёт «Обновить пул» (баг 19.08). bal — словарь prov.balance()
    {"balance": "...", "currency": "..."}; пустой/без суммы НЕ затирает прежний."""
    if not bal:
        return False
    val = bal.get("balance")
    if val is None or str(val).strip() == "":
        return False
    pool.set_setting("balance:%s" % name,
                     ("%s %s" % (val, bal.get("currency") or "")).strip())
    return True


def delete_and_record(pool, provider, row, *, actor="auto", src_ip="",
                      price=None, currency=None, balance_after=None, note=""):
    """Удаление по ЯВНОМУ ext_id (delete?descr= запрещён навсегда, §5) + запись.

    Гейты §6.4 проверяет ВЫЗЫВАЮЩИЙ через can_delete(); здесь — механика и факт."""
    n = provider.delete(row["ext_id"])       # ТОЛЬКО ids — descr в запрос не попадает
    pool.record_money(row["provider"], "delete", row["uid"], price,
                      currency or "RUB", balance_after, None, row.get("descr"))
    pool.log_event("delete", actor=actor, from_uid=row["uid"],
                   result="ok" if n else "noop", src_ip=src_ip,
                   detail=json.dumps({"deleted": n, "note": note,
                                      "balance_after": balance_after}, ensure_ascii=False))
    return n
