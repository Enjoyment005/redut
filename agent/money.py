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
import json
import re
import secrets as _secrets

import country as country_mod
from providers.base import ProviderError, HARD_BLOCK_CC, DEFAULT_WHITELIST_CC

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


# ------------------------------------------------------------------- настройки
def limits(cfg):
    m = dict(DEFAULT_LIMITS)
    m.update((cfg or {}).get("money") or {})
    return m


def whitelist(cfg):
    """Предпочитаемые страны трат — «начни отсюда», НЕ жёсткий фильтр (с 2026-08-15).

    Чёрный список вычищаем всегда, даже если кто-то впишет его в конфиг (§6.1,
    предохранитель в коде). Провайдер проверит ещё раз.
    """
    cc = ((cfg or {}).get("countries") or {}).get("whitelist")
    wl = [str(c).strip().lower() for c in cc] if cc else list(DEFAULT_WHITELIST_CC)
    return [c for c in wl if c and not country_mod.is_blocked(c, cfg)]


def buy_candidates(cfg, available=None):
    """Порядок перебора стран при авто-покупке.

    Сначала предпочитаемые из конфига, затем всё остальное, что есть у провайдера,
    и всё это пересортировано умной оценкой (country_mod.rank). Страны с оценкой ниже
    порога автоматика сама не покупает — их берут только по явной просьбе человека.
    """
    pref = whitelist(cfg)
    rest = [c for c in (available or []) if c not in pref]
    ranked = country_mod.rank(list(pref) + list(rest), cfg)
    return [c for c in ranked if country_mod.auto_allowed(c, True, cfg)]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_SRV_RE = re.compile(r"[^A-Za-z0-9]")


def gen_descr(server, now=None):
    """Уникальный идемпотентный тег покупки vpnbuy-<server>-<ts>-<rnd> (≤50, §6.2)."""
    now = now or datetime.datetime.now()
    srv = _SRV_RE.sub("", str(server or "srv"))[:12] or "srv"
    d = "vpnbuy-%s-%s-%s" % (srv, now.strftime("%Y%m%dT%H%M%S"), _secrets.token_hex(2)[:3])
    return d[:50]


# --------------------------------------------------------------------- покупка
def preflight_buy(pool, provider, cfg, *, country, period=None, count=1, version=None,
                  auto=True):
    """Все гейты §6.2 ДО траты. -> dict(price, currency, balance_before, period,
    version, count, country, whitelist). Отказ -> SpendDenied (ничего не потрачено).

    `auto=True` — покупает автоматика: разрешены только страны с оценкой не ниже
    порога (country.MIN_AUTO_RATING). `auto=False` — человек выбрал страну руками:
    пропускаем всё, кроме чёрного списка, но причину пишем в журнал вызывающего.
    """
    lim = limits(cfg)
    wl = whitelist(cfg)
    period = int(period or lim["buy_period_days"])
    version = int(version if version is not None else lim["buy_version"])
    count = int(count)
    currency = lim["currency"]
    country = (country or "").strip().lower()

    # ГЕЙТ 1 — тумблер (§6.2)
    if not lim["buy_enabled"]:
        raise SpendDenied("покупки выключены тумблером buy_enabled — только алерт «купи руками» (§6.2)")
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
    if price is None or price <= 0:
        raise SpendDenied("getprice вернул некорректную цену %r — покупка отменена" % pr.get("price"))
    # ГЕЙТ 3 — цена одной покупки ≤ M
    if price > lim["max_price_per_buy"]:
        raise SpendDenied("цена %.2f %s > лимита %.2f/покупка (§6.2)"
                          % (price, currency, lim["max_price_per_buy"]))
    # ГЕЙТ 4 — траты за сутки + эта ≤ N
    spent = pool.spent_today(currency)
    if spent + price > lim["max_spend_per_day"]:
        raise SpendDenied("суточный лимит трат: %.2f + %.2f > %.2f %s (§6.2)"
                          % (spent, price, lim["max_spend_per_day"], currency))
    # ГЕЙТ 5 — неснижаемый остаток баланса (глобальный предохранитель, баланс общий)
    if bal_before is not None and (bal_before - price) < lim["min_balance_reserve"]:
        raise SpendDenied("баланс %.2f − %.2f < неснижаемого остатка %.2f %s (§6.2)"
                          % (bal_before, price, lim["min_balance_reserve"], currency))
    return {"price": price, "currency": currency, "balance_before": bal_before,
            "period": period, "version": version, "count": count,
            "country": country, "whitelist": wl}


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
    pre = preflight_buy(pool, provider, cfg, country=country, period=period,
                        count=count, version=version, auto=auto)
    server = server or (cfg or {}).get("server") or "srv"
    descr = gen_descr(server)
    recovered = False
    try:
        # allow_cc=None: страну уже одобрили гейты выше (чёрный список + оценка).
        # Слой провайдера всё равно перепроверит чёрный список независимо.
        resp = provider.buy(pre["count"], pre["period"], pre["country"],
                            version=pre["version"], descr=descr, allow_cc=None)
    except ProviderError as e:
        if not getattr(e, "network", False):
            raise
        # Сеть оборвалась. buy НЕ повторяем — проверяем, не прошла ли она (§6.2).
        try:
            found = provider.find_by_descr(descr)
        except ProviderError:
            found = None
        if not found:
            pool.log_event("buy", actor=actor, result="unconfirmed", src_ip=src_ip,
                           detail="сеть оборвалась, покупка НЕ подтверждена (descr=%s)" % descr)
            raise SpendDenied(
                "покупка НЕ подтверждена (сеть). Проверь кабинет по descr=%s ПЕРЕД повтором — "
                "иначе риск двойной покупки; повтор безопасен только с НОВЫМ descr (§6.2)" % descr)
        recovered = True
        resp = {"proxies": found, "order_id": None, "price": None, "count": len(found),
                "period": pre["period"], "country": pre["country"], "balance": None,
                "currency": pre["currency"]}

    proxies = resp.get("proxies") or []
    price_charged = _num(resp.get("price"))
    if price_charged is None:                # recovered: точной цены нет, пишем оценку getprice
        price_charged = pre["price"]
    currency = resp.get("currency") or pre["currency"]
    bal_after = resp.get("balance")
    per_unit = price_charged if len(proxies) <= 1 else round(price_charged / len(proxies), 4)
    uids = []
    for pxy in proxies:
        uid = "%s:%s" % (pxy["provider"], pxy["ext_id"])
        uids.append(uid)
        pool.record_money(pxy["provider"], "buy", uid, per_unit, currency,
                          bal_after, resp.get("order_id"), descr)
    pool.log_event("buy", actor=actor, result="recovered" if recovered else "ok", src_ip=src_ip,
                   detail=json.dumps({"country": pre["country"], "period": pre["period"],
                                      "count": len(proxies), "price": price_charged,
                                      "currency": currency, "balance_after": bal_after,
                                      "descr": descr, "uids": uids}, ensure_ascii=False))
    return {"ok": True, "recovered": recovered, "proxies": proxies, "price": price_charged,
            "currency": currency, "descr": descr, "order_id": resp.get("order_id"),
            "balance_after": bal_after, "period": pre["period"], "country": pre["country"]}


# ------------------------------------------------------------------- продление
def prolong_with_limits(pool, provider, cfg, *, row, days, actor="auto", src_ip=""):
    """Продлить один прокси на days (§6.3) под гейтами трат + запись в money.

    row — запись пула (provider, ext_id, uid, descr). Для PROXY6 сверяем цену
    через getprice ДО траты; у ProxyLine getprice нет — гейтим тумблером и пишем
    цену из ответа /renew/ (валюта USD)."""
    lim = limits(cfg)
    days = int(days)
    if not (1 <= days <= 365):
        raise SpendDenied("period=%d вне 1..365 дней" % days)
    if not lim["buy_enabled"]:
        raise SpendDenied("траты выключены тумблером buy_enabled — продление недоступно (§6.2)")

    pname, ext_id, uid = row["provider"], row["ext_id"], row["uid"]
    price = None
    currency = lim["currency"] if pname == "proxy6" else "USD"
    if pname == "proxy6":
        pr = provider.getprice(1, days, int(lim["buy_version"]))
        price = _num(pr.get("price"))
        bal = _num(pr.get("balance"))
        if price is not None:
            if price > lim["max_price_per_buy"]:
                raise SpendDenied("цена продления %.2f %s > лимита %.2f/покупка (§6.2)"
                                  % (price, currency, lim["max_price_per_buy"]))
            if pool.spent_today(currency) + price > lim["max_spend_per_day"]:
                raise SpendDenied("суточный лимит трат превышен продлением (§6.2)")
            if bal is not None and (bal - price) < lim["min_balance_reserve"]:
                raise SpendDenied("продление опустит баланс ниже неснижаемого остатка (§6.2)")

    resp = provider.prolong(ext_id, days)
    price_charged = _num(resp.get("price"))
    if price_charged is None:
        price_charged = price
    currency = resp.get("currency") or currency
    bal_after = resp.get("balance")
    pool.record_money(pname, "prolong", uid, price_charged, currency,
                      bal_after, resp.get("order_id"), row.get("descr"))
    new_end = None
    if pname == "proxy6":
        new_end = ((resp.get("proxies") or {}).get(str(ext_id)) or {}).get("date_end")
        if new_end:
            pool.set_date_end(uid, str(new_end).replace(" ", "T"))
    pool.log_event("prolong", actor=actor, to_uid=uid, result="ok", src_ip=src_ip,
                   detail=json.dumps({"days": days, "price": price_charged, "currency": currency,
                                      "balance_after": bal_after, "date_end": new_end},
                                     ensure_ascii=False))
    return {"ok": True, "uid": uid, "days": days, "price": price_charged,
            "currency": currency, "balance_after": bal_after, "date_end": new_end}


# -------------------------------------------------------------------- удаление
def can_delete(row, cfg, *, current_host=None, provider_check=None, min_fail=2):
    """§6.4: удаляем ТОЛЬКО если выполнены ВСЕ условия. -> (ok: bool, reason: str).

    provider_check — результат check?ids= провайдера (True|False|None). Требуется
    именно False (труп подтверждён провайдером); True/None не проходят."""
    lim = limits(cfg)
    if not lim.get("delete_enabled"):
        return False, "тумблер удаления выключен (delete_enabled=false, §6.4 п.5)"
    if row.get("role") in ("chrome", "reserve"):
        return False, "роль %s защищена от удаления (§6.4 п.4)" % row.get("role")
    if current_host and row.get("host") == current_host:
        return False, "это ТЕКУЩИЙ upstream — сначала замена и verify (§6.4 п.3)"
    if int(row.get("fail_count") or 0) < min_fail:
        return False, ("наша проба провалена <%d раз (fail_count=%s) (§6.4 п.1)"
                       % (min_fail, row.get("fail_count") or 0))
    if provider_check is not False:
        return False, "check провайдера не false (%r) — не удаляем (§6.4 п.2)" % (provider_check,)
    return True, "все условия §6.4 выполнены"


def delete_and_record(pool, provider, row, *, actor="auto", src_ip="",
                      price=None, currency=None, balance_after=None, note=""):
    """Удаление по ЯВНОМУ ext_id (delete?descr= запрещён навсегда, §5) + запись.

    Гейты §6.4 проверяет ВЫЗЫВАЮЩИЙ через can_delete(); здесь — механика и факт.
    Роль chrome защищена дополнительным предохранителем и тут."""
    if row.get("role") == "chrome":
        raise SpendDenied("роль chrome защищена от удаления навсегда (§5)")
    n = provider.delete(row["ext_id"])       # ТОЛЬКО ids — descr в запрос не попадает
    pool.record_money(row["provider"], "delete", row["uid"], price,
                      currency or "RUB", balance_after, None, row.get("descr"))
    pool.log_event("delete", actor=actor, from_uid=row["uid"],
                   result="ok" if n else "noop", src_ip=src_ip,
                   detail=json.dumps({"deleted": n, "note": note,
                                      "balance_after": balance_after}, ensure_ascii=False))
    return n
