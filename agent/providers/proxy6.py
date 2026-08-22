# -*- coding: utf-8 -*-
"""PROXY6 (proxy6.net) — основной провайдер с полным жизненным циклом (§2).

Транспорт: https://{host}/api/{api_key}/{method}/?params — ключ В ПУТИ URL,
поэтому URL никогда не попадает в логи/исключения (маскируем …/api/****/…).
Домены перебираются по приоритету (proxy6.net -> px6.link), рабочий запоминается;
при network error пробуем следующий, при HTTP-ошибке — не перебираем.
Лимит 3 запроса/сек. Ответ всегда {status:"yes"|"no", balance, currency, …}.

Фаза 1: list + balance + check. Фаза 2: полный жизненный цикл денег —
buy / prolong / delete + рынок getprice / getcount / getcountry. ВСЯ валидация
ДО обращения к API (§15). Политику трат (лимиты, тумблеры, идемпотентность,
запись в money) держит money.py; здесь — транспорт и предохранители страны/версии.
ipauth АГЕНТ НЕ ВЫЗЫВАЕТ НИКОГДА (§2.2: заменяет список привязанных IP и ломает
SOCKS5 в Chrome-расширении) — в коде стоит предохранитель.
Портировано с common.js (p6Api / p6ErrorText / normProxy6 / fetchProxy6Data).
"""
import re
import urllib.parse

from .base import (Provider, ProviderError, ProviderErrorKind, Capability,
                   capabilities, http_get_json, build_query,
                   HARD_BLOCK_CC, DEFAULT_WHITELIST_CC)

P6_HOSTS = ("proxy6.net", "px6.link")

# Границы валидации ДО вызова API (§15) — санитарные, не политика трат (та в money.py).
MAX_BUY_COUNT = 100     # покупаем поштучно; всё крупнее — почти наверняка баг
MAX_PERIOD_DAYS = 365
DESCR_MAX = 50          # ограничение API PROXY6 на длину descr
_RE_DESCR = re.compile(r"^[A-Za-z0-9._:-]{1,%d}$" % DESCR_MAX)
_RE_ISO2 = re.compile(r"^[a-z]{2}$")
_RE_IDS = re.compile(r"^\d+$")

# Коды ошибок, которые агент обязан различать (§2.2 + PDF-дока)
P6_ERRORS = {
    30: "неизвестная ошибка",
    100: "API-ключ PROXY6 не принят",
    105: "PROXY6: доступ с неверного IP (добавьте IP сервера в ограничение API в кабинете)",
    110: "ошибочный метод",
    200: "неверное количество прокси",
    210: "неверный период",
    220: "неверная страна (нужен iso2)",
    230: "неверный список номеров прокси (ids через запятую)",
    240: "некорректная версия прокси",
    250: "ошибка технического комментария (descr)",
    260: "ошибка типа (протокола) прокси",
    270: "ошибка порта прокси",
    280: "ошибка строки прокси для check",
    300: "нет столько прокси в наличии у сервиса",
    400: "не хватает денег на балансе",
    404: "элемент не найден",
    410: "ошибка расчёта стоимости",
}


def p6_error_text(data):
    code = data.get("error_id")
    if code in P6_ERRORS:
        prefix = "" if code in (100, 105) else "PROXY6: "
        return "%s%s (error %s)" % (prefix, P6_ERRORS[code], code)
    return "PROXY6: %s" % (data.get("error") or code or "ошибка")


def norm_proxy6(it):
    """Нормализация записи getproxy. version 5 (MTproto) отсеивается -> None.

    ip может быть IPv6, host — всегда IPv4: подключаемся к host (§2.2).
    type=auto — оба протокола на одном порту (подарок для RETUNE §7.2).
    """
    version = str(it.get("version", ""))
    if version == "5":
        return None
    try:
        port = int(it.get("port") or 0) or None
    except (TypeError, ValueError):
        port = None
    ptype = it.get("type")  # http | socks | auto
    date_end = it.get("date_end_iso") or str(it.get("date_end") or "").replace(" ", "T")
    return {
        "provider": "proxy6",
        "ext_id": str(it["id"]),
        "ip": it.get("ip") or "",
        "host": it.get("host") or "",
        "port_http": port if ptype in ("http", "auto") else None,
        "port_socks5": port if ptype in ("socks", "auto") else None,
        "user": it.get("user") or "",
        "password": it.get("pass") or "",
        "country": (it.get("country") or "").lower(),
        "ip_version": 6 if version == "6" else 4,
        "kind": "shared" if version == "3" else "dedicated",
        "date_end": date_end,
        "descr": it.get("descr") or "",
    }


def norm_bought(it, version, country):
    """Нормализация записи из ответа buy.

    В ответе buy у элементов list НЕТ полей version и country (в отличие от
    getproxy) — подставляем запрошенные, чтобы norm_proxy6 отработал верно.
    Полные паспортные поля всё равно подтянутся следующим pool-refresh (getproxy).
    """
    it = dict(it)
    it.setdefault("version", str(version))
    it.setdefault("country", country)
    return norm_proxy6(it)


def _as_int(value, what):
    """int в разумных границах или ProviderError (валидация ДО API, §15)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ProviderError("PROXY6: %s=%r не целое число" % (what, value)) from None


def _ids_csv(ids):
    """Список внутренних id -> 'a,b,c'. Только цифры (id PROXY6 числовые).

    Отсекает инъекции/мусор ДО API; пустой список запрещён (§5: никаких
    операций «по всему списку»). Строка и список принимаются, descr — НИКОГДА."""
    if isinstance(ids, (str, int)):
        parts = [p.strip() for p in str(ids).split(",")]
    else:
        parts = [str(x).strip() for x in (ids or [])]
    parts = [p for p in parts if p != ""]
    if not parts:
        raise ProviderError("PROXY6: пустой список ids — операция отклонена (§5)")
    for p in parts:
        if not _RE_IDS.match(p):
            raise ProviderError("PROXY6: id %r не числовой — отклонено валидацией (§15)" % p)
    return ",".join(parts)


def _validate_descr(descr):
    """descr для buy: ≤50 символов, безопасный алфавит. Пустой -> None."""
    if descr is None or descr == "":
        return None
    descr = str(descr)
    if not _RE_DESCR.match(descr):
        raise ProviderError(
            "PROXY6: descr %r недопустим (нужно ≤%d символов [A-Za-z0-9._:-])" % (descr, DESCR_MAX))
    return descr


class Proxy6(Provider):
    name = "proxy6"
    caps = capabilities(Capability.BUY, Capability.DELETE,
                        Capability.PROLONG, Capability.CHECK)
    min_interval = 0.35  # 3 запроса/сек -> 429

    def __init__(self, api_key):
        super().__init__(api_key)
        self._good_host = None  # запомненный рабочий домен (как p6GoodHost в расширении)

    def _mask(self, text):
        """Ключ идёт в пути URL — в любых сообщениях/логах маскируем (§15)."""
        return str(text).replace(self.api_key, "****").replace(urllib.parse.quote(self.api_key, safe=""), "****")

    def _api(self, method, params=None, mutating=False):
        """GET к API PROXY6 (все методы — GET). Ключ в пути маскируется в ошибках.

        mutating=True (buy/prolong/delete): при сетевой ошибке НЕ перебираем
        запасной домен. Таймаут мог означать «запрос прошёл, ответ потерян» —
        повтор на другом домене = двойная покупка. Идемпотентность обеспечивает
        вызывающий (money.plan_and_buy: поиск по descr, §6.2), а не транспорт.
        """
        if method == "ipauth":
            # Предохранитель: ipauth ЗАМЕНЯЕТ список привязанных IP и сломает
            # SOCKS5 в Chrome-расширении владельца. Только руками, полным списком.
            raise RuntimeError("ipauth запрещён агенту навсегда (§2.2)")
        return self._guarded(
            method, lambda: self._api_request(method, params, mutating))

    def _api_request(self, method, params=None, mutating=False):
        qs = build_query(params)
        suffix = "/api/%s/%s/" % (urllib.parse.quote(self.api_key, safe=""), method)
        if qs:
            suffix += "?" + qs
        order = ([self._good_host] + [h for h in P6_HOSTS if h != self._good_host]) if self._good_host else list(P6_HOSTS)
        last = None
        for host in order:
            try:
                # mutating уходит и в транспорт: повтор через канал узла (tun0) допустим для денег
                # только если запрос заведомо не был доставлен (providers/base._request_json).
                data = http_get_json("https://" + host + suffix, host_label=host, mutating=mutating)
            except ProviderError as e:
                if e.network:
                    last = e
                    if mutating:
                        # Не перебираем домены на мутации — см. docstring.
                        raise ProviderError(self._mask(str(e)), code=e.code, network=True,
                                            unsent=e.unsent, kind=e.kind,
                                            retry_after=e.retry_after) from None
                    continue  # чтение: домен недоступен — пробуем следующий
                raise ProviderError(self._mask(str(e)), code=e.code, unsent=e.unsent,
                                    kind=e.kind,
                                    retry_after=e.retry_after) from None
            if isinstance(data, dict) and data.get("status") == "no":
                code = data.get("error_id")
                kind = (ProviderErrorKind.AUTH if code in (100, 105)
                        else ProviderErrorKind.NOT_FOUND if code == 404
                        else ProviderErrorKind.UNKNOWN)
                raise ProviderError(self._mask(p6_error_text(data)), code=code, kind=kind)
            self._good_host = host
            return data or {}
        raise ProviderError(
            "PROXY6: домены %s недоступны — возможно, заблокированы в вашей сети (%s)"
            % (", ".join(P6_HOSTS), self._mask(str(last))),
            code=getattr(last, "code", None), network=True,
            unsent=bool(last and last.unsent),
            kind=getattr(last, "kind", ProviderErrorKind.NETWORK),
            retry_after=getattr(last, "retry_after", None))

    def list(self):
        out = []
        page = 1
        while True:
            r = self._api("getproxy", {"state": "active", "page": page, "limit": 1000})
            # ВАЖНО: list — ОБЪЕКТ с ключами-id, не массив
            items = list((r.get("list") or {}).values())
            for it in items:
                n = norm_proxy6(it)
                if n:
                    out.append(n)
            if len(items) < 1000 or page > 50:
                break
            page += 1
        return out

    def balance(self):
        r = self._api("getproxy", {"limit": 1})  # баланс приходит в любом ответе
        return {"balance": r.get("balance"), "currency": r.get("currency") or "RUB"}

    def check(self, ext_id):
        """Дешёвая проверка на стороне провайдера: check?ids= -> proxy_status."""
        r = self._api("check", {"ids": str(ext_id)})
        return bool(r.get("proxy_status"))

    # ------------------------------------------------------------- рынок (без трат)
    def getcountry(self, version=4):
        """Список доступных к покупке стран (iso2, lower) для версии."""
        version = _as_int(version, "version")
        r = self._api("getcountry", {"version": version})
        return [str(c).lower() for c in (r.get("list") or []) if isinstance(c, str)]

    def getcount(self, country, version=4):
        """Сколько прокси доступно к покупке в стране (int)."""
        country = (country or "").strip().lower()
        if not _RE_ISO2.match(country):
            raise ProviderError("PROXY6.getcount: страна %r не iso2" % country)
        version = _as_int(version, "version")
        r = self._api("getcount", {"country": country, "version": version})
        return int(r.get("count") or 0)

    def getprice(self, count, period, version=4):
        """Стоимость заказа ДО покупки (§6.2: сверяем M₽ до buy). getprice
        страну не принимает — цена в API от страны не зависит."""
        count = _as_int(count, "count")
        period = _as_int(period, "period")
        version = _as_int(version, "version")
        if count < 1 or period < 1:
            raise ProviderError("PROXY6.getprice: count/period должны быть ≥1")
        r = self._api("getprice", {"count": count, "period": period, "version": version})
        return {"price": r.get("price"), "price_single": r.get("price_single"),
                "period": r.get("period"), "count": r.get("count"),
                "balance": r.get("balance"), "currency": r.get("currency") or "RUB"}

    # ------------------------------------------------------------- деньги (§6, фаза 2)
    def _check_buy_country(self, country, allow_cc):
        """Двухслойная проверка страны ДО buy (§6.1).

        Слой 1 — **чёрный список в коде**: проверяется ПЕРВЫМ и независимо ни от
        чего. Даже если вызывающий передаст испорченный список разрешённых стран
        с Россией внутри, покупка не пройдёт.

        Слой 2 — необязательное сужение `allow_cc` (список от вызывающего). С
        2026-08-15 `allow_cc=None` означает «любая страна вне чёрного списка»:
        решение, где покупать, принимает умная оценка (`country.rank`) выше по
        стеку, а не жёсткий белый список. Передашь список — сузит до него.
        """
        country = (country or "").strip().lower()
        if not _RE_ISO2.match(country):
            raise ProviderError("PROXY6.buy: страна %r не iso2" % country)
        if country in HARD_BLOCK_CC:                         # слой 1 — предохранитель в коде
            raise ProviderError(
                "PROXY6.buy: страна '%s' в ЧЁРНОМ СПИСКЕ §6.1 — покупка запрещена навсегда" % country)
        if allow_cc is not None and country not in set(allow_cc):   # слой 2 — сужение
            raise ProviderError(
                "PROXY6.buy: страна '%s' не в списке разрешённых — покупка запрещена (§6.1)" % country)
        return country

    def buy(self, count, period, country, version=4, descr=None, allow_cc=None):
        """Покупка прокси. ВСЯ валидация — ДО обращения к API (§15).

        allow_cc — необязательное сужение списка стран (None — любая вне чёрного
        списка: пользовательского «белого списка» больше нет, приёмка №7).
        auto_prolong НЕ передаём никогда (§6.2: продлением управляет агент осознанно).
        Возврат: dict(proxies=[norm], order_id, price, price_single, count, period,
                       country, balance, currency).
        """
        version = _as_int(version, "version")
        if version != 4:
            raise ProviderError(
                "PROXY6.buy: покупаем только version=4 (IPv4); version=%r отклонён "
                "(v3 shared — грязный IP, v5 MTproto, v6 IPv6-выход бесполезен, §2.2)" % version)
        country = self._check_buy_country(country, allow_cc)
        count = _as_int(count, "count")
        period = _as_int(period, "period")
        if not (1 <= count <= MAX_BUY_COUNT):
            raise ProviderError("PROXY6.buy: count=%d вне 1..%d" % (count, MAX_BUY_COUNT))
        if not (1 <= period <= MAX_PERIOD_DAYS):
            raise ProviderError("PROXY6.buy: period=%d вне 1..%d дней" % (period, MAX_PERIOD_DAYS))
        descr = _validate_descr(descr)
        params = {"count": count, "period": period, "country": country, "version": version}
        if descr:
            params["descr"] = descr
        # NB: auto_prolong СПЕЦИАЛЬНО отсутствует (§6.2).
        r = self._api("buy", params, mutating=True)
        proxies = [n for n in (norm_bought(it, version, r.get("country") or country)
                               for it in (r.get("list") or {}).values()) if n]
        return {"proxies": proxies, "order_id": r.get("order_id"),
                "price": r.get("price"), "price_single": r.get("price_single"),
                "count": r.get("count"), "period": r.get("period"),
                "country": r.get("country") or country,
                "balance": r.get("balance"), "currency": r.get("currency") or "RUB"}

    def find_by_descr(self, descr, state="all"):
        """getproxy?descr= — восстановление после оборванного buy (§6.2).

        Идемпотентность: если ответ buy не пришёл, НЕ повторяем buy, а ищем по
        тому же descr — прокси там => покупка прошла. Это ЧТЕНИЕ (перебор
        доменов допустим). Возврат: список нормализованных прокси (может быть пуст).
        """
        descr = _validate_descr(descr)
        if not descr:
            raise ProviderError("find_by_descr: пустой descr")
        r = self._api("getproxy", {"descr": descr, "state": state, "limit": 1000})
        return [n for n in (norm_proxy6(it) for it in (r.get("list") or {}).values()) if n]

    def prolong(self, ids, period):
        """Продление списка прокси на period дней (prolong?ids=&period=).

        Возврат: dict(order_id, price, count, period, balance, currency,
                       proxies={ext_id: {date_end}}). Мутация: без перебора доменов."""
        ids_csv = _ids_csv(ids)
        period = _as_int(period, "period")
        if not (1 <= period <= MAX_PERIOD_DAYS):
            raise ProviderError("PROXY6.prolong: period=%d вне 1..%d дней" % (period, MAX_PERIOD_DAYS))
        r = self._api("prolong", {"ids": ids_csv, "period": period}, mutating=True)
        got = r.get("list") or {}
        return {"order_id": r.get("order_id"), "price": r.get("price"),
                "price_single": r.get("price_single"), "count": r.get("count"),
                "period": r.get("period"), "balance": r.get("balance"),
                "currency": r.get("currency") or "RUB",
                "proxies": {str(k): {"date_end": (v or {}).get("date_end")} for k, v in got.items()}}

    def delete(self, ids):
        """Удаление прокси ТОЛЬКО по явным ids (delete?ids=). -> кол-во удалённых.

        delete?descr= ЗАПРЕЩЁН НАВСЕГДА (§5: массовое удаление по комментарию) —
        сигнатура принимает только ids, descr в запрос не попадает никогда.
        Мутация: без перебора доменов (двойной delete безвреден, но политика едина)."""
        ids_csv = _ids_csv(ids)
        r = self._api("delete", {"ids": ids_csv}, mutating=True)
        return int(r.get("count") or 0)
