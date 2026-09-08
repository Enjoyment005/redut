# -*- coding: utf-8 -*-
"""ProxyLine (panel.proxyline.net): import, balance and read-only market.

API: заголовок API-KEY, пагинация results/next, лимит 50 запросов/мин.
API has new-order and renew, but Redut money gates require a verified payment
contract; the read-only quote is not proof of a renewal price or a payment.
Портировано с common.js (plApi / plFetchAllProxies / plRenew / normProxyline).
"""
import re
import math

from . import base
from .base import (Provider, ProviderError, Capability, capabilities,
                   http_get_json, http_post_form, build_query)

API_BASE = "https://panel.proxyline.net/api"
HOST_LABEL = "panel.proxyline.net"

_RE_IDS = re.compile(r"^\d+$")
PERIODS = (5, 10, 20, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330, 360)
MAX_LIST_ITEMS = 20000


def norm_proxyline(p):
    """Нормализация записи /proxies/ к единому виду (см. base.py)."""
    t = str(p.get("type", ""))
    kind = "dedicated" if t in ("dedicated", "1") else ("shared" if t in ("shared", "2") else "")
    return {
        "provider": "proxyline",
        "ext_id": str(p["id"]),
        "ip": p.get("ip") or "",
        "host": p.get("ip") or "",          # у ProxyLine подключение по ip
        "port_http": p.get("port_http") or None,
        "port_socks5": p.get("port_socks5") or None,
        "user": p.get("username") or p.get("user") or "",
        "password": p.get("password") or "",
        "country": (p.get("country") or "").lower(),
        "ip_version": int(p.get("ip_version") or 4),
        "kind": kind,
        "date_end": p.get("date_end") or "",
        "descr": ", ".join(t.get("name", "") for t in (p.get("tags") or []) if isinstance(t, dict)),
    }


class ProxyLine(Provider):
    name = "proxyline"
    caps = capabilities(Capability.PROLONG)
    min_interval = 1.3  # 50 req/мин

    def _api(self, path, params=None):
        def request():
            url = API_BASE + path
            qs = build_query(params)
            if qs:
                url += "?" + qs
            return http_get_json(url, headers={"API-KEY": self.api_key},
                                 host_label=HOST_LABEL)
        return self._guarded(path, request)

    def list(self):
        out = []
        seen = set()
        offset = 0
        while True:
            page = self._api("/proxies/", {"status": "active", "limit": 500, "offset": offset})
            if (not isinstance(page, dict) or not isinstance(page.get('results'), list)
                    or 'next' not in page or type(page.get('count')) is not int):
                raise ProviderError('ProxyLine: неполная страница списка прокси')
            items = page['results']
            for item in items:
                if not isinstance(item, dict) or not _RE_IDS.fullmatch(str(item.get('id', ''))):
                    raise ProviderError('ProxyLine: некорректный ID в списке прокси')
                ident = str(item['id'])
                if ident in seen:
                    raise ProviderError('ProxyLine: API повторил страницу списка')
                seen.add(ident)
                out.append(norm_proxyline(item))
            total = page.get('count')
            if total < len(out):
                raise ProviderError('ProxyLine: некорректное число прокси')
            if not page.get('next'):
                if total != len(out):
                    raise ProviderError('ProxyLine: список прокси обрезан')
                return out
            if not items or len(out) >= MAX_LIST_ITEMS:
                raise ProviderError('ProxyLine: список не завершён; старый пул сохранён')
            offset += len(items)

    def countries(self):
        """Read the live country/city catalog without asserting stock availability."""
        rows = self._api('/countries/')
        if not isinstance(rows, list):
            raise ProviderError('ProxyLine: некорректный каталог стран')
        result = []
        for row in rows:
            if not isinstance(row, dict) or not re.fullmatch('[a-z]{2}', str(row.get('code') or '')):
                raise ProviderError('ProxyLine: некорректная страна каталога')
            result.append({'code': row['code'], 'name': str(row.get('name') or row['code'])})
        return result

    @staticmethod
    def _market_params(country, kind, version):
        """Validate catalog filters before passing any caller input to the API."""
        if not isinstance(country, str) or not re.fullmatch('[a-z]{2}', country):
            raise ProviderError('ProxyLine: страна должна быть кодом из двух букв')
        if kind not in ('dedicated', 'shared') or type(version) is not int or version not in (4, 6):
            raise ProviderError('ProxyLine: неизвестный тип прокси')
        if version == 6 and kind != 'dedicated':
            raise ProviderError('ProxyLine: IPv6 доступен только dedicated')
        return {'country': country, 'type': kind, 'ip_version': version}

    def stock(self, country, kind='dedicated', version=4):
        reply = self._api('/ips-count/', self._market_params(country, kind, version))
        count = reply.get('count') if isinstance(reply, dict) else None
        if type(count) is not int or not 0 <= count <= 1000:
            raise ProviderError('ProxyLine: наличие не подтверждено')
        return count

    def quote(self, country, kind='dedicated', version=4, quantity=1, period=30):
        """Read the exact new-order amount; this endpoint does not purchase proxies."""
        params = self._market_params(country, kind, version)
        if type(quantity) is not int or not 1 <= quantity <= 100:
            raise ProviderError('ProxyLine: количество должно быть от 1 до 100')
        if type(period) is not int or period not in PERIODS:
            raise ProviderError('ProxyLine: неподдерживаемый срок')
        params.update(quantity=quantity, period=period)
        reply = self._guarded('quote', lambda: http_post_form(
            API_BASE + '/new-order-amount/', params, headers={'API-KEY': self.api_key},
            host_label=HOST_LABEL, mutating=False))
        data = reply.get('data') if isinstance(reply, dict) else None
        response_type = {('dedicated', 4): 'dedicated_ipv4',
                         ('shared', 4): 'shared_ipv4', ('dedicated', 6): 'ipv6'}[(kind, version)]
        # The quote response uses product type names instead of the request enum.
        if (not isinstance(data, dict)
                or data.get('type') not in (kind, response_type)
                or any(data.get(k) != v for k, v in params.items() if k != 'type')):
            raise ProviderError('ProxyLine: цена относится к другим параметрам заказа')
        value = reply.get('amount')
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ProviderError('ProxyLine: цена не подтверждена')
        return dict(params, amount=value, currency='USD')

    def balance(self):
        b = self._api("/balance/") or {}
        return {"balance": b.get("balance"), "currency": "USD", "partner": b.get("partner_balance")}

    def prolong(self, ids, period, on_submit=None):
        """Продление: POST /api/renew/ {proxies, period} (form-encoded, §2.1).

        ids -> список внутренних id (только числовые, валидация ДО API §15);
        period — кол-во дней. Возврат — распарсенный ответ + балансовые поля,
        если провайдер их вернул (форма ответа /renew/ в доке не зафиксирована —
        не завязываемся на конкретные ключи, отдаём как есть)."""
        proxies = self._ids_list(ids)
        if isinstance(period, bool) or not (isinstance(period, int) or
                isinstance(period, str) and re.fullmatch('[0-9]+', period)):
            raise ProviderError('ProxyLine.prolong: срок должен быть целым числом дней')
        try:
            period = int(period)
        except (TypeError, ValueError):
            raise ProviderError("ProxyLine.prolong: period=%r не целое" % (period,)) from None
        if period not in PERIODS:
            raise ProviderError('ProxyLine.prolong: неподдерживаемый срок продления')
        def renew():
            if on_submit is not None:
                on_submit()
            return http_post_form(
                API_BASE + "/renew/", {"proxies": proxies, "period": period},
                headers={"API-KEY": self.api_key}, host_label=HOST_LABEL,
                mutating=True)
        r = self._guarded("prolong", renew) or {}
        return {"proxies": proxies, "period": period,
                "price": r.get("price") or r.get("amount") or r.get("cost"),
                "balance": r.get("balance"),
                "currency": r.get("currency") or "USD", "raw": r}

    @staticmethod
    def _ids_list(ids):
        """Список числовых id (str/int/список). Пустой запрещён; descr — не про ProxyLine."""
        if isinstance(ids, (str, int)):
            parts = [p.strip() for p in str(ids).split(",")]
        else:
            parts = [str(x).strip() for x in (ids or [])]
        parts = [p for p in parts if p != ""]
        if not parts:
            raise ProviderError("ProxyLine.prolong: пустой список ids")
        for p in parts:
            if not _RE_IDS.match(p):
                raise ProviderError("ProxyLine.prolong: id %r не числовой (§15)" % p)
        return parts
