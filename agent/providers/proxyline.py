# -*- coding: utf-8 -*-
"""ProxyLine API: catalog, new orders and renewal of existing proxy IDs."""
import re
import math
import datetime
import ipaddress

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
    kind = "dedicated" if t in ("dedicated", "1", "dedicated_ipv4", "ipv6") else ("shared" if t in ("shared", "2", "shared_ipv4") else "")
    return {
        "provider": "proxyline",
        "ext_id": str(p["id"]),
        "order_id": str(p['order_id']) if p.get('order_id') is not None else None,
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
    caps = capabilities(Capability.BUY, Capability.PROLONG)
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
        return self._list_pages({'status': 'active'})

    def get_proxies(self, ids):
        """Fetch exact purchased IDs, including expired proxies eligible for renewal."""
        wanted = self._ids_list(ids)
        rows = self._list_pages({'ids': wanted})
        if {p['ext_id'] for p in rows} != set(wanted):
            raise ProviderError('ProxyLine: запрошенные прокси не найдены в аккаунте')
        return rows

    def _list_pages(self, filters):
        out = []
        seen = set()
        offset = 0
        while True:
            page = self._api("/proxies/", dict(filters, limit=500, offset=offset))
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
        params = self.order_params(country, kind, version, quantity, period)
        reply = self._guarded('quote', lambda: http_post_form(
            API_BASE + '/new-order-amount/', params, headers={'API-KEY': self.api_key},
            host_label=HOST_LABEL, mutating=False))
        data = reply.get('data') if isinstance(reply, dict) else None
        if (not isinstance(data, dict) or data.get('type') != params['type']
                or any(data.get(k) != v or type(data.get(k)) is not type(v)
                       for k, v in params.items())
                or data.get('ip_list') not in (None, [])
                or ('ip_version' in data and (type(data['ip_version']) is not int or data['ip_version'] != version))):
            raise ProviderError('ProxyLine: цена относится к другим параметрам заказа')
        value = api_amount(reply.get('amount'), positive=True)
        return dict(country=country, type=kind, ip_version=version, quantity=quantity,
                    period=period, amount=value, currency='USD')

    @classmethod
    def order_params(cls, country, kind='dedicated', version=4, quantity=1, period=30):
        """New-order uses modern product names; stock filters remain legacy enums."""
        cls._market_params(country, kind, version)
        if type(quantity) is not int or not 1 <= quantity <= 100:
            raise ProviderError('ProxyLine: количество должно быть от 1 до 100')
        if type(period) is not int or period not in PERIODS:
            raise ProviderError('ProxyLine: неподдерживаемый срок')
        product = {('dedicated', 4): 'dedicated_ipv4', ('shared', 4): 'shared_ipv4',
                   ('dedicated', 6): 'ipv6'}[(kind, version)]
        return dict(type=product, country=country, quantity=quantity, period=period)

    def buy(self, count, period, country, version=4, kind='dedicated', on_submit=None):
        """Create one order; a successful API reply is a list, without charged total."""
        params = self.order_params(country, kind, version, count, period)
        if country in base.HARD_BLOCK_CC:
            raise ProviderError('ProxyLine: страна в чёрном списке')
        return self._purchase('/new-order/', params, on_submit)

    def _purchase(self, path, params, on_submit):
        def request():
            if on_submit is not None:
                on_submit()
            return http_post_form(API_BASE + path, params, headers={'API-KEY': self.api_key},
                                  host_label=HOST_LABEL, mutating=True)
        reply = self._guarded(path, request)
        return {'proxies': payment_proxies(reply), 'price': None, 'currency': 'USD'}

    def balance(self):
        b = self._api("/balance/") or {}
        if not isinstance(b, dict):
            raise ProviderError('ProxyLine: баланс не подтверждён')
        return {"balance": api_amount(b.get("balance")), "currency": "USD", "partner": b.get("partner_balance")}

    def prolong(self, ids, period, on_submit=None):
        """Renew purchased IDs using repeated form fields and a list response."""
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
        result = self._purchase('/renew/', {'proxies': proxies, 'period': period}, on_submit)
        if {p['ext_id'] for p in result['proxies']} != set(proxies):
            raise ProviderError('ProxyLine: ответ продления содержит другие ID')
        return dict(result, period=period)

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
            if not _RE_IDS.fullmatch(p):
                raise ProviderError('ProxyLine: ID должен быть числовым')
        if len(parts) != len(set(parts)):
            raise ProviderError('ProxyLine: повторяющиеся ID')
        return parts


def api_amount(value, *, positive=False):
    """Accept finite API decimal amounts, never booleans or missing values."""
    if type(value) not in (int, float) and not (
            isinstance(value, str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value.strip())):
        raise ProviderError('ProxyLine: сумма не подтверждена')
    number = float(value)
    if not math.isfinite(number) or number < 0 or (positive and number == 0):
        raise ProviderError('ProxyLine: сумма не подтверждена')
    return number


def payment_proxies(reply):
    """Validate a documented successful list before considering the payment complete."""
    if not isinstance(reply, list) or not reply:
        raise ProviderError('ProxyLine: список оплаченных прокси не подтверждён')
    result, seen = [], set()
    try:
        for row in reply:
            if not isinstance(row, dict):
                raise ValueError()
            ident = str(row.get('id', ''))
            if not _RE_IDS.fullmatch(ident) or ident in seen:
                raise ValueError()
            seen.add(ident)
            item = norm_proxyline(row)
            if (not item['order_id'] or not _RE_IDS.fullmatch(item['order_id'])
                    or item['kind'] not in ('dedicated', 'shared')
                    or not re.fullmatch('[a-z]{2}', item['country'])
                    or item['ip_version'] not in (4, 6)):
                raise ValueError()
            if ipaddress.ip_address(item['ip']).version != item['ip_version']:
                raise ValueError()
            datetime.datetime.fromisoformat(item['date_end'].replace('Z', '+00:00'))
            result.append(item)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ProviderError('ProxyLine: неполный ответ оплаченной операции; повторная оплата запрещена') from None
    return result
