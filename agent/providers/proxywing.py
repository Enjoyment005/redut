# -*- coding: utf-8 -*-
"""ProxyWing — datacenter и ISP прокси через Developer API v1.

Месячные заказы имеют отдельный явный контракт; дневные buy/prolong ядра
не включаются, чтобы автоматические 7 дней не превратились в месяц.
"""
import datetime
import ipaddress
import math
import re

from .base import Provider, ProviderError, capabilities, http_get_json, http_post_json, http_put_json

API_BASE = "https://api.proxywing.com/v1"
HOST_LABEL = "api.proxywing.com"
FAMILIES = ('datacenter', 'isp')
MONTHS = (1, 3, 6, 12)


def identifier(value):
    """Accept opaque API IDs without allowing path/query injection."""
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value):
        raise ProviderError('ProxyWing: некорректный идентификатор')
    return value


def family_name(value):
    if value not in FAMILIES:
        raise ProviderError('ProxyWing: выбери Datacenter или ISP')
    return value


def order_identity(ext_id):
    """Extract one order identity from a persisted normalized proxy ID."""
    parts = str(ext_id).removeprefix('proxywing:').split('|')
    if len(parts) != 3:
        raise ProviderError('ProxyWing: некорректный ID прокси')
    identifier(parts[2])
    return family_name(parts[0]), identifier(parts[1])


def billing_date(value):
    """Parse a provider date (UTC midnight) or an explicitly zoned ISO timestamp.

    Naive timestamps, malformed dates and local proxy expiry never prove the
    provider billing deadline. Return an aware UTC datetime for comparisons.
    """
    try:
        if not isinstance(value, str):
            raise ValueError()
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            date = datetime.date.fromisoformat(value)
            return datetime.datetime.combine(date, datetime.time(), datetime.timezone.utc)
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T.+', value):
            raise ValueError()
        date = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if date.tzinfo is None:
            raise ValueError()
        return date.astimezone(datetime.timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise ProviderError('ProxyWing: дата оплаты услуги не подтверждена') from None


def amount(value):
    """Validate a positive finite API amount, never reinterpret currency."""
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        number = 0
    if isinstance(value, bool) or not math.isfinite(number) or number <= 0:
        raise ProviderError('ProxyWing: API не вернул корректную цену')
    return number


def product_location(row, family):
    """Read ISO country and package size from structured data or the ISP product name."""
    location = str(row.get('location') or '').upper()
    quantity = row.get('quantity')
    if quantity is not None and (type(quantity) is not int or quantity < 1):
        raise ProviderError('ProxyWing: некорректный размер пакета')
    named = re.fullmatch(r'(\d+) Prox(?:y|ies) ISP ([A-Z]{2})', str(row.get('name') or ''), re.I)
    if family == 'isp' and named:
        named_country = named[2].upper()
        if location and location.replace('UK', 'GB') != named_country.replace('UK', 'GB'):
            raise ProviderError('ProxyWing: страна тарифа противоречит его названию')
        location = location or named_country
        if quantity is not None and quantity != int(named[1]):
            raise ProviderError('ProxyWing: размер пакета противоречит названию тарифа')
        quantity = int(named[1])
    country = ('gb' if location == 'UK' else location.lower()) if re.fullmatch('[A-Z]{2}', location) else ''
    if location == 'EU':
        country = ''  # Regional bundles do not identify the country being purchased.
    return country, quantity


def _ip_version(value):
    try:
        return ipaddress.ip_address(str(value)).version
    except ValueError:
        return 4


def norm_proxywing(proxy, order, family):
    """Один proxy из GET /{datacenter|isp}/proxies -> контракт пула.

    ext_id включает семейство, заказ и сам прокси: order стабилен, но один заказ
    может содержать несколько IP. Разделитель ``|`` безопасен для SQLite/URL и
    не конфликтует с ``provider:ext_id``, из которого pool собирает uid.
    """
    host = str(proxy.get("ip") or "")
    order_id = str(order.get("id") or "")
    proxy_id = str(proxy.get("id") or "")
    location = proxy.get("location") or order.get("location") or ""
    expires = proxy.get("expires_at") or order.get("expires_at") or ""
    return {
        "provider": "proxywing",
        "ext_id": "%s|%s|%s" % (family, order_id, proxy_id),
        "ip": host,
        "host": host,
        "port_http": proxy.get("http_port") or None,
        "port_socks5": proxy.get("socks_port") or None,
        "user": proxy.get("username") or "",
        "password": proxy.get("password") or "",
        "country": str(location).lower(),
        "ip_version": _ip_version(host),
        "kind": "dedicated",
        "date_end": expires,
        "descr": "%s %s" % (family, order_id),
    }


class ProxyWing(Provider):
    name = "proxywing"
    caps = capabilities()
    monthly_orders = True
    min_interval = 0.11                 # API: 600 запросов/мин с одного IP

    def _api(self, path):
        def request():
            return http_get_json(
                API_BASE + path,
                headers={"Authorization": "Bearer " + self.api_key},
                host_label=HOST_LABEL,
            ) or {}
        return self._guarded(path, request)

    def _post(self, path, body, request_id, on_submit=None):
        """Submit exactly the caller's durable idempotency key after journaling."""
        if not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{8,128}', request_id):
            raise ProviderError('ProxyWing: нужен стабильный Idempotency-Key')
        def request():
            if on_submit is not None:
                on_submit()
            return http_post_json(API_BASE + path, body,
                headers={'Authorization': 'Bearer ' + self.api_key, 'Idempotency-Key': request_id},
                host_label=HOST_LABEL, mutating=True)
        return self._guarded(path, request)

    def order_service(self, family, order_id):
        """Resolve an exact singleton order/service through service_id, never IP.

        Read both proxy families to exclude other orders sharing the service;
        require one proxy, one matching active monthly account service and a real
        billing deadline. Account services[].family is a product group label
        (e.g. "Proxy UK"), NOT the datacenter/isp API family enum.
        """
        family_name(family)
        identifier(order_id)
        data = self._api('/%s/proxies' % family)
        if (not isinstance(data, dict) or not isinstance(data.get('orders'), list)
                or any(not isinstance(r, dict) for r in data['orders'])):
            raise ProviderError('ProxyWing: неполный список заказов')
        orders = [r for r in data['orders'] if r.get('id') == order_id]
        if len(orders) != 1:
            raise ProviderError('ProxyWing: заказ не определён однозначно')
        proxies = orders[0].get('proxies')
        if (not isinstance(proxies, list) or len(proxies) != 1
                or not isinstance(proxies[0], dict)):
            raise ProviderError('ProxyWing: автоплатёж разрешён только для услуги с одним боевым прокси', code='auto-renew-scope')
        proxy_id = identifier(proxies[0].get('id'))
        service_id = identifier(orders[0].get('service_id'))
        if sum(r.get('service_id') == service_id for r in data['orders']) != 1:
            raise ProviderError('ProxyWing: связь заказа и услуги неоднозначна', code='auto-renew-scope')
        other_family = next(name for name in FAMILIES if name != family)
        other = self._api('/%s/proxies' % other_family)
        if (not isinstance(other, dict) or not isinstance(other.get('orders'), list)
                or any(not isinstance(r, dict) for r in other['orders'])
                or any(r.get('service_id') == service_id for r in other['orders'])):
            raise ProviderError('ProxyWing: не доказана единственная связь услуги с боевым заказом', code='auto-renew-scope')
        data = self._api('/account/services')
        if (not isinstance(data, dict) or not isinstance(data.get('services'), list)
                or any(not isinstance(r, dict) for r in data['services'])):
            raise ProviderError('ProxyWing: неполный список услуг')
        services = [r for r in data['services'] if r.get('id') == service_id]
        if len(services) != 1:
            raise ProviderError('ProxyWing: услуга не определена однозначно')
        if services[0].get('status') != 'active' or services[0].get('billing_cycle') != 'monthly':
            raise ProviderError('ProxyWing: нужна активная месячная услуга')
        billing_date(services[0].get('next_due_date'))
        return dict(services[0], service_id=service_id, order_id=order_id, family=family,
                    proxy_id=proxy_id, proxy_count=1)

    def get_auto_renew(self, service_id):
        """Read the exact service-scoped switch; it is not a payment receipt."""
        service_id = identifier(service_id)
        data = self._api('/account/services/%s/auto-renew' % service_id)
        return self._auto_renew_response(data, service_id)

    @staticmethod
    def _auto_renew_response(data, service_id):
        if (not isinstance(data, dict) or data.get('service_id') != service_id
                or type(data.get('enabled')) is not bool):
            raise ProviderError('ProxyWing: настройка автоплатежа не подтверждена')
        return {'service_id': service_id, 'enabled': data['enabled']}

    def set_auto_renew(self, service_id, enabled, on_submit=None):
        """Set one boolean only; caller journals ownership and verifies with a fresh GET."""
        service_id = identifier(service_id)
        if type(enabled) is not bool:
            raise ProviderError('ProxyWing: enabled должен быть bool')
        path = '/account/services/%s/auto-renew' % service_id
        def request():
            if on_submit is not None:
                on_submit()
            data = http_put_json(API_BASE + path, {'enabled': enabled},
                headers={'Authorization': 'Bearer ' + self.api_key},
                host_label=HOST_LABEL, mutating=True)
            result = self._auto_renew_response(data, service_id)
            if result['enabled'] is not enabled:
                raise ProviderError('ProxyWing: API подтвердил другую настройку автоплатежа')
            return result
        return self._guarded(path, request)

    def catalog(self, family=None):
        """Return family-specific IDs, package sizes and published monthly prices."""
        out = []
        for name in (FAMILIES if family is None else (family_name(family),)):
            data = self._api('/%s/products' % name)
            if not isinstance(data, dict) or not isinstance(data.get('products'), list):
                raise ProviderError('ProxyWing: неполный ответ каталога')
            for row in data['products']:
                if not isinstance(row, dict) or row.get('category', name) != name:
                    raise ProviderError('ProxyWing: некорректная категория товара')
                if str(row.get('ip_version', row.get('version', 4))) != '4':
                    continue
                country, quantity = product_location(row, name)
                if quantity is not None and (type(quantity) is not int or quantity < 1):
                    raise ProviderError('ProxyWing: некорректный размер пакета')
                out.append({'product_id': identifier(row.get('product_id')), 'family': name,
                    'name': str(row.get('name') or row.get('location') or row.get('product_id')),
                    'group': str(row.get('group') or ''), 'country': country,
                    'quantity': quantity, 'price_monthly': amount(row.get('price_monthly')),
                    'currency': 'USD'})
        return out

    def renewal_options(self, family, order_id):
        """Read the real quote for extending the whole order, in calendar months."""
        path = '/%s/orders/%s/renewal-options' % (family_name(family), identifier(order_id))
        data = self._api(path)
        if (not isinstance(data, dict) or data.get('order_id') != order_id
                or not isinstance(data.get('options'), list)):
            raise ProviderError('ProxyWing: неполный ответ условий продления')
        options = []
        for item in data['options']:
            if not isinstance(item, dict) or type(item.get('months')) is not int or item['months'] not in MONTHS:
                raise ProviderError('ProxyWing: некорректный срок продления')
            if item['months'] in [x['months'] for x in options]:
                raise ProviderError('ProxyWing: неоднозначные цены продления')
            options.append({'months': item['months'], 'total': amount(item.get('total'))})
        if not options:
            raise ProviderError('ProxyWing: продление заказа через API недоступно')
        return {'order_id': order_id, 'next_due_date': data.get('next_due_date'),
                'options': options, 'currency': 'USD'}

    def order_product(self, family, product_id, billing_cycle, request_id, on_submit=None):
        """Buy a product on the explicit monthly cycle whose price is published."""
        if billing_cycle != 'monthly':
            raise ProviderError('ProxyWing: новая покупка поддерживает месячный тариф')
        return self._post('/%s/orders' % family_name(family),
            {'product_id': identifier(product_id), 'billing_cycle': billing_cycle}, request_id, on_submit)

    def extend_order(self, family, order_id, months, request_id, on_submit=None):
        """Extend the entire order, never multiply a charge by the number of IPs."""
        if type(months) is not int or months not in MONTHS:
            raise ProviderError('ProxyWing: срок продления — 1, 3, 6 или 12 месяцев')
        return self._post('/%s/orders/%s/extend' % (family_name(family), identifier(order_id)),
            {'cycle': months, 'cycle_type': 'monthly'}, request_id, on_submit)

    def list(self):
        """Require complete family snapshots before allowing the pool to remove rows."""
        out = []
        for family in FAMILIES:
            data = self._api("/%s/proxies" % family)
            if not isinstance(data, dict) or not isinstance(data.get("orders"), list):
                raise ProviderError('ProxyWing: неполный список заказов')
            for order in data["orders"]:
                if not isinstance(order, dict):
                    raise ProviderError('ProxyWing: некорректная запись заказа')
                identifier(order.get("id"))
                status = order.get("status")
                if status is not None and not isinstance(status, str):
                    raise ProviderError('ProxyWing: некорректный статус заказа')
                if (status or "").lower() not in ("", "active"):
                    continue
                if not isinstance(order.get("proxies"), list):
                    raise ProviderError('ProxyWing: неполный список прокси заказа')
                for proxy in order["proxies"]:
                    if not isinstance(proxy, dict):
                        raise ProviderError('ProxyWing: некорректная запись прокси')
                    identifier(proxy.get("id"))
                    item = norm_proxywing(proxy, order, family)
                    if not item["host"] or not (item["port_http"] or item["port_socks5"]):
                        raise ProviderError('ProxyWing: неполные параметры подключения прокси')
                    out.append(item)
        return out

    def balance(self):
        data = self._api("/account/balance")
        return {"balance": data.get("balance"), "currency": data.get("currency")}
