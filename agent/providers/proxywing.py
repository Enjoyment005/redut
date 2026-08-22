# -*- coding: utf-8 -*-
"""ProxyWing — datacenter и ISP прокси через Developer API v1.

Первый безопасный этап интеграции: список уже оплаченных каналов и баланс.
Денежные операции намеренно выключены: ProxyWing продаёт месяцы (1/3/6/12),
а текущая политика Редута оперирует днями и рассчитана на PROXY6. Нельзя молча
превращать автопродление на 7 дней в покупку месяца.
"""
import ipaddress

from .base import Provider, capabilities, http_get_json

API_BASE = "https://api.proxywing.com/v1"
HOST_LABEL = "api.proxywing.com"


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
    min_interval = 0.11                 # API: 600 запросов/мин с одного IP

    def _api(self, path):
        def request():
            return http_get_json(
                API_BASE + path,
                headers={"Authorization": "Bearer " + self.api_key},
                host_label=HOST_LABEL,
            ) or {}
        return self._guarded(path, request)

    def list(self):
        out = []
        for family in ("datacenter", "isp"):
            data = self._api("/%s/proxies" % family)
            for order in data.get("orders") or []:
                if str(order.get("status") or "").lower() not in ("", "active"):
                    continue
                for proxy in order.get("proxies") or []:
                    item = norm_proxywing(proxy, order, family)
                    if item["host"] and (item["port_http"] or item["port_socks5"]):
                        out.append(item)
        return out

    def balance(self):
        data = self._api("/account/balance")
        return {"balance": data.get("balance"), "currency": data.get("currency") or "USD"}
