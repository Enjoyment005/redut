# -*- coding: utf-8 -*-
"""ProxyLine (panel.proxyline.net) — статический резерв (§2, §5).

API: заголовок API-KEY, пагинация results/next, лимит 50 запросов/мин.
Фаза 1: list + balance. Фаза 2: prolong (POST /api/renew/). Купить/удалить
ProxyLine через API нельзя (caps buy/delete=False) — только продлить.
Портировано с common.js (plApi / plFetchAllProxies / plRenew / normProxyline).
"""
import re

from . import base
from .base import Provider, ProviderError, http_get_json, http_post_form, build_query

API_BASE = "https://panel.proxyline.net/api"
HOST_LABEL = "panel.proxyline.net"

_RE_IDS = re.compile(r"^\d+$")


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
    caps = {"buy": False, "delete": False, "prolong": True, "check": False}
    min_interval = 1.3  # 50 req/мин

    def _api(self, path, params=None):
        self._throttle()
        url = API_BASE + path
        qs = build_query(params)
        if qs:
            url += "?" + qs
        return http_get_json(url, headers={"API-KEY": self.api_key}, host_label=HOST_LABEL)

    def list(self):
        out = []
        offset = 0
        while True:
            page = self._api("/proxies/", {"status": "active", "limit": 500, "offset": offset})
            items = (page or {}).get("results") or []
            out.extend(norm_proxyline(x) for x in items)
            if not page or not page.get("next") or not items or len(out) > 20000:
                break
            offset += len(items)
        return out

    def balance(self):
        b = self._api("/balance/") or {}
        return {"balance": b.get("balance"), "currency": "USD", "partner": b.get("partner_balance")}

    def prolong(self, ids, period):
        """Продление: POST /api/renew/ {proxies, period} (form-encoded, §2.1).

        ids -> список внутренних id (только числовые, валидация ДО API §15);
        period — кол-во дней. Возврат — распарсенный ответ + балансовые поля,
        если провайдер их вернул (форма ответа /renew/ в доке не зафиксирована —
        не завязываемся на конкретные ключи, отдаём как есть)."""
        proxies = self._ids_list(ids)
        try:
            period = int(period)
        except (TypeError, ValueError):
            raise ProviderError("ProxyLine.prolong: period=%r не целое" % (period,)) from None
        if not (1 <= period <= 365):
            raise ProviderError("ProxyLine.prolong: period=%d вне 1..365 дней" % period)
        self._throttle()
        r = http_post_form(API_BASE + "/renew/", {"proxies": proxies, "period": period},
                           headers={"API-KEY": self.api_key}, host_label=HOST_LABEL) or {}
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
