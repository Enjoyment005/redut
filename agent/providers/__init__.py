# -*- coding: utf-8 -*-
"""Адаптеры провайдеров. Добавить третьего провайдера = один файл (§4)."""
from .base import Provider, ProviderError
from .proxyline import ProxyLine
from .proxy6 import Proxy6
from .proxywing import ProxyWing

PROVIDER_CLASSES = {
    ProxyLine.name: ProxyLine,
    Proxy6.name: Proxy6,
    ProxyWing.name: ProxyWing,
}


def make_providers(secrets):
    """secrets: {"proxyline": {"api_key": "…"}, "proxy6": {"api_key": "…"}}
    -> dict name->Provider только для провайдеров с ключом."""
    out = {}
    for name, cls in PROVIDER_CLASSES.items():
        key = ((secrets or {}).get(name) or {}).get("api_key")
        if key:
            out[name] = cls(key)
    return out
