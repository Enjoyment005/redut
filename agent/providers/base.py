# -*- coding: utf-8 -*-
"""Интерфейс адаптера провайдера прокси + общий HTTP-хелпер (только stdlib).

Единственное, что знают ядро и панель о провайдере, — этот интерфейс (§4 плана).
Нормализованный прокси — dict с ключами:
    provider, ext_id, ip, host, port_http, port_socks5, user, password,
    country, ip_version, kind (dedicated|shared), date_end (ISO), descr
uid = f"{provider}:{ext_id}" собирает pool.py.
"""
import json
import time
import socket
import urllib.request
import urllib.error
import urllib.parse

USER_AGENT = "vpn-agent/1.0"
HTTP_TIMEOUT = 25

# ЧЁРНЫЙ СПИСОК СТРАН (§6.1) — предохранитель В КОДЕ, из панели/настроек НЕ
# редактируется и не сужается. Покупка и использование выхода в эти страны
# отклоняются на уровне провайдера. Источник истины — country.BLACKLIST_CC;
# probe.HARD_BLOCK_CC держит независимую копию для проверки страны выхода;
# tests/test_provider_money.py сверяет, что копии не разошлись (§6.1).
#
# 2026-08-15 (решение владельца): список сужен с «всего СНГ» до Россия/Украина/
# Беларусь. Бывшие в нём kz/kg/tj/uz/tm/am/az/md/ge не запрещены, но получают
# низкую оценку в country.LOW_TRUST_CC — сама автоматика их не купит.
HARD_BLOCK_CC = frozenset({"ru", "ua", "by"})

# Предпочитаемые страны (§6.1), по возрастанию задержки из РФ. Это НЕ жёсткий
# фильтр: с 2026-08-15 покупать можно в любой стране вне чёрного списка, а порядок
# выбора определяет умная оценка (country.rank). Список остаётся подсказкой
# «начни отсюда» и живёт в /etc/vpn-panel/config.json → countries.whitelist.
DEFAULT_WHITELIST_CC = ("fi", "ee", "lv", "lt", "se", "de", "nl", "pl", "cz",
                        "at", "ch", "gb", "fr", "it", "es", "us", "ca")


class ProviderError(Exception):
    """Ошибка API провайдера.

    code    — числовой код ошибки провайдера (error_id у PROXY6), если есть;
    network — True, если это сетевая недоступность (для перебора запасных доменов).
    """

    def __init__(self, message, code=None, network=False):
        super().__init__(message)
        self.code = code
        self.network = network


def _urlopen_json(req, host_label, timeout):
    """Общая обработка ответа/ошибок для GET и POST.

    В сообщениях ошибок URL не фигурирует (у PROXY6 в пути лежит ключ) —
    только host_label, который передаёт вызывающий.
    """
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        data = None
        try:
            data = json.loads(body) if body else None
        except ValueError:
            pass
        msg = "HTTP %s" % e.code
        if isinstance(data, dict):
            # ProxyLine отдаёт ошибки вида {"field": ["msg"], "detail": "..."}
            parts = []
            for field, errs in data.items():
                text = ", ".join(str(x) for x in errs) if isinstance(errs, list) else str(errs)
                parts.append(text if field in ("detail", "non_field_errors") else "%s: %s" % (field, text))
            if parts:
                msg = "; ".join(parts)
        if e.code in (401, 403):
            msg = "API-ключ не принят (%s)" % msg
        if e.code == 429:
            msg = "Превышен лимит запросов к API — подождите"
        raise ProviderError("%s: %s" % (host_label or "API", msg), code=e.code) from None
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        why = getattr(e, "reason", None) or e
        raise ProviderError("Нет связи с %s (%s)" % (host_label or "API", why), network=True) from None
    try:
        return json.loads(body) if body else None
    except ValueError:
        raise ProviderError("%s: ответ не JSON" % (host_label or "API")) from None


def http_get_json(url, headers=None, timeout=HTTP_TIMEOUT, host_label=""):
    """GET url -> распарсенный JSON."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    return _urlopen_json(req, host_label, timeout)


def http_post_form(url, fields, headers=None, timeout=HTTP_TIMEOUT, host_label=""):
    """POST application/x-www-form-urlencoded -> распарсенный JSON.

    Списки кодируются повтором ключа (doseq): {"proxies":[15,16]} -> proxies=15&proxies=16
    — как в расширении (plApi: URLSearchParams.append) для /api/renew/ ProxyLine.
    """
    data = urllib.parse.urlencode(fields or {}, doseq=True).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": USER_AGENT,
                 "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                 **(headers or {})})
    return _urlopen_json(req, host_label, timeout)


def build_query(params):
    """Собрать query string, выкидывая None/пустые значения (как в расширении)."""
    clean = {}
    for k, v in (params or {}).items():
        if v is None or v == "":
            continue
        clean[k] = v
    return urllib.parse.urlencode(clean, doseq=True)


class Provider:
    """Базовый адаптер. Флаги возможностей — caps (§4).

    В фазе 1 реализованы только read-only методы (list/balance/check).
    Методы с деньгами (buy/prolong/delete) объявлены, но поднимают
    NotImplementedError до фазы 2 — даже там, где caps=True.
    """

    name = "base"
    caps = {"buy": False, "delete": False, "prolong": False, "check": False}
    min_interval = 0.0  # секунды между запросами (лимиты API)

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("%s: пустой API-ключ" % self.name)
        self.api_key = api_key
        self._last_request = 0.0

    def _throttle(self):
        if self.min_interval <= 0:
            return
        wait = self._last_request + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    # --- интерфейс ---
    def list(self):
        """-> list[dict] нормализованных активных прокси."""
        raise NotImplementedError

    def balance(self):
        """-> {"balance": float|str, "currency": str, ...}"""
        raise NotImplementedError

    def buy(self, count, period, country, version=4, descr=None, allow_cc=None):
        raise NotImplementedError("%s.buy не поддерживается" % self.name)

    def delete(self, ids):
        # delete по descr запрещён навсегда (§5) — сигнатура принимает только ids.
        raise NotImplementedError("%s.delete не поддерживается" % self.name)

    def prolong(self, ids, period):
        raise NotImplementedError("%s.prolong не поддерживается" % self.name)

    def check(self, ext_id):
        """Проверка на стороне провайдера. -> bool"""
        raise NotImplementedError
