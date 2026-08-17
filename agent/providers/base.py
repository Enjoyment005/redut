# -*- coding: utf-8 -*-
"""Интерфейс адаптера провайдера прокси + общий HTTP-хелпер (только stdlib).

Единственное, что знают ядро и панель о провайдере, — этот интерфейс (§4 плана).
Нормализованный прокси — dict с ключами:
    provider, ext_id, ip, host, port_http, port_socks5, user, password,
    country, ip_version, kind (dedicated|shared), date_end (ISO), descr
uid = f"{provider}:{ext_id}" собирает pool.py.
"""
import json
import os
import subprocess
import time
import socket
import urllib.request
import urllib.error
import urllib.parse

USER_AGENT = "vpn-agent/1.0"
HTTP_TIMEOUT = 25

# ── Транспорт к API провайдера: напрямую или через СОБСТВЕННЫЙ канал узла (tun0) ────────
# Найдено на приёмке 15.08 (снос №4): с российского VPS домены PROXY6 (proxy6.net, px6.link)
# недоступны напрямую — TLS-рукопожатие рвётся (SNI-блокировка), а через канал узла
# (curl --interface tun0 -> sing-box -> upstream) API отвечает за секунду. Поэтому:
#   * по умолчанию ходим напрямую; если напрямую «нет связи», а у узла есть живой канал —
#     повторяем через tun0 и запоминаем рабочий транспорт (в процессе + подсказка в /run,
#     чтобы следующий запуск агента из cron не жёг таймауты заново);
#   * ДЕНЬГИ (mutating=True: buy/prolong/delete): повтор другим транспортом допустим ТОЛЬКО
#     если запрос заведомо не был доставлен (ошибка на этапе соединения/TLS/отправки —
#     urllib поднимает URLError, curl — коды 6/7/35). Таймаут ЧТЕНИЯ ответа = «запрос мог
#     пройти, ответ потерян» → повтора нет, как и раньше (иначе двойная покупка §6.2).
TRANSPORT_HINT = "/run/vpn-agent-provider-transport"
TRANSPORT_HINT_TTL = 3600
_transport = {"pref": None}     # None -> прочитать подсказку; "direct" | "tun0"


def _tun0_alive():
    """Есть ли живой собственный канал: tun0 с carrier и узел НЕ в аварийном режиме
    (в аварии клиенты идут напрямую, а sing-box без upstream — через tun0 ходить некуда)."""
    try:
        with open("/sys/class/net/tun0/carrier") as f:
            if f.read().strip() != "1":
                return False
    except OSError:
        return False
    return not os.path.exists("/run/vpn-agent-emergency")


def _read_hint():
    try:
        with open(TRANSPORT_HINT, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("transport") in ("direct", "tun0") and time.time() - float(d.get("ts") or 0) < TRANSPORT_HINT_TTL:
            return d["transport"]
    except (OSError, ValueError, TypeError):
        pass
    return None


def _write_hint(transport):
    try:
        tmp = TRANSPORT_HINT + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"transport": transport, "ts": time.time()}, f)
        os.replace(tmp, TRANSPORT_HINT)
    except OSError:
        pass


def preferred_transport():
    """Текущее предпочтение. «tun0» держим в памяти процесса; «direct» каждый раз сверяем
    с подсказкой в /run — долгоживущая панель так подхватывает открытие агента из cron
    (иначе она узнала бы о блокировке только после собственных таймаутов)."""
    if _transport["pref"] in (None, "direct"):
        _transport["pref"] = _read_hint() or "direct"
    return _transport["pref"]


def set_transport(transport, persist=True):
    if _transport["pref"] != transport:
        _transport["pref"] = transport
        if persist:
            _write_hint(transport)


def reset_transport_for_tests():
    _transport["pref"] = None

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

# ВНУТРЕННИЙ порядок предпочтения стран, по возрастанию задержки из РФ. Это НЕ
# жёсткий фильтр и НЕ пользовательский «белый список» (его больше нет — приёмка №7,
# 17.08): покупать вручную можно в любой стране вне чёрного списка, автопокупку
# гейтит внутренний рейтинг (country.auto_allowed), а этот кортеж лишь даёт
# tie-break «при равном рейтинге — ближняя страна раньше».
DEFAULT_COUNTRY_ORDER = ("fi", "ee", "lv", "lt", "se", "de", "nl", "pl", "cz",
                         "at", "ch", "gb", "fr", "it", "es", "us", "ca")
DEFAULT_WHITELIST_CC = DEFAULT_COUNTRY_ORDER   # старое имя — для совместимости импортов


class ProviderError(Exception):
    """Ошибка API провайдера.

    code    — числовой код ошибки провайдера (error_id у PROXY6), если есть;
    network — True, если это сетевая недоступность (для перебора запасных доменов);
    unsent  — True, если запрос заведомо НЕ был доставлен (ошибка соединения/TLS/отправки):
              такой вызов безопасно повторить другим транспортом даже для денег.
    """

    def __init__(self, message, code=None, network=False, unsent=False):
        super().__init__(message)
        self.code = code
        self.network = network
        self.unsent = unsent


def _http_error(host_label, status, body):
    """Единая расшифровка HTTP-ошибки (для urllib и curl-транспорта)."""
    data = None
    try:
        data = json.loads(body) if body else None
    except ValueError:
        pass
    msg = "HTTP %s" % status
    if isinstance(data, dict):
        # ProxyLine отдаёт ошибки вида {"field": ["msg"], "detail": "..."}
        parts = []
        for field, errs in data.items():
            text = ", ".join(str(x) for x in errs) if isinstance(errs, list) else str(errs)
            parts.append(text if field in ("detail", "non_field_errors") else "%s: %s" % (field, text))
        if parts:
            msg = "; ".join(parts)
    if status in (401, 403):
        msg = "API-ключ не принят (%s)" % msg
    if status == 429:
        msg = "Превышен лимит запросов к API — подождите"
    return ProviderError("%s: %s" % (host_label or "API", msg), code=status)


def _urlopen_json(req, host_label, timeout):
    """Общая обработка ответа/ошибок для GET и POST (прямой транспорт, urllib).

    В сообщениях ошибок URL не фигурирует (у PROXY6 в пути лежит ключ) —
    только host_label, который передаёт вызывающий.
    URLError = ошибка ДО получения ответа (DNS/соединение/TLS/отправка: urllib оборачивает
    исключения h.request()) -> unsent=True; сырые OSError/timeout — уже при чтении ответа.
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
        raise _http_error(host_label, e.code, body) from None
    except urllib.error.URLError as e:
        why = getattr(e, "reason", None) or e
        raise ProviderError("Нет связи с %s (%s)" % (host_label or "API", why), network=True, unsent=True) from None
    except (socket.timeout, OSError) as e:
        raise ProviderError("Нет связи с %s (%s)" % (host_label or "API", e), network=True) from None
    try:
        return json.loads(body) if body else None
    except ValueError:
        raise ProviderError("%s: ответ не JSON" % (host_label or "API")) from None


# curl: коды, при которых запрос заведомо не ушёл (DNS / connect / TLS-рукопожатие)
_CURL_UNSENT = {6, 7, 35}


def _curl_json(url, headers, form_fields, host_label, timeout):
    """Тот же запрос через СОБСТВЕННЫЙ канал узла: curl --interface tun0 (sing-box -> upstream)."""
    cmd = ["curl", "-sS", "--interface", "tun0", "-m", str(int(timeout)), "-A", USER_AGENT,
           "-o", "-", "-w", "\n__HTTP__%{http_code}"]
    for k, v in (headers or {}).items():
        cmd += ["-H", "%s: %s" % (k, v)]
    if form_fields is not None:
        cmd += ["-X", "POST"]
        for k, v in urllib.parse.parse_qsl(urllib.parse.urlencode(form_fields or {}, doseq=True)):
            cmd += ["--data-urlencode", "%s=%s" % (k, v)]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except (OSError, subprocess.SubprocessError) as e:
        raise ProviderError("Нет связи с %s через канал узла (%s)" % (host_label or "API", e),
                            network=True, unsent=True) from None
    if p.returncode != 0:
        raise ProviderError("Нет связи с %s через канал узла (curl %s)" % (host_label or "API", p.returncode),
                            network=True, unsent=p.returncode in _CURL_UNSENT)
    out = p.stdout or ""
    body, _, code = out.rpartition("\n__HTTP__")
    try:
        status = int(code.strip() or 0)
    except ValueError:
        status = 0
    if status >= 400:
        raise _http_error(host_label, status, body)
    if status == 0:
        raise ProviderError("Нет связи с %s через канал узла (нет ответа)" % (host_label or "API"), network=True)
    try:
        return json.loads(body) if body else None
    except ValueError:
        raise ProviderError("%s: ответ не JSON" % (host_label or "API")) from None


def _request_json(url, headers, form_fields, timeout, host_label, mutating):
    """Запрос предпочтительным транспортом; при «нет связи» — другим, если это безопасно.

    direct -> tun0: если tun0 жив; для mutating — только при unsent (запрос не доставлен).
    tun0 -> direct: симметрично (канал умер — вернуться к прямому доступу).
    Успех другим транспортом переключает предпочтение (память процесса + подсказка в /run).
    """
    order = ["direct", "tun0"] if preferred_transport() == "direct" else ["tun0", "direct"]
    last = None
    for i, tr in enumerate(order):
        if tr == "tun0" and not _tun0_alive():
            continue
        try:
            if tr == "direct":
                if form_fields is None:
                    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
                else:
                    data = urllib.parse.urlencode(form_fields or {}, doseq=True).encode("utf-8")
                    req = urllib.request.Request(
                        url, data=data, method="POST",
                        headers={"User-Agent": USER_AGENT,
                                 "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                                 **(headers or {})})
                data = _urlopen_json(req, host_label, timeout)
            else:
                data = _curl_json(url, headers, form_fields, host_label, timeout)
        except ProviderError as e:
            if not e.network:
                raise                       # ответ API получен (HTTP-ошибка) — транспорт ни при чём
            last = e
            if mutating and not e.unsent:
                raise                       # деньги: ответ мог потеряться — повтор запрещён (§6.2)
            continue
        if i > 0:                           # заработал запасной транспорт — запомнить
            set_transport(tr)
        return data
    if last is None:
        raise ProviderError("Нет связи с %s (канал узла недоступен)" % (host_label or "API"), network=True, unsent=True)
    raise last


def http_get_json(url, headers=None, timeout=HTTP_TIMEOUT, host_label="", mutating=False):
    """GET url -> распарсенный JSON (напрямую или через канал узла — см. _request_json)."""
    return _request_json(url, headers, None, timeout, host_label, mutating)


def http_post_form(url, fields, headers=None, timeout=HTTP_TIMEOUT, host_label="", mutating=False):
    """POST application/x-www-form-urlencoded -> распарсенный JSON.

    Списки кодируются повтором ключа (doseq): {"proxies":[15,16]} -> proxies=15&proxies=16
    — как в расширении (plApi: URLSearchParams.append) для /api/renew/ ProxyLine.
    """
    return _request_json(url, headers, fields or {}, timeout, host_label, mutating)


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
