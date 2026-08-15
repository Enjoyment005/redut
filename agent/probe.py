# -*- coding: utf-8 -*-
"""Проба кандидата: матрица порт×протокол + качество + скоринг (§7).

Всё через системный curl, subprocess СПИСКОМ аргументов (§15: креды со
спецсимволами не должны попадать в шелл-строку — шелла здесь нет вовсе).

Качество (§7.2): exit-IP (ipify), страна выхода (жёсткий блок СНГ §6.1),
Telegram-проба (CONNECT по домену), латентность = медиана 3.
Для PROXY6 перед матрицей — дешёвый check?ids= (отсеивает труп одним запросом).
"""
import json
import re
import statistics
import subprocess
import urllib.request

import country

# ЧЁРНЫЙ СПИСОК СТРАН (§6.1) — предохранитель в коде, из панели/настроек НЕ редактируется.
# Никогда не покупать и не использовать выходы в этих странах. С 2026-08-15 (решение
# владельца) это Россия/Украина/Беларусь; прочие страны не блокируются, а оцениваются
# модулем country (репутация + сходимость geoip-баз) — см. score() ниже.
HARD_BLOCK_CC = frozenset({"ru", "ua", "by"})

CURL = "curl"
IPIFY_URL = "https://api.ipify.org"
TG_URL = "https://api.telegram.org"     # проба CONNECT по домену (§7.2 п.3)
LAT_URL = "https://www.gstatic.com/generate_204"
CURL_TIMEOUT = 12
GEO_TIMEOUT = 8

_RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_ipv4(s):
    return bool(_RE_IPV4.match((s or "").strip()))


def looks_like_ip(s):
    """IPv4 или IPv6 (у PROXY6 version=6 выход — IPv6, ipify вернёт его)."""
    s = (s or "").strip()
    if is_ipv4(s):
        return True
    return ":" in s and bool(re.fullmatch(r"[0-9a-fA-F:]+", s))


def _run_curl(args, timeout=CURL_TIMEOUT):
    """curl списком аргументов -> (rc, stdout). Никаких shell-строк."""
    try:
        p = subprocess.run([CURL, "-s", "--max-time", str(timeout)] + list(args),
                           capture_output=True, text=True, timeout=timeout + 8)
        return p.returncode, (p.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError):
        return -1, ""


def _proxy_args(proto, host, port, user, password):
    """Аргументы curl для прохода через кандидата указанным протоколом."""
    cred = ["--proxy-user", "%s:%s" % (user, password)] if user or password else []
    if proto == "socks":
        return ["--socks5-hostname", "%s:%s" % (host, port)] + cred
    return ["-x", "http://%s:%s" % (host, port)] + cred


def fetch_via(proto, host, port, user, password, url, timeout=CURL_TIMEOUT):
    rc, out = _run_curl(_proxy_args(proto, host, port, user, password) + [url], timeout)
    return out if rc == 0 else ""


def http_code_via(proto, host, port, user, password, url, timeout=CURL_TIMEOUT):
    """Код ответа через кандидата; '000' = не достучались (в т.ч. отказ CONNECT)."""
    rc, out = _run_curl(_proxy_args(proto, host, port, user, password)
                        + ["-o", "/dev/null" if _posix() else "NUL", "-w", "%{http_code}", url],
                        timeout)
    return out if rc == 0 and out else "000"


def time_total_via(proto, host, port, user, password, url, timeout=CURL_TIMEOUT):
    """Полное время запроса, секунды float, либо None."""
    rc, out = _run_curl(_proxy_args(proto, host, port, user, password)
                        + ["-o", "/dev/null" if _posix() else "NUL", "-w", "%{time_total}", url],
                        timeout)
    if rc == 0 and out:
        try:
            return float(out.replace(",", "."))
        except ValueError:
            return None
    return None


def _posix():
    import os
    return os.name == "posix"


def geo_country(ip):
    """Страна exit-IP (двухбуквенный код, lower) или None.

    Запрос идёт НАПРЯМУЮ с сервера (не через кандидата): ip-api.com,
    фолбэк ipinfo.io. Не смогли узнать — None (неизвестность не равна блоку).
    """
    if not ip:
        return None
    for url in (_GEO_PRIMARY, _GEO_SECONDARY):
        cc = _geo_ask(url % ip)
        if cc:
            return cc
    return None


_GEO_PRIMARY = "http://ip-api.com/line/%s?fields=countryCode"
_GEO_SECONDARY = "https://ipinfo.io/%s/country"


def _geo_ask(url):
    try:
        with urllib.request.urlopen(url, timeout=GEO_TIMEOUT) as r:
            cc = r.read().decode("ascii", "replace").strip().lower()
    except Exception:
        return None
    return cc if re.fullmatch(r"[a-z]{2}", cc or "") else None


def geo_country_consensus(ip):
    """Страна exit-IP по ДВУМ независимым базам сразу -> {cc, alt, agree}.

    Зачем спрашивать обе: у перепроданных диапазонов базы расходятся. Реальный
    случай 2026-08-15 — `203.0.113.77`: ip-api видит Нигерию, ipinfo Нью-Йорк.
    Сайты пользуются разными базами, поэтому для них «страна скачет» — типовая
    реакция антифрода: капчи и отказы оплаты. Расхождение (agree=False) не
    дисквалифицирует прокси, но снижает его оценку (см. country.rating).

    Обе базы молчат -> {cc: None, alt: None, agree: True}: незнание страны — это
    не расхождение, штрафовать не за что.
    """
    if not ip:
        return {"cc": None, "alt": None, "agree": True}
    cc = _geo_ask(_GEO_PRIMARY % ip)
    alt = _geo_ask(_GEO_SECONDARY % ip)
    agree = not (cc and alt and cc != alt)
    return {"cc": cc or alt, "alt": alt, "agree": agree}


def probe_matrix(host, ports, user, password):
    """Каждый порт-кандидат прогоняется ОБОИМИ протоколами (§7.2).

    -> {(port, "socks"|"http"): exit_ip|None}
    """
    matrix = {}
    for port in ports:
        for proto in ("socks", "http"):
            out = fetch_via(proto, host, port, user, password, IPIFY_URL)
            matrix[(port, proto)] = out if looks_like_ip(out) else None
    return matrix


def probe(proxy, provider_check=None, latency_runs=3):
    """Полная проба кандидата (dict из pool) -> результат для record_probe.

    proxy: нужны host, port_socks5, port_http, user, password.
    provider_check: callable()->bool — дешёвый check?ids= у PROXY6 до матрицы.
    """
    host = proxy.get("host") or proxy.get("ip")
    user, password = proxy.get("user") or "", proxy.get("password") or ""
    res = {
        "ok": False, "disqualified": None, "matrix": {},
        "socks_ok": False, "http_ok": False,
        "socks_port": None, "http_port": None,
        "exit_ip": None, "exit_cc": None, "tg_ok": False, "latency_ms": None,
        "provider_check": None,
    }

    # 0. (PROXY6) check?ids= — 1 дешёвый запрос отсеивает труп (§7.2 п.5)
    if provider_check is not None:
        try:
            alive = bool(provider_check())
            res["provider_check"] = alive
            if not alive:
                res["disqualified"] = "provider-check-dead"
                return res
        except Exception as e:
            res["provider_check"] = "error: %s" % e  # ошибка API не блокирует пробу

    ports = [p for p in dict.fromkeys([proxy.get("port_socks5"), proxy.get("port_http")]) if p]
    if not host or not ports:
        res["disqualified"] = "no-host-or-ports"
        return res

    # 1. матрица порт×протокол
    matrix = probe_matrix(host, ports, user, password)
    res["matrix"] = {"%s/%s" % (port, proto): ip for (port, proto), ip in matrix.items()}
    socks_ports = [port for (port, proto), ip in matrix.items() if proto == "socks" and ip]
    http_ports = [port for (port, proto), ip in matrix.items() if proto == "http" and ip]
    res["socks_ok"], res["http_ok"] = bool(socks_ports), bool(http_ports)

    # порт из паспорта прокси — приоритетная подсказка, но не обязательство
    ps, ph = proxy.get("port_socks5"), proxy.get("port_http")
    res["socks_port"] = ps if ps in socks_ports else (socks_ports[0] if socks_ports else None)
    res["http_port"] = ph if ph in http_ports else (http_ports[0] if http_ports else None)

    if not socks_ports and not http_ports:
        res["disqualified"] = "no-combo"  # не работает ни одна комбинация — дисквалификация
        return res

    # основная комбинация: как socks-out (§7.3 — SOCKS5 предпочтителен)
    main = ("socks", res["socks_port"]) if res["socks_port"] else ("http", res["http_port"])
    res["exit_ip"] = matrix[(main[1], main[0])]

    # 2. страна выхода: чёрный список §6.1 (реальная страна, не метка провайдера).
    #    Спрашиваем две базы: расхождение само по себе портит репутацию IP (§оценка).
    geo = geo_country_consensus(res["exit_ip"])
    res["exit_cc"], res["exit_cc_alt"], res["geo_agree"] = geo["cc"], geo["alt"], geo["agree"]
    if res["exit_cc"] in HARD_BLOCK_CC or (res["exit_cc_alt"] or "") in HARD_BLOCK_CC:
        res["disqualified"] = "blocked-cc:%s" % (res["exit_cc"] or res["exit_cc_alt"])
        return res

    # 3. Telegram: через комбинацию, которая пойдёт в http-tg (HTTP предпочтителен)
    tg = ("http", res["http_port"]) if res["http_port"] else ("socks", res["socks_port"])
    code = http_code_via(tg[0], host, tg[1], user, password, TG_URL)
    res["tg_code"] = code
    res["tg_ok"] = code != "000" and code.isdigit() and 200 <= int(code) <= 499

    # 4. латентность — медиана 3 запросов через основную комбинацию
    times = []
    for _ in range(latency_runs):
        t = time_total_via(main[0], host, main[1], user, password, LAT_URL)
        if t is not None:
            times.append(t)
    if times:
        res["latency_ms"] = int(statistics.median(times) * 1000)

    res["ok"] = True
    return res


def score(row, res, is_current=False):
    """Скоринг §7.4. None = дисквалификация."""
    if not res.get("ok"):
        return None
    s = 100.0
    if res.get("latency_ms") is not None:
        s -= min(res["latency_ms"] / 10.0, 40.0)
    s -= int(row.get("fail_count") or 0) * 15  # история провалов до этой пробы
    if res.get("tg_ok"):
        s += 20
    if res.get("socks_ok") and res.get("http_ok"):
        s += 15  # есть куда откатиться без смены IP (RETUNE)
    if row.get("kind") == "dedicated" and int(row.get("ip_version") or 4) == 4:
        s += 10
    elif row.get("kind") == "shared":
        s -= 20
    if is_current:
        s += 15  # стикинес: не дёргаться зря
    days = days_left(row.get("date_end"))
    if days is not None and days < 2:
        s -= 30
    # умная оценка страны (2026-08-15): репутация выхода + сходимость geoip-баз.
    # Чёрный список сюда не доходит — он отсекается дисквалификацией выше.
    cr = country.rating(res.get("exit_cc") or row.get("country"),
                        res.get("geo_agree", True))
    if cr is not None:
        s += cr
    return round(s, 1)


def days_left(date_end):
    """Дней до окончания (float) или None. Понимает ISO и 'YYYY-MM-DD HH:MM:SS'."""
    if not date_end:
        return None
    import datetime
    s = str(date_end).strip().replace(" ", "T")
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    now = datetime.datetime.now(dt.tzinfo) if dt.tzinfo else datetime.datetime.now()
    return (dt - now).total_seconds() / 86400.0
