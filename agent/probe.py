# -*- coding: utf-8 -*-
"""Проба кандидата: матрица порт×протокол + качество + скоринг (§7).

Всё через системный curl, subprocess СПИСКОМ аргументов (§15: креды со
спецсимволами не должны попадать в шелл-строку — шелла здесь нет вовсе).

Качество (§7.2): exit-IP (ipify), страна выхода (жёсткий блок СНГ §6.1),
Telegram-проба (CONNECT по домену), латентность = медиана 3.
Для PROXY6 перед матрицей — дешёвый check?ids= (отсеивает труп одним запросом).
"""
import json
import datetime
import math
import re
import socket
import statistics
import subprocess
import urllib.request

import country
import health as health_mod

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

DEFAULT_FRESHNESS = {"fresh_seconds": 7200, "stale_seconds": 86400}


def freshness_cfg(cfg=None):
    raw = (cfg or {}).get("health") or {}
    if not isinstance(raw, dict):
        raw = {}
    def seconds(key):
        try:
            if isinstance(raw.get(key, DEFAULT_FRESHNESS[key]), bool):
                raise ValueError
            value = float(raw.get(key, DEFAULT_FRESHNESS[key]))
            if not math.isfinite(value) or value < 0:
                raise ValueError
            return value
        except (TypeError, ValueError, OverflowError):
            return float(DEFAULT_FRESHNESS[key])
    fresh = seconds("fresh_seconds")
    return {"fresh_seconds": fresh,
            "stale_seconds": max(fresh + 1.0, seconds("stale_seconds"))}


def probe_age_seconds(row, now=None):
    value = _rget(row, "last_probe_at")
    if not value:
        return None
    try:
        stamp = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")
                                                .replace(" ", "T"))
        current = now or datetime.datetime.now(stamp.tzinfo)
        if current.tzinfo is None and stamp.tzinfo is not None:
            current = current.replace(tzinfo=stamp.tzinfo)
        delta = (current - stamp).total_seconds()
        if delta < -300:  # небольшой clock skew допустим, далёкое будущее — corrupt
            return None
        return max(0.0, delta)
    except (TypeError, ValueError, OverflowError):
        return None


def freshness_weight(row, cfg=None, now=None):
    age = probe_age_seconds(row, now)
    if age is None:
        return 0.0
    limits = freshness_cfg(cfg)
    if age <= limits["fresh_seconds"]:
        return 1.0
    if age >= limits["stale_seconds"]:
        return 0.0
    span = limits["stale_seconds"] - limits["fresh_seconds"]
    return max(0.0, min(1.0, (limits["stale_seconds"] - age) / span))


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


def http_evidence_via(proto, host, port, user, password, url, signal=None,
                      timeout=CURL_TIMEOUT):
    """Один timestamped HTTP-сигнал; curl rc=7 сохраняет быстрый TCP-refusal path."""
    rc, out = _run_curl(_proxy_args(proto, host, port, user, password)
                        + ["-o", "/dev/null" if _posix() else "NUL",
                           "-w", "%{http_code}", url], timeout)
    code = out if rc == 0 and out else "000"
    ok = bool(code.isdigit() and 200 <= int(code) <= 499)
    error_kind = "" if ok else ("tcp-refused" if rc == 7 else "transport-error")
    return health_mod.evidence(signal or proto, ok, target=url,
                               error_kind=error_kind, via_proxy=True,
                               detail="curl_rc=%s code=%s" % (rc, code))


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


# ── технический паспорт IP для карты выхода (19.08) ──────────────────────────
# Те же публичные базы, что у geo_country (ip-api.com, фолбэк ipinfo.io) — новых
# зависимостей и хостов узел не получает. Ответ кэшируется панелью (setting) по IP:
# паспорт адреса меняется редко, TTL недели хватает.
INTEL_TTL_S = 7 * 24 * 3600

_INTEL_PRIMARY = ("http://ip-api.com/json/%s?fields=status,countryCode,regionName,city,"
                  "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,lat,lon")
_INTEL_SECONDARY = "https://ipinfo.io/%s/json"


# proxycheck.io отвечает 403 на дефолтный UA «Python-urllib/…» (анти-бот);
# честный узнаваемый UA пропускают все наши источники (живой случай node1 19.08)
_HTTP_UA = "Mozilla/5.0 (compatible; redut-panel)"


def _http_json(url, timeout=GEO_TIMEOUT):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _HTTP_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _intel_from_ipapi(d):
    """Разбор ответа ip-api.com/json -> общий словарь паспорта или None."""
    if not isinstance(d, dict) or d.get("status") != "success":
        return None
    asn = (d.get("as") or "").split(" ")[0] or None
    as_rest = (d.get("as") or "").split(" ", 1)
    return {
        "cc": (d.get("countryCode") or "").lower() or None,
        "region": d.get("regionName") or None,
        "city": d.get("city") or None,
        "tz": d.get("timezone") or None,
        "isp": d.get("isp") or None,
        "org": d.get("org") or None,
        "asn": asn,
        "asname": d.get("asname") or (as_rest[1] if len(as_rest) > 1 else None),
        "ptr": d.get("reverse") or None,
        "mobile": bool(d.get("mobile")) if "mobile" in d else None,
        "proxy": bool(d.get("proxy")) if "proxy" in d else None,
        "hosting": bool(d.get("hosting")) if "hosting" in d else None,
        "lat": d.get("lat"), "lon": d.get("lon"),
        "src": "ip-api",
    }


def _intel_from_ipinfo(d):
    """Разбор ответа ipinfo.io/json (фолбэк): полей меньше — mobile/proxy/hosting
    эта база бесплатно не отдаёт, оставляем None (фронт различает None и False)."""
    if not isinstance(d, dict) or not (d.get("org") or d.get("city") or d.get("hostname")):
        return None
    org = (d.get("org") or "").strip()
    asn = org.split(" ")[0] if org.startswith("AS") else None
    name = (org.split(" ", 1)[1] if asn and " " in org else org) or None
    lat = lon = None
    loc = (d.get("loc") or "").split(",")
    if len(loc) == 2:
        try:
            lat, lon = float(loc[0]), float(loc[1])
        except ValueError:
            pass
    return {"cc": (d.get("country") or "").lower() or None,
            "region": d.get("region") or None, "city": d.get("city") or None,
            "tz": d.get("timezone") or None,
            "isp": name, "org": name, "asn": asn, "asname": name,
            "ptr": d.get("hostname") or None,
            "mobile": None, "proxy": None, "hosting": None,
            "lat": lat, "lon": lon, "src": "ipinfo"}


def ip_intel(ip):
    """Технический паспорт exit-IP (ASN, оператор, город, пояс, PTR, датацентр…).

    Для оверлея на карте выхода: панель показывает человеку, ЧТО за адрес видят
    сайты. Запрос идёт напрямую с сервера (как geo_country); обе базы молчат ->
    None (кэшировать нечего, панель попробует позже)."""
    if not ip:
        return None
    intel = _intel_from_ipapi(_http_json(_INTEL_PRIMARY % ip))
    if intel is None:
        intel = _intel_from_ipinfo(_http_json(_INTEL_SECONDARY % ip))
    return intel


# ── риск-разведка exit-IP (19.08): чем адрес светится в антифрод-базах ────────
# Поверх паспорта — сигналы риска из независимых источников. Без ключей работают
# proxycheck.io (анонимный лимит ~100/день — при нашем кэше 7 дн это капля) и
# DNSBL-зоны (обычные DNS-запросы, HTTP вообще нет). Ключи в secrets.json,
# раздел {"ipintel": {"proxycheck": …, "abuseipdb": …, "ipqs": …}} — все
# бесплатные тарифы, вписывает владелец; появился ключ — источник сам включится
# при следующем протухании кэша. Любой источник молчит — его поля None, оценка
# считается по тому, что есть: неизвестность не карается.
INTEL_VERSION = 2          # формат кэша ipintel:*; старые записи перечитываются

_PROXYCHECK_URL = "https://proxycheck.io/v2/%s?vpn=3&asn=1&risk=1"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90"
_IPQS_URL = "https://www.ipqualityscore.com/api/json/ip/%s/%s"
# три классические зоны: спам-репутация Spamhaus/SpamCop + Barracuda
_DNSBL_ZONES = ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org")


def _http_json_hdr(url, headers, timeout=GEO_TIMEOUT):
    """_http_json с заголовками (AbuseIPDB требует ключ в Key:)."""
    try:
        hdrs = {"User-Agent": _HTTP_UA}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _intel_from_proxycheck(d, ip):
    """proxycheck.io/v2 -> {pc_proxy, pc_type, pc_risk} (+ запасные geo-поля).

    Ответ: {"status":"ok", "<ip>": {proxy:"yes|no", type:"VPN|SOCKS…", risk:0-100,
    asn, provider, isocode…}}. status warning|denied|error без блока IP -> None.
    """
    if not isinstance(d, dict):
        return None
    row = d.get(ip)
    if not isinstance(row, dict) or str(d.get("status", "ok")) not in ("ok", "warning"):
        return None
    out = {"pc_proxy": str(row.get("proxy", "")).lower() == "yes",
           "pc_type": (row.get("type") or None)}
    try:
        out["pc_risk"] = max(0, min(100, int(row.get("risk"))))
    except (TypeError, ValueError):
        out["pc_risk"] = None
    # запасные поля паспорта: пригодятся, если гео-базы молчали
    out["_pc_cc"] = (row.get("isocode") or "").lower() or None
    out["_pc_asn"] = row.get("asn") or None
    out["_pc_org"] = row.get("provider") or None
    return out


def _intel_from_abuseipdb(d):
    """AbuseIPDB /v2/check -> {abuse_score, abuse_reports} (жалобы за 90 дней)."""
    data = (d or {}).get("data") if isinstance(d, dict) else None
    if not isinstance(data, dict) or "abuseConfidenceScore" not in data:
        return None
    try:
        return {"abuse_score": max(0, min(100, int(data["abuseConfidenceScore"]))),
                "abuse_reports": int(data.get("totalReports") or 0)}
    except (TypeError, ValueError):
        return None


def _intel_from_ipqs(d):
    """IPQualityScore -> {ipqs_fraud, ipqs_vpn, ipqs_tor}."""
    if not isinstance(d, dict) or not d.get("success"):
        return None
    out = {"ipqs_vpn": bool(d.get("vpn")), "ipqs_tor": bool(d.get("tor"))}
    try:
        out["ipqs_fraud"] = max(0, min(100, int(d.get("fraud_score"))))
    except (TypeError, ValueError):
        out["ipqs_fraud"] = None
    return out


def dnsbl_check(ip, zones=_DNSBL_ZONES, resolver=None):
    """Числится ли IPv4 в DNS-чёрных списках -> {"checked": N, "listed": [зоны]}.

    Обычный DNS-запрос <перевёрнутый-ip>.<зона>: ответ есть — числится, NXDOMAIN —
    чист. Ошибка/таймаут зоны считается «не числится» (лучше недоглядеть, чем
    пугать по сетевому чиху). resolver подменяется в тестах."""
    resolver = resolver or socket.gethostbyname
    parts = (ip or "").split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return {"checked": 0, "listed": []}
    rev = ".".join(reversed(parts))
    listed = []
    for zone in zones:
        try:
            resolver("%s.%s" % (rev, zone))
            listed.append(zone)
        except OSError:
            pass
    return {"checked": len(zones), "listed": listed}


def ip_quality(d):
    """Итоговая оценка качества exit-IP 0–100 (больше = лучше).

    Мягкая свёртка: наш выход — почти всегда датацентровый прокси, топить оценку
    за сам факт нельзя; топят РИСКИ — высокие баллы антифрод-баз, жалобы, чёрные
    списки, Tor. Неизвестный сигнал (None) не участвует."""
    score = 100.0
    if d.get("pc_risk") is not None:
        score -= d["pc_risk"] * 0.35
    if d.get("ipqs_fraud") is not None:
        score -= d["ipqs_fraud"] * 0.35
    if d.get("abuse_score") is not None:
        score -= d["abuse_score"] * 0.4
    listed = len((d.get("dnsbl") or {}).get("listed") or [])
    score -= 14 * min(listed, 3)
    if d.get("ipqs_tor") or str(d.get("pc_type") or "").lower() == "tor":
        score -= 35
    if d.get("hosting"):
        score -= 10
    if d.get("proxy") or d.get("pc_proxy") or d.get("ipqs_vpn"):
        score -= 6
    if d.get("ping_ms") is not None and d["ping_ms"] > 250:
        score -= 5
    return int(max(0, min(100, round(score))))


def ip_intel_full(ip, keys=None, ping_ms=None):
    """Полный паспорт + риск-разведка одним словарём (кэшируется панелью).

    Паспорт (ip-api/ipinfo) + proxycheck (без ключа) + AbuseIPDB/IPQS (по ключам)
    + DNSBL + пинг до прокси (замер последней пробы пула, приходит снаружи).
    Совсем никто не ответил -> None (кэшировать нечего)."""
    if not ip:
        return None
    keys = keys or {}
    base = ip_intel(ip)
    url = _PROXYCHECK_URL % ip
    if keys.get("proxycheck"):
        url += "&key=%s" % keys["proxycheck"]
    pc = _intel_from_proxycheck(_http_json(url), ip)
    if base is None and pc is None:
        return None
    out = dict(base or {})
    if pc:
        # запасные geo-поля proxycheck — только в дыры паспорта
        for src, dst in (("_pc_cc", "cc"), ("_pc_asn", "asn"), ("_pc_org", "org")):
            if not out.get(dst) and pc.get(src):
                out[dst] = pc[src]
        out.update({k: v for k, v in pc.items() if not k.startswith("_")})
    if keys.get("abuseipdb"):
        ab = _intel_from_abuseipdb(_http_json_hdr(
            _ABUSEIPDB_URL % ip, {"Key": keys["abuseipdb"], "Accept": "application/json"}))
        if ab:
            out.update(ab)
    if keys.get("ipqs"):
        qs = _intel_from_ipqs(_http_json(_IPQS_URL % (keys["ipqs"], ip)))
        if qs:
            out.update(qs)
    out["dnsbl"] = dnsbl_check(ip)
    if ping_ms is not None:
        out["ping_ms"] = ping_ms
    out["quality"] = ip_quality(out)
    out["v"] = INTEL_VERSION
    return out


def geo_country_consensus(ip):
    """Страна exit-IP по ДВУМ независимым базам сразу -> {cc, alt, agree}.

    Зачем спрашивать обе: у перепроданных диапазонов базы расходятся. Реальный
    случай 2026-08-15 — `45.86.21.249`: ip-api видит Нигерию, ipinfo Нью-Йорк.
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
        "exit_ip": None, "exit_cc": None, "asn": None,
        "tg_ok": False, "latency_ms": None,
        "provider_check": None,
        "evidence": [], "health_decision": None,
    }

    # 0. (PROXY6) check?ids= — ПОДСКАЗКА, не приговор (F4, 1.3.0): API провайдера
    # иногда врёт/лагает, а живой прокси терять из-за этого нельзя. false больше
    # не дисквалифицирует сам по себе — матрицу гоняем всё равно; дисквалификация
    # только если И матрица мертва (пометка в disq различает эти случаи).
    provider_dead = False
    if provider_check is not None:
        try:
            alive = bool(provider_check())
            res["provider_check"] = alive
            res["evidence"].append(health_mod.evidence(
                "provider_api", alive, target=proxy.get("provider") or "provider"))
            provider_dead = not alive
        except Exception as e:
            res["provider_check"] = "error: %s" % e  # ошибка API не блокирует пробу
            res["evidence"].append(health_mod.evidence(
                "provider_api", False, target=proxy.get("provider") or "provider",
                error_kind="api-error", detail=str(e)))

    ports = [p for p in dict.fromkeys([proxy.get("port_socks5"), proxy.get("port_http")]) if p]
    if not host or not ports:
        res["disqualified"] = "no-host-or-ports"
        return res

    # 1. матрица порт×протокол
    matrix = probe_matrix(host, ports, user, password)
    res["matrix"] = {"%s/%s" % (port, proto): ip for (port, proto), ip in matrix.items()}
    for (port, proto), ip in matrix.items():
        res["evidence"].append(health_mod.evidence(
            proto, bool(ip), target=IPIFY_URL, via_proxy=True,
            error_kind="" if ip else "external-or-transport",
            detail="port=%s" % port))
    socks_ports = [port for (port, proto), ip in matrix.items() if proto == "socks" and ip]
    http_ports = [port for (port, proto), ip in matrix.items() if proto == "http" and ip]
    res["socks_ok"], res["http_ok"] = bool(socks_ports), bool(http_ports)

    # порт из паспорта прокси — приоритетная подсказка, но не обязательство
    ps, ph = proxy.get("port_socks5"), proxy.get("port_http")
    res["socks_port"] = ps if ps in socks_ports else (socks_ports[0] if socks_ports else None)
    res["http_port"] = ph if ph in http_ports else (http_ports[0] if http_ports else None)

    if not socks_ports and not http_ports:
        # ipify — один внешний target, поэтому его отказ через оба протокола ещё
        # не доказывает смерть прокси. Только в этой редкой ветке спрашиваем два
        # независимых HTTP endpoint и строим quorum без лишней цены нормальной пробы.
        for port in ports:
            for proto in ("socks", "http"):
                res["evidence"].append(http_evidence_via(
                    proto, host, port, user, password, LAT_URL, signal=proto))
                res["evidence"].append(http_evidence_via(
                    proto, host, port, user, password, TG_URL, signal="telegram"))
        res["health_decision"] = health_mod.proxy_fault_decision(res["evidence"])
        # не работает ни одна комбинация — дисквалификация (+пометка, если и
        # провайдер считает его трупом: п.2 гейта удаления §6.4 останется честным)
        res["disqualified"] = "provider-check-dead+no-combo" if provider_dead else "no-combo"
        return res

    # основная комбинация: как socks-out (§7.3 — SOCKS5 предпочтителен)
    main = ("socks", res["socks_port"]) if res["socks_port"] else ("http", res["http_port"])
    res["exit_ip"] = matrix[(main[1], main[0])]

    # 2. страна выхода: чёрный список §6.1 (реальная страна, не метка провайдера).
    #    Спрашиваем две базы: расхождение само по себе портит репутацию IP (§оценка).
    geo = geo_country_consensus(res["exit_ip"])
    res["exit_cc"], res["exit_cc_alt"], res["geo_agree"] = geo["cc"], geo["alt"], geo["agree"]
    intel = ip_intel(res["exit_ip"])
    res["asn"] = (intel or {}).get("asn")
    res["evidence"].append(health_mod.evidence(
        "geo", bool(geo["cc"] or geo["alt"]), target="geo-consensus",
        detail="agree=%s" % geo["agree"]))
    if res["exit_cc"] in HARD_BLOCK_CC or (res["exit_cc_alt"] or "") in HARD_BLOCK_CC:
        res["disqualified"] = "blocked-cc:%s" % (res["exit_cc"] or res["exit_cc_alt"])
        return res

    # 3. Telegram: через комбинацию, которая пойдёт в http-tg (HTTP предпочтителен)
    tg = ("http", res["http_port"]) if res["http_port"] else ("socks", res["socks_port"])
    code = http_code_via(tg[0], host, tg[1], user, password, TG_URL)
    res["tg_code"] = code
    res["tg_ok"] = code != "000" and code.isdigit() and 200 <= int(code) <= 499
    res["evidence"].append(health_mod.evidence(
        "telegram", res["tg_ok"], target=TG_URL, via_proxy=True,
        error_kind="" if res["tg_ok"] else "external-or-transport",
        detail="code=%s" % code))

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


def _score_core(vals, cfg=None, is_current=False, freshness=1.0):
    """Единая математика скоринга §7.4 — ОДИН источник истины (П3).

    vals: ok, latency_ms, fail_count, tg_ok, socks_ok, http_ok, kind, ip_version,
    date_end, exit_cc, country, geo_agree.
    -> (полная_оценка, базовая_часть_без_странового_вклада) или (None, None).
    Базовая часть нужна rank_candidates: в режимах country_first страна — отдельный
    первичный ключ, и полная оценка удвоила бы её вес.
    """
    if not vals.get("ok"):
        return None, None
    s = 100.0
    freshness = max(0.0, min(1.0, float(freshness)))
    if vals.get("latency_ms") is not None:
        s -= min(vals["latency_ms"] / 10.0, 40.0) * freshness
    s -= int(vals.get("fail_count") or 0) * 15  # история провалов до этой пробы
    if vals.get("tg_ok"):
        s += 20 * freshness
    if vals.get("socks_ok") and vals.get("http_ok"):
        s += 15 * freshness  # есть куда откатиться без смены IP (RETUNE)
    if vals.get("kind") == "dedicated" and int(vals.get("ip_version") or 4) == 4:
        s += 10
    elif vals.get("kind") == "shared":
        s -= 20
    if is_current:
        s += 15  # стикинес: не дёргаться зря
    days = days_left(vals.get("date_end"))
    if days is not None and days < 2:
        s -= 30
    base = s
    # умная оценка страны (2026-08-15): репутация выхода + сходимость geoip-баз,
    # помноженные на вес выбранной стратегии (2026-08-17; у «скорости» вес 0).
    # Чёрный список сюда не доходит — он отсекается дисквалификацией выше.
    cr = country.rating(vals.get("exit_cc") or vals.get("country"),
                        vals.get("geo_agree", True), cfg)
    if cr is not None:
        s += cr
    return round(s, 1), round(base, 1)


def score(row, res, is_current=False, cfg=None):
    """Скоринг §7.4 после живой пробы. None = дисквалификация.

    cfg нужен только политике стран: чёрный список из конфига и **вес страны по
    выбранной стратегии** (country.rating). Без cfg действуют значения по умолчанию.
    Делегирует _score_core — та же формула, что у score_from_row (П3)."""
    vals = {
        "ok": res.get("ok"), "latency_ms": res.get("latency_ms"),
        "fail_count": row.get("fail_count"),
        "tg_ok": res.get("tg_ok"), "socks_ok": res.get("socks_ok"),
        "http_ok": res.get("http_ok"),
        "kind": row.get("kind"), "ip_version": row.get("ip_version"),
        "date_end": row.get("date_end"),
        "exit_cc": res.get("exit_cc"), "country": row.get("country"),
        "geo_agree": res.get("geo_agree", True),
    }
    return _score_core(vals, cfg, is_current)[0]


def _rget(row, key):
    """Значение колонки из dict ИЛИ sqlite3.Row (у Row нет .get)."""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return None


def score_from_row(row, cfg=None, is_current=False, now=None):
    """П3: оценка «на лету» из сохранённой строки пула под ТЕКУЩУЮ стратегию.

    Смена стратегии ничего не пересчитывает в БД — потребители (таблица пула,
    порядок ротации, превью стратегий) зовут эту функцию и видят ОДНИ И ТЕ ЖЕ
    числа немедленно. Колонка score в БД остаётся «последним замером» (CLI list,
    отладка), потребители на неё больше не завязаны.

    Все входы формулы лежат в строке (latency_ms, socks/http/tg_ok, kind,
    ip_version, date_end, fail_count, exit_cc, geo_agree). Штраф «<2 дней до
    конца» считается от текущего времени — честно «плывёт» без новой пробы.
    -> (полная_оценка, базовая_часть); (None, None), если последняя проба не прошла.
    """
    geo = _rget(row, "geo_agree")
    vals = {
        "ok": bool(_rget(row, "probe_ok")), "latency_ms": _rget(row, "latency_ms"),
        "fail_count": _rget(row, "fail_count"),
        "tg_ok": _rget(row, "tg_ok"), "socks_ok": _rget(row, "socks_ok"),
        "http_ok": _rget(row, "http_ok"),
        "kind": _rget(row, "kind"), "ip_version": _rget(row, "ip_version"),
        "date_end": _rget(row, "date_end"),
        "exit_cc": _rget(row, "exit_cc"), "country": _rget(row, "country"),
        "geo_agree": True if geo is None else bool(geo),
    }
    return _score_core(vals, cfg, is_current, freshness_weight(row, cfg, now))


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
