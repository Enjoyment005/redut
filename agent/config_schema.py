# -*- coding: utf-8 -*-
"""Версионированный effective-config с fail-closed нормализацией опасных полей."""
import copy
import ipaddress
import math
import os
import re
import shutil
import datetime

import config_store


CURRENT_VERSION = 1
_STRATEGIES = {"reputation", "balanced", "speed"}
_CURRENCIES = {"RUB", "USD", "EUR"}
_PATHS = ("db", "ring", "singbox_config", "boot_script", "lock")
_SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|private[_-]?key|totp|recovery",
                         re.I)


class ConfigMigrationError(Exception):
    pass


def _raw_version(raw):
    if not isinstance(raw, dict):
        raise ConfigMigrationError("корень config.json должен быть объектом")
    value = raw.get("config_schema_version", 0)
    if isinstance(value, bool):
        raise ConfigMigrationError("невалидная версия схемы")
    try:
        version = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ConfigMigrationError("невалидная версия схемы")
    if version < 0 or str(value).strip() != str(version):
        raise ConfigMigrationError("невалидная версия схемы")
    return version


def _migrate_0_1(data):
    data["config_schema_version"] = 1
    return data


_MIGRATIONS = {0: _migrate_0_1}


def migration_plan(raw):
    """Чистый dry-run: какие версии будут применены, без изменения raw."""
    version = _raw_version(raw)
    if version > CURRENT_VERSION:
        raise ConfigMigrationError("будущая версия схемы %s" % version)
    data = copy.deepcopy(raw)
    steps = []
    while version < CURRENT_VERSION:
        migrate = _MIGRATIONS.get(version)
        if migrate is None:
            raise ConfigMigrationError("нет миграции %s -> %s" % (version, version + 1))
        data = migrate(data)
        steps.append("%s->%s" % (version, version + 1))
        version += 1
    return {"from_version": _raw_version(raw), "to_version": version,
            "steps": steps, "changed": bool(steps), "data": data}


def migrate_file(path, dry_run=False):
    """Мигрировать config.json под общим writer-lock; backup создаётся до replace."""
    cfg = {"_source": os.path.abspath(path)}
    with config_store.writer(cfg):
        try:
            raw = config_store.read(cfg)
        except (ValueError, RecursionError, MemoryError) as e:
            raise ConfigMigrationError(str(e))
        plan = migration_plan(raw)
        plan["backup"] = None
        if dry_run or not plan["changed"]:
            return plan
        stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
        backup = "%s.schema-v%s.%s.bak" % (path, plan["from_version"], stamp)
        shutil.copy2(path, backup)
        with open(backup, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        if os.name == "posix":
            dfd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        config_store.update(cfg, lambda _data: copy.deepcopy(plan["data"]), _locked=True)
        plan["backup"] = backup
        return plan


def _issue(issues, path, reason, action="default"):
    issues.append({"path": path, "reason": reason, "action": action})


def _leaf_paths(value, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).startswith("_"):
                continue
            path = "%s.%s" % (prefix, key) if prefix else str(key)
            yield from _leaf_paths(child, path)
    else:
        yield prefix


def _contains_path(value, path):
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def _redact(value):
    if isinstance(value, dict):
        return {str(key): _redact(child) for key, child in value.items()
                if not str(key).startswith("_") and not _SECRET_KEY.search(str(key))}
    if isinstance(value, (list, tuple)):
        return [_redact(child) for child in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    return "<unsupported:%s>" % type(value).__name__


def diagnostics(cfg):
    """JSON-safe authenticated diagnostic view; secret-bearing keys are absent."""
    meta = (cfg or {}).get("_config_meta") or {}
    effective = _redact(cfg or {})
    visible = set(_leaf_paths(effective))
    sources = {path: source for path, source in (meta.get("sources") or {}).items()
               if path in visible and not any(_SECRET_KEY.search(part) for part in path.split("."))}
    return {"effective": effective, "sources": sources,
            "schema_version": meta.get("schema_version", CURRENT_VERSION),
            "source_version": meta.get("source_version"),
            "safe_mode": bool(meta.get("safe_mode")),
            "issues": copy.deepcopy(meta.get("issues") or [])}


def _mapping(value, issues, path):
    if isinstance(value, dict):
        return copy.deepcopy(value)
    _issue(issues, path, "ожидался объект")
    return {}


def _bool(value, default, issues, path, dangerous=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    _issue(issues, path, "ожидался boolean", "disabled" if dangerous else "default")
    return False if dangerous else default


def _number(value, default, issues, path, minimum=None, maximum=None, integer=False,
            dangerous=False):
    try:
        if isinstance(value, bool):
            raise ValueError
        number = float(value)
        if not math.isfinite(number):
            raise ValueError
        if integer and not number.is_integer():
            raise ValueError
        if minimum is not None and number < minimum:
            raise ValueError
        if maximum is not None and number > maximum:
            raise ValueError
        return int(number) if integer else number
    except (TypeError, ValueError, OverflowError):
        _issue(issues, path, "невалидное число", "disabled" if dangerous else "default")
        return 0 if dangerous else default


def _version(raw, issues):
    value = raw.get("config_schema_version", 0)
    try:
        if isinstance(value, bool):
            raise ValueError
        version = int(value)
        if version < 0 or str(value).strip() != str(version):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        _issue(issues, "config_schema_version", "невалидная версия", "safe-mode")
        return None
    if version > CURRENT_VERSION:
        _issue(issues, "config_schema_version", "будущая версия %s" % version, "safe-mode")
    return version


def normalize(raw, defaults=None, source=""):
    """Вернуть effective config; неизвестные поля сохраняются, секреты не добавляются."""
    issues = []
    defaults = copy.deepcopy(defaults or {})
    root_invalid = not isinstance(raw, dict)
    if root_invalid:
        _issue(issues, "$", "корень config.json должен быть объектом", "safe-mode")
        raw = {}
    else:
        try:
            raw = copy.deepcopy(raw)
        except (RecursionError, MemoryError):
            _issue(issues, "$", "config.json слишком глубоко вложен", "safe-mode")
            raw = {}
            root_invalid = True
    source_raw = raw
    version = _version(raw, issues)
    cfg = copy.deepcopy(defaults)
    cfg.update(raw)
    safe_mode = root_invalid or version is None or version > CURRENT_VERSION
    cfg["config_schema_version"] = CURRENT_VERSION

    default_port = int(defaults.get("panel_port") or 8443)
    cfg["panel_port"] = _number(cfg.get("panel_port", default_port), default_port,
                                issues, "panel_port", 1, 65535, integer=True)
    for key in _PATHS:
        value = cfg.get(key, defaults.get(key))
        if (not isinstance(value, str) or not value.strip()
                or any(ord(ch) < 32 for ch in value)
                or not os.path.isabs(value)):
            _issue(issues, key, "ожидался абсолютный путь")
            value = defaults.get(key)
        cfg[key] = value

    countries = _mapping(cfg.get("countries", {"strategy": "speed", "blacklist": []}),
                         issues, "countries")
    strategy = str(countries.get("strategy") or "speed").strip().lower()
    if strategy not in _STRATEGIES:
        _issue(issues, "countries.strategy", "неизвестная стратегия")
        strategy = "speed"
    countries["strategy"] = strategy
    blacklist = countries.get("blacklist", [])
    if not isinstance(blacklist, list):
        _issue(issues, "countries.blacklist", "ожидался список ISO-кодов")
        blacklist = []
    countries["blacklist"] = sorted({str(x).strip().lower() for x in blacklist
                                     if re.fullmatch(r"[A-Za-z]{2}", str(x).strip())})
    cfg["countries"] = countries

    health_defaults = {
        "fresh_seconds": 7200.0, "stale_seconds": 86400.0,
        "switch_margin": 15.0, "min_hold_time": 1800.0,
        "max_latency_regression": 500.0,
        "quorum_window_seconds": 60.0, "quorum_min_targets": 2,
    }
    if isinstance(defaults.get("health"), dict):
        health_defaults.update(defaults["health"])
    health = _mapping(cfg.get("health", health_defaults), issues, "health")
    health_specs = {
        "fresh_seconds": (0.0, 604800.0, False),
        "stale_seconds": (1.0, 2592000.0, False),
        "switch_margin": (0.0, 1000.0, False),
        "min_hold_time": (0.0, 604800.0, False),
        "max_latency_regression": (0.0, 60000.0, False),
        "quorum_window_seconds": (1.0, 3600.0, False),
        "quorum_min_targets": (2, 10, True),
    }
    for key, (lo, hi, integer) in health_specs.items():
        health[key] = _number(health.get(key, health_defaults[key]),
                              health_defaults[key], issues, "health.%s" % key,
                              lo, hi, integer=integer)
    if health["stale_seconds"] <= health["fresh_seconds"]:
        _issue(issues, "health.stale_seconds",
               "должно быть больше health.fresh_seconds")
        fallback = float(health_defaults["stale_seconds"])
        health["stale_seconds"] = (fallback if fallback > health["fresh_seconds"]
                                   else health["fresh_seconds"] + 1.0)
    cfg["health"] = health

    learning_defaults = {
        "mode": "shadow", "shadow_min_days": 30,
        "owner_approved": False, "canary_servers": [],
    }
    if isinstance(defaults.get("learning"), dict):
        learning_defaults.update(defaults["learning"])
    learning = _mapping(cfg.get("learning", learning_defaults), issues, "learning")
    mode = str(learning.get("mode") or "shadow").strip().lower()
    if mode not in ("shadow", "canary", "active"):
        _issue(issues, "learning.mode", "неизвестный режим", "shadow")
        mode = "shadow"
    learning["mode"] = mode
    learning["shadow_min_days"] = _number(
        learning.get("shadow_min_days", learning_defaults["shadow_min_days"]),
        learning_defaults["shadow_min_days"], issues, "learning.shadow_min_days",
        30, 365, integer=True)
    learning["owner_approved"] = _bool(
        learning.get("owner_approved", learning_defaults["owner_approved"]), False,
        issues, "learning.owner_approved", dangerous=True)
    canaries = learning.get("canary_servers", learning_defaults["canary_servers"])
    if not isinstance(canaries, list):
        _issue(issues, "learning.canary_servers", "ожидался список", "empty")
        canaries = []
    learning["canary_servers"] = sorted({str(item).strip() for item in canaries
                                          if str(item).strip()})
    exploration_start = len(issues)
    learning["exploration_enabled"] = _bool(
        learning.get("exploration_enabled", False), False, issues,
        "learning.exploration_enabled", dangerous=True)
    learning["exploration_rate"] = _number(
        learning.get("exploration_rate", 0.05), 0.05, issues,
        "learning.exploration_rate", 0.0, 1.0, dangerous=True)
    learning["exploration_max_per_day"] = _number(
        learning.get("exploration_max_per_day", 1), 1, issues,
        "learning.exploration_max_per_day", 0, 10, integer=True, dangerous=True)
    learning["exploration_purchase_budget_per_day"] = _number(
        learning.get("exploration_purchase_budget_per_day", 0.0), 0.0, issues,
        "learning.exploration_purchase_budget_per_day", 0.0, 1e9, dangerous=True)
    if len(issues) > exploration_start:
        learning["exploration_enabled"] = False
    if safe_mode:
        learning["mode"] = "shadow"
        learning["owner_approved"] = False
        learning["exploration_enabled"] = False
    cfg["learning"] = learning

    money_defaults = _mapping(defaults.get("money"), [], "money")
    raw_money = cfg.get("money")
    money_invalid = not isinstance(raw_money, dict)
    money = _mapping(raw_money, issues, "money")
    money_issue_start = len(issues)
    for key in ("buy_enabled", "delete_enabled"):
        money[key] = _bool(money.get(key, money_defaults.get(key, False)), False, issues,
                           "money.%s" % key, dangerous=True)
    specs = {
        "max_buys_per_day": (0, 1000, True),
        "max_spend_per_day": (0, 1e9, False),
        "max_price_per_buy": (0, 1e9, False),
        "min_balance_reserve": (0, 1e12, False),
        "buy_period_days": (1, 3650, True),
        "buy_version": (4, 4, True),
    }
    for key, (lo, hi, integer) in specs.items():
        default = money_defaults.get(key, lo)
        money[key] = _number(money.get(key, default), default, issues, "money.%s" % key,
                             lo, hi, integer=integer, dangerous=True)
    currency = str(money.get("currency") or money_defaults.get("currency") or "").upper()
    if currency not in _CURRENCIES:
        _issue(issues, "money.currency", "неподдерживаемая валюта", "disabled")
        currency = ""
        money["buy_enabled"] = False
        money["delete_enabled"] = False
    money["currency"] = currency
    if money_invalid or len(issues) > money_issue_start or safe_mode:
        money["buy_enabled"] = False
        money["delete_enabled"] = False
    cfg["money"] = money

    cfg["has_dnsmasq"] = _bool(cfg.get("has_dnsmasq", defaults.get("has_dnsmasq", False)),
                                bool(defaults.get("has_dnsmasq", False)), issues,
                                "has_dnsmasq")
    raw_wg_port = cfg.get("wg_port", defaults.get("wg_port"))
    if raw_wg_port in (None, ""):
        cfg.pop("wg_port", None)  # legacy: clients.py прочитает ListenPort из wg0.conf
    else:
        wg_port = _number(raw_wg_port, None, issues, "wg_port",
                          1, 65535, integer=True)
        if wg_port is None:
            cfg.pop("wg_port", None)
        else:
            cfg["wg_port"] = wg_port

    prolong_defaults = defaults.get("auto_prolong") or {
        "enabled": True, "days_before": 3, "period_days": 30}
    raw_prolong = cfg.get("auto_prolong", prolong_defaults)
    prolong_invalid = not isinstance(raw_prolong, dict)
    prolong = _mapping(raw_prolong, issues, "auto_prolong")
    start = len(issues)
    prolong["enabled"] = _bool(prolong.get("enabled", prolong_defaults.get("enabled", True)),
                                bool(prolong_defaults.get("enabled", True)), issues,
                                "auto_prolong.enabled", dangerous=True)
    prolong["days_before"] = _number(
        prolong.get("days_before", prolong_defaults.get("days_before", 3)),
        int(prolong_defaults.get("days_before", 3)), issues, "auto_prolong.days_before",
        0, 365, integer=True)
    prolong["period_days"] = _number(
        prolong.get("period_days", prolong_defaults.get("period_days", 30)),
        int(prolong_defaults.get("period_days", 30)), issues, "auto_prolong.period_days",
        1, 3650, integer=True)
    if prolong_invalid or len(issues) > start or safe_mode:
        prolong["enabled"] = False
    cfg["auto_prolong"] = prolong

    update_defaults = defaults.get("update") or {
        "auto": True, "window": "04:00-06:00", "repo": "Enjoyment005/redut"}
    raw_update = cfg.get("update", update_defaults)
    update_invalid = not isinstance(raw_update, dict)
    update = _mapping(raw_update, issues, "update")
    update["auto"] = _bool(update.get("auto", update_defaults.get("auto", True)),
                            bool(update_defaults.get("auto", True)), issues, "update.auto",
                            dangerous=True)
    window = update.get("window", update_defaults.get("window", "04:00-06:00"))
    match = (re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*", window)
             if isinstance(window, str) else None)
    valid_window = bool(match and all((0 <= int(match.group(i)) <= (23 if i in (1, 3) else 59))
                                      for i in range(1, 5)))
    if not valid_window:
        _issue(issues, "update.window", "невалидное окно")
        window = update_defaults.get("window", "04:00-06:00")
        update["auto"] = False
    else:
        window = "%02d:%02d-%02d:%02d" % tuple(int(match.group(i)) for i in range(1, 5))
    update["window"] = window
    repo = update.get("repo", update_defaults.get("repo", "Enjoyment005/redut"))
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        _issue(issues, "update.repo", "невалидный GitHub repo")
        repo = update_defaults.get("repo", "Enjoyment005/redut")
        update["auto"] = False
    update["repo"] = repo
    if update_invalid or safe_mode:
        update["auto"] = False
    cfg["update"] = update

    for key in ("subnet", "gw", "server_ip"):
        value = cfg.get(key)
        if value in (None, ""):
            continue
        try:
            if not isinstance(value, str):
                raise ValueError
            cfg[key] = str(ipaddress.ip_network(value, strict=False) if key == "subnet"
                           else ipaddress.ip_address(value))
        except (TypeError, ValueError):
            _issue(issues, key, "невалидная сеть/IP")
            cfg[key] = defaults.get(key)
    wan = cfg.get("wan")
    if wan is not None and (not isinstance(wan, str)
                            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", wan)):
        _issue(issues, "wan", "невалидное имя интерфейса")
        cfg["wan"] = defaults.get("wan")

    cfg["_source"] = source or cfg.get("_source") or ""
    issue_paths = {item["path"] for item in issues}
    sources = {}
    for path in _leaf_paths(cfg):
        if path in issue_paths or any(path.startswith(p + ".") for p in issue_paths):
            sources[path] = "safe-default"
        elif _contains_path(source_raw, path):
            sources[path] = "config"
        elif _contains_path(defaults, path):
            sources[path] = "default"
        else:
            sources[path] = "derived"
    if safe_mode:
        for path in ("money.buy_enabled", "money.delete_enabled",
                     "auto_prolong.enabled", "update.auto",
                     "learning.owner_approved"):
            sources[path] = "safe-default"
    cfg["_config_meta"] = {"schema_version": CURRENT_VERSION,
                           "source_version": version,
                           "safe_mode": safe_mode,
                           "issues": issues, "sources": sources}
    return cfg
