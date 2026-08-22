# -*- coding: utf-8 -*-
"""Общая временная шкала health-сигналов и чистое quorum-решение."""
import datetime
import math
import time


DEFAULT_QUORUM = {"quorum_window_seconds": 60.0, "quorum_min_targets": 2}
_PROXY_SIGNALS = frozenset({"socks", "http", "telegram"})


def evidence(signal, ok, target="", observed_at=None, error_kind="", via_proxy=False,
             detail=""):
    return {"signal": str(signal), "ok": bool(ok), "target": str(target or ""),
            "observed_at": float(time.time() if observed_at is None else observed_at),
            "error_kind": str(error_kind or ""), "via_proxy": bool(via_proxy),
            "detail": str(detail or "")}


def quorum_cfg(cfg=None):
    raw = (cfg or {}).get("health") or {}
    if not isinstance(raw, dict):
        raw = {}
    result = {}
    try:
        value = raw.get("quorum_window_seconds", DEFAULT_QUORUM["quorum_window_seconds"])
        if isinstance(value, bool):
            raise ValueError
        value = float(value)
        if not math.isfinite(value) or value < 1 or value > 3600:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        value = DEFAULT_QUORUM["quorum_window_seconds"]
    result["quorum_window_seconds"] = value
    try:
        value = raw.get("quorum_min_targets", DEFAULT_QUORUM["quorum_min_targets"])
        if isinstance(value, bool):
            raise ValueError
        numeric = float(value)
        if not math.isfinite(numeric) or not numeric.is_integer() or not 2 <= numeric <= 10:
            raise ValueError
        value = int(numeric)
    except (TypeError, ValueError, OverflowError):
        value = DEFAULT_QUORUM["quorum_min_targets"]
    result["quorum_min_targets"] = value
    return result


def _stamp(value):
    try:
        if isinstance(value, bool):
            raise ValueError
        return float(value)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")
                                                     .replace(" ", "T"))
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            return None


def proxy_fault_decision(items, cfg=None, now=None):
    """Решить, виноват ли прокси, по свежим независимым endpoint-сигналам.

    Один внешний target не образует кворум, даже если он упал через оба протокола.
    Явный TCP refusal от proxy endpoint — быстрый путь без ожидания кворума.
    """
    policy = quorum_cfg(cfg)
    current = float(time.time() if now is None else now)
    fresh = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        stamp = _stamp(item.get("observed_at"))
        if stamp is None or stamp > current + 5:
            continue
        if current - stamp <= policy["quorum_window_seconds"]:
            fresh.append(item)
    routed = [item for item in fresh if item.get("via_proxy")
              and item.get("signal") in _PROXY_SIGNALS]
    successes = [item for item in routed if item.get("ok")]
    refusals = [item for item in fresh
                if item.get("via_proxy") and item.get("signal") in _PROXY_SIGNALS
                and not item.get("ok") and item.get("error_kind") == "tcp-refused"]
    if refusals and not successes:
        return {"proxy_fault": True, "confirmed": True, "fast_path": True,
                "reason": "tcp-refused", "fresh_signals": len(fresh),
                "failed_targets": sorted({item.get("target") or "proxy-endpoint"
                                           for item in refusals}),
                "successful_signals": 0,
                "window_seconds": policy["quorum_window_seconds"],
                "threshold": policy["quorum_min_targets"]}

    failed_targets = sorted({item.get("target") for item in routed
                             if not item.get("ok") and item.get("target")})
    if successes:
        reason = "proxy-path-alive"
        fault = False
    elif len(failed_targets) >= policy["quorum_min_targets"]:
        reason = "target-quorum"
        fault = True
    else:
        reason = "single-target-or-insufficient"
        fault = False
    return {"proxy_fault": fault, "confirmed": fault, "fast_path": False,
            "reason": reason, "fresh_signals": len(fresh),
            "failed_targets": failed_targets,
            "successful_signals": len(successes),
            "window_seconds": policy["quorum_window_seconds"],
            "threshold": policy["quorum_min_targets"]}
