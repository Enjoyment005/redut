# -*- coding: utf-8 -*-
"""Bounded, read-only local reliability/SLO report.

All timestamps in the legacy database are local wall-clock ISO strings.  The report
uses the same clock and excludes malformed/future rows.  It never returns proxy rows,
event source IPs, provider credentials, or free-form provider error messages.
"""
import datetime
import json
import math
from collections import Counter, defaultdict

import learning as learning_mod


REPORT_VERSION = 1
DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 180
MAX_ROWS_PER_TABLE = 100000
FALSE_SWITCH_WINDOW_SECONDS = 15 * 60
MTTR_TARGET_SECONDS = 3 * 60

SWITCH_ACTIONS = frozenset({
    "rotate", "replenish", "provider-switch", "strategy-apply", "apply",
})
SWITCH_SUCCESS_RESULTS = frozenset({"ok"})
SWITCH_FAILURE_RESULTS = frozenset({"fail", "verify-fail", "stuck"})
DECISION_ACTIONS = frozenset({
    "strategy-apply", "rotate", "replenish", "retune", "provider-switch",
    "emergency", "panel-emergency", "panel-rotate", "selection-reconcile",
    "selection-mode", "manual-failover", "explicit-apply", "health-quorum",
    "suspect", "rotating", "degraded", "frozen_net", "self-heal",
    "buy-postcheck", "auto-prolong", "proxy-fault",
})


def _now(value=None):
    current = value or datetime.datetime.now()
    if isinstance(current, datetime.date) and not isinstance(current, datetime.datetime):
        current = datetime.datetime.combine(current, datetime.time.max)
    if not isinstance(current, datetime.datetime):
        raise ValueError("now must be datetime/date")
    if current.tzinfo is not None:
        current = current.astimezone().replace(tzinfo=None)
    return current.replace(microsecond=0)


def _stamp(value):
    try:
        stamp = datetime.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone().replace(tzinfo=None)
        return stamp.replace(microsecond=0)
    except (TypeError, ValueError, OverflowError):
        return None


def _ratio(success, total):
    return round(float(success) / total, 6) if total else None


def _p95(values):
    clean = sorted(float(value) for value in values
                   if isinstance(value, (int, float)) and math.isfinite(float(value))
                   and value >= 0)
    if not clean:
        return None
    index = max(0, math.ceil(0.95 * len(clean)) - 1)
    return round(clean[index], 3)


def _bounded_rows(conn, query, limit=MAX_ROWS_PER_TABLE):
    rows = conn.execute(query, (int(limit) + 1,)).fetchall()
    return ([dict(row) for row in rows[:limit]], len(rows) > limit)


def _valid_rows(rows, since, current):
    out = []
    malformed = future = 0
    for row in rows:
        stamp = _stamp(row.get("ts"))
        if stamp is None:
            malformed += 1
        elif stamp > current:
            future += 1
        elif stamp >= since:
            item = dict(row)
            item["_stamp"] = stamp
            out.append(item)
    out.sort(key=lambda item: (item["_stamp"], int(item.get("id") or 0)))
    return out, malformed, future


def _availability(probes):
    current = [row for row in probes if bool(row.get("is_current"))]
    egress = [int(bool(row.get("ok"))) for row in current if row.get("ok") is not None]
    telegram = [int(bool(row.get("tg_ok"))) for row in current
                if row.get("tg_ok") is not None]
    return {
        "egress": {"samples": len(egress), "successful": sum(egress),
                   "ratio": _ratio(sum(egress), len(egress))},
        "telegram": {"samples": len(telegram), "successful": sum(telegram),
                     "ratio": _ratio(sum(telegram), len(telegram))},
        "scope": "probe_log rows with is_current=1",
    }


def _fault_recovery(events):
    pending = []
    durations = []
    for event in events:
        if event.get("action") == "proxy-fault" and event.get("result") == "confirmed":
            if not pending:
                pending.append(event["_stamp"])
            continue
        if (pending and event.get("action") in ("rotate", "replenish")
                and event.get("result") == "ok"):
            durations.append(max(0.0, (event["_stamp"] - pending.pop(0)).total_seconds()))
    p95 = _p95(durations)
    return {"confirmed": len(durations) + len(pending), "recovered": len(durations),
            "unresolved": len(pending), "samples": len(durations),
            "mean_seconds": (round(sum(durations) / len(durations), 3)
                             if durations else None),
            "p95_seconds": p95, "target_p95_seconds": MTTR_TARGET_SECONDS,
            "meets_target": None if p95 is None else p95 <= MTTR_TARGET_SECONDS}


def _switches(events, window_days):
    attempts = [event for event in events
                if event.get("action") in SWITCH_ACTIONS
                and event.get("result") in SWITCH_SUCCESS_RESULTS | SWITCH_FAILURE_RESULTS]
    successes = [event for event in attempts if event.get("result") in SWITCH_SUCCESS_RESULTS]
    failures = len(attempts) - len(successes)
    rollback_events = [event for event in events
                       if event.get("action") == "rollback" and event.get("result") == "ok"]
    rollbacks = []
    rollback_unknown = 0
    for event in rollback_events:
        try:
            detail = json.loads(
                event.get("detail") or "",
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
            bad, good = detail.get("bad_ip"), detail.get("good_ip")
            if not bad or not good:
                rollback_unknown += 1
            elif str(bad) != str(good):
                rollbacks.append(event)
        except (AttributeError, TypeError, ValueError, RecursionError):
            rollback_unknown += 1
    automatic = [event for event in successes if event.get("actor") == "auto"]
    daily = Counter(event["_stamp"].date().isoformat() for event in automatic)

    false_switches = 0
    used = set()
    for rollback in rollbacks:
        eligible = [(idx, event) for idx, event in enumerate(successes)
                    if idx not in used and event["_stamp"] <= rollback["_stamp"]
                    and (rollback["_stamp"] - event["_stamp"]).total_seconds()
                    <= FALSE_SWITCH_WINDOW_SECONDS]
        if eligible:
            idx, _ = eligible[-1]
            used.add(idx)
            false_switches += 1
    return {
        "attempts": len(attempts), "successful": len(successes), "failed": failures,
        "success_rate": _ratio(len(successes), len(attempts)),
        "rollbacks": len(rollbacks),
        "rollback_unknown": rollback_unknown,
        "rollback_rate": _ratio(len(rollbacks), len(successes)),
        "automatic": len(automatic),
        "automatic_per_day": round(len(automatic) / float(window_days), 6),
        "automatic_daily": [{"day": day, "count": daily[day]} for day in sorted(daily)],
        "false_switches": false_switches,
        "false_switch_rate": _ratio(false_switches, len(successes)),
        "false_switch_definition": "successful switch followed by rollback within 15 minutes",
    }


def _manual_reason(detail):
    text = str(detail or "").lower()
    if "подтверж" in text or "proxy-fault" in text:
        return "confirmed-proxy-fault"
    if "drift" in text or "обход" in text:
        return "manual-pin-drift"
    if "стратег" in text:
        return "strategy-selection"
    if "руч" in text or "explicit" in text:
        return "owner-action"
    return "other"


def _manual(events, since, current):
    transitions = [event for event in events if event.get("action") == "selection-mode"
                   and event.get("result") in ("manual", "auto")]
    manual_since = None
    entries = exits = 0
    seconds = 0.0
    reasons = Counter()
    for event in transitions:
        if event.get("result") == "manual":
            if event["_stamp"] >= since:
                entries += 1
            if manual_since is None:
                manual_since = max(since, event["_stamp"])
        elif manual_since is not None:
            in_window = event["_stamp"] >= since
            if in_window:
                exits += 1
            seconds += max(0.0, (event["_stamp"] - manual_since).total_seconds())
            if in_window:
                reasons[_manual_reason(event.get("detail"))] += 1
            manual_since = None
    active = manual_since is not None
    if active:
        seconds += max(0.0, (current - manual_since).total_seconds())
    return {"seconds": round(seconds, 3), "entries": entries, "exits": exits,
            "active": active,
            "exit_reasons": [{"reason": reason, "count": reasons[reason]}
                             for reason in sorted(reasons)]}


def _safe_payload(raw):
    if not raw:
        return None
    try:
        value = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("invalid constant: %s" % value)))
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError, RecursionError):
        return None


def _stale_decisions(events):
    total = stale_inputs = rejected = corrupt = 0
    for event in events:
        if event.get("action") not in DECISION_ACTIONS:
            continue
        total += 1
        payload = _safe_payload(event.get("payload_json"))
        if event.get("payload_json") and payload is None:
            corrupt += 1
        freshness = (payload or {}).get("freshness") or {}
        try:
            if any(math.isfinite(float(value)) and float(value) < 1.0
                   for value in freshness.values()):
                stale_inputs += 1
        except (AttributeError, TypeError, ValueError, OverflowError):
            corrupt += 1
        if event.get("action") == "strategy-apply" and event.get("result") == "stale":
            rejected += 1
    return {"total_decisions": total, "with_stale_inputs": stale_inputs,
            "stale_input_rate": _ratio(stale_inputs, total),
            "superseded_decisions": rejected, "corrupt_payloads": corrupt}


def _provider_api(events):
    observed = [event for event in events if event.get("action") == "provider-api"]
    kinds = Counter(str(event.get("result") or "unknown") for event in observed)
    rate_limits = kinds.get("rate-limit", 0)
    return {"errors": len(observed), "rate_limits": rate_limits,
            "by_kind": [{"kind": kind, "count": kinds[kind]} for kind in sorted(kinds)]}


def _spend(money, events):
    totals = defaultdict(float)
    daily = defaultdict(float)
    ignored = 0
    for row in money:
        if row.get("op") not in ("buy", "prolong"):
            continue
        try:
            amount = float(row.get("price"))
            if not math.isfinite(amount) or amount < 0:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            ignored += 1
            continue
        currency = str(row.get("currency") or "UNKNOWN").upper()[:12]
        day = row["_stamp"].date().isoformat()
        totals[currency] += amount
        daily[(day, currency)] += amount
    denied_actions = {"buy", "auto-prolong", "replenish", "prolong"}
    denied = sum(1 for event in events if event.get("action") in denied_actions
                 and event.get("result") == "denied")
    return {
        "by_currency": [{"currency": currency, "amount": round(totals[currency], 6)}
                        for currency in sorted(totals)],
        "daily": [{"day": day, "currency": currency,
                   "amount": round(daily[(day, currency)], 6)}
                  for day, currency in sorted(daily)],
        "denied": denied, "ignored_invalid_amounts": ignored,
    }


def _learning(buckets, shadow, current, cfg=None):
    global_rows = [row for row in buckets if row.get("level") == "global"]
    summary = learning_mod.summarize_buckets(global_rows, now=current.date())
    samples = float((((summary.get("ewma") or {}).get("availability") or {})
                     .get("sample_size") or 0.0))
    raw = (cfg or {}).get("learning") or {}
    try:
        minimum = max(30, int(raw.get("shadow_min_days") or 30))
    except (TypeError, ValueError, OverflowError):
        minimum = 30
    mode = str(raw.get("mode") or "shadow")
    cutoff = current - datetime.timedelta(days=365)
    formula_rows = [row for row in shadow
                    if row.get("formula_version") == learning_mod.FORMULA_VERSION
                    and row["_stamp"] >= cutoff]
    shadow_rows = [row for row in formula_rows if row.get("mode") == "shadow"]
    days = sorted({row["_stamp"].date().isoformat() for row in shadow_rows})
    qualified_at = None
    if len(days) >= minimum:
        nth_day = days[minimum - 1]
        qualified_at = min(row["_stamp"] for row in shadow_rows
                           if row["_stamp"].date().isoformat() == nth_day)
    canaries = {str(item) for item in (raw.get("canary_servers") or []) if str(item)}
    canary_rows = [row for row in formula_rows if row.get("mode") == "canary"
                   and row.get("server") in canaries
                   and qualified_at is not None and row["_stamp"] >= qualified_at]
    blockers = []
    if mode == "shadow":
        blockers.append("mode-shadow")
    if raw.get("owner_approved") is not True:
        blockers.append("owner-approval-required")
    if len(days) < minimum:
        blockers.append("shadow-days-%d/%d" % (len(days), minimum))
    server = str((cfg or {}).get("server") or "")
    if mode == "canary" and server not in canaries:
        blockers.append("server-not-in-canary")
    if mode == "active" and not canary_rows:
        blockers.append("canary-evidence-required")
    if mode not in ("shadow", "canary", "active"):
        blockers.append("invalid-mode")
    return {"coverage_days": summary.get("coverage_days", 0),
            "effective_samples": round(samples, 4),
            "maturity": round(samples / (samples + 20.0), 6) if samples >= 0 else 0.0,
            "drift_7_vs_90": summary.get("drift_7_vs_90"),
            "formula_version": learning_mod.FORMULA_VERSION,
            "mode": mode, "shadow_days": len(days),
            "shadow_decisions": len(shadow_rows), "shadow_min_days": minimum,
            "shadow_qualified": qualified_at is not None,
            "shadow_qualified_at": (qualified_at.isoformat(sep=" ")
                                    if qualified_at is not None else None),
            "activation_eligible": not blockers, "activation_blockers": blockers,
            "canary_decisions_after_qualification": len(canary_rows)}


def local_report(pool, cfg=None, now=None, window_days=DEFAULT_WINDOW_DAYS,
                 max_rows=MAX_ROWS_PER_TABLE):
    """Return one secret-free snapshot; performs no INSERT/UPDATE/DELETE/PRAGMA writes."""
    current = _now(now)
    try:
        days = max(1, min(MAX_WINDOW_DAYS, int(window_days)))
        limit = max(1, min(MAX_ROWS_PER_TABLE, int(max_rows)))
    except (TypeError, ValueError, OverflowError):
        days, limit = DEFAULT_WINDOW_DAYS, MAX_ROWS_PER_TABLE
    since = current - datetime.timedelta(days=days)
    with pool._tx_lock:  # one connection snapshot; all fetched values are detached dicts
        event_rows, event_truncated = _bounded_rows(
            pool.conn, "SELECT id,ts,actor,action,result,detail,payload_json "
                       "FROM event ORDER BY id DESC LIMIT ?", limit)
        probe_rows, probe_truncated = _bounded_rows(
            pool.conn, "SELECT id,ts,ok,tg_ok,is_current FROM probe_log "
                       "ORDER BY id DESC LIMIT ?", limit)
        money_rows, money_truncated = _bounded_rows(
            pool.conn, "SELECT id,ts,price,currency,op FROM money "
                       "ORDER BY id DESC LIMIT ?", limit)
        shadow_rows, shadow_truncated = _bounded_rows(
            pool.conn, "SELECT id,ts,server,mode,formula_version FROM shadow_decision "
                       "ORDER BY id DESC LIMIT ?", limit)
        bucket_rows = [dict(row) for row in pool.conn.execute(
            "SELECT day,level,probes_ok,probes_fail,tg_ok,tg_fail,geo_ok,geo_fail,"
            "latency_sum,latency_count,battle_drops,battle_seconds "
            "FROM learning_bucket ORDER BY day DESC LIMIT ?", (limit + 1,)).fetchall()]
        bucket_truncated = len(bucket_rows) > limit
        bucket_rows = bucket_rows[:limit]

    event_history, bad_events, future_events = _valid_rows(
        event_rows, datetime.datetime.min, current)
    events = [row for row in event_history if row["_stamp"] >= since]
    probes, bad_probes, future_probes = _valid_rows(probe_rows, since, current)
    money, bad_money, future_money = _valid_rows(money_rows, since, current)
    shadow_history, bad_shadow, future_shadow = _valid_rows(
        shadow_rows, datetime.datetime.min, current)
    report = {
        "report_version": REPORT_VERSION,
        "generated_at": current.isoformat(sep=" "),
        "window_days": days, "since": since.isoformat(sep=" "),
        "availability": _availability(probes),
        "fault_recovery": _fault_recovery(events),
        "switches": _switches(events, days),
        "manual": _manual(event_history, since, current),
        "stale_score": _stale_decisions(events),
        "provider_api": _provider_api(events),
        "spend": _spend(money, events),
        "learning": _learning(bucket_rows, shadow_history, current, cfg=cfg),
        "quality": {
            "truncated": {"event": event_truncated, "probe_log": probe_truncated,
                          "money": money_truncated, "shadow_decision": shadow_truncated,
                          "learning_bucket": bucket_truncated},
            "malformed_timestamps": {"event": bad_events, "probe_log": bad_probes,
                                     "money": bad_money, "shadow_decision": bad_shadow},
            "future_rows_ignored": {"event": future_events, "probe_log": future_probes,
                                    "money": future_money, "shadow_decision": future_shadow},
        },
    }
    # Last-line guard: report is always strict JSON before callers expose it.
    json.dumps(report, ensure_ascii=False, allow_nan=False)
    return report
