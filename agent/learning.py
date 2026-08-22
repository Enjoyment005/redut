# -*- coding: utf-8 -*-
"""Learning v2: дневные окна, EWMA, uncertainty и иерархические priors.

Модуль пока вычисляет shadow-рекомендации; v1 aggregate остаётся активным для
покупки до отдельного canary/owner gate.
"""
import datetime
import math


WINDOW_DAYS = (7, 30, 90)
DEFAULT_HALF_LIFE_DAYS = 14.0
FORMULA_VERSION = "2.0-shadow"
DEFAULT_CONFIG = {
    "mode": "shadow",
    "shadow_min_days": 30,
    "owner_approved": False,
    "canary_servers": [],
    "exploration_enabled": False,
    "exploration_rate": 0.05,
    "exploration_max_per_day": 1,
    "exploration_purchase_budget_per_day": 0.0,
}


def _day(value):
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def decay_weight(day, now=None, half_life_days=DEFAULT_HALF_LIFE_DAYS):
    stamp = _day(day)
    current = now or datetime.date.today()
    if isinstance(current, datetime.datetime):
        current = current.date()
    try:
        half_life = float(half_life_days)
        if not math.isfinite(half_life) or half_life <= 0 or stamp is None:
            return 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0
    age = (current - stamp).days
    if age < 0:
        return 0.0
    return 0.5 ** (age / half_life)


def wilson_interval(successes, total, z=1.96):
    try:
        successes, total, z = float(successes), float(total), float(z)
        if not all(math.isfinite(x) for x in (successes, total, z)) or total <= 0:
            return (0.0, 1.0)
        successes = max(0.0, min(total, successes))
        p = successes / total
        denominator = 1.0 + z * z / total
        centre = p + z * z / (2.0 * total)
        radius = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total)
        return (max(0.0, (centre - radius) / denominator),
                min(1.0, (centre + radius) / denominator))
    except (TypeError, ValueError, OverflowError):
        return (0.0, 1.0)


def _feature(success, fail):
    total = success + fail
    low, high = wilson_interval(success, total)
    return {"success": round(success, 4), "fail": round(fail, 4),
            "sample_size": round(total, 4),
            "mean": round(success / total, 6) if total > 0 else 0.5,
            "lower": round(low, 6), "upper": round(high, 6)}


def _aggregate(rows, weight):
    counters = {key: 0.0 for key in (
        "probes_ok", "probes_fail", "tg_ok", "tg_fail", "geo_ok", "geo_fail",
        "latency_sum", "latency_count", "battle_drops", "battle_seconds")}
    days = set()
    for row in rows:
        w = float(weight(row))
        if not math.isfinite(w) or w <= 0:
            continue
        days.add(str(row.get("day") or ""))
        for key in counters:
            try:
                value = float(row.get(key) or 0)
                if math.isfinite(value) and value >= 0:
                    counters[key] += value * w
            except (TypeError, ValueError, OverflowError):
                pass
    latency = (counters["latency_sum"] / counters["latency_count"]
               if counters["latency_count"] > 0 else None)
    hours = counters["battle_seconds"] / 3600.0
    return {
        "availability": _feature(counters["probes_ok"], counters["probes_fail"]),
        "telegram": _feature(counters["tg_ok"], counters["tg_fail"]),
        "geo_honesty": _feature(counters["geo_ok"], counters["geo_fail"]),
        "latency_ms": round(latency, 2) if latency is not None else None,
        "latency_samples": round(counters["latency_count"], 4),
        "battle_drop_rate": (round(counters["battle_drops"] / hours, 6)
                             if hours > 0 else None),
        "battle_hours": round(hours, 4), "observed_days": len(days),
    }


def summarize_buckets(rows, now=None, half_life_days=DEFAULT_HALF_LIFE_DAYS):
    current = now or datetime.date.today()
    if isinstance(current, datetime.datetime):
        current = current.date()
    valid = []
    for row in rows or []:
        stamp = _day((row or {}).get("day"))
        if stamp is not None and 0 <= (current - stamp).days <= 3650:
            valid.append(row)
    windows = {}
    for window in WINDOW_DAYS:
        windows[str(window)] = _aggregate(
            valid, lambda row, window=window: 1.0
            if (current - _day(row.get("day"))).days < window else 0.0)
    ewma = _aggregate(valid, lambda row: decay_weight(
        row.get("day"), now=current, half_life_days=half_life_days))
    short = windows["7"]["availability"]["mean"]
    long = windows["90"]["availability"]["mean"]
    return {"windows": windows, "ewma": ewma,
            "coverage_days": len({row.get("day") for row in valid}),
            "drift_7_vs_90": round(short - long, 6)}


def hierarchical_estimate(level_summaries, prior_mean=0.5, prior_strength=10.0,
                          feature="availability"):
    """global→provider→family→country→uid/ASN с наследованием parent prior."""
    mean = max(0.0, min(1.0, float(prior_mean)))
    strength = max(0.01, float(prior_strength))
    path = []
    total_local = 0.0
    for item in level_summaries or []:
        stats = ((item or {}).get("ewma") or {}).get(feature) or {}
        success = max(0.0, float(stats.get("success") or 0))
        fail = max(0.0, float(stats.get("fail") or 0))
        local = success + fail
        alpha = success + mean * strength
        beta = fail + (1.0 - mean) * strength
        mean = alpha / (alpha + beta)
        total_local = local
        path.append({"level": item.get("level") or "", "local_samples": round(local, 4),
                     "inherited_mean": round(mean, 6)})
    effective = total_local + strength
    low, high = wilson_interval(mean * effective, effective)
    return {"mean": round(mean, 6), "lower": round(low, 6), "upper": round(high, 6),
            "sample_size": round(total_local, 4),
            "maturity": round(total_local / effective, 6), "path": path}


def shadow_score(summary):
    """Объяснимый v2 score для shadow replay; не меняет канал и не тратит деньги."""
    ewma = (summary or {}).get("ewma") or {}
    availability = (ewma.get("availability") or {}).get("lower", 0.0)
    telegram = (ewma.get("telegram") or {}).get("lower", 0.0)
    geo = (ewma.get("geo_honesty") or {}).get("lower", 0.0)
    latency = ewma.get("latency_ms")
    drop_rate = ewma.get("battle_drop_rate")
    score = 100.0 * availability + 20.0 * telegram + 10.0 * geo
    if latency is not None:
        score -= min(40.0, float(latency) / 25.0)
    if drop_rate is not None:
        score -= min(20.0, 10.0 * float(drop_rate))
    return round(score, 3)


def _summary_for(pool, level, row, now=None):
    filters = {"level": level}
    if level != "global":
        filters["provider"] = str((row or {}).get("provider") or "")
    if level == "provider_family":
        filters["family"] = str((row or {}).get("kind") or "")
    elif level == "provider_country":
        filters["country"] = str((row or {}).get("country") or "").strip().lower()
    elif level == "uid":
        filters["family"] = str((row or {}).get("kind") or "")
        filters["country"] = str((row or {}).get("country") or "").strip().lower()
        filters["uid"] = str((row or {}).get("uid") or "")
    elif level == "asn":
        filters["family"] = str((row or {}).get("kind") or "")
        filters["country"] = str((row or {}).get("country") or "").strip().lower()
        filters["asn"] = str((row or {}).get("asn") or "")
    summary = summarize_buckets(pool.learning_buckets(**filters), now=now)
    summary["level"] = level
    return summary


def candidate_shadow_score(pool, row, now=None, prior_strength=20.0):
    """Оценка уже купленного proxy без влияния на боевой выбор.

    UID и ASN — соседние leaf-группы: выбираем ту, где больше собственных проб,
    чтобы не считать одну и ту же probe дважды. Холодный leaf наследует общий
    путь global→provider→family→country через hierarchical prior.
    """
    common = [_summary_for(pool, level, row, now) for level in (
        "global", "provider", "provider_family", "provider_country")]
    leaves = [_summary_for(pool, "uid", row, now)]
    if (row or {}).get("asn"):
        leaves.append(_summary_for(pool, "asn", row, now))
    leaf = max(leaves, key=lambda item: (
        ((item.get("ewma") or {}).get("availability") or {}).get("sample_size", 0),
        item.get("level") == "uid"))
    path = common + [leaf]
    estimates = {feature: hierarchical_estimate(
        path, prior_strength=prior_strength, feature=feature)
        for feature in ("availability", "telegram", "geo_honesty")}

    latency = drop_rate = None
    for item in reversed(path):
        ewma = item.get("ewma") or {}
        if latency is None and (ewma.get("latency_samples") or 0) > 0:
            latency = ewma.get("latency_ms")
        if drop_rate is None and (ewma.get("battle_hours") or 0) > 0:
            drop_rate = ewma.get("battle_drop_rate")
    synthetic = {"ewma": {
        "availability": estimates["availability"],
        "telegram": estimates["telegram"],
        "geo_honesty": estimates["geo_honesty"],
        "latency_ms": latency, "battle_drop_rate": drop_rate,
    }}
    score = shadow_score(synthetic)
    return {"uid": str((row or {}).get("uid") or ""), "score": score,
            "leaf": leaf["level"], "breakdown": synthetic["ewma"],
            "coverage_days": max(item.get("coverage_days") or 0 for item in path)}


def shadow_recommendation(pool, candidates, current_host=None, strategy="", now=None):
    """Посчитать v2-рекомендацию; функция только читает learning buckets."""
    rows = [dict(row) for row in (candidates or []) if (row or {}).get("uid")]
    scored = [candidate_shadow_score(pool, row, now=now) for row in rows]
    scored.sort(key=lambda item: (-item["score"], item["uid"]))
    current_uid = next((row["uid"] for row in rows
                        if current_host and row.get("host") == current_host), None)
    return {"formula_version": FORMULA_VERSION, "strategy": strategy or "",
            "current_uid": current_uid,
            "recommended_uid": scored[0]["uid"] if scored else None,
            "candidate_count": len(scored), "scores": scored}


def record_shadow_decision(pool, candidates, cfg=None, current_host=None,
                           strategy="", now=None, context="pool-refresh"):
    recommendation = shadow_recommendation(
        pool, candidates, current_host=current_host, strategy=strategy, now=now)
    mode = str(((cfg or {}).get("learning") or {}).get("mode") or "shadow")
    decision = pool.record_shadow_decision(
        recommendation, mode=mode, context=context, ts=now)
    decision["exploration"] = maybe_exploration(
        pool, candidates, cfg=cfg, current_host=current_host, now=now,
        context=context)
    return decision


def exploration_policy(cfg=None):
    raw = (cfg or {}).get("learning") or {}
    try:
        rate = float(raw.get("exploration_rate", DEFAULT_CONFIG["exploration_rate"]))
        maximum = int(raw.get("exploration_max_per_day",
                              DEFAULT_CONFIG["exploration_max_per_day"]))
        budget = float(raw.get("exploration_purchase_budget_per_day", 0.0))
        if not all(math.isfinite(value) for value in (rate, budget)):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        rate, maximum, budget = 0.0, 0, 0.0
    return {"enabled": raw.get("exploration_enabled") is True,
            "owner_approved": raw.get("owner_approved") is True,
            "rate": max(0.0, min(1.0, rate)),
            "max_per_day": max(0, maximum),
            "purchase_budget_per_day": max(0.0, budget)}


def maybe_exploration(pool, candidates, cfg=None, current_host=None, now=None,
                      rng=None, context="learning-v2"):
    """Выбрать холодный уже купленный reserve; канал и деньги не меняет."""
    policy = exploration_policy(cfg)
    blockers = []
    if not policy["enabled"]:
        blockers.append("disabled")
    if not policy["owner_approved"]:
        blockers.append("owner-approval-required")
    if not current_host:
        blockers.append("current-host-unknown")
    if policy["max_per_day"] <= 0:
        blockers.append("daily-limit-zero")
    if policy["rate"] <= 0:
        blockers.append("sample-rate-zero")
    if blockers:
        return {"result": "disabled", "reason": "+".join(blockers),
                "selected_uid": None}
    try:
        draw = float((rng or __import__("random").random)())
        if not math.isfinite(draw) or not 0.0 <= draw < 1.0:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        return {"result": "denied", "reason": "invalid-rng",
                "selected_uid": None}
    if draw >= policy["rate"]:
        return {"result": "skipped", "reason": "sample-rate",
                "selected_uid": None}

    eligible = []
    for candidate in candidates or []:
        uid = str((candidate or {}).get("uid") or "")
        stored = pool.get(uid) if uid else None
        if (not stored or stored.get("role") != "auto" or stored.get("gone")
                or stored.get("host") == current_host):
            continue
        cooldown = stored.get("cooldown_until")
        stamp = (now.replace(microsecond=0).isoformat(sep=" ")
                 if isinstance(now, datetime.datetime) else str(now or datetime.datetime.now()
                                                                 .replace(microsecond=0)
                                                                 .isoformat(sep=" ")))
        if cooldown and str(cooldown) > stamp:
            continue
        scored = candidate_shadow_score(pool, stored, now=now)
        availability = scored["breakdown"]["availability"]
        width = float(availability["upper"]) - float(availability["lower"])
        eligible.append((float(availability["sample_size"]), -width, uid, scored))
    if not eligible:
        return {"result": "denied", "reason": "no-owned-reserve",
                "selected_uid": None}
    eligible.sort(key=lambda item: item[:3])
    chosen = eligible[0]
    claim = pool.claim_exploration(
        chosen[2], current_host, max_per_day=policy["max_per_day"],
        eligible_count=len(eligible), now=now, context=context)
    claim["score"] = chosen[3]
    return claim


def exploration_purchase_status(cfg=None, estimated_cost=0.0, spent_today=0.0):
    """Readiness только: отдельного buy-actuator для exploration нет."""
    policy = exploration_policy(cfg)
    try:
        cost, spent = float(estimated_cost), float(spent_today)
        if not math.isfinite(cost) or not math.isfinite(spent) or cost < 0 or spent < 0:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        return {"eligible": False, "reason": "invalid-cost",
                "note": "readiness only; no exploration buy actuator is wired"}
    blockers = []
    if not policy["owner_approved"]:
        blockers.append("owner-approval-required")
    budget = policy["purchase_budget_per_day"]
    if budget <= 0:
        blockers.append("separate-budget-required")
    elif spent + cost > budget:
        blockers.append("exploration-budget-exceeded")
    return {"eligible": not blockers, "reason": "+".join(blockers) or "within-budget",
            "budget": budget, "remaining": max(0.0, budget - spent),
            "note": "readiness only; no exploration buy actuator is wired"}


def activation_status(pool, cfg=None, server=None, now=None):
    """Readiness gate; сам по себе никогда не включает влияние v2."""
    raw = (cfg or {}).get("learning") or {}
    mode = str(raw.get("mode") or "shadow")
    minimum = max(30, int(raw.get("shadow_min_days") or 30))
    coverage = pool.shadow_coverage(FORMULA_VERSION, now=now, modes=("shadow",))
    blockers = []
    if mode == "shadow":
        blockers.append("mode-shadow")
    if not bool(raw.get("owner_approved")):
        blockers.append("owner-approval-required")
    if coverage["days"] < minimum:
        blockers.append("shadow-days-%d/%d" % (coverage["days"], minimum))
    canaries = {str(item) for item in (raw.get("canary_servers") or [])}
    if mode == "canary" and str(server or "") not in canaries:
        blockers.append("server-not-in-canary")
    qualified_at = pool.shadow_qualification_at(FORMULA_VERSION, minimum, now=now)
    canary_coverage = (pool.shadow_coverage(
        FORMULA_VERSION, now=now, modes=("canary",), servers=canaries,
        since=qualified_at) if qualified_at else
        {"days": 0, "first_at": None, "last_at": None, "decisions": 0})
    if mode == "active" and canary_coverage["decisions"] < 1:
        blockers.append("canary-evidence-required")
    if mode not in ("shadow", "canary", "active"):
        blockers.append("invalid-mode")
    return {"eligible": not blockers, "mode": mode, "blockers": blockers,
            "coverage": coverage, "minimum_days": minimum,
            "shadow_qualified_at": qualified_at, "canary_coverage": canary_coverage,
            "note": "readiness only; no v2 actuator is wired"}
