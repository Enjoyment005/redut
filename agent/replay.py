# -*- coding: utf-8 -*-
"""Read-only offline replay learning v2 по probe_log/event/money.

Replay не открывает Pool: никаких migration/recovery/commit, сети, apply или buy.
"""
import bisect
import datetime
import hashlib
import math
import os
import shutil
import sqlite3
import tempfile

import learning


SWITCH_ACTIONS = frozenset({"apply", "rotate", "replenish", "strategy-apply",
                            "switch-provider"})


class ReplaySnapshotError(RuntimeError):
    pass


def _stamp(value):
    try:
        stamp = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")
                                                 .replace(" ", "T"))
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return stamp
    except (TypeError, ValueError, OverflowError):
        return None


def _iso(value):
    return value.replace(microsecond=0).isoformat(sep=" ")


def _percentile95(values):
    clean = sorted(_clean_numbers(values))
    if not clean:
        return None
    index = max(0, math.ceil(0.95 * len(clean)) - 1)
    return round(clean[index], 3)


def _latency_metrics(values):
    clean = _clean_numbers(values)
    return {"samples": len(clean),
            "mean_ms": round(sum(clean) / len(clean), 3) if clean else None,
            "p95_ms": _percentile95(clean)}


def _clean_numbers(values):
    clean = []
    for value in values:
        try:
            number = float(value)
            if math.isfinite(number) and number >= 0:
                clean.append(number)
        except (TypeError, ValueError, OverflowError):
            pass
    return clean


def load_sqlite(db_path, days=90, now=None):
    """Согласованный read-only snapshot нужных журналов."""
    current = now or datetime.datetime.now()
    if isinstance(current, datetime.date) and not isinstance(current, datetime.datetime):
        current = datetime.datetime.combine(current, datetime.time.max)
    days = max(1, min(3650, int(days)))
    since = _iso(current - datetime.timedelta(days=days))
    until = _iso(current)
    absolute = os.path.abspath(db_path)

    def read(path, immutable=False):
        uri_path = path.replace("\\", "/")
        suffix = "?mode=ro&immutable=1" if immutable else "?mode=rw"
        conn = sqlite3.connect("file:%s%s" % (uri_path, suffix), uri=True)
        conn.row_factory = sqlite3.Row
        def rows(table):
            return [dict(row) for row in conn.execute(
                "SELECT * FROM %s WHERE ts>=? AND ts<=? ORDER BY ts,id" % table,
                (since, until)).fetchall()]
        try:
            return {"since": since, "until": until,
                    "probe_log": rows("probe_log"), "event": rows("event"),
                    "money": rows("money")}
        finally:
            conn.close()

    wal = absolute + "-wal"
    def digest(path):
        try:
            value = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    value.update(chunk)
            return (os.path.getsize(path), value.hexdigest())
        except FileNotFoundError:
            return None

    def fingerprint():
        return digest(absolute), digest(wal)

    # SQLite read-connection сама меняет WAL shared-memory read marks. Поэтому
    # всегда снимаем файловый snapshot optimistic-loop: пара main+WAL должна иметь
    # одинаковые content hashes до и после копирования. Checkpoint/append в окне
    # обнаруживается и весь attempt повторяется; молча вернуть stale DB нельзя.
    with tempfile.TemporaryDirectory(prefix="vpn-replay-") as tmp:
        for attempt in range(8):
            attempt_dir = os.path.join(tmp, "attempt-%d" % attempt)
            os.makedirs(attempt_dir)
            copied = os.path.join(attempt_dir, "state.db")
            before = fingerprint()
            shutil.copy2(absolute, copied)
            if before[1] is not None and before[1][0] > 0:
                try:
                    shutil.copy2(wal, copied + "-wal")
                except FileNotFoundError:
                    pass
            after = fingerprint()
            if before != after:
                continue
            try:
                return read(copied, immutable=after[1] is None or after[1][0] == 0)
            except sqlite3.DatabaseError:
                continue
        raise ReplaySnapshotError("state.db/WAL менялись во время snapshot; повторите replay")


class _MemoryBuckets:
    def __init__(self):
        self._rows = {}

    @staticmethod
    def _keys(row):
        provider = str(row.get("provider") or "")
        country = str(row.get("country") or "").strip().lower()
        uid = str(row.get("uid") or "")
        keys = [("global", "", "", "", "", ""),
                ("provider", provider, "", "", "", "")]
        if provider and country:
            keys.append(("provider_country", provider, "", country, "", ""))
        if uid:
            keys.append(("uid", provider, "", country, uid, ""))
        return keys

    def add_probe(self, row):
        stamp = _stamp(row.get("ts"))
        if stamp is None:
            return
        ok = bool(row.get("ok"))
        tg = row.get("tg_ok")
        geo = row.get("geo_agree")
        latency = row.get("latency_ms")
        try:
            latency = float(latency)
            latency_ok = math.isfinite(latency) and latency >= 0
        except (TypeError, ValueError, OverflowError):
            latency, latency_ok = 0.0, False
        for level, provider, family, country, uid, asn in self._keys(row):
            key = (stamp.date().isoformat(), level, provider, family, country, uid, asn)
            bucket = self._rows.setdefault(key, {
                "day": key[0], "level": level, "provider": provider,
                "family": family, "country": country, "uid": uid, "asn": asn,
                "probes_ok": 0, "probes_fail": 0, "tg_ok": 0, "tg_fail": 0,
                "geo_ok": 0, "geo_fail": 0, "latency_sum": 0.0,
                "latency_count": 0, "battle_drops": 0, "battle_seconds": 0})
            bucket["probes_ok" if ok else "probes_fail"] += 1
            if tg is not None:
                bucket["tg_ok" if bool(tg) else "tg_fail"] += 1
            if geo is not None:
                bucket["geo_ok" if bool(geo) else "geo_fail"] += 1
            if latency_ok:
                bucket["latency_sum"] += latency
                bucket["latency_count"] += 1

    def learning_buckets(self, **filters):
        out = []
        for row in self._rows.values():
            if all(value is None or str(row.get(key)) == str(value)
                   for key, value in filters.items()):
                out.append(dict(row))
        return out


def _downtime_share(probes):
    rows = [(stamp, row) for row in probes if (stamp := _stamp(row.get("ts"))) is not None]
    rows.sort(key=lambda item: item[0])
    if len(rows) < 2:
        return None
    total = down = 0.0
    for (stamp, row), (next_stamp, _next) in zip(rows, rows[1:]):
        seconds = max(0.0, (next_stamp - stamp).total_seconds())
        total += seconds
        if not bool(row.get("ok")):
            down += seconds
    return round(down / total, 6) if total > 0 else None


def _next_probe(index, uid, stamp):
    items = index.get(uid) or []
    positions = [item[0] for item in items]
    offset = bisect.bisect_right(positions, stamp)
    return items[offset][1] if offset < len(items) else None


def run(snapshot):
    """Детерминированно воспроизвести v2 только на данных, известных к моменту решения."""
    probes = [dict(row) for row in (snapshot or {}).get("probe_log") or []]
    probes = [row for row in probes if _stamp(row.get("ts")) is not None]
    probes.sort(key=lambda row: (_stamp(row["ts"]), int(row.get("id") or 0)))
    events = [dict(row) for row in (snapshot or {}).get("event") or []]
    money = [dict(row) for row in (snapshot or {}).get("money") or []]

    actual_switches = [row for row in events
                       if row.get("action") in SWITCH_ACTIONS
                       and row.get("result") == "ok" and row.get("to_uid")]
    spend = {}
    for row in money:
        try:
            value = float(row.get("price") or 0)
            if math.isfinite(value) and value >= 0:
                currency = str(row.get("currency") or "UNKNOWN").strip().upper() or "UNKNOWN"
                spend[currency] = spend.get(currency, 0.0) + value
        except (TypeError, ValueError, OverflowError):
            pass

    current_probes = [row for row in probes if bool(row.get("is_current"))]
    actual_latency = _latency_metrics(
        row.get("latency_ms") for row in current_probes if bool(row.get("ok")))

    groups = []
    for row in probes:
        stamp = _stamp(row["ts"])
        if not groups or groups[-1][0] != stamp:
            groups.append((stamp, []))
        groups[-1][1].append(row)
    index = {}
    for row in probes:
        index.setdefault(str(row.get("uid") or ""), []).append((_stamp(row["ts"]), row))

    memory, candidates = _MemoryBuckets(), {}
    simulated_uid = None
    v2_switches = 0
    choices = []
    v2_timeline = []
    for stamp, batch in groups:
        for row in batch:
            memory.add_probe(row)
            uid = str(row.get("uid") or "")
            if uid:
                candidates[uid] = {"uid": uid, "provider": row.get("provider") or "",
                                   "country": row.get("country") or "", "kind": ""}
            if bool(row.get("is_current")):
                simulated_uid = simulated_uid or uid
        scored = [learning.candidate_shadow_score(memory, row, now=stamp)
                  for row in candidates.values()]
        scored.sort(key=lambda item: (-item["score"], item["uid"]))
        recommended = scored[0]["uid"] if scored else None
        if recommended and recommended != simulated_uid:
            if simulated_uid is not None:
                v2_switches += 1
            simulated_uid = recommended
            choices.append({"ts": _iso(stamp), "uid": recommended,
                            "score": scored[0]["score"]})
        observed = next((row for row in reversed(batch)
                         if str(row.get("uid") or "") == simulated_uid), None)
        if observed is not None:
            v2_timeline.append({"ts": _iso(stamp), "uid": simulated_uid,
                                "ok": bool(observed.get("ok")),
                                "latency_ms": observed.get("latency_ms")})

    evaluated = wrong = 0
    v2_latencies = []
    choice_outcomes = []
    for choice in choices:
        stamp = _stamp(choice["ts"])
        outcome = _next_probe(index, choice["uid"], stamp)
        if outcome is None:
            continue
        evaluated += 1
        failed = not bool(outcome.get("ok"))
        wrong += 1 if failed else 0
        if not failed:
            v2_latencies.append(outcome.get("latency_ms"))
        choice_outcomes.append({"ts": choice["ts"], "uid": choice["uid"],
                                "ok": not failed, "next_probe_at": outcome.get("ts")})

    return {
        "window": {"since": (snapshot or {}).get("since"),
                   "until": (snapshot or {}).get("until")},
        "actual": {"switches": len(actual_switches), "latency": actual_latency,
                   "downtime_share": _downtime_share(current_probes),
                   "spend_by_currency": {key: round(value, 4)
                                         for key, value in sorted(spend.items())}},
        "v2": {"switches": v2_switches,
               "extra_switches_vs_actual": max(0, v2_switches - len(actual_switches)),
               "latency": _latency_metrics(
                   row.get("latency_ms") for row in v2_timeline if row["ok"]),
               "downtime_share": _downtime_share(v2_timeline),
               "spend_by_currency": {key: round(value, 4)
                                      for key, value in sorted(spend.items())},
               "incremental_spend_by_currency": {},
               "wrong_choice": {"evaluated": evaluated, "wrong": wrong,
                                "share": round(wrong / evaluated, 6)
                                if evaluated else None}},
        "trace": {"choices": choices, "outcomes": choice_outcomes,
                  "v2_timeline": v2_timeline},
        "limitations": [
            "historical probe_log has no family/ASN, so replay hierarchy uses global/provider/country/uid",
            "downtime_share is weighted between observation timestamps, not packet-level downtime",
            "v2 uses only already observed purchased proxies and adds no hypothetical spend",
        ],
    }
