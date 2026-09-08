# -*- coding: utf-8 -*-
"""DNS Rescue coordinator.

DNS Rescue is an orthogonal, opt-in DNS interception used only after Redut's
ordinary recovery is exhausted. Every network mutation is serialized by the
same flock as proxy rotation. A failed cleanup keeps the listener alive: the
coordinator must never leave port 53 redirected to a stopped process.
"""
import datetime
import json
import os
import random
import time
import uuid

import apply as apply_mod
import dns_probe
import dns_runtime
import dns_evidence

MODES = ("disabled", "observe_only", "manual_canary", "automatic_last_resort")
ACTIVE_PHASES = ("active_isolated", "active_proxy", "active_direct")
MAX_CONTINUATION_ROUNDS = 3


class DNSRescueError(Exception):
    pass


def _audit_event(pool, **values):
    """Telemetry is best-effort and never reverses a committed data plane."""
    try:
        pool.log_event("dns-rescue", **values)
    except Exception:
        pass


def _now():
    return datetime.datetime.now().replace(microsecond=0).isoformat(sep=" ")


def _future(seconds):
    return (datetime.datetime.now() + datetime.timedelta(seconds=int(seconds))).replace(
        microsecond=0).isoformat(sep=" ")


def _boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as handle:
            value = handle.read().strip().lower()
        return value if len(value) == 36 else None
    except OSError:
        return None


def _age(stamp):
    if not stamp:
        return None
    try:
        moment = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        now = datetime.datetime.now(moment.tzinfo) if moment.tzinfo else datetime.datetime.now()
        return (now - moment).total_seconds()
    except (TypeError, ValueError):
        return None


def _is_future(stamp):
    if not stamp:
        return False
    try:
        deadline = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        now = datetime.datetime.now(deadline.tzinfo) if deadline.tzinfo else datetime.datetime.now()
        return deadline > now
    except (TypeError, ValueError):
        return False


def _cap_candidate_deadline(stamp, requested_deadline, safety_seconds=1.0):
    """Never start candidate-dependent work at or beyond evidence expiry."""
    try:
        moment = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        now = datetime.datetime.now(moment.tzinfo) if moment.tzinfo else datetime.datetime.now()
        remaining = (moment - now).total_seconds() - float(safety_seconds)
    except (TypeError, ValueError):
        remaining = -1.0
    if remaining <= 0:
        raise DNSRescueError("DNS Rescue slot evidence is expired")
    return min(float(requested_deadline), time.monotonic() + remaining)


def _require_candidate_fresh(chosen, stage):
    if not _is_future(chosen.get("not_after")):
        raise DNSRescueError("candidate evidence expired " + str(stage))


def _scope_label(scope):
    return "all" if scope == "all" else "peer"


def _active(state):
    return bool(state.get("active_scope"))


def _isolated_ttl_expired(state):
    if state.get("active_kind") != "isolated_manual":
        return False
    expires = state.get("expires_at")
    expires_age = _age(expires)
    try:
        monotonic_expired = (
            state.get("expires_monotonic") is None
            or time.monotonic() >= float(state.get("expires_monotonic")))
    except (TypeError, ValueError):
        monotonic_expired = True
    return (not expires or expires_age is None or expires_age >= 0
            or monotonic_expired)


def _state_shape_valid(cfg, state):
    """Validate the durable phase/scope/kind matrix before trusting it."""
    phase = state.get("phase")
    if phase not in ACTIVE_PHASES:
        return not any(state.get(key) for key in (
            "active_scope", "active_slot", "active_kind"))
    scope = str(state.get("active_scope") or "")
    slot_id = state.get("active_slot")
    active_kind = state.get("active_kind")
    if (not slot_id or not state.get("incident_id")
            or not state.get("generation") or not state.get("scope_identity")
            or not state.get("boot_id")):
        return False
    chosen = next((item for item in _slots(cfg) if item.get("id") == slot_id), None)
    if chosen is None:
        return False
    if phase == "active_isolated":
        return (active_kind == "isolated_manual" and scope.startswith("peer:")
                and bool(scope[5:]) and bool(state.get("expires_at"))
                and state.get("expires_monotonic") is not None
                and not state.get("manual_emergency_ref"))
    expected_phase = ("active_proxy" if chosen.get("transport") == "proxy"
                      else "active_direct")
    manual_ref_ok = (bool(state.get("manual_emergency_ref"))
                     if active_kind == "node_wide_manual"
                     else not state.get("manual_emergency_ref"))
    return (phase == expected_phase and scope == "all"
            and active_kind in ("node_wide_manual", "node_wide_automatic")
            and manual_ref_ok
            and not state.get("expires_at")
            and state.get("expires_monotonic") is None)


def _kind(scope, automatic):
    if automatic:
        return "node_wide_automatic"
    return "node_wide_manual" if scope == "all" else "isolated_manual"


def _slots(cfg):
    return list((cfg.get("dns_rescue") or {}).get("candidates") or [])


def _slot(cfg, slot_id=None, require_fresh=False):
    slots = _slots(cfg)
    if slot_id:
        for item in slots:
            if item.get("id") == slot_id:
                if require_fresh and not _is_future(item.get("not_after")):
                    raise DNSRescueError("DNS Rescue slot evidence is expired")
                return item
        raise DNSRescueError("unknown DNS Rescue slot")
    if require_fresh:
        slots = [item for item in slots if _is_future(item.get("not_after"))]
    return slots[0] if slots else None


def _tried_slots(pool, incident_id):
    return pool.tried_dns_activation_slots(incident_id)


def _active_profile_class(pool, state):
    if state.get("active_kind") in ("node_wide_manual", "node_wide_automatic"):
        return "all-present"
    return pool.committed_dns_activation_profile(
        state.get("incident_id"), state.get("active_slot"),
        state.get("active_scope"), state.get("generation"))


def _recovery_guard_scope(cfg, state, unfinished):
    """Derive only a journal-authorized listener ACL scope; never guess all."""
    candidate = state.get("active_scope")
    if not candidate:
        for operation in unfinished or ():
            kind = str(operation.get("kind") or "")
            phase = operation.get("phase")
            scope = str(operation.get("scope") or "")
            if kind.startswith("deactivate-"):
                # A deactivation may use scope=all merely as a cleanup target
                # for unknown residue.  That is not authorization to expose or
                # restart the listener for every WG peer after a crash.
                try:
                    snapshot = json.loads(operation.get("snapshot_json") or "{}")
                except (TypeError, ValueError):
                    snapshot = {}
                candidate = snapshot.get("authorized_guard_scope")
                break
            if kind == "activate-isolated_manual":
                candidate = scope
                break
            if kind in ("activate-node_wide_manual",
                        "activate-node_wide_automatic"):
                if phase in ("redirected", "verifying"):
                    candidate = "all"
                else:
                    canary = str((cfg.get("dns_rescue") or {}).get(
                        "canary_peer_ipv4") or "")
                    candidate = "peer:" + canary if canary else None
                break
    if not candidate:
        return None
    try:
        dns_runtime._scope_source(cfg, candidate)
        return candidate
    except (dns_runtime.DNSRuntimeError, KeyError, TypeError, ValueError):
        return None


def _failover_slots(cfg, current_slot, tried, require_fresh=False):
    slots = _slots(cfg)
    if require_fresh:
        slots = [item for item in slots if _is_future(item.get("not_after"))]
    current = next((item for item in slots if item.get("id") == current_slot), None)
    remaining = [item for item in slots if item.get("id") not in tried]
    if current is None:
        return remaining
    order = {item.get("id"): index for index, item in enumerate(slots)}
    return sorted(remaining, key=lambda item: (
        item.get("transport") != current.get("transport"),
        item.get("operator") == current.get("operator"),
        order.get(item.get("id"), 999)))


def _allowed(cfg, automatic=False, continuation=False):
    block = cfg.get("dns_rescue") or {}
    # A continuation is reachable only from a durable active/compensation saga.
    # Current config gates authorize new incidents, not restoration of the
    # exact route/scope/TTL identity removed for a failed coordinated exit.
    if continuation:
        return
    mode = block.get("mode", "disabled")
    if mode not in MODES or mode in ("disabled", "observe_only"):
        raise DNSRescueError("DNS Rescue activation is disabled")
    if not block.get("owner_approved"):
        raise DNSRescueError("owner approval is absent")
    if not block.get("active_probes"):
        raise DNSRescueError("active DNS probes are disabled")
    if automatic and (mode != "automatic_last_resort"
                      or (not continuation and not block.get("automatic_ready"))):
        raise DNSRescueError("automatic last-resort gate is closed")
    if automatic and (block.get('runner_contract_version') != 4
                      or not _is_future(block.get('readiness_not_after'))):
        raise DNSRescueError('automatic runner/readiness evidence is unavailable')


def _proof_context(cfg, deadline=None):
    """Freeze actual profile inventory, exact canary and direct route before proof."""
    inventory = dns_runtime.profile_inventory(cfg, deadline)
    if not inventory or not dns_runtime.emergency_route_ready(cfg, deadline):
        return None
    canary = 'peer:' + str((cfg.get('dns_rescue') or {}).get('canary_peer_ipv4') or '')
    identity = dns_runtime.wireguard_scope_identity(cfg, canary, deadline)
    route = dns_runtime.route_generation(cfg, deadline)
    if not identity or not route:
        return None
    return dict(inventory, canary_identity=identity, route_generation=route)


def _required_profiles(cfg, state=None):
    if state and state.get('active_kind') == 'isolated_manual':
        return ()
    inventory = dns_runtime.profile_inventory(cfg)
    return tuple(inventory['profiles']) if inventory else ()


def _stability(pool, state):
    """Durable counters are generation-bound and independent of probe retention."""
    try:
        value = json.loads(pool.get_setting('dns_stability') or '{}')
        if isinstance(value, dict) and value.get('generation') == state.get('generation'):
            return value
    except (TypeError, ValueError):
        pass
    return {'generation': state.get('generation'), 'dwell_started': time.monotonic(),
            'client_failures': 0, 'client_last_check': None,
            'unknown_since': None, 'unknown_alerted': False}


def _save_stability(pool, value):
    pool.set_setting('dns_stability', json.dumps(value, sort_keys=True))


def _resolve_unknowns(pool, state, *labels):
    """Clear only observations actually completed; other UNKNOWN intervals survive."""
    stability = _stability(pool, state)
    causes = stability.get('unknown_causes', {})
    for label in labels:
        causes.pop(label, None)
    stability['unknown_causes'] = causes
    stability['unknown_since'] = min((x['since'] for x in causes.values()), default=None)
    stability['unknown_alerted'] = any(x.get('alerted') for x in causes.values())
    _save_stability(pool, stability)
    if not causes and 'unknown' in str(state.get('last_error') or ''):
        pool.set_dns_state(last_error=None)
    return stability


def _physical(cfg, state):
    if (os.name != "posix" or state.get("phase") not in ACTIVE_PHASES
            or not _active(state) or not _state_shape_valid(cfg, state)):
        return False
    try:
        block = cfg.get("dns_rescue") or {}
        backend_window = max(
            15, int(block.get("active_check_seconds", 5))
            * (int(block.get("active_failures", 3)) + 1))
        path_window = int(block.get("path_evidence_ttl_seconds", 300))
        node_wide = state.get("active_kind") in (
            "node_wide_manual", "node_wide_automatic")
        return (dns_runtime.firewall_effective(cfg, scope=state.get("active_scope"))
                and dns_runtime.service_active()
                and (not node_wide or dns_runtime.emergency_route_ready(cfg))
                and bool(state.get("boot_id")) and state.get("boot_id") == _boot_id()
                and (state.get("active_kind") != "isolated_manual"
                     or (_is_future(state.get("expires_at"))
                         and state.get("expires_monotonic") is not None
                         and time.monotonic() < float(state.get("expires_monotonic"))))
                and _age(state.get("backend_last_ok")) is not None
                and 0 <= _age(state.get("backend_last_ok")) <= backend_window
                and _age(state.get("client_path_last_ok")) is not None
                and 0 <= _age(state.get("client_path_last_ok")) <= path_window
                and bool(state.get("scope_identity"))
                and dns_runtime.wireguard_scope_identity(
                    cfg, state.get("active_scope")) == state.get("scope_identity"))
    except Exception:
        return False


def _pre_exit_physical_state(cfg, state):
    """Tri-state ownership proof used before a coordinated route transition.

    A transient inspection failure must not erase the only exact compensation
    contract.  Definite drift may be torn down fail-open; unknown inspection
    instead postpones the data-plane exit without mutating DNS interception.
    """
    if (os.name != "posix" or state.get("phase") not in ACTIVE_PHASES
            or not _active(state) or not _state_shape_valid(cfg, state)):
        return "invalid"
    block = cfg.get("dns_rescue") or {}
    backend_window = max(
        15, int(block.get("active_check_seconds", 5))
        * (int(block.get("active_failures", 3)) + 1))
    path_window = int(block.get("path_evidence_ttl_seconds", 300))
    backend_age = _age(state.get("backend_last_ok"))
    path_age = _age(state.get("client_path_last_ok"))
    if (backend_age is None or backend_age < 0 or backend_age > backend_window
            or path_age is None or path_age < 0 or path_age > path_window):
        # Stale telemetry is absence of proof, not proof that the guarded
        # runtime is gone. Postpone the route transition until it is refreshed.
        return "unknown"
    if state.get("active_kind") == "isolated_manual":
        try:
            if (not _is_future(state.get("expires_at"))
                    or state.get("expires_monotonic") is None
                    or time.monotonic() >= float(state.get("expires_monotonic"))):
                return "invalid"
        except (TypeError, ValueError):
            return "invalid"
    current_boot = _boot_id()
    if not current_boot:
        return "unknown"
    if not state.get("boot_id") or state.get("boot_id") != current_boot:
        return "invalid"
    deadline = time.monotonic() + 10.0
    try:
        if not dns_runtime._firewall_attached_strict(
                cfg, scope=state.get("active_scope"),
                deadline_monotonic=deadline):
            return "invalid"
    except dns_runtime.DNSRuntimeError:
        return "unknown"
    service_state = dns_runtime.service_state(deadline)
    if service_state == "unknown":
        return "unknown"
    if service_state != "active":
        return "invalid"
    if state.get("active_kind") in (
            "node_wide_manual", "node_wide_automatic"):
        route_state = dns_runtime.emergency_route_state(cfg, deadline)
        if route_state == "unknown":
            return "unknown"
        if route_state != "ready":
            return "invalid"
    identity_state = dns_runtime.wireguard_scope_identity_state(
        cfg, state.get("active_scope"), deadline)
    if identity_state.get("status") == "unknown":
        return "unknown"
    if (identity_state.get("status") != "valid"
            or identity_state.get("identity") != state.get("scope_identity")):
        return "invalid"
    return "ready"


def _runtime_proof_recent(cfg, state):
    block = cfg.get("dns_rescue") or {}
    backend_window = max(
        15, int(block.get("active_check_seconds", 5))
        * (int(block.get("active_failures", 3)) + 1))
    path_window = int(block.get("path_evidence_ttl_seconds", 300))
    backend_age = _age(state.get("backend_last_ok"))
    path_age = _age(state.get("client_path_last_ok"))
    return (backend_age is not None and 0 <= backend_age <= backend_window
            and path_age is not None and 0 <= path_age <= path_window)


def coverage(cfg, state=None):
    state = state or {}
    proven = bool(state.get("effective_active") and state.get("proof_fresh") is True)
    global_scope = state.get("active_scope") == "all"
    return {
        "wireguard_ipv4_dns53": proven,
        "wireguard_ipv6": False,
        "application_doh_dot": False,
        "legacy_clients_external_dns": bool(proven and global_scope),
        "scope": _scope_label(state.get("active_scope")) if state.get("active_scope") else None,
        "note": "Only proven IPv4 UDP/TCP port 53 traffic entering through wg0 is controlled",
        "configured_mode": (cfg.get("dns_rescue") or {}).get("mode", "disabled"),
    }


def status(cfg, pool):
    raw = pool.dns_state()
    state = dict(raw)
    state["configured_mode"] = (cfg.get("dns_rescue") or {}).get("mode", "disabled")
    state["effective_active"] = _physical(cfg, raw)
    current_slot = next((item for item in _slots(cfg)
                         if item.get("id") == raw.get("active_slot")), None)
    state["proof_fresh"] = bool(
        state["effective_active"] and current_slot
        and _is_future(current_slot.get("not_after"))
        and 'unknown' not in str(state.get('last_error') or ''))
    state['health_status'] = ('UNKNOWN' if 'unknown' in str(state.get('last_error') or '')
                              else 'PASS' if state['proof_fresh'] else 'UNKNOWN')
    stability = _stability(pool, raw)
    state['critical_alert'] = bool(_active(raw) and stability.get('unknown_alerted'))
    if _active(raw) and stability.get('unknown_since'):
        state['health_status'] = 'UNKNOWN'
        state['proof_fresh'] = False
    state['recovery_pending'] = bool(_active(raw) and (
        state.get('last_error') == 'recovery-pending' or state.get('return_successes')))
    state['minimum_dwell_remaining'] = (max(0, int(300 - (
        time.monotonic() - float(stability.get('dwell_started', time.monotonic())))))
        if _active(raw) else 0)
    # Never expose the WG key/inventory digest through the panel/CLI.
    state.pop("scope_identity", None)
    state.pop("manual_emergency_ref", None)
    state.pop("boot_id", None)
    state.pop("expires_monotonic", None)
    if state.get("active_scope") and state["active_scope"] != "all":
        state["active_scope"] = "peer"
    unfinished = []
    for row in pool.unfinished_dns_operations(limit=20):
        public = {key: row.get(key) for key in
                  ("id", "kind", "phase", "slot_id", "requested_at", "updated_at")}
        public["scope"] = _scope_label(row.get("scope"))
        unfinished.append(public)
    return {"state": state, "coverage": coverage(cfg, state), "unfinished": unfinished}


def probe_backend(cfg, pool, incident_id=None, slot_id=None,
                  deadline_monotonic=None):
    block = cfg["dns_rescue"]
    host = block.get("listen_ip") or dns_runtime.wireguard_ip(cfg)
    suffix = str(block.get("canary_qname_suffix") or "")
    expected_ipv4 = str(block.get("canary_expected_ipv4") or "")
    if not suffix or not expected_ipv4:
        return {"ok": False, "results": [],
                "error": "owned DNS canary is not configured"}
    results = []
    qname = "%s.%s" % (uuid.uuid4().hex, suffix)
    for transport in ("udp", "tcp"):
        timeout = float(block["request_timeout_seconds"])
        if deadline_monotonic is not None:
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                return {"ok": False, "results": results,
                        "error": "operation deadline exceeded"}
            timeout = min(timeout, remaining)
        result = dns_probe.probe(
            host, block["listen_port"], transport, timeout,
            name=qname, expected_ipv4=expected_ipv4)
        pool.record_dns_probe(result, incident_id=incident_id, slot_id=slot_id)
        results.append(result)
    status = ("UNKNOWN" if any(item.get("status") == "UNKNOWN" for item in results)
              else "PASS" if all(item.get("ok") for item in results) else "FAIL")
    return {"ok": status == "PASS", "status": status, "results": results}


# Compatibility name: this proves only the backend, never the client path.
probe_listener = probe_backend


def observe(cfg, pool):
    block = cfg.get("dns_rescue") or {}
    if not block.get("owner_approved") or not block.get("active_probes"):
        return {"ok": False, "skipped": "active probes are not approved"}
    if os.name != "posix":
        return {"ok": False, "action": "unsupported", "results": []}

    def run():
        profiles = tuple(block.get("profile_classes_ready") or ())
        canary = str(block.get("canary_peer_ipv4") or "")
        scope = "peer:" + canary
        if (not profiles or not canary
                or not dns_runtime.peer_canary_runner_ready(cfg)
                or not dns_runtime.wireguard_scope_ready(cfg, scope)):
            return {"ok": False, "action": "observe-prerequisites-unproven",
                    "results": []}
        with open(cfg["singbox_config"], encoding="utf-8") as handle:
            main_config = json.load(handle)
        deadline = time.monotonic() + float(block["activation_deadline_seconds"])
        results = []
        for chosen in _slots(cfg):
            if not _is_future(chosen.get("not_after")):
                results.append({"slot": chosen.get("id"), "ok": False,
                                "error_kind": "ExpiredEvidence"})
                continue
            if time.monotonic() >= deadline:
                results.append({"slot": chosen.get("id"), "ok": False,
                                "error_kind": "DeadlineExceeded"})
                break
            try:
                candidate_deadline = _cap_candidate_deadline(
                    chosen.get("not_after"), deadline)
                _require_candidate_fresh(chosen, "before observe sidecar")
                remaining = max(0.0, candidate_deadline - time.monotonic())
                if remaining <= 0:
                    raise DNSRescueError("candidate evidence expired before observe")
                outcomes = {}
                proven = dns_runtime.candidate_sidecar_preflight_proven(
                    cfg, chosen, main_config, scope, profiles,
                    min(block["active_check_seconds"], remaining),
                    deadline_monotonic=candidate_deadline,
                    evidence_out=outcomes)
                if not outcomes:
                    outcomes = {"udp": bool(proven), "tcp": bool(proven),
                                "application_dns": bool(proven),
                                "controls": bool(proven)}
                results.append({"slot": chosen.get("id"), "ok": bool(proven),
                                "transports": {
                                    "udp": bool(outcomes.get("udp")),
                                    "tcp": bool(outcomes.get("tcp"))},
                                "application_dns": bool(
                                    outcomes.get("application_dns")),
                                "controls": bool(outcomes.get("controls")),
                                "error_kind": None if proven else "ProofFailed"})
            except Exception as error:
                results.append({"slot": chosen.get("id"), "ok": False,
                                "error_kind": type(error).__name__})
                # A cleanup exception may mean a guarded sidecar still exists;
                # do not launch another candidate until reconcile proves it gone.
                break
        return {"ok": any(item.get("ok") for item in results),
                "action": "observed", "results": results}

    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except (apply_mod.ApplyError, OSError, ValueError) as error:
        return {"ok": False, "action": "observe-failed", "results": [],
                "error": type(error).__name__}


def _validate_scope_locked(cfg, pool, scope, automatic, continuation=False,
                           profile_class=None, deadline_monotonic=None):
    _allowed(cfg, automatic=automatic, continuation=continuation)
    block = cfg.get("dns_rescue") or {}
    if os.name != "posix":
        raise DNSRescueError("activation is available only on Linux")
    if automatic:
        if scope != "all":
            raise DNSRescueError("automatic mode requires node-wide scope")
        if pool.get_setting("automat_state") != "EMERGENCY":
            raise DNSRescueError("automatic activation requires EMERGENCY")
        if pool.get_setting("emergency_manual") == "1":
            raise DNSRescueError("manual EMERGENCY blocks automatic activation")
        if not continuation and pool.get_setting("automat_frozen") == "1":
            raise DNSRescueError("automatic activation is paused")
        if pool.get_setting("dns_recovery_exhausted") != "1":
            raise DNSRescueError("ordinary recovery is not exhausted")
    elif scope == "all":
        if (pool.get_setting("automat_state") != "EMERGENCY"
                or pool.get_setting("emergency_manual") != "1"):
            raise DNSRescueError("node-wide manual rescue requires sticky manual EMERGENCY")
        if not pool.get_setting("manual_emergency_ref"):
            raise DNSRescueError("node-wide manual rescue requires an exact emergency reference")
    elif not str(scope).startswith("peer:"):
        raise DNSRescueError("manual canary requires an exact peer:<IPv4> scope")
    elif profile_class not in ("wg-ip", "external-ip"):
        raise DNSRescueError("manual canary requires an exact client profile class")
    elif (pool.get_setting("automat_state") or "OK") != "OK":
        raise DNSRescueError("isolated manual canary requires NORMAL state")
    elif ((not continuation and pool.get_setting("automat_frozen") == "1")
          or pool.get_setting("emergency_manual") == "1"):
        raise DNSRescueError("isolated manual canary is blocked by frozen/emergency state")
    if not dns_runtime.peer_canary_runner_ready(cfg):
        raise DNSRescueError("external DNS canary runner is not ready")
    if scope == "all" and not dns_runtime.emergency_route_ready(
            cfg, deadline_monotonic):
        raise DNSRescueError("node-wide rescue requires proven direct EMERGENCY route")
    if not dns_runtime.wireguard_scope_ready(cfg, scope, deadline_monotonic):
        raise DNSRescueError("WireGuard scope/profile is not proven")
    if scope == "all":
        canary_ip = str(block.get("canary_peer_ipv4") or "")
        if (not canary_ip or not dns_runtime.wireguard_scope_ready(
                cfg, "peer:" + canary_ip, deadline_monotonic)):
            raise DNSRescueError("exact synthetic WG canary peer is not proven")


def _mark_operation_failed(pool, operation, phase, error_kind):
    try:
        if phase == "planned":
            pool.transition_dns_operation(operation["id"], "failed", error=error_kind)
        elif phase not in ("committed", "rolled_back", "failed"):
            pool.transition_dns_operation(operation["id"], "rollback", error=error_kind)
            pool.transition_dns_operation(operation["id"], "rolled_back", error=error_kind)
    except (ValueError, KeyError):
        try:
            pool.transition_dns_operation(operation["id"], "failed", error=error_kind)
        except Exception:
            pass


def _activate_locked(cfg, pool, scope="all", slot_id=None, actor="user",
                     automatic=False, log=print, incident_id=None,
                     idempotency_key=None, deadline_monotonic=None,
                     continuation=False, resume_expires_at=None,
                      profile_class=None, resume_expires_monotonic=None,
                      resume_boot_id=None, expected_scope_identity=None,
                      expected_manual_emergency_ref=None,
                      clear_resume_setting=None, clear_resume_id=None,
                      proof_context=None):
    if automatic and not continuation and proof_context is None:
        raise DNSRescueError('automatic activation requires completed causal quorum')
    deadline = (deadline_monotonic if deadline_monotonic is not None else
                time.monotonic() + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    _validate_scope_locked(cfg, pool, scope, automatic, continuation=continuation,
                           profile_class=profile_class,
                           deadline_monotonic=deadline)
    chosen = _slot(cfg, slot_id, require_fresh=True)
    if chosen is None:
        raise DNSRescueError("no safe DNS candidates configured")
    deadline = _cap_candidate_deadline(chosen.get("not_after"), deadline)
    readiness = (cfg.get('dns_rescue') or {}).get('readiness_not_after')
    if automatic:
        deadline = _cap_candidate_deadline(readiness, deadline)
    inventory = (proof_context or _proof_context(cfg, deadline)) if scope == 'all' else None
    if scope == 'all' and (not inventory or _proof_context(cfg, deadline) != inventory):
        raise DNSRescueError('profile inventory changed or unavailable')
    current = pool.dns_state()
    if _active(current):
        if current.get("active_slot") == chosen["id"] and current.get("active_scope") == scope:
            if (_physical(cfg, current) and not pool.unfinished_dns_operations()):
                return {"ok": True, "action": "already-active", "state": current}
            raise DNSRescueError("matching DNS Rescue state is not physically proven")
        raise DNSRescueError("another DNS Rescue scope is already active")
    if dns_runtime.firewall_attached(cfg, deadline) or pool.unfinished_dns_operations():
        recovered = _reconcile_locked(cfg, pool, "pre-activation")
        if (_active(recovered) or dns_runtime.firewall_attached(cfg, deadline)
                or pool.unfinished_dns_operations()):
            raise DNSRescueError("stale DNS Rescue ownership is not reconciled")
    incident_id = (incident_id or (pool.get_setting("dns_incident_id") if automatic else None)
                   or (("manual-" if not automatic else "dns-") + uuid.uuid4().hex))
    active_kind = _kind(scope, automatic)
    manual_emergency_ref = (pool.get_setting("manual_emergency_ref")
                            if active_kind == "node_wide_manual" else None)
    if (expected_manual_emergency_ref is not None
            and manual_emergency_ref != expected_manual_emergency_ref):
        raise DNSRescueError("manual emergency reference changed")
    scope_identity = dns_runtime.wireguard_scope_identity(cfg, scope, deadline)
    if not scope_identity:
        raise DNSRescueError("WireGuard scope identity is not proven")
    if expected_scope_identity and scope_identity != expected_scope_identity:
        raise DNSRescueError("WireGuard scope identity changed")
    operation_profile = (profile_class if active_kind == "isolated_manual"
                         else "all-present")
    generation = uuid.uuid4().hex
    boot_id = resume_boot_id or _boot_id()
    if not boot_id:
        raise DNSRescueError("kernel boot identity is unavailable")
    expires_at = ((resume_expires_at or _future(cfg["dns_rescue"]["isolated_ttl_seconds"]))
                  if active_kind == "isolated_manual" else None)
    expires_monotonic = ((float(resume_expires_monotonic)
                          if resume_expires_monotonic is not None else
                          time.monotonic() + float(cfg["dns_rescue"]["isolated_ttl_seconds"]))
                         if active_kind == "isolated_manual" else None)
    if active_kind == "isolated_manual" and not _is_future(expires_at):
        raise DNSRescueError("isolated DNS Rescue deadline is expired")
    if (active_kind == "isolated_manual"
            and (resume_boot_id and resume_boot_id != _boot_id()
                 or expires_monotonic is None or expires_monotonic <= time.monotonic())):
        raise DNSRescueError("isolated DNS Rescue monotonic deadline is expired")
    key = (idempotency_key or
           "dns-activate:%s:%s:%s" % (incident_id, chosen["id"], scope))
    operation = pool.begin_dns_operation(
        incident_id, "activate-" + active_kind, chosen["id"], scope, actor, key,
        profile_class=operation_profile,
        expires_at=expires_at, generation=generation,
        snapshot={"firewall_attached": dns_runtime.firewall_attached(cfg, deadline),
                  "service_active": dns_runtime.service_active(deadline),
                  "scope_identity": scope_identity,
                  "manual_emergency_ref": manual_emergency_ref})
    # A resumed idempotent operation must keep the durable generation/expiry
    # created by its first attempt, not invent a new in-memory identity.
    generation = operation.get("generation") or generation
    expires_at = operation.get("expires_at") or expires_at
    if operation["phase"] == "committed":
        current = pool.dns_state()
        if (_active(current) and current.get("active_slot") == chosen["id"]
                and current.get("scope_identity") == scope_identity
                and _physical(cfg, current)):
            return {"ok": True, "action": "idempotent", "state": current}
        raise DNSRescueError("committed operation has no matching effective state")
    op_phase = operation["phase"]
    state_phase = "idle" if active_kind == "isolated_manual" else "probing"
    # Compute node-wide preflight authorization before any fallible staging.
    # Until the global ACL itself is completely installed, recovery may expose
    # the listener only to this exact canary peer.
    preflight_scope = ("peer:" + str(cfg["dns_rescue"]["canary_peer_ipv4"])
                       if scope == "all" else scope)
    # Tracks the narrowest listener guard that has actually been installed.
    # A failed exact-peer preflight must never be "repaired" by broadening the
    # high listener port to the whole WireGuard subnet.
    guard_scope = preflight_scope
    pool.set_dns_state(phase=state_phase, configured_mode=cfg["dns_rescue"]["mode"],
                       incident_id=incident_id, attempt_used=True, last_error=None,
                       active_kind=None, expires_at=None, generation=generation,
                       scope_identity=scope_identity, boot_id=boot_id,
                       expires_monotonic=expires_monotonic,
                       backend_last_ok=None, client_path_last_ok=None)
    try:
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        with open(cfg["singbox_config"], encoding="utf-8") as handle:
            main_config = json.load(handle)
        dns_runtime.stage_config(cfg, chosen, main_config,
                                 deadline_monotonic=deadline)
        if time.monotonic() >= deadline:
            raise DNSRescueError("activation deadline exceeded before service start")
        pool.transition_dns_operation(operation["id"], "started")
        op_phase = "started"
        # Node-wide changes first expose the high listener port only to one
        # exact synthetic peer. No global DNS traffic is redirected yet.
        dns_runtime.stage_listener_acl(cfg, scope=preflight_scope,
                                       deadline_monotonic=deadline)
        _require_candidate_fresh(chosen, "before service start")
        dns_runtime.service_start(cfg, deadline)
        _require_candidate_fresh(chosen, "before initial backend proof")
        initial = probe_backend(cfg, pool, incident_id, chosen["id"], deadline)
        if not initial["ok"]:
            raise DNSRescueError("gateway backend did not pass UDP and TCP probes")
        required_profiles = (tuple(inventory['profiles'])
                             if active_kind != "isolated_manual" else
                             (operation_profile,))
        if scope == "all":
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                raise DNSRescueError("candidate preflight deadline exceeded")
            dns_runtime.activate_firewall(
                cfg, scope=preflight_scope, deadline_monotonic=deadline)
            if not dns_runtime.client_candidate_preflight_proven(
                    cfg, preflight_scope, required_profiles,
                    min(cfg["dns_rescue"]["active_check_seconds"], remaining),
                    deadline_monotonic=deadline):
                raise DNSRescueError("candidate preflight through exact WG peer failed")
            if (not _detach_redirect_locked(
                    cfg, pool, scope=preflight_scope, deadline_monotonic=deadline)
                    or not dns_runtime.redirect_detached(cfg, deadline)):
                raise DNSRescueError("candidate preflight redirect cleanup failed")
            # Replace the test-only ACL with the node-wide guard while NAT is
            # still absent. The listener is stopped during the ACL transition.
            dns_runtime.service_stop(deadline)
            dns_runtime.remove_listener_acl(cfg, preflight_scope, deadline)
            dns_runtime.stage_listener_acl(cfg, scope=scope,
                                           deadline_monotonic=deadline)
            guard_scope = scope
            _require_candidate_fresh(chosen, "before guarded service restart")
            dns_runtime.service_start(cfg, deadline)
            _require_candidate_fresh(chosen, "before restarted backend proof")
            restarted = probe_backend(cfg, pool, incident_id, chosen["id"], deadline)
            if not restarted["ok"]:
                raise DNSRescueError("gateway backend failed after guarded preflight")
            _validate_scope_locked(
                cfg, pool, scope, automatic, continuation=continuation,
                profile_class=profile_class, deadline_monotonic=deadline)
            if dns_runtime.wireguard_scope_identity(cfg, scope, deadline) != scope_identity:
                raise DNSRescueError("WireGuard scope changed during candidate preflight")
            if automatic:
                remaining = max(0.0, deadline - time.monotonic())
                latest = dns_runtime.causal_round(
                    cfg, required_profiles, chosen, min(2.5, remaining), deadline)
                if (remaining <= 0 or not dns_evidence.current_fault_confirmed(
                        latest, required_profiles)):
                    raise DNSRescueError("primary path recovered during candidate preflight")
        _require_candidate_fresh(chosen, "before live cutover")
        if scope == 'all' and _proof_context(cfg, deadline) != inventory:
            raise DNSRescueError('profile inventory changed before live cutover')
        if automatic and not _is_future(readiness):
            raise DNSRescueError('readiness expired before live cutover')
        if dns_runtime.wireguard_scope_identity(
                cfg, scope, deadline) != scope_identity:
            raise DNSRescueError("WireGuard scope changed before live cutover")
        pool.transition_dns_operation(operation["id"], "redirected")
        op_phase = "redirected"
        dns_runtime.activate_firewall(cfg, scope=scope,
                                      deadline_monotonic=deadline)
        pool.transition_dns_operation(operation["id"], "verifying")
        op_phase = "verifying"
        if not dns_runtime.firewall_effective(cfg, scope=scope,
                                              deadline_monotonic=deadline):
            raise DNSRescueError("redirect is not effective")
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            raise DNSRescueError("activation deadline exceeded before client-path proof")
        proof_budget = min(cfg["dns_rescue"]["active_check_seconds"], remaining)
        _require_candidate_fresh(chosen, "before client-path proof")
        if not dns_runtime.client_roundtrip_proven(
                cfg, scope, required_profiles, proof_budget,
                deadline_monotonic=deadline):
            raise DNSRescueError("external WG client request/reply proof failed")
        _require_candidate_fresh(chosen, "before final backend proof")
        final = probe_backend(cfg, pool, incident_id, chosen["id"], deadline)
        if not final["ok"]:
            raise DNSRescueError("post-cutover backend probe failed")
        if time.monotonic() >= deadline:
            raise DNSRescueError("activation deadline exceeded")
        _require_candidate_fresh(chosen, "before commit")
        if scope == 'all' and _proof_context(cfg, deadline) != inventory:
            raise DNSRescueError('profile inventory changed before commit')
        if automatic and not _is_future(readiness):
            raise DNSRescueError('readiness expired before commit')
        if dns_runtime.wireguard_scope_identity(
                cfg, scope, deadline) != scope_identity:
            raise DNSRescueError("WireGuard scope changed before commit")
        phase = ("active_isolated" if active_kind == "isolated_manual" else
                 ("active_proxy" if chosen["transport"] == "proxy" else "active_direct"))
        state = pool.commit_dns_activation(
            operation["id"],
            clear_resume_setting=clear_resume_setting,
            clear_resume_id=clear_resume_id,
            phase=phase, configured_mode=cfg["dns_rescue"]["mode"],
            incident_id=incident_id, active_scope=scope, active_slot=chosen["id"],
            activated_at=_now(), attempt_used=True, return_successes=0,
            last_error=None, active_kind=active_kind, expires_at=expires_at,
            active_failures=0, active_last_check=_now(), return_last_check=None,
            generation=generation, backend_last_ok=_now(),
            client_path_last_ok=_now(), scope_identity=scope_identity,
            boot_id=boot_id, expires_monotonic=expires_monotonic,
            manual_emergency_ref=manual_emergency_ref)
        _save_stability(pool, _stability(pool, state))
        _audit_event(pool, actor=actor, result="active",
                     detail="slot=%s transport=%s scope=%s" % (
                         chosen["id"], chosen["transport"], _scope_label(scope)))
        result = {"ok": True, "action": "activated", "state": state}
        try:
            result["coverage"] = coverage(cfg, dict(
                state, effective_active=True,
                proof_fresh=_is_future(chosen.get("not_after"))))
        except Exception:
            pass
        return result
    except Exception as error:
        error_kind = type(error).__name__
        cleanup_deadline = time.monotonic() + 10.0
        try:
            redirect_detached = bool(_detach_redirect_locked(
                cfg, pool, scope=scope, deadline_monotonic=cleanup_deadline))
        except Exception:
            redirect_detached = False
        if not redirect_detached or not dns_runtime.redirect_detached(
                cfg, cleanup_deadline):
            try:
                if not dns_runtime.listener_guard_effective(
                        cfg, guard_scope, cleanup_deadline):
                    dns_runtime.stage_listener_acl(
                        cfg, guard_scope, cleanup_deadline)
                if not dns_runtime.service_active(cleanup_deadline):
                    dns_runtime.service_start(cfg, cleanup_deadline)
            except Exception:
                pass
            try:
                pool.transition_dns_operation(operation["id"], "failed",
                                              error="cleanup:" + error_kind)
            except Exception:
                pass
            state = pool.set_dns_state(
                phase="recovering", configured_mode=cfg["dns_rescue"]["mode"],
                incident_id=incident_id, active_scope=guard_scope,
                active_slot=chosen["id"],
                activated_at=_now(), attempt_used=True, last_error="cleanup:" + error_kind,
                active_kind=active_kind, expires_at=expires_at, generation=generation)
            return {"ok": False, "action": "fail-open-blocked", "error": str(error),
                    "state": state}
        try:
            dns_runtime.service_stop(cleanup_deadline)
            dns_runtime.remove_listener_acl(cfg, guard_scope, cleanup_deadline)
        except Exception as cleanup_error:
            # Redirect is proven absent. Keep/rebuild the ACL if the listener
            # could not be stopped; direct high-port access remains denied.
            try:
                if not dns_runtime.service_inactive(cleanup_deadline) and not dns_runtime.listener_guard_effective(
                        cfg, guard_scope, time.monotonic() + 5.0):
                    dns_runtime.stage_listener_acl(
                        cfg, guard_scope, time.monotonic() + 5.0)
            except Exception:
                pass
            try:
                pool.transition_dns_operation(operation["id"], "failed",
                                              error="cleanup:" + type(cleanup_error).__name__)
            except Exception:
                pass
            state = pool.set_dns_state(
                phase="recovering", configured_mode=cfg["dns_rescue"]["mode"],
                incident_id=incident_id, active_scope=None, active_slot=None,
                active_kind=None, last_error="cleanup:" + type(cleanup_error).__name__,
                backend_last_ok=None, client_path_last_ok=None,
                scope_identity=None, boot_id=None, expires_monotonic=None)
            return {"ok": False, "action": "cleanup-pending", "error": str(error),
                    "state": state}
        _mark_operation_failed(pool, operation, op_phase, error_kind)
        state = pool.set_dns_state(
            phase="idle" if active_kind == "isolated_manual" else "failed",
            configured_mode=cfg["dns_rescue"]["mode"], incident_id=incident_id,
            active_scope=None, active_slot=None, activated_at=None, attempt_used=True,
            return_successes=0, last_error=error_kind, active_kind=None,
            expires_at=None, active_failures=0, active_last_check=None,
            return_last_check=None, generation=generation,
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        _audit_event(pool, actor=actor, result="failed",
                     detail="activation failed: %s scope=%s" % (
                         error_kind, _scope_label(scope)))
        return {"ok": False, "action": "rolled-back", "error": str(error), "state": state}


def activate(cfg, pool, scope="all", slot_id=None, actor="user", automatic=False,
             log=print, _locked=False, incident_id=None, profile_class=None):
    def run():
        return _activate_locked(cfg, pool, scope, slot_id, actor, automatic, log,
                                incident_id, profile_class=profile_class)
    if _locked:
        return run()
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def _finish_drain_operation(pool, operation):
    phases = ('planned', 'staging', 'started', 'redirected', 'verifying', 'committed')
    phase = operation.get('phase')
    if phase not in phases:
        raise DNSRescueError('invalid pending drain phase')
    for next_phase in phases[phases.index(phase) + 1:]:
        pool.transition_dns_operation(operation['id'], next_phase)


def _detach_redirect_locked(cfg, pool, scope='all', deadline_monotonic=None):
    """Persist all drain scopes before NAT mutation; replay survives lost chains."""
    operations = []
    state = pool.dns_state()
    pending = pool.unfinished_dns_operations()
    incident = (state.get('incident_id') or next(
        (op.get('incident_id') for op in pending if op.get('incident_id')), None)
        or 'cleanup-' + uuid.uuid4().hex)

    def record_plan(scopes):
        if any(json.loads(op.get('snapshot_json') or '{}').get('drain_scopes') == scopes
               for op in operations):
            return
        operation = pool.begin_dns_operation(
            incident, 'scope-drain', state.get('active_slot'),
            scope, 'recovery', 'dns-scope-drain:' + uuid.uuid4().hex,
            generation=state.get('generation'), snapshot={'drain_scopes': scopes})
        operation = pool.transition_dns_operation(operation['id'], 'staging')
        operations.append(operation)

    record_plan([scope])
    result = dns_runtime.deactivate_redirect(
        cfg, scope=scope, deadline_monotonic=deadline_monotonic,
        on_detach_plan=record_plan,
        on_global_drain=lambda: _audit_event(
            pool, actor='recovery', result='degraded',
            detail='stale global ownership requires journaled global conntrack drain'))
    if not result:
        raise DNSRescueError('redirect and conntrack drain not proven')
    for operation in operations:
        _finish_drain_operation(pool, operation)
    return result


def _replay_pending_drains(cfg, pool, deadline):
    """Complete durable drains before any janitor may stop a listener."""
    operations = [op for op in pool.unfinished_dns_operations()
                  if op.get('kind') == 'scope-drain']
    if not operations:
        return
    scopes = set()
    for operation in operations:
        snapshot = json.loads(operation.get('snapshot_json') or '{}')
        values = snapshot.get('drain_scopes')
        if not isinstance(values, list) or not values:
            raise DNSRescueError('pending drain scope is unknown')
        for value in values:
            dns_runtime._scope_source(cfg, value)
            scopes.add(value)
    # Reinspect current ownership, journal any newly found scope, then replay
    # older scopes which are no longer discoverable after a killed NAT detach.
    requested = 'all' if 'all' in scopes else next(iter(sorted(scopes)))
    _detach_redirect_locked(cfg, pool, requested, deadline)
    for scope in (['all'] if 'all' in scopes else sorted(scopes)):
        dns_runtime._drain_dns_conntrack(cfg, scope, deadline)
    for operation in operations:
        _finish_drain_operation(pool, operation)


def _restore_detached_generation(cfg, pool, current, operation, deadline):
    """Restore the exact live generation; never restart a changed or dead scope."""
    scope = current.get('active_scope')
    if (not scope or dns_runtime.service_state(deadline) != 'active'
            or dns_runtime.wireguard_scope_identity(cfg, scope, deadline)
            != current.get('scope_identity')
            or not dns_runtime.listener_guard_effective(cfg, scope, deadline)):
        raise DNSRescueError('last working generation cannot be safely restored')
    dns_runtime.activate_firewall(cfg, scope=scope, deadline_monotonic=deadline)
    if not dns_runtime.firewall_effective(cfg, scope=scope, deadline_monotonic=deadline):
        raise DNSRescueError('restored redirect is not proven')
    if operation.get('phase') != 'rollback':
        pool.transition_dns_operation(operation['id'], 'rollback')
    state = pool.commit_dns_restoration(operation['id'], current.get('generation'),
                                        scope, current['phase'])
    _audit_event(pool, actor='recovery', result='rescue-restored',
                 detail='primary DNS after NAT detachment is not proven')
    return {'ok': False, 'action': 'primary-unproven-rescue-restored', 'state': state}


def _deactivate_locked(cfg, pool, actor="user", reason="manual",
                       deadline_monotonic=None):
    deadline = (deadline_monotonic if deadline_monotonic is not None
                else time.monotonic() + 15.0)
    try:
        _replay_pending_drains(cfg, pool, deadline)
    except Exception:
        state = pool.set_dns_state(phase='recovering', last_error='drain-inspection-unknown')
        return {'ok': False, 'action': 'fail-open-blocked', 'state': state}
    current = pool.dns_state()
    attached = dns_runtime.firewall_attached(cfg, deadline)
    unfinished = pool.unfinished_dns_operations()
    if _active(current) and current.get('phase') == 'recovering':
        for pending in unfinished:
            if pending.get('generation') != current.get('generation'):
                continue
            try:
                snapshot_phase = json.loads(pending.get('snapshot_json') or '{}').get('active_phase')
            except (TypeError, ValueError):
                continue
            if snapshot_phase in ACTIVE_PHASES:
                current = dict(current, phase=snapshot_phase)
                break
    if not _active(current) and not attached and not unfinished:
        if not dns_runtime.service_inactive(deadline):
            try:
                dns_runtime.service_stop(deadline)
            except Exception as error:
                current = pool.set_dns_state(
                    phase="recovering", active_scope=None, active_slot=None,
                    active_kind=None, last_error="cleanup:" + type(error).__name__,
                    backend_last_ok=None, client_path_last_ok=None,
                    scope_identity=None, boot_id=None, expires_monotonic=None)
                return {"ok": False, "action": "service-stop-unproven",
                        "error": str(error), "state": current}
        if current.get("phase") in ("probing", "failed", "recovering"):
            current = pool.set_dns_state(phase="idle", active_scope=None, active_slot=None,
                                         activated_at=None, active_kind=None, expires_at=None,
                                         active_failures=0, active_last_check=None,
                                         backend_last_ok=None, client_path_last_ok=None,
                                         scope_identity=None, boot_id=None,
                                         expires_monotonic=None)
        return {"ok": True, "action": "already-idle", "state": current}
    scope = _recovery_guard_scope(cfg, current, unfinished)
    runtime_scope = scope or "all"
    incident = current.get("incident_id") or uuid.uuid4().hex
    generation = current.get("generation") or "unknown"
    primary_proof_required = (_active(current) and reason in (
        'manual', 'primary-dns-restored', 'coordinated-emergency-exit'))
    snapshot = {'firewall_attached': attached, 'authorized_guard_scope': scope,
                'service_active': dns_runtime.service_active(deadline),
                'primary_proof_required': primary_proof_required,
                'active_phase': current.get('phase')}
    key = "dns-deactivate:%s:%s:%s" % (incident, generation, reason)
    operation = pool.begin_dns_operation(
        incident, "deactivate-" + str(current.get("active_kind") or "recovery"),
        current.get("active_slot"), runtime_scope, actor, key, generation=generation,
        snapshot=snapshot)
    if operation.get("phase") in ("failed", "rolled_back"):
        # A prior terminal cleanup attempt is audit history, not a reusable
        # transaction. Give the bounded retry a fresh journal identity.
        operation = pool.begin_dns_operation(
            incident, "deactivate-" + str(current.get("active_kind") or "recovery"),
            current.get("active_slot"), runtime_scope, actor,
            key + ":retry:" + uuid.uuid4().hex, generation=generation,
            snapshot=snapshot)
    if operation["phase"] == "committed" and dns_runtime.firewall_detached(cfg, deadline):
        state = pool.set_dns_state(phase="idle", active_scope=None, active_slot=None,
                                   activated_at=None, active_kind=None, expires_at=None,
                                   active_failures=0, active_last_check=None,
                                   backend_last_ok=None, client_path_last_ok=None,
                                   scope_identity=None, boot_id=None,
                                   expires_monotonic=None)
        return {"ok": True, "action": "idempotent", "state": state}
    op_phase = operation["phase"]
    drain_complete = False
    try:
        pool.set_dns_state(phase="recovering", last_error=None)
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        if not _detach_redirect_locked(
                cfg, pool, scope=runtime_scope, deadline_monotonic=deadline):
            raise DNSRescueError("interception cleanup is not proven")
        drain_complete = True
        pool.transition_dns_operation(operation["id"], "started")
        op_phase = "started"
        if not dns_runtime.redirect_detached(cfg, deadline):
            raise DNSRescueError("redirect remains attached")
        if primary_proof_required:
            profile = _active_profile_class(pool, current)
            profiles = ((profile,) if current.get('active_kind') == 'isolated_manual' and profile
                        else _required_profiles(cfg))
            proof = dns_runtime.client_primary_detached_result(
                cfg, runtime_scope, profiles, min(3.0, max(0.01, deadline - time.monotonic())),
                deadline)
            if proof['status'] != 'PASS':
                try:
                    return _restore_detached_generation(
                        cfg, pool, current, operation, time.monotonic() + 10.0)
                except Exception:
                    # Keep the journal and guarded listener for a later conclusive
                    # retry. UNKNOWN restoration is not permission to stop DNS.
                    state = pool.set_dns_state(phase='recovering',
                                               last_error='detach-restore-unknown')
                    return {'ok': False, 'action': 'detach-restore-unknown', 'state': state}
        dns_runtime.service_stop(deadline)
        dns_runtime.remove_listener_acl(cfg, runtime_scope, deadline)
        pool.transition_dns_operation(operation["id"], "redirected")
        op_phase = "redirected"
        pool.transition_dns_operation(operation["id"], "verifying")
        op_phase = "verifying"
        if (not dns_runtime.firewall_detached(cfg, deadline)
                or dns_runtime.service_active(deadline)):
            raise DNSRescueError("deactivation effective state mismatch")
        state = pool.set_dns_state(
            phase="idle", active_scope=None, active_slot=None, activated_at=None,
            active_kind=None, expires_at=None, active_failures=0,
            active_last_check=None, return_successes=0, return_last_check=None,
            last_error=None, backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        pool.transition_dns_operation(operation["id"], "committed")
        for previous_operation in unfinished:
            if previous_operation['id'] != operation['id']:
                _mark_operation_failed(pool, previous_operation,
                                       previous_operation['phase'], 'completed-by-deactivation')
        _audit_event(pool, actor=actor, result="idle",
                     detail="deactivated: %s scope=%s" % (
                         reason, _scope_label(runtime_scope)))
        return {"ok": True, "action": "deactivated", "state": state}
    except Exception as error:
        error_kind = type(error).__name__
        if not drain_complete:
            state = pool.set_dns_state(phase='recovering', last_error='drain-inspection-unknown')
            return {'ok': False, 'action': 'fail-open-blocked', 'state': state}
        try:
            redirect_remains = not dns_runtime.redirect_detached(
                cfg, time.monotonic() + 5.0)
        except Exception:
            redirect_remains = True
        if redirect_remains:
            try:
                if scope and not dns_runtime.listener_guard_effective(
                        cfg, scope, time.monotonic() + 5.0):
                    dns_runtime.stage_listener_acl(
                        cfg, scope, time.monotonic() + 5.0)
                cleanup_retry = time.monotonic() + 5.0
                if (scope and dns_runtime.listener_guard_effective(
                        cfg, scope, cleanup_retry)
                        and dns_runtime.service_state(cleanup_retry) == "inactive"):
                    dns_runtime.service_start(cfg, cleanup_retry)
            except Exception:
                pass
            state = pool.set_dns_state(phase="recovering", active_scope=scope,
                                       last_error="cleanup:" + error_kind)
        else:
            try:
                cleanup_retry = time.monotonic() + 5.0
                if not dns_runtime.service_inactive(cleanup_retry):
                    if (scope and not dns_runtime.listener_guard_effective(
                            cfg, scope, time.monotonic() + 5.0)):
                        dns_runtime.stage_listener_acl(
                            cfg, scope, time.monotonic() + 5.0)
                    dns_runtime.service_stop(time.monotonic() + 5.0)
                dns_runtime.remove_listener_acl(
                    cfg, runtime_scope, time.monotonic() + 5.0)
            except Exception:
                pass
            state = pool.set_dns_state(phase="failed", active_scope=None, active_slot=None,
                                       activated_at=None, active_kind=None, expires_at=None,
                                       last_error=error_kind, backend_last_ok=None,
                                       client_path_last_ok=None, scope_identity=None,
                                       boot_id=None, expires_monotonic=None)
        try:
            pool.transition_dns_operation(operation["id"], "failed", error=error_kind)
        except Exception:
            pass
        return {"ok": False, "action": "fail-open-blocked" if redirect_remains else "failed",
                "error": str(error), "state": state}


def deactivate(cfg, pool, actor="user", reason="manual", _locked=False):
    if os.name != "posix":
        return {"ok": False, "action": "unsupported", "state": pool.dns_state()}
    if _locked:
        return _deactivate_locked(cfg, pool, actor, reason)
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _deactivate_locked(cfg, pool, actor, reason)
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def _new_boot_resume_descriptor(pool, state):
    if (state.get("active_kind") not in (
            "node_wide_manual", "node_wide_automatic")
            or state.get("active_scope") != "all"):
        return None
    profile_class = _active_profile_class(pool, state)
    if profile_class != "all-present":
        return None
    return {
        "resume_id": uuid.uuid4().hex,
        "incident_id": state.get("incident_id"),
        "scope": "all", "slot_id": state.get("active_slot"),
        "active_kind": state.get("active_kind"),
        "profile_class": profile_class,
        "scope_identity": state.get("scope_identity"),
        "manual_emergency_ref": state.get("manual_emergency_ref"),
        "attempt_seq": 0, "retry_monotonic": 0, "target_boot_id": None,
        "max_rounds": MAX_CONTINUATION_ROUNDS, "exhausted": False,
    }


def _new_exit_resume_descriptor(pool, state):
    profile_class = _active_profile_class(pool, state)
    kind = state.get("active_kind")
    scope = state.get("active_scope")
    valid = (
        (kind == "isolated_manual" and str(scope or "").startswith("peer:")
         and profile_class in ("wg-ip", "external-ip"))
        or (kind in ("node_wide_manual", "node_wide_automatic")
            and scope == "all" and profile_class == "all-present"))
    if not valid:
        return None
    return {
        "resume_id": uuid.uuid4().hex,
        "incident_id": state.get("incident_id"),
        "scope": scope, "slot_id": state.get("active_slot"),
        "active_kind": kind, "expires_at": state.get("expires_at"),
        "expires_monotonic": state.get("expires_monotonic"),
        "boot_id": state.get("boot_id"),
        "scope_identity": state.get("scope_identity"),
        "profile_class": profile_class,
        "manual_emergency_ref": state.get("manual_emergency_ref"),
        "attempt_seq": 0, "retry_monotonic": 0,
        "max_rounds": MAX_CONTINUATION_ROUNDS, "exhausted": False,
    }


def _resume_matches_active_state(resume, state):
    if not isinstance(resume, dict):
        return False
    pairs = (
        ("incident_id", "incident_id"), ("scope", "active_scope"),
        ("slot_id", "active_slot"), ("active_kind", "active_kind"),
        ("boot_id", "boot_id"), ("scope_identity", "scope_identity"),
    )
    if any(resume.get(left) != state.get(right) for left, right in pairs):
        return False
    return ((resume.get("manual_emergency_ref") or None)
            == (state.get("manual_emergency_ref") or None))


def _clear_physical_resume(pool, setting_key, state):
    """Resolve a publish-before-teardown crash without leaving stale replay."""
    raw = pool.get_setting(setting_key)
    if not raw:
        return None
    try:
        resume = json.loads(raw)
    except (TypeError, ValueError):
        return False
    if not isinstance(resume, dict) or not resume.get("resume_id"):
        return False
    # A matching descriptor was published immediately before a teardown that
    # never began. A conflicting descriptor is superseded by the conclusively
    # physical active generation and must never replay after its later removal.
    matched = _resume_matches_active_state(resume, state)
    cleared = pool.clear_dns_resume(setting_key, resume["resume_id"])
    return matched if cleared else False


def _schedule_continuation_retry(pool, setting_key, resume, attempt_seq,
                                 pending_action, exhausted_action,
                                 error_label, errors, clear_active=False):
    """Persist one bounded compensation round without storing raw errors."""
    next_attempt = attempt_seq + 1
    resume["attempt_seq"] = next_attempt
    resume["max_rounds"] = MAX_CONTINUATION_ROUNDS
    if next_attempt >= MAX_CONTINUATION_ROUNDS:
        resume["exhausted"] = True
        resume["retry_monotonic"] = 0
        pool.set_setting(setting_key,
                         json.dumps(resume, ensure_ascii=True, sort_keys=True))
        fields = {"last_error": error_label + "-exhausted"}
        if clear_active:
            fields.update({
                "phase": "failed", "active_scope": None, "active_slot": None,
                "active_kind": None, "backend_last_ok": None,
                "client_path_last_ok": None, "scope_identity": None,
                "boot_id": None, "expires_monotonic": None})
        state = pool.set_dns_state(**fields)
        pool.clear_dns_resume(setting_key, resume.get("resume_id"))
        return {"ok": False, "action": exhausted_action,
                "attempts": errors, "state": state}
    retry_delay = min(300, 2 ** min(next_attempt, 8))
    resume["exhausted"] = False
    resume["retry_monotonic"] = time.monotonic() + retry_delay
    pool.set_setting(setting_key,
                     json.dumps(resume, ensure_ascii=True, sort_keys=True))
    state = pool.set_dns_state(last_error=error_label + "-retry-pending")
    return {"ok": False, "action": pending_action,
            "retry_after_seconds": retry_delay, "attempts": errors,
            "state": state}


def _resume_after_boot_locked(cfg, pool, log=print):
    raw = pool.get_setting("dns_boot_resume")
    try:
        resume = json.loads(raw) if raw else None
        required = ("resume_id", "incident_id", "scope", "slot_id",
                    "active_kind", "profile_class", "scope_identity")
        if (not isinstance(resume, dict)
                or not all(resume.get(key) for key in required)
                or resume.get("scope") != "all"
                or resume.get("active_kind") not in (
                    "node_wide_manual", "node_wide_automatic")
                or resume.get("profile_class") != "all-present"
                or (resume.get("active_kind") == "node_wide_manual"
                    and not resume.get("manual_emergency_ref"))):
            raise ValueError("invalid boot resume descriptor")
    except (TypeError, ValueError):
        pool.set_setting("dns_boot_resume", None)
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-invalid",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        return {"ok": False, "action": "boot-resume-invalid", "state": state}
    state = pool.dns_state()
    if _physical(cfg, state):
        pool.set_setting("dns_boot_resume", None)
        return {"ok": True, "action": "boot-already-restored", "state": state}
    try:
        attempt_seq = max(0, int(resume.get("attempt_seq") or 0))
    except (TypeError, ValueError):
        attempt_seq = MAX_CONTINUATION_ROUNDS
    if resume.get("exhausted") is True or attempt_seq >= MAX_CONTINUATION_ROUNDS:
        resume["exhausted"] = True
        resume["max_rounds"] = MAX_CONTINUATION_ROUNDS
        resume["retry_monotonic"] = 0
        pool.set_setting("dns_boot_resume",
                         json.dumps(resume, ensure_ascii=True, sort_keys=True))
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-exhausted",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        pool.clear_dns_resume("dns_boot_resume", resume.get("resume_id"))
        return {"ok": False, "action": "boot-resume-exhausted", "state": state}
    current_boot = _boot_id()
    if not current_boot:
        return _schedule_continuation_retry(
            pool, "dns_boot_resume", resume, attempt_seq,
            "boot-resume-retry-pending", "boot-resume-exhausted",
            "boot-resume", [{"slot": None,
                              "action": "boot-identity-unavailable"}],
            clear_active=True)
    if resume.get("target_boot_id") != current_boot:
        # monotonic values are meaningful only within one boot. Preserve the
        # bounded round count but discard a stale old-uptime backoff.
        resume["target_boot_id"] = current_boot
        resume["retry_monotonic"] = 0
        pool.set_setting("dns_boot_resume",
                         json.dumps(resume, ensure_ascii=True, sort_keys=True))
    try:
        retry_at = float(resume.get("retry_monotonic") or 0)
    except (TypeError, ValueError):
        retry_at = 0
    if retry_at > time.monotonic():
        return {"ok": False, "action": "boot-resume-retry-pending",
                "retry_after_seconds": retry_at - time.monotonic(), "state": state}
    automatic = resume["active_kind"] == "node_wide_automatic"
    if (automatic
            and (pool.get_setting("dns_incident_id") != resume.get("incident_id")
                 or pool.get_setting("dns_recovery_exhausted") != "1")):
        pool.set_setting("dns_boot_resume", None)
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-incident-changed",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        return {"ok": False, "action": "boot-resume-cancelled", "state": state}
    current_manual_ref = pool.get_setting("manual_emergency_ref")
    owner_still_wants_rescue = (
        pool.get_setting("automat_state") == "EMERGENCY"
        and ((automatic and pool.get_setting("emergency_manual") != "1")
             or (not automatic and pool.get_setting("emergency_manual") == "1"
                 and current_manual_ref == resume.get("manual_emergency_ref"))))
    if not owner_still_wants_rescue:
        pool.set_setting("dns_boot_resume", None)
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-contract-changed",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        return {"ok": False, "action": "boot-resume-cancelled", "state": state}
    identity_state = dns_runtime.wireguard_scope_identity_state(cfg, "all")
    current_identity = identity_state.get("identity")
    if identity_state.get("status") == "unknown":
        return _schedule_continuation_retry(
            pool, "dns_boot_resume", resume, attempt_seq,
            "boot-resume-retry-pending", "boot-resume-exhausted",
            "boot-resume", [{"slot": None,
                              "action": "wireguard-identity-unavailable"}],
            clear_active=True)
    if (identity_state.get("status") != "valid"
            or current_identity != resume.get("scope_identity")):
        pool.set_setting("dns_boot_resume", None)
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-contract-changed",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        return {"ok": False, "action": "boot-resume-cancelled", "state": state}
    if not dns_runtime.service_inactive(time.monotonic() + 5.0):
        try:
            dns_runtime.service_stop(time.monotonic() + 10.0)
        except Exception as error:
            return _schedule_continuation_retry(
                pool, "dns_boot_resume", resume, attempt_seq,
                "boot-resume-retry-pending", "boot-resume-exhausted",
                "boot-resume", [{"slot": None,
                                  "action": "service-stop-unproven"}],
                clear_active=True)
    # Publish fail-open absence before the first reattachment attempt.  The
    # descriptor, not an impossible old-boot active state, owns later retries.
    if _active(state):
        state = pool.set_dns_state(
            phase="failed", active_scope=None, active_slot=None,
            active_kind=None, last_error="boot-resume-pending",
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
    slots = [item for item in _slots(cfg) if _is_future(item.get("not_after"))]
    slots.sort(key=lambda item: item.get("id") != resume.get("slot_id"))
    deadline = (time.monotonic()
                + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    errors = []
    for index, chosen in enumerate(slots):
        if time.monotonic() >= deadline:
            break
        try:
            result = _activate_locked(
                cfg, pool, "all", chosen.get("id"), "recovery", automatic, log,
                incident_id=resume["incident_id"],
                idempotency_key="dns-boot-resume:%s:%s:%s" % (
                    resume["resume_id"], attempt_seq, index),
                deadline_monotonic=deadline, continuation=True,
                profile_class="all-present", resume_boot_id=current_boot,
                expected_scope_identity=resume["scope_identity"],
                expected_manual_emergency_ref=resume.get("manual_emergency_ref"),
                clear_resume_setting="dns_boot_resume",
                clear_resume_id=resume["resume_id"])
        except Exception as error:
            result = {"ok": False, "action": "exception",
                      "error": type(error).__name__, "state": pool.dns_state()}
        if result.get("ok"):
            _audit_event(pool, actor="recovery", result="active",
                         detail="restored after boot slot=%s" % chosen.get("id"))
            result["action"] = "boot-restored"
            return result
        errors.append({"slot": chosen.get("id"),
                       "action": result.get("action") or "failed"})
        if result.get("action") in ("fail-open-blocked", "cleanup-pending"):
            return result
    return _schedule_continuation_retry(
        pool, "dns_boot_resume", resume, attempt_seq,
        "boot-resume-retry-pending", "boot-resume-exhausted",
        "boot-resume", errors, clear_active=True)


def _reconcile_locked(cfg, pool, actor):
    deadline = time.monotonic() + 15.0
    auxiliary_errors = []
    try:
        # A candidate preflight runs in a fixed transient systemd control group.
        # After coordinator death, prove that group inactive before removing
        # its exact-peer high-port guard or temporary config.
        dns_runtime.scrub_candidate_sidecar(cfg, deadline)
    except Exception as error:
        auxiliary_errors.append("sidecar-cleanup:" + type(error).__name__)
    try:
        # A killed return-to-primary check may leave its exact test-peer bypass.
        # Neutralize that chain before any physical/effective-state decision.
        dns_runtime.scrub_primary_test_bypass(cfg, deadline)
    except Exception as error:
        auxiliary_errors.append("primary-bypass-cleanup:" + type(error).__name__)
    state = pool.dns_state()
    try:
        _replay_pending_drains(cfg, pool, deadline)
    except Exception:
        return pool.set_dns_state(phase='recovering', last_error='drain-inspection-unknown')
    unfinished = pool.unfinished_dns_operations()
    # A coordinator killed after detach must restore its last serving generation
    # before generic cleanup can stop the listener without a primary proof.
    for operation in unfinished:
        try:
            snapshot = json.loads(operation.get('snapshot_json') or '{}')
        except (TypeError, ValueError):
            snapshot = {}
        if (str(operation.get('kind') or '').startswith('deactivate-')
                and snapshot.get('primary_proof_required')
                and operation.get('phase') in ('staging', 'started', 'rollback')
                and state.get('active_scope') and state.get('boot_id') == _boot_id()
                and not _isolated_ttl_expired(state)):
            if dns_runtime.service_state(deadline) == 'inactive':
                # A kill after service_stop but before its journal transition
                # leaves phase=started. Proven death permits fail-open cleanup.
                continue
            try:
                current = dict(state, phase=snapshot['active_phase'])
                return _restore_detached_generation(cfg, pool, current, operation, deadline)['state']
            except Exception:
                # UNKNOWN cannot authorize stopping a possibly serving listener.
                return pool.set_dns_state(phase='recovering', last_error='detach-restore-unknown')
    for operation in list(unfinished):
        if operation.get("kind") == "primary-recovery-check":
            _mark_operation_failed(
                pool, operation, operation.get("phase"), "crash-recovery")
    unfinished = pool.unfinished_dns_operations()
    attached = dns_runtime.firewall_attached(cfg, deadline)
    isolated_expired = _isolated_ttl_expired(state)
    # Resume only after every interrupted journal row is terminal and main NAT
    # is proven absent. This avoids recursive reconcile when a crash happened
    # between publishing idle state and committing the deactivation operation.
    if (not attached and not _active(state) and not unfinished and not auxiliary_errors
            and pool.get_setting("dns_exit_resume")):
        resumed = _resume_after_exit_failure_locked(cfg, pool, actor)
        return resumed.get("state") or pool.dns_state()
    current_boot = _boot_id()
    deactivation_in_progress = any(
        str(operation.get("kind") or "").startswith("deactivate-")
        for operation in unfinished)
    if (state.get("phase") in ACTIVE_PHASES and _active(state)
            and not current_boot and not attached
            and state.get("active_kind") in (
                "node_wide_manual", "node_wide_automatic")
            and not deactivation_in_progress
            and not pool.get_setting("dns_exit_resume")
            and not pool.get_setting("dns_boot_resume")
            and _state_shape_valid(cfg, state)):
        # A transient boot-id read failure must not erase exact node-wide
        # ownership if the rebooted runtime is already absent. Persist the
        # compensation intent first; a later inspection will decide whether
        # this was same-boot drift or a real cross-boot restore.
        descriptor = _new_boot_resume_descriptor(pool, state)
        if descriptor is not None:
            pool.set_setting("dns_boot_resume",
                             json.dumps(descriptor, ensure_ascii=True,
                                        sort_keys=True))
            if not attached and not unfinished and not auxiliary_errors:
                return _resume_after_boot_locked(
                    cfg, pool).get("state") or pool.dns_state()
    if (state.get("phase") in ACTIVE_PHASES
            and _active(state) and current_boot and state.get("boot_id")
            and state.get("boot_id") != current_boot
            and not deactivation_in_progress
            and not pool.get_setting("dns_exit_resume")
            and not pool.get_setting("dns_boot_resume")):
        descriptor = _new_boot_resume_descriptor(pool, state)
        if descriptor is not None and _state_shape_valid(cfg, state):
            pool.set_setting("dns_boot_resume",
                             json.dumps(descriptor, ensure_ascii=True,
                                        sort_keys=True))
            if not attached and not unfinished and not auxiliary_errors:
                return _resume_after_boot_locked(
                    cfg, pool).get("state") or pool.dns_state()
    if (not attached and not unfinished and not _active(state)
            and not auxiliary_errors
            and pool.get_setting("dns_boot_resume")):
        return _resume_after_boot_locked(cfg, pool).get("state") or pool.dns_state()
    physically_consistent = False
    service_state = None
    base_consistent = False
    ownership_inspection_unknown = False
    identity_state = {"status": "unknown", "identity": None}
    route_state = "unknown"
    firewall_ok = False
    boot_matches = False
    node_wide = False
    if (attached and not isolated_expired
            and state.get("phase") in ACTIVE_PHASES and _active(state)
            and _state_shape_valid(cfg, state)):
        try:
            # Reconcile repairs ownership/crash drift only. Backend health and
            # its failure threshold belong to automatic_tick; probing here made
            # a single transient failure tear down rescue before failover.
            service_state = dns_runtime.service_state(deadline)
            identity_state = dns_runtime.wireguard_scope_identity_state(
                cfg, state.get("active_scope"), deadline)
            node_wide = state.get("active_kind") in (
                "node_wide_manual", "node_wide_automatic")
            route_state = (dns_runtime.emergency_route_state(cfg, deadline)
                           if node_wide else "ready")
            firewall_ok = dns_runtime.firewall_effective(
                cfg, scope=state.get("active_scope"))
            boot_matches = bool(current_boot) and state.get("boot_id") == current_boot
            base_consistent = (
                firewall_ok and boot_matches
                and identity_state.get("status") == "valid"
                and identity_state.get("identity") == state.get("scope_identity")
                and route_state == "ready")
            ownership_inspection_unknown = (
                firewall_ok
                and (boot_matches or current_boot is None)
                and identity_state.get("status") != "invalid"
                and route_state != "mismatch"
                and (current_boot is None
                     or identity_state.get("status") == "unknown"
                     or route_state == "unknown"))
            physically_consistent = base_consistent and service_state == "active"
        except Exception:
            physically_consistent = False
    if physically_consistent and not unfinished and not auxiliary_errors:
        _clear_physical_resume(pool, "dns_exit_resume", state)
        _clear_physical_resume(pool, "dns_boot_resume", state)
        return state
    if (not isolated_expired and service_state == "unknown" and base_consistent
            and not unfinished and not auxiliary_errors
            and state.get("phase") in ACTIVE_PHASES
            and _state_shape_valid(cfg, state)):
        # An inspection timeout is not proof that a live resolver disappeared.
        # Preserve the guarded path and let repeated health ticks cross their
        # normal failure threshold before failover.
        return pool.set_dns_state(last_error="service-inspection-unknown")
    if (not isolated_expired
            and ownership_inspection_unknown and service_state != "inactive"
            and not unfinished and not auxiliary_errors
            and state.get("phase") in ACTIVE_PHASES
            and _state_shape_valid(cfg, state)):
        # The health tick applies the durable failure threshold. Reconcile must
        # not tear down a guarded live path on one ip/wg inspection timeout.
        return pool.set_dns_state(last_error="ownership-inspection-unknown")
    # A positively owned generation with either a dead listener or exact route
    # drift needs fail-open teardown, but it must not lose the incident/scope/
    # TTL identity needed for bounded repair. Publish the continuation before
    # touching NAT so a kill at any later point is recoverable by reconcile.
    resume_published = False
    repairable_failure = (
        attached and not isolated_expired and not unfinished and not auxiliary_errors
        and state.get("phase") in ACTIVE_PHASES and _active(state)
        and _state_shape_valid(cfg, state)
        and bool((cfg.get("dns_rescue") or {}).get("active_probes"))
        # A transient boot-id read failure is not evidence that this exact
        # owned generation belongs to another boot.  Publish the descriptor,
        # detach the dead path, and let the continuation wait until boot
        # identity is readable; cross-boot isolated resumes are still rejected
        # and node-wide resumes are converted to the stricter boot contract.
        and firewall_ok and (boot_matches or current_boot is None)
        and identity_state.get("status") == "valid"
        and identity_state.get("identity") == state.get("scope_identity")
        and ((service_state == "inactive"
              and route_state in ("ready", "unknown", "mismatch"))
             or (node_wide and route_state == "mismatch"
                 and service_state in ("active", "inactive", "unknown"))))
    if (repairable_failure and not pool.get_setting("dns_exit_resume")
            and not pool.get_setting("dns_boot_resume")):
        descriptor = _new_exit_resume_descriptor(pool, state)
        if descriptor is not None:
            pool.set_setting("dns_exit_resume", json.dumps(
                descriptor, ensure_ascii=True, sort_keys=True))
            resume_published = True
    if not attached:
        try:
            if unfinished or _active(state):
                guard = _recovery_guard_scope(cfg, state, unfinished) or 'all'
                _detach_redirect_locked(cfg, pool, guard, deadline)
            if not dns_runtime.service_inactive(deadline):
                dns_runtime.service_stop(deadline)
        except Exception as error:
            for op in unfinished:
                _mark_operation_failed(pool, op, op.get("phase"), "crash-recovery")
            return pool.set_dns_state(
                phase="recovering", active_scope=None, active_slot=None,
                activated_at=None, active_kind=None, expires_at=None,
                active_failures=0, active_last_check=None,
                last_error="cleanup:" + type(error).__name__,
                backend_last_ok=None, client_path_last_ok=None,
                scope_identity=None, boot_id=None, expires_monotonic=None)
        for op in unfinished:
            _mark_operation_failed(pool, op, op.get("phase"), "crash-recovery")
        safe_state = pool.set_dns_state(
            phase=("recovering" if auxiliary_errors else
                   ("idle" if state.get("active_kind") == "isolated_manual" else
                    ("failed" if _active(state) else "idle"))),
            active_scope=None, active_slot=None, activated_at=None, active_kind=None,
            expires_at=None, active_failures=0, active_last_check=None,
            last_error=(";".join(auxiliary_errors) if auxiliary_errors else
                        ("effective-state-mismatch" if _active(state) else
                         state.get("last_error"))),
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)
        if not auxiliary_errors and pool.get_setting("dns_exit_resume"):
            resumed = _resume_after_exit_failure_locked(cfg, pool, actor)
            return resumed.get("state") or pool.dns_state()
        return safe_state
    detach_error = None
    detached = False
    guard_scope = _recovery_guard_scope(cfg, state, unfinished)
    runtime_scope = guard_scope or "all"
    try:
        detached = bool(_detach_redirect_locked(
            cfg, pool, scope=runtime_scope,
            deadline_monotonic=deadline))
    except Exception as error:
        detach_error = error
    if not detached:
        # Missing NAT is insufficient: conntrack drain must also be proven.
        try:
            if guard_scope and not dns_runtime.listener_guard_effective(
                    cfg, guard_scope, deadline):
                dns_runtime.stage_listener_acl(cfg, guard_scope, deadline)
            if guard_scope and dns_runtime.listener_guard_effective(
                    cfg, guard_scope, deadline):
                service_state = dns_runtime.service_state(deadline)
                if service_state == "inactive":
                    dns_runtime.service_start(cfg, deadline)
        except Exception:
            pass
        reason = type(detach_error).__name__ if detach_error else "DNSRescueError"
        return pool.set_dns_state(
            phase="recovering", last_error="cleanup:" + reason)
    try:
        dns_runtime.service_stop(deadline)
        dns_runtime.remove_listener_acl(
            cfg, runtime_scope, deadline)
        for op in unfinished:
            _mark_operation_failed(pool, op, op.get("phase"), "crash-recovery")
        safe_state = pool.set_dns_state(
            phase="idle" if state.get("active_kind") == "isolated_manual" else "failed",
            active_scope=None, active_slot=None, activated_at=None, active_kind=None,
            expires_at=None, active_failures=0, active_last_check=None,
            last_error="recovered-after-crash", backend_last_ok=None,
            client_path_last_ok=None, scope_identity=None, boot_id=None,
            expires_monotonic=None)
        if resume_published:
            resumed = _resume_after_exit_failure_locked(cfg, pool, actor)
            return resumed.get("state") or pool.dns_state()
        return safe_state
    except Exception as error:
        # Redirect is already proven absent. Never recreate the listener merely
        # because service/ACL cleanup is incomplete.
        return pool.set_dns_state(
            phase="recovering", active_scope=None, active_slot=None,
            activated_at=None, active_kind=None, expires_at=None,
            active_failures=0, active_last_check=None,
            last_error="cleanup:" + type(error).__name__,
            backend_last_ok=None, client_path_last_ok=None,
            scope_identity=None, boot_id=None, expires_monotonic=None)


def reconcile(cfg, pool, actor="recovery", _locked=False):
    if os.name != "posix":
        return pool.set_dns_state(phase="failed", active_scope=None, active_slot=None,
                                  active_kind=None, last_error="recovery-requires-linux")
    if _locked:
        return _reconcile_locked(cfg, pool, actor)
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _reconcile_locked(cfg, pool, actor)
    except apply_mod.ApplyError:
        return pool.dns_state()


def _primary_dns_failure(cfg, pool, incident_id):
    target = str(cfg.get("dns") or "1.1.1.1")
    block = cfg.get("dns_rescue") or {}
    timeout = block.get("request_timeout_seconds", 3)
    suffix = str(block.get("canary_qname_suffix") or "")
    expected_ipv4 = str(block.get("canary_expected_ipv4") or "")
    if not suffix or not expected_ipv4:
        return False, []
    results = []
    for transport in ("udp", "tcp"):
        qname = "%s.%s" % (uuid.uuid4().hex, suffix)
        result = dns_probe.probe(target, 53, transport, timeout,
                                 name=qname, expected_ipv4=expected_ipv4)
        pool.record_dns_probe(result, incident_id=incident_id, slot_id="primary")
        results.append(result)
    return all(not item.get("ok") for item in results), results


def _client_primary_recovery_locked(cfg, pool, state):
    """Journal the temporary exact-peer original-path proof."""
    canary = str((cfg.get("dns_rescue") or {}).get("canary_peer_ipv4") or "")
    scope = "peer:" + canary
    operation = pool.begin_dns_operation(
        state.get("incident_id"), "primary-recovery-check", "primary", scope,
        "auto", "dns-primary-recovery:" + uuid.uuid4().hex,
        profile_class="all-present", generation=state.get("generation"),
        snapshot={"active_slot": state.get("active_slot"),
                  "scope_identity": state.get("scope_identity")})
    op_phase = operation["phase"]
    try:
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        evidence = {}
        profiles = _required_profiles(cfg)
        proven = dns_runtime.client_primary_recovery_proven(
            cfg, profiles,
            (cfg.get("dns_rescue") or {}).get("request_timeout_seconds", 3),
            evidence_out=evidence)
        if not proven:
            _mark_operation_failed(pool, operation, op_phase, 'PrimaryUnproven')
            return evidence or dns_evidence.outcome()
        for phase in ("started", "redirected", "verifying", "committed"):
            pool.transition_dns_operation(operation["id"], phase)
            op_phase = phase
        return dns_evidence.outcome('PASS', 'ok')
    except Exception as error:
        _mark_operation_failed(pool, operation, op_phase, type(error).__name__)
        return dns_evidence.outcome()


def _activate_series_locked(cfg, pool, incident_id, actor="auto", log=print,
                            proof_context=None, slot_id=None):
    errors = []
    deadline = (time.monotonic()
                + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    for chosen in _slots(cfg):
        if slot_id is not None and chosen['id'] != slot_id:
            continue
        if not _is_future(chosen.get("not_after")):
            errors.append({"slot": chosen.get("id"), "action": "expired"})
            continue
        if time.monotonic() >= deadline:
            errors.append({"slot": chosen.get("id"), "action": "deadline-exhausted"})
            break
        result = _activate_locked(cfg, pool, "all", chosen.get("id"), actor, True,
                                  log, incident_id=incident_id,
                                  deadline_monotonic=deadline,
                                  proof_context=proof_context)
        if result.get("ok"):
            return result
        errors.append({"slot": chosen.get("id"), "action": result.get("action")})
        if result.get("action") == "fail-open-blocked":
            return result
    state = pool.set_dns_state(phase="failed", active_scope=None, active_slot=None,
                               active_kind=None, last_error="candidate-series-exhausted",
                               attempt_used=True, backend_last_ok=None,
                               client_path_last_ok=None, scope_identity=None,
                               boot_id=None, expires_monotonic=None)
    return {"ok": False, "action": "candidates-exhausted", "state": state,
            "attempts": errors}


def _switch_active_candidate_locked(cfg, pool, state, chosen, profile_class,
                                    deadline, log):
    """Pre-prove and atomically replace only the live resolver process.

    The current NAT/ACL remains attached throughout.  A separate, exact-peer
    high-port sidecar proves the successor before the live config is touched.
    """
    deadline = _cap_candidate_deadline(chosen.get("not_after"), deadline)
    incident = state.get("incident_id")
    scope = state.get("active_scope") or "all"
    active_kind = state.get("active_kind")
    automatic = active_kind == "node_wide_automatic"
    inventory = _proof_context(cfg, deadline) if scope == 'all' else None
    if scope == 'all' and not inventory:
        return _hold_active_inspection_unknown(cfg, pool, state, 'profile-inventory')
    if automatic:
        if not _is_future((cfg.get('dns_rescue') or {}).get('readiness_not_after')):
            return _hold_active_inspection_unknown(cfg, pool, state, 'readiness')
        deadline = _cap_candidate_deadline(cfg['dns_rescue']['readiness_not_after'], deadline)
    _validate_scope_locked(cfg, pool, scope, automatic, continuation=True,
                           profile_class=profile_class,
                           deadline_monotonic=deadline)
    current_identity = dns_runtime.wireguard_scope_identity(cfg, scope, deadline)
    if (not current_identity or current_identity != state.get("scope_identity")
            or state.get("boot_id") != _boot_id()):
        raise DNSRescueError("active rescue identity changed before failover")
    manual_ref = (pool.get_setting("manual_emergency_ref")
                  if active_kind == "node_wide_manual" else None)
    if manual_ref != state.get("manual_emergency_ref"):
        raise DNSRescueError("manual emergency reference changed before failover")
    operation_profile = (profile_class if active_kind == "isolated_manual"
                         else "all-present")
    generation = uuid.uuid4().hex
    operation = pool.begin_dns_operation(
        incident, "activate-" + active_kind, chosen["id"], scope, "auto",
        "dns-failover:%s:%s:%s" % (incident, chosen["id"], uuid.uuid4().hex),
        profile_class=operation_profile, expires_at=state.get("expires_at"),
        generation=generation,
        snapshot={"previous_slot": state.get("active_slot"),
                  "previous_generation": state.get("generation"),
                  "scope_identity": current_identity,
                   "manual_emergency_ref": manual_ref})
    op_phase = operation["phase"]
    live_config_changed = False
    required_profiles = ((operation_profile,) if active_kind == "isolated_manual"
                         else tuple(inventory['profiles']))
    try:
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        with open(cfg["singbox_config"], encoding="utf-8") as handle:
            main_config = json.load(handle)
        preflight_scope = (scope if active_kind == "isolated_manual" else
                           "peer:" + str(cfg["dns_rescue"]["canary_peer_ipv4"]))
        remaining = max(0.0, deadline - time.monotonic())
        evidence = {}
        if (remaining <= 0 or not dns_runtime.candidate_sidecar_preflight_proven(
                cfg, chosen, main_config, preflight_scope, required_profiles,
                min(cfg["dns_rescue"]["active_check_seconds"], remaining),
                deadline_monotonic=deadline, evidence_out=evidence)):
            if evidence.get('status', 'UNKNOWN') == 'UNKNOWN':
                _mark_operation_failed(pool, operation, op_phase, 'CandidateProofUnknown')
                return _hold_active_inspection_unknown(cfg, pool, state, 'candidate-path')
            raise DNSRescueError("successor sidecar preflight failed")
        _require_candidate_fresh(chosen, "before successor live cutover")
        if scope == 'all' and _proof_context(cfg, deadline) != inventory:
            raise DNSRescueError('profile inventory changed before failover')
        # Only the resolver process is switched. The already proven scoped NAT
        # and listener guard remain in place and are revalidated before commit.
        dns_runtime.stage_config(cfg, chosen, main_config,
                                 deadline_monotonic=deadline)
        live_config_changed = True
        _require_candidate_fresh(chosen, "before successor service start")
        dns_runtime.service_start(cfg, deadline)
        pool.transition_dns_operation(operation["id"], "started")
        op_phase = "started"
        _require_candidate_fresh(chosen, "before successor backend proof")
        initial = probe_backend(cfg, pool, incident, chosen["id"], deadline)
        if not initial.get("ok"):
            raise DNSRescueError("successor failed after live restart")
        pool.transition_dns_operation(operation["id"], "redirected")
        op_phase = "redirected"
        pool.transition_dns_operation(operation["id"], "verifying")
        op_phase = "verifying"
        if not dns_runtime.firewall_effective(cfg, scope=scope,
                                              deadline_monotonic=deadline):
            raise DNSRescueError("existing redirect changed during failover")
        remaining = max(0.0, deadline - time.monotonic())
        _require_candidate_fresh(chosen, "before successor client-path proof")
        if (remaining <= 0 or not dns_runtime.client_roundtrip_proven(
                cfg, scope, required_profiles,
                min(cfg["dns_rescue"]["active_check_seconds"], remaining),
                deadline_monotonic=deadline)):
            raise DNSRescueError("successor client path failed after restart")
        _require_candidate_fresh(chosen, "before successor final backend proof")
        final = probe_backend(cfg, pool, incident, chosen["id"], deadline)
        if not final.get("ok"):
            raise DNSRescueError("successor final backend proof failed")
        _require_candidate_fresh(chosen, "before successor commit")
        if dns_runtime.wireguard_scope_identity(
                cfg, scope, deadline) != current_identity:
            raise DNSRescueError("WireGuard scope changed before failover commit")
        phase = ("active_isolated" if active_kind == "isolated_manual" else
                 ("active_proxy" if chosen["transport"] == "proxy"
                  else "active_direct"))
        committed = pool.commit_dns_activation(
            operation["id"], phase=phase,
            configured_mode=cfg["dns_rescue"]["mode"], incident_id=incident,
            active_scope=scope, active_slot=chosen["id"], activated_at=_now(),
            attempt_used=True, return_successes=0, last_error=None,
            active_kind=active_kind, expires_at=state.get("expires_at"),
            active_failures=0, active_last_check=_now(),
            return_last_check=state.get("return_last_check"),
            generation=generation, backend_last_ok=_now(),
            client_path_last_ok=_now(), scope_identity=current_identity,
            boot_id=state.get("boot_id"),
            expires_monotonic=state.get("expires_monotonic"),
            manual_emergency_ref=manual_ref)
        _save_stability(pool, _stability(pool, committed))
        _audit_event(pool, actor="auto", result="active",
                     detail="failover slot=%s transport=%s scope=%s" % (
                         chosen["id"], chosen["transport"], _scope_label(scope)))
        return {"ok": True, "action": "backend-failover", "state": committed}
    except Exception as error:
        restored = False
        previous = next((item for item in _slots(cfg)
                         if item.get("id") == state.get("active_slot")), None)
        if (not live_config_changed and previous is not None
                and _is_future(previous.get("not_after"))):
            # Sidecar rejection says nothing about the old runtime.  Preserve
            # it only after a new, end-to-end proof; firewall presence alone
            # must never turn a dead listener into "current preserved".
            try:
                backend = probe_backend(
                    cfg, pool, incident, state.get("active_slot"),
                    time.monotonic() + 10.0)
                restored = (
                    dns_runtime.service_state(time.monotonic() + 5.0) == "active"
                    and backend.get("ok")
                    and dns_runtime.firewall_effective(
                        cfg, scope=scope,
                        deadline_monotonic=time.monotonic() + 5.0)
                    and dns_runtime.client_roundtrip_proven(
                        cfg, scope, required_profiles,
                        cfg["dns_rescue"]["active_check_seconds"],
                        deadline_monotonic=time.monotonic() + 10.0))
            except Exception:
                restored = False
        elif (not live_config_changed and previous is not None
              and not _is_future(previous.get("not_after"))):
            # Sidecar rejection did not touch the established runtime.  An
            # expired authorization forbids re-dialing it, but a recent cached
            # end-to-end proof plus current kernel/service proof is enough to
            # preserve it while other fresh successors are considered.
            try:
                restored = (
                    _runtime_proof_recent(cfg, state)
                    and dns_runtime.service_state(
                        time.monotonic() + 5.0) == "active"
                    and dns_runtime.firewall_effective(
                        cfg, scope=scope,
                        deadline_monotonic=time.monotonic() + 5.0))
            except Exception:
                restored = False
        else:
            # Re-dialing an evidence-expired previous slot is forbidden.  For a
            # still-fresh slot, restore its config and prove both backend and
            # client path before claiming that the current rescue survived.
            if previous is not None and _is_future(previous.get("not_after")):
                try:
                    with open(cfg["singbox_config"], encoding="utf-8") as handle:
                        main_config = json.load(handle)
                    dns_runtime.stage_config(cfg, previous, main_config,
                                             deadline_monotonic=time.monotonic() + 10.0)
                    dns_runtime.service_start(cfg, time.monotonic() + 10.0)
                    backend = probe_backend(
                        cfg, pool, incident, previous["id"], time.monotonic() + 10.0)
                    restored = (backend.get("ok")
                                and dns_runtime.firewall_effective(
                                    cfg, scope=scope,
                                    deadline_monotonic=time.monotonic() + 5.0)
                                and dns_runtime.client_roundtrip_proven(
                                    cfg, scope, required_profiles,
                                    cfg["dns_rescue"]["active_check_seconds"],
                                    deadline_monotonic=time.monotonic() + 10.0))
                except Exception:
                    restored = False
        _mark_operation_failed(pool, operation, op_phase, type(error).__name__)
        if restored and dns_runtime.firewall_effective(
                cfg, scope=scope, deadline_monotonic=time.monotonic() + 5.0):
            current = pool.set_dns_state(last_error="failover:" + type(error).__name__)
            return {"ok": False, "action": "successor-rejected-current-preserved",
                    "state": current}
        return {"ok": False, "action": "current-runtime-unproven",
                "error": str(error), "state": pool.dns_state()}


def _failover_locked(cfg, pool, state, manual_emergency, log,
                     current_runtime_proven=True):
    incident = state.get("incident_id")
    current_slot = state.get("active_slot")
    active_kind = state.get("active_kind")
    scope = state.get("active_scope") or "all"
    profile_class = _active_profile_class(pool, state)
    tried = _tried_slots(pool, incident)
    deadline = (time.monotonic()
                + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    candidates = _failover_slots(
        cfg, current_slot, tried, require_fresh=True)
    stability = _stability(pool, state)
    candidate_age = _age(stability.get('candidate_last_check'))
    if (current_runtime_proven and 'candidate-path' in stability.get('unknown_causes', {})
            and candidate_age is not None and 0 <= candidate_age < 60):
        return _hold_active_inspection_unknown(cfg, pool, state, 'candidate-path')
    if (current_runtime_proven and not candidates and any(
            item.get('id') != current_slot and not _is_future(item.get('not_after'))
            for item in _slots(cfg))):
        return _hold_active_inspection_unknown(cfg, pool, state, 'candidate-evidence')
    stability['candidate_last_check'] = _now()
    _save_stability(pool, stability)
    detached_current = False

    def activate_replacements(replacements):
        for replacement in replacements:
            if time.monotonic() >= deadline:
                break
            try:
                activated = _activate_locked(
                    cfg, pool, scope, replacement.get("id"), "auto",
                    active_kind == "node_wide_automatic", log,
                    incident_id=incident, deadline_monotonic=deadline,
                    continuation=True, profile_class=profile_class,
                    resume_expires_at=(state.get("expires_at")
                                       if active_kind == "isolated_manual" else None),
                    resume_expires_monotonic=(state.get("expires_monotonic")
                                              if active_kind == "isolated_manual" else None),
                    resume_boot_id=(state.get("boot_id")
                                    if active_kind == "isolated_manual" else None),
                    # Reattach only to the exact WG cohort that owned the
                    # interrupted active path, including node-wide recovery.
                    expected_scope_identity=state.get("scope_identity"),
                    expected_manual_emergency_ref=state.get("manual_emergency_ref"))
            except Exception as error:
                activated = {"ok": False, "action": "continuation-rejected",
                             "error": type(error).__name__,
                             "state": pool.dns_state()}
            if activated.get("ok"):
                activated["action"] = "backend-failover"
                return activated
            if activated.get("action") in ("fail-open-blocked", "cleanup-pending"):
                return activated
        return None

    if not current_runtime_proven:
        # Positive proof that the listener is inactive turns an attached NAT
        # redirect into a black hole.  Detach it before any successor sidecar
        # probe, then use the ordinary guarded activation saga.
        stopped = _deactivate_locked(cfg, pool, "auto", "inactive-listener")
        if not stopped.get("ok"):
            return stopped
        detached_current = True
        activated = activate_replacements(candidates)
        if activated is not None:
            return activated
        candidates = []

    for index, chosen in enumerate(candidates):
        if time.monotonic() >= deadline:
            break
        try:
            result = _switch_active_candidate_locked(
                cfg, pool, state, chosen, profile_class, deadline, log)
        except Exception as error:
            result = {"ok": False, "action": "current-runtime-unproven",
                      "error": type(error).__name__, "state": pool.dns_state()}
        if result.get("ok"):
            return result
        if str(result.get('action') or '').endswith('-inspection-unknown'):
            return result
        if result.get("action") == "successor-rejected-current-preserved":
            # Fresh end-to-end success disproves the original current failure.
            current = pool.set_dns_state(active_failures=0, active_last_check=_now(),
                                         backend_last_ok=_now(), client_path_last_ok=_now())
            stability = _resolve_unknowns(pool, current, 'candidate-path', 'client-path', 'backend')
            stability['client_failures'] = 0
            _save_stability(pool, stability)
            result['state'] = current
            return result
        stopped = _deactivate_locked(cfg, pool, "auto", "backend-failover")
        if not stopped.get("ok"):
            return stopped
        detached_current = True
        # The current listener is gone and the just-tried successor failed.
        # Remaining candidates use the ordinary guarded activation saga.
        activated = activate_replacements(candidates[index + 1:])
        if activated is not None:
            return activated
        break
    current = pool.dns_state()
    current_slot_cfg = next((item for item in _slots(cfg)
                             if item.get("id") == current_slot), None)
    if (_active(current) and current.get("active_slot") == current_slot
            and current_slot_cfg is not None
            and not _is_future(current_slot_cfg.get("not_after"))
            and _runtime_proof_recent(cfg, current)
            and dns_runtime.firewall_effective(
                cfg, scope=scope, deadline_monotonic=time.monotonic() + 5.0)
            and dns_runtime.service_active(time.monotonic() + 5.0)):
        current = pool.set_dns_state(last_error="candidate-evidence-expired")
        return {"ok": False, "action": "active-evidence-expired", "state": current}
    if (not detached_current
            and (_active(pool.dns_state()) or dns_runtime.firewall_attached(cfg))):
        stopped = _deactivate_locked(cfg, pool, "auto", "all-candidates-unhealthy")
        if not stopped.get("ok"):
            return stopped
    final = pool.set_dns_state(
        phase="idle" if active_kind == "isolated_manual" else "failed",
        active_scope=None, active_slot=None, active_kind=None,
        last_error="all-candidates-unhealthy", attempt_used=True,
        backend_last_ok=None, client_path_last_ok=None, scope_identity=None,
        boot_id=None, expires_monotonic=None)
    return {"ok": False, "action": "all-candidates-unhealthy", "state": final}


def _hold_active_inspection_unknown(cfg, pool, state, label):
    """UNKNOWN preserves serving DNS and never consumes the failure counter."""
    stability = _stability(pool, state)
    causes = stability.setdefault('unknown_causes', {})
    cause = causes.setdefault(label, {'since': _now(), 'alerted': False})
    age = _age(cause['since'])
    if age is not None and age >= 900 and not cause.get('alerted'):
        _audit_event(pool, actor='auto', result='critical',
                     detail='DNS Rescue inspection UNKNOWN for 15 minutes')
        cause['alerted'] = True
    stability['unknown_since'] = min(x['since'] for x in causes.values())
    stability['unknown_alerted'] = any(x.get('alerted') for x in causes.values())
    _save_stability(pool, stability)
    current = pool.set_dns_state(active_last_check=_now(),
                                 last_error=str(label) + '-inspection-unknown')
    return {'ok': False, 'action': str(label) + '-inspection-unknown', 'state': current}


def _align_new_automatic_incident(cfg, pool, state, automat_state,
                                  manual_emergency):
    """Recover the handoff from an old isolated incident to a new auto one."""
    block = cfg.get("dns_rescue") or {}
    incident = pool.get_setting("dns_incident_id")
    eligible_context = (
        not _active(state) and state.get("phase") in ("idle", "failed")
        and automat_state == "EMERGENCY" and not manual_emergency
        and pool.get_setting("automat_frozen") != "1"
        and block.get("mode") == "automatic_last_resort"
        and block.get("owner_approved") and block.get("active_probes")
        and block.get("automatic_ready")
        and pool.get_setting("dns_recovery_exhausted") == "1"
        and incident)
    if eligible_context and state.get("incident_id") != incident:
        return pool.set_dns_state(
            configured_mode=block.get("mode"), incident_id=incident,
            attempt_used=False, last_error=None, return_successes=0,
            active_failures=0, active_last_check=None, return_last_check=None,
            generation=None)
    return state


def _automatic_tick_locked(cfg, pool, automat_state, manual_emergency, log):
    state = pool.dns_state()
    block = cfg.get("dns_rescue") or {}
    if (state.get("phase") in ("probing", "recovering")
            or pool.unfinished_dns_operations()):
        return {"ok": False, "action": "cleanup-pending", "state": state}
    if not _active(state) and pool.get_setting("dns_exit_resume"):
        resumed = _resume_after_exit_failure_locked(cfg, pool, "recovery", log)
        if resumed.get("action") != "exit-transition-pending":
            return resumed
    if _active(state):
        if (state.get("active_kind") == "isolated_manual"
                and automat_state != "OK"):
            result = _deactivate_locked(
                cfg, pool, "auto", "isolated-left-normal-state")
            if result.get("ok"):
                result["state"] = _align_new_automatic_incident(
                    cfg, pool, result.get("state") or pool.dns_state(),
                    automat_state, manual_emergency)
            return result
        if state.get("active_kind") == "isolated_manual":
            # TTL is a hard janitor boundary.  It is independent of boot/WG
            # inspection availability and therefore runs before any bounded
            # unknown-state hold.
            if _isolated_ttl_expired(state):
                return _deactivate_locked(cfg, pool, "auto", "isolated-ttl")
        if (state.get("active_kind") == "node_wide_automatic"
                and manual_emergency):
            # Sticky owner intent takes control of an already active automatic
            # rescue. From this point no return probe may remove it; only an
            # explicit manual exit can coordinate DNS and route teardown.
            manual_ref = pool.get_setting("manual_emergency_ref")
            if not manual_ref:
                return _deactivate_locked(
                    cfg, pool, "auto", "manual-emergency-reference-missing")
            state = pool.set_dns_state(active_kind="node_wide_manual",
                                       manual_emergency_ref=manual_ref)
            _audit_event(pool, actor="user", result="manual-takeover",
                         detail="node-wide rescue закреплён ручным EMERGENCY")
        if (state.get("active_kind") == "node_wide_manual"
                and (pool.get_setting("emergency_manual") != "1"
                     or not state.get("manual_emergency_ref")
                     or state.get("manual_emergency_ref")
                     != pool.get_setting("manual_emergency_ref"))):
            return _deactivate_locked(
                cfg, pool, "auto", "manual-emergency-reference-changed")
        current_boot = _boot_id()
        if current_boot is None:
            return _hold_active_inspection_unknown(
                cfg, pool, state, "boot-identity")
        if not state.get("boot_id") or state.get("boot_id") != current_boot:
            if (state.get("active_kind") in (
                    "node_wide_manual", "node_wide_automatic")
                    and not pool.get_setting("dns_boot_resume")
                    and _state_shape_valid(cfg, state)):
                descriptor = _new_boot_resume_descriptor(pool, state)
                if descriptor is not None:
                    pool.set_setting("dns_boot_resume", json.dumps(
                        descriptor, ensure_ascii=True, sort_keys=True))
            stopped = _deactivate_locked(
                cfg, pool, "auto", "boot-identity-changed")
            if stopped.get("ok") and pool.get_setting("dns_boot_resume"):
                return _resume_after_boot_locked(cfg, pool, log)
            return stopped
        if state.get("active_kind") in (
                "node_wide_manual", "node_wide_automatic"):
            route_state = dns_runtime.emergency_route_state(cfg)
            if route_state == "mismatch":
                route_state = _ensure_resume_emergency_route(cfg, log)
                if route_state == "unknown":
                    return _hold_active_inspection_unknown(
                        cfg, pool, state, "emergency-route")
                if route_state != "ready":
                    if (not pool.get_setting("dns_exit_resume")
                            and _state_shape_valid(cfg, state)):
                        descriptor = _new_exit_resume_descriptor(pool, state)
                        if descriptor is not None:
                            pool.set_setting("dns_exit_resume", json.dumps(
                                descriptor, ensure_ascii=True, sort_keys=True))
                    stopped = _deactivate_locked(
                        cfg, pool, "auto", "emergency-route-drift")
                    if stopped.get("ok") and pool.get_setting("dns_exit_resume"):
                        stopped["resume_pending"] = True
                    return stopped
            if route_state == "unknown":
                return _hold_active_inspection_unknown(
                    cfg, pool, state, "emergency-route")
        identity_state = dns_runtime.wireguard_scope_identity_state(
            cfg, state.get("active_scope"))
        current_identity = identity_state.get("identity")
        if identity_state.get("status") == "unknown":
            return _hold_active_inspection_unknown(
                cfg, pool, state, "wireguard-scope")
        if (identity_state.get("status") != "valid"
                or not state.get("scope_identity")
                or current_identity != state.get("scope_identity")):
            return _deactivate_locked(cfg, pool, "auto", "wireguard-scope-drift")
        if not block.get("active_probes"):
            # Disabling probes is not cleanup authority.  Keep a proven live
            # generation serving, but still detach a listener which systemd
            # proves dead; explicit/manual deactivation remains available.
            runtime_state = dns_runtime.service_state()
            if runtime_state == "inactive":
                return _deactivate_locked(
                    cfg, pool, "auto", "active-probes-disabled-backend-inactive")
            if runtime_state == "unknown":
                return _hold_active_inspection_unknown(
                    cfg, pool, state, "service")
            return {"ok": True, "action": "active-probes-disabled", "state": state}
        active_slot = next((item for item in _slots(cfg)
                            if item.get("id") == state.get("active_slot")), None)
        if active_slot is None or not _is_future(active_slot.get('not_after')):
            runtime_state = dns_runtime.service_state()
            if runtime_state == 'inactive':
                return _failover_locked(cfg, pool, state, manual_emergency, log,
                                         current_runtime_proven=False)
            return _hold_active_inspection_unknown(cfg, pool, state, 'candidate-evidence')
        _resolve_unknowns(pool, state, 'boot-identity', 'wireguard-scope',
                          'emergency-route', 'candidate-evidence')
        age = _age(state.get("active_last_check"))
        if (age is not None and 0 <= age
                < int(block.get("active_check_seconds", 5))):
            return {"ok": True, "action": "active", "state": state}
        runtime_state = dns_runtime.service_state()
        if runtime_state == 'unknown':
            return _hold_active_inspection_unknown(cfg, pool, state, 'service')
        if runtime_state == 'inactive':
            return _failover_locked(cfg, pool, state, manual_emergency, log,
                                     current_runtime_proven=False)
        health = probe_backend(cfg, pool, state.get('incident_id'), state.get('active_slot'))
        if health.get('status') == 'UNKNOWN':
            return _hold_active_inspection_unknown(cfg, pool, state, 'backend')
        failures = 0 if health.get('ok') else int(state.get('active_failures') or 0) + 1
        state = pool.set_dns_state(active_failures=failures, active_last_check=_now())
        if failures >= max(3, int(block.get('active_failures', 3))):
            return _failover_locked(cfg, pool, state, manual_emergency, log,
                                     current_runtime_proven=True)
        if not health.get('ok'):
            return {'ok': False, 'action': 'active', 'state': state}
        state = pool.set_dns_state(backend_last_ok=_now())
        stability = _resolve_unknowns(pool, state, 'service', 'backend')
        path_age = _age(stability.get('client_last_check'))
        if path_age is None or path_age < 0 or path_age >= 60:
            profile = _active_profile_class(pool, state)
            profiles = ((profile,) if profile and state.get('active_kind') == 'isolated_manual'
                        else _required_profiles(cfg))
            path = dns_runtime.client_roundtrip_result(cfg, state.get('active_scope'), profiles,
                                                       block.get('active_check_seconds', 5))
            stability['client_last_check'] = _now()
            if path['status'] == 'UNKNOWN':
                _save_stability(pool, stability)
                return _hold_active_inspection_unknown(cfg, pool, state, 'client-path')
            stability['client_failures'] = (0 if path['status'] == 'PASS' else
                                           int(stability.get('client_failures', 0)) + 1)
            if path['status'] == 'PASS':
                state = pool.set_dns_state(client_path_last_ok=_now())
            _save_stability(pool, stability)
            stability = _resolve_unknowns(pool, state, 'client-path', *(
                ('candidate-path',) if path['status'] == 'PASS' else ()))
            if stability['client_failures'] >= 2:
                return _failover_locked(cfg, pool, state, manual_emergency, log,
                                         current_runtime_proven=True)
        # Only a full successful observation ends a continuous UNKNOWN interval.
        if ('client-path' in stability.get('unknown_causes', {})
                and path_age is not None and path_age < 60):
            return {'ok': False, 'action': 'client-path-inspection-unknown', 'state': state}
        if state.get('active_kind') == 'node_wide_automatic':
            return_age = _age(state.get('return_last_check'))
            if return_age is None or return_age < 0 or return_age >= 60:
                restored = _client_primary_recovery_locked(cfg, pool, state)
                if not isinstance(restored, dict):
                    restored = dns_evidence.outcome('PASS', 'ok') if restored else dns_evidence.outcome()
                dwell = time.monotonic() - float(stability.get('dwell_started', time.monotonic()))
                old = int(state.get('return_successes') or 0)
                successes = (old if restored['status'] == 'UNKNOWN' else
                             old + 1 if restored['status'] == 'PASS' else 0)
                if dwell < max(300, int(block.get('minimum_dwell_seconds', 300))):
                    successes = 0
                state = pool.set_dns_state(return_successes=successes, return_last_check=_now())
                if restored['status'] == 'UNKNOWN':
                    return _hold_active_inspection_unknown(cfg, pool, state, 'primary-path')
                _resolve_unknowns(pool, state, 'primary-path')
                if successes >= max(3, int(block.get('return_checks', 3))):
                    return _deactivate_locked(cfg, pool, 'auto', 'primary-dns-restored')
                state = pool.set_dns_state(last_error='recovery-pending')
        return {'ok': True, 'action': 'active', 'state': state}
    state = _align_new_automatic_incident(
        cfg, pool, state, automat_state, manual_emergency)
    eligible = (automat_state == "EMERGENCY" and not manual_emergency
                and pool.get_setting("automat_frozen") != "1"
                and block.get("mode") == "automatic_last_resort"
                and block.get("owner_approved") and block.get("active_probes")
                and block.get("automatic_ready")
                and pool.get_setting("dns_recovery_exhausted") == "1"
                and not state.get("attempt_used"))
    if not eligible:
        return {"ok": False, "action": "ineligible", "state": state}
    incident = pool.get_setting("dns_incident_id")
    if not incident:
        return {"ok": False, "action": "causal-unproven", "state": state}
    if not dns_runtime.emergency_route_ready(cfg) or not dns_runtime.wireguard_scope_ready(cfg, "all"):
        return {"ok": False, "action": "causal-unproven", "state": state}
    if not dns_runtime.peer_canary_runner_ready(cfg):
        return {"ok": False, "action": "canary-runner-unavailable", "state": state}
    # Reserve the sole automatic causal-probe series before the first external
    # query. A crash or an inconclusive client/server comparison must not turn
    # the five-second watchdog into an unbounded probe loop for this incident.
    state = pool.set_dns_state(
        phase="probing", configured_mode=block.get("mode"),
        incident_id=incident, attempt_used=True, last_error=None)
    deadline = time.monotonic() + 15.0
    context = _proof_context(cfg, deadline)
    chosen = _slot(cfg, require_fresh=True)
    if (not context or not chosen or block.get('runner_contract_version') != 4
            or not _is_future(block.get('readiness_not_after'))
            or not set(context['profiles']) <= set(block.get('profile_classes_ready', []))):
        state = pool.set_dns_state(phase='failed', last_error='causal-context-unavailable')
        return {'ok': False, 'action': 'causal-unproven', 'state': state}
    started = time.monotonic()
    rounds = []
    for index in range(3):
        scheduled = started + index * 4.0 + random.uniform(0, 0.5)
        delay = scheduled - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        if (time.monotonic() >= deadline or _proof_context(cfg, deadline) != context
                or not _is_future(chosen.get('not_after'))
                or not _is_future(block.get('readiness_not_after'))):
            break
        report = dns_runtime.causal_round(cfg, context['profiles'], chosen,
                                          min(2.5, deadline - time.monotonic()), deadline)
        if _proof_context(cfg, deadline) != context:
            break
        rounds.append(report)
    proof = dns_evidence.causal_quorum(rounds, context['profiles'])
    if proof['status'] != 'PASS' or time.monotonic() >= deadline:
        state = pool.set_dns_state(phase='failed', last_error='causal-unknown')
        return {'ok': False, 'action': 'causal-unproven', 'state': state}
    _audit_event(pool, actor='auto', result='causal-proven', detail=proof['reason'])
    return _activate_series_locked(cfg, pool, incident, 'auto', log,
                                   proof_context=context, slot_id=chosen['id'])



def automatic_tick(cfg, pool, automat_state, manual_emergency=False, log=print,
                   _locked=False):
    def run():
        current_automat = pool.get_setting("automat_state") or automat_state
        current_manual = pool.get_setting("emergency_manual") == "1"
        return _automatic_tick_locked(cfg, pool, current_automat,
                                      current_manual or manual_emergency, log)
    if _locked:
        return run()
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def prepare_for_emergency_exit(cfg, pool, actor="auto", log=print, _locked=False):
    """Remove every DNS interception before the data-plane may leave EMERGENCY."""
    def run():
        state = pool.dns_state()
        unfinished = pool.unfinished_dns_operations()
        if actor == 'auto' and _active(state):
            # Ordinary recovery cannot bypass DNS dwell/quorum by requesting
            # the shared EMERGENCY exit before DNS itself has reached idle.
            return {'ok': False, 'action': 'dns-recovery-pending', 'state': state}
        if (_active(state) or dns_runtime.firewall_attached(cfg)
                or unfinished):
            resume = None
            proof_state = None
            if (state.get("phase") in ACTIVE_PHASES and _active(state)
                    and not unfinished and _state_shape_valid(cfg, state)):
                proof_state = _pre_exit_physical_state(cfg, state)
            if proof_state == "unknown":
                return {"ok": False, "action": "dns-exit-proof-unknown",
                        "state": state}
            if proof_state == "ready":
                resume = _new_exit_resume_descriptor(pool, state)
                if resume is None:
                    return {"ok": False, "action": "dns-exit-state-invalid",
                            "state": state}
                pool.set_setting("dns_exit_resume",
                                 json.dumps(resume, ensure_ascii=True, sort_keys=True))
            result = _deactivate_locked(cfg, pool, actor, "coordinated-emergency-exit")
            if resume:
                result["resume_pending"] = True
            return result
        if state.get("phase") in ("probing", "failed", "recovering"):
            state = pool.set_dns_state(phase="idle", active_scope=None, active_slot=None,
                                       active_kind=None, activated_at=None, expires_at=None,
                                       backend_last_ok=None, client_path_last_ok=None,
                                       scope_identity=None, boot_id=None,
                                       expires_monotonic=None)
        return {"ok": True, "action": "dns-idle", "state": state}
    if os.name != "posix":
        return {"ok": True, "action": "non-linux", "state": pool.dns_state()}
    if _locked:
        return run()
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def _ensure_resume_emergency_route(cfg, log=print):
    """Restore the direct route for a still-owned node-wide compensation."""
    route_state = dns_runtime.emergency_route_state(cfg)
    if route_state == "ready":
        return "ready"
    if route_state == "unknown":
        return "unknown"
    try:
        import states as states_mod
        return "ready" if states_mod.emergency_on(cfg, log) else "failed"
    except Exception:
        return "failed"


def _resume_after_exit_failure_locked(cfg, pool, actor="recovery", log=print):
    raw = pool.get_setting("dns_exit_resume")
    if not raw:
        return {"ok": True, "action": "nothing-to-resume", "state": pool.dns_state()}
    try:
        resume = json.loads(raw)
        required = ("resume_id", "incident_id", "scope", "slot_id", "active_kind",
                    "boot_id", "scope_identity")
        if not isinstance(resume, dict) or not all(resume.get(key) for key in required):
            raise ValueError("invalid resume descriptor")
        if (resume.get("active_kind") == "node_wide_manual"
                and not resume.get("manual_emergency_ref")):
            raise ValueError("missing manual emergency reference")
        if resume.get("active_kind") == "isolated_manual":
            if (not str(resume.get("scope") or "").startswith("peer:")
                    or resume.get("profile_class") not in ("wg-ip", "external-ip")):
                raise ValueError("invalid isolated resume scope/profile")
        elif resume.get("active_kind") in (
                "node_wide_manual", "node_wide_automatic"):
            if (resume.get("scope") != "all"
                    or resume.get("profile_class") != "all-present"):
                raise ValueError("invalid node-wide resume scope/profile")
        else:
            raise ValueError("invalid resume kind")
    except (TypeError, ValueError):
        pool.set_setting("dns_exit_resume", None)
        return {"ok": False, "action": "resume-invalid", "state": pool.dns_state()}
    state = pool.dns_state()
    if _active(state):
        if _physical(cfg, state):
            matched = _clear_physical_resume(pool, "dns_exit_resume", state)
            return {"ok": True,
                    "action": ("already-resumed" if matched
                               else "resume-superseded"),
                    "state": state}
        return {"ok": False, "action": "resume-active-unproven", "state": state}
    automatic = resume.get("active_kind") == "node_wide_automatic"
    if (automatic
            and (pool.get_setting("dns_incident_id") != resume.get("incident_id")
                 or pool.get_setting("dns_recovery_exhausted") != "1")):
        pool.set_setting("dns_exit_resume", None)
        state = pool.set_dns_state(last_error="exit-resume-incident-changed")
        return {"ok": False, "action": "resume-cancelled", "state": state}
    try:
        attempt_seq = max(0, int(resume.get("attempt_seq") or 0))
    except (TypeError, ValueError):
        attempt_seq = MAX_CONTINUATION_ROUNDS
    if resume.get("exhausted") is True or attempt_seq >= MAX_CONTINUATION_ROUNDS:
        resume["exhausted"] = True
        resume["max_rounds"] = MAX_CONTINUATION_ROUNDS
        resume["retry_monotonic"] = 0
        pool.set_setting("dns_exit_resume",
                         json.dumps(resume, ensure_ascii=True, sort_keys=True))
        state = pool.set_dns_state(last_error="exit-resume-exhausted")
        pool.clear_dns_resume("dns_exit_resume", resume.get("resume_id"))
        return {"ok": False, "action": "resume-exhausted", "state": state}
    current_boot = _boot_id()
    if not current_boot:
        return _schedule_continuation_retry(
            pool, "dns_exit_resume", resume, attempt_seq,
            "resume-retry-pending", "resume-exhausted", "exit-resume",
            [{"slot": None, "action": "boot-identity-unavailable"}])
    cross_boot = resume.get("boot_id") != current_boot
    if cross_boot and resume.get("target_boot_id") != current_boot:
        # The persisted monotonic deadline belonged to another boot. Record the
        # new destination boot and make the first compensation attempt eligible.
        resume["target_boot_id"] = current_boot
        resume["retry_monotonic"] = 0
        pool.set_setting("dns_exit_resume",
                         json.dumps(resume, ensure_ascii=True, sort_keys=True))
    now_monotonic = time.monotonic()
    try:
        retry_monotonic = float(resume.get("retry_monotonic") or 0)
    except (TypeError, ValueError):
        retry_monotonic = 0
    if retry_monotonic > now_monotonic:
        return {"ok": False, "action": "resume-retry-pending", "state": state,
                "retry_after_seconds": retry_monotonic - now_monotonic}
    if cross_boot:
        if resume.get("active_kind") == "isolated_manual":
            pool.set_setting("dns_exit_resume", None)
            return {"ok": False, "action": "resume-boot-mismatch", "state": state}
    if resume.get("active_kind") == "isolated_manual":
        try:
            monotonic_expired = (resume.get("expires_monotonic") is None
                                 or time.monotonic()
                                 >= float(resume.get("expires_monotonic")))
        except (TypeError, ValueError):
            monotonic_expired = True
        if not _is_future(resume.get("expires_at")) or monotonic_expired:
            pool.set_setting("dns_exit_resume", None)
            return {"ok": False, "action": "resume-expired", "state": state}
    automat_state = pool.get_setting("automat_state")
    if resume.get("active_kind") == "isolated_manual":
        state_allows_resume = automat_state == "OK"
    else:
        state_allows_resume = automat_state == "EMERGENCY"
    if not state_allows_resume:
        # The data-plane transition may have succeeded before a crash. Keep the
        # descriptor until states.py either closes the incident or restores the
        # direct route; never reattach DNS interception on an unproven route.
        return {"ok": False, "action": "exit-transition-pending", "state": state}
    if resume.get("active_kind") != "isolated_manual":
        route_result = _ensure_resume_emergency_route(cfg, log)
        if route_result != "ready":
            return _schedule_continuation_retry(
                pool, "dns_exit_resume", resume, attempt_seq,
                "resume-retry-pending", "resume-exhausted", "exit-resume",
                [{"slot": None, "action": "emergency-route-" + route_result}])
    if cross_boot:
        # Restore/prove WAN first, then transfer the exact node-wide descriptor
        # into the boot contract without broadening its scope.
        boot_resume = {
            "resume_id": resume.get("resume_id"),
            "incident_id": resume.get("incident_id"),
            "scope": resume.get("scope"),
            "slot_id": resume.get("slot_id"),
            "active_kind": resume.get("active_kind"),
            "profile_class": resume.get("profile_class"),
            "scope_identity": resume.get("scope_identity"),
            "manual_emergency_ref": resume.get("manual_emergency_ref"),
            "attempt_seq": attempt_seq,
            "retry_monotonic": 0, "target_boot_id": current_boot,
            "max_rounds": MAX_CONTINUATION_ROUNDS,
            "exhausted": resume.get("exhausted") is True,
        }
        pool.set_settings({"dns_exit_resume": None,
                           "dns_boot_resume": json.dumps(
                               boot_resume, ensure_ascii=True, sort_keys=True)})
        return _resume_after_boot_locked(cfg, pool, log)
    # A terminal activation journal entry must never be reused. Each bounded
    # compensation round therefore gets fresh idempotency keys and may try the
    # remaining fresh candidates without extending an isolated rescue TTL.
    candidates = []
    try:
        candidates.append(_slot(cfg, resume["slot_id"], require_fresh=True))
    except DNSRescueError:
        pass
    candidates.extend(_failover_slots(
        cfg, resume["slot_id"], {resume["slot_id"]}, require_fresh=True))
    deadline = (time.monotonic()
                + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    errors = []
    for index, chosen in enumerate(candidates):
        if time.monotonic() >= deadline:
            errors.append({"slot": chosen.get("id"),
                           "action": "deadline-exhausted"})
            break
        try:
            result = _activate_locked(
                cfg, pool, resume["scope"], chosen.get("id"), actor, automatic, log,
                incident_id=resume["incident_id"],
                idempotency_key="dns-exit-resume:%s:%s:%s" % (
                    resume["resume_id"], attempt_seq, index),
                deadline_monotonic=deadline,
                continuation=True, resume_expires_at=resume.get("expires_at"),
                profile_class=resume.get("profile_class"),
                resume_expires_monotonic=resume.get("expires_monotonic"),
                resume_boot_id=resume.get("boot_id"),
                expected_scope_identity=resume.get("scope_identity"),
                expected_manual_emergency_ref=resume.get("manual_emergency_ref"),
                clear_resume_setting="dns_exit_resume",
                clear_resume_id=resume["resume_id"])
        except Exception as error:
            result = {"ok": False, "action": "exception",
                      "error": type(error).__name__, "state": pool.dns_state()}
        if result.get("ok"):
            return result
        errors.append({"slot": chosen.get("id"),
                       "action": result.get("action") or "failed"})
        if result.get("action") in ("fail-open-blocked", "cleanup-pending"):
            # Reconcile must first remove or prove the partial interception.
            # The durable descriptor remains for the next safe round.
            return result

    return _schedule_continuation_retry(
        pool, "dns_exit_resume", resume, attempt_seq,
        "resume-retry-pending", "resume-exhausted",
        "exit-resume", errors)


def resume_after_emergency_exit_failure(cfg, pool, actor="recovery", log=print,
                                        _locked=False):
    if os.name != "posix":
        return {"ok": False, "action": "unsupported", "state": pool.dns_state()}
    if _locked:
        return _resume_after_exit_failure_locked(cfg, pool, actor, log)
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return _resume_after_exit_failure_locked(cfg, pool, actor, log)
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def close_incident(cfg, pool, settings=None):
    """Close the recovery episode only after the normal data-plane is proven."""
    return pool.close_dns_incident(
        (cfg.get("dns_rescue") or {}).get("mode", "disabled"), settings=settings)
