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
import time
import uuid

import apply as apply_mod
import dns_probe
import dns_runtime

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
    if automatic and (mode != "automatic_last_resort"
                      or (not continuation and not block.get("automatic_ready"))):
        raise DNSRescueError("automatic last-resort gate is closed")


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
        and _is_future(current_slot.get("not_after")))
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
    for transport in ("udp", "tcp"):
        timeout = float(block["request_timeout_seconds"])
        if deadline_monotonic is not None:
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                return {"ok": False, "results": results,
                        "error": "operation deadline exceeded"}
            timeout = min(timeout, remaining)
        # A different opaque label per transport defeats resolver/OS cache and
        # is never persisted or returned by the status API.
        qname = "%s.%s" % (uuid.uuid4().hex, suffix)
        result = dns_probe.probe(
            host, block["listen_port"], transport, timeout,
            name=qname, expected_ipv4=expected_ipv4)
        pool.record_dns_probe(result, incident_id=incident_id, slot_id=slot_id)
        results.append(result)
    return {"ok": all(item.get("ok") for item in results), "results": results}


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
                      clear_resume_setting=None, clear_resume_id=None):
    deadline = (deadline_monotonic if deadline_monotonic is not None else
                time.monotonic() + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    _validate_scope_locked(cfg, pool, scope, automatic, continuation=continuation,
                           profile_class=profile_class,
                           deadline_monotonic=deadline)
    chosen = _slot(cfg, slot_id, require_fresh=True)
    if chosen is None:
        raise DNSRescueError("no safe DNS candidates configured")
    deadline = _cap_candidate_deadline(chosen.get("not_after"), deadline)
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
        dns_runtime.service_start(deadline)
        _require_candidate_fresh(chosen, "before initial backend proof")
        initial = probe_backend(cfg, pool, incident_id, chosen["id"], deadline)
        if not initial["ok"]:
            raise DNSRescueError("gateway backend did not pass UDP and TCP probes")
        required_profiles = (("wg-ip", "external-ip")
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
            if (not dns_runtime.deactivate_redirect(
                    cfg, scope=preflight_scope, deadline_monotonic=deadline)
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
            dns_runtime.service_start(deadline)
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
                if (remaining <= 0 or not dns_runtime.client_primary_failure_proven(
                        cfg, required_profiles,
                        min(cfg["dns_rescue"]["request_timeout_seconds"], remaining),
                        deadline_monotonic=deadline)):
                    raise DNSRescueError("primary path recovered during candidate preflight")
        _require_candidate_fresh(chosen, "before live cutover")
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
            redirect_detached = bool(dns_runtime.deactivate_redirect(
                cfg, scope=scope, deadline_monotonic=cleanup_deadline))
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
                    dns_runtime.service_start(cleanup_deadline)
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


def _deactivate_locked(cfg, pool, actor="user", reason="manual",
                       deadline_monotonic=None):
    deadline = (deadline_monotonic if deadline_monotonic is not None
                else time.monotonic() + 15.0)
    current = pool.dns_state()
    attached = dns_runtime.firewall_attached(cfg, deadline)
    unfinished = pool.unfinished_dns_operations()
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
    key = "dns-deactivate:%s:%s:%s" % (incident, generation, reason)
    operation = pool.begin_dns_operation(
        incident, "deactivate-" + str(current.get("active_kind") or "recovery"),
        current.get("active_slot"), runtime_scope, actor, key, generation=generation,
        snapshot={"firewall_attached": attached,
                  "authorized_guard_scope": scope,
                  "service_active": dns_runtime.service_active(deadline)})
    if operation.get("phase") in ("failed", "rolled_back"):
        # A prior terminal cleanup attempt is audit history, not a reusable
        # transaction. Give the bounded retry a fresh journal identity.
        operation = pool.begin_dns_operation(
            incident, "deactivate-" + str(current.get("active_kind") or "recovery"),
            current.get("active_slot"), runtime_scope, actor,
            key + ":retry:" + uuid.uuid4().hex, generation=generation,
            snapshot={"firewall_attached": attached,
                      "authorized_guard_scope": scope,
                      "service_active": dns_runtime.service_active(deadline)})
    if operation["phase"] == "committed" and dns_runtime.firewall_detached(cfg, deadline):
        state = pool.set_dns_state(phase="idle", active_scope=None, active_slot=None,
                                   activated_at=None, active_kind=None, expires_at=None,
                                   active_failures=0, active_last_check=None,
                                   backend_last_ok=None, client_path_last_ok=None,
                                   scope_identity=None, boot_id=None,
                                   expires_monotonic=None)
        return {"ok": True, "action": "idempotent", "state": state}
    op_phase = operation["phase"]
    try:
        pool.set_dns_state(phase="recovering", last_error=None)
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        if not dns_runtime.deactivate_redirect(
                cfg, scope=runtime_scope, deadline_monotonic=deadline):
            raise DNSRescueError("interception cleanup is not proven")
        pool.transition_dns_operation(operation["id"], "started")
        op_phase = "started"
        if not dns_runtime.redirect_detached(cfg, deadline):
            raise DNSRescueError("redirect remains attached")
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
        _audit_event(pool, actor=actor, result="idle",
                     detail="deactivated: %s scope=%s" % (
                         reason, _scope_label(runtime_scope)))
        return {"ok": True, "action": "deactivated", "state": state}
    except Exception as error:
        error_kind = type(error).__name__
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
                    dns_runtime.service_start(cleanup_retry)
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
    unfinished = pool.unfinished_dns_operations()
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
    if (not attached and not unfinished and not auxiliary_errors
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
    if not attached:
        try:
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
        detached = bool(dns_runtime.deactivate_redirect(
            cfg, scope=runtime_scope,
            deadline_monotonic=deadline))
    except Exception as error:
        detach_error = error
    if not detached:
        detached = dns_runtime.redirect_detached(cfg, deadline)
    if not detached:
        # NAT detachment always comes first. Only when it cannot be proved do
        # we preserve/restart the listener, and then only behind a proven ACL.
        try:
            if guard_scope and not dns_runtime.listener_guard_effective(
                    cfg, guard_scope, deadline):
                dns_runtime.stage_listener_acl(cfg, guard_scope, deadline)
            if guard_scope and dns_runtime.listener_guard_effective(
                    cfg, guard_scope, deadline):
                service_state = dns_runtime.service_state(deadline)
                if service_state == "inactive":
                    dns_runtime.service_start(deadline)
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
        return pool.set_dns_state(
            phase="idle" if state.get("active_kind") == "isolated_manual" else "failed",
            active_scope=None, active_slot=None, activated_at=None, active_kind=None,
            expires_at=None, active_failures=0, active_last_check=None,
            last_error="recovered-after-crash", backend_last_ok=None,
            client_path_last_ok=None, scope_identity=None, boot_id=None,
            expires_monotonic=None)
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
        proven = dns_runtime.client_primary_recovery_proven(
            cfg, ("wg-ip", "external-ip"),
            (cfg.get("dns_rescue") or {}).get("request_timeout_seconds", 3))
        if not proven:
            raise DNSRescueError("client primary recovery is not proven")
        for phase in ("started", "redirected", "verifying", "committed"):
            pool.transition_dns_operation(operation["id"], phase)
            op_phase = phase
        return True
    except Exception as error:
        _mark_operation_failed(pool, operation, op_phase, type(error).__name__)
        return False


def _activate_series_locked(cfg, pool, incident_id, actor="auto", log=print):
    errors = []
    deadline = (time.monotonic()
                + float(cfg["dns_rescue"]["activation_deadline_seconds"]))
    for chosen in _slots(cfg):
        if not _is_future(chosen.get("not_after")):
            errors.append({"slot": chosen.get("id"), "action": "expired"})
            continue
        if time.monotonic() >= deadline:
            errors.append({"slot": chosen.get("id"), "action": "deadline-exhausted"})
            break
        result = _activate_locked(cfg, pool, "all", chosen.get("id"), actor, True,
                                  log, incident_id=incident_id,
                                  deadline_monotonic=deadline)
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
                         else ("wg-ip", "external-ip"))
    try:
        pool.transition_dns_operation(operation["id"], "staging")
        op_phase = "staging"
        with open(cfg["singbox_config"], encoding="utf-8") as handle:
            main_config = json.load(handle)
        preflight_scope = (scope if active_kind == "isolated_manual" else
                           "peer:" + str(cfg["dns_rescue"]["canary_peer_ipv4"]))
        remaining = max(0.0, deadline - time.monotonic())
        if (remaining <= 0 or not dns_runtime.candidate_sidecar_preflight_proven(
                cfg, chosen, main_config, preflight_scope, required_profiles,
                min(cfg["dns_rescue"]["active_check_seconds"], remaining),
                deadline_monotonic=deadline)):
            raise DNSRescueError("successor sidecar preflight failed")
        _require_candidate_fresh(chosen, "before successor live cutover")
        # Only the resolver process is switched. The already proven scoped NAT
        # and listener guard remain in place and are revalidated before commit.
        dns_runtime.stage_config(cfg, chosen, main_config,
                                 deadline_monotonic=deadline)
        live_config_changed = True
        _require_candidate_fresh(chosen, "before successor service start")
        dns_runtime.service_start(deadline)
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
                    dns_runtime.service_start(time.monotonic() + 10.0)
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
        if result.get("action") == "successor-rejected-current-preserved":
            continue
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
    """Bound transient kernel-inspection failures before fail-open teardown."""
    failures = int(state.get("active_failures") or 0) + 1
    current = pool.set_dns_state(
        active_failures=failures, active_last_check=_now(),
        last_error=str(label) + "-inspection-unknown")
    if failures >= int((cfg.get("dns_rescue") or {}).get("active_failures", 3)):
        resume = None
        if (state.get("active_kind") in (
                "node_wide_manual", "node_wide_automatic")
                and not pool.get_setting("dns_exit_resume")
                and not pool.get_setting("dns_boot_resume")
                and _state_shape_valid(cfg, state)):
            resume = _new_exit_resume_descriptor(pool, state)
            if resume is not None:
                pool.set_setting("dns_exit_resume", json.dumps(
                    resume, ensure_ascii=True, sort_keys=True))
        result = _deactivate_locked(
            cfg, pool, "auto", str(label) + "-inspection-unknown")
        if result.get("ok") and resume is not None:
            result["resume_pending"] = True
        return result
    return {"ok": False, "action": str(label) + "-inspection-unknown",
            "state": current}


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
        and block.get("owner_approved") and block.get("automatic_ready")
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
        active_slot = next((item for item in _slots(cfg)
                            if item.get("id") == state.get("active_slot")), None)
        if active_slot is None or not _is_future(active_slot.get("not_after")):
            # Expired metadata forbids every new dial/probe with this slot, but
            # does not itself prove that the already established TLS path died.
            # Move only when a fresh replacement exists; otherwise preserve the
            # guarded listener and expose stale/unknown evidence for manual exit.
            fresh = _failover_slots(
                cfg, state.get("active_slot"),
                _tried_slots(pool, state.get("incident_id")), require_fresh=True)
            expired_runtime_state = dns_runtime.service_state()
            if expired_runtime_state == "unknown":
                failures = int(state.get("active_failures") or 0) + 1
                threshold = int(block.get("active_failures", 3))
                if fresh and failures >= threshold:
                    state = pool.set_dns_state(
                        active_failures=failures, active_last_check=_now(),
                        last_error="service-inspection-unknown")
                    return _failover_locked(
                        cfg, pool, state, manual_emergency, log,
                        current_runtime_proven=False)
                return _hold_active_inspection_unknown(
                    cfg, pool, state, "service")
            if fresh:
                return _failover_locked(
                    cfg, pool, state, manual_emergency, log,
                    current_runtime_proven=expired_runtime_state == "active")
            runtime_present = (_runtime_proof_recent(cfg, state)
                               and expired_runtime_state == "active"
                               and dns_runtime.firewall_effective(
                                   cfg, scope=state.get("active_scope")))
            if runtime_present:
                state = pool.set_dns_state(last_error="candidate-evidence-expired")
                return {"ok": False, "action": "active-evidence-expired",
                        "state": state}
            return _failover_locked(
                cfg, pool, state, manual_emergency, log,
                current_runtime_proven=expired_runtime_state == "active")
        age = _age(state.get("active_last_check"))
        if (age is not None and 0 <= age
                < int(block.get("active_check_seconds", 5))):
            return {"ok": True, "action": "active", "state": state}
        runtime_state = dns_runtime.service_state()
        immediate = runtime_state == "inactive"
        health = ({"ok": False} if runtime_state != "active" else
                  probe_backend(cfg, pool, state.get("incident_id"), state.get("active_slot")))
        if health.get("ok"):
            state = pool.set_dns_state(backend_last_ok=_now())
            path_age = _age(state.get("client_path_last_ok"))
            path_ttl = int(block.get("path_evidence_ttl_seconds", 300))
            if path_age is None or path_age < 0 or path_age >= path_ttl / 2.0:
                profile = _active_profile_class(pool, state)
                required_profiles = ((profile,) if state.get("active_kind") == "isolated_manual"
                                     else ("wg-ip", "external-ip"))
                path_ok = bool(profile or state.get("active_kind") != "isolated_manual")
                path_ok = path_ok and dns_runtime.client_roundtrip_proven(
                    cfg, state.get("active_scope"), required_profiles,
                    block.get("active_check_seconds", 5))
                if path_ok:
                    state = pool.set_dns_state(client_path_last_ok=_now())
                else:
                    health = {"ok": False}
        failures = 0 if health.get("ok") else int(state.get("active_failures") or 0) + 1
        state = pool.set_dns_state(active_failures=failures, active_last_check=_now())
        if immediate or failures >= int(block.get("active_failures", 3)):
            return _failover_locked(
                cfg, pool, state, manual_emergency, log,
                current_runtime_proven=runtime_state == "active")
        if health.get("ok") and state.get("active_kind") == "node_wide_automatic":
            return_age = _age(state.get("return_last_check"))
            if return_age is None or return_age >= int(block.get("return_interval_seconds", 60)):
                _failed, primary = _primary_dns_failure(
                    cfg, pool, state.get("incident_id"))
                restored = (all(item.get("ok") for item in primary)
                            and _client_primary_recovery_locked(
                                cfg, pool, state))
                successes = int(state.get("return_successes") or 0) + 1 if restored else 0
                state = pool.set_dns_state(return_successes=successes,
                                           return_last_check=_now())
                if successes >= int(block.get("return_checks", 3)):
                    return _deactivate_locked(cfg, pool, "auto", "primary-dns-restored")
        return {"ok": bool(health.get("ok")), "action": "active", "state": state}
    state = _align_new_automatic_incident(
        cfg, pool, state, automat_state, manual_emergency)
    eligible = (automat_state == "EMERGENCY" and not manual_emergency
                and pool.get_setting("automat_frozen") != "1"
                and block.get("mode") == "automatic_last_resort"
                and block.get("owner_approved") and block.get("automatic_ready")
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
    if not dns_runtime.client_primary_failure_proven(
            cfg, ("wg-ip", "external-ip"), block.get("request_timeout_seconds", 3)):
        state = pool.set_dns_state(
            phase="failed", last_error="client-primary-unproven")
        return {"ok": False, "action": "client-primary-unproven", "state": state}
    failed, _results = _primary_dns_failure(cfg, pool, incident)
    if not failed:
        state = pool.set_dns_state(
            phase="failed", last_error="primary-dns-working")
        return {"ok": False, "action": "primary-dns-working", "state": state}
    return _activate_series_locked(cfg, pool, incident, "auto", log)


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
