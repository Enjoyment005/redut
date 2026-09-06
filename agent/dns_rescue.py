# -*- coding: utf-8 -*-
"""DNS Rescue coordinator: an opt-in, last-resort Redut operating mode.

The coordinator owns activation, rollback and recovery under the same network
lock as proxy rotation.  DNS evidence is observational only: it never grants
permission to rotate, buy, delete, or alter the primary outbound.
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
ACTIVE_PHASES = ("active_proxy", "active_direct")


class DNSRescueError(Exception):
    pass


def _now():
    return datetime.datetime.now().replace(microsecond=0).isoformat(sep=" ")


def coverage(cfg, state=None):
    block = cfg.get("dns_rescue") or {}
    state = state or {}
    return {
        "wireguard_ipv4_dns53": state.get("phase") in ACTIVE_PHASES,
        "wireguard_ipv6": False,
        "application_doh_dot": False,
        "legacy_clients_external_dns": False,
        "scope": state.get("active_scope"),
        "note": "Only IPv4 UDP/TCP port 53 entering through wg0 is controlled",
        "configured_mode": block.get("mode", "disabled"),
    }


def status(cfg, pool):
    state = pool.dns_state()
    state["configured_mode"] = (cfg.get("dns_rescue") or {}).get("mode", "disabled")
    return {"state": state, "coverage": coverage(cfg, state),
            "unfinished": pool.unfinished_dns_operations(limit=20)}


def _slot(cfg, slot_id=None):
    slots = (cfg.get("dns_rescue") or {}).get("candidates") or []
    if slot_id:
        for item in slots:
            if item.get("id") == slot_id:
                return item
        raise DNSRescueError("unknown DNS Rescue slot")
    return slots[0] if slots else None


def _allowed(cfg, automatic=False):
    block = cfg.get("dns_rescue") or {}
    mode = block.get("mode", "disabled")
    if mode not in MODES or mode in ("disabled", "observe_only"):
        raise DNSRescueError("DNS Rescue activation is disabled")
    if not block.get("owner_approved"):
        raise DNSRescueError("owner approval is absent")
    if automatic and (mode != "automatic_last_resort" or not block.get("automatic_ready")):
        raise DNSRescueError("automatic last-resort gate is closed")


def probe_listener(cfg, pool, incident_id=None, slot_id=None):
    block = cfg["dns_rescue"]
    host = block.get("listen_ip") or dns_runtime.wireguard_ip(cfg)
    results = []
    for transport in ("udp", "tcp"):
        result = dns_probe.probe(host, block["listen_port"], transport,
                                 block["request_timeout_seconds"])
        pool.record_dns_probe(result, incident_id=incident_id, slot_id=slot_id)
        results.append(result)
    return {"ok": all(item.get("ok") for item in results), "results": results}


def observe(cfg, pool):
    block = cfg.get("dns_rescue") or {}
    if not block.get("owner_approved") or not block.get("active_probes"):
        return {"ok": False, "skipped": "active probes are not approved"}
    return probe_listener(cfg, pool)


def activate(cfg, pool, scope="all", slot_id=None, actor="user", automatic=False,
             log=print, _locked=False):
    _allowed(cfg, automatic=automatic)
    if os.name != "posix":
        raise DNSRescueError("activation is available only on Linux")
    if automatic and scope != "all":
        raise DNSRescueError("automatic mode may only use the declared all-client scope")
    chosen = _slot(cfg, slot_id)
    if chosen is None:
        raise DNSRescueError("no safe DNS candidates configured")
    incident_id = (pool.get_setting("dns_incident_id") if automatic else None) or uuid.uuid4().hex
    current = pool.dns_state()
    if current.get("phase") in ACTIVE_PHASES:
        if current.get("active_slot") == chosen["id"] and current.get("active_scope") == scope:
            return {"ok": True, "action": "already-active", "state": current}
        raise DNSRescueError("another DNS Rescue scope is already active")
    key = "dns-activate:%s:%s:%s" % (incident_id, chosen["id"], scope)
    operation = pool.begin_dns_operation(incident_id, "activate", chosen["id"], scope,
                                         actor, key)
    if operation["phase"] == "committed":
        return {"ok": True, "action": "idempotent", "state": pool.dns_state()}

    def run():
        started = time.monotonic()
        phase = operation["phase"]
        pool.set_dns_state(phase="probing", configured_mode=cfg["dns_rescue"]["mode"],
                           incident_id=incident_id, attempt_used=True, last_error=None)
        try:
            pool.transition_dns_operation(operation["id"], "staging")
            phase = "staging"
            with open(cfg["singbox_config"], encoding="utf-8") as handle:
                main_config = json.load(handle)
            dns_runtime.stage_config(cfg, chosen, main_config)
            if time.monotonic() - started > cfg["dns_rescue"]["activation_deadline_seconds"]:
                raise DNSRescueError("activation deadline exceeded before service start")
            pool.transition_dns_operation(operation["id"], "started")
            phase = "started"
            dns_runtime.service_start()
            initial = probe_listener(cfg, pool, incident_id, chosen["id"])
            if not initial["ok"]:
                raise DNSRescueError("gateway listener did not pass UDP and TCP probes")
            pool.transition_dns_operation(operation["id"], "redirected")
            phase = "redirected"
            dns_runtime.activate_firewall(cfg, scope=scope)
            pool.transition_dns_operation(operation["id"], "verifying")
            phase = "verifying"
            if not dns_runtime.firewall_effective(cfg, scope=scope):
                raise DNSRescueError("redirect is not effective")
            if time.monotonic() - started > cfg["dns_rescue"]["activation_deadline_seconds"]:
                raise DNSRescueError("activation deadline exceeded")
            final = probe_listener(cfg, pool, incident_id, chosen["id"])
            if not final["ok"]:
                raise DNSRescueError("post-redirect gateway probe failed")
            pool.transition_dns_operation(operation["id"], "committed")
            phase = "committed"
            phase = "active_proxy" if chosen["transport"] == "proxy" else "active_direct"
            state = pool.set_dns_state(
                phase=phase, configured_mode=cfg["dns_rescue"]["mode"],
                incident_id=incident_id, active_scope=scope, active_slot=chosen["id"],
                activated_at=_now(), attempt_used=True, return_successes=0, last_error=None)
            pool.log_event("dns-rescue", actor=actor, result="active",
                           detail="slot=%s transport=%s scope=%s" % (
                               chosen["id"], chosen["transport"], scope))
            return {"ok": True, "action": "activated", "state": state,
                    "coverage": coverage(cfg, state)}
        except Exception as error:
            # Rollback order matters: stop interception before stopping its server.
            try:
                if phase == "planned":
                    pool.transition_dns_operation(operation["id"], "failed",
                                                  error=type(error).__name__)
                    phase = "failed"
                elif phase not in ("committed", "rolled_back", "failed"):
                    pool.transition_dns_operation(operation["id"], "rollback",
                                                  error=type(error).__name__)
                    phase = "rollback"
                dns_runtime.deactivate_firewall(cfg, scope=scope)
                dns_runtime.service_stop()
                if phase == "rollback":
                    pool.transition_dns_operation(operation["id"], "rolled_back",
                                                  error=type(error).__name__)
            except Exception as rollback_error:
                try:
                    pool.transition_dns_operation(operation["id"], "failed",
                                                  error="rollback:" + type(rollback_error).__name__)
                except Exception:
                    pass
            state = pool.set_dns_state(
                phase="failed", configured_mode=cfg["dns_rescue"]["mode"],
                incident_id=incident_id, active_scope=None, active_slot=None,
                activated_at=None, attempt_used=True, return_successes=0,
                last_error=type(error).__name__)
            pool.log_event("dns-rescue", actor=actor, result="failed",
                           detail="activation failed: %s" % type(error).__name__)
            return {"ok": False, "action": "rolled-back", "error": str(error), "state": state}

    if _locked:
        return run()
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error),
                "state": pool.dns_state()}


def deactivate(cfg, pool, actor="user", reason="manual", _locked=False):
    current = pool.dns_state()
    if current.get("phase") not in ACTIVE_PHASES and not pool.unfinished_dns_operations():
        return {"ok": True, "action": "already-idle", "state": current}
    incident = current.get("incident_id") or uuid.uuid4().hex
    key = "dns-deactivate:%s:%s" % (incident, reason)
    operation = pool.begin_dns_operation(incident, "deactivate", current.get("active_slot"),
                                         current.get("active_scope") or "all", actor, key)

    def run():
        try:
            pool.transition_dns_operation(operation["id"], "staging")
            dns_runtime.deactivate_firewall(cfg, scope=current.get("active_scope") or "all")
            pool.transition_dns_operation(operation["id"], "started")
            dns_runtime.service_stop()
            pool.transition_dns_operation(operation["id"], "redirected")
            pool.transition_dns_operation(operation["id"], "verifying")
            if dns_runtime.firewall_effective(cfg, scope=current.get("active_scope") or "all"):
                raise DNSRescueError("redirect remains effective")
            pool.transition_dns_operation(operation["id"], "committed")
            state = pool.set_dns_state(
                phase="idle", configured_mode=cfg["dns_rescue"]["mode"],
                incident_id=None, active_scope=None, active_slot=None, activated_at=None,
                attempt_used=False, return_successes=0, last_error=None)
            pool.set_setting("dns_recovery_exhausted", None)
            pool.log_event("dns-rescue", actor=actor, result="idle", detail="deactivated: " + reason)
            return {"ok": True, "action": "deactivated", "state": state}
        except Exception as error:
            try:
                pool.transition_dns_operation(operation["id"], "failed",
                                              error=type(error).__name__)
            except Exception:
                pass
            state = pool.set_dns_state(last_error=type(error).__name__)
            return {"ok": False, "action": "failed", "error": str(error), "state": state}

    if _locked:
        return run()
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            return run()
    except apply_mod.ApplyError as error:
        return {"ok": False, "action": "deferred", "error": str(error), "state": current}


def reconcile(cfg, pool, actor="recovery"):
    """Crash recovery is conservative: remove interception, then close sagas."""
    unfinished = pool.unfinished_dns_operations()
    if not unfinished:
        state = pool.dns_state()
        if (state.get("phase") in ACTIVE_PHASES
                and (cfg.get("dns_rescue") or {}).get("mode") == "disabled"):
            return deactivate(cfg, pool, actor=actor, reason="configuration-disabled")["state"]
        effective = (dns_runtime.firewall_effective(
            cfg, scope=state.get("active_scope") or "all") if os.name == "posix" else False)
        if state.get("phase") in ACTIVE_PHASES and not effective:
            return pool.set_dns_state(phase="failed", active_scope=None, active_slot=None,
                                      last_error="effective-state-mismatch")
        return state
    if os.name != "posix":
        return pool.set_dns_state(phase="failed", active_scope=None, active_slot=None,
                                  last_error="recovery-requires-linux")
    try:
        with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
            dns_runtime.deactivate_firewall(cfg)
            dns_runtime.service_stop()
            for op in unfinished:
                try:
                    if op["phase"] == "planned":
                        pool.transition_dns_operation(op["id"], "failed", error="crash-recovery")
                    elif op["phase"] != "rollback":
                        pool.transition_dns_operation(op["id"], "rollback", error="crash-recovery")
                        pool.transition_dns_operation(op["id"], "rolled_back", error="crash-recovery")
                    else:
                        pool.transition_dns_operation(op["id"], "rolled_back", error="crash-recovery")
                except (ValueError, KeyError):
                    pass
            return pool.set_dns_state(phase="idle", active_scope=None, active_slot=None,
                                      activated_at=None, return_successes=0,
                                      last_error="recovered-after-crash")
    except apply_mod.ApplyError:
        return pool.dns_state()


def _age(stamp):
    if not stamp:
        return None
    try:
        return (datetime.datetime.now() - datetime.datetime.fromisoformat(str(stamp))).total_seconds()
    except (TypeError, ValueError):
        return None


def _primary_probe(cfg):
    target = str(cfg.get("dns") or "1.1.1.1")
    timeout = (cfg.get("dns_rescue") or {}).get("request_timeout_seconds", 3)
    results = [dns_probe.probe(target, 53, transport, timeout) for transport in ("udp", "tcp")]
    return all(item.get("ok") for item in results)


def automatic_tick(cfg, pool, automat_state, manual_emergency=False, log=print,
                   _locked=False):
    """One-shot auto entry.  Caller must invoke before ordinary heartbeat mutation."""
    state = pool.dns_state()
    block = cfg.get("dns_rescue") or {}
    if state.get("phase") in ACTIVE_PHASES:
        # Fail-open guards apply even to a manual canary: expiry or repeated
        # gateway failure removes interception before stopping the process.
        if (_age(state.get("activated_at")) or 0) >= block.get("isolated_ttl_seconds", 900):
            return deactivate(cfg, pool, actor="auto", reason="isolated-ttl", _locked=_locked)
        health = probe_listener(cfg, pool, state.get("incident_id"), state.get("active_slot"))
        if health.get("ok"):
            pool.set_setting("dns_active_failures", None)
        else:
            failures = int(pool.get_setting("dns_active_failures") or 0) + 1
            pool.set_setting("dns_active_failures", str(failures))
            if failures >= int(block.get("active_failures", 3)):
                return deactivate(cfg, pool, actor="auto", reason="gateway-unhealthy",
                                  _locked=_locked)
        last_return = pool.get_setting("dns_return_last")
        if _age(last_return) is None or _age(last_return) >= block.get("return_interval_seconds", 60):
            pool.set_setting("dns_return_last", _now())
            successes = state.get("return_successes", 0) + 1 if _primary_probe(cfg) else 0
            state = pool.set_dns_state(return_successes=successes)
            if successes >= int(block.get("return_checks", 3)):
                return deactivate(cfg, pool, actor="auto", reason="primary-dns-restored",
                                  _locked=_locked)
        return {"ok": True, "action": "active", "state": state}
    eligible = (automat_state == "EMERGENCY" and not manual_emergency
                and block.get("mode") == "automatic_last_resort"
                and block.get("owner_approved") and block.get("automatic_ready")
                and pool.get_setting("dns_recovery_exhausted") == "1"
                and not state.get("attempt_used"))
    if not eligible:
        return {"ok": False, "action": "ineligible", "state": state}
    return activate(cfg, pool, scope="all", actor="auto", automatic=True, log=log,
                    _locked=_locked)
