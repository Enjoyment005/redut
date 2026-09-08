"""Strict v4 runner evidence and bounded semantic quorum, without network I/O."""
import json
import math

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"
REASONS = {"ok", "nxdomain", "nodata", "servfail", "refused", "timeout",
           "wrong_rrset", "control_failed", "runner_error"}
CONTROL_DOMAINS = {"control-a": "cloudflare", "control-b": "google"}


def outcome(status=UNKNOWN, reason="runner_error", **values):
    """Produce bounded metadata; callers must never persist the raw report."""
    return dict(ok=status == PASS, status=status, reason=reason, **values)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence key")
        result[key] = value
    return result


def _dns(item, qname, expected=None):
    """Validate one measured path, including the full owned-canary RRset."""
    if not isinstance(item, dict) or set(item) != {
            "status", "reason", "qname", "rcode", "answers", "latency_ms"}:
        raise ValueError("invalid DNS evidence shape")
    status, reason, latency = item['status'], item['reason'], item['latency_ms']
    if (status not in (PASS, FAIL, UNKNOWN) or reason not in REASONS
            or item['qname'] != qname or type(latency) not in (int, float)
            or not math.isfinite(latency) or not 0 <= latency <= 2000):
        raise ValueError("invalid DNS evidence identity")
    rcode, answers = item['rcode'], item['answers']
    if rcode is not None and (type(rcode) is not int or not 0 <= rcode <= 15):
        raise ValueError("invalid rcode")
    if not isinstance(answers, list) or len(answers) > 16:
        raise ValueError("invalid RRset")
    for rr in answers:
        if (not isinstance(rr, dict) or set(rr) != {'owner', 'type', 'value', 'ttl'}
                or type(rr['ttl']) is not int or not 0 <= rr['ttl'] <= 86400
                or not all(isinstance(rr[k], str) for k in ('owner', 'type', 'value'))):
            raise ValueError("invalid RR")
    if status == UNKNOWN:
        if reason != 'runner_error' or rcode is not None or answers:
            raise ValueError("unknown is not a negative answer")
    elif status == PASS:
        if reason != 'ok' or rcode != 0 or not answers:
            raise ValueError("invalid positive answer")
        if expected is not None and (len(answers) != 1 or answers[0] != {
                'owner': qname, 'type': 'A', 'value': expected, 'ttl': answers[0]['ttl']}
                or answers[0]['ttl'] > 30):
            raise ValueError("positive owned canary RRset mismatch")
    else:
        if reason in ('ok', 'runner_error', 'control_failed'):
            raise ValueError("invalid negative answer")
        if reason in ('nxdomain', 'servfail') and rcode != {
                'nxdomain': 3, 'servfail': 2, 'refused': 5}[reason]:
            raise ValueError("negative rcode mismatch")
        if reason == 'refused' and rcode not in (None, 5):
            raise ValueError('refusal evidence mismatch')
        if reason in ('nodata', 'wrong_rrset') and rcode != 0:
            raise ValueError("negative semantics mismatch")
        if reason in ('timeout', 'nodata', 'nxdomain') and answers:
            raise ValueError("negative answer has unexpected records")
        if reason == 'timeout' and rcode is not None:
            raise ValueError("timeout has rcode")
    return item


def _controls(controls):
    if not isinstance(controls, list) or len(controls) != 2:
        raise ValueError("two controls required")
    seen = set()
    for control in controls:
        if (not isinstance(control, dict) or set(control) != {
                'id', 'failure_domain', 'status', 'ip_tls', 'hostname'}
                or control['id'] in seen or control['id'] not in CONTROL_DOMAINS
                or control['failure_domain'] != CONTROL_DOMAINS[control['id']]
                or control['status'] not in (PASS, FAIL, UNKNOWN)
                or type(control['ip_tls']) is not bool
                or type(control['hostname']) is not bool):
            raise ValueError("independent controls not proven")
        seen.add(control['id'])
    return all(c['status'] == PASS and c['ip_tls'] and c['hostname'] for c in controls)


def parse_report(proc, *, challenge, generation, qname, expected_ipv4, profiles,
                 mode, candidate=None, sentinels=()):
    """Accept only complete, challenge-bound v4 evidence; malformed means UNKNOWN."""
    try:
        raw = proc.stdout or ''
        if proc.returncode != 0 or len(raw.encode('utf-8')) > 32768:
            return outcome()
        report = json.loads(raw, object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        keys = {'version', 'challenge', 'route_generation', 'query', 'profiles'}
        if (not isinstance(report, dict) or set(report) != keys
                or type(report['version']) is not int or report['version'] != 4
                or report['challenge'] != challenge or report['route_generation'] != generation
                or report['query'] != {'qname': qname, 'type': 'A', 'expected_ipv4': expected_ipv4}
                or not isinstance(report['profiles'], dict)
                or set(report['profiles']) != set(profiles) or not profiles):
            return outcome()
        summarized = {}
        for profile in profiles:
            item = report['profiles'][profile]
            required = {'dns', 'application_dns', 'controls'}
            if mode == 'causal-round':
                required |= {'secure', 'sentinels'}
            if not isinstance(item, dict) or set(item) != required:
                return outcome()
            if not isinstance(item['dns'], dict) or set(item['dns']) != {'udp', 'tcp'}:
                return outcome()
            paths = {t: _dns(item['dns'][t], qname, expected_ipv4) for t in ('udp', 'tcp')}
            paths['application'] = _dns(item['application_dns'], qname, expected_ipv4)
            controls = _controls(item['controls'])
            if mode != 'causal-round':
                statuses = [p['status'] for p in paths.values()]
                status = UNKNOWN if UNKNOWN in statuses or not controls else (
                    PASS if all(s == PASS for s in statuses) else FAIL)
                summarized[profile] = outcome(status, 'ok' if status == PASS else
                                              'runner_error' if status == UNKNOWN else 'wrong_rrset')
                continue
            secure = item['secure']
            if (not isinstance(secure, dict) or set(secure) != {'slot', 'operator', 'transport', 'dns'}
                    or candidate is None or secure['slot'] != candidate['id']
                    or secure['operator'] != candidate['operator']
                    or secure['transport'] != candidate['transport']):
                return outcome()
            secure_dns = _dns(secure['dns'], qname, expected_ipv4)
            classes = [('transport', paths)]
            if not isinstance(item['sentinels'], dict) or set(item['sentinels']) != set(sentinels):
                return outcome()
            for name in sentinels:
                sentinel = item['sentinels'][name]
                if not isinstance(sentinel, dict) or set(sentinel) != {'dns', 'application_dns', 'secure'}:
                    return outcome()
                if not isinstance(sentinel['dns'], dict) or set(sentinel['dns']) != {'udp', 'tcp'}:
                    return outcome()
                dns = {t: _dns(sentinel['dns'][t], name) for t in ('udp', 'tcp')}
                dns['application'] = _dns(sentinel['application_dns'], name)
                protected = sentinel['secure']
                if not isinstance(protected, dict) or set(protected) != {'cloudflare', 'google'}:
                    return outcome()
                secured = [_dns(protected[op], name) for op in ('cloudflare', 'google')]
                # Authoritative NXDOMAIN or disagreement never proves interference.
                if all(d['status'] == PASS and d['rcode'] == 0 for d in secured):
                    classes.append((name, dns))
            failures = {}
            for test_id, dns in classes:
                app, udp, tcp = dns['application'], dns['udp'], dns['tcp']
                semantic = (app['status'] == FAIL and udp['status'] == FAIL
                            and app['reason'] == udp['reason']
                            and udp['reason'] in ('nxdomain', 'wrong_rrset', 'nodata'))
                transport = (app['status'] == FAIL and udp['status'] == FAIL and tcp['status'] == FAIL
                             and app['reason'] in ('timeout', 'servfail', 'refused')
                             and udp['reason'] == app['reason'] == tcp['reason'])
                if semantic or transport:
                    failures[test_id] = ('INTERFERENCE_SUSPECTED' if semantic else
                                         'PRIMARY_DNS_PATH_FAILED')
            summarized[profile] = {'controls': controls,
                                   'candidate': secure_dns['status'] == PASS,
                                   'failures': failures}
        if mode == 'causal-round':
            return outcome(PASS, 'ok', profiles=summarized)
        statuses = [p['status'] for p in summarized.values()]
        status = UNKNOWN if UNKNOWN in statuses else FAIL if FAIL in statuses else PASS
        return outcome(status, 'ok' if status == PASS else
                       'runner_error' if status == UNKNOWN else 'wrong_rrset')
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        return outcome()


def causal_quorum(rounds, profiles):
    """Require 3/3 controls/candidate and matching 2/3 client faults including last."""
    if len(rounds) != 3 or not profiles or any(r.get('status') != PASS for r in rounds):
        return outcome()
    reasons = []
    for profile in profiles:
        evidence = [r.get('profiles', {}).get(profile, {}) for r in rounds]
        if not all(p.get('controls') and p.get('candidate') for p in evidence):
            return outcome()
        matching = [(test, reason) for test, reason in evidence[-1].get('failures', {}).items()
                    if sum(p.get('failures', {}).get(test) == reason for p in evidence) >= 2]
        if not matching:
            return outcome()
        reasons.extend(reason for _, reason in matching)
    return outcome(PASS, 'INTERFERENCE_SUSPECTED' if 'INTERFERENCE_SUSPECTED' in reasons
                   else 'PRIMARY_DNS_PATH_FAILED')


def current_fault_confirmed(report, profiles):
    """A final freshness check cannot replace the preceding three-round quorum."""
    return bool(profiles and report.get('status') == PASS and all(
        report.get('profiles', {}).get(profile, {}).get('controls')
        and report['profiles'][profile].get('candidate')
        and report['profiles'][profile].get('failures') for profile in profiles))
