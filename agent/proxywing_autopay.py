"""Service-scoped ProxyWing settings, not invoice payment or paid extension."""
import datetime
import hashlib
import json
import re

import apply
import money
from providers.proxywing import order_identity, identifier, family_name, billing_date
from providers.base import ProviderError

STATE_KEY = 'proxywing_autopay:v1'
REASONS = {
    'scope-denied': 'Автоплатёж разрешён только для услуги с одним боевым прокси и одним заказом; оплачивать запасные вместе с ним запрещено',
    'provider-missing': 'Адаптер ProxyWing с исходным ключом недоступен',
    'credential-rotated': 'Ключ ProxyWing изменился: прежний автоплатёж требует сверки со старым аккаунтом',
    'state-invalid': 'Состояние владения автоплатежом повреждено или неизвестно; требуется ручная сверка',
    'current-changed': 'Боевой канал, здоровье или ключ изменились; автоплатёж не включён',
    'current-proxy-mismatch': 'Единственный прокси услуги не совпадает с боевым; автоплатёж запрещён',
    'spend-pending': 'Незавершённая или неизвестная денежная операция требует сверки; автоплатёж не включён',
    'payment-pending': 'Срок оплаты услуги наступил, перенос даты не подтверждён. Включение настройки не оплачивает текущий счёт немедленно; нужна проверка кабинета и баланса провайдера',
    'ineligible': 'Новые автоплатежи запрещены: режим, срок или боевой канал не подтверждены',
    'unverified': 'Настройка или отключение автоплатежа не подтверждены; новая услуга не включена',
    'state-unavailable': 'Безопасное состояние или блокировка автоплатежа недоступны; требуется повторная сверка',
}



class _Blocked(Exception):
    """Only locally authored safe reasons may leave the domain boundary."""
    def __init__(self, code, reason):
        self.code = code
        self.reason = reason


def _credential(provider):
    key = getattr(provider, 'api_key', None)
    if not isinstance(key, str) or not key or getattr(provider, 'name', None) != 'proxywing':
        raise _Blocked('provider-missing', 'Адаптер ProxyWing с исходным ключом недоступен')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def _check_credentials(provider, state):
    if state['owned'] and any(r['credential_identity'] != _credential(provider) for r in state['owned']):
        raise _Blocked('credential-rotated', 'Ключ ProxyWing изменился: прежний автоплатёж требует сверки со старым аккаунтом')


def status(pool) -> dict:
    """Return local ownership and last result without credentials or network I/O."""
    try:
        state = _load(pool)
        return dict(state['last'] or {'ok': True, 'mode': 'off', 'managed': False},
                    owned=[{k: row[k] for k in ('family', 'order_id', 'service_id', 'phase', 'next_due_date')}
                           for row in state['owned']])
    except Exception:
        return dict(ok=False, mode='blocked', managed=True, pending_cleanup=True,
                    owned=[], reason_code='state-invalid',
                    reason='Состояние владения автоплатежом повреждено или неизвестно; требуется ручная сверка')


def _mode(cfg):
    ap = cfg.get('auto_prolong') or {}
    requested = ap.get('proxywing_provider_auto_renew', False) is True
    return dict(mode='provider-auto-renew' if requested else 'off', managed=requested)


def _fresh_policy(cfg):
    """Read persisted authorization under the apply lock, never trust an old cron snapshot."""
    if not cfg.get('_source'):
        return cfg
    import config_schema
    import config_store
    try:
        fresh = config_schema.normalize(config_store.read(cfg), source=cfg['_source'])
    except Exception:
        raise _Blocked('state-unavailable', REASONS['state-unavailable']) from None
    # Runtime paths are owned by this invocation; billing authority is the fresh disk policy.
    return dict(cfg, auto_prolong=fresh['auto_prolong'], _config_meta=fresh['_config_meta'])


def _target(cfg, pool):
    """Find exactly one healthy full connection, never merely the current IP."""
    ap = cfg.get('auto_prolong') or {}
    if (ap.get('proxywing_provider_auto_renew', False) is not True
            or ap.get('enabled', True) is not True
            or type(ap.get('proxywing_months', 1)) is not int
            or ap.get('proxywing_months', 1) != 1
            or (cfg.get('_config_meta') or {}).get('safe_mode')):
        return None
    try:
        sb = apply.load_json(cfg['singbox_config'])
    except (OSError, ValueError, KeyError):
        return None
    if not isinstance(sb, dict) or not isinstance(sb.get('outbounds'), list):
        return None
    if any(not isinstance(o, dict) for o in sb['outbounds']):
        return None
    outs = [o for o in sb.get('outbounds', []) if o.get('tag') == 'socks-out']
    if len(outs) != 1:
        return None
    ob = outs[0]
    port_field = {'socks': 'port_socks5', 'http': 'port_http'}.get(ob.get('type'))
    if port_field is None or type(ob.get('server_port')) is not int:
        return None
    rows = [r for r in pool.list() if r['host'] == ob.get('server')
            and r.get(port_field) == ob['server_port']
            and (r.get('user') or '') == (ob.get('username') or '')
            and (r.get('password') or '') == (ob.get('password') or '')]
    if (len(rows) != 1 or rows[0].get('provider') != 'proxywing'
            or type(rows[0].get('probe_ok')) is not int or rows[0]['probe_ok'] != 1):
        return None
    return rows[0]


def _unique_json_object(pairs):
    """Duplicate JSON fields can hide ownership records; treat them as corruption."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate state field')
    return result


def _load(pool):
    raw = pool.get_setting(STATE_KEY)
    if raw is None:
        return {'version': 1, 'owned': [], 'last': {}, 'observation': None}
    try:
        state = json.loads(raw, object_pairs_hook=_unique_json_object)
        if (not isinstance(state, dict) or set(state) != {'version', 'owned', 'last', 'observation'}
                or type(state['version']) is not int or state['version'] != 1
                or not isinstance(state['owned'], list) or not isinstance(state['last'], dict)):
            raise ValueError()
        fields = {'family', 'order_id', 'service_id', 'credential_identity', 'phase', 'next_due_date', 'submitted'}
        identities = set()
        for row in state['owned']:
            if not isinstance(row, dict) or set(row) != fields:
                raise ValueError()
            family_name(row['family'])
            identifier(row['order_id'])
            identifier(row['service_id'])
            billing_date(row['next_due_date'])
            if (not isinstance(row['credential_identity'], str)
                    or not re.fullmatch('[0-9a-f]{64}', row['credential_identity'])
                    or row['phase'] not in ('enabling', 'owned', 'disabling')
                    or type(row['submitted']) is not bool
                    or (row['phase'] != 'enabling' and not row['submitted'])):
                raise ValueError()
            identity = (row['credential_identity'], row['service_id'])
            if identity in identities:
                raise ValueError()
            identities.add(identity)
        observation = state['observation']
        if observation is not None:
            if not isinstance(observation, dict) or set(observation) != fields - {'phase', 'submitted'}:
                raise ValueError()
            family_name(observation['family'])
            identifier(observation['order_id'])
            identifier(observation['service_id'])
            billing_date(observation['next_due_date'])
            if not re.fullmatch('[0-9a-f]{64}', observation['credential_identity']):
                raise ValueError()
        allowed = {'ok', 'mode', 'managed', 'pending_cleanup', 'reason', 'reason_code',
                   'service_id', 'order_id', 'ownership', 'payment_pending', 'next_due_date'}
        last = state['last']
        if set(last) - allowed:
            raise ValueError()
        if 'reason' in last and last['reason'] not in REASONS.values():
            raise ValueError()
        if 'reason_code' in last and last['reason_code'] not in REASONS:
            raise ValueError()
        for key in ('ok', 'managed', 'pending_cleanup', 'payment_pending'):
            if key in last and type(last[key]) is not bool:
                raise ValueError()
        if 'mode' in last and last['mode'] not in ('off', 'provider-auto-renew'):
            raise ValueError()
        for key in ('service_id', 'order_id'):
            if key in last:
                identifier(last[key])
        if 'ownership' in last and last['ownership'] not in ('owned', 'external-enabled'):
            raise ValueError()
        if 'next_due_date' in last:
            billing_date(last['next_due_date'])
        return state
    except Exception:
        raise _Blocked('state-invalid', 'Состояние владения автоплатежом повреждено или неизвестно; требуется ручная сверка') from None


def _save(pool, state):
    pool.set_setting(STATE_KEY, json.dumps(state))


def _check_spends(pool, credential):
    """Read all unfinished operations, without a pagination hole or any execution."""
    rows = pool.conn.execute("SELECT * FROM spend_operation WHERE phase NOT IN ('failed','acknowledged')").fetchall()
    for raw in rows:
        op = pool._spend_item(raw)
        request = op.get('request')
        known_phase = op.get('phase') in ('planned', 'submitted', 'committed')
        bound = request.get('credential_identity') if isinstance(request, dict) else None
        if (not known_phase or not isinstance(request, dict)
                or op.get('provider') not in ('proxywing', 'proxy6', 'proxyline')
                or (op['provider'] == 'proxywing' and
                    (not isinstance(bound, str) or not re.fullmatch('[0-9a-f]{64}', bound) or bound == credential))):
            raise _Blocked('spend-pending', 'Незавершённая или неизвестная денежная операция требует сверки; автоплатёж не включён')


def _set_verified(provider, service_id, enabled, on_submit=None, on_unsent=None):
    """Observe ambiguous replies; proven non-submission cannot establish ownership."""
    try:
        provider.set_auto_renew(service_id, enabled, on_submit=on_submit)
    except _Blocked:
        raise
    except ProviderError as error:
        if error.unsent:
            if on_unsent is not None:
                on_unsent()
            raise
        # A lost reply may follow a successful mutation; only GET can resolve it.
    except Exception:
        # The setting may already have changed. Do not log provider exceptions,
        # which can contain credentials, or resend before observing its state.
        pass
    if provider.get_auto_renew(service_id)['enabled'] is not enabled:
        raise money.SpendDenied('Настройка автоплатежа не подтверждена свежим GET')


def _cleanup(pool, provider, state, keep=None):
    """Disable prior owned services and retain records until a GET proves false."""
    for record in list(state['owned']):
        _check_credentials(provider, state)
        if (keep and record['phase'] != 'disabling'
                and all(record[key] == keep[key] for key in ('family', 'order_id', 'service_id'))):
            continue
        if not record['submitted']:
            state['owned'].remove(record)
            _save(pool, state)
            continue
        service_id = record['service_id']
        observed = provider.get_auto_renew(service_id)
        _check_credentials(provider, state)
        if observed['enabled']:
            record['phase'] = 'disabling'
            _save(pool, state)
            def on_submit():
                _check_credentials(provider, state)
            _set_verified(provider, service_id, False, on_submit=on_submit)
            _check_credentials(provider, state)
        state['owned'].remove(record)
        _save(pool, state)


def _report(pool, result, previous, log, actor, release):
    """Report settings and overdue observations, never a fabricated payment success."""
    if result.get('payment_pending'):
        outcome = 'payment-pending'
    elif not result['ok']:
        outcome = 'deferred'
    elif release:
        outcome = 'released'
    else:
        outcome = result.get('ownership', 'inactive')
    reason = result.get('reason') or 'Настройка ProxyWing проверена; факт оплаты не установлен'
    try:
        if outcome in ('payment-pending', 'deferred'):
            log(reason)
        if result != previous:
            pool.log_event('provider-auto-renew', actor=actor, result=outcome, detail=reason)
    except Exception:
        # Observability failure must not change a verified setting or block VPN.
        pass


def _run(cfg, providers, pool, log, actor, locked, release):
    """Always acquire the network lock before the single-writer spend lock."""
    try:
        with apply._maybe_lock(cfg, locked):
            with money._spend_lock(pool):
                state = _load(pool)
                previous = dict(state['last'])
                try:
                    _check_credentials(providers.get('proxywing'), state)
                    if release:
                        _cleanup(pool, providers.get('proxywing'), state)
                        result = dict(ok=True, **_mode(cfg))
                    else:
                        cfg = _fresh_policy(cfg)
                        result = _reconcile(cfg, providers, pool, state, actor)
                except _Blocked as error:
                    result = dict(ok=False, pending_cleanup=bool(state['owned']), **_mode(cfg),
                                  reason_code=error.code, reason=error.reason)
                except ProviderError as error:
                    code = 'scope-denied' if error.code == 'auto-renew-scope' else 'unverified'
                    result = dict(ok=False, pending_cleanup=bool(state['owned']), **_mode(cfg),
                                  reason_code=code, reason=REASONS[code])
                except Exception:
                    result = dict(ok=False, pending_cleanup=bool(state['owned']), **_mode(cfg),
                                  reason_code='unverified', reason=REASONS['unverified'])
                for key in ('service_id', 'order_id'):
                    if key not in result and key in state['last']:
                        result[key] = state['last'][key]
                state['last'] = result
                _save(pool, state)
                _report(pool, result, previous, log, actor, release)
                return result
    except Exception:
        return dict(ok=False, pending_cleanup=True, **_mode(cfg),
                    reason=REASONS['state-unavailable'])


def release_owned(cfg, providers, pool, *, log=print, actor='auto', _locked=False) -> dict:
    """Disable only owned switches, GET-verify each, and return blockers without throwing.

    Used before a channel switch. A failed cleanup retains its durable record and
    must not prevent emergency VPN rotation. Never enables a replacement service.
    """
    return _run(cfg, providers, pool, log, actor, _locked, True)


def reconcile(cfg, providers, pool, *, log=print, actor='auto', _locked=False) -> dict:
    """Manage only one healthy current service, never invoice payments or extend.

    Requires exact boolean opt-in, global auto-prolong enabled, no safe mode,
    local proxywing_months == 1 and an active monthly singleton provider service.
    ``managed`` means provider-managed mode is requested, NOT that anything was
    paid. ``ok`` proves the setting/readback or cleanup, not payment success.
    ``_locked=True`` means the caller already holds the network apply lock.
    """
    return _run(cfg, providers, pool, log, actor, _locked, False)


def _observe(pool, provider, state, identity, actor):
    """A changed billing deadline is an observation, never an invented paid invoice."""
    fresh = {key: identity[key] for key in ('family', 'order_id', 'service_id', 'next_due_date')}
    fresh['credential_identity'] = _credential(provider)
    before = state['observation']
    same = before and all(before[k] == fresh[k] for k in fresh if k != 'next_due_date')
    if same and billing_date(fresh['next_due_date']) > billing_date(before['next_due_date']):
        pool.log_event('proxywing-auto-renew-observed', actor=actor, result='due-date-advanced',
                       detail='ProxyWing service %s: billing date %s -> %s; payment amount and invoice unknown' %
                       (identity['service_id'], before['next_due_date'], fresh['next_due_date']))
    state['observation'] = fresh
    _save(pool, state)
    pending = billing_date(fresh['next_due_date']) <= datetime.datetime.now(datetime.timezone.utc)
    result = dict(next_due_date=fresh['next_due_date'], payment_pending=pending)
    if pending:
        result.update(reason_code='payment-pending',
                      reason='Срок оплаты услуги наступил, перенос даты не подтверждён. Включение настройки не оплачивает текущий счёт немедленно; нужна проверка кабинета и баланса провайдера')
    return result


def _reconcile(cfg, providers, pool, state, actor):
    provider = providers.get('proxywing')
    row = _target(cfg, pool)
    if row is None:
        _cleanup(pool, provider, state)
        result = dict(ok=True, reason='Новые автоплатежи запрещены: режим, срок или боевой канал не подтверждены',
                      **_mode(cfg))
        state['last'] = result
        _save(pool, state)
        return result
    credential = _credential(provider)
    family, order_id = order_identity(row['ext_id'])
    state['last'] = dict(order_id=order_id, **_mode(cfg))
    try:
        identity = provider.order_service(family, order_id)
    except Exception:
        _cleanup(pool, provider, state)
        raise
    if _credential(provider) != credential:
        raise _Blocked('credential-rotated', REASONS['credential-rotated'])
    if identity['proxy_id'] != row['ext_id'].split('|')[2]:
        _cleanup(pool, provider, state)
        raise _Blocked('current-proxy-mismatch', 'Единственный прокси услуги не совпадает с боевым; автоплатёж запрещён')
    service_id = identity['service_id']
    state['last']['service_id'] = service_id
    observation = _observe(pool, provider, state, identity, actor)
    _cleanup(pool, provider, state, keep=identity)
    record = next((r for r in state['owned'] if r['service_id'] == service_id), None)
    observed = provider.get_auto_renew(service_id)
    if _credential(provider) != credential:
        raise _Blocked('credential-rotated', REASONS['credential-rotated'])
    if observed['enabled'] is True:
        if record and not record['submitted']:
            state['owned'].remove(record)
            record = None
        ownership = 'owned' if record else 'external-enabled'
        if record:
            record['phase'] = 'owned'
        result = dict(ok=True, mode='provider-auto-renew', managed=True,
                      service_id=service_id, order_id=order_id, ownership=ownership, **observation)
        state['last'] = result
        _save(pool, state)
        return result
    fresh = provider.order_service(family, order_id)
    if fresh != identity or _credential(provider) != credential:
        raise _Blocked('current-changed', REASONS['current-changed'])
    _check_spends(pool, credential)
    if record is None:
        record = dict(family=family, order_id=order_id, service_id=service_id,
                      credential_identity=credential,
                      phase='enabling', next_due_date=identity['next_due_date'], submitted=False)
        state['owned'].append(record)
    record['phase'] = 'enabling'
    _save(pool, state)
    previously_submitted = record['submitted']
    def on_unsent():
        # Restore only this attempt's boundary, never discard prior proven ownership.
        record['submitted'] = previously_submitted
        _save(pool, state)
    def on_submit():
        _check_spends(pool, _credential(provider))
        if _target(_fresh_policy(cfg), pool) != row or _credential(provider) != record['credential_identity']:
            raise _Blocked('current-changed', 'Боевой канал, здоровье или ключ изменились; автоплатёж не включён')
        previous = record['submitted']
        record['submitted'] = True
        try:
            _save(pool, state)
        except Exception:
            record['submitted'] = previous
            raise _Blocked('state-unavailable', REASONS['state-unavailable']) from None
    _set_verified(provider, service_id, True, on_submit=on_submit, on_unsent=on_unsent)
    result = dict(ok=True, mode='provider-auto-renew', managed=True,
                  service_id=service_id, order_id=order_id, ownership='owned', **observation)
    record['phase'] = 'owned'
    state['last'] = result
    _save(pool, state)
    return result
