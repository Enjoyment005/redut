"""Explicit automatic purchase selection across the three provider contracts."""
import hashlib
import json

import country
import money
import proxyline_orders
import proxywing_orders
from providers.base import ProviderError
from providers.proxyline import PERIODS

JOB_KEYS = ('money_request:reserve', 'money_request:replenish')


def policy_snapshot(cfg, pool):
    """Bind a purchase to the selection revision and complete current endpoint."""
    import states
    sb = states.apply_mod.load_json(cfg['singbox_config'])
    outbound = [o for o in sb.get('outbounds', []) if o.get('tag') == 'socks-out']
    digest = hashlib.sha256(json.dumps(outbound, sort_keys=True).encode()).hexdigest()
    return {'selection_revision': pool.get_setting('desired_selection_revision'),
            'current_endpoint': digest, 'strategy': country.strategy(cfg)}


def check_buy(cfg, pool, cc):
    """Common automatic controls; provider-specific currency checks remain separate."""
    lim = money.limits(cfg)
    if ((cfg.get('_config_meta') or {}).get('safe_mode') or not lim['buy_enabled']):
        raise money.SpendDenied('автоматические покупки выключены')
    if not country.auto_allowed(cc, True, cfg):
        raise money.SpendDenied('страна не разрешена выбранной стратегией покупки')
    if pool.buys_today() >= lim['max_buys_per_day']:
        raise money.SpendDenied('достигнут суточный предел автоматических покупок')


def activation_allowed(cfg, pool, job):
    """A paid receipt can be recovered after policy changes, but cannot override them."""
    import states
    if states.selection_state(pool, cfg)['mode'] == states.SELECTION_MANUAL:
        return False
    snapshot = policy_snapshot(cfg, pool)
    return not any(k in job['intent'] and job['intent'][k] != v for k, v in snapshot.items())


def offers(cfg, providers, pool, log):
    """Rank actual sale countries using reputation and each provider's own history."""
    import states
    lim = money.limits(cfg)
    version, period = int(lim['buy_version']), int(lim['buy_period_days'])
    current = states._current_proxy_uid(pool, states.apply_mod.load_json(cfg['singbox_config']))
    preferred = current.split(':', 1)[0] if current else None
    preference = {c: i for i, c in enumerate(country.preference_order(cfg))}
    candidates, errors = [], []
    for name in ('proxy6', 'proxyline', 'proxywing'):
        provider = providers.get(name)
        if provider is None:
            continue
        try:
            if name == 'proxy6':
                rows = [dict(country=cc, period=period, version=version, quantity=1)
                        for cc in provider.getcountry(version)]
            elif name == 'proxyline':
                term = next((p for p in PERIODS if p >= period), None)
                if term is None:
                    raise money.SpendDenied('ProxyLine: нет подходящего срока покупки')
                rows = [dict(country=r['code'], period=term, version=6 if version == 6 else 4,
                             type='shared' if version == 3 else 'dedicated', quantity=1)
                        for r in provider.countries()]
            else:
                rows = []
                for family in ('datacenter', 'isp'):
                    try:
                        rows.extend(dict(p, months=1, max_total=p['price_monthly'])
                                    for p in provider.catalog(family)
                                    if type(p.get('quantity')) is int and p['quantity'] > 0)
                    except (ProviderError, money.SpendDenied) as error:
                        errors.append('%s/%s: %s' % (name, family, error))
            allowed = set(money.buy_candidates(cfg, [r['country'] for r in rows], pool, name))
            for row in rows:
                cc = row['country']
                if cc not in allowed:
                    continue
                rank = country.rating(cc, True, cfg) + money.stability_bonus(pool.stability_get(name, cc), cfg)
                key = (-rank, preference.get(cc, len(preference)), cc,
                       row['quantity'], name != preferred, name,
                       row.get('price_monthly', 0), row.get('family', ''), row.get('product_id', ''))
                candidates.append((key, dict(row, provider=name, kind='buy')))
        except (ProviderError, money.SpendDenied) as error:
            errors.append('%s: %s' % (name, error))
    for _, body in sorted(candidates, key=lambda item: item[0]):
        name, cc = body['provider'], body['country']
        provider = providers[name]
        try:
            check_buy(cfg, pool, cc)
            if name == 'proxy6':
                if provider.getcount(cc, body['version']) < 1:
                    continue
                money.preflight_buy(pool, provider, cfg, country=cc, period=body['period'],
                                    version=body['version'])
            elif name == 'proxyline':
                if provider.stock(cc, body['type'], body['version']) < 1:
                    continue
                quote = provider.quote(cc, body['type'], body['version'], 1, body['period'])
                balance = provider.balance()
                price = money._num(quote.get('amount'))
                funds = money._num(balance.get('balance'))
                if (price is None or price <= 0 or funds is None or funds < price
                        or quote.get('currency') != 'USD' or balance.get('currency') != 'USD'):
                    raise money.SpendDenied('ProxyLine: цена или доступный баланс не подтверждены')
                body['max_total'] = price
            else:
                balance = provider.balance()
                funds = money._num(balance.get('balance'))
                if balance.get('currency') != 'USD' or funds is None or funds < body['max_total']:
                    raise money.SpendDenied('ProxyWing: недостаточно средств USD')
            return body
        except (ProviderError, money.SpendDenied) as error:
            errors.append('%s: %s' % (name, error))
    reason = 'нет доступного предложения по выбранной стратегии'
    if errors:
        reason += '; ' + '; '.join(dict.fromkeys(errors))
    raise money.SpendDenied(reason)


def purchase(cfg, providers, pool, key, *, actor='auto', min_reserve=1, log=print):
    """Resume one fixed intent, or select an offer only when no paid result is pending."""
    import states
    job, raw = states._load_money_job(pool, key)
    if job is None:
        snapshot = policy_snapshot(cfg, pool)
        body = offers(cfg, providers, pool, log)
        body.update(snapshot)
        with money._spend_lock(pool):
            if any(pool.get_setting(other) for other in JOB_KEYS if other != key):
                raise money.SpendDenied('другая автоматическая покупка ещё проверяется')
            job, raw = states._begin_money_job(pool, key, body)
    body = dict(job['intent'], request_id=job['request_id'])
    name = body.get('provider', 'proxy6')  # Upgrade already persisted PROXY6 jobs.
    provider = providers.get(name)
    if provider is None:
        raise money.SpendDenied('нет ключа провайдера сохранённой покупки: ' + name)

    def before_submit():
        check_buy(cfg, pool, body['country'])
        if pool.get_setting(key) != raw:
            raise money.SpendDenied('автоматический запрос изменился')
        if any(pool.get_setting(other) for other in JOB_KEYS if other != key):
            raise money.SpendDenied('другая автоматическая покупка ещё проверяется')
        if states.selection_state(pool, cfg)['mode'] == states.SELECTION_MANUAL:
            raise money.SpendDenied('ручной канал закреплён; автоматическая покупка отменена')
        snapshot = policy_snapshot(cfg, pool)
        if any(k in body and body[k] != v for k, v in snapshot.items()):
            raise money.SpendDenied('канал или стратегия изменились до оплаты')
        current = states.apply_mod.current_upstream(states.apply_mod.load_json(cfg['singbox_config']))
        needed = min_reserve if key.endswith(':reserve') else 1
        if len(states.selectable_candidates(pool, cfg, current, providers)) >= needed:
            raise money.SpendDenied('в пуле появились пригодные прокси; покупка не нужна')

    try:
        op = money.bound_spend_request(pool, job['request_id'])
        if op is None or op['phase'] == 'planned':
            before_submit()
        if name == 'proxy6':
            result = money.plan_and_buy(pool, provider, cfg, country=body['country'],
                period=body['period'], version=body['version'], count=1, actor=actor,
                request_id=job['request_id'], before_submit=before_submit)
        else:
            execute = proxyline_orders.execute if name == 'proxyline' else proxywing_orders.execute
            result = execute(pool, provider, cfg, body, actor='auto', job_key=key,
                             job_raw=raw, before_submit=before_submit)
        result = dict(result, country=body['country'], period=body.get('period'),
                      balance_after=result.get('balance_after'))
        if name == 'proxy6':
            for row in result['proxies']:
                pool.upsert_proxy(row)
        if name != 'proxy6':
            if name == 'proxyline':
                ids = [uid.removeprefix('proxyline:') for uid in result['uids']]
                bought = provider.get_proxies(ids)
            else:
                prefix = '%s|%s|' % (body['family'], result['order_id'])
                bought = [r for r in provider.list() if r['ext_id'].startswith(prefix)]
                # ProxyWing sells calendar months; do not represent one month as 30 days.
                result['period'] = '1 мес'
            if not bought or len(bought) != body.get('quantity', 1):
                raise money.SpendDenied('покупка оплачена, ожидается полный список новых прокси')
            for row in bought:
                pool.upsert_proxy(row)
            result['proxies'] = bought
        return result, job, raw
    except Exception as error:
        # Unsent intent can be retired under the same mutex used to bind/pay it.
        # Submitted, committed and acknowledged jobs retain their exact identity.
        try:
            with money._spend_lock(pool):
                op = money.bound_spend_request(pool, job['request_id'])
                if op and op['phase'] == 'planned':
                    pool.transition_spend_operation(op['id'], 'failed', str(error))
                    op = pool.get_spend_operation(op['id'])
                if op is None or op['phase'] == 'failed':
                    pool.compare_and_delete_setting(key, raw)
        except money.SpendDenied:
            pass
        raise
