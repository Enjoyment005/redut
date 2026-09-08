"""Durable ProxyLine orders; no blind retries and no invented charged amounts."""
import hashlib

import country
import money
from providers.base import ProviderError
from providers.proxyline import ProxyLine, PERIODS, api_amount

CONTRACT = 'proxyline-list-v1'


def intent(body):
    """Bind a click to exact purchase parameters or an existing proxy and term."""
    if not isinstance(body, dict) or body.get('kind') not in ('buy', 'prolong'):
        raise money.SpendDenied('ProxyLine: неизвестная операция')
    kind = body['kind']
    period = body.get('period')
    if type(period) is not int or period not in PERIODS:
        raise money.SpendDenied('ProxyLine: выбери срок из доступных в каталоге')
    expected = {'contract': CONTRACT, 'period': period}
    if kind == 'buy':
        cc, proxy_type = body.get('country'), body.get('type', 'dedicated')
        version, count = body.get('version', 4), body.get('quantity', 1)
        ProxyLine.order_params(cc, proxy_type, version, count, period)
        expected.update(country=cc, type=proxy_type, version=version, quantity=count,
                        max_total=api_amount(body.get('max_total'), positive=True))
    else:
        uid = body.get('uid')
        if not isinstance(uid, str) or not uid.startswith('proxyline:'):
            raise money.SpendDenied('ProxyLine: нужен ID действующего прокси')
        ids = ProxyLine._ids_list([uid.removeprefix('proxyline:')])
        expected.update(uid=uid, ext_id=ids[0], days=period, pricing='provider_tariff')
    return kind, expected


def _receipt(op, response):
    """Keep only correlated IDs and expiry dates; credentials never enter the receipt."""
    if not isinstance(response, dict) or not isinstance(response.get('proxies'), list):
        raise money.SpendDenied('ProxyLine: ответ оплаты не подтверждён')
    req, items = op['request'], response['proxies']
    expected_count = req['quantity'] if op['kind'] == 'buy' else 1
    if len(items) != expected_count:
        raise money.SpendDenied('ProxyLine: число оплаченных прокси не совпало с запросом')
    out, seen = [], set()
    for row in items:
        if not isinstance(row, dict):
            raise money.SpendDenied('ProxyLine: неполный ответ оплаты')
        ident = ProxyLine._ids_list([row.get('ext_id')])[0]
        order_id = ProxyLine._ids_list([row.get('order_id')])[0]
        if ident in seen or money._date_value(row.get('date_end')) is None:
            raise money.SpendDenied('ProxyLine: ID или срок оплаты не подтверждён')
        seen.add(ident)
        if op['kind'] == 'buy':
            if (ident in req['existing_ids'] or row.get('country') != req['country']
                    or row.get('kind') != req['type'] or row.get('ip_version') != req['version']):
                raise money.SpendDenied('ProxyLine: ответ покупки относится к другим прокси')
        elif (ident != req['ext_id'] or order_id != req['order_id']
              or not money._expiry_advanced(req['date_before'], row.get('date_end'))):
            raise money.SpendDenied('ProxyLine: новый срок выбранного прокси не подтверждён')
        out.append({k: row[k] for k in ('ext_id', 'order_id', 'date_end', 'country', 'kind', 'ip_version')})
    if len({r['order_id'] for r in out}) != 1:
        raise money.SpendDenied('ProxyLine: ответ содержит разные заказы')
    return {'proxies': out}


def finish(pool, op, response, *, recovered=False):
    """Commit the documented successful operation, explicitly leaving its price unknown."""
    receipt = _receipt(op, response)
    rows, req = receipt['proxies'], op['request']
    uids = ['proxyline:' + p['ext_id'] for p in rows]
    result = dict(ok=True, provider='proxyline', kind=op['kind'], uids=uids,
                  uid=op.get('uid'), order_id=rows[0]['order_id'], period=req['period'],
                  days=req['period'], date_end=rows[0]['date_end'], currency='USD',
                  price=None, price_source='unreported', balance_after=None,
                  quoted_price=op['quote_price'] if op['kind'] == 'buy' else None,
                  recovered=recovered, spend_operation_id=op['id'])
    pool.complete_spend_operation(op['id'], [dict(provider='proxyline', op=op['kind'],
        uid=op.get('uid'), price=None, currency='USD', price_source='unreported',
        order_id=rows[0]['order_id'], descr='Сумма списания не возвращается API ProxyLine')],
        date_updates=[(uid, row['date_end']) for uid, row in zip(uids, rows)] if op['kind'] == 'prolong' else [],
        result=result, hold_order=('proxyline', 'static', rows[0]['order_id']) if op['kind'] == 'buy' else None)
    pool.log_event(op['kind'], actor=req.get('actor', 'user'), result='recovered' if recovered else 'ok',
                   detail='ProxyLine: %s, %s IP, %s дн; сумма в кабинете провайдера' % (
                       rows[0]['order_id'], len(rows), req['period']))
    return result


def recover(pool, op):
    """Recovery consumes a saved receipt only: this API has no documented idempotency key."""
    if (op.get('request') or {}).get('contract') != CONTRACT:
        raise money.SpendDenied('ProxyLine: старую операцию нужно сверить вручную')
    response = (op.get('result') or {}).get('provider_response')
    if not response:
        raise money.SpendDenied('ProxyLine: ответ на оплату потерян. Повторное списание заблокировано; '
                               'сверь операцию в кабинете провайдера')
    return finish(pool, op, response, recovered=True)


def _deliver(pool, provider, result, rid):
    """Refresh only bought IDs and balance; a read failure cannot erase a paid result."""
    result = money._deliver_result(pool, result, rid)
    if result['kind'] == 'buy':
        try:
            for row in provider.get_proxies([uid.removeprefix('proxyline:') for uid in result['uids']]):
                pool.upsert_proxy(row)  # The committed order hold supplies the initial off role.
        except Exception:
            result['warning'] = 'Покупка подтверждена; обнови пул для загрузки новых прокси'
    try:
        result['balance_after'] = api_amount(provider.balance().get('balance'))
        pool.set_setting('balance:proxyline', '%s USD' % result['balance_after'])
    except Exception:
        result['balance_after'] = None
    return result


def execute(pool, provider, cfg, body, *, actor='user', job_key=None, job_raw=None, before_submit=None):
    """Send one paid POST per durable request; retries may return a receipt, never repay."""
    kind, expected = intent(body)
    if (getattr(provider, 'name', None) != 'proxyline'
            or not isinstance(getattr(provider, 'api_key', None), str)
            or not callable(getattr(provider, 'get_proxies', None))):
        raise money.SpendDenied('ProxyLine: неверный адаптер')
    expected['credential_identity'] = hashlib.sha256(provider.api_key.encode('utf-8')).hexdigest()
    if not body.get('request_id'):
        raise money.SpendDenied('ProxyLine: нужен request_id')
    rid, key = money._request_identity(body['request_id'])
    with money._spend_lock(pool):
        op = pool.get_spend_operation_by_idempotency(key)
        if op:
            money._validate_bound_request(op, kind, 'proxyline', expected, uid=expected.get('uid'))
            if op['phase'] in ('committed', 'acknowledged'):
                return _deliver(pool, provider, money._stored_result(op), rid)
            if op['phase'] == 'failed':
                raise money.SpendDenied('ProxyLine: запрос завершён отказом; можно повторить действие', replace_request=True)
            if op['phase'] == 'submitted':
                return _deliver(pool, provider, recover(pool, op), rid)
        else:
            money._guard_new_request(pool, {'proxyline': provider}, actor=actor)
        try:
            if ((cfg or {}).get('_config_meta') or {}).get('safe_mode'):
                raise money.SpendDenied('ProxyLine: конфигурация в безопасном режиме')
            money._safe_spent_today(pool, 'USD', allow_unreported=True)
            if actor != 'user':
                if not job_key or not job_raw or pool.get_setting(job_key) != job_raw:
                    raise money.SpendDenied('ProxyLine: автоматический запрос изменился или отключён')
                if kind == 'buy':
                    from auto_purchase import check_buy
                    check_buy(cfg, pool, expected['country'])
                elif (not ((cfg or {}).get('auto_prolong') or {}).get('enabled', True)
                      or pool.prolonged_today(expected['uid'])):
                    raise money.SpendDenied('ProxyLine: автопродление выключено или уже выполнено сегодня')
            balance = api_amount(provider.balance().get('balance'))
            quote_price = 0
            if kind == 'buy':
                if country.is_blocked(expected['country'], cfg):
                    raise money.SpendDenied('ProxyLine: страна запрещена')
                if provider.stock(expected['country'], expected['type'], expected['version']) < expected['quantity']:
                    raise money.SpendDenied('ProxyLine: недостаточно прокси в продаже')
                q = provider.quote(expected['country'], expected['type'], expected['version'],
                                   expected['quantity'], expected['period'])
                quote_price = api_amount(q.get('amount'), positive=True)
                if q.get('currency') != 'USD' or quote_price > expected['max_total']:
                    raise money.SpendDenied('ProxyLine: цена изменилась; обнови предложение')
                if balance < quote_price:
                    raise money.SpendDenied('ProxyLine: недостаточно средств')
                extra = {'existing_ids': sorted(p['ext_id'] for p in provider.list())}
            else:
                row = provider.get_proxies([expected['ext_id']])[0]
                if money._date_value(row.get('date_end')) is None:
                    raise money.SpendDenied('ProxyLine: исходный срок не подтверждён')
                extra = {'date_before': row['date_end'], 'order_id': ProxyLine._ids_list([row.get('order_id')])[0]}
                if op and any(op['request'].get(k) != v for k, v in extra.items()):
                    raise money.SpendDenied('ProxyLine: срок или заказ изменился до отправки')
                if actor != 'user':
                    import probe
                    left = probe.days_left(row['date_end'])
                    if left is None or left > float(((cfg or {}).get('auto_prolong') or {}).get('days_before', 3)):
                        raise money.SpendDenied('ProxyLine: по сроку провайдера продлевать ещё рано')
            if op is None:
                expected.update(extra, actor=actor)
                op, created = pool.begin_spend_operation(kind, 'proxyline', expected, key,
                    uid=expected.get('uid'), quote_price=quote_price, currency='USD', balance_before=balance)
                if not created:
                    raise money.SpendDenied('Другая денежная операция уже выполняется')
                op = pool.get_spend_operation(op['id'])
        except (money.SpendDenied, ProviderError) as error:
            if op and op['phase'] == 'planned':
                pool.transition_spend_operation(op['id'], 'failed', str(error))
            error.replace_request = True
            raise
        def on_submit():
            if actor != 'user':
                if not callable(before_submit):
                    raise money.SpendDenied('ProxyLine: нужна проверка боевого канала перед продлением')
                before_submit()
                if pool.get_setting(job_key) != job_raw:
                    raise money.SpendDenied('ProxyLine: автоматический запрос изменился')
            pool.transition_spend_operation(op['id'], 'submitted')
        try:
            if kind == 'buy':
                response = provider.buy(expected['quantity'], expected['period'], expected['country'],
                                        version=expected['version'], kind=expected['type'], on_submit=on_submit)
            else:
                response = provider.prolong([expected['ext_id']], expected['period'], on_submit=on_submit)
        except (money.SpendDenied, ProviderError) as error:
            phase = pool.get_spend_operation(op['id'])['phase']
            if phase == 'planned' or getattr(error, 'definitive', False) or getattr(error, 'unsent', False):
                pool.transition_spend_operation(op['id'], 'failed', str(error))
                error.replace_request = True
            raise
        if pool.get_spend_operation(op['id'])['phase'] != 'submitted':
            pool.transition_spend_operation(op['id'], 'submitted')
            raise money.SpendDenied('ProxyLine: адаптер не подтвердил границу отправки')
        receipt = _receipt(op, response)
        pool.record_spend_response(op['id'], {'provider_response': receipt})
        return _deliver(pool, provider, finish(pool, op, receipt), rid)


def pending(pool):
    """Return a sanitized original request so reload/new tabs can recover its result."""
    for op in pool.pending_spend_operations() + pool.unacknowledged_spend_operations():
        req = op.get('request') or {}
        if op['provider'] != 'proxyline' or req.get('contract') != CONTRACT:
            continue
        fields = ('country', 'type', 'version', 'quantity', 'max_total') if op['kind'] == 'buy' else ('uid',)
        return dict({k: req[k] for k in fields}, kind=op['kind'], period=req['period'],
                    request_id=op['idempotency_key'].removeprefix('request-v1:'))
    return None
