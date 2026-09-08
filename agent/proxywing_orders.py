"""Explicit monthly ProxyWing purchases with USD budgets and durable receipts."""
import hashlib
import re

import country
import money
from providers.proxywing import amount, family_name, identifier, order_identity, MONTHS
from providers.base import ProviderError

CONTRACT = 'proxywing-monthly-v1'
BUDGET_DEFAULTS = {'enabled': False, 'max_price_per_buy': 0.0,
                   'max_spend_per_day': 0.0, 'min_balance_reserve': 0.0}


def validate_budget(value):
    """Require an explicit independent USD budget, never reuse numeric RUB limits."""
    if not isinstance(value, dict) or type(value.get('enabled')) is not bool:
        raise money.SpendDenied('ProxyWing: задай отдельный бюджет в USD')
    out = {'enabled': value['enabled']}
    for key in BUDGET_DEFAULTS:
        if key == 'enabled':
            continue
        number = money._num(value.get(key))
        if isinstance(value.get(key), bool) or number is None or not 0 <= number <= 1e9:
            raise money.SpendDenied('ProxyWing: некорректный лимит USD')
        out[key] = number
    return out


def budget(cfg):
    return validate_budget((cfg or {}).get('proxywing_money', BUDGET_DEFAULTS))


def intent(body):
    """Bind the caller's exact family, product/order, term and price ceiling."""
    kind = body.get('kind')
    family = family_name(body.get('family'))
    if kind not in ('buy', 'prolong'):
        raise money.SpendDenied('ProxyWing: неизвестная операция')
    expected = {'contract': CONTRACT, 'family': family, 'max_total': amount(body.get('max_total'))}
    if kind == 'buy':
        if body.get('months', 1) != 1 or isinstance(body.get('months', 1), bool):
            raise money.SpendDenied('ProxyWing: покупка на 1 месяц')
        cc = country.norm(body.get('country'))
        if not re.fullmatch('[a-z]{2}', cc):
            raise money.SpendDenied('ProxyWing: укажи страну выбранного товара')
        expected.update(product_id=identifier(body.get('product_id')), months=1, country=cc)
    else:
        months = body.get('months')
        if type(months) is not int or months not in MONTHS:
            raise money.SpendDenied('ProxyWing: срок — 1, 3, 6 или 12 месяцев')
        expected.update(order_id=identifier(body.get('order_id')), months=months)
    return kind, expected


def quote(provider, cfg, kind, request):
    """Read the current exact monthly/package or whole-order renewal price."""
    family = family_name(request.get('family'))
    if kind == 'buy':
        items = [p for p in provider.catalog(family) if p['product_id'] == request.get('product_id')]
        if len(items) != 1:
            raise money.SpendDenied('ProxyWing: товар отсутствует или неоднозначен')
        product = items[0]
        cc = product['country'] or request.get('country')
        if country.is_blocked(cc, cfg):
            raise money.SpendDenied('ProxyWing: страна товара запрещена')
        if product['country'] and request.get('country') and product['country'] != request['country']:
            raise money.SpendDenied('ProxyWing: выбранная страна не совпадает с товаром')
        result = dict(product, total=product['price_monthly'], months=1)
    else:
        terms = provider.renewal_options(family, identifier(request.get('order_id')))
        matches = [x for x in terms['options'] if x['months'] == request.get('months')]
        if len(matches) != 1:
            raise money.SpendDenied('ProxyWing: этот срок продления недоступен')
        result = dict(matches[0], order_id=terms['order_id'], next_due_date=terms['next_due_date'])
    bal = provider.balance()
    value = money._num(bal.get('balance'))
    if bal.get('currency') != 'USD' or value is None or value < 0:
        raise money.SpendDenied('ProxyWing: баланс USD не подтверждён')
    return dict(result, balance=value, currency='USD', family=family)


def _gates(pool, cfg, kind, request, price, balance, *, reserved=False):
    limits = budget(cfg)
    if not limits['enabled'] or not money.limits(cfg)['buy_enabled']:
        raise money.SpendDenied('ProxyWing: траты выключены; проверь общий тумблер и отдельный бюджет USD')
    if price > request['max_total'] or price > limits['max_price_per_buy']:
        raise money.SpendDenied('ProxyWing: цена выше подтверждённой суммы или лимита операции USD')
    if money._safe_spent_today(pool, 'USD') + price > limits['max_spend_per_day']:
        raise money.SpendDenied('ProxyWing: исчерпан дневной бюджет USD')
    if not reserved and balance - price < limits['min_balance_reserve']:
        raise money.SpendDenied('ProxyWing: недостаточно баланса с учётом резерва USD')
    if kind == 'buy' and pool.buys_today() >= money.limits(cfg)['max_buys_per_day']:
        raise money.SpendDenied('ProxyWing: исчерпан общий лимит числа покупок')


def _receipt(op, response):
    """Accept only a paid, correlated invoice; do not infer payment from expiry."""
    if not isinstance(response, dict):
        raise money.SpendDenied('ProxyWing: ответ оплаты не подтверждён; сохрани request_id')
    if response.get('status') != 'paid':
        raise money.SpendDenied('ProxyWing: заказ ожидает оплаты или подтверждения; новая трата заблокирована')
    req = op['request']
    if (op['kind'] == 'buy' and response.get('product_id') != req['product_id'] or
            op['kind'] == 'prolong' and response.get('order_id') != req['order_id'] or
            response.get('category', req['family']) != req['family'] or
            response.get('currency', 'USD') != 'USD'):
        raise money.SpendDenied('ProxyWing: ответ относится к другой операции')
    receipt = {'status': 'paid', 'total': amount(response.get('total')),
               'order_id': identifier(response.get('order_id')),
               'invoice_id': identifier(response.get('invoice_id'))}
    if op['kind'] == 'buy':
        if response.get('billing_cycle') != 'monthly':
            raise money.SpendDenied('ProxyWing: API подтвердил другой срок покупки')
        receipt.update(product_id=req['product_id'], billing_cycle='monthly')
    else:
        date = response.get('next_due_date')
        if (money._date_value(date) is None or
                req.get('date_before') and not money._expiry_advanced(req['date_before'], date)):
            raise money.SpendDenied('ProxyWing: новый срок заказа не подтверждён')
        receipt['next_due_date'] = date
    return receipt


def finish(pool, op, receipt, recovered=False):
    """Atomically record one order charge and update every local IP in that order."""
    receipt = _receipt(op, receipt)
    req = op['request']
    prefix = 'proxywing:%s|%s|' % (req['family'], receipt['order_id'])
    siblings = [r for r in pool.list(include_gone=True) if r['uid'].startswith(prefix)]
    updates = [(r['uid'], receipt['next_due_date']) for r in siblings] if op['kind'] == 'prolong' else []
    result = {'ok': True, 'provider': 'proxywing', 'kind': op['kind'], 'family': req['family'],
              'order_id': receipt['order_id'], 'invoice_id': receipt['invoice_id'],
              'months': req['months'], 'price': receipt['total'], 'currency': 'USD',
              'date_end': receipt.get('next_due_date'), 'recovered': recovered,
              'uids': [r['uid'] for r in siblings], 'spend_operation_id': op['id'],
              'warning': 'API списал сумму выше предварительной цены' if receipt['total'] > op['quote_price'] else ''}
    pool.complete_spend_operation(op['id'], [{'provider': 'proxywing', 'op': op['kind'],
        'price': receipt['total'], 'currency': 'USD', 'uid': op.get('uid'),
        'order_id': receipt['order_id']}], date_updates=updates, result=result,
        hold_order=('proxywing', req['family'], receipt['order_id']) if op['kind'] == 'buy' else None)
    pool.log_event(op['kind'], actor='user', result='recovered' if recovered else 'ok',
                   detail='ProxyWing %s: %.2f USD, %s months' % (receipt['order_id'], receipt['total'], req['months']))
    return result


def recover(pool, op):
    """Read-only recovery: never issue a payment from a background reconciler."""
    response = (op.get('result') or {}).get('provider_response')
    if not response:
        raise money.SpendDenied('ProxyWing: ответ оплаты не сохранён; повтори исходную операцию с тем же request_id')
    return finish(pool, op, response, recovered=True)


def execute(pool, provider, cfg, body):
    """An authenticated manual request may replay the exact provider idempotency key."""
    kind, expected = intent(body)
    if getattr(provider, 'name', None) != 'proxywing':
        raise money.SpendDenied('ProxyWing: неверный адаптер')
    expected['credential_identity'] = hashlib.sha256(provider.api_key.encode('utf-8')).hexdigest()
    if not body.get('request_id'):
        raise money.SpendDenied('ProxyWing: нужен request_id')
    rid, key = money._request_identity(body['request_id'])
    with money._spend_lock(pool):
        op = pool.get_spend_operation_by_idempotency(key)
        if op:
            money._validate_bound_request(op, kind, 'proxywing', expected)
            if op['phase'] in ('committed', 'acknowledged'):
                return money._deliver_result(pool, money._stored_result(op), rid)
            if op['phase'] == 'failed':
                raise money.SpendDenied('ProxyWing: запрос завершён ошибкой', replace_request=True)
            if (op.get('result') or {}).get('provider_response'):
                return money._deliver_result(pool, recover(pool, op), rid)
        else:
            money._guard_new_request(pool, {'proxywing': provider}, actor='user')
        with money._retire_planned_on_denial(pool, op):
            current = quote(provider, cfg, kind, expected)
            # A submitted request reserves this local operation and blocks new ones.
            # The account balance may already include its charge. A fresh price
            # ceiling still protects a crash between journaling and actual HTTP.
            _gates(pool, cfg, kind, expected, current['total'], current['balance'],
                   reserved=bool(op and op['phase'] == 'submitted'))
            if op and current['total'] > op['quote_price']:
                raise money.SpendDenied('ProxyWing: цена выросла; требуется сверка исходной операции')
            if op is None:
                if kind == 'prolong':
                    if money._date_value(current.get('next_due_date')) is None:
                        raise money.SpendDenied('ProxyWing: исходная дата заказа не подтверждена')
                    expected['date_before'] = current['next_due_date']
                op, created = pool.begin_spend_operation(kind, 'proxywing', expected, key,
                    quote_price=current['total'], currency='USD', balance_before=current['balance'])
                if not created:
                    raise money.SpendDenied('Другая денежная операция уже выполняется')
                op = pool.get_spend_operation(op['id'])
        expected = op['request']
        already_submitted = op['phase'] == 'submitted'
        def on_submit():
            if pool.get_spend_operation(op['id'])['phase'] == 'planned':
                pool.transition_spend_operation(op['id'], 'submitted')
        try:
            if kind == 'buy':
                response = provider.order_product(expected['family'], expected['product_id'], 'monthly', rid, on_submit)
            else:
                response = provider.extend_order(expected['family'], expected['order_id'], expected['months'], rid, on_submit)
        except ProviderError as error:
            phase = pool.get_spend_operation(op['id'])['phase']
            if phase == 'planned' or (not already_submitted and
                    (getattr(error, 'definitive', False) or getattr(error, 'unsent', False))):
                pool.transition_spend_operation(op['id'], 'failed', str(error))
                error.replace_request = True
            raise
        if pool.get_spend_operation(op['id'])['phase'] != 'submitted':
            pool.transition_spend_operation(op['id'], 'submitted')
            raise money.SpendDenied('ProxyWing: адаптер не подтвердил границу отправки')
        receipt = _receipt(op, response)
        pool.record_spend_response(op['id'], {'provider_response': receipt})
        result = finish(pool, op, receipt)
        return money._deliver_result(pool, result, rid)
