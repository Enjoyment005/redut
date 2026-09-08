// Usage: node proxywing_ui_regression.js <rendered-dashboard.js>
// Exercise the actual dashboard functions with storage and network failures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('const __moneyRequestFallback=');
const end = source.indexOf('async function buy()', start);
assert.ok(start >= 0 && end > start);

async function scenario(mode) {
  const values = new Map(), requests = [];
  let sequence = 0, lost = true;
  if (mode === 'reload-remove') {
    const original = {kind:'buy',family:'isp',product_id:'prod_1',months:1,country:'us',max_total:3};
    values.set('redut-money-v1:proxywing:' + JSON.stringify(original), 'request-0');
    values.set('redut-pw-pending', JSON.stringify({...original, request_id:'request-0'}));
  }
  const context = vm.createContext({
    sessionStorage: {
      getItem: key => values.get(key) || null,
      setItem: (key, value) => {
        if (mode === 'quota') throw Error('QuotaExceededError');
        values.set(key, value);
      },
      removeItem: key => {
        if (mode.endsWith('remove')) throw Error('SecurityError');
        values.delete(key);
      },
    },
    crypto: {randomUUID: () => 'request-' + (++sequence)},
    api: async (url, options) => {
      const body = JSON.parse(options.body);
      requests.push(body);
      if (lost) { lost = false; throw Error('lost response'); }
      return {price: 3, order_id: 'ord_1'};
    },
    toast() {}, confirm: () => true, reloadAll: async () => {},
  });
  vm.runInContext(source.slice(start, end), context);
  const spend = "pwSpend({kind:'buy',family:'isp',product_id:'prod_1',months:1,country:'us',max_total:3})";
  await vm.runInContext(mode === 'reload-remove' ? 'pwResume()' : spend, context);
  assert.equal(vm.runInContext('pwPending().request_id', context), requests[0].request_id, mode);
  await vm.runInContext(spend, context);
  assert.equal(requests.length, 1, mode + ': pending blocks a new purchase');
  await vm.runInContext('pwResume()', context);
  assert.equal(requests.length, 2, mode);
  assert.equal(requests[1].request_id, requests[0].request_id, mode + ': stable retry key');
  assert.equal(vm.runInContext('pwPending()', context), null, mode + ': cleared after payment');
  await vm.runInContext(spend, context);
  assert.equal(requests.length, 3, mode);
  assert.notEqual(requests[2].request_id, requests[0].request_id, mode + ': new purchase needs a new key');
}

(async () => {
  for (const mode of ['normal', 'quota', 'remove', 'reload-remove']) await scenario(mode);
  console.log('ProxyWing UI: network retry and 4 storage scenarios PASS');
})().catch(error => { console.error(error); process.exitCode = 1; });
