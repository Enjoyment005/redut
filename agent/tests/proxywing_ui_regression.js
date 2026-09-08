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

async function renewalScenario(budget, mode = 'normal') {
  const elements = new Map(), requests = [], messages = [], opened = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', checked:false, open:false,
      textContent:'', scrollIntoView() {}, focus() {}});
    return elements.get(id);
  };
  const quote = {order_id:'ord_existing', family:'isp', affected_count:2,
    budget:{...budget}, spent_today:0, options:[{months:3,total:9}]};
  if(mode==='pending')quote.pending={kind:'prolong',family:'isp',order_id:'ord_existing',
    months:3,max_total:9,request_id:'original-auto-request'};
  let confirmations = 0;
  const context = vm.createContext({
    window:{}, document:{getElementById:element},
    sessionStorage:{getItem:()=>null, setItem() {}, removeItem() {}},
    crypto:{randomUUID:()=> 'renew-existing-request'},
    prompt:()=> mode==='cancel'?null:mode==='invalid'?'2':'3', confirm:()=> { confirmations++; return true; },
    openFold:async name=>opened.push(name), toast:message=>messages.push(message),
    reloadAll:async()=>{},
    api:async(url, options)=> {
      requests.push({url, body:options && JSON.parse(options.body)});
      if (url.startsWith('/api/proxywing/renewal?')) return quote;
      if (url==='/api/proxywing/budget') {
        quote.budget=JSON.parse(options.body); return {ok:true,budget:quote.budget};
      }
      assert.equal(url,'/api/proxywing/spend');
      return {price:9,order_id:'ord_existing',date_end:'2026-12-10'};
    },
  });
  vm.runInContext(source.slice(start,end),context);
  await vm.runInContext("pwRenew({},'proxywing:isp|ord_existing|ip_1')",context);
  assert.equal(confirmations,mode==='pending'?1:0,'one confirmation at most');
  assert.deepEqual(opened,[],'renewal must not open purchase settings');
  const paid=requests.filter(r=>r.url==='/api/proxywing/spend');
  if(mode==='cancel'||mode==='invalid') {
    assert.equal(paid.length,0,'cancel or invalid term must not charge');return;
  }
  assert.equal(paid.length,1,'existing order is renewed once');
  assert.equal(paid[0].body.kind,'prolong');
  assert.equal(paid[0].body.order_id,'ord_existing');
  assert.equal(paid[0].body.months,3);
  assert.equal(paid[0].body.max_total,9);
  if(mode==='pending')assert.equal(paid[0].body.request_id,'original-auto-request');
  assert.equal(vm.runInContext('pwPending()',context),null);
  assert.ok(requests.every(r=>!r.url.includes('market')),'renewal does not need the purchase catalog');
}

(async () => {
  for (const mode of ['normal', 'quota', 'remove', 'reload-remove']) await scenario(mode);
  const budget={enabled:true,max_price_per_buy:50,max_spend_per_day:100,min_balance_reserve:1};
  await renewalScenario({...budget,enabled:false,max_price_per_buy:0,max_spend_per_day:0});
  await renewalScenario({...budget,max_price_per_buy:8});
  await renewalScenario({...budget,max_spend_per_day:8});
  await renewalScenario(budget);
  for(const mode of ['normal','pending','cancel','invalid'])await renewalScenario({},mode);
  console.log('ProxyWing UI: 4 storage and 8 existing-order renewal scenarios PASS');
})().catch(error => { console.error(error); process.exitCode = 1; });
