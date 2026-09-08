// Usage: node other_providers_ui_regression.js <rendered-dashboard.js>
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('const __moneyRequestFallback=');
const end = source.indexOf('async function del(', start);
assert.ok(start >= 0 && end > start);
const elements = Object.fromEntries(['buycc','buyccfree','buyperiod','plbox','plcountry','plkind',
  'plquantity','plperiod','plinfo','plquote'].map(id => [id, {value:''}]));
let promptValue = '', calls = [];
const context = vm.createContext({
  document: {getElementById: id => elements[id]},
  URLSearchParams, toast() {}, confirm: () => true, prompt: () => promptValue,
  openFold: async () => {}, esc: value => String(value), country: value => value,
  sessionStorage: {getItem: () => null, setItem() {}, removeItem() {}},
  crypto: {randomUUID: () => 'request-test-0001'},
  api: async (url, options) => {
    calls.push({url, options});
    if (url.includes('country=')) return {stock:1000,quote:{country:'us',type:'dedicated',quantity:1,period:30,amount:1.2}};
    return {countries:[{code:'us'}],periods:[5,30],balance:{balance:10},notice:'read-only'};
  },
});
vm.runInContext(source.slice(start,end), context);
(async () => {
  for (const value of ['30.5','7days','true','0','366']) {
    elements.buyperiod.value = value;
    await vm.runInContext('buy()', context);
    promptValue = value;
    await vm.runInContext("prolong({},'proxy6:15')", context);
    assert.equal(calls.length, 0, value + ': no financial request for invalid input');
  }
  await vm.runInContext('plMarket()', context);
  Object.assign(elements.plcountry, {value:'us'});
  Object.assign(elements.plkind, {value:'dedicated'});
  Object.assign(elements.plquantity, {value:'1'});
  Object.assign(elements.plperiod, {value:'30'});
  await vm.runInContext('plQuote({})', context);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.url.startsWith('/api/market?') && !call.options));
  assert.match(elements.plquote.textContent, /1000/);
  assert.match(elements.plquote.textContent, /1.2 USD/);
  console.log('Other providers UI: invalid periods and read-only catalog PASS');
})().catch(error => { console.error(error); process.exitCode=1; });
