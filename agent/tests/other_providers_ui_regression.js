// Usage: node other_providers_ui_regression.js <rendered-dashboard.js>
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('const __moneyRequestFallback=');
const end = source.indexOf('async function del(', start);
assert.ok(start >= 0 && end > start);
function fixture(customApi){
  const elements=new Map(),calls=[],messages=[];
  const element=id=>{if(!elements.has(id))elements.set(id,{value:'',textContent:'',innerHTML:'',hidden:false,disabled:false,setAttribute(){}});return elements.get(id)};
  let promptValue='';
  const context=vm.createContext({window:{},document:{getElementById:element},URLSearchParams,
    toast:message=>messages.push(message),confirm:()=>true,prompt:()=>promptValue,
    reloadAll:async()=>{},esc:v=>String(v),country:v=>v,
    sessionStorage:{getItem:()=>null,setItem(){},removeItem(){}},
    crypto:{randomUUID:()=> 'request-test-'+calls.length},
    api:async(url,options)=>{calls.push({url,options});return customApi(url,options)}});
  vm.runInContext(source.slice(start,end),context);
  return {element,calls,messages,run:code=>vm.runInContext(code,context),prompt:value=>{promptValue=value}};
}
const p6Market={available:[{cc:'de'}],period:7,price:{price:28,balance:500,currency:'RUB'}};
(async () => {
  const invalid=fixture(()=>{throw Error('invalid input must not call API')});
  for (const value of ['30.5','7days','true','0','366']) {
    invalid.element('buyperiod').value=value;invalid.prompt(value);
    await invalid.run('buy()');await invalid.run("prolong({},'proxy6:15')");
    assert.equal(invalid.calls.length,0,value+': no financial request for invalid input');
  }
  const p6=fixture(async(url)=>url==='/api/buy'?{price:28,currency:'RUB',balance_after:'472.00'}:structuredClone(p6Market));
  p6.element('marketprovider').value='proxy6';await p6.run('shopSelect()');
  p6.element('buyperiod').value='7';await p6.run('buy()');
  assert.equal(p6.element('shopbalance').textContent,'472 RUB','PROXY6 payment updates displayed balance');
  await p6.run('shopSelect()');assert.equal(p6.element('shopbalance').textContent,'472 RUB','updated balance survives cached reopen');
  assert.equal(p6.calls.filter(c=>c.url==='/api/market?provider=proxy6').length,1);

  let finishPayment;
  const busy=fixture(async(url)=>url==='/api/buy'?new Promise(resolve=>{finishPayment=resolve}):
    url.includes('proxy6')?structuredClone(p6Market):{countries:[],periods:[30],balance:{balance:10,currency:'USD'}});
  busy.element('marketprovider').value='proxy6';await busy.run('shopSelect()');busy.element('buyperiod').value='7';
  const paying=busy.run('buy()');await busy.run('shopSelect()');busy.element('buyperiod').value='7';
  assert.equal(busy.element('p6buy').disabled,true,'reopening the provider cannot enable a second payment');
  await busy.run('buy()');assert.equal(busy.calls.filter(c=>c.url==='/api/buy').length,1);
  busy.element('marketprovider').value='proxyline';await busy.run('shopSelect()');
  finishPayment({price:28,currency:'RUB',balance_after:472});await paying;
  assert.equal(busy.element('shopbalance').textContent,'10 USD');
  busy.element('marketprovider').value='proxy6';await busy.run('shopSelect()');
  assert.equal(busy.element('shopbalance').textContent,'472 RUB','background payment updates its own provider');
  assert.equal(busy.element('p6buy').disabled,false);

  const renewal=fixture(async(url)=>url.includes('/prolong')?{price:28,currency:'RUB',balance_after:472,days:30}:structuredClone(p6Market));
  renewal.element('marketprovider').value='proxy6';await renewal.run('shopSelect()');renewal.prompt('30');
  await renewal.run("prolong({},'proxy6:15')");assert.equal(renewal.element('shopbalance').textContent,'472 RUB');

  let completeQuote;
  const stale=fixture(async(url)=>url.includes('quote=1')?new Promise(resolve=>{completeQuote=resolve}):
    url.includes('proxy6')?structuredClone(p6Market):{countries:[],periods:[30],balance:{balance:10,currency:'USD'}});
  stale.element('marketprovider').value='proxy6';await stale.run('shopSelect()');stale.element('buyperiod').value='30';
  const quoting=stale.run('shopProxy6Quote()');stale.element('marketprovider').value='proxyline';await stale.run('shopSelect()');
  completeQuote({period:30,price:{price:120,balance:500,currency:'RUB'}});await quoting;
  assert.equal(stale.element('shopbalance').textContent,'10 USD');assert.equal(stale.element('p6buy').disabled,true);

  const pl=fixture(async(url)=>url.includes('country=')?{stock:1000,quote:{country:'us',type:'dedicated',quantity:1,period:30,amount:1.2}}:
    {countries:[{code:'us'}],periods:[5,30],balance:{balance:10,currency:'USD'}});
  for(const [id,value] of Object.entries({marketprovider:'proxyline',plkind:'dedicated',plquantity:'1'}))pl.element(id).value=value;
  await pl.run('shopSelect()');assert.equal(pl.calls.length,2);
  assert.ok(pl.calls.every(c=>c.url.startsWith('/api/market?')&&!c.options));
  assert.match(pl.element('plquote').textContent,/1000/);assert.match(pl.element('plquote').textContent,/1.2 USD/);
  pl.element('plcountry').value='';await pl.run('plQuote()');
  assert.ok(!pl.element('plquote').textContent.includes('1.2 USD'),'empty country cannot retain a stale offer');

  for(const price of [null,true,[28],'',-1,'bad',Infinity]){
    const noPrice=fixture(async()=>({available:[{cc:'de'}],period:7,price:{price,balance:500,currency:'RUB'}}));
    noPrice.element('marketprovider').value='proxy6';await noPrice.run('shopSelect()');
    assert.equal(noPrice.element('p6buy').disabled,true,'unconfirmed price cannot enable purchase: '+price);
  }
  for(const value of [true,[472],'',null,'bad',-1])assert.equal(p6.run('shopAmount('+JSON.stringify(value)+')'),null);
  console.log('Other providers UI: invalid periods, PROXY6 balance/cache, ProxyLine read-only catalog, empty offers PASS');
})().catch(error => { console.error(error); process.exitCode=1; });
