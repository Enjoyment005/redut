// Run against the actual rendered dashboard script: node ... <dashboard.js>
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[2],'utf8');
const script=source.slice(source.indexOf('const __moneyRequestFallback='),source.indexOf('async function prolong('));
function fixture(overrides={}){
  const elements=new Map(),requests=[],storage=new Map();
  function element(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',hidden:false,disabled:false,attributes:{},
    setAttribute(k,v){this.attributes[k]=v},set innerHTML(v){this.html=v},get innerHTML(){return this.html||''}});return elements.get(id)}
  const product=(family,cc,group,id,n=1)=>({family,country:cc,group,product_id:id,quantity:n,price_monthly:n*3,name:id});
  const catalog={products:[product('datacenter','de','','d1'),product('datacenter','de','','d2',2),
    product('datacenter','lt','','d3'),product('isp','nl','ISP Netherlands Premium','i1'),
    product('isp','us','ISP US New York Premium','i2'),product('isp','us','ISP US Los Angeles Premium','i3'),
    product('isp','gb','ISP United Kingdom Premium','i4')],balance:{balance:48.6,currency:'USD'}};
  const context=vm.createContext({window:{__S:{auto_prolong:{enabled:true}}},document:{getElementById:element},
    esc:v=>String(v),country:cc=>({de:'Германия',lt:'Литва',nl:'Нидерланды',us:'США',gb:'Великобритания'}[cc]||cc),
    crypto:{randomUUID:()=> 'shop-request-'+requests.length},URLSearchParams,
    sessionStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    confirm:overrides.confirm||(()=>{throw Error('purchase must not ask extra questions')}),toast(){},reloadAll:async()=>{},
    api:async(url,options)=>{requests.push({url,body:options&&JSON.parse(options.body)});
      if(overrides.api)return overrides.api(url,options,catalog);
      if(url==='/api/money')return {providers:['proxywing','proxy6','proxyline'],rows:[]};
      if(url==='/api/market?provider=proxywing')return catalog;
      if(url==='/api/market?provider=proxy6')return {available:[{cc:'de'}],period:7,price:{price:28,balance:500,currency:'RUB'}};
      if(url==='/api/proxywing/spend')return {price:3,order_id:'paid',balance:{balance:45.6,currency:'USD'}};
      throw Error('unexpected '+url);
    }});
  vm.runInContext(script,context);
  return {context,element,requests,catalog,run:code=>vm.runInContext(code,context)};
}
(async()=>{
  const f=fixture();await f.run('loadMoney()');await f.run('loadMoney()');
  assert.equal(f.element('marketprovider').value,'proxywing');
  assert.equal(f.requests.filter(r=>r.url==='/api/market?provider=proxywing').length,1,'one automatic catalog load');
  f.run("pwChooseFamily('isp')");
  assert.ok(f.element('pwcountry').innerHTML.includes('Нидерланды'));
  assert.ok(!f.element('pwcountry').innerHTML.includes('Литва'),'datacenter countries never leak into ISP');
  assert.ok(!f.element('pwcountry').innerHTML.includes('value="fr"'),'no world-country fallback');
  f.element('pwcountry').value='us';f.run('pwCountriesChanged()');
  assert.equal(f.element('pwlocationbox').hidden,false);
  assert.equal(f.element('pwcountry').innerHTML.match(/value="us"/g).length,1,'country does not repeat per city');
  await f.run('pwBuy()');
  const payment=f.requests.find(r=>r.url==='/api/proxywing/spend');
  assert.equal(payment.body.country,'us');assert.equal(payment.body.family,'isp');assert.equal(payment.body.max_total,3);
  assert.equal(f.element('shopbalance').textContent,'45.6 USD','balance updates without catalog reload');
  f.element('marketprovider').value='proxy6';await f.run('shopSelect()');
  f.element('marketprovider').value='proxywing';await f.run('shopSelect()');
  assert.equal(f.requests.filter(r=>r.url==='/api/market?provider=proxywing').length,1);
  await f.run('shopSelect(true)');assert.equal(f.requests.filter(r=>r.url==='/api/market?provider=proxywing').length,2);

  const empty=fixture();empty.catalog.products=empty.catalog.products.filter(p=>p.family!=='isp');
  empty.catalog.errors={isp:'API unavailable'};await empty.run('loadMoney()');empty.run("pwChooseFamily('isp')");
  assert.equal(empty.element('pwcountry').innerHTML,'');assert.equal(empty.element('pwbuy').disabled,true);
  assert.equal(empty.element('shopmessage').textContent,'API unavailable');

  let finishPayment;
  const concurrent=fixture({api:async(url,options,catalog)=>{
    if(url==='/api/money')return {providers:['proxywing'],rows:[]};
    if(url.includes('/api/market'))return catalog;
    return new Promise(resolve=>{finishPayment=resolve});
  }});
  await concurrent.run('loadMoney()');const first=concurrent.run('pwBuy()');await concurrent.run('pwBuy()');
  concurrent.run("pwChooseFamily('isp')");assert.equal(concurrent.element('pwbuy').disabled,true);
  finishPayment({price:3,order_id:'paid'});await first;
  assert.equal(concurrent.requests.filter(r=>r.url==='/api/proxywing/spend').length,1,'double click sends once');

  let finishSwitched;
  const switched=fixture({api:async(url,options,catalog)=>{
    if(url==='/api/money')return {providers:['proxywing','proxy6'],rows:[]};
    if(url==='/api/market?provider=proxywing')return catalog;
    if(url==='/api/market?provider=proxy6')return {available:[{cc:'de'}],period:7,price:{price:28,balance:500,currency:'RUB'}};
    return new Promise(resolve=>{finishSwitched=resolve});
  }});
  await switched.run('loadMoney()');const inFlight=switched.run('pwBuy()');
  switched.element('marketprovider').value='proxy6';await switched.run('shopSelect()');
  finishSwitched({price:3,order_id:'paid',balance:{balance:45.6,currency:'USD'}});await inFlight;
  assert.equal(switched.element('shopbalance').textContent,'500 RUB');
  switched.element('marketprovider').value='proxywing';await switched.run('shopSelect()');
  assert.equal(switched.element('shopbalance').textContent,'45.6 USD','payment updates provider cache while another provider is selected');

  const p6=fixture({confirm:text=>{assert.ok(text.includes('28 RUB'));return true},api:async(url,options)=>{
    if(url.includes('/api/market'))return {available:[{cc:'de'}],period:7,price:{price:28,balance:500,currency:'RUB'}};
    if(url==='/api/buy')return {uids:[],price:28,currency:'RUB'};
    throw Error(url);
  }});
  p6.element('marketprovider').value='proxy6';await p6.run('shopSelect()');
  p6.element('buyperiod').value='7';await p6.run('buy()');
  const p6payment=p6.requests.find(r=>r.url==='/api/buy');
  assert.equal(p6payment.body.max_total,28);assert.equal(p6payment.body.currency,'RUB');

  let lost=true;
  const recovery=fixture({confirm:()=>true,api:async(url,options,catalog)=>{
    if(url==='/api/money')return {providers:['proxywing'],rows:[]};
    if(url.includes('/api/market'))return catalog;
    if(lost){lost=false;throw Error('lost response')}
    return {price:3,order_id:'paid'};
  }});
  await recovery.run('loadMoney()');await recovery.run('pwBuy()');
  assert.equal(recovery.element('pwbuy').disabled,true);assert.equal(recovery.element('pwresume').hidden,false);
  await recovery.run('pwResume()');
  assert.equal(recovery.run('pwPending()'),null);
  assert.equal(recovery.element('pwbuy').disabled,false,'retry completion unlocks purchase');
  assert.equal(recovery.element('pwresume').hidden,true,'completed pending action disappears');

  let finishPW;
  const race=fixture({api:async(url,options,catalog)=>{
    if(url.includes('proxywing'))return new Promise(resolve=>{finishPW=()=>resolve(catalog)});
    return {available:[{cc:'de'}],period:7,price:{price:28,balance:500,currency:'RUB'}};
  }});
  race.element('marketprovider').value='proxywing';const slow=race.run('shopSelect()');
  race.element('marketprovider').value='proxy6';await race.run('shopSelect()');finishPW();await slow;
  assert.equal(race.element('shop-proxywing').hidden,true);assert.equal(race.element('shopbalance').textContent,'500 RUB');
  console.log('Money shop UI: catalog cache, actual countries, 3-step purchase, balances, empty catalog, double click, provider race PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
