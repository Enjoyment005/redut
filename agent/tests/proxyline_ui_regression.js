// Runs the actual rendered dashboard, without provider requests.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[2],'utf8');
const script=source.slice(source.indexOf('const __moneyRequestFallback='),source.indexOf('async function del('));
function fixture(customApi,storage=new Map()){
  const elements=new Map(),calls=[],messages=[];let prompted='30',prompts=0;
  const element=id=>{if(!elements.has(id))elements.set(id,{value:'',disabled:false,hidden:false,textContent:'',innerHTML:'',setAttribute(){}});return elements.get(id)};
  const market={countries:[{code:'us'}],periods:[5,10,30],balance:{balance:100,currency:'USD'}};
  const context=vm.createContext({window:{},document:{getElementById:element},URLSearchParams,
    esc:String,country:String,reloadAll:async()=>{},toast:m=>messages.push(m),
    confirm:()=>{throw Error('extra confirmation')},prompt:()=>{prompts++;return prompted},
    crypto:{randomUUID:()=> 'pl-test-request-'+calls.length},
    sessionStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    api:async(url,options)=>{const body=options&&JSON.parse(options.body);calls.push({url,body});
      if(customApi){const response=await customApi(url,body);if(response!==undefined)return response}
      if(url==='/api/market?provider=proxyline')return structuredClone(market);
      if(url.startsWith('/api/market?')&&url.includes('country=')){const q=new URLSearchParams(url.split('?')[1]);return {stock:10,
        quote:{country:q.get('country'),type:q.get('type'),quantity:Number(q.get('quantity')),period:Number(q.get('period')),amount:1.2,currency:'USD'}}}
      if(url.startsWith('/api/proxyline/renewal?'))return {periods:[5,10,30],default_period:30};
      if(url==='/api/proxyline/spend')return {kind:body.kind,uids:['proxyline:100'],date_end:'2026-10-10',balance_after:'98.8',currency:'USD',price:null};
      if(url==='/api/market?provider=proxy6')return {available:[],period:7};
      throw Error('unexpected '+url)}});
  vm.runInContext(script,context);
  for(const [id,value] of Object.entries({marketprovider:'proxyline',plkind:'dedicated',plquantity:'1'}))element(id).value=value;
  return {run:s=>vm.runInContext(s,context),element,calls,messages,storage,market,prompt:value=>{prompted=value},prompts:()=>prompts};
}
const payments=f=>f.calls.filter(c=>c.url==='/api/proxyline/spend');
(async()=>{
  const f=fixture();await f.run('shopSelect()');await f.run('shopSelect()');
  assert.equal(f.calls.filter(c=>c.url==='/api/market?provider=proxyline').length,1,'country catalog loads once');
  assert.equal(f.element('plbuy').disabled,false);
  await f.run('plBuy()');assert.equal(payments(f).length,1);
  assert.deepEqual({...payments(f)[0].body,request_id:undefined},{kind:'buy',country:'us',type:'dedicated',version:4,quantity:1,period:30,max_total:1.2,request_id:undefined});
  assert.equal(f.element('shopbalance').textContent,'98.8 USD');
  assert.ok(f.messages.some(m=>m.includes('сумма списания в кабинете')));
  assert.ok(!f.messages.some(m=>m.includes('null')));

  let finish;
  const busy=fixture((url)=>url==='/api/proxyline/spend'?new Promise(r=>{finish=r}):undefined);
  await busy.run('shopSelect()');const paying=busy.run('plBuy()');await busy.run('shopSelect()');
  assert.equal(busy.element('plbuy').disabled,true);await busy.run('plBuy()');assert.equal(payments(busy).length,1);
  busy.element('marketprovider').value='proxy6';await busy.run('shopSelect()');
  finish({kind:'buy',uids:['proxyline:100'],date_end:'2026-10-10',balance_after:98.8,currency:'USD'});await paying;
  busy.element('marketprovider').value='proxyline';await busy.run('shopSelect()');
  assert.equal(busy.element('shopbalance').textContent,'98.8 USD');

  const renew=fixture();await renew.run('shopSelect()');await renew.run("prolong({},'proxyline:15')");
  assert.equal(renew.prompts(),1);assert.equal(payments(renew).length,1);
  assert.equal(payments(renew)[0].body.uid,'proxyline:15');assert.equal(payments(renew)[0].body.period,30);
  for(const value of ['7','30.5','true','0']){
    const invalid=fixture();invalid.prompt(value);await invalid.run("prolong({},'proxyline:15')");
    assert.equal(payments(invalid).length,0);
  }

  const timeout=fixture(url=>{if(url==='/api/proxyline/spend')throw Error('lost response')});
  await timeout.run('shopSelect()');await timeout.run('plBuy()');
  assert.equal(timeout.element('plbuy').disabled,true);assert.equal(timeout.element('plresume').hidden,false);
  const reloaded=fixture(undefined,timeout.storage);await reloaded.run('shopSelect()');
  await reloaded.run('plResume()');assert.equal(payments(reloaded)[0].body.request_id,payments(timeout)[0].body.request_id);
  assert.equal(reloaded.element('plresume').hidden,true);

  const unrelated=fixture(url=>url.startsWith('/api/proxyline/renewal?')?{pending:{kind:'buy',request_id:'saved-buy',period:30}}:undefined);
  await unrelated.run("prolong({},'proxyline:15')");assert.equal(payments(unrelated).length,0,'renewal cannot submit an unrelated pending purchase');

  const saved=payments(timeout)[0].body;
  const offline=fixture(url=>url==='/api/market?provider=proxyline'?{error:'catalog outage',pending:saved}:undefined);
  await offline.run('shopSelect()');assert.equal(offline.element('plresume').hidden,false,'server pending survives catalog error');
  await offline.run('plResume()');assert.equal(payments(offline)[0].body.request_id,saved.request_id);
  const offlineStored=fixture(url=>{if(url.startsWith('/api/market'))throw Error('offline')},new Map([['redut-pl-pending',JSON.stringify(saved)]]));
  await offlineStored.run('shopSelect()');assert.equal(offlineStored.element('plresume').hidden,false,'local pending survives network error');

  const rejected=fixture(url=>{if(url==='/api/proxyline/spend'){const e=Error('price changed');e.replace_request=true;throw e}});
  await rejected.run('shopSelect()');await rejected.run('plBuy()');assert.equal(rejected.element('plresume').hidden,true);

  let finishQuote;
  const stale=fixture(url=>url.includes('country=')?new Promise(r=>{finishQuote=r}):undefined);
  const selecting=stale.run('shopSelect()');await new Promise(setImmediate);
  stale.element('marketprovider').value='proxy6';await stale.run('shopSelect()');
  finishQuote({stock:10,quote:{country:'us',type:'dedicated',quantity:1,period:30,amount:1.2}});await selecting;
  assert.equal(stale.element('plbuy').disabled,true,'stale quote cannot enable another provider');
  for(const amount of [null,true,0,-1,'bad',Infinity]){
    const invalid=fixture(url=>url.includes('country=')?{stock:10,quote:{country:'us',type:'dedicated',quantity:1,period:30,amount}}:undefined);
    await invalid.run('shopSelect()');assert.equal(invalid.element('plbuy').disabled,true);
  }
  console.log('ProxyLine UI: buy, renewal, catalog cache, balance, stale quotes, busy state and durable retry PASS');
})().catch(error=>{console.error(error);process.exitCode=1});
