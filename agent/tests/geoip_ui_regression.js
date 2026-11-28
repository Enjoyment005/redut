const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm');
const html=fs.readFileSync(process.argv[2],'utf8');
assert.match(html,/href="https:\/\/www.ip2location.io"/);
const code=html.slice(html.indexOf('function intelRow('),html.indexOf("document.addEventListener('visibilitychange'"));
const ip='1.2.3.4';
const node={style:{},innerHTML:'',textContent:''};
let calls=0, now=1000000, answer={ok:true,ip,intel:{src:'ip2location',city:'Beijing',geo_status:'single-source',cc:'cn'}};
const context=vm.createContext({document:{getElementById:()=>node},window:{__S:{egress:ip}},
  geoSync:()=>{},renderSelectedChannel:()=>{},CONTOUR:'2',isFolded:()=>false,esc:x=>String(x).replaceAll('<','&lt;'),
  Date:{now:()=>now},api:async()=>{calls++;return answer},Intl});
vm.runInContext(code,context);
context.state={egress:ip,egress_at:'2026-11-27'};
async function run(){
  await vm.runInContext('geoIntel(state)',context);
  assert.equal(context.window.__S.egress_cc,'cn');assert.match(node.innerHTML,/Beijing/);assert.match(node.innerHTML,/ip2location/);
  await vm.runInContext('geoIntel(state)',context);assert.equal(calls,1);
  now+=300001;
  answer={ok:true,ip,intel:{src:'ipwho.is',city:'Tokyo',geo_status:'conflict'}};
  await vm.runInContext('geoIntel(state)',context);
  assert.equal(calls,2);assert.match(node.innerHTML,/Tokyo/);assert.match(node.innerHTML,/базы расходятся/);
  now+=300001; answer={ok:false,ip};
  await vm.runInContext('geoIntel(state)',context);
  assert.match(node.textContent,/Геолокация временно недоступна/);
  await vm.runInContext('geoIntel(state)',context);assert.equal(calls,3);
  now+=300001;
  let resolve;
  context.api=()=>new Promise(r=>{resolve=r});
  const pending=vm.runInContext('geoIntel(state)',context);
  context.CONTOUR='1';node.innerHTML='current contour';
  resolve({ok:true,ip,intel:{city:'wrong contour'}});await pending;
  assert.equal(node.innerHTML,'current contour');
  console.log('GeoIP UI regression PASS');
}
run().catch(e=>{console.error(e);process.exitCode=1});
