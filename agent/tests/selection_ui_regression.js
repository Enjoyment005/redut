// Run against the rendered dashboard so escaping and async handlers are exercised.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync(process.argv[2],'utf8');
const helpers=html.slice(html.indexOf('function toast(t,cls,ms='),html.indexOf('/* ── подсказки:'));
const manual=html.slice(html.indexOf('async function apply(btn,uid){'),html.indexOf('async function rollback(){'));
const strategy=html.slice(html.indexOf('async function setStrategy(id,title){'),html.indexOf('/* ── ключи провайдеров:'));
const selected={uid:'zenxnet:test',host:'192.0.2.20',country:'cn',label:'China, Beijing'};
function harness(api){
  const nodes=new Map(),buttons=[],timers=[],messages=[];let confirmations=0,reloads=0;
  const element=()=>({textContent:'',className:'',hidden:false,disabled:false,dataset:{},removed:false,
    setAttribute(k,v){this[k]=v},remove(){this.removed=true},appendChild(n){messages.push(n)}});
  const node=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id)};
  const context=vm.createContext({document:{getElementById:node,createElement:element,querySelectorAll:()=>buttons},
    country:cc=>({cn:'Китай',fi:'Финляндия',nl:'Нидерланды'}[cc]||cc),api,
    confirm:()=>{confirmations++;return true},setTimeout:(fn,ms)=>{if(ms===3000)fn();else timers.push(fn)},
    reloadAll:async()=>{reloads++}});
  vm.runInContext(helpers+manual+strategy,context);
  context.selected=selected;vm.runInContext('__poolRows.set(selected.uid,selected)',context);
  const button=element();button.textContent='В бой';buttons.push(button);
  const unavailable=element();unavailable.dataset.unavailable='1';buttons.push(unavailable);
  return {context,node,button,buttons,timers,messages,counts:()=>({confirmations,reloads})};
}
async function pendingManual(failure=false){
  let resolve,reject,calls=0;
  const pending=new Promise((yes,no)=>{resolve=yes;reject=no});
  const h=harness(async()=>{calls++;return pending});h.context.button=h.button;
  const operation=vm.runInContext("apply(button,'zenxnet:test')",h.context);
  assert.equal(h.button.textContent,'Переключаю…');assert.ok(h.buttons.every(x=>x.disabled));
  assert.match(h.node('pool-feedback').textContent,/China, Beijing/);
  for(const timer of h.timers)timer();
  assert.equal(h.messages.length,1);assert.equal(h.messages[0].removed,false,'pending message must not expire');
  await vm.runInContext("apply(button,'zenxnet:test')",h.context);
  await vm.runInContext("setStrategy('speed','Скорость')",h.context);
  assert.equal(calls,1);assert.equal(h.counts().confirmations,1,'repeat clicks are ignored');
  if(failure)reject(new Error('проверка сервера не прошла'));
  else resolve({ok:true,selected,egress:'192.0.2.20',egress_cc:'fi'});
  await operation;
  assert.equal(h.button.disabled,false);assert.equal(h.buttons[1].disabled,true);
  assert.equal(h.button.textContent,'В бой');assert.equal(h.messages[0].removed,true);
  assert.equal(h.node('pool-feedback').hidden,false);assert.equal(h.counts().reloads,1);
  assert.match(h.node('pool-feedback').textContent,failure?/Не удалось подтвердить/:/В каталоге: Китай; GeoIP: Финляндия/);
  assert.ok(h.node('pool-feedback').className.includes(failure?'bad':'warn'));
}
async function automatic(mode){
  let reads=0;
  const h=harness(async(url,options)=>{
    if(options)return {mode:'auto',current:'speed',revision:{desired:8,applied:7,pending:true}};
    if(url==='/api/status')return {selected_channel:selected,egress:'192.0.2.20',egress_cc:'fi',
      selection_mode:mode==='status-superseded'?'manual':'auto',strategy:'speed',
      selection_revision:{desired:mode==='status-superseded'?9:8,applied:mode==='held'?7:8,pending:mode==='held'},
      selection_attempt:{revision:8,state:'done',ok:true,action:'held'}};
    reads++;
    if(mode==='held'||mode==='held-then-applied'||mode==='failed')return {mode:'auto',current:'speed',revision:{desired:8,applied:7,pending:true},
      attempt:{revision:8,state:'done',ok:mode!=='failed',action:mode!=='failed'?'held':'probe-inconclusive'}};
    if(mode==='superseded')return {mode:'manual',revision:{desired:9,applied:9,pending:false}};
    if(mode==='waiting')return {mode:'auto',current:'speed',revision:{desired:8,applied:7,pending:true}};
    return {mode:'auto',current:'speed',revision:{desired:8,applied:reads<2?7:8,pending:reads<2}};
  });
  await vm.runInContext("setStrategy('speed','Скорость')",h.context);
  const feedback=h.node('pool-feedback').textContent;
  if(mode==='superseded'||mode==='status-superseded')assert.match(feedback,/другой вкладке/);
  else if(mode==='held'){assert.equal(reads,1);assert.match(feedback,/Сохранён текущий канал по правилу стабильности/)}
  else if(mode==='held-then-applied'){assert.equal(reads,1);assert.match(feedback,/Выбран /);assert.doesNotMatch(feedback,/Сохранён текущий канал/)}
  else if(mode==='failed'){assert.equal(reads,1);assert.match(feedback,/проверка не подтвердила/)}
  else if(mode==='waiting'){assert.equal(reads,60);assert.match(feedback,/Проверка ещё идёт/)}
  else{assert.equal(reads,2);assert.match(feedback,/Автоматика «Скорость» включена/)}
  assert.equal(h.button.disabled,false);assert.ok(h.messages[0].removed);
}
async function rendering(){
  const h=harness(async()=>{});h.context.status={selected_channel:selected,selection_mode:'manual',egress_cc:'fi'};
  vm.runInContext('renderSelectedChannel(status)',h.context);
  assert.match(h.node('selected-channel').textContent,/Закреплён вручную: China, Beijing/);
  assert.match(h.node('selected-channel').textContent,/GeoIP: Финляндия/);
  h.context.status={selected_channel:{...selected,label:'<img src=x onerror=alert(1)>'},selection_mode:'auto'};
  vm.runInContext('renderSelectedChannel(status)',h.context);
  assert.match(h.node('selected-channel').textContent,/<img/);
  assert.equal(h.node('selected-channel').innerHTML,undefined,'provider label is text, never HTML');
}
(async()=>{await pendingManual();await pendingManual(true);for(const m of ['success','superseded','waiting','held','failed','status-superseded','held-then-applied'])await automatic(m);await rendering();console.log('selection feedback regression PASS')})().catch(e=>{console.error(e);process.exitCode=1});
