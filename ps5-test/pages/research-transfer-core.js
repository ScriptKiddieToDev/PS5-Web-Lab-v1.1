(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ResearchTransferCore = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  var CASES = [
    {id:'A-getContext-webidl', title:'Canvas getContext(), alpha false e getter rientranti', profile:'worker', source:"const c=new OffscreenCanvas(1,1);let reads=0;const o={};Object.defineProperty(o,'alpha',{enumerable:true,get(){reads++;return false}});const x=c.getContext('2d',o);x.fillStyle='rgba(1,2,3,1)';x.fillRect(0,0,1,1);x.clearRect(0,0,1,1);const pixel=Array.from(x.getImageData(0,0,1,1).data);const attrs=x.getContextAttributes?x.getContextAttributes():null;const r={getterReads:reads,pixel,alphaAttribute:attrs&&attrs.alpha};if(reads!==1||(attrs&&attrs.alpha!==false)||pixel[3]!==255)r.__unexpected=true;return r;"},
    {id:'B-bitmap-lifecycle', title:'createImageBitmap() e ridimensionamento/sostituzione', profile:'worker', source:"if(typeof createImageBitmap!=='function')return {skipped:'createImageBitmap unavailable'};const c=new OffscreenCanvas(1,1),x=c.getContext('2d');x.fillStyle='rgb(41,83,127)';x.fillRect(0,0,1,1);const pending=createImageBitmap(c);c.width=2;c.height=1;const y=c.getContext('2d');y.fillStyle='rgb(9,9,9)';y.fillRect(0,0,2,1);const b=await pending;const out=new OffscreenCanvas(2,1),ox=out.getContext('2d');ox.drawImage(b,0,0);const pixel=Array.from(ox.getImageData(0,0,1,1).data);const replacement=Array.from(y.getImageData(0,0,1,1).data);const r={bitmap:[b.width,b.height],canvas:[c.width,c.height],capturedPixel:pixel,replacementPixel:replacement};if(b.close)b.close();if(r.bitmap[0]!==1||r.bitmap[1]!==1||pixel[0]!==41||replacement[0]!==9)r.__unexpected=true;return r;"},
    {id:'C1-blob-url-lifecycle', title:'Blob URL locale: round-trip e revoca', profile:'worker', source:"const blob=new Blob(['local-blob-check'],{type:'text/plain'}),url=URL.createObjectURL(blob);let before,after;try{before=await (await fetch(url)).text();}finally{URL.revokeObjectURL(url)}try{await fetch(url);after='unexpectedly-loaded'}catch(e){after=e.name||'rejected'}const r={blobUrlOrigin:new URL(url).origin,workerOrigin:self.origin,beforeRevoke:before,afterRevoke:after};if(before!=='local-blob-check'||after==='unexpectedly-loaded')r.__unexpected=true;return r;"},
    {id:'C2-blob-url-opaque-origin', title:'Blob URL da origine pagina in contesto sandbox a origine opaca', profile:'opaque-iframe', source:''},
    {id:'C3-blob-url-local-origin', title:'Blob URL tra origine dashboard e fixture HTTP locale a porta diversa', profile:'local-origin-fixture', source:''},
    {id:'D-origin-clean-matrix', title:'origin-clean: getImageData(), toDataURL(), toBlob()', profile:'local-fixture', source:''}
  ];
  function cases() { return CASES.map(function (item) { return {id:item.id,title:item.title,profile:item.profile}; }); }
  function caseSource(id) { var item=CASES.find(function (candidate) { return candidate.id===id; }); return item ? item.source : null; }
  function validRelativePath(value) {
    if (typeof value !== 'string' || value.length > 2048 || value.indexOf('\\') !== -1 || value.indexOf('\0') !== -1) return false;
    return value.split('/').every(function (part) { return part !== '..' && part !== '.'; });
  }
  function safeFilename(value) { return /^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.js$/i.test(value) && !value.includes('..'); }
  function fuzz(seed, count) {
    var state=(Number(seed)>>>0)||1, out=[], n=Math.max(0,Math.min(100,Number(count)||0));
    for(var i=0;i<n;i++){state^=state<<13;state^=state>>>17;state^=state<<5;out.push({index:i,alpha:!!((state>>>0)&1),width:1+((state>>>1)&1),height:1+((state>>>3)&1),sequence:(state>>>4)&3});}
    return out;
  }
  function envelope(sessionId, env, testId, input, observed, error, durationMs, startedAt) {
    var hasError=!!error;
    return {sessionId:sessionId,testId:testId,timestamp:new Date().toISOString(),startedAt:startedAt||null,environment:env,input:input,observed:observed,error:hasError?{name:String(error.name||'Error'),message:String(error.message||error).slice(0,2000)}:null,durationMs:Math.max(0,Math.min(3600000,Number(durationMs)||0)),state:hasError?'ERROR':(observed&&observed.skipped?'SKIPPED':(observed&&observed.inconclusive?'INCONCLUSIVE':(observed&&observed.__unexpected?'UNEXPECTED':'OBSERVED'))),engineIndicators:hasError&&error.name==='WorkerError'?['worker runtime error; requires independent reproduction; not evidence of engine defect']:[],evidenceRefs:[]};
  }
  function runWorker(source, timeoutMs, platform) {
    platform=platform||{};
    var WorkerType=platform.Worker||Worker,BlobType=platform.Blob||Blob,urlApi=platform.URL||URL;
    var setTimer=platform.setTimeout||setTimeout,clearTimer=platform.clearTimeout||clearTimeout;
    var started=Date.now(),worker=null,timer=null,objectUrl=null,settled=false,resolvePromise;
    var promise=new Promise(function(resolve){resolvePromise=resolve;});
    function finish(value){if(settled)return;settled=true;clearTimer(timer);if(worker)worker.terminate();if(objectUrl){try{urlApi.revokeObjectURL(objectUrl);}catch(_e){}objectUrl=null;}resolvePromise(Object.assign({durationMs:Math.max(0,Date.now()-started)},value));}
    try { if(platform.createWorker)worker=platform.createWorker(source);else{objectUrl=urlApi.createObjectURL(new BlobType([source],{type:'text/javascript'}));worker=new WorkerType(objectUrl);} }
    catch(error){finish({error:{name:String(error.name||'Error'),message:String(error.message||error)},data:null});return {promise:promise,stop:function(){}};}
    timer=setTimer(function(){finish({timedOut:true,data:null,error:{name:'TimeoutError',message:'Worker timeout'}});},timeoutMs);
    worker.onmessage=function(event){finish({data:event.data,error:null});};
    worker.onerror=function(event){finish({data:null,error:{name:'WorkerError',message:String(event.message||'Worker error')}});};
    return {promise:promise,stop:function(){if(!settled)finish({stopped:true,data:null,error:null});}};
  }
  function reportMarkdown(doc) {
    var lines=['# Browser Research Lab — risultati','', '- Sessione: `'+doc.sessionId+'`','- Esportato: '+doc.exportedAt,'- Ambiente: `'+JSON.stringify(doc.environment)+'`','','| Test | Stato | Durata ms |','|---|---:|---:|'];
    (doc.results||[]).forEach(function(r){lines.push('| '+String(r.testId).replace(/\|/g,'\\|')+' | '+r.state+' | '+r.durationMs+' |');});
    (doc.results||[]).forEach(function(r){lines.push('','## '+r.testId,'','Input: `'+JSON.stringify(r.input)+'`','','Osservato:','```json',JSON.stringify(r.observed,null,2),'```','', 'Errore: '+(r.error?JSON.stringify(r.error):'nessuno'),'','Indicatori motore: '+JSON.stringify(r.engineIndicators||[]));});
    return lines.join('\n')+'\n';
  }
  return {cases:cases,caseSource:caseSource,validRelativePath:validRelativePath,safeFilename:safeFilename,fuzz:fuzz,envelope:envelope,runWorker:runWorker,reportMarkdown:reportMarkdown};
}));
