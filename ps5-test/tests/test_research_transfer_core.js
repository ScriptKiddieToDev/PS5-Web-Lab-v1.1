'use strict';
const assert = require('node:assert/strict');
const Core = require('../pages/research-transfer-core.js');
const fs = require('node:fs');
const path = require('node:path');

assert.equal(Core.cases().length, 6);
assert.ok(Core.cases().some(x => x.id === 'C3-blob-url-local-origin'));
assert.equal(Core.cases().find(x => x.id === 'D-origin-clean-matrix').profile, 'local-fixture');
assert.equal(Core.validRelativePath(''), true);
assert.equal(Core.validRelativePath('nested/fuzz-case.js'), true);
assert.equal(Core.validRelativePath('../outside.js'), false);
assert.equal(Core.validRelativePath('nested\\outside.js'), false);
assert.equal(Core.safeFilename('canvas-check.js'), true);
assert.equal(Core.safeFilename('../canvas-check.js'), false);
assert.equal(Core.safeFilename('readme.txt'), false);
assert.deepEqual(Core.fuzz(1234, 100), Core.fuzz(1234, 100));
assert.equal(Core.fuzz(1234, 101).length, 100);
assert.notDeepEqual(Core.fuzz(1234, 10), Core.fuzz(1235, 10));

const env = {pageOrigin: 'http://127.0.0.1:8765', userAgent: 'test'};
const row = Core.envelope('session-1', env, 'A-case', {alpha: false}, {pixel: [0, 0, 0, 255]}, null, 2.5, '2026-10-24T00:00:00Z');
for (const key of ['sessionId','testId','timestamp','environment','input','observed','error','durationMs','engineIndicators','evidenceRefs']) assert.ok(key in row);
assert.equal(JSON.stringify(row).includes('localTransferToken'), false);
assert.match(Core.reportMarkdown({sessionId:'session-1',exportedAt:'now',environment:env,results:[row]}), /A-case/);
const ui = fs.readFileSync(path.join(__dirname,'../pages/research-transfer.js'),'utf8');
for (const page of ['active-vulnerability-research-lab.html','canvas-security-impact.html','vulnerability-scanner.html']) {
  const html = fs.readFileSync(path.join(__dirname,'../pages',page),'utf8');
  assert.match(html,/research-transfer-core\.js/);
  assert.match(html,/research-transfer\.js/);
}
assert.match(ui,/X-Transfer-Token/);
assert.match(ui,/\/api\/list/);
assert.match(ui,/\/api\/file/);
assert.match(ui,/\/api\/upload/);
assert.match(ui,/sandbox','allow-scripts/);
assert.match(ui,/explicitUserConfirmation:true/);
assert.match(ui,/setTimeout\(function\(\).*timeoutMs/s);
assert.doesNotMatch(ui,/localTransferToken[^\n]{0,40}\?token=/);

class FakeBlob { constructor(parts) { this.parts=parts; } }
const revoked=[];
const fakeURL = {createObjectURL() { return 'blob:runner'; },revokeObjectURL(url) { revoked.push(url); }};
class ReplyWorker {
  constructor() { queueMicrotask(() => this.onmessage && this.onmessage({data:{ok:true,value:{answer:42},logs:[]}})); }
  terminate() { this.terminated=true; }
}
class HangingWorker { constructor() { HangingWorker.last=this; } terminate() { this.terminated=true; } }
async function run() {
  const success = await Core.runWorker('return 42', 100, {Worker:ReplyWorker, Blob:FakeBlob, URL:fakeURL}).promise;
  assert.equal(success.data.value.answer, 42);
  const timeoutJob = Core.runWorker('while(true){}', 15, {Worker:HangingWorker, Blob:FakeBlob, URL:fakeURL});
  const timeout = await timeoutJob.promise;
  assert.equal(timeout.timedOut, true);
  assert.equal(HangingWorker.last.terminated, true, 'timeout terminates the worker');
  const stoppedJob = Core.runWorker('while(true){}', 1000, {Worker:HangingWorker, Blob:FakeBlob, URL:fakeURL});
  stoppedJob.stop();
  const stopped = await stoppedJob.promise;
  assert.equal(stopped.stopped, true);
  assert.equal(HangingWorker.last.terminated, true, 'explicit stop terminates the worker');
  assert.equal(revoked.length, 3, 'worker script Blob URLs are revoked on success, timeout, and stop');
}
run().then(() => console.log('research transfer core: case metadata, path checks, deterministic cap, export envelope, worker timeout/stop passed'));
