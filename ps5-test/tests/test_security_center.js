'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const ids = ['analysisStatus','metricCanvas','metricScanner','metricSessions','metricResults','collectionStatus','backendErrors','canvasSummary','scannerSummary','comparison','canvasCases','scannerFindings','filterFrom','filterTo','filterTool','filterSession','filterCategory','filterOutcome','timelineCount','eventList','eventDetail','analysisRefresh','exportFilteredJson','exportFilteredCsv'];
const elements = new Map();
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.options = []; this.value = ''; this._textContent = ''; this.className = ''; this.handlers = {}; }
  get textContent() { return this._textContent; }
  set textContent(value) { this._textContent = String(value); if (this._textContent === '') this.children = []; }
  appendChild(child) { this.children.push(child); child.parentNode = this; if (this.tagName === 'select') this.options.push(child); return child; }
  removeChild(child) { this.children = this.children.filter(item => item !== child); return child; }
  remove(index) { this.options.splice(index, 1); }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  click() { if (this.onclick) this.onclick(); if (this.handlers.click) this.handlers.click(); }
}
ids.forEach(id => elements.set(id, new Element('div')));
for (const id of ['filterTool','filterSession','filterCategory','filterOutcome']) {
  const select = new Element('select');
  select.appendChild(Object.assign(new Element('option'), { value: '', textContent: '' }));
  elements.set(id, select);
}
const payloadEvents = [
  { eventId:'canvas-start-01', eventType:'scan_start', sessionId:'canvas-session-01', clientTime:'2026-10-24T01:00:00Z', payload:{} },
  { eventId:'canvas-test-01', eventType:'test_result', sessionId:'canvas-session-01', clientTime:'2026-10-24T01:00:01Z', payload:{ result:{id:'canvas-security-impact.A2-alpha-false-data',caseId:'A2-alpha-false-data',category:'Canvas Security Impact',state:'PASS',startedAt:'2026-10-24T01:00:01Z',runIndex:1}, canvasSecurityImpactRecord:{caseId:'A2-alpha-false-data',runIndex:1,startedAt:'2026-10-24T01:00:01Z'} } },
  { eventId:'canvas-done-01', eventType:'scan_complete', sessionId:'canvas-session-01', clientTime:'2026-10-24T01:00:02Z', payload:{} },
  { eventId:'scanner-start-01', eventType:'scan_start', sessionId:'scanner-session-01', clientTime:'2026-10-24T02:00:00Z', payload:{} },
  { eventId:'scanner-test-01', eventType:'test_result', sessionId:'scanner-session-01', clientTime:'2026-10-24T02:00:01Z', payload:{ result:{id:'<img src=x onerror=alert(1)>',category:'Storage',state:'INCONCLUSIVE',observed:{apiToken:'topsecret',endpoint:'https://local.test/?token=topsecret'}} } },
  { eventId:'canvas-summary-01', eventType:'session_summary', sessionId:'canvas-session-01', clientTime:'2026-10-24T03:00:00Z', payload:{dossier:{results:[{id:'canvas-security-impact.A2-alpha-false-data',caseId:'A2-alpha-false-data',category:'Canvas Security Impact',state:'PASS',startedAt:'2026-10-24T01:00:01Z',runIndex:1},{id:'canvas-security-impact.F-cross-origin',caseId:'F-cross-origin',category:'Canvas Security Impact',state:'SKIPPED',description:'Cross-origin resource did not load',startedAt:'2026-10-24T03:00:00Z',runIndex:1}]}}}
];
let downloaded = [];
class TestBlob { constructor(parts, options) { this.parts = parts; this.type = options.type; downloaded.push(parts.join('')); } }
const context = {
  document: { getElementById: id => elements.get(id), createElement: tag => new Element(tag), body: new Element('body') },
  fetch: url => { assert.equal(url, '/api/analysis-events'); return Promise.resolve({ status:200, headers:{get:()=>'application/json'}, json:()=>Promise.resolve({ok:true,events:payloadEvents,truncated:false}) }); },
  Blob: TestBlob,
  URL: { createObjectURL:()=> 'blob:test', revokeObjectURL:()=>{} },
  Date, JSON, Array, Object, String, Set, isFinite, Promise,
  console
};
vm.runInNewContext(fs.readFileSync('dashboard-security-center.js','utf8'), context);
setImmediate(() => {
  assert.match(elements.get('analysisStatus').textContent, /6 eventi caricati/);
  assert.equal(elements.get('metricSessions').textContent, '1 / 1');
  assert.equal(elements.get('metricResults').textContent, '1 / 0 / 2', 'summary-only skipped results are counted and repeated results are deduplicated');
  assert.match(elements.get('canvasSummary').textContent, /1 sessioni Canvas; 2 risultati deduplicati/);
  assert.equal(elements.get('canvasCases').children.length, 2, 'summary-only canvas cases are included');
  assert.match(elements.get('comparison').textContent, /indipendenti/);
  assert.equal(elements.get('eventList').children.length, 6);
  const maliciousRow = elements.get('eventList').children.find(item => item.children[1].textContent.includes('<img'));
  maliciousRow.click();
  assert.match(elements.get('eventDetail').textContent, /<img src=x/);
  assert.equal(elements.get('eventDetail').innerHTML, undefined, 'event details are assigned as text, never parsed as markup');
  assert.doesNotMatch(elements.get('eventDetail').textContent, /topsecret/, 'secret fields and URL tokens are redacted from details');
  const tool = elements.get('filterTool'); tool.value = 'canvas'; tool.handlers.change();
  assert.equal(elements.get('eventList').children.length, 4, 'tool filter applies to timeline');
  elements.get('exportFilteredJson').click();
  assert.equal(JSON.parse(downloaded[0]).events.length, 4, 'JSON export contains only filtered events');
  elements.get('exportFilteredCsv').click();
  assert.equal(downloaded[1].split('\r\n').length, 5, 'CSV export has one header and filtered rows');
  console.log('security center: API aggregation, incomplete sessions, correlation guard, safe text rendering, filters and filtered exports passed');
});
