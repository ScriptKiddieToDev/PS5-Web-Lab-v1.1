'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const NodeURL = require('node:url').URL;

class Element {
  constructor(tagName) {
    this.tagName = String(tagName || 'div').toUpperCase();
    this.children = [];
    this.attributes = {};
    this.style = {};
    this.className = '';
    this.disabled = false;
    this.hidden = false;
    this.checked = false;
    this.value = '';
    this.files = [];
    this._text = '';
    this._html = '';
  }
  set textContent(value) { this._text = String(value); this._html = ''; this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent || '').join(''); }
  set innerHTML(value) { this._html = String(value); this._text = ''; this.children = []; }
  get innerHTML() { return this._html; }
  appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
  removeChild(child) { this.children = this.children.filter(item => item !== child); child.parentNode = null; return child; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] || null; }
  querySelectorAll(selector) {
    const found = [];
    function visit(node) {
      for (const child of node.children) {
        if (selector === 'input[type="checkbox"]' && child.tagName === 'INPUT' && child.type === 'checkbox') found.push(child);
        visit(child);
      }
    }
    visit(this);
    return found;
  }
  click() {}
  focus() {}
  select() {}
}

class TestBlob {
  constructor(parts, options) { this.text = parts.join(''); this.type = options && options.type; }
}
const objectUrls = new Map();
const TestURL = {
  createObjectURL(blob) {
    if (TestURL.failNextCreate) { TestURL.failNextCreate = false; throw new TypeError('The string did not match the expected pattern.'); }
    const value = 'blob:test-' + (objectUrls.size + 1); objectUrls.set(value, blob.text); return value;
  },
  revokeObjectURL(value) { objectUrls.delete(value); }
};
TestURL.failNextCreate = false;
class TestWorker {
  constructor(url) {
    if (TestWorker.failNextConstruction) {
      TestWorker.failNextConstruction = false;
      throw new TypeError('The string did not match the expected pattern.');
    }
    this.source = objectUrls.get(url) || '';
    this.terminated = false;
    if (this.source.indexOf('expected-local-worker-error') !== -1) {
      setTimeout(() => {
        if (!this.terminated && this.onerror) this.onerror({ message: 'expected-local-worker-error', filename: 'blob:test', lineno: 1, preventDefault() {} });
      }, 0);
    }
  }
  postMessage(value) {
    setTimeout(() => {
      if (this.terminated) return;
      if (this.source.indexOf('expected-local-worker-error') !== -1) {
        if (this.onerror) this.onerror({ message: 'expected-local-worker-error', filename: 'blob:test', lineno: 1, preventDefault() {} });
      } else if (this.onmessage) this.onmessage({ data: { echo: value, ok: value === 'PS5_WEB_LAB_ECHO' } });
    }, 0);
  }
  terminate() { this.terminated = true; }
}
TestWorker.failNextConstruction = false;

async function main() {
  const root = path.join(__dirname, '..');
  const catalog = JSON.parse(fs.readFileSync(path.join(root, 'data/cve-catalog.json'), 'utf8'));
  const elements = new Map();
  const ids = ['serverState', 'linkState', 'pageOrigin', 'logsPath', 'firmware', 'startScan', 'stopScan', 'exportJson', 'exportMarkdown', 'exportQueue', 'retryLogs', 'logState', 'errorBox', 'progress', 'progressText', 'featureSummary', 'testChecklist', 'results', 'catalogMeta', 'catalogList', 'updateCatalog', 'catalogFile'];
  ids.forEach(id => elements.set(id, new Element(id === 'startScan' || id === 'stopScan' ? 'button' : 'div')));
  const progressBar = new Element('div');
  const document = {
    body: new Element('body'),
    getElementById(id) { return elements.get(id); },
    querySelector(selector) { return selector === '[role="progressbar"]' ? progressBar : null; },
    createElement(tag) {
      const element = new Element(tag);
      if (tag === 'canvas') {
        let context = null;
        element.width = 0; element.height = 0;
        element.getContext = function (type, options) {
          if (options && Object.prototype.hasOwnProperty.call(options, 'alpha')) void options.alpha;
          if (type === 'bitmaprenderer') return null;
          if (type !== '2d') return null;
          if (!context) context = { fillStyle: '', fillRect() {}, getImageData() { return { data: [18, 52, 86, 255] }; } };
          return context;
        };
      }
      return element;
    },
    createTextNode(value) { const node = new Element('#text'); node.textContent = value; return node; }
  };
  const storage = new Map();
  const queuedEvents = Array.from({ length: 19 }, (_, index) => ({
    eventId: 'queued-event-' + String(index + 1).padStart(2, '0'),
    eventType: 'scan_start', sessionId: 'queued-session-0001', clientTime: '2026-10-24T00:00:00Z', payload: { index: index + 1 }
  }));
  storage.set('ps5-web-lab.pending-events.v1', JSON.stringify(queuedEvents));
  const localStorage = { getItem(key) { return storage.has(key) ? storage.get(key) : null; }, setItem(key, value) { storage.set(key, String(value)); }, removeItem(key) { storage.delete(key); } };
  const navigator = { userAgent: 'Mock PS5 WebKit/605.1.15', platform: 'MockPS5', language: 'it-IT', languages: ['it-IT'], onLine: true, cookieEnabled: true, serviceWorker: null, sendBeacon() { return true; } };
  const location = { origin: 'http://127.0.0.1:8000', pathname: '/pages/vulnerability-scanner.html' };
  const received = [];
  const requests = [];
  const diagnostics = [];
  const persistedIds = new Set();
  let loseNextPostResponse = false;
  let backendMode = '404';
  function response(status, body, contentType, parseError) {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get(name) { return name.toLowerCase() === 'content-type' ? contentType || 'application/json; charset=utf-8' : name.toLowerCase() === 'x-ps5-web-lab-version' && body && body.backendVersion ? body.backendVersion : null; } },
      json() { return parseError ? Promise.reject(parseError) : Promise.resolve(body); }
    };
  }
  function fetch(url, options) {
    const requestUrl = new NodeURL(String(url));
    const requestPath = requestUrl.pathname;
    requests.push({ url: requestUrl.origin + requestPath, method: options && options.method || 'GET' });
    if (requestPath === '/api/health') {
      if (backendMode === 'offline') return Promise.reject(new TypeError('The string did not match the expected pattern.'));
      if (backendMode === '404') return Promise.resolve(response(404, { ok: false, error: 'Endpoint non disponibile' }));
      if (backendMode === 'non-json') return Promise.resolve(response(200, '<html>static server</html>', 'text/html; charset=utf-8'));
      if (backendMode === 'invalid-json') return Promise.resolve(response(200, '{broken', 'application/json; charset=utf-8', new SyntaxError('Unexpected token in JSON')));
      const healthy = { ok: true, service: 'PS5-Web-Lab', apiVersion: 1, backendVersion: '1.0.0', logging: true, logsDirectory: '/tmp/ps5-test/logs', postEndpoint: '/api/scan-log' };
      return Promise.resolve(response(backendMode === 'health-202' ? 202 : 200, healthy));
    }
    if (requestPath === '/api/catalog') return Promise.resolve(response(200, catalog));
    if (requestPath === '/api/scan-log' && options && options.method === 'POST') {
      if (backendMode === 'post-404') return Promise.resolve(response(404, { ok: false, error: 'Endpoint POST non disponibile' }));
      const event = JSON.parse(options.body);
      if (persistedIds.has(event.eventId)) return Promise.resolve(response(200, { ok: true, saved: true, duplicate: true, logsDirectory: '/tmp/ps5-test/logs', sessionFile: 'logs/scan-test.jsonl' }));
      persistedIds.add(event.eventId);
      received.push(event);
      if (loseNextPostResponse) { loseNextPostResponse = false; return Promise.reject(new TypeError('Connection reset after simulated disk persistence')); }
      return Promise.resolve(response(201, { ok: true, saved: true, duplicate: false, logsDirectory: '/tmp/ps5-test/logs', sessionFile: 'logs/scan-test.jsonl' }));
    }
    return Promise.reject(new Error('Unexpected test fetch ' + requestPath));
  }
  const window = { navigator, location, localStorage, URL: TestURL, indexedDB: null, addEventListener() {}, sessionStorage: {
    values: new Map(), setItem(key, value) { this.values.set(key, value); }, getItem(key) { return this.values.has(key) ? this.values.get(key) : null; }, removeItem(key) { this.values.delete(key); }
  } };
  const context = { window, document, navigator, location, fetch, console: { error(_label, record) { diagnostics.push(record); } }, Blob: TestBlob, URL: TestURL, Worker: TestWorker, AbortController, Promise, Map, Set, Symbol, Object, Array, Date, Math, Error, JSON, String, Number, RegExp, isFinite, setTimeout, clearTimeout, setInterval, clearInterval, crypto: { getRandomValues(array) { return array; } }, requestAnimationFrame() {} };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(root, 'pages/vulnerability-scanner-core.js'), 'utf8'), context, { filename: 'vulnerability-scanner-core.js' });
  vm.runInContext(fs.readFileSync(path.join(root, 'pages/vulnerability-scanner.js'), 'utf8'), context, { filename: 'vulnerability-scanner.js' });
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /HTTP 404/);
  assert.match(elements.get('errorBox').textContent, /phase/);
  assert.match(elements.get('errorBox').textContent, /\/api\/health/);
  assert.deepEqual(requests[0], { url: 'http://127.0.0.1:8000/api/health', method: 'GET' }, 'health uses the exact same-origin backend route');
  assert.equal(received.length, 0, 'queue is not POSTed to a server that failed the health check');
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'all 19 pending events remain untouched after HTTP 404');
  TestURL.failNextCreate = true;
  const backupOffset = objectUrls.size;
  elements.get('exportQueue').onclick();
  assert.ok(diagnostics.some(record => record && record.phase === 'export-object-url-create' && record.url === null && record.stack), 'blob URL exception is attributed to its precise statement');
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'failed queue export leaves the saved events intact');
  elements.get('exportQueue').onclick();
  const queueBackup = JSON.parse(Array.from(objectUrls.values()).slice(backupOffset)[0]);
  assert.equal(queueBackup.events.length, 19, 'queue export contains all pending events');
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'export does not mutate the saved queue');
  assert.match(elements.get('catalogMeta').textContent, /snapshot locale/);
  const checkboxes = elements.get('testChecklist').querySelectorAll('input[type="checkbox"]');
  assert.equal(checkboxes.length, 15, 'all categories are listed as selectable checks');

  backendMode = 'offline';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /Errore di rete\/fetch/);
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'queue survives offline fetch failure');
  const networkDiagnostic = diagnostics.find(record => record && record.phase === 'health-get:fetch-rejected');
  assert.ok(networkDiagnostic && networkDiagnostic.url === 'http://127.0.0.1:8000/api/health');
  assert.ok(networkDiagnostic.stack && networkDiagnostic.message.indexOf('expected pattern') !== -1);

  backendMode = 'post-404';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('linkState').textContent, /POST non confermato/);
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'POST 404 does not remove any queued event');
  assert.ok(diagnostics.some(record => record && record.phase === 'event-log-post' && record.method === 'POST' && record.status === 404 && record.url === 'http://127.0.0.1:8000/api/scan-log'));

  backendMode = 'non-json';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /Content-Type inatteso/);
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'HTML from a static server is rejected without touching the queue');
  assert.ok(diagnostics.some(record => record && record.phase === 'health-get:response-content-type'));

  backendMode = 'invalid-json';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /Unexpected token in JSON/);
  assert.ok(diagnostics.some(record => record && record.phase === 'health-get:response-json' && record.kind === 'protocol'));
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'invalid JSON also preserves the queue');

  backendMode = 'health-202';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /HTTP 202/);
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'non-200 health is not accepted as backend identity');

  const savedOrigin = location.origin;
  location.origin = 'null';
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('serverState').textContent, /Eccezione JavaScript/);
  assert.ok(diagnostics.some(record => record && record.phase === 'health-get:url-build' && record.kind === 'javascript'));
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'invalid URL is distinct and preserves all events');
  location.origin = savedOrigin;

  backendMode = 'ok';
  loseNextPostResponse = true;
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(received.length, 1, 'the test backend persisted the first event before simulating a lost response');
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 19, 'a lost POST response does not remove the event from the queue');
  const firstStableId = received[0].eventId;
  elements.get('retryLogs').onclick();
  await new Promise(resolve => setTimeout(resolve, 250));
  assert.equal(received.length, 19, 'the recovered backend receives each queued event once');
  assert.equal(requests.filter(request => request.url === 'http://127.0.0.1:8000/api/scan-log' && request.method === 'POST').length, 21, 'one retried event is safely acknowledged as a server-side duplicate');
  assert.equal(received.filter(event => event.eventId === firstStableId).length, 1, 'retry reuses the same event ID and does not create a duplicate record');
  assert.ok(requests.some(request => request.url === 'http://127.0.0.1:8000/api/scan-log' && request.method === 'POST'), 'queued events use the exact same-origin POST route');
  assert.ok(requests.every(request => request.url.indexOf('http://127.0.0.1:8000/') === 0), 'all API traffic uses the page origin');
  assert.equal(new Set(received.map(event => event.eventId)).size, 19, 'queue recovery preserves unique event IDs');
  assert.equal(JSON.parse(storage.get('ps5-web-lab.pending-events.v1')).length, 0, 'only confirmed events are removed from the queue');
  assert.equal(elements.get('errorBox').hidden, true, 'a successful backend recheck clears stale connection diagnostics');

  TestWorker.failNextConstruction = true;
  elements.get('startScan').onclick();
  await new Promise(resolve => setTimeout(resolve, 350));
  const results = elements.get('results').children;
  assert.equal(results.length, 15, 'all selected diagnostics produce visible results');
  const resultEvents = received.filter(event => event.eventType === 'test_result');
  assert.equal(resultEvents.length, 15, 'each diagnostic is posted incrementally');
  assert.equal(new Set(received.map(event => event.eventId)).size, received.length, 'new campaign events also receive unique IDs');
  const workerError = resultEvents.find(event => event.payload.result.id === 'worker.echo').payload.result.error;
  assert.equal(workerError.message, 'The string did not match the expected pattern.');
  assert.equal(workerError.phase, 'worker-constructor', 'the failing worker statement is identified');
  assert.match(workerError.url, /^blob:test-/);
  assert.ok(workerError.stack, 'test errors retain their JavaScript stack');
  assert.ok(diagnostics.some(record => record && record.phase === 'worker-constructor'), 'worker exceptions are logged with phase and URL');
  assert.ok(received.some(event => event.eventType === 'scan_start'));
  assert.ok(received.some(event => event.eventType === 'connectivity_check'));
  assert.ok(received.some(event => event.eventType === 'scan_complete'));
  assert.ok(received.some(event => event.eventType === 'session_summary'));
  for (const event of resultEvents) assert.equal(CoreResultValid(event.payload.result), true);
  assert.equal(elements.get('exportJson').disabled, false);
  assert.equal(elements.get('exportMarkdown').disabled, false);
  assert.equal(elements.get('linkState').className, 'value good');
  const exportOffset = objectUrls.size;
  elements.get('exportJson').onclick();
  elements.get('exportMarkdown').onclick();
  const exported = Array.from(objectUrls.values()).slice(exportOffset);
  assert.equal(exported.length, 2, 'JSON and Markdown downloads are generated');
  assert.equal(JSON.parse(exported[0]).sessionId, received.filter(event => event.eventType === 'scan_start').slice(-1)[0].sessionId);
  assert.match(exported[1], /Fatti osservati/);
  console.log('scanner UI simulation: health, catalog, 15 diagnostics, POST queue, and exports passed');
}

function CoreResultValid(result) {
  const Core = require('../pages/vulnerability-scanner-core.js');
  return Core.validateResult(result).valid;
}

main().catch(error => { console.error(error); process.exitCode = 1; });
