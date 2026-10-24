'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { performance } = require('node:perf_hooks');

class Element {
  constructor(tagName) {
    this.tagName = String(tagName || 'div').toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.className = '';
    this.disabled = false;
    this.value = '';
    this.max = 100;
    this.valueAsNumber = 0;
    this.download = '';
    this.href = '';
    this._text = '';
    this._html = '';
  }
  set textContent(value) { this._text = String(value); this._html = ''; this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent || '').join(''); }
  set innerHTML(value) { this._html = String(value); this._text = ''; this.children = []; }
  get innerHTML() { return this._html; }
  appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
  insertBefore(child, before) {
    const index = this.children.indexOf(before);
    if (index < 0) this.children.push(child); else this.children.splice(index, 0, child);
    child.parentNode = this;
    return child;
  }
  removeChild(child) { this.children = this.children.filter(item => item !== child); child.parentNode = null; return child; }
  focus() {}
  select() {}
  click() {}
}

function testCanvas() {
  let context = null;
  let alpha = true;
  let pixel = [0, 0, 0, 0];
  return {
    getContext(type, options) {
      if (type !== '2d') return null;
      if (context) return context;
      if (options && Object.prototype.hasOwnProperty.call(options, 'alpha')) alpha = options.alpha;
      pixel = [0, 0, 0, alpha ? 0 : 255];
      context = {
        fillStyle: '',
        getContextAttributes() { return { alpha }; },
        fillRect() { pixel = String(this.fillStyle).indexOf('197') !== -1 ? [197, 51, 123, 255] : [37, 101, 179, 255]; },
        clearRect() { pixel = [0, 0, 0, alpha ? 0 : 255]; },
        getImageData() { return { data: pixel.slice() }; },
        drawImage() {}
      };
      return context;
    }
  };
}

async function main() {
  const root = path.join(__dirname, '..');
  const elements = new Map();
  const ids = ['sessionId', 'firmware', 'userAgent', 'origin', 'backendState', 'persistenceState', 'logsPath', 'startCampaign', 'stopCampaign', 'retrySend', 'exportJson', 'progress', 'progressLabel', 'resultCount', 'aggregates', 'results', 'campaignError', 'runCrossOrigin', 'crossOriginPort', 'crossOriginState', 'crossOriginDetails', 'exportPreview'];
  ids.forEach(id => elements.set(id, new Element(id === 'firmware' ? 'input' : 'div')));
  elements.get('firmware').value = '14.10';
  elements.get('crossOriginPort').value = '8001';
  const body = new Element('body');
  let canvasCount = 0;
  const document = {
    body,
    getElementById(id) { return elements.get(id); },
    createElement(tag) {
      const el = new Element(tag);
      if (tag === 'canvas') { canvasCount++; Object.assign(el, testCanvas()); el.width = 2; el.height = 2; }
      return el;
    }
  };
  const queueKey = 'ps5-web-lab.canvas-impact.pending-events.v1';
  const legacyQueueKey = 'ps5-web-lab.pending-events.v1';
  const storageValues = new Map();
  const storageAccesses = [];
  const storage = {
    getItem(key) { assert.notEqual(key, legacyQueueKey, 'new controller must not read the old scanner queue'); storageAccesses.push(['get', key]); return storageValues.has(key) ? storageValues.get(key) : null; },
    setItem(key, value) { assert.notEqual(key, legacyQueueKey, 'new controller must not write the old scanner queue'); storageAccesses.push(['set', key]); storageValues.set(key, String(value)); },
    removeItem(key) { assert.notEqual(key, legacyQueueKey, 'new controller must not remove the old scanner queue'); storageAccesses.push(['remove', key]); storageValues.delete(key); }
  };
  const location = { origin: 'http://127.0.0.1:8000', protocol: 'http:', hostname: '127.0.0.1', port: '8000', pathname: '/pages/canvas-security-impact.html' };
  const navigator = { userAgent: 'Mock desktop WebKit; UI simulation only', platform: 'Node test', language: 'it-IT' };
  const events = [];
  const idsSeen = new Set();
  const attempts = [];
  const requests = [];
  let fetchCalls = 0;
  let backendMode = 'offline';
  let postMode = 'success';
  let lastExportText = null;
  const URLMock = {
    createObjectURL(blob) { lastExportText = blob.text; return 'blob:canvas-test-' + (blob.text.length + 1); },
    revokeObjectURL() {}
  };
  class TestBlob {
    constructor(parts, options) { this.text = parts.join(''); this.type = options.type; this.size = this.text.length; }
  }
  function response(status, data, options) {
    options = options || {};
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get(name) { return name.toLowerCase() === 'content-type' ? (options.contentType || 'application/json; charset=utf-8') : null; } },
      json() { return options.rejectJson ? Promise.reject(new SyntaxError('simulated malformed JSON')) : Promise.resolve(data); }
    };
  }
  function fetch(url, options) {
    fetchCalls++;
    requests.push({ url: String(url), method: options && options.method, headers: options && options.headers, body: options && options.body });
    if (String(url).endsWith('/api/health')) {
      assert.equal(String(url), location.origin + '/api/health');
      assert.equal(options.method, 'GET');
      assert.equal(options.headers.Accept, 'application/json');
      if (backendMode === 'offline') return Promise.reject(new TypeError('simulated offline for UI test'));
      if (backendMode === 'health-404') return Promise.resolve(response(404, { ok: false, error: 'missing' }));
      if (backendMode === 'health-html') return Promise.resolve(response(200, {}, { contentType: 'text/html' }));
      if (backendMode === 'health-malformed') return Promise.resolve(response(200, {}, { rejectJson: true }));
      if (backendMode === 'health-wrong-identity') return Promise.resolve(response(200, { ok: true, service: 'static-server', apiVersion: 1, backendVersion: 'test-1', postEndpoint: '/api/scan-log' }));
      return Promise.resolve(response(200, { ok: true, service: 'PS5-Web-Lab', apiVersion: 1, backendVersion: 'test-1', postEndpoint: '/api/scan-log', logsDirectory: '/tmp/ps5-test/logs' }));
    }
    if (String(url).endsWith('/api/scan-log') && options && options.method === 'POST') {
      const event = JSON.parse(options.body);
      assert.equal(String(url), location.origin + '/api/scan-log');
      assert.equal(options.headers['Content-Type'], 'application/json');
      assert.equal(options.headers.Accept, 'application/json');
      attempts.push(event);
      if (postMode === 'network') return Promise.reject(new TypeError('simulated POST network failure'));
      if (postMode === 'http-404') return Promise.resolve(response(404, { ok: false, error: 'missing' }));
      if (postMode === 'http-413') return Promise.resolve(response(413, { ok: false, error: 'too large' }));
      if (postMode === 'http-500') return Promise.resolve(response(500, { ok: false, error: 'disk error' }));
      if (postMode === 'html') return Promise.resolve(response(201, {}, { contentType: 'text/html' }));
      if (postMode === 'malformed-json') return Promise.resolve(response(201, {}, { rejectJson: true }));
      if (postMode === 'not-saved') return Promise.resolve(response(201, { ok: true, saved: false }));
      if (postMode === 'wrong-event-type') return Promise.resolve(response(201, { ok: true, saved: true, eventType: 'scan_complete' }));
      if (postMode === 'network-after-save') {
        if (!idsSeen.has(event.eventId)) { idsSeen.add(event.eventId); events.push(event); }
        return Promise.reject(new TypeError('simulated response lost after persistence'));
      }
      const duplicate = idsSeen.has(event.eventId);
      idsSeen.add(event.eventId);
      if (!duplicate) events.push(event);
      return Promise.resolve(response(duplicate ? 200 : 201, { ok: true, saved: true, duplicate, eventType: event.eventType, logsDirectory: '/tmp/ps5-test/logs' }));
    }
    return Promise.reject(new Error('unexpected fetch URL: ' + url));
  }
  const window = { location, navigator, performance, AbortController, URL: URLMock, Blob: TestBlob, localStorage: storage, addEventListener() {} };
  const context = {
    window, document, location, navigator, performance, AbortController, URL: URLMock, Blob: TestBlob, fetch,
    Promise, Date, Math, Object, Array, String, Number, RegExp, Error, TypeError, JSON, isFinite,
    setTimeout, clearTimeout, console, Image: undefined, localStorage: storage
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(root, 'pages/canvas-security-impact-core.js'), 'utf8'), context, { filename: 'canvas-security-impact-core.js' });
  const controllerSource = fs.readFileSync(path.join(root, 'pages/canvas-security-impact.js'), 'utf8');
  vm.runInContext(controllerSource, context, { filename: 'canvas-security-impact.js' });
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(canvasCount, 0, 'page load does not start a campaign');
  assert.equal(events.length, 0, 'page load does not post scan results');
  assert.match(elements.get('backendState').textContent, /Backend non verificato/);
  assert.match(elements.get('persistenceState').textContent, /memoria/);

  elements.get('startCampaign').onclick();
  const deadline = Date.now() + 6000;
  while ((elements.get('startCampaign').disabled || !events.some(event => event.eventType === 'session_summary') && !JSON.parse(storageValues.get(queueKey) || '{"events":[]}').events.some(event => event.eventType === 'session_summary')) && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(elements.get('startCampaign').disabled, false, 'the run completes and returns controls to the operator');
  assert.equal(canvasCount, 45, 'five repetitions run five A cases and four isolation canvases per repetition');
  assert.equal(events.length, 0, 'offline health retains all events in memory and sends nothing');
  assert.match(elements.get('persistenceState').textContent, /38 eventi non ancora confermati/);
  assert.match(elements.get('persistenceState').textContent, /coda Canvas salvata localmente/);
  const queuedBeforeReload = JSON.parse(storageValues.get(queueKey)).events;
  assert.equal(queuedBeforeReload.length, 38, 'all offline events are persisted before any request is attempted');
  const originalIds = queuedBeforeReload.map(event => event.eventId);
  assert.equal(storageValues.has(legacyQueueKey), false, 'the previous scanner queue remains untouched');
  assert.equal(JSON.parse(lastExportText).pendingEvents.length, 38, 'the local JSON export contains the unconfirmed envelopes as a recovery copy');

  // A new controller instance represents a page reload. The campaign must not rerun.
  backendMode = 'online';
  vm.runInContext(controllerSource, context, { filename: 'canvas-security-impact-reload.js' });
  assert.match(elements.get('persistenceState').textContent, /38 eventi non ancora confermati/);
  const sendDeadline = Date.now() + 6000;
  while (events.length < 38 && Date.now() < sendDeadline) await new Promise(resolve => setTimeout(resolve, 10));
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(canvasCount, 45, 'reload restores delivery state without rerunning any Canvas test');
  postMode = 'success';
  assert.equal(events.filter(event => event.eventType === 'test_result').length, 35, 'five cases, Blob, and isolation each run five times');
  assert.equal(events.filter(event => event.eventType === 'scan_start').length, 1);
  assert.equal(events.filter(event => event.eventType === 'scan_complete').length, 1);
  assert.equal(events.filter(event => event.eventType === 'session_summary').length, 1);
  assert.equal(new Set(events.map(event => event.eventId)).size, events.length, 'all event identifiers are unique');
  assert.deepEqual(events.map(event => event.eventId), originalIds, 'retry preserves original event IDs and sends in FIFO order');
  const summary = events.find(event => event.eventType === 'session_summary');
  assert.ok(events.every(event => Buffer.byteLength(JSON.stringify(event), 'utf8') <= 256 * 1024), 'all client events including session_summary fit the backend byte limit');
  assert.equal(summary.payload.dossier.canvasSecurityImpact.rawResults.length, 35);
  assert.equal(summary.payload.dossier.canvasSecurityImpact.securityImpactDemonstrated, false);
  assert.ok(summary.payload.dossier.results.every(result => ['PASS', 'FAIL', 'ERROR', 'SKIPPED', 'INCONCLUSIVE'].includes(result.state)));
  assert.match(elements.get('persistenceState').textContent, /Tutti gli eventi inviati sono confermati/);
  assert.equal(fetchCalls, events.length + 3, 'initial offline health, campaign health, reload health, and one POST per event');
  assert.equal(requests.filter(request => request.method === 'POST').length, 38);
  assert.ok(requests.every(request => request.url.indexOf(location.origin + '/') === 0), 'health and POST use the page origin');

  const makePending = suffix => ({
    eventId: 'csi-event-regression-' + suffix, eventType: 'scan_start', sessionId: 'csi-regression-session',
    clientTime: new Date().toISOString(), payload: { regression: suffix }
  });
  async function waitUntil(predicate, message) {
    const stopAt = Date.now() + 3000;
    while (!predicate() && Date.now() < stopAt) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(predicate(), message);
  }
  for (const healthFailure of ['offline', 'health-404', 'health-html', 'health-malformed', 'health-wrong-identity']) {
    const queued = makePending('health-' + healthFailure);
    storageValues.set(queueKey, JSON.stringify({ schemaVersion: 1, events: [queued] }));
    backendMode = healthFailure;
    const priorAttempts = attempts.length;
    vm.runInContext(controllerSource, context, { filename: 'canvas-security-impact-health-regression.js' });
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(attempts.length, priorAttempts, healthFailure + ' must not permit POST');
    assert.equal(JSON.parse(storageValues.get(queueKey)).events[0].eventId, queued.eventId, healthFailure + ' must preserve the queued event');
    if (healthFailure === 'offline') assert.match(elements.get('backendState').textContent, /simulated offline/);
    if (healthFailure === 'health-404') assert.match(elements.get('backendState').textContent, /HTTP 404.*GET \/api\/health/);
    if (healthFailure === 'health-html') assert.match(elements.get('backendState').textContent, /Formato health inatteso/);
    if (healthFailure === 'health-malformed') assert.match(elements.get('backendState').textContent, /malformed JSON/);
    if (healthFailure === 'health-wrong-identity') assert.match(elements.get('backendState').textContent, /Identità o versione API/);
    backendMode = 'online'; postMode = 'success';
    elements.get('retrySend').onclick();
    await waitUntil(() => JSON.parse(storageValues.get(queueKey)).events.length === 0, healthFailure + ' recovery drains only after valid health and POST confirmation');
    assert.equal(attempts[attempts.length - 1].eventId, queued.eventId, 'health recovery keeps the stable event ID');
  }

  for (const failedPost of ['network', 'http-404', 'http-413', 'http-500', 'html', 'malformed-json', 'not-saved', 'wrong-event-type', 'network-after-save']) {
    const queued = makePending('post-' + failedPost);
    storageValues.set(queueKey, JSON.stringify({ schemaVersion: 1, events: [queued] }));
    backendMode = 'online'; postMode = failedPost;
    const priorAttempts = attempts.length;
    vm.runInContext(controllerSource, context, { filename: 'canvas-security-impact-post-regression.js' });
    await waitUntil(() => attempts.length > priorAttempts, failedPost + ' must attempt the queued POST');
    await waitUntil(() => elements.get('backendState').textContent.indexOf('Invio non confermato:') === 0, failedPost + ' must report an unconfirmed HTTP or network response');
    assert.equal(JSON.parse(storageValues.get(queueKey)).events[0].eventId, queued.eventId, failedPost + ' must not remove an unconfirmed event');
    if (failedPost === 'http-404') assert.match(elements.get('campaignError').textContent, /HTTP 404.*missing/);
    if (failedPost === 'http-413') assert.match(elements.get('campaignError').textContent, /HTTP 413.*too large/);
    if (failedPost === 'http-500') assert.match(elements.get('campaignError').textContent, /HTTP 500.*disk error/);
    if (failedPost === 'html') assert.match(elements.get('campaignError').textContent, /POST non JSON: Content-Type text\/html/);
    if (failedPost === 'malformed-json') assert.match(elements.get('campaignError').textContent, /JSON|SyntaxError/);
    if (failedPost === 'not-saved') assert.match(elements.get('campaignError').textContent, /non ha confermato la persistenza/);
    postMode = 'success';
    elements.get('retrySend').onclick();
    await waitUntil(() => JSON.parse(storageValues.get(queueKey)).events.length === 0, failedPost + ' retry must remove only after saved:true');
    const matchingAttempts = attempts.filter(event => event.eventId === queued.eventId);
    assert.ok(matchingAttempts.length >= 2, failedPost + ' retry must reuse the same event ID');
    assert.equal(events.filter(event => event.eventId === queued.eventId).length, 1, failedPost + ' must not duplicate persisted events');
  }
  storage.getItem = function () { throw new Error('simulated localStorage denied'); };
  storage.setItem = function () { throw new Error('simulated localStorage denied'); };
  backendMode = 'offline';
  vm.runInContext(controllerSource, context, { filename: 'canvas-security-impact-storage-disabled.js' });
  await new Promise(resolve => setTimeout(resolve, 10));
  elements.get('startCampaign').onclick();
  const fallbackDeadline = Date.now() + 6000;
  while ((elements.get('startCampaign').disabled || elements.get('progressLabel').textContent.indexOf('Campagna completata') !== 0) && Date.now() < fallbackDeadline) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.match(elements.get('persistenceState').textContent, /38 eventi non ancora confermati.*sola memoria volatile/);
  assert.equal(storageValues.has(legacyQueueKey), false, 'no regression test reads or alters the old scanner queue');
  console.log('canvas security impact UI: offline queue survives reload, health gates POST, HTTP/network/JSON errors retain events, stable retries deduplicate, storage fallback works, old scanner queue untouched');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
