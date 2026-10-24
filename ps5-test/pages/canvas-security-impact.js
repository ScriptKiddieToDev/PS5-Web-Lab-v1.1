(function () {
  'use strict';

  var Core = window.CanvasSecurityImpactCore;
  var RUNS_PER_CAMPAIGN = 5;
  var QUEUE_KEY = 'ps5-web-lab.canvas-impact.pending-events.v1';
  var sessionId = makeId('csi');
  var sessionStartedAt = null;
  var sessionFrozen = false;
  var frozenFirmware = null;
  var runIndex = 0;
  var running = false;
  var stopRequested = false;
  var eventCounter = 0;
  var records = [];
  var runs = [];
  var queueStorageAvailable = true;
  var queueStorageError = null;
  var queueStorageCorrupt = false;
  var pendingEvents = loadPendingEvents();
  var hasDeliveryActivity = pendingEvents.length > 0;
  var sending = false;
  var backend = { verified: false, health: null, url: null, logPath: null };
  var activeRunStartedAt = null;
  var currentProgress = 0;
  var totalProgress = RUNS_PER_CAMPAIGN * 7;
  var crossOriginTimer = null;
  var el = {
    sessionId: document.getElementById('sessionId'), firmware: document.getElementById('firmware'), userAgent: document.getElementById('userAgent'), origin: document.getElementById('origin'),
    backend: document.getElementById('backendState'), persistence: document.getElementById('persistenceState'), logsPath: document.getElementById('logsPath'),
    start: document.getElementById('startCampaign'), stop: document.getElementById('stopCampaign'), retry: document.getElementById('retrySend'), export: document.getElementById('exportJson'),
    progress: document.getElementById('progress'), progressLabel: document.getElementById('progressLabel'), resultCount: document.getElementById('resultCount'),
    aggregates: document.getElementById('aggregates'), results: document.getElementById('results'), error: document.getElementById('campaignError'),
    crossOriginButton: document.getElementById('runCrossOrigin'), crossOriginPort: document.getElementById('crossOriginPort'), crossOriginState: document.getElementById('crossOriginState'),
    crossOriginDetails: document.getElementById('crossOriginDetails'), exportPreview: document.getElementById('exportPreview')
  };

  function now() { return new Date().toISOString(); }
  function makeId(prefix) {
    return prefix + '-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 0x7fffffff).toString(36);
  }
  function sessionMeta() {
    return {
      sessionId: sessionId,
      startedAt: sessionStartedAt || now(),
      declaredFirmware: sessionFrozen ? frozenFirmware : (el.firmware.value.trim() || null),
      userAgent: navigator.userAgent || null,
      origin: location.origin || null,
      platform: navigator.platform || null
    };
  }
  function runtime() {
    return { document: document, Blob: typeof Blob === 'function' ? Blob : null, performance: window.performance || null, now: now };
  }
  function isPendingEvent(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value) &&
      typeof value.eventId === 'string' && /^[A-Za-z0-9_-]{8,96}$/.test(value.eventId) &&
      typeof value.eventType === 'string' && /^(scan_start|test_result|connectivity_check|transmission_error|scan_interrupted|scan_complete|session_summary)$/.test(value.eventType) &&
      typeof value.sessionId === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(value.sessionId) &&
      typeof value.clientTime === 'string' && !!value.payload && typeof value.payload === 'object' && !Array.isArray(value.payload);
  }
  function loadPendingEvents() {
    try {
      var storage = window.localStorage;
      if (!storage || typeof storage.getItem !== 'function') throw new Error('localStorage non disponibile');
      var serialized = storage.getItem(QUEUE_KEY);
      if (!serialized) { queueStorageAvailable = true; queueStorageError = null; return []; }
      var parsed;
      try { parsed = JSON.parse(serialized); }
      catch (parseError) { queueStorageCorrupt = true; throw new Error('Coda Canvas locale non interpretabile; il contenuto salvato non è stato sovrascritto.'); }
      if (!parsed || parsed.schemaVersion !== 1 || !Array.isArray(parsed.events) || !parsed.events.every(isPendingEvent)) {
        queueStorageCorrupt = true;
        throw new Error('Coda Canvas locale non valida; il contenuto salvato non è stato sovrascritto.');
      }
      queueStorageAvailable = true;
      queueStorageError = null;
      return parsed.events;
    } catch (error) {
      queueStorageAvailable = false;
      queueStorageError = String(error && error.message || error);
      return [];
    }
  }
  function persistPendingEvents() {
    try {
      if (queueStorageCorrupt) throw new Error('Coda Canvas locale non valida; esportare o esaminare il contenuto prima di sostituirla.');
      var storage = window.localStorage;
      if (!storage || typeof storage.setItem !== 'function') throw new Error('localStorage non disponibile');
      storage.setItem(QUEUE_KEY, JSON.stringify({ schemaVersion: 1, events: pendingEvents }));
      queueStorageAvailable = true;
      queueStorageError = null;
      return true;
    } catch (error) {
      queueStorageAvailable = false;
      queueStorageError = String(error && error.message || error);
      return false;
    }
  }
  function safeText(node, value) { if (node) node.textContent = String(value === undefined || value === null ? '' : value); }
  function showError(message) {
    if (!message) { el.error.className = 'errorbox hidden'; el.error.textContent = ''; return; }
    el.error.className = 'errorbox';
    el.error.textContent = String(message);
  }
  function errorDetails(error, phase, url, method) {
    return {
      phase: phase,
      url: url || null,
      method: method || null,
      name: error && error.name ? String(error.name) : 'Error',
      message: error && error.message ? String(error.message) : String(error),
      stack: error && error.stack ? String(error.stack) : null
    };
  }
  function healthUrl() {
    var origin = window.location && window.location.origin;
    if (!origin || origin === 'null') throw new Error('Origin HTTP non valido: aprire questa pagina dal server locale.');
    return origin + '/api/health';
  }
  function timedFetch(url, options, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var settled = false;
      var controller = typeof window.AbortController === 'function' ? new window.AbortController() : null;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        if (controller) { try { controller.abort(); } catch (ignore) {} }
        var error = new Error('Timeout HTTP dopo ' + timeoutMs + ' ms'); error.name = 'TimeoutError';
        reject(error);
      }, timeoutMs);
      var requestOptions = options || {};
      if (controller) requestOptions.signal = controller.signal;
      try {
        fetch(url, requestOptions).then(function (response) {
          if (settled) return;
          settled = true; clearTimeout(timer); resolve(response);
        }, function (error) {
          if (settled) return;
          settled = true; clearTimeout(timer); reject(error);
        });
      } catch (error) {
        if (!settled) { settled = true; clearTimeout(timer); reject(error); }
      }
    });
  }
  function verifyBackend() {
    var url;
    try { url = healthUrl(); }
    catch (error) {
      backend.verified = false; backend.health = null; backend.url = null;
      safeText(el.backend, 'Origin non valido: ' + error.message); el.backend.className = 'value bad';
      return Promise.resolve(false);
    }
    backend.url = url;
    safeText(el.backend, 'Verifica GET /api/health…'); el.backend.className = 'value';
    return timedFetch(url, { method: 'GET', cache: 'no-store', headers: { Accept: 'application/json' } }, 5000).then(function (response) {
      if (response.status !== 200) throw new Error('HTTP ' + response.status + ' su GET /api/health');
      var contentType = response.headers && response.headers.get ? response.headers.get('Content-Type') : '';
      if (!/application\/json/i.test(contentType || '')) throw new Error('Formato health inatteso: Content-Type ' + (contentType || 'assente'));
      return response.json().then(function (health) {
        if (!health || health.ok !== true || health.service !== 'PS5-Web-Lab' || health.apiVersion !== 1 || !health.backendVersion || health.postEndpoint !== '/api/scan-log') {
          throw new Error('Identità o versione API del backend non valida.');
        }
        backend.verified = true; backend.health = health;
        backend.logPath = health.logsDirectory || 'logs/ sul server';
        safeText(el.backend, 'PS5-Web-Lab verificato · API ' + health.apiVersion + ' · versione ' + health.backendVersion);
        el.backend.className = 'value good';
        safeText(el.logsPath, 'Destinazione confermata dal backend: ' + backend.logPath);
        pumpEvents();
        return true;
      });
    }).catch(function (error) {
      backend.verified = false; backend.health = null;
      safeText(el.backend, 'Backend non verificato: ' + String(error && error.message || error));
      el.backend.className = 'value warn';
      if (error && error.stack) showError('Fase: health-get\nMetodo: GET\nURL: ' + url + '\n' + error.name + ': ' + error.message + '\n' + error.stack);
      return false;
    });
  }
  function newEvent(type, payload) {
    eventCounter++;
    return {
      eventId: 'csi-event-' + Date.now().toString(36) + '-' + eventCounter.toString(36) + '-' + Math.floor(Math.random() * 0x7fffffff).toString(36),
      eventType: type,
      sessionId: sessionId,
      clientTime: now(),
      payload: payload
    };
  }
  function enqueueEvent(type, payload) {
    var envelope = newEvent(type, payload);
    pendingEvents.push(envelope);
    hasDeliveryActivity = true;
    persistPendingEvents();
    updatePersistence();
    if (backend.verified) pumpEvents();
    return envelope;
  }
  function updatePersistence() {
    var storageNote = queueStorageAvailable ? 'coda Canvas salvata localmente' : 'solo memoria volatile: esportare prima di chiudere' + (queueStorageError ? ' (' + queueStorageError + ')' : '');
    if (backend.verified && pendingEvents.length === 0) {
      if (hasDeliveryActivity) safeText(el.persistence, 'Tutti gli eventi inviati sono confermati dal server' + (queueStorageAvailable ? '' : ' · ' + storageNote));
      else safeText(el.persistence, 'Backend verificato · nessun risultato inviato' + (queueStorageAvailable ? '' : ' · ' + storageNote));
      el.persistence.className = queueStorageAvailable ? 'value good' : 'value warn';
    } else if (pendingEvents.length) {
      safeText(el.persistence, pendingEvents.length + ' eventi non ancora confermati · ' + storageNote); el.persistence.className = 'value warn';
    } else {
      safeText(el.persistence, 'Risultati in memoria · nessun evento inviato' + (queueStorageAvailable ? '' : ' · ' + storageNote)); el.persistence.className = queueStorageAvailable ? 'value' : 'value warn';
    }
  }
  function removePending(eventId) {
    for (var i = 0; i < pendingEvents.length; i++) {
      if (pendingEvents[i].eventId === eventId) { pendingEvents.splice(i, 1); persistPendingEvents(); return true; }
    }
    return false;
  }
  function responseErrorText(response) {
    var status = response && response.status;
    var contentType = response && response.headers && response.headers.get ? response.headers.get('Content-Type') : '';
    if (/application\/json/i.test(contentType || '') && response && typeof response.json === 'function') {
      try {
        return response.json().then(function (body) {
          var detail = body && typeof body.error === 'string' ? body.error : JSON.stringify(body);
          return 'HTTP ' + status + ' su POST /api/scan-log' + (detail ? ': ' + String(detail).slice(0, 800) : '');
        }, function (error) {
          return 'HTTP ' + status + ' su POST /api/scan-log; risposta JSON non leggibile: ' + String(error && error.message || error);
        });
      } catch (error) {
        return Promise.resolve('HTTP ' + status + ' su POST /api/scan-log; errore lettura risposta: ' + String(error && error.message || error));
      }
    }
    return Promise.resolve('HTTP ' + status + ' su POST /api/scan-log; Content-Type inatteso: ' + (contentType || 'assente'));
  }
  function pumpEvents() {
    if (sending || !backend.verified || !pendingEvents.length) { updatePersistence(); return; }
    sending = true;
    var item = pendingEvents[0];
    var url = location.origin + '/api/scan-log';
    timedFetch(url, { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(item) }, 8000).then(function (response) {
      if (response.status !== 200 && response.status !== 201) {
        return responseErrorText(response).then(function (message) { var httpError = new Error(message); httpError.name = 'HttpError'; throw httpError; });
      }
      var contentType = response.headers && response.headers.get ? response.headers.get('Content-Type') : '';
      if (!/application\/json/i.test(contentType || '')) throw new Error('POST non JSON: Content-Type ' + (contentType || 'assente'));
      return response.json().then(function (reply) {
        if (!reply || reply.ok !== true || reply.saved !== true || reply.eventType !== item.eventType) throw new Error('Il server non ha confermato la persistenza dell’evento ' + item.eventId + '.');
        if (reply.logsDirectory) { backend.logPath = reply.logsDirectory; safeText(el.logsPath, 'Log salvati dal server in: ' + reply.logsDirectory); }
        removePending(item.eventId);
        updatePersistence();
      });
    }).catch(function (error) {
      backend.verified = false;
      safeText(el.backend, 'Invio non confermato: ' + String(error && error.message || error)); el.backend.className = 'value warn';
      if (error && error.stack) showError('Fase: event-log-post\nMetodo: POST\nURL: ' + url + '\nEvent ID: ' + item.eventId + '\n' + error.name + ': ' + error.message + '\n' + error.stack);
    }).then(function () {
      sending = false;
      updatePersistence();
      if (backend.verified && pendingEvents.length) pumpEvents();
    });
  }
  function appendRecord(record) {
    records.push(record);
    renderRecord(record);
    safeText(el.resultCount, records.length + ' risultati raw · ' + pendingEvents.length + ' eventi in memoria');
    var scannerResult = Core.toScannerResult(record);
    enqueueEvent('test_result', { result: scannerResult, canvasSecurityImpactRecord: record });
  }
  function renderRecord(record) {
    if (records.length === 1) el.results.textContent = '';
    var details = document.createElement('details'); details.className = 'result';
    var summary = document.createElement('summary');
    summary.textContent = record.caseId + ' · run ' + record.runIndex + ' · ' + record.interpretation.classification + ' · esecuzione ' + record.raw.executionStatus;
    details.appendChild(summary);
    var explanation = document.createElement('p'); explanation.textContent = record.interpretation.explanation || ''; details.appendChild(explanation);
    var rawTitle = document.createElement('h3'); rawTitle.textContent = 'Dati grezzi'; details.appendChild(rawTitle);
    var pre = document.createElement('pre'); pre.textContent = JSON.stringify(record.raw, null, 2); details.appendChild(pre);
    var expectedTitle = document.createElement('h3'); expectedTitle.textContent = 'Atteso e limitazioni'; details.appendChild(expectedTitle);
    var expected = document.createElement('pre'); expected.textContent = JSON.stringify({ expected: record.interpretation.expected, securityImpact: record.interpretation.securityImpact, limitations: record.interpretation.limitations, references: record.interpretation.references }, null, 2); details.appendChild(expected);
    el.results.insertBefore(details, el.results.firstChild);
  }
  function caseRecords(caseId) { return records.filter(function (record) { return record.caseId === caseId; }); }
  function renderAggregates() {
    var cases = Core.getCases();
    var blob = caseRecords('C-blob-dictionary');
    var items = [];
    for (var i = 0; i < cases.length; i++) items.push(Core.aggregateCase(cases[i].id, caseRecords(cases[i].id), blob));
    items.push(Core.aggregateBlob(blob));
    var isolation = Core.aggregateIsolation(caseRecords('E-canvas-isolation'));
    items.push({ caseId: isolation.caseId, classification: isolation.classification, metrics: isolation.metrics, explanation: isolation.explanation, patternMatchesInOtherCanvas: isolation.patternMatchesInOtherCanvas });
    if (!records.length) { el.aggregates.innerHTML = '<p class="muted">Le statistiche appariranno dopo una campagna.</p>'; return items; }
    var table = document.createElement('table');
    var head = document.createElement('thead'); head.innerHTML = '<tr><th>Caso</th><th>Classificazione</th><th>Esecuzioni</th><th>Getter letti / non letti</th><th>Concordanza</th><th>Eccezioni</th></tr>'; table.appendChild(head);
    var body = document.createElement('tbody');
    for (i = 0; i < items.length; i++) {
      var item = items[i]; var row = document.createElement('tr');
      var values = [item.caseId, item.classification, item.metrics.totalExecutions,
        item.metrics.getterReadExecutions + ' / ' + item.metrics.getterNotReadExecutions,
        item.metrics.concordantPercentage + '%', item.metrics.exceptionCount];
      for (var j = 0; j < values.length; j++) { var cell = document.createElement('td'); cell.textContent = String(values[j]); row.appendChild(cell); }
      body.appendChild(row);
    }
    table.appendChild(body); el.aggregates.textContent = ''; el.aggregates.appendChild(table);
    return items;
  }
  function progress(complete, label) {
    currentProgress = complete;
    el.progress.max = totalProgress;
    el.progress.value = Math.min(complete, totalProgress);
    safeText(el.progressLabel, label);
  }
  function pauseUi() { return new Promise(function (resolve) { setTimeout(resolve, 0); }); }
  function campaignRecord(runNumber, started, completed, interrupted, startOffset) {
    return { runIndex: runNumber, startedAt: started, completedAt: completed, interrupted: interrupted, firstRecordIndex: startOffset, resultCount: records.length - startOffset };
  }
  function resultEventResult(record) { return Core.toScannerResult(record); }
  function makeDossier(aggregateList, overallState) {
    var session = sessionMeta();
    session.sessionId = sessionId; session.startedAt = sessionStartedAt; session.overallState = overallState;
    var dossier = Core.buildDossier(session, runs, records, aggregateList);
    dossier.overallState = overallState;
    dossier.completedAt = now();
    return dossier;
  }
  function startCampaign() {
    if (running) return;
    freezeSessionMetadata();
    running = true; stopRequested = false; runIndex++; activeRunStartedAt = now();
    showError(''); el.start.disabled = true; el.stop.disabled = false; el.crossOriginButton.disabled = true;
    currentProgress = 0; totalProgress = RUNS_PER_CAMPAIGN * 7; progress(0, 'Verifica backend; poi iniziano i controlli locali…');
    verifyBackend().then(function () {
      var meta = sessionMeta();
      enqueueEvent('scan_start', { startedAt: activeRunStartedAt, declaredFirmware: meta.declaredFirmware, environment: { userAgent: meta.userAgent, platform: meta.platform, origin: meta.origin }, selectedTests: Core.getCases().map(function (item) { return item.id; }).concat(['C-blob-dictionary', 'E-canvas-isolation']), runIndex: runIndex, test: 'canvas-security-impact' });
      return executeCampaign(runIndex, activeRunStartedAt);
    }).catch(function (error) {
      showError('Fase: campaign-run\n' + errorDetails(error, 'campaign-run').name + ': ' + errorDetails(error, 'campaign-run').message + '\n' + (error.stack || ''));
      finishCampaign(runIndex, activeRunStartedAt, true);
    });
  }
  function executeCampaign(activeRunIndex, started) {
    var startOffset = records.length;
    var caseDefs = Core.getCases();
    var sequence = 0;
    function executeNext() {
      if (stopRequested || sequence >= totalProgress) {
        finishCampaign(activeRunIndex, started, stopRequested, startOffset);
        return Promise.resolve();
      }
      var repetition = Math.floor(sequence / 7) + 1;
      var slot = sequence % 7;
      var record;
      try {
        if (slot < 5) record = Core.runCanvasCase(caseDefs[slot].id, runtime(), sessionMeta(), activeRunIndex);
        else if (slot === 5) record = Core.runBlobControl(runtime(), sessionMeta(), activeRunIndex);
        else record = Core.runIsolationCheck(runtime(), sessionMeta(), activeRunIndex);
      } catch (error) {
        record = createUnexpectedErrorRecord(sequence, activeRunIndex, error);
      }
      record.runIndex = activeRunIndex;
      record.raw.input.repetition = repetition;
      record.raw.input.distinctCanvasPerCase = true;
      appendRecord(record);
      sequence++; currentProgress++;
      progress(currentProgress, 'Ripetizione ' + repetition + ' di ' + RUNS_PER_CAMPAIGN + ' · controllo ' + sequence + ' di ' + totalProgress);
      renderAggregates();
      return pauseUi().then(executeNext);
    }
    return executeNext();
  }
  function createUnexpectedErrorRecord(sequence, activeRunIndex, error) {
    var at = now();
    return {
      schemaVersion: 1, sessionId: sessionId, testId: 'canvas-security-impact.unexpected-' + sequence, caseId: 'unexpected-' + sequence,
      runIndex: activeRunIndex, startedAt: at, completedAt: now(), declaredFirmware: el.firmware.value.trim() || null,
      userAgent: navigator.userAgent || null, origin: location.origin || null,
      raw: { input: { sequence: sequence }, observed: {}, exceptions: [errorDetails(error, 'test-dispatch')], executionStatus: 'ERROR', durationMs: 0 },
      interpretation: { classification: 'ERROR', expected: {}, explanation: 'Eccezione non gestita dal dispatcher; record parziale conservato.', securityImpact: 'Non determinato.', limitations: ['Errore tecnico del test.'], references: [] }
    };
  }
  function finishCampaign(activeRunIndex, started, interrupted, startOffset) {
    if (typeof startOffset !== 'number') startOffset = records.length;
    var completed = now();
    runs.push(campaignRecord(activeRunIndex, started, completed, interrupted, startOffset));
    var aggregates = renderAggregates();
    if (interrupted) enqueueEvent('scan_interrupted', { interruptedAt: completed, runIndex: activeRunIndex, resultCount: records.length - startOffset });
    else enqueueEvent('scan_complete', { completedAt: completed, runIndex: activeRunIndex, resultCount: records.length - startOffset });
    var dossier = makeDossier(aggregates, interrupted ? 'INTERRUPTED' : 'COMPLETED');
    enqueueEvent('session_summary', { dossier: dossier, canvasSecurityImpactExport: Core.exportReport(sessionMeta(), runs, records, aggregates, pendingEvents.length) });
    running = false; stopRequested = false; el.start.disabled = false; el.stop.disabled = true; el.crossOriginButton.disabled = false;
    progress(currentProgress, interrupted ? 'Campagna interrotta; i risultati già raccolti restano disponibili.' : 'Campagna completata; ogni caso è stato eseguito cinque volte.');
    safeText(el.resultCount, records.length + ' risultati raw · ' + pendingEvents.length + ' eventi da confermare');
    updatePersistence();
    downloadExport();
  }
  function stopCampaign() { if (running) { stopRequested = true; safeText(el.progressLabel, 'Interruzione richiesta; termina il controllo corrente…'); } }

  function freezeSessionMetadata() {
    if (sessionFrozen) return;
    sessionStartedAt = now();
    frozenFirmware = el.firmware.value.trim() || null;
    sessionFrozen = true;
    el.firmware.disabled = true;
  }

  function makeCrossOriginRecord(port, sourceUrl, observed, exceptions, executionStatus, classification, explanation) {
    var timestamp = now();
    return {
      schemaVersion: 1, sessionId: sessionId, testId: 'canvas-security-impact.F-cross-origin', caseId: 'F-cross-origin', runIndex: Math.max(1, runIndex),
      startedAt: timestamp, completedAt: now(), declaredFirmware: el.firmware.value.trim() || null, userAgent: navigator.userAgent || null, origin: location.origin || null,
      raw: { input: { resourceUrl: sourceUrl, requestedOrigin: sourceUrl ? sourceUrl.split('/').slice(0, 3).join('/') : null, helperPort: port, crossOriginMode: 'img; crossOrigin unset', corsAttributeSet: false }, observed: observed, exceptions: exceptions, executionStatus: executionStatus, durationMs: 0 },
      interpretation: { classification: classification, expected: { getImageData: 'SecurityError', toDataURL: 'SecurityError', responseHeaderAccessControlAllowOrigin: 'absent' }, explanation: explanation, securityImpact: classification === 'SECURITY_BOUNDARY_ANOMALY_PENDING_REPRODUCTION' ? 'Possibile anomalia di barriera; non confermata. Nessun altro test di lettura verrà eseguito automaticamente.' : 'Non dimostrato.', limitations: ['Gli header HTTP cross-origin non sono leggibili dalla pagina; verificare log del server ausiliario e curl sul PC.', 'Questo test è indipendente dall’anomalia alpha F-01.'], references: ['https://html.spec.whatwg.org/multipage/canvas.html#security-with-canvas-elements'] }
    };
  }
  function runCrossOrigin() {
    if (running || crossOriginTimer) return;
    var portText = el.crossOriginPort.value.trim();
    if (!/^\d{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) {
      safeText(el.crossOriginState, 'ERROR — porta non valida'); el.crossOriginState.className = 'bad';
      showError('Fase: cross-origin-port-validate\nInserire una porta TCP valida fra 1 e 65535.'); return;
    }
    var pageOrigin = location.origin || '';
    var sourceOrigin = location.protocol + '//' + location.hostname + ':' + Number(portText);
    var defaultPagePort = location.port || (location.protocol === 'https:' ? '443' : '80');
    if (!pageOrigin || Number(defaultPagePort) === Number(portText)) {
      safeText(el.crossOriginState, 'NOT_RUN — la porta non crea un origin distinto'); el.crossOriginState.className = 'warn'; return;
    }
    freezeSessionMetadata();
    var sourceUrl = sourceOrigin + '/canvas-cross-origin.png?probe=' + Date.now().toString(36);
    if (typeof Image !== 'function') {
      var unavailable = makeCrossOriginRecord(Number(portText), sourceUrl, { loadStatus: 'unavailable', crossOriginVerified: true }, [], 'SKIPPED', 'SKIPPED', 'NOT_RUN: Image non disponibile.');
      appendRecord(unavailable); safeText(el.crossOriginState, 'SKIPPED — Image non disponibile'); return;
    }
    el.crossOriginButton.disabled = true;
    safeText(el.crossOriginState, 'Richiesta immagine alla seconda origine…'); el.crossOriginState.className = 'muted';
    var image = new Image();
    var settled = false;
    crossOriginTimer = setTimeout(function () {
      if (settled) return;
      settled = true; image.onload = null; image.onerror = null;
      finishUnavailable('timeout', 'Timeout durante il caricamento della risorsa; stato NOT_RUN.');
    }, 8000);
    function finishUnavailable(kind, message) {
      clearTimeout(crossOriginTimer); crossOriginTimer = null; el.crossOriginButton.disabled = false;
      var record = makeCrossOriginRecord(Number(portText), sourceUrl, {
        loadStatus: kind, crossOriginVerified: true, imageLoadError: message,
        responseHeadersAccessibleFromPage: false, headerVerification: 'Richiesta verificabile dal log del server ausiliario e da curl sul PC.'
      }, [], 'SKIPPED', 'SKIPPED', 'NOT_RUN: la seconda origine non ha fornito una risorsa caricabile. Nessun risultato di sicurezza viene inferito.');
      appendRecord(record); safeText(el.crossOriginState, 'NOT_RUN — risorsa non raggiungibile (' + kind + ')'); el.crossOriginState.className = 'warn';
      safeText(el.crossOriginDetails, message + ' Avvia il server ausiliario su questa porta e riprova.');
    }
    image.onload = function () {
      if (settled) return;
      settled = true; clearTimeout(crossOriginTimer); crossOriginTimer = null;
      var observed = {
        loadStatus: 'loaded', crossOriginVerified: sourceOrigin !== pageOrigin,
        pageOrigin: pageOrigin, requestedOrigin: sourceOrigin, requestedUrl: sourceUrl,
        imageNaturalWidth: image.naturalWidth || image.width || null, imageNaturalHeight: image.naturalHeight || image.height || null,
        corsAttributeSet: false, responseHeadersAccessibleFromPage: false,
        headerVerification: 'Confermare nel terminale del server ausiliario: Host sulla porta configurata, Content-Type image/png e nessun Access-Control-Allow-Origin.'
      };
      var exceptions = [];
      var canvas; var context;
      try {
        canvas = document.createElement('canvas'); canvas.width = 2; canvas.height = 2;
        context = canvas.getContext('2d');
        if (!context) throw new Error('Contesto Canvas 2D non disponibile.');
        context.drawImage(image, 0, 0, 2, 2);
      } catch (error) {
        exceptions.push(errorDetails(error, 'cross-origin-draw', sourceUrl, 'drawImage'));
        observed.loadStatus = 'loaded-draw-failed';
        var drawRecord = makeCrossOriginRecord(Number(portText), sourceUrl, observed, exceptions, 'ERROR', 'ERROR', 'Errore tecnico durante il disegno della risorsa cross-origin.');
        appendRecord(drawRecord); safeText(el.crossOriginState, 'ERROR — drawImage non completato'); el.crossOriginState.className = 'bad';
        el.crossOriginButton.disabled = false; return;
      }
      try { observed.getImageDataSucceeded = !!context.getImageData(0, 0, 1, 1); observed.getImageDataError = null; }
      catch (readError) { observed.getImageDataSucceeded = false; observed.getImageDataError = readError && readError.name || 'Error'; exceptions.push(errorDetails(readError, 'cross-origin-getImageData', sourceUrl, 'getImageData')); }
      if (observed.getImageDataSucceeded) {
        observed.toDataURLAttempted = false;
        observed.stopReason = 'getImageData returned data; no further canvas read was attempted.';
      } else {
        observed.toDataURLAttempted = true;
        try { observed.toDataURLSucceeded = typeof canvas.toDataURL === 'function' ? typeof canvas.toDataURL() === 'string' : false; observed.toDataURLError = null; }
        catch (urlError) { observed.toDataURLSucceeded = false; observed.toDataURLError = urlError && urlError.name || 'Error'; exceptions.push(errorDetails(urlError, 'cross-origin-toDataURL', sourceUrl, 'toDataURL')); }
      }
      var outcome = Core.runCrossOriginInterpretation(observed, 'PASS');
      var execution = outcome.classification === 'ERROR' ? 'ERROR' : outcome.classification === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PASS';
      var record = makeCrossOriginRecord(Number(portText), sourceUrl, observed, exceptions, execution, outcome.classification, outcome.explanation);
      appendRecord(record);
      if (outcome.classification === 'SECURITY_BOUNDARY_ANOMALY_PENDING_REPRODUCTION') {
        safeText(el.crossOriginState, outcome.classification + ' — fermato dopo il primo esito'); el.crossOriginState.className = 'bad';
        safeText(el.crossOriginDetails, 'Salva subito l’export e conserva il log del server ausiliario. Non ripetere automaticamente il test e non tentare bypass.');
      } else {
        safeText(el.crossOriginState, outcome.classification); el.crossOriginState.className = outcome.classification === 'EXPECTED' ? 'good' : 'warn';
        safeText(el.crossOriginDetails, outcome.explanation + ' Gli header della risposta non sono accessibili da JavaScript sulla pagina cross-origin.');
      }
      el.crossOriginButton.disabled = false;
    };
    image.onerror = function () {
      if (settled) return; settled = true; finishUnavailable('network-error', 'Evento error dell’immagine: origine=' + sourceOrigin + ', URL=' + sourceUrl + '.');
    };
    try { image.src = sourceUrl; }
    catch (error) {
      if (!settled) { settled = true; clearTimeout(crossOriginTimer); crossOriginTimer = null; el.crossOriginButton.disabled = false; }
      var record = makeCrossOriginRecord(Number(portText), sourceUrl, { loadStatus: 'src-exception', crossOriginVerified: true }, [errorDetails(error, 'cross-origin-image-src', sourceUrl, 'GET')], 'ERROR', 'ERROR', 'Errore tecnico nella costruzione o assegnazione dell’URL immagine.');
      appendRecord(record); safeText(el.crossOriginState, 'ERROR — assegnazione URL'); el.crossOriginState.className = 'bad';
    }
  }

  function getAggregates() { return renderAggregates(); }
  function downloadExport() {
    var data;
    try {
      data = Core.exportReport(sessionMeta(), runs, records, getAggregates(), pendingEvents.length);
      data.pendingEvents = pendingEvents.slice();
      data.delivery = { pendingEventCount: pendingEvents.length, queueStorageAvailable: queueStorageAvailable, queueStorageKey: QUEUE_KEY };
    }
    catch (error) { showError('Fase: export-serialize\n' + error.name + ': ' + error.message + '\n' + (error.stack || '')); return; }
    var json;
    try { json = JSON.stringify(data, null, 2); }
    catch (error2) { showError('Fase: export-json-stringify\n' + error2.name + ': ' + error2.message + '\n' + (error2.stack || '')); return; }
    try {
      var blob = new Blob([json], { type: 'application/json;charset=utf-8' });
      var objectUrl = URL.createObjectURL(blob);
      var link = document.createElement('a'); link.href = objectUrl; link.download = 'canvas-security-impact-' + sessionId + '.json';
      document.body.appendChild(link); link.click(); document.body.removeChild(link);
      setTimeout(function () { try { URL.revokeObjectURL(objectUrl); } catch (ignore) {} }, 1000);
      el.exportPreview.className = 'hidden';
      safeText(el.persistence, 'Export JSON scaricato; ' + pendingEvents.length + ' eventi non ancora confermati · ' + (queueStorageAvailable ? 'coda Canvas salvata localmente' : 'sola memoria volatile'));
    } catch (error3) {
      el.exportPreview.className = '';
      el.exportPreview.value = json;
      el.exportPreview.focus(); el.exportPreview.select();
      showError('Fase: export-download\n' + error3.name + ': ' + error3.message + '\n' + (error3.stack || '') + '\nIl JSON completo è visibile nel riquadro copiabile.');
    }
  }

  function initialize() {
    safeText(el.sessionId, sessionId);
    safeText(el.userAgent, navigator.userAgent || 'non disponibile');
    safeText(el.origin, location.origin || 'origin non disponibile — aprire via HTTP');
    safeText(el.resultCount, '0 risultati · ' + pendingEvents.length + ' eventi nella coda di consegna');
    updatePersistence();
    verifyBackend();
    el.start.onclick = startCampaign;
    el.stop.onclick = stopCampaign;
    el.retry.onclick = function () { verifyBackend().then(function (ok) { if (ok) pumpEvents(); }); };
    el.export.onclick = downloadExport;
    el.crossOriginButton.onclick = runCrossOrigin;
  }
  initialize();
}());
