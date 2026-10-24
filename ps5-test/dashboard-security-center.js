(function () {
  'use strict';
  var events = [];
  var state = { backend: 'checking', error: '' };
  var byId = function (id) { return document.getElementById(id); };
  var filters = ['filterFrom', 'filterTo', 'filterTool', 'filterSession', 'filterCategory', 'filterOutcome'];

  function safeString(value) {
    return String(value == null ? '' : value)
      .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [redacted]')
      .replace(/([?&](?:access_token|api[_-]?key|token|secret|password|authorization)=)[^&#\s]+/gi, '$1[redacted]');
  }
  function safeData(value) {
    if (Array.isArray(value)) return value.map(safeData);
    if (!value || typeof value !== 'object') return typeof value === 'string' ? safeString(value) : value;
    var output = {};
    Object.keys(value).forEach(function (key) {
      if (/(?:token|secret|password|authorization|cookie|credential|api[_-]?key)/i.test(key)) output[key] = '[redacted]';
      else output[key] = safeData(value[key]);
    });
    return output;
  }
  function text(id, value) { byId(id).textContent = safeString(value == null ? '' : value); }
  function dateValue(value) {
    var time = Date.parse(value || '');
    return isFinite(time) ? time : 0;
  }
  function resultFrom(event) {
    var payload = event && event.payload || {};
    if (payload.result && typeof payload.result === 'object') return payload.result;
    var dossier = payload.dossier || (payload.canvasSecurityImpactExport && payload.canvasSecurityImpactExport.dossier);
    return dossier && dossier.results && dossier.results.length ? dossier.results[0] : null;
  }
  function dossierFrom(event) {
    var p = event.payload || {};
    return p.dossier || (p.canvasSecurityImpactExport && p.canvasSecurityImpactExport.dossier) || null;
  }
  function isCanvas(event) {
    var p = event.payload || {}, result = resultFrom(event), dossier = dossierFrom(event);
    return !!(p.canvasSecurityImpactRecord || (result && (result.category === 'Canvas Security Impact' || String(result.id || '').indexOf('canvas-security-impact.') === 0)) || (dossier && dossier.results && dossier.results.some(function (item) { return item.category === 'Canvas Security Impact' || String(item.id || '').indexOf('canvas-security-impact.') === 0; })));
  }
  function evidenceTool(event) {
    var payload = event && event.payload || {};
    if (isCanvas(event)) return 'canvas';
    if (event && event.eventType === 'test_result' && payload.result) return 'scanner';
    if (event && event.eventType === 'scan_start' && payload.test === 'canvas-security-impact') return 'canvas';
    if (event && event.eventType === 'scan_start' && Array.isArray(payload.selectedTests)) return 'scanner';
    var dossier = dossierFrom(event);
    if (dossier && Array.isArray(dossier.results) && dossier.results.length) return dossier.results.some(function (item) { return item.category === 'Canvas Security Impact' || String(item.id || '').indexOf('canvas-security-impact.') === 0; }) ? 'canvas' : 'scanner';
    return '';
  }
  function toolOf(event) {
    var direct = evidenceTool(event); if (direct) return direct;
    var tools = [];
    events.forEach(function (item) { if (item.sessionId === event.sessionId) { var tool = evidenceTool(item); if (tool && tools.indexOf(tool) < 0) tools.push(tool); } });
    return tools.length === 1 ? tools[0] : (tools.length > 1 ? 'mixed' : 'unknown');
  }
  function toolLabel(event) {
    var tool = toolOf(event);
    return tool === 'canvas' ? 'Canvas' : (tool === 'scanner' ? 'Vulnerability Scanner' : (tool === 'mixed' ? 'Sessione mista' : 'Strumento non identificato'));
  }
  function outcomeOf(event) {
    var result = resultFrom(event), p = event.payload || {};
    if (result && result.state) return String(result.state);
    if (p.resultCount != null && event.eventType === 'scan_complete') return 'COMPLETED';
    if (event.eventType === 'transmission_error') return 'ERROR';
    if (event.eventType === 'scan_interrupted') return 'INCOMPLETE';
    return event.eventType || 'UNKNOWN';
  }
  function categoryOf(event) {
    var result = resultFrom(event), p = event.payload || {}, record = p.canvasSecurityImpactRecord;
    if (record && record.caseId) return String(record.caseId);
    if (result && (result.caseId || result.category)) return String(result.caseId || result.category);
    var dossier = dossierFrom(event);
    if (dossier && dossier.results && dossier.results[0]) return String(dossier.results[0].category || 'Session summary');
    return event.eventType || 'Evento';
  }
  function sessionData() {
    var sessions = Object.create(null);
    events.forEach(function (event) {
      var s = sessions[event.sessionId] || (sessions[event.sessionId] = { id: event.sessionId, tool: 'unknown', tools: [], first: event.clientTime, last: event.clientTime, complete: false, errors: 0 });
      var evidence = evidenceTool(event); if (evidence && s.tools.indexOf(evidence) < 0) s.tools.push(evidence);
      if (dateValue(event.clientTime) < dateValue(s.first)) s.first = event.clientTime;
      if (dateValue(event.clientTime) > dateValue(s.last)) s.last = event.clientTime;
      if (event.eventType === 'scan_complete' || event.eventType === 'session_summary') s.complete = true;
      if (event.eventType === 'transmission_error') s.errors += 1;
    });
    return Object.keys(sessions).map(function (key) { var s = sessions[key]; s.tool = s.tools.length === 1 ? s.tools[0] : (s.tools.length > 1 ? 'mixed' : 'unknown'); return s; });
  }
  function addOption(select, value, label) {
    var option = document.createElement('option'); option.value = safeString(value); option.textContent = safeString(label); select.appendChild(option);
  }
  function fillOptions(id, values, label) {
    var select = byId(id), previous = select.value;
    while (select.options.length > 1) select.remove(1);
    values.forEach(function (value) { addOption(select, value, value); });
    if (values.indexOf(previous) >= 0) select.value = previous;
  }
  function getFiltered() {
    var from = byId('filterFrom').value ? Date.parse(byId('filterFrom').value + 'T00:00:00') : 0;
    var to = byId('filterTo').value ? Date.parse(byId('filterTo').value + 'T23:59:59.999') : Infinity;
    var tool = byId('filterTool').value, session = byId('filterSession').value;
    var category = byId('filterCategory').value, outcome = byId('filterOutcome').value;
    return events.filter(function (event) {
      var time = dateValue(event.clientTime);
      return time >= from && time <= to && (!tool || toolOf(event) === tool) && (!session || event.sessionId === session) && (!category || categoryOf(event) === category) && (!outcome || outcomeOf(event) === outcome);
    }).sort(function (a, b) { return dateValue(b.clientTime) - dateValue(a.clientTime); });
  }
  function eventLabel(event) {
    var result = resultFrom(event);
    return result ? (result.id || result.description || event.eventType) : (event.eventType === 'session_summary' ? 'Riepilogo sessione' : event.eventType);
  }
  function renderTimeline() {
    var filtered = getFiltered(), list = byId('eventList');
    list.textContent = '';
    text('timelineCount', filtered.length + ' eventi mostrati su ' + events.length + ' caricati');
    filtered.forEach(function (event) {
      var button = document.createElement('button'); button.type = 'button'; button.className = 'event-item';
      var date = document.createElement('span'); date.textContent = safeString(event.clientTime || 'Data assente');
      var label = document.createElement('span'); label.textContent = safeString(eventLabel(event));
      var meta = document.createElement('small'); meta.textContent = safeString(toolLabel(event) + ' · ' + outcomeOf(event) + ' · ' + event.sessionId);
      button.appendChild(date); button.appendChild(label); button.appendChild(meta);
      button.onclick = function () { byId('eventDetail').textContent = JSON.stringify(safeData(event), null, 2); };
      list.appendChild(button);
    });
    if (!filtered.length) { var empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = 'Nessun evento corrisponde ai filtri.'; list.appendChild(empty); }
  }
  function collectResults() {
    var found = [], seen = Object.create(null);
    events.forEach(function (event) {
      var p = event.payload || {}, dossier = dossierFrom(event), candidates = [];
      if (event.eventType === 'test_result' && p.result && typeof p.result === 'object') candidates.push({ result: p.result, record: p.canvasSecurityImpactRecord || null, event: event });
      if (dossier && Array.isArray(dossier.results)) dossier.results.forEach(function (result) { candidates.push({ result: result, record: result.rawRecord || null, event: event }); });
      candidates.forEach(function (candidate) {
        var result = candidate.result, record = candidate.record || {}, id = result.id || result.testId || 'unknown';
        var run = record.runIndex || result.runIndex || '';
        var started = result.startedAt || record.startedAt || '';
        var key = event.sessionId + '|' + id + '|' + run + '|' + started;
        if (seen[key]) return;
        seen[key] = true;
        found.push(candidate);
      });
    });
    return found;
  }
  function renderSummaries() {
    var sessions = sessionData(), canvas = events.filter(function (event) { return toolOf(event) === 'canvas'; });
    var scanner = events.filter(function (event) { return toolOf(event) === 'scanner'; });
    var completed = sessions.filter(function (s) { return s.complete; }).length;
    var incomplete = sessions.length - completed;
    var results = collectResults();
    var pass = results.filter(function (item) { return item.result.state === 'PASS'; }).length;
    var fail = results.filter(function (item) { return item.result.state === 'FAIL'; }).length;
    var inconclusive = results.filter(function (item) { return ['SKIPPED', 'ERROR', 'INCONCLUSIVE'].indexOf(item.result.state) >= 0; }).length;
    var latest = function (items) { return items.slice().sort(function (a, b) { return dateValue(b.clientTime) - dateValue(a.clientTime); })[0]; };
    var latestCanvas = latest(canvas), latestScanner = latest(scanner);
    var prettyTime = function (event) { var value = event && dateValue(event.clientTime); return value ? new Date(value).toLocaleString() : 'Dato assente'; };
    text('metricCanvas', latestCanvas ? prettyTime(latestCanvas) : 'Dato assente');
    text('metricScanner', latestScanner ? prettyTime(latestScanner) : 'Dato assente');
    text('metricSessions', sessions.length ? completed + ' / ' + incomplete : 'Nessuna sessione');
    text('metricResults', results.length ? pass + ' / ' + fail + ' / ' + inconclusive : 'Nessun test registrato');
    text('collectionStatus', state.backend === 'ok' ? 'API disponibile; ' + events.length + ' eventi letti dallo storico del server. La coda locale non è esposta da questa API.' : 'Storico server non disponibile; nessun dato locale viene simulato.');
    text('backendErrors', state.error || (sessions.some(function (s) { return s.errors; }) ? 'Sono registrati errori di trasmissione in una o più sessioni.' : 'Nessun errore di trasmissione registrato.'));
    var cSessions = sessions.filter(function (s) { return s.tools.indexOf('canvas') >= 0; });
    var sSessions = sessions.filter(function (s) { return s.tools.indexOf('scanner') >= 0; });
    text('canvasSummary', cSessions.length ? cSessions.length + ' sessioni Canvas; ' + results.filter(function (item) { return item.record || item.result.category === 'Canvas Security Impact' || String(item.result.id || '').indexOf('canvas-security-impact.') === 0; }).length + ' risultati deduplicati. Le classificazioni descrivono osservazioni sperimentali.' : 'Nessuna analisi Canvas disponibile.');
    text('scannerSummary', sSessions.length ? sSessions.length + ' sessioni scanner; ' + scanner.filter(function (e) { return e.eventType === 'test_result'; }).length + ' risultati diagnostici. Le rilevazioni di vulnerabilità sono mostrate solo se presenti nel modello dati.' : 'Nessuna scansione Vulnerability Scanner disponibile.');
    renderCases(results.filter(function (item) { return item.record || item.result.category === 'Canvas Security Impact' || String(item.result.id || '').indexOf('canvas-security-impact.') === 0; }));
    renderFindings(results.filter(function (item) { return !item.record && item.result.category !== 'Canvas Security Impact' && String(item.result.id || '').indexOf('canvas-security-impact.') !== 0; }));
    var common = cSessions.some(function (c) { return sSessions.some(function (s) { return s.id === c.id; }); });
    text('comparison', common ? 'Le analisi condividono un sessionId; la chiave è riportata per un confronto manuale dei record della stessa sessione.' : (cSessions.length && sSessions.length ? 'Le sessioni dei due strumenti sono indipendenti: non è disponibile una chiave condivisa per correlarle. Le differenze temporali non vengono usate come correlazione.' : 'Confronto non disponibile: occorrono dati registrati da entrambi gli strumenti. Nessuna rilevazione mancante viene interpretata come assenza di vulnerabilità.'));
    fillOptions('filterSession', sessions.map(function (s) { return s.id; }).sort(), '');
    fillOptions('filterCategory', Array.from(new Set(events.map(categoryOf))).sort(), '');
    fillOptions('filterOutcome', Array.from(new Set(events.map(outcomeOf))).sort(), '');
    renderTimeline();
  }
  function renderCases(canvasResults) {
    var cases = Object.create(null), container = byId('canvasCases'); container.textContent = '';
    canvasResults.forEach(function (item) {
      var event = item.event, record = item.record;
      var result = item.result, key = record && record.caseId || result && (result.caseId || result.id);
      if (!key) return;
      var item = cases[key] || (cases[key] = { count: 0, latest: event, result: result, record: record, state: result.state || outcomeOf(event) });
      item.count += 1; if (dateValue(event.clientTime) >= dateValue(item.latest.clientTime)) { item.latest = event; item.result = result; item.record = record; item.state = result.state || outcomeOf(event); }
    });
    Object.keys(cases).sort().forEach(function (key) {
      var row = document.createElement('div'); row.className = 'event-item';
      var a = document.createElement('span'); a.textContent = safeString(key);
      var b = document.createElement('span'); b.textContent = cases[key].count + ' esecuzioni registrate';
      var result = cases[key].result, record = cases[key].record;
      var c = document.createElement('small'); c.textContent = safeString(((record && record.interpretation && record.interpretation.classification) || cases[key].state) + ' · ' + cases[key].latest.clientTime);
      row.appendChild(a); row.appendChild(b); row.appendChild(c);
      if (result && result.description) { var description = document.createElement('small'); description.textContent = safeString(result.description); row.appendChild(description); }
      row.onclick = function () { byId('eventDetail').textContent = JSON.stringify(safeData(cases[key].latest), null, 2); };
      container.appendChild(row);
    });
    if (!Object.keys(cases).length) { var empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = 'Nessun dettaglio di caso disponibile nei dati caricati.'; container.appendChild(empty); }
  }
  function renderFindings(findings) {
    var container = byId('scannerFindings'); container.textContent = '';
    findings.forEach(function (item) {
      var event = item.event, result = item.result, row = document.createElement('div'); row.className = 'event-item';
      var a = document.createElement('span'); a.textContent = safeString(result.id || 'Rilevazione senza ID');
      var b = document.createElement('span'); b.textContent = safeString(result.category || 'Categoria non disponibile');
      var c = document.createElement('small'); c.textContent = safeString((result.severity ? 'Severità ' + result.severity + ' · ' : '') + (result.state || 'Esito assente') + ' · ' + event.clientTime);
      row.appendChild(a); row.appendChild(b); row.appendChild(c); row.onclick = function () { byId('eventDetail').textContent = JSON.stringify(safeData(event), null, 2); }; container.appendChild(row);
    });
    if (!findings.length) { var empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = 'Nessun risultato scanner disponibile.'; container.appendChild(empty); }
  }
  function download(name, type, data) {
    var blob = new Blob([data], { type: type }), url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  }
  function csvEscape(value) { return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"'; }
  function exportJson() { download('security-analysis-filtered.json', 'application/json', JSON.stringify({ exportedAt: new Date().toISOString(), eventCount: getFiltered().length, events: getFiltered().map(safeData) }, null, 2)); }
  function exportCsv() {
    var rows = [['clientTime', 'tool', 'sessionId', 'eventType', 'category', 'outcome', 'eventId']];
    getFiltered().forEach(function (e) { rows.push([safeString(e.clientTime), toolOf(e), safeString(e.sessionId), safeString(e.eventType), safeString(categoryOf(e)), safeString(outcomeOf(e)), safeString(e.eventId)]); });
    download('security-analysis-filtered.csv', 'text/csv;charset=utf-8', rows.map(function (r) { return r.map(csvEscape).join(','); }).join('\r\n'));
  }
  function load() {
    text('analysisStatus', 'Lettura di GET /api/analysis-events…');
    fetch('/api/analysis-events', { cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (response) {
      if (response.status !== 200) throw new Error('HTTP ' + response.status);
      if (!/application\/json/i.test(response.headers.get('Content-Type') || '')) throw new Error('Risposta non JSON');
      return response.json();
    }).then(function (body) {
      if (!body || body.ok !== true || !Array.isArray(body.events)) throw new Error('Formato dati storico non valido');
      events = body.events.filter(function (item) { return item && typeof item.sessionId === 'string' && typeof item.eventType === 'string' && item.payload && typeof item.payload === 'object'; });
      state.backend = 'ok'; state.error = '';
      text('analysisStatus', events.length + ' eventi caricati' + (body.truncated ? ' · storico parziale per limite API' : '') + '.');
      renderSummaries();
    }).catch(function (error) {
      events = []; state.backend = 'error'; state.error = 'Errore API: ' + String(error && error.message || 'comunicazione non disponibile');
      text('analysisStatus', 'Dati non disponibili. Verificare il backend locale.'); renderSummaries();
    });
  }
  filters.forEach(function (id) { byId(id).addEventListener('change', renderTimeline); });
  byId('analysisRefresh').onclick = load;
  byId('exportFilteredJson').onclick = exportJson;
  byId('exportFilteredCsv').onclick = exportCsv;
  load();
}());
