(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.CanvasSecurityImpactCore = api;
}(typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  var CLASSIFICATIONS = [
    'EXPECTED', 'SPEC_ANOMALY_CANDIDATE', 'REPRODUCIBLE_FUNCTIONAL_DIFFERENCE',
    'SECURITY_BOUNDARY_ANOMALY_PENDING_REPRODUCTION', 'INCONCLUSIVE', 'SKIPPED', 'ERROR'
  ];
  var CASES = [
    { id: 'A1-baseline', kind: 'baseline', label: 'A1 — Baseline senza opzioni', expectedAlpha: true, expectedGetterReads: null },
    { id: 'A2-alpha-false-data', kind: 'data', value: false, label: 'A2 — alpha:false come proprietà dati', expectedAlpha: false, expectedGetterReads: null },
    { id: 'A3-alpha-true-data', kind: 'data', value: true, label: 'A3 — alpha:true come proprietà dati', expectedAlpha: true, expectedGetterReads: null },
    { id: 'A4-alpha-false-getter', kind: 'getter', value: false, label: 'A4 — Getter alpha che restituisce false', expectedAlpha: false, expectedGetterReads: 1 },
    { id: 'A5-alpha-true-getter', kind: 'getter', value: true, label: 'A5 — Getter alpha che restituisce true', expectedAlpha: true, expectedGetterReads: 1 }
  ];
  var REFERENCES = [
    'https://html.spec.whatwg.org/multipage/canvas.html#concept-canvas-context-2d-creation',
    'https://webidl.spec.whatwg.org/#es-dictionary'
  ];

  function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
  function now(runtime) {
    if (runtime && typeof runtime.now === 'function') return runtime.now();
    return new Date().toISOString();
  }
  function clock(runtime) {
    if (runtime && runtime.performance && typeof runtime.performance.now === 'function') return runtime.performance.now();
    return Date.now();
  }
  function exceptionInfo(error, phase) {
    return {
      phase: phase,
      name: error && error.name ? String(error.name) : 'Error',
      message: error && error.message ? String(error.message) : String(error),
      stack: error && error.stack ? String(error.stack) : null
    };
  }
  function definition(caseId) {
    for (var i = 0; i < CASES.length; i++) if (CASES[i].id === caseId) return CASES[i];
    return null;
  }
  function makeBaseRecord(meta, testId, caseId, runIndex, startedAt, startClock, input) {
    return {
      schemaVersion: 1,
      sessionId: meta.sessionId,
      testId: testId,
      caseId: caseId,
      runIndex: runIndex,
      startedAt: startedAt,
      completedAt: null,
      declaredFirmware: meta.declaredFirmware || null,
      userAgent: meta.userAgent || null,
      origin: meta.origin || null,
      raw: { input: input, observed: {}, exceptions: [], executionStatus: 'PASS', durationMs: 0 },
      interpretation: {
        classification: 'INCONCLUSIVE',
        expected: {},
        explanation: '',
        securityImpact: 'Non dimostrato dai soli risultati diagnostici Canvas.',
        limitations: ['Il risultato non è una verifica di exploitabilità, memoria nativa o sicurezza complessiva.'],
        references: REFERENCES.slice()
      }
    };
  }
  function finish(record, runtime, startClock) {
    record.completedAt = now(runtime);
    record.raw.durationMs = Math.max(0, clock(runtime) - startClock);
    return record;
  }
  function alphaPixelExpected(alpha) { return alpha === false ? 255 : 0; }
  function classifyCanvas(record, def) {
    var observed = record.raw.observed;
    var expected = record.interpretation.expected;
    if (record.raw.executionStatus === 'ERROR') {
      record.interpretation.classification = 'ERROR';
      record.interpretation.explanation = 'Una fase del controllo ha generato un’eccezione; i dati parziali sono conservati.';
      return record;
    }
    if (record.raw.executionStatus === 'SKIPPED') {
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'Canvas 2D o il contesto richiesto non è disponibile.';
      return record;
    }
    if (!observed.contextCreated) {
      record.raw.executionStatus = 'SKIPPED';
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'getContext("2d") non ha creato un contesto.';
      return record;
    }

    var evidenceCount = 0;
    var functionalMismatch = false;
    if (observed.contextAttributesAvailable && typeof observed.contextAttributesAlpha === 'boolean') {
      evidenceCount++;
      if (observed.contextAttributesAlpha !== expected.alpha) functionalMismatch = true;
    }
    if (observed.pixelRGBA && observed.pixelRGBA.length === 4) {
      evidenceCount++;
      if (observed.pixelRGBA[3] !== expected.clearPixelAlpha) functionalMismatch = true;
    }
    if (def.kind === 'getter' && observed.getterReads !== expected.getterReads) {
      record.interpretation.classification = 'SPEC_ANOMALY_CANDIDATE';
      record.interpretation.explanation = 'Il getter alpha è stato letto ' + observed.getterReads + ' volte; la conversione del dizionario dovrebbe leggerlo una volta. Il controllo non dimostra da solo impatto di sicurezza.';
      record.interpretation.observedFunctionalDifference = functionalMismatch;
      return record;
    }
    if (!evidenceCount) {
      record.interpretation.classification = 'INCONCLUSIVE';
      record.interpretation.explanation = 'Contesto creato, ma né gli attributi né la lettura del pixel hanno fornito una misura utilizzabile.';
      return record;
    }
    if (functionalMismatch) {
      record.interpretation.classification = 'SPEC_ANOMALY_CANDIDATE';
      record.interpretation.explanation = 'Attributo alpha o pixel dopo clearRect() non coincide con il valore atteso; ripetere con controlli positivi prima di attribuire una causa.';
      record.interpretation.observedFunctionalDifference = true;
      return record;
    }
    record.interpretation.classification = 'EXPECTED';
    record.interpretation.explanation = 'Getter e comportamento osservabile del contesto coerenti con questo controllo. EXPECTED non significa assenza di vulnerabilità.';
    record.interpretation.observedFunctionalDifference = false;
    return record;
  }

  function runCanvasCase(caseId, runtime, meta, runIndex) {
    runtime = runtime || {};
    meta = meta || {};
    var def = definition(caseId);
    var start = now(runtime);
    var startClock = clock(runtime);
    var record = makeBaseRecord(meta, 'canvas-security-impact.' + (def ? def.id : 'unknown'), caseId, runIndex, start, startClock, {
      canvasFresh: true,
      optionsKind: def ? def.kind : 'unknown',
      alphaValue: def && def.kind !== 'baseline' ? def.value : null,
      inputNote: 'Un canvas nuovo viene creato per ciascuna esecuzione.'
    });
    if (!def) {
      record.raw.executionStatus = 'ERROR';
      record.raw.exceptions.push({ phase: 'case-select', name: 'RangeError', message: 'caseId sconosciuto', stack: null });
      record.interpretation.classification = 'ERROR';
      record.interpretation.explanation = 'Identificativo del caso non riconosciuto.';
      return finish(record, runtime, startClock);
    }
    record.interpretation.expected = {
      getterReads: def.expectedGetterReads,
      alpha: def.expectedAlpha,
      clearPixelAlpha: alphaPixelExpected(def.expectedAlpha)
    };
    if (!runtime.document || typeof runtime.document.createElement !== 'function') {
      record.raw.executionStatus = 'SKIPPED';
      record.raw.observed.apiAvailable = false;
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'document.createElement non disponibile.';
      return finish(record, runtime, startClock);
    }

    var canvas;
    try { canvas = runtime.document.createElement('canvas'); }
    catch (createError) {
      record.raw.executionStatus = 'ERROR';
      record.raw.exceptions.push(exceptionInfo(createError, 'canvas-create'));
      return finish(classifyCanvas(record, def), runtime, startClock);
    }
    if (!canvas || typeof canvas.getContext !== 'function') {
      record.raw.executionStatus = 'SKIPPED';
      record.raw.observed.apiAvailable = false;
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'HTMLCanvasElement.getContext non disponibile.';
      return finish(record, runtime, startClock);
    }
    record.raw.observed.apiAvailable = true;
    var getterReads = 0;
    var options = null;
    try {
      if (def.kind === 'data') options = { alpha: def.value };
      else if (def.kind === 'getter') {
        options = {};
        Object.defineProperty(options, 'alpha', {
          enumerable: true,
          configurable: false,
          get: function () { getterReads++; return def.value; }
        });
      }
    } catch (defineError) {
      record.raw.executionStatus = 'ERROR';
      record.raw.exceptions.push(exceptionInfo(defineError, 'options-define'));
      record.raw.observed.getterReads = getterReads;
      return finish(classifyCanvas(record, def), runtime, startClock);
    }
    var context = null;
    try {
      context = def.kind === 'baseline' ? canvas.getContext('2d') : canvas.getContext('2d', options);
      record.raw.observed.contextCreated = !!context;
    } catch (contextError) {
      record.raw.executionStatus = 'ERROR';
      record.raw.exceptions.push(exceptionInfo(contextError, 'getContext'));
    }
    record.raw.observed.getterReads = def.kind === 'getter' ? getterReads : null;
    if (!context) return finish(classifyCanvas(record, def), runtime, startClock);

    record.raw.observed.contextAttributesAvailable = false;
    record.raw.observed.contextAttributes = 'UNAVAILABLE';
    record.raw.observed.contextAttributesAlpha = null;
    if (typeof context.getContextAttributes === 'function') {
      try {
        var attrs = context.getContextAttributes();
        record.raw.observed.contextAttributesAvailable = !!attrs;
        record.raw.observed.contextAttributes = attrs ? 'AVAILABLE' : 'UNAVAILABLE';
        record.raw.observed.contextAttributesAlpha = attrs && typeof attrs.alpha === 'boolean' ? attrs.alpha : null;
      } catch (attrsError) {
        record.raw.exceptions.push(exceptionInfo(attrsError, 'getContextAttributes'));
        record.raw.executionStatus = 'ERROR';
      }
    } else {
      record.raw.observed.contextAttributes = 'UNAVAILABLE';
    }

    record.raw.observed.pixelRGBA = null;
    try {
      if (typeof context.fillRect === 'function' && typeof context.clearRect === 'function' && typeof context.getImageData === 'function') {
        context.fillStyle = 'rgba(37, 101, 179, 1)';
        context.fillRect(0, 0, 1, 1);
        context.clearRect(0, 0, 1, 1);
        var pixel = context.getImageData(0, 0, 1, 1).data;
        if (pixel && pixel.length >= 4) record.raw.observed.pixelRGBA = [Number(pixel[0]), Number(pixel[1]), Number(pixel[2]), Number(pixel[3])];
        else record.raw.observed.pixelRead = 'UNAVAILABLE';
      } else record.raw.observed.pixelRead = 'UNAVAILABLE';
    } catch (pixelError) {
      record.raw.exceptions.push(exceptionInfo(pixelError, 'fill-clear-read-pixel'));
      record.raw.executionStatus = 'ERROR';
    }
    return finish(classifyCanvas(record, def), runtime, startClock);
  }

  function runBlobControl(runtime, meta, runIndex) {
    runtime = runtime || {};
    meta = meta || {};
    var start = now(runtime);
    var startClock = clock(runtime);
    var record = makeBaseRecord(meta, 'canvas-security-impact.C-blob-dictionary', 'C-blob-dictionary', runIndex, start, startClock, {
      blobParts: [], typeValue: 'text/plain', blobBytes: 0, getterMember: 'type'
    });
    if (typeof runtime.Blob !== 'function') {
      record.raw.executionStatus = 'SKIPPED';
      record.raw.observed.apiAvailable = false;
      record.raw.observed.getterReads = null;
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'Blob non disponibile nel runtime.';
      record.interpretation.expected = { getterReads: 1, type: 'text/plain', size: 0 };
      return finish(record, runtime, startClock);
    }
    var reads = 0;
    var options = {};
    var blob = null;
    record.interpretation.expected = { getterReads: 1, type: 'text/plain', size: 0 };
    try {
      Object.defineProperty(options, 'type', { enumerable: true, configurable: false, get: function () { reads++; return 'text/plain'; } });
      blob = new runtime.Blob([], options);
      record.raw.observed.blobCreated = !!blob;
      record.raw.observed.blobType = blob ? String(blob.type) : null;
      record.raw.observed.blobSize = blob && typeof blob.size === 'number' ? blob.size : null;
    } catch (error) {
      record.raw.executionStatus = 'ERROR';
      record.raw.exceptions.push(exceptionInfo(error, 'blob-create'));
    }
    record.raw.observed.apiAvailable = true;
    record.raw.observed.getterReads = reads;
    if (record.raw.executionStatus === 'ERROR') {
      record.interpretation.classification = 'ERROR';
      record.interpretation.explanation = 'Il controllo Blob ha generato un’eccezione.';
    } else if (!blob) {
      record.raw.executionStatus = 'SKIPPED';
      record.interpretation.classification = 'SKIPPED';
      record.interpretation.explanation = 'La Blob vuota non è stata creata.';
    } else if (reads === 1 && blob.type === 'text/plain' && blob.size === 0) {
      record.interpretation.classification = 'EXPECTED';
      record.interpretation.explanation = 'Il getter type è stato letto e la Blob vuota ha i metadati previsti; è un controllo positivo limitato.';
    } else {
      record.interpretation.classification = 'SPEC_ANOMALY_CANDIDATE';
      record.interpretation.explanation = 'La conversione osservata del BlobPropertyBag differisce dal controllo previsto; questo non prova una non conformità generale Web IDL.';
    }
    return finish(record, runtime, startClock);
  }

  function readPixel(context) {
    if (!context || typeof context.getImageData !== 'function') return null;
    var data = context.getImageData(0, 0, 1, 1).data;
    if (!data || data.length < 4) return null;
    return [Number(data[0]), Number(data[1]), Number(data[2]), Number(data[3])];
  }
  function runIsolationCheck(runtime, meta, runIndex) {
    runtime = runtime || {};
    meta = meta || {};
    var start = now(runtime);
    var startClock = clock(runtime);
    var record = makeBaseRecord(meta, 'canvas-security-impact.E-canvas-isolation', 'E-canvas-isolation', runIndex, start, startClock, {
      independentCanvases: 4, alphaMode: 'default', syntheticPatternRGBA: [197, 51, 123, 255],
      patternCanvas: 'A', blankCanvasesAfterA: ['B', 'C'], independentReferenceCanvas: 'R'
    });
    record.interpretation.expected = { referenceBlankRGBA: [0, 0, 0, 0], canvasBAfterA: [0, 0, 0, 0], canvasCAfterA: [0, 0, 0, 0] };
    if (!runtime.document || typeof runtime.document.createElement !== 'function') {
      record.raw.executionStatus = 'SKIPPED'; record.raw.observed.apiAvailable = false;
      record.interpretation.classification = 'SKIPPED'; record.interpretation.explanation = 'document.createElement non disponibile.';
      return finish(record, runtime, startClock);
    }
    var exceptions = record.raw.exceptions;
    function fresh(label) {
      var canvas = runtime.document.createElement('canvas');
      if (!canvas || typeof canvas.getContext !== 'function') throw new Error(label + ': getContext non disponibile');
      var context = canvas.getContext('2d');
      if (!context) throw new Error(label + ': contesto 2D non creato');
      return context;
    }
    try {
      var reference = fresh('R');
      var referencePixel = readPixel(reference);
      var a = fresh('A');
      a.fillStyle = 'rgba(197, 51, 123, 1)';
      a.fillRect(0, 0, 1, 1);
      var patternPixel = readPixel(a);
      var b = fresh('B');
      var bInitial = readPixel(b);
      var c = fresh('C');
      var cInitial = readPixel(c);
      record.raw.observed.apiAvailable = true;
      record.raw.observed.referenceInitialRGBA = referencePixel;
      record.raw.observed.patternRGBA = patternPixel;
      record.raw.observed.canvasBInitialRGBA = bInitial;
      record.raw.observed.canvasCInitialRGBA = cInitial;
      record.raw.observed.canvasBMatchesPattern = !!(patternPixel && bInitial && JSON.stringify(patternPixel) === JSON.stringify(bInitial));
      record.raw.observed.canvasCMatchesPattern = !!(patternPixel && cInitial && JSON.stringify(patternPixel) === JSON.stringify(cInitial));
      record.raw.observed.independentCanvasesMatchBlank = !!(referencePixel && bInitial && cInitial && JSON.stringify(referencePixel) === JSON.stringify(bInitial) && JSON.stringify(referencePixel) === JSON.stringify(cInitial));
      if (!referencePixel || !patternPixel || !bInitial || !cInitial) {
        record.raw.executionStatus = 'INCONCLUSIVE';
        record.interpretation.classification = 'INCONCLUSIVE';
        record.interpretation.explanation = 'Una o più letture pixel non erano disponibili.';
      } else if (record.raw.observed.canvasBMatchesPattern || record.raw.observed.canvasCMatchesPattern) {
        record.interpretation.classification = 'SPEC_ANOMALY_CANDIDATE';
        record.interpretation.explanation = 'Un canvas non disegnato sembra corrispondere al pattern A; ripetere e confrontare il canvas indipendente prima di interpretare.';
      } else if (record.raw.observed.independentCanvasesMatchBlank) {
        record.interpretation.classification = 'EXPECTED';
        record.interpretation.explanation = 'I canvas B e C creati dopo A risultano uguali al riferimento vuoto e non al pattern A.';
      } else {
        record.interpretation.classification = 'INCONCLUSIVE';
        record.interpretation.explanation = 'Le letture differiscono ma non corrispondono al pattern A; ripetere per escludere variazioni di ambiente.';
      }
    } catch (error) {
      exceptions.push(exceptionInfo(error, 'canvas-isolation'));
      record.raw.executionStatus = error && /non disponibile|non creato/.test(String(error.message)) ? 'SKIPPED' : 'ERROR';
      record.interpretation.classification = record.raw.executionStatus;
      record.interpretation.explanation = 'Il controllo di isolamento non è stato completato.';
    }
    return finish(record, runtime, startClock);
  }

  function runCrossOriginInterpretation(observed, executionStatus) {
    observed = observed || {};
    if (executionStatus === 'ERROR') return { classification: 'ERROR', explanation: 'Errore tecnico durante il controllo cross-origin.' };
    if (executionStatus === 'SKIPPED' || observed.loadStatus !== 'loaded') return { classification: 'SKIPPED', explanation: 'NOT_RUN: la seconda origine o la risorsa non è stata raggiunta; nessun esito di sicurezza viene inferito.' };
    if (!observed.crossOriginVerified) return { classification: 'INCONCLUSIVE', explanation: 'Non è stato possibile confermare che la risorsa provenga da un’origine diversa.' };
    if (observed.getImageDataError === 'SecurityError' && observed.toDataURLError === 'SecurityError') {
      return { classification: 'EXPECTED', explanation: 'Entrambe le API di lettura hanno rispettato la barriera canvas cross-origin.' };
    }
    if (observed.getImageDataSucceeded || observed.toDataURLSucceeded) {
      return { classification: 'SECURITY_BOUNDARY_ANOMALY_PENDING_REPRODUCTION', explanation: 'Una lettura canvas cross-origin è riuscita dopo il caricamento; conservare le prove e fermare ulteriori tentativi.' };
    }
    return { classification: 'INCONCLUSIVE', explanation: 'La risorsa è caricata ma gli esiti delle API non corrispondono a SecurityError per entrambe.' };
  }

  function observationSignature(record) {
    var observed = record && record.raw ? record.raw.observed || {} : {};
    return JSON.stringify({
      executionStatus: record && record.raw ? record.raw.executionStatus : null,
      getterReads: observed.getterReads === undefined ? null : observed.getterReads,
      contextCreated: observed.contextCreated === undefined ? null : observed.contextCreated,
      alpha: observed.contextAttributesAlpha === undefined ? null : observed.contextAttributesAlpha,
      pixelRGBA: observed.pixelRGBA || null,
      exceptions: (record && record.raw && record.raw.exceptions || []).map(function (item) { return item.name + ':' + item.message; })
    });
  }
  function summarizeReproducibility(records) {
    records = Array.isArray(records) ? records : [];
    var signatures = {};
    var getterReads = 0;
    var getterNotRead = 0;
    var totalGetterReadCalls = 0;
    var exceptionCount = 0;
    var i;
    for (i = 0; i < records.length; i++) {
      var record = records[i];
      var sig = observationSignature(record);
      signatures[sig] = (signatures[sig] || 0) + 1;
      var readCount = record.raw && record.raw.observed ? record.raw.observed.getterReads : null;
      if (readCount !== null && readCount !== undefined) {
        totalGetterReadCalls += readCount;
        if (readCount > 0) getterReads++;
        else getterNotRead++;
      }
      exceptionCount += record.raw && Array.isArray(record.raw.exceptions) ? record.raw.exceptions.length : 0;
    }
    var mostCommon = 0;
    Object.keys(signatures).forEach(function (key) { if (signatures[key] > mostCommon) mostCommon = signatures[key]; });
    return {
      totalExecutions: records.length,
      getterReadExecutions: getterReads,
      getterNotReadExecutions: getterNotRead,
      totalGetterReadCalls: totalGetterReadCalls,
      exceptionCount: exceptionCount,
      concordantPercentage: records.length ? Math.round((mostCommon / records.length) * 10000) / 100 : 0,
      signatures: signatures
    };
  }
  function aggregateCase(caseId, records, blobRecords) {
    records = Array.isArray(records) ? records : [];
    blobRecords = Array.isArray(blobRecords) ? blobRecords : [];
    var metrics = summarizeReproducibility(records);
    var outcome = { caseId: caseId, metrics: metrics, classification: 'INCONCLUSIVE', functionalDifferenceRuns: 0, explanation: '' };
    if (records.length < 5) {
      outcome.classification = 'INCONCLUSIVE';
      outcome.explanation = 'Sono richieste almeno cinque esecuzioni valide per questa campagna.';
      return outcome;
    }
    var usable = records.filter(function (record) { return record.raw.executionStatus === 'PASS'; });
    if (!usable.length) {
      outcome.classification = records.every(function (record) { return record.raw.executionStatus === 'SKIPPED'; }) ? 'SKIPPED' : 'ERROR';
      outcome.explanation = 'Non sono disponibili cinque risultati utilizzabili.';
      return outcome;
    }
    var def = definition(caseId);
    var mismatches = 0;
    usable.forEach(function (record) {
      var obs = record.raw.observed || {};
      var exp = record.interpretation.expected || {};
      var mismatch = false;
      if (typeof obs.contextAttributesAlpha === 'boolean' && obs.contextAttributesAlpha !== exp.alpha) mismatch = true;
      if (obs.pixelRGBA && obs.pixelRGBA.length === 4 && obs.pixelRGBA[3] !== exp.clearPixelAlpha) mismatch = true;
      if (def && def.kind === 'getter' && obs.getterReads !== exp.getterReads) mismatch = true;
      if (mismatch) mismatches++;
    });
    outcome.functionalDifferenceRuns = mismatches;
    var blobPositive = blobRecords.length >= 5 && blobRecords.every(function (record) {
      return record.raw.executionStatus === 'PASS' && record.raw.observed.getterReads === 1;
    });
    if (usable.length === records.length && mismatches === records.length && blobPositive) {
      outcome.classification = 'REPRODUCIBLE_FUNCTIONAL_DIFFERENCE';
      outcome.explanation = 'La differenza si ripete in tutte le esecuzioni e il controllo Blob dimostra che il runtime legge un getter di dizionario indipendente.';
    } else if (mismatches > 0 || usable.some(function (record) { return record.interpretation.classification === 'SPEC_ANOMALY_CANDIDATE'; })) {
      outcome.classification = 'SPEC_ANOMALY_CANDIDATE';
      outcome.explanation = 'È stata osservata una differenza o una lettura getter inattesa; i controlli positivi non bastano a dimostrare un impatto di sicurezza.';
    } else if (usable.length === records.length && mismatches === 0) {
      outcome.classification = 'EXPECTED';
      outcome.explanation = 'Tutte le esecuzioni utilizzabili corrispondono al comportamento atteso.';
    } else {
      outcome.classification = 'INCONCLUSIVE';
      outcome.explanation = 'Risultati misti o non sufficienti per una classificazione più forte.';
    }
    return outcome;
  }
  function aggregateIsolation(records) {
    records = Array.isArray(records) ? records : [];
    var metrics = summarizeReproducibility(records);
    var leaks = records.filter(function (record) {
      var o = record.raw && record.raw.observed || {};
      return o.canvasBMatchesPattern || o.canvasCMatchesPattern;
    }).length;
    var classification = 'INCONCLUSIVE';
    if (records.length >= 5 && leaks === records.length) classification = 'REPRODUCIBLE_FUNCTIONAL_DIFFERENCE';
    else if (records.length >= 5 && leaks > 0) classification = 'SPEC_ANOMALY_CANDIDATE';
    else if (records.length >= 5 && records.every(function (r) { return r.interpretation.classification === 'EXPECTED'; })) classification = 'EXPECTED';
    else if (records.length && records.every(function (r) { return r.raw.executionStatus === 'SKIPPED'; })) classification = 'SKIPPED';
    return { caseId: 'E-canvas-isolation', totalExecutions: records.length, patternMatchesInOtherCanvas: leaks, metrics: metrics, classification: classification,
      explanation: classification === 'EXPECTED' ? 'I canvas indipendenti non hanno esposto il pattern sintetico.' : classification === 'REPRODUCIBLE_FUNCTIONAL_DIFFERENCE' ? 'Il pattern A è comparso nei canvas separati in tutte le ripetizioni; è una differenza funzionale, non prova da sola una fuga di memoria nativa.' : 'Le evidenze sono insufficienti o parziali.' };
  }
  function aggregateBlob(records) {
    records = Array.isArray(records) ? records : [];
    var metrics = summarizeReproducibility(records);
    var classification = 'INCONCLUSIVE';
    var allAvailable = records.length >= 5 && records.every(function (r) { return r.raw.executionStatus === 'PASS'; });
    if (records.length >= 5 && records.every(function (r) { return r.raw.executionStatus === 'SKIPPED'; })) classification = 'SKIPPED';
    else if (allAvailable && records.every(function (r) { return r.raw.observed.getterReads === 1 && r.raw.observed.blobType === 'text/plain' && r.raw.observed.blobSize === 0; })) classification = 'EXPECTED';
    else if (records.some(function (r) { return r.raw.executionStatus === 'ERROR'; })) classification = 'ERROR';
    else if (allAvailable && records.every(function (r) { return r.raw.observed.getterReads !== 1; })) classification = 'SPEC_ANOMALY_CANDIDATE';
    return { caseId: 'C-blob-dictionary', totalExecutions: records.length, metrics: metrics, classification: classification,
      explanation: classification === 'EXPECTED' ? 'Il getter type è stato letto e la Blob vuota ha i metadati previsti; controllo positivo limitato.' : 'La conversione Blob osservata non fornisce un controllo positivo stabile o non è disponibile.' };
  }

  function validateRecord(record) {
    if (!object(record)) return { valid: false, error: 'Il record deve essere un oggetto.' };
    var requiredStrings = ['sessionId', 'testId', 'caseId', 'startedAt', 'completedAt'];
    for (var i = 0; i < requiredStrings.length; i++) if (typeof record[requiredStrings[i]] !== 'string' || !record[requiredStrings[i]]) return { valid: false, error: 'Campo obbligatorio mancante: ' + requiredStrings[i] };
    if (typeof record.runIndex !== 'number' || record.runIndex < 1) return { valid: false, error: 'runIndex non valido.' };
    if (!object(record.raw) || !object(record.raw.input) || !object(record.raw.observed) || !Array.isArray(record.raw.exceptions)) return { valid: false, error: 'Dati raw non validi.' };
    if (typeof record.raw.executionStatus !== 'string' || typeof record.raw.durationMs !== 'number') return { valid: false, error: 'Stato o durata raw non validi.' };
    if (!object(record.interpretation) || CLASSIFICATIONS.indexOf(record.interpretation.classification) === -1) return { valid: false, error: 'Interpretazione/classificazione non valida.' };
    if (!Array.isArray(record.interpretation.limitations) || !Array.isArray(record.interpretation.references)) return { valid: false, error: 'Limitazioni o riferimenti mancanti.' };
    return { valid: true };
  }
  function toScannerResult(record) {
    var raw = record.raw || {};
    var executionState = raw.executionStatus === 'ERROR' ? 'ERROR' : raw.executionStatus === 'SKIPPED' ? 'SKIPPED' : raw.executionStatus === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PASS';
    return {
      id: record.testId,
      category: 'Canvas Security Impact',
      description: 'Test diagnostico ' + record.caseId + '; PASS significa solo che la procedura è stata eseguita, non che il browser sia sicuro.',
      state: executionState,
      observed: { raw: raw.observed || {}, interpretation: record.interpretation || {} },
      error: raw.exceptions && raw.exceptions.length ? { name: raw.exceptions[0].name, message: raw.exceptions[0].message, stack: raw.exceptions[0].stack, phase: raw.exceptions[0].phase } : null,
      durationMs: typeof raw.durationMs === 'number' ? raw.durationMs : 0,
      limitations: record.interpretation && record.interpretation.limitations || ['Diagnostica non distruttiva; non è una prova di exploitabilità.'],
      sessionId: record.sessionId,
      caseId: record.caseId,
      runIndex: record.runIndex,
      startedAt: record.startedAt,
      completedAt: record.completedAt,
      rawRecord: record
    };
  }
  function exportReport(session, runs, records, aggregates, pendingEvents) {
    var payload = {
      schemaVersion: 1,
      generatedAt: now(),
      session: session,
      runs: runs || [],
      rawResults: records || [],
      aggregates: aggregates || [],
      pendingEventCount: pendingEvents || 0,
      conclusion: {
        securityImpactDemonstrated: false,
        note: 'Nessun impatto di sicurezza è dichiarato senza una prova indipendente. Le classificazioni tecniche sono separate dai dati raw.'
      }
    };
    var json = JSON.stringify(payload);
    JSON.parse(json);
    return payload;
  }
  function buildDossier(session, runs, records, aggregates) {
    var results = (records || []).map(toScannerResult);
    var facts = [];
    (aggregates || []).forEach(function (item) { facts.push(item.caseId + ': ' + item.classification + ' — ' + item.explanation); });
    return {
      schemaVersion: 1,
      sessionId: session.sessionId,
      startedAt: session.startedAt,
      completedAt: now(),
      declaredFirmware: session.declaredFirmware || null,
      environment: { userAgent: session.userAgent || null, origin: session.origin || null, platform: session.platform || null },
      overallState: session.overallState || 'COMPLETED',
      results: results,
      transmissionErrors: [],
      conclusions: { factsObserved: facts, hypotheses: [], vulnerabilityCorrelations: [], inconclusiveResults: [], recommendedChecks: ['Ripetere sulla PS5 e salvare il JSON esportato.', 'Confrontare con browser desktop indicando versione esatta e sistema operativo.', 'Non interpretare differenze Canvas come vulnerabilità senza prova di impatto.'] },
      missingData: ['L’esecuzione sulla PS5 è presente solo dopo che l’operatore avvia la pagina.', 'Il test cross-origin richiede il server ausiliario sulla seconda porta.'],
      limitations: ['PASS significa completamento diagnostico e non indica assenza di vulnerabilità.', 'Nessun test esegue payload di exploit o prova corruzione di memoria.', 'L’applicabilità delle CVE richiede una mappatura attendibile della build del componente.'],
      canvasSecurityImpact: { runs: runs || [], rawResults: records || [], aggregates: aggregates || [], securityImpactDemonstrated: false }
    };
  }

  function getCases() { return CASES.map(function (item) { return { id: item.id, kind: item.kind, value: item.value, label: item.label }; }); }
  return {
    CLASSIFICATIONS: CLASSIFICATIONS.slice(),
    getCases: getCases,
    runCanvasCase: runCanvasCase,
    runBlobControl: runBlobControl,
    runIsolationCheck: runIsolationCheck,
    runCrossOriginInterpretation: runCrossOriginInterpretation,
    summarizeReproducibility: summarizeReproducibility,
    aggregateCase: aggregateCase,
    aggregateIsolation: aggregateIsolation,
    aggregateBlob: aggregateBlob,
    validateRecord: validateRecord,
    toScannerResult: toScannerResult,
    exportReport: exportReport,
    buildDossier: buildDossier,
    observationSignature: observationSignature
  };
}));
