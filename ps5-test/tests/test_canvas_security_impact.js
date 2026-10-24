'use strict';

const assert = require('node:assert/strict');
const Core = require('../pages/canvas-security-impact-core.js');

function makeRuntime(options) {
  options = options || {};
  const stats = { canvases: 0, blobCalls: 0 };
  const doc = {
    createElement(tag) {
      if (tag !== 'canvas') return {};
      stats.canvases++;
      const canvasNumber = stats.canvases;
      let context = null;
      const canvas = {
        getContext(type, settings) {
          if (options.throwGetContext) throw new TypeError('controlled getContext error');
          if (type !== '2d') return null;
          if (context) return context;
          let alpha = true;
          const isGetter = settings && Object.getOwnPropertyDescriptor(settings, 'alpha') && Object.getOwnPropertyDescriptor(settings, 'alpha').get;
          if (settings && (!options.ignoreCanvasGetters || !isGetter) && Object.prototype.hasOwnProperty.call(settings, 'alpha')) alpha = settings.alpha;
          let pixel = [0, 0, 0, alpha ? 0 : 255];
          context = {
            fillStyle: '',
            getContextAttributes() { return { alpha: alpha }; },
            fillRect() {
              if (String(this.fillStyle).indexOf('197') !== -1) pixel = [197, 51, 123, 255];
              else pixel = [37, 101, 179, 255];
            },
            clearRect() { pixel = [0, 0, 0, alpha ? 0 : 255]; },
            getImageData() {
              if (options.throwPixel) throw new Error('controlled pixel error');
              return { data: pixel.slice() };
            }
          };
          if (canvasNumber > 1000) throw new Error('unexpected canvas count');
          return context;
        }
      };
      return canvas;
    }
  };
  function TestBlob(parts, bag) {
    stats.blobCalls++;
    this.type = bag.type;
    this.size = parts.reduce((sum, part) => sum + String(part).length, 0);
  }
  return { runtime: { document: doc, Blob: options.noBlob ? null : TestBlob, performance: require('node:perf_hooks').performance }, stats };
}

const meta = { sessionId: 'csi-test-session-0001', declaredFirmware: '14.10', userAgent: 'Node mock; not a PS5 result', origin: 'http://127.0.0.1:8000' };

function validateRequired(record) {
  assert.equal(Core.validateRecord(record).valid, true);
  assert.ok(record.sessionId && record.testId && record.caseId && record.startedAt && record.completedAt);
  assert.ok(record.raw && record.raw.input && record.raw.observed && Array.isArray(record.raw.exceptions));
  assert.ok(record.interpretation && record.interpretation.classification);
}

async function main() {
  const cases = Core.getCases();
  assert.deepEqual(cases.map(item => item.id), [
    'A1-baseline', 'A2-alpha-false-data', 'A3-alpha-true-data', 'A4-alpha-false-getter', 'A5-alpha-true-getter'
  ], 'five independent Canvas cases are defined in the required order');

  const mock = makeRuntime();
  const canvasRecords = [];
  for (let run = 1; run <= 5; run++) {
    for (const item of cases) {
      const record = Core.runCanvasCase(item.id, mock.runtime, meta, run);
      validateRequired(record);
      assert.equal(record.raw.input.canvasFresh, true);
      assert.equal(record.raw.executionStatus, 'PASS');
      assert.equal(record.interpretation.classification, 'EXPECTED');
      canvasRecords.push(record);
    }
  }
  assert.equal(mock.stats.canvases, 25, 'each Canvas case creates a fresh canvas in each of five repetitions');
  assert.deepEqual(canvasRecords.filter(r => r.caseId === 'A4-alpha-false-getter').map(r => r.raw.observed.getterReads), [1, 1, 1, 1, 1]);
  assert.deepEqual(canvasRecords.filter(r => r.caseId === 'A4-alpha-false-getter').map(r => r.raw.observed.contextAttributesAlpha), [false, false, false, false, false]);
  assert.deepEqual(canvasRecords.filter(r => r.caseId === 'A4-alpha-false-getter').map(r => r.raw.observed.pixelRGBA[3]), [255, 255, 255, 255, 255]);
  assert.deepEqual(canvasRecords.filter(r => r.caseId === 'A5-alpha-true-getter').map(r => r.raw.observed.getterReads), [1, 1, 1, 1, 1]);
  assert.deepEqual(canvasRecords.filter(r => r.caseId === 'A3-alpha-true-data').map(r => r.raw.observed.pixelRGBA[3]), [0, 0, 0, 0, 0]);

  const blobRecords = [];
  for (let run = 1; run <= 5; run++) {
    const record = Core.runBlobControl(mock.runtime, meta, run);
    validateRequired(record);
    assert.equal(record.raw.observed.getterReads, 1);
    assert.equal(record.raw.observed.blobSize, 0);
    assert.equal(record.interpretation.classification, 'EXPECTED');
    blobRecords.push(record);
  }
  assert.equal(Core.aggregateBlob(blobRecords).classification, 'EXPECTED');

  const a4 = Core.aggregateCase('A4-alpha-false-getter', canvasRecords.filter(r => r.caseId === 'A4-alpha-false-getter'), blobRecords);
  assert.equal(a4.classification, 'EXPECTED', 'a stable conforming controlled runtime classifies A4 as expected');
  assert.equal(a4.metrics.totalExecutions, 5);
  assert.equal(a4.metrics.totalGetterReadCalls, 5);
  assert.equal(a4.metrics.concordantPercentage, 100);

  const broken = makeRuntime({ ignoreCanvasGetters: true });
  const brokenA4 = [];
  for (let run = 1; run <= 5; run++) brokenA4.push(Core.runCanvasCase('A4-alpha-false-getter', broken.runtime, meta, run));
  const brokenAggregate = Core.aggregateCase('A4-alpha-false-getter', brokenA4, blobRecords);
  assert.equal(brokenAggregate.classification, 'REPRODUCIBLE_FUNCTIONAL_DIFFERENCE', 'the test distinguishes a repeated ignored alpha getter with a working Blob positive control');
  assert.equal(brokenAggregate.functionalDifferenceRuns, 5);
  assert.equal(brokenAggregate.metrics.getterNotReadExecutions, 5);

  const inconsistent = brokenA4.slice(0, 4).concat([canvasRecords.find(r => r.caseId === 'A4-alpha-false-getter')]);
  assert.equal(Core.summarizeReproducibility(inconsistent).concordantPercentage, 80, 'concordance uses the modal raw observation signature');

  const isolationMock = makeRuntime();
  const isolation = [];
  for (let run = 1; run <= 5; run++) isolation.push(Core.runIsolationCheck(isolationMock.runtime, meta, run));
  assert.equal(isolationMock.stats.canvases, 20, 'isolation control uses four independent canvases for each repetition');
  assert.ok(isolation.every(record => record.raw.executionStatus === 'PASS'));
  assert.equal(Core.aggregateIsolation(isolation).classification, 'EXPECTED');
  assert.ok(isolation.every(record => record.raw.observed.independentCanvasesMatchBlank));

  const noCanvas = Core.runCanvasCase('A1-baseline', { document: { createElement() { return {}; } } }, meta, 1);
  assert.equal(noCanvas.raw.executionStatus, 'SKIPPED');
  assert.equal(noCanvas.interpretation.classification, 'SKIPPED');
  const noBlob = Core.runBlobControl({ Blob: null }, meta, 1);
  assert.equal(noBlob.raw.executionStatus, 'SKIPPED');
  assert.equal(noBlob.interpretation.classification, 'SKIPPED');
  const thrown = Core.runCanvasCase('A1-baseline', makeRuntime({ throwGetContext: true }).runtime, meta, 1);
  assert.equal(thrown.raw.executionStatus, 'ERROR');
  assert.equal(thrown.raw.exceptions[0].phase, 'getContext');
  assert.match(thrown.raw.exceptions[0].stack, /controlled getContext error/);
  const pixelThrown = Core.runCanvasCase('A1-baseline', makeRuntime({ throwPixel: true }).runtime, meta, 1);
  assert.equal(pixelThrown.raw.executionStatus, 'ERROR');
  assert.equal(pixelThrown.raw.exceptions[0].phase, 'fill-clear-read-pixel');

  assert.equal(Core.runCrossOriginInterpretation({ loadStatus: 'error' }, 'SKIPPED').classification, 'SKIPPED');
  assert.equal(Core.runCrossOriginInterpretation({ crossOriginVerified: true, loadStatus: 'loaded', getImageDataError: 'SecurityError', toDataURLError: 'SecurityError' }, 'PASS').classification, 'EXPECTED');
  assert.equal(Core.runCrossOriginInterpretation({ crossOriginVerified: true, loadStatus: 'loaded', getImageDataSucceeded: true }, 'PASS').classification, 'SECURITY_BOUNDARY_ANOMALY_PENDING_REPRODUCTION');

  const scannerResult = Core.toScannerResult(canvasRecords[0]);
  assert.equal(scannerResult.state, 'PASS');
  assert.ok(scannerResult.observed.raw && scannerResult.observed.interpretation, 'raw observations remain separate from interpretation in server event data');
  assert.equal(Object.prototype.hasOwnProperty.call(scannerResult.observed.raw, 'classification'), false);
  const exportObject = Core.exportReport(meta, [{ runIndex: 1 }], [canvasRecords[0]], [a4], 0);
  const serialized = JSON.stringify(exportObject);
  const reparsed = JSON.parse(serialized);
  assert.equal(reparsed.rawResults[0].raw.observed.pixelRGBA[3], 0);
  assert.equal(reparsed.rawResults[0].interpretation.classification, 'EXPECTED');
  assert.equal(Core.validateRecord({}).valid, false, 'required fields are validated');

  console.log('canvas security impact core: cases, five-run repeatability, alpha pixels, Blob control, isolation, skips, exceptions, classifications, and JSON export passed');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
