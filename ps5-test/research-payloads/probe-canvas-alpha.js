(function () {
  'use strict';

  var startedAt = new Date().toISOString();
  var started = Date.now();
  var input = {
    contextType: '2d',
    colors: ['rgba(255, 0, 0, 0)', 'rgba(0, 255, 0, 0)'],
    cases: ['fresh-alpha-false', 'fresh-alpha-true', 'preinitialized-alpha-true-then-request-false']
  };
  var report = { test: 'probe-canvas-alpha', status: 'COMPLETE', startedAt: startedAt, input: input, observed: {}, exceptions: [] };

  function makeCanvas() {
    return new OffscreenCanvas(2, 2);
  }

  function attributes(context) {
    if (!context || typeof context.getContextAttributes !== 'function') return null;
    try { return context.getContextAttributes(); }
    catch (error) { report.exceptions.push({ operation: 'getContextAttributes', name: error.name || 'Error', message: String(error.message || error) }); return null; }
  }

  function sample(context) {
    context.fillStyle = 'rgba(255, 0, 0, 0)';
    context.fillRect(0, 0, 2, 2);
    return Array.prototype.slice.call(context.getImageData(0, 0, 1, 1).data);
  }

  try {
    if (typeof OffscreenCanvas === 'undefined') {
      report.status = 'SKIPPED';
      report.reason = 'OffscreenCanvas is unavailable in this execution context.';
    } else {
      [false, true].forEach(function (alpha) {
        try {
          var canvas = makeCanvas();
          var context = canvas.getContext('2d', { alpha: alpha });
          if (!context) throw new Error('getContext returned null');
          report.observed[alpha ? 'freshAlphaTrue' : 'freshAlphaFalse'] = {
            requestedAlpha: alpha,
            attributes: attributes(context),
            pixel: sample(context)
          };
        } catch (error) {
          report.exceptions.push({ operation: alpha ? 'fresh-alpha-true' : 'fresh-alpha-false', name: error.name || 'Error', message: String(error.message || error) });
        }
      });

      try {
        var initializedCanvas = makeCanvas();
        var firstContext = initializedCanvas.getContext('2d', { alpha: true });
        if (!firstContext) throw new Error('Initial getContext returned null');
        var secondContext = initializedCanvas.getContext('2d', { alpha: false });
        if (!secondContext) throw new Error('Second getContext returned null');
        report.observed.preinitialized = {
          initialRequest: { alpha: true },
          laterRequest: { alpha: false },
          sameContext: firstContext === secondContext,
          initialAttributes: attributes(firstContext),
          returnedAttributes: attributes(secondContext),
          pixel: sample(secondContext)
        };
      } catch (error) {
        report.exceptions.push({ operation: 'preinitialized-context', name: error.name || 'Error', message: String(error.message || error) });
      }

      if (!Object.keys(report.observed).length) report.status = 'ERROR';
      else if (report.exceptions.length) report.status = 'ERROR';
    }
  } catch (error) {
    report.status = 'ERROR';
    report.exceptions.push({ operation: 'probe', name: error.name || 'Error', message: String(error.message || error) });
  }

  report.durationMs = Date.now() - started;
  var serialized;
  try { serialized = JSON.stringify(report); }
  catch (error) {
    report = { test: 'probe-canvas-alpha', status: 'ERROR', startedAt: startedAt, durationMs: Date.now() - started, exceptions: [{ operation: 'JSON.stringify', name: error.name || 'Error', message: String(error.message || error) }] };
    serialized = JSON.stringify(report);
  }
  console.log('CANVAS_ALPHA_PROBE ' + serialized);
  return report;
}());
