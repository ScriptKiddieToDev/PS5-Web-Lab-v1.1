(function () {
  'use strict';

  var startedAt = new Date().toISOString();
  var started = Date.now();
  var report = {
    test: 'probe-canvas-reentrancy',
    status: 'COMPLETE',
    startedAt: startedAt,
    input: { contextType: '2d', outerOptions: { alpha: 'getter returns true' }, reentrantOptions: { alpha: false }, maxReentrantCalls: 1 },
    observed: {},
    exceptions: []
  };

  function getAttributes(context, label) {
    if (!context || typeof context.getContextAttributes !== 'function') return null;
    try { return context.getContextAttributes(); }
    catch (error) {
      report.exceptions.push({ operation: label + '.getContextAttributes', name: error.name || 'Error', message: String(error.message || error) });
      return null;
    }
  }

  try {
    if (typeof OffscreenCanvas === 'undefined') {
      report.status = 'SKIPPED';
      report.reason = 'OffscreenCanvas is unavailable in this execution context.';
    } else {
      var canvas = new OffscreenCanvas(2, 2);
      var reads = 0;
      var reentered = false;
      var innerContext = null;
      var options = {};
      Object.defineProperty(options, 'alpha', {
        enumerable: true,
        configurable: false,
        get: function () {
          reads += 1;
          if (!reentered) {
            reentered = true;
            try { innerContext = canvas.getContext('2d', { alpha: false }); }
            catch (error) { report.exceptions.push({ operation: 'reentrant-getContext', name: error.name || 'Error', message: String(error.message || error) }); }
          }
          return true;
        }
      });

      var outerContext = null;
      try { outerContext = canvas.getContext('2d', options); }
      catch (error) { report.exceptions.push({ operation: 'outer-getContext', name: error.name || 'Error', message: String(error.message || error) }); }

      report.observed = {
        getterReads: reads,
        reentrantCallMade: reentered,
        innerContextReturned: !!innerContext,
        outerContextReturned: !!outerContext,
        sameContext: !!innerContext && !!outerContext && innerContext === outerContext,
        innerAttributes: getAttributes(innerContext, 'inner'),
        outerAttributes: getAttributes(outerContext, 'outer')
      };
      if (!outerContext) report.status = 'ERROR';
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
    report = { test: 'probe-canvas-reentrancy', status: 'ERROR', startedAt: startedAt, durationMs: Date.now() - started, exceptions: [{ operation: 'JSON.stringify', name: error.name || 'Error', message: String(error.message || error) }] };
    serialized = JSON.stringify(report);
  }
  console.log('CANVAS_REENTRANCY_PROBE ' + serialized);
  return report;
}());
