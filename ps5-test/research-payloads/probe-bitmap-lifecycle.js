(function () {
  'use strict';

  var startedAt = new Date().toISOString();
  var started = Date.now();
  var iterationLimit = 10;
  var report = {
    test: 'probe-bitmap-lifecycle',
    status: 'COMPLETE',
    startedAt: startedAt,
    input: { iterations: iterationLimit, initialSize: [2, 2], resizedSize: [4, 3], snapshotColor: [255, 0, 0, 255], postResizeColor: [0, 0, 255, 255] },
    observed: [],
    exceptions: []
  };

  function pixel(context) {
    return Array.prototype.slice.call(context.getImageData(0, 0, 1, 1).data);
  }

  function paint(canvas, color) {
    var context = canvas.getContext('2d', { alpha: false });
    if (!context) throw new Error('Could not create 2D context');
    context.fillStyle = color;
    context.fillRect(0, 0, canvas.width, canvas.height);
    return context;
  }

  function oneIteration(index) {
    var source = new OffscreenCanvas(2, 2);
    paint(source, 'rgb(255, 0, 0)');
    var bitmap = null;
    var entry = { index: index, expected: { width: 2, height: 2, pixel: [255, 0, 0, 255] } };

    return createImageBitmap(source).then(function (createdBitmap) {
      bitmap = createdBitmap;
      entry.observedBitmapSize = [bitmap.width, bitmap.height];

      // Mutate the source immediately after createImageBitmap() has been requested.
      source.width = 4;
      source.height = 3;
      paint(source, 'rgb(0, 0, 255)');
      entry.sourceAfterResize = { size: [source.width, source.height], pixel: pixel(source.getContext('2d')) };

      var destination = new OffscreenCanvas(bitmap.width || 1, bitmap.height || 1);
      var destinationContext = destination.getContext('2d', { alpha: false });
      if (!destinationContext) throw new Error('Could not create destination 2D context');
      destinationContext.drawImage(bitmap, 0, 0);
      entry.bitmapPixel = pixel(destinationContext);
      entry.comparison = {
        dimensionsMatchSnapshot: bitmap.width === 2 && bitmap.height === 2,
        pixelMatchesPreMutationSource: entry.bitmapPixel.join(',') === '255,0,0,255',
        differsFromPostMutationSource: entry.bitmapPixel.join(',') !== '0,0,255,255'
      };
      return entry;
    }).catch(function (error) {
      entry.error = { name: error.name || 'Error', message: String(error.message || error) };
      report.exceptions.push({ operation: 'iteration-' + index, name: error.name || 'Error', message: String(error.message || error) });
      return entry;
    }).then(function (result) {
      if (bitmap && typeof bitmap.close === 'function') {
        try { bitmap.close(); result.bitmapClosed = true; }
        catch (error) {
          result.bitmapClosed = false;
          result.closeError = { name: error.name || 'Error', message: String(error.message || error) };
          report.exceptions.push({ operation: 'bitmap-close-' + index, name: error.name || 'Error', message: String(error.message || error) });
        }
      } else if (bitmap) {
        result.bitmapClosed = false;
        result.closeUnavailable = true;
        report.exceptions.push({ operation: 'bitmap-close-' + index, name: 'NotSupportedError', message: 'ImageBitmap.close() is unavailable; the bitmap could not be explicitly released.' });
      }
      report.observed.push(result);
    });
  }

  var run;
  if (typeof createImageBitmap !== 'function') {
    report.status = 'SKIPPED';
    report.reason = 'createImageBitmap() is unavailable.';
    run = Promise.resolve();
  } else if (typeof OffscreenCanvas === 'undefined') {
    report.status = 'SKIPPED';
    report.reason = 'OffscreenCanvas is unavailable in this execution context.';
    run = Promise.resolve();
  } else {
    run = Promise.resolve();
    for (var i = 0; i < iterationLimit; i += 1) {
      (function (index) { run = run.then(function () { return oneIteration(index); }); }(i));
    }
  }

  return run.then(function () {
    if (report.exceptions.length) report.status = 'ERROR';
    report.durationMs = Date.now() - started;
    var serialized;
    try { serialized = JSON.stringify(report); }
    catch (error) {
      report = { test: 'probe-bitmap-lifecycle', status: 'ERROR', startedAt: startedAt, durationMs: Date.now() - started, exceptions: [{ operation: 'JSON.stringify', name: error.name || 'Error', message: String(error.message || error) }] };
      serialized = JSON.stringify(report);
    }
    console.log('BITMAP_PROBE ' + serialized);
    return report;
  }).catch(function (error) {
    report.status = 'ERROR';
    report.exceptions.push({ operation: 'campaign', name: error.name || 'Error', message: String(error.message || error) });
    report.durationMs = Date.now() - started;
    console.log('BITMAP_PROBE ' + JSON.stringify(report));
    return report;
  });
}());
