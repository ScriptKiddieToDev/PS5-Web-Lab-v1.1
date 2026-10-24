(function () {
  'use strict';

  // Set this only to a controlled local fixture served from a different origin.
  // Example shape: http://192.168.1.4:8001/canvas-cross-origin.png
  var IMAGE_URL = 'CONFIGURE_LOCAL_CROSS_ORIGIN_FIXTURE_URL';
  var startedAt = new Date().toISOString();
  var started = Date.now();
  var report = {
    test: 'probe-canvas-origin-clean',
    status: 'COMPLETE',
    startedAt: startedAt,
    input: { imageUrl: IMAGE_URL, corsMode: 'no-cors (crossOrigin is not set)', apis: ['getImageData', 'toDataURL', 'toBlob'] },
    observed: {},
    exceptions: []
  };

  function finish() {
    report.durationMs = Date.now() - started;
    var serialized;
    try { serialized = JSON.stringify(report); }
    catch (error) {
      report = { test: 'probe-canvas-origin-clean', status: 'ERROR', startedAt: startedAt, durationMs: Date.now() - started, exceptions: [{ operation: 'JSON.stringify', name: error.name || 'Error', message: String(error.message || error) }] };
      serialized = JSON.stringify(report);
    }
    console.log('ORIGIN_CLEAN_PROBE ' + serialized);
    return report;
  }

  function isPrivateIPv4(host) {
    var match = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec(host);
    if (!match) return false;
    var parts = host.split('.').map(Number);
    if (parts.some(function (part) { return part < 0 || part > 255; })) return false;
    return parts[0] === 10 || parts[0] === 127 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31;
  }

  function localHost(host) {
    return host === 'localhost' || host === '::1' || host.slice(-6) === '.local' || isPrivateIPv4(host);
  }

  function rejected(reason, state) {
    report.status = state;
    report.reason = reason;
    return finish();
  }

  if (IMAGE_URL === 'CONFIGURE_LOCAL_CROSS_ORIGIN_FIXTURE_URL' || !IMAGE_URL) {
    return rejected('Set IMAGE_URL to a controlled local cross-origin image fixture before running.', 'SKIPPED');
  }
  if (typeof document === 'undefined' || typeof Image === 'undefined') {
    return rejected('This probe requires a document and Image; the isolated research runner worker does not provide them.', 'SKIPPED');
  }

  var parsedUrl = document.createElement('a');
  parsedUrl.href = IMAGE_URL;
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return rejected('Only HTTP/HTTPS local fixture URLs are accepted.', 'ERROR');
  }
  if (!localHost(parsedUrl.hostname.toLowerCase())) {
    return rejected('Fixture host is not localhost, .local, loopback, or a private IPv4 address; no request was made.', 'ERROR');
  }
  if (parsedUrl.origin && window.location && parsedUrl.origin === window.location.origin) {
    return rejected('Fixture must be served from an origin different from this page.', 'ERROR');
  }

  var image = new Image();
  var timer = null;
  var settled = false;

  function loadFailure(message, name) {
    if (settled) return;
    settled = true;
    if (timer !== null) clearTimeout(timer);
    report.status = 'ERROR';
    report.loadError = { name: name || 'ImageLoadError', message: message };
    finish();
  }

  image.onload = function () {
    if (settled) return;
    settled = true;
    if (timer !== null) clearTimeout(timer);
    report.observed.image = { width: image.naturalWidth, height: image.naturalHeight, loaded: true };
    try {
      var canvas = document.createElement('canvas');
      canvas.width = Math.max(1, image.naturalWidth);
      canvas.height = Math.max(1, image.naturalHeight);
      var context = canvas.getContext('2d');
      if (!context) throw new Error('Could not create 2D canvas context');
      context.drawImage(image, 0, 0);

      try {
        var pixel = context.getImageData(0, 0, 1, 1).data;
        report.observed.getImageData = { outcome: 'ALLOWED', pixel: Array.prototype.slice.call(pixel) };
      } catch (error) {
        report.observed.getImageData = { outcome: error.name === 'SecurityError' ? 'BLOCKED_SECURITY' : 'ERROR', exception: { name: error.name || 'Error', message: String(error.message || error) } };
        if (error.name !== 'SecurityError') report.exceptions.push({ operation: 'getImageData', name: error.name || 'Error', message: String(error.message || error) });
      }

      try {
        var dataUrl = canvas.toDataURL();
        report.observed.toDataURL = { outcome: 'ALLOWED', mimeType: dataUrl.slice(5, dataUrl.indexOf(';')), length: dataUrl.length };
      } catch (error) {
        report.observed.toDataURL = { outcome: error.name === 'SecurityError' ? 'BLOCKED_SECURITY' : 'ERROR', exception: { name: error.name || 'Error', message: String(error.message || error) } };
        if (error.name !== 'SecurityError') report.exceptions.push({ operation: 'toDataURL', name: error.name || 'Error', message: String(error.message || error) });
      }

      if (typeof canvas.toBlob !== 'function') {
        report.observed.toBlob = { outcome: 'SKIPPED_API_UNAVAILABLE' };
      } else {
        var readbackDone = false;
        var blobTimer = setTimeout(function () {
          if (readbackDone) return;
          readbackDone = true;
          report.observed.toBlob = { outcome: 'ERROR', exception: { name: 'TimeoutError', message: 'toBlob callback did not complete within 3000 ms.' } };
          report.exceptions.push({ operation: 'toBlob', name: 'TimeoutError', message: 'toBlob callback did not complete within 3000 ms.' });
          finishReadback();
        }, 3000);
        try {
          canvas.toBlob(function (blob) {
            if (readbackDone) return;
            readbackDone = true;
            clearTimeout(blobTimer);
            report.observed.toBlob = { outcome: blob ? 'ALLOWED' : 'NULL_BLOB', mimeType: blob && blob.type || null, size: blob && blob.size || 0 };
            finishReadback();
          });
        } catch (error) {
          if (readbackDone) return;
          readbackDone = true;
          clearTimeout(blobTimer);
          report.observed.toBlob = { outcome: error.name === 'SecurityError' ? 'BLOCKED_SECURITY' : 'ERROR', exception: { name: error.name || 'Error', message: String(error.message || error) } };
          if (error.name !== 'SecurityError') report.exceptions.push({ operation: 'toBlob', name: error.name || 'Error', message: String(error.message || error) });
          finishReadback();
        }
      }

      function finishReadback() {
        var outcomes = ['getImageData', 'toDataURL', 'toBlob'].map(function (name) { return report.observed[name] && report.observed[name].outcome; });
        report.observed.securityCheckConsistent = outcomes.every(function (outcome) { return outcome === 'BLOCKED_SECURITY' || outcome === 'SKIPPED_API_UNAVAILABLE'; });
        if (report.exceptions.length) report.status = 'ERROR';
        else if (outcomes.some(function (outcome) { return outcome === 'ALLOWED'; })) report.status = 'UNEXPECTED';
        finish();
      }
    } catch (error) {
      report.status = 'ERROR';
      report.exceptions.push({ operation: 'drawImage-or-setup', name: error.name || 'Error', message: String(error.message || error) });
      finish();
    }
  };
  image.onerror = function () { loadFailure('Image fixture failed to load; this is a loading failure, not a readback security result.', 'ImageLoadError'); };
  timer = setTimeout(function () { loadFailure('Timed out while loading the local fixture.', 'TimeoutError'); }, 8000);

  // Deliberately leave image.crossOrigin unset. The browser must request a no-CORS image.
  image.src = IMAGE_URL;
  return undefined;
}());
