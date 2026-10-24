'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Core = require('../pages/vulnerability-scanner-core.js');

async function main() {
  const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/cve-catalog.json'), 'utf8'));
  assert.equal(Core.validateCatalog(catalog).valid, true, 'bundled vulnerability catalog validates');
  assert.equal(Core.validateCatalog({ schemaVersion: 1, updatedAt: 'now', provenance: 'test', entries: [{ id: 'not-a-cve' }] }).valid, false, 'invalid CVE IDs are rejected');

  const result = {
    id: 'canvas.context', category: 'Canvas e grafica', description: 'Tiny controlled canvas test.', state: 'PASS',
    observed: { contextCreated: true }, error: null, durationMs: 1, limitations: ['No exploitability claim.'], sessionId: 'test-session-0001'
  };
  assert.deepEqual(Core.validateResult(result), { valid: true });
  assert.equal(Core.validateResult({ ...result, state: 'VULNERABLE' }).valid, false, 'unsupported result states are rejected');

  const dossier = Core.buildDossier({ sessionId: result.sessionId, startedAt: '2026-10-24T00:00:00Z', declaredFirmware: '14.10', environment: { userAgent: 'test' }, results: [result], transmissionErrors: [] }, catalog);
  assert.equal(dossier.conclusions.factsObserved.length, 1);
  assert.ok(dossier.conclusions.vulnerabilityCorrelations.every(item => item.applicability === 'UNKNOWN'));
  assert.match(Core.renderMarkdown(dossier), /Fatti osservati/);
  assert.match(Core.renderMarkdown(dossier), /nvd\.nist\.gov/);

  let timedOut = false;
  await assert.rejects(
    Core.withTimeout(new Promise(() => {}), 15, () => { timedOut = true; }),
    error => error.name === 'TimeoutError'
  );
  assert.equal(timedOut, true, 'timeout calls the resource cleanup hook');
  console.log('scanner core: catalog, result, dossier, Markdown, and timeout checks passed');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
