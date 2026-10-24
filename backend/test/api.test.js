// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_SCANS_PER_MIN = '5';
process.env.MAX_ACTIVE_SCANS = '1';
process.env.MAX_QUEUED_SCANS = '1';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');
const { parseSpec } = require('../src/scanner/spec');

let calls = 0;
let delayMs = 0;
async function stubScan(input) {
  const spec = parseSpec(input); // real validation
  calls += 1;
  if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
  return { package: spec, verdict: 'allow', requested: spec.version, score: { final: 0 } };
}

async function withServer(fn) {
  const app = createApp({ scanPackage: stubScan });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    server.close();
  }
}

test('health, meta and rules endpoints', async () => {
  await withServer(async (base) => {
    assert.deepEqual(await (await fetch(`${base}/health`)).json(), { status: 'ok' });
    const meta = await (await fetch(`${base}/api/v1`)).json();
    assert.equal(meta.name, 'depvault-api');
    assert.deepEqual(meta.thresholds, { warn: 30, block: 70 });
    const rules = await (await fetch(`${base}/api/v1/rules`)).json();
    assert.ok(rules.rules.some((r) => r.id === 'R-CRED-01'));
  });
});

test('security headers are strict', async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/api/v1`);
    assert.equal(res.headers.get('content-security-policy'), "default-src 'none';frame-ancestors 'none';base-uri 'none';form-action 'none'");
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-powered-by'), null);
    assert.ok(res.headers.get('x-request-id'));
  });
});

test('CORS allows the website and refuses other origins', async () => {
  await withServer(async (base) => {
    const good = await fetch(`${base}/api/v1`, { headers: { origin: 'https://depvault.netlify.app' } });
    assert.equal(good.headers.get('access-control-allow-origin'), 'https://depvault.netlify.app');
    const bad = await fetch(`${base}/api/v1`, { headers: { origin: 'https://evil.example' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });
});

test('scan input validation and error shapes', async () => {
  await withServer(async (base) => {
    const cases = [
      [fetch(`${base}/api/v1/scan`), 400, 'invalid_package'],
      [fetch(`${base}/api/v1/scan?package=npm:../x`), 400, 'invalid_package'],
      [fetch(`${base}/api/v1/scan`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' }), 415, 'unsupported_media_type'],
      [fetch(`${base}/api/v1/scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' }), 400, 'invalid_json'],
      [fetch(`${base}/api/v1/scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: 'x'.repeat(5000) }) }), 413, 'payload_too_large'],
      [fetch(`${base}/nope`), 404, 'not_found'],
    ];
    for (const [p, status, code] of cases) {
      const res = await p;
      assert.equal(res.status, status);
      assert.equal((await res.json()).error.code, code);
    }
  });
});

test('GET and POST scans work, and the scan rate limit applies', async () => {
  await withServer(async (base) => {
    const post = await fetch(`${base}/api/v1/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ecosystem: 'pypi', name: 'requests', version: '2.31.0' }),
    });
    assert.equal(post.status, 200);
    assert.equal((await post.json()).package.name, 'requests');

    const get = await fetch(`${base}/api/v1/scan?package=${encodeURIComponent('npm:express@4.21.2')}`);
    assert.equal(get.status, 200);
    assert.equal(get.headers.get('cache-control'), 'public, max-age=300');

    // Limit is 5 per minute in this test; 2 used above (plus 1 from the validation test's server instance is separate).
    let last;
    for (let i = 0; i < 4; i += 1) last = await fetch(`${base}/api/v1/scan?package=npm:react`);
    assert.equal(last.status, 429);
    assert.equal((await last.json()).error.code, 'rate_limited');
  });
});

test('excess concurrent scans get 503 instead of piling up', async () => {
  delayMs = 300;
  await withServer(async (base) => {
    const url = (n) => `${base}/api/v1/scan?package=npm:pkg-${n}`;
    const results = await Promise.all([1, 2, 3].map((n) => fetch(url(n)).then((r) => r.status)));
    assert.deepEqual(results.sort(), [200, 200, 503]);
  });
  delayMs = 0;
});
