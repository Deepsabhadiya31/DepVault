// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

/**
 * End-to-end scans against the real registries. Skipped unless LIVE_TESTS=1
 * so CI stays fast and offline-friendly: npm run test:live
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { scanPackage } = require('../src/scanner');

const live = process.env.LIVE_TESTS === '1';

test('express 4.21.2 is allowed with a verified hash', { skip: !live, timeout: 60000 }, async () => {
  const r = await scanPackage('npm:express@4.21.2');
  assert.equal(r.verdict, 'allow');
  assert.equal(r.artifacts[0].hashVerified, true);
});

test('a PyPI package with wheel and sdist scans both', { skip: !live, timeout: 60000 }, async () => {
  const r = await scanPackage('pypi:six==1.16.0');
  assert.deepEqual(r.artifacts.map((a) => a.type).sort(), ['sdist', 'wheel']);
  assert.ok(r.artifacts.every((a) => a.hashVerified));
});

test('a typo of a popular name gets a "did you mean"', { skip: !live, timeout: 60000 }, async () => {
  await assert.rejects(scanPackage('pypi:reqeusts'), (e) => e.code === 'not_found' && /requests/.test(e.message));
});

test('second scan of the same version is served from cache', { skip: !live, timeout: 60000 }, async () => {
  await scanPackage('npm:left-pad@1.3.0');
  const again = await scanPackage('npm:left-pad@1.3.0');
  assert.equal(again.cached, true);
});
