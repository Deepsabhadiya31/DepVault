// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSpec } = require('../src/scanner/spec');
const { checkTyposquat, osaDistance } = require('../src/scanner/checks/typosquat');

test('parses npm, scoped npm and PyPI specs', () => {
  assert.deepEqual(parseSpec('npm:express@4.21.2'), { ecosystem: 'npm', name: 'express', version: '4.21.2' });
  assert.deepEqual(parseSpec('npm:@babel/core@7.0.0'), { ecosystem: 'npm', name: '@babel/core', version: '7.0.0' });
  assert.deepEqual(parseSpec('npm:@babel/core'), { ecosystem: 'npm', name: '@babel/core', version: 'latest' });
  assert.deepEqual(parseSpec('pypi:Requests==2.31.0'), { ecosystem: 'pypi', name: 'requests', version: '2.31.0' });
  assert.deepEqual(parseSpec('pip:Flask_Login'), { ecosystem: 'pypi', name: 'flask-login', version: 'latest' });
  assert.deepEqual(parseSpec({ ecosystem: 'npm', name: 'react', version: 'next' }), { ecosystem: 'npm', name: 'react', version: 'next' });
});

test('rejects anything that could reach a URL unsafely', () => {
  const bad = [
    'npm:../etc/passwd',
    'npm:express@../../x',
    'npm:EXPRESS',
    'npm:a/b',
    'npm:express@1.0.0?x=1',
    'pypi:req uests',
    'pypi:requests==1.0/../../',
    'cargo:serde',
    'express',
    `npm:${'a'.repeat(300)}`,
    'npm:%2e%2e',
    'npm:exp\u0000ress',
  ];
  for (const s of bad) assert.throws(() => parseSpec(s), (e) => e.code === 'invalid_package', s);
  assert.throws(() => parseSpec(42), (e) => e.code === 'invalid_package');
  assert.throws(() => parseSpec(null), (e) => e.code === 'invalid_package');
});

test('typosquat detection', () => {
  assert.equal(checkTyposquat('npm', 'expresss').target, 'express');
  assert.equal(checkTyposquat('npm', 'lodahs').target, 'lodash');
  assert.equal(checkTyposquat('pypi', 'reqeusts').target, 'requests');
  assert.equal(checkTyposquat('pypi', 'python-dateutil'), null); // the real one
  assert.equal(checkTyposquat('pypi', 'pythondateutil').reason, 'only separators differ');
  assert.equal(checkTyposquat('npm', 'react'), null);
  assert.equal(checkTyposquat('npm', 'preact'), null);
  assert.equal(checkTyposquat('npm', '@evil/express'), null);
  assert.equal(checkTyposquat('npm', 'zzzzzzzzzz-unique'), null);
});

test('OSA distance counts a transposition as one edit', () => {
  assert.equal(osaDistance('reqeusts', 'requests', 2), 1);
  assert.equal(osaDistance('abc', 'abc', 2), 0);
  assert.equal(osaDistance('kitten', 'sitting', 1), 2);
});
