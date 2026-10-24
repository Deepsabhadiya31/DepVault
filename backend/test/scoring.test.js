// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { aggregate, ruleScore, finalScore, verdictFor } = require('../src/scanner/scoring');

const hit = (ruleId, context = 'metadata') => ({ ruleId, context, evidence: { file: null, line: null, snippet: 'x' } });

test('final score follows S = max(R, round(0.6R + 0.4A))', () => {
  assert.equal(finalScore(50, 100), 70);
  assert.equal(finalScore(10, 90), 42);
  assert.equal(finalScore(40, null), 40);
});

test('the AI can never lower the rule score (SEC-5)', () => {
  for (const rule of [0, 30, 71, 100]) assert.equal(finalScore(rule, 0), rule);
});

test('AI alone can reach Warn but never Block', () => {
  assert.equal(verdictFor(finalScore(0, 100)), 'warn');
});

test('verdict thresholds: Allow < 30, Warn 30 to 70, Block > 70', () => {
  assert.equal(verdictFor(29), 'allow');
  assert.equal(verdictFor(30), 'warn');
  assert.equal(verdictFor(70), 'warn');
  assert.equal(verdictFor(71), 'block');
});

test('metadata rules are capped at 20 points in total', () => {
  const f = aggregate([hit('R-META-01'), hit('R-META-02'), hit('R-META-03')]);
  assert.equal(ruleScore(f), 20);
});

test('repeated hits of one rule count once, with the highest context weight', () => {
  const f = aggregate([hit('R-CRED-01', 'runtime'), hit('R-CRED-01', 'runtime'), hit('R-CRED-01', 'install')]);
  assert.equal(f.length, 1);
  assert.equal(f[0].points, 40);
  assert.equal(f[0].occurrences, 3);
});

test('hash mismatch and known-malicious entries are hard blocks', () => {
  assert.equal(ruleScore(aggregate([hit('R-HASH-01', 'install')])), 100);
  assert.equal(ruleScore(aggregate([hit('R-MAL-01')])), 100);
});
