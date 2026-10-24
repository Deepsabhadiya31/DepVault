// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const http = require('node:http');

// A fake Ollama on localhost. Must be configured before the config module loads.
let reply = () => ({});
let requests = 0;
let lastBody = null;
const fake = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    requests += 1;
    lastBody = JSON.parse(body);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ message: { content: JSON.stringify(reply()) } }));
  });
});

const test = require('node:test');
const assert = require('node:assert/strict');

test('AI integration with a local Ollama', async (t) => {
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  process.env.OLLAMA_URL = `http://127.0.0.1:${fake.address().port}`;
  const ai = require('../src/scanner/ai');
  const { finalScore, verdictFor } = require('../src/scanner/scoring');
  const { filesFrom } = require('./helpers');

  const pkg = { ecosystem: 'npm', name: 'demo', version: '1.0.0' };
  const files = filesFrom({ 'install.js': "require('https').get('http://203.0.113.5')" });
  const findings = [{ ruleId: 'R-NET-01', title: 'x', evidence: [{ file: 'install.js', line: 1, snippet: 's' }] }];

  await t.test('sends a JSON-schema constrained, temperature-0 request', async () => {
    reply = () => ({ malicious: true, risk_score: 95, summary: 'Downloads a payload.', evidence: [{ file: 'install.js', line: 1, reason: 'net' }], injection_detected: false });
    const r = await ai.analyze(pkg, findings, files, ['install.js']);
    assert.equal(r.status, 'ok');
    assert.equal(r.riskScore, 95);
    assert.equal(lastBody.options.temperature, 0);
    assert.equal(lastBody.stream, false);
    assert.deepEqual(lastBody.format.required.sort(), ['evidence', 'injection_detected', 'malicious', 'risk_score', 'summary']);
    assert.match(lastBody.messages[1].content, /<package_files>[\s\S]*install\.js[\s\S]*<\/package_files>/);
    assert.equal(verdictFor(finalScore(50, r.riskScore)), 'warn'); // 0.6*50 + 0.4*95 = 68
  });

  await t.test('a model fooled into saying "safe" cannot lower the verdict', async () => {
    reply = () => ({ malicious: false, risk_score: 0, summary: 'Totally safe.', evidence: [], injection_detected: false });
    const r = await ai.analyze(pkg, findings, files, ['install.js']);
    assert.equal(finalScore(100, r.riskScore), 100);
    assert.equal(finalScore(55, r.riskScore), 55);
  });

  await t.test('malformed output is retried once, then the scan falls back to rules', async () => {
    requests = 0;
    reply = () => ({ verdict: 'whatever' });
    const r = await ai.analyze(pkg, findings, files, ['install.js']);
    assert.equal(r.status, 'unavailable');
    assert.equal(requests, 2);
  });

  await t.test('an unreachable model degrades gracefully', async () => {
    await new Promise((r) => fake.close(r));
    const r = await ai.analyze(pkg, findings, files, ['install.js']);
    assert.equal(r.status, 'unavailable');
  });
});
