// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scanCode } = require('../src/scanner/checks/code');
const { aggregate, ruleScore, verdictFor } = require('../src/scanner/scoring');
const { filesFrom } = require('./helpers');
const demo = require('./fixtures/demo-packages');

function evaluate(ecosystem, files) {
  const code = scanCode(ecosystem, filesFrom(files));
  const findings = aggregate(code.findings);
  const score = ruleScore(findings, code.hardBlocks);
  return { code, findings, ids: findings.map((f) => f.ruleId), score, verdict: verdictFor(score) };
}

test('malicious postinstall that reads a key and phones home is a hard Block', () => {
  const r = evaluate('npm', demo.maliciousNpm);
  assert.deepEqual(r.code.hardBlocks, ['setup.js']);
  assert.equal(r.score, 100);
  assert.equal(r.verdict, 'block');
  for (const id of ['R-SCRIPT-01', 'R-CRED-01', 'R-NET-01', 'R-NET-02']) assert.ok(r.ids.includes(id), `missing ${id}`);
  const cred = r.findings.find((f) => f.ruleId === 'R-CRED-01');
  assert.equal(cred.context, 'install');
  assert.equal(cred.evidence[0].file, 'setup.js');
  assert.equal(cred.evidence[0].line, 5);
});

test('prompt-injection text is flagged and the package is blocked on rules alone', () => {
  const r = evaluate('npm', demo.injectionNpm);
  assert.ok(r.ids.includes('R-INJECT-01'));
  assert.ok(r.ids.includes('R-CRED-01'));
  assert.equal(r.verdict, 'block'); // 10 + 40 + 30 = 80, no AI needed
});

test('a clean package scores zero', () => {
  const r = evaluate('npm', demo.cleanNpm);
  assert.deepEqual(r.ids, []);
  assert.equal(r.verdict, 'allow');
});

test('setup.py with a custom install class and exec(b64decode) is caught', () => {
  const r = evaluate('pypi', demo.maliciousPypi);
  assert.ok(r.ids.includes('R-SETUP-01'));
  assert.ok(r.ids.includes('R-OBF-01'));
  assert.equal(r.findings.find((f) => f.ruleId === 'R-OBF-01').context, 'install');
  assert.equal(r.verdict, 'warn'); // 15 + 30 = 45
});

test('.pth files with import lines are treated as install-time code', () => {
  const r = evaluate('pypi', demo.pthWheel);
  assert.ok(r.ids.includes('R-PTH-01'));
  assert.ok(r.ids.includes('R-EXEC-01'));
  assert.equal(r.verdict, 'warn');
});

test('tests, docs and runtime-only network code do not raise the score', () => {
  const r = evaluate('npm', demo.noisyButSafe);
  assert.deepEqual(r.ids, []);
});

test('evidence snippets strip ANSI escapes and control characters (SEC-8)', () => {
  const r = evaluate('npm', {
    'package.json': JSON.stringify({ scripts: { postinstall: 'node a.js' } }),
    'a.js': "const k = '\u001b[2J\u001b[31m' + require('os').homedir() + '/.ssh/id_rsa';\u0007",
  });
  const snippet = r.findings.find((f) => f.ruleId === 'R-CRED-01').evidence[0].snippet;
  assert.ok(!/[\x00-\x08\x0b-\x1f\x7f]/.test(snippet), snippet);
});

test('install files are followed one level through local requires', () => {
  const r = evaluate('npm', {
    'package.json': JSON.stringify({ scripts: { preinstall: 'node scripts/pre.js' } }),
    'scripts/pre.js': "require('./lib/payload');",
    'scripts/lib/payload.js': "require('child_process').execSync('id');",
  });
  assert.ok(r.code.installFiles.includes('scripts/lib/payload.js'));
  assert.equal(r.findings.find((f) => f.ruleId === 'R-EXEC-01').context, 'install');
});

test('very long minified lines are scanned without hanging (SEC-7)', () => {
  const huge = `var a=${'x'.repeat(400000)};eval(atob("ZGVtbw=="));`;
  const start = Date.now();
  const r = evaluate('npm', { 'package.json': '{}', 'dist/app.min.js': huge });
  assert.ok(Date.now() - start < 2000, 'took too long');
  assert.ok(r.ids.includes('R-OBF-01'));
});
