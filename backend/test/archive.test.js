// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Tiny limits so the bomb test is fast. Must be set before config loads.
process.env.MAX_UNPACKED_MB = '1';
process.env.MAX_FILES = '50';

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { readTarGz, readZip, safeEntryPath } = require('../src/scanner/archive');
const { makeTgz } = require('./helpers');

test('safeEntryPath rejects traversal, absolute and drive paths', () => {
  for (const p of ['../x', 'a/../../x', '/etc/passwd', 'C:\\Windows\\x', 'a\\..\\..\\x', 'ok\0.js', '']) {
    assert.equal(safeEntryPath(p), null, p);
  }
  assert.equal(safeEntryPath('package/index.js'), 'package/index.js');
  assert.equal(safeEntryPath('./package/a/../b.js'), 'package/b.js');
});

test('tarballs: hostile entries are reported, never read', async () => {
  const tgz = await makeTgz([
    { name: 'package/package.json', content: '{"name":"x"}' },
    { name: 'package/../../escape.js', content: 'evil' },
    { name: 'package/link', type: 'symlink', linkname: '/home/user/.ssh/id_rsa' },
    { name: 'package/hard', type: 'link', linkname: 'package/package.json' },
    { name: 'package/dev', type: 'character-device' },
  ]);
  const r = await readTarGz(tgz, 'x.tgz', { stripFirstDir: true });
  assert.deepEqual([...r.files.keys()], ['package.json']);
  const reasons = r.findings.map((f) => f.detail).join(' | ');
  assert.match(reasons, /escapes the package root/);
  assert.match(reasons, /symlink entry/);
  assert.match(reasons, /link entry/);
  assert.match(reasons, /character-device entry/);
});

test('decompression bombs stop at the unpack limit (SEC-2)', async () => {
  const bomb = await makeTgz([{ name: 'package/zeros.bin', content: Buffer.alloc(5 * 1024 * 1024) }]);
  assert.ok(bomb.length < 20000, 'fixture should be tiny when compressed');
  const r = await readTarGz(bomb, 'bomb.tgz');
  assert.ok(r.findings.some((f) => f.ruleId === 'R-ARCH-02'));
});

test('too many files stops reading (SEC-2)', async () => {
  const entries = Array.from({ length: 60 }, (_, i) => ({ name: `package/f${i}.js`, content: '1' }));
  const r = await readTarGz(await makeTgz(entries), 'many.tgz');
  assert.ok(r.findings.some((f) => f.ruleId === 'R-ARCH-02'));
  assert.ok(r.files.size <= 50);
});

test('corrupt archives fail cleanly', async () => {
  await assert.rejects(readTarGz(Buffer.from('not a gzip'), 'bad.tgz'), /Corrupt/);
  await assert.rejects(readTarGz(zlib.gzipSync(Buffer.from('not a tar file at all, just text')), 'bad2.tgz'), /Corrupt/);
  await assert.rejects(readZip(Buffer.from('PK nope'), 'bad.whl'), /Corrupt/);
});
