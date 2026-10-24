// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const zlib = require('node:zlib');
const tarStream = require('tar-stream');

/** Build the in-memory file map the scanner works on. */
function filesFrom(obj) {
  const m = new Map();
  for (const [p, text] of Object.entries(obj)) {
    const buf = Buffer.from(text);
    m.set(p, { size: buf.length, content: buf });
  }
  return m;
}

/** Build a .tgz in memory. entries: [{ name, content?, type?, linkname? }] */
function makeTgz(entries) {
  return new Promise((resolve, reject) => {
    const pack = tarStream.pack();
    const chunks = [];
    const gz = zlib.createGzip();
    gz.on('data', (c) => chunks.push(c));
    gz.on('end', () => resolve(Buffer.concat(chunks)));
    gz.on('error', reject);
    pack.pipe(gz);
    for (const e of entries) {
      const header = { name: e.name, type: e.type || 'file' };
      if (e.linkname) header.linkname = e.linkname;
      if (header.type === 'file') pack.entry(header, e.content || '');
      else pack.entry(header);
    }
    pack.finalize();
  });
}

module.exports = { filesFrom, makeTgz };
