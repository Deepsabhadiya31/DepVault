// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const zlib = require('node:zlib');
const path = require('node:path');
const { Readable } = require('node:stream');
const tarStream = require('tar-stream');
const yauzl = require('yauzl');
const config = require('../config');

/**
 * Read package archives entirely in memory (SEC-1, SEC-2, SEC-3).
 * Nothing is written to disk and nothing is executed, so there is no
 * extraction directory to escape. Hostile entries are still reported as findings,
 * because a legitimate package has no reason to contain them.
 */

const SCANNABLE = new Set([
  '.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts',
  '.py', '.pyw', '.pth', '.sh', '.bash', '.ps1', '.bat', '.cmd',
  '.json', '.cfg', '.toml', '.txt', '.md', '.gyp', '.yml', '.yaml',
]);
const ALWAYS_SCAN = new Set(['setup.py', 'package.json', 'binding.gyp', 'makefile']);

function isScannable(filePath) {
  const base = path.posix.basename(filePath).toLowerCase();
  if (ALWAYS_SCAN.has(base)) return true;
  return SCANNABLE.has(path.posix.extname(base));
}

/** Returns a safe, normalized relative path or null if the entry path is hostile. */
function safeEntryPath(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 1024) return null;
  if (name.includes('\0')) return null;
  const unified = name.replace(/\\/g, '/');
  if (unified.startsWith('/') || /^[a-zA-Z]:/.test(unified)) return null;
  const normalized = path.posix.normalize(unified);
  if (normalized === '..' || normalized.startsWith('../') || normalized.split('/').includes('..')) return null;
  return normalized.replace(/^\.\//, '');
}

class ArchiveReader {
  constructor(label) {
    this.label = label;
    this.files = new Map();
    this.findings = [];
    this.unpackedBytes = 0;
    this.fileCount = 0;
    this.stopped = false;
  }

  hostile(ruleId, detail, entryName) {
    this.findings.push({ ruleId, detail, file: String(entryName).slice(0, 200) });
  }

  overLimit(kind) {
    if (!this.stopped) this.hostile('R-ARCH-02', kind, this.label);
    this.stopped = true;
  }

  /** Accounts for an entry; returns false when limits say to stop reading. */
  admit(size) {
    this.fileCount += 1;
    this.unpackedBytes += size;
    if (this.fileCount > config.limits.maxFiles) {
      this.overLimit(`more than ${config.limits.maxFiles} files`);
      return false;
    }
    if (this.unpackedBytes > config.limits.maxUnpackedBytes) {
      this.overLimit(`more than ${Math.round(config.limits.maxUnpackedBytes / 1048576)} MB unpacked`);
      return false;
    }
    return true;
  }

  add(filePath, size, content) {
    this.files.set(filePath, { size, content });
  }
}

/** Read a .tgz / .tar.gz buffer. */
function readTarGz(buffer, label, { stripFirstDir = false } = {}) {
  const reader = new ArchiveReader(label);
  return new Promise((resolve, reject) => {
    const extract = tarStream.extract();
    const gunzip = zlib.createGunzip();

    const finish = () => resolve(reader);
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    extract.on('entry', (header, stream, next) => {
      const drain = () => {
        stream.on('end', next);
        stream.resume();
      };
      if (reader.stopped) return drain();

      const safe = safeEntryPath(header.name);
      if (!safe) {
        reader.hostile('R-ARCH-01', 'path escapes the package root', header.name);
        return drain();
      }
      if (header.type !== 'file' && header.type !== 'directory') {
        reader.hostile('R-ARCH-01', `${header.type} entry`, header.name);
        return drain();
      }
      if (header.type === 'directory') return drain();
      if (!reader.admit(header.size || 0)) return drain();

      let rel = safe;
      if (stripFirstDir) rel = rel.split('/').slice(1).join('/') || rel;

      if (!isScannable(rel) || header.size > config.limits.maxScannedFileBytes) {
        reader.add(rel, header.size || 0, null);
        return drain();
      }

      const chunks = [];
      let got = 0;
      stream.on('data', (c) => {
        got += c.length;
        if (got <= config.limits.maxScannedFileBytes) chunks.push(c);
      });
      stream.on('end', () => {
        reader.add(rel, header.size || 0, Buffer.concat(chunks));
        next();
      });
      stream.on('error', fail);
    });

    extract.on('finish', () => {
      settled = true;
      finish();
    });
    extract.on('error', (err) => fail(new Error(`Corrupt tar archive: ${err.message}`)));

    // Hard stop on decompression bombs even if tar headers lie about sizes.
    let inflated = 0;
    gunzip.on('data', (c) => {
      inflated += c.length;
      if (inflated > config.limits.maxUnpackedBytes + 1048576) {
        reader.overLimit('decompressed stream exceeds the unpack limit');
        gunzip.destroy();
        extract.destroy();
        settled = true;
        finish();
      }
    });
    gunzip.on('error', (err) => fail(new Error(`Corrupt gzip data: ${err.message}`)));

    Readable.from([buffer]).pipe(gunzip).pipe(extract);
  });
}

/** Read a .whl / .zip buffer. */
function readZip(buffer, label) {
  const reader = new ArchiveReader(label);
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, validateEntrySizes: true, strictFileNames: false }, (err, zip) => {
      if (err) return reject(new Error(`Corrupt zip archive: ${err.message}`));

      zip.on('error', (e) => reject(new Error(`Corrupt zip archive: ${e.message}`)));
      zip.on('end', () => resolve(reader));
      zip.on('entry', (entry) => {
        if (reader.stopped) return zip.readEntry();

        const safe = safeEntryPath(entry.fileName);
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        if (!safe) {
          reader.hostile('R-ARCH-01', 'path escapes the package root', entry.fileName);
          return zip.readEntry();
        }
        if (mode === 0o120000) {
          reader.hostile('R-ARCH-01', 'symlink entry', entry.fileName);
          return zip.readEntry();
        }
        if (entry.fileName.endsWith('/')) return zip.readEntry();
        if (!reader.admit(entry.uncompressedSize)) return zip.readEntry();

        if (!isScannable(safe) || entry.uncompressedSize > config.limits.maxScannedFileBytes) {
          reader.add(safe, entry.uncompressedSize, null);
          return zip.readEntry();
        }

        zip.openReadStream(entry, (e2, stream) => {
          if (e2) return reject(new Error(`Corrupt zip entry: ${e2.message}`));
          const chunks = [];
          stream.on('data', (c) => chunks.push(c));
          stream.on('error', (e3) => reject(new Error(`Corrupt zip entry: ${e3.message}`)));
          stream.on('end', () => {
            reader.add(safe, entry.uncompressedSize, Buffer.concat(chunks));
            zip.readEntry();
          });
        });
      });
      zip.readEntry();
    });
  });
}

module.exports = { readTarGz, readZip, safeEntryPath, isScannable };
