// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { errors } = require('../errors');

/**
 * Parse and strictly validate a package spec (FR-1).
 * Accepts "npm:express@4.21.2", "npm:@scope/pkg@1.0.0", "pypi:requests==2.31.0",
 * or an object { ecosystem, name, version }.
 * Validation is allowlist-based so nothing odd ever reaches a URL.
 */

const ECOSYSTEM_ALIASES = { npm: 'npm', node: 'npm', pypi: 'pypi', pip: 'pypi', python: 'pypi' };

const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const NPM_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/; // exact version or dist-tag
const PYPI_VERSION = /^[0-9A-Za-z][0-9A-Za-z.!+_-]{0,63}$/;

function normalizeEcosystem(eco) {
  const key = String(eco || '').trim().toLowerCase();
  const out = ECOSYSTEM_ALIASES[key];
  if (!out) throw errors.invalidPackage('Ecosystem must be "npm" or "pypi".');
  return out;
}

function splitString(spec) {
  const s = String(spec).trim();
  const colon = s.indexOf(':');
  if (colon <= 0) throw errors.invalidPackage('Use the form npm:<name>[@version] or pypi:<name>[==version].');
  const ecosystem = normalizeEcosystem(s.slice(0, colon));
  let rest = s.slice(colon + 1);
  let version = '';

  if (ecosystem === 'pypi' && rest.includes('==')) {
    [rest, version] = rest.split('==');
  } else {
    // Skip a leading "@" that belongs to an npm scope.
    const at = rest.indexOf('@', rest.startsWith('@') ? 1 : 0);
    if (at > 0) {
      version = rest.slice(at + 1);
      rest = rest.slice(0, at);
    }
  }
  return { ecosystem, name: rest, version };
}

function parseSpec(input) {
  if (input === null || input === undefined) throw errors.invalidPackage('A package is required.');

  let parts;
  if (typeof input === 'string') {
    if (input.length > 300) throw errors.invalidPackage('Package spec is too long.');
    parts = splitString(input);
  } else if (typeof input === 'object') {
    parts = {
      ecosystem: normalizeEcosystem(input.ecosystem),
      name: typeof input.name === 'string' ? input.name.trim() : '',
      version: typeof input.version === 'string' ? input.version.trim() : '',
    };
  } else {
    throw errors.invalidPackage('Package must be a string or an object.');
  }

  const { ecosystem } = parts;
  let { name, version } = parts;

  if (ecosystem === 'npm') {
    if (name.length === 0 || name.length > 214 || !NPM_NAME.test(name)) {
      throw errors.invalidPackage(`"${truncate(name)}" is not a valid npm package name.`);
    }
    if (version && !NPM_VERSION.test(version)) throw errors.invalidPackage('Invalid npm version or tag.');
  } else {
    if (name.length === 0 || name.length > 100 || !PYPI_NAME.test(name)) {
      throw errors.invalidPackage(`"${truncate(name)}" is not a valid PyPI project name.`);
    }
    if (version && !PYPI_VERSION.test(version)) throw errors.invalidPackage('Invalid PyPI version.');
    name = normalizePypiName(name);
  }

  return { ecosystem, name, version: version || 'latest' };
}

/** PEP 503 normalization: runs of -, _ and . become a single "-". */
function normalizePypiName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

function truncate(s) {
  const clean = String(s).replace(/[^\x20-\x7e]/g, '?');
  return clean.length > 60 ? `${clean.slice(0, 60)}…` : clean;
}

module.exports = { parseSpec, normalizePypiName };
