// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const config = require('../config');
const { errors } = require('../errors');

/**
 * The only door to the network (SEC-13).
 * - HTTPS only, to a fixed host allowlist (blocks SSRF via crafted metadata).
 * - Redirects are followed manually and only to allowlisted hosts.
 * - Every request has a timeout and a streamed byte cap.
 */

const ALLOWED_HOSTS = new Set([
  'registry.npmjs.org',
  'api.npmjs.org',
  'pypi.org',
  'files.pythonhosted.org',
  'api.osv.dev',
]);

const MAX_REDIRECTS = 3;
const USER_AGENT = `depvault-api/${config.version} (+https://github.com/VaikunthAnkola/DepVault)`;

function assertAllowed(url, extraHosts = []) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw errors.upstream('Registry returned an invalid URL.');
  }
  const isExtra = extraHosts.includes(u.host);
  if (!isExtra && (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname) || u.port)) {
    throw errors.upstream(`Refused to contact a host outside the allowlist: ${u.hostname}`);
  }
  if (u.username || u.password) throw errors.upstream('Refused a URL with credentials.');
  return u;
}

/**
 * Fetch a URL and return its body as a Buffer, never more than maxBytes.
 * Throws ApiError on failure; returns { status: 404 } style objects only via options.allow404.
 */
async function request(url, opts = {}) {
  const {
    method = 'GET',
    body,
    headers = {},
    maxBytes = config.limits.maxMetadataBytes,
    timeoutMs = config.limits.httpTimeoutMs,
    allow404 = false,
    extraHosts = [],
  } = opts;

  let current = assertAllowed(url, extraHosts);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      let res;
      try {
        res = await fetch(current, {
          method,
          body,
          headers: { 'user-agent': USER_AGENT, ...headers },
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch (err) {
        if (controller.signal.aborted) throw errors.timeout(`Timed out contacting ${current.hostname}.`);
        throw errors.upstream(`Could not reach ${current.hostname}.`);
      }

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        await res.body?.cancel();
        current = assertAllowed(new URL(res.headers.get('location'), current).toString(), extraHosts);
        continue;
      }
      if (res.status === 404 && allow404) {
        await res.body?.cancel();
        return { status: 404, body: null };
      }
      if (!res.ok) {
        await res.body?.cancel();
        throw errors.upstream(`${current.hostname} answered HTTP ${res.status}.`);
      }

      const declared = Number(res.headers.get('content-length') || 0);
      if (declared > maxBytes) {
        await res.body?.cancel();
        return { status: res.status, body: null, tooLarge: true, bytes: declared };
      }

      const chunks = [];
      let total = 0;
      for await (const chunk of res.body) {
        total += chunk.length;
        if (total > maxBytes) {
          controller.abort();
          return { status: res.status, body: null, tooLarge: true, bytes: total };
        }
        chunks.push(chunk);
      }
      return { status: res.status, body: Buffer.concat(chunks), bytes: total };
    }
    throw errors.upstream('Too many redirects.');
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(url, opts = {}) {
  const res = await request(url, { ...opts, headers: { accept: 'application/json', ...opts.headers } });
  if (res.status === 404 || res.tooLarge) return res;
  try {
    return { status: res.status, json: JSON.parse(res.body.toString('utf8')) };
  } catch {
    throw errors.upstream('Registry returned invalid JSON.');
  }
}

module.exports = { request, getJson, assertAllowed, ALLOWED_HOSTS };
