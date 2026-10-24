// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

/**
 * Central configuration. Every value can be overridden with an environment
 * variable so the same code runs locally, in CI and on Render.
 */

function int(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function list(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

const MB = 1024 * 1024;

const config = Object.freeze({
  version: require('../package.json').version,
  env: process.env.NODE_ENV || 'development',
  port: int('PORT', 3000),

  // Browsers allowed to call the API. Never "*".
  allowedOrigins: list('ALLOWED_ORIGINS', [
    'https://depvault.netlify.app',
    'http://localhost:5173',
    'http://localhost:8080',
    'http://127.0.0.1:5500',
  ]),

  // Number of reverse proxies in front of the app (Render = 1).
  trustProxy: int('TRUST_PROXY', 1),

  rateLimit: {
    windowMs: 60 * 1000,
    scansPerWindow: int('RATE_LIMIT_SCANS_PER_MIN', 10),
    requestsPerWindow: int('RATE_LIMIT_REQUESTS_PER_MIN', 120),
  },

  concurrency: {
    maxActiveScans: int('MAX_ACTIVE_SCANS', 3),
    maxQueuedScans: int('MAX_QUEUED_SCANS', 20),
  },

  // SEC-2 limits (PRD section 4).
  limits: {
    maxDownloadBytes: int('MAX_DOWNLOAD_MB', 50) * MB,
    maxMetadataBytes: int('MAX_METADATA_MB', 25) * MB,
    maxUnpackedBytes: int('MAX_UNPACKED_MB', 200) * MB,
    maxFiles: int('MAX_FILES', 10000),
    maxScannedFileBytes: int('MAX_SCANNED_FILE_MB', 5) * MB,
    maxLineChunk: 50000,
    httpTimeoutMs: int('HTTP_TIMEOUT_MS', 10000),
    scanTimeoutMs: int('SCAN_TIMEOUT_MS', 60000),
  },

  thresholds: Object.freeze({
    warn: int('THRESHOLD_WARN', 30),
    block: int('THRESHOLD_BLOCK', 70),
  }),

  cache: {
    maxEntries: int('CACHE_MAX_ENTRIES', 500),
    ttlMs: int('CACHE_TTL_MINUTES', 360) * 60 * 1000,
  },

  // Optional AI. Disabled unless OLLAMA_URL is set. Render does not run Ollama.
  ai: {
    url: process.env.OLLAMA_URL || '',
    model: process.env.OLLAMA_MODEL || 'gemma2:2b',
    timeoutMs: int('OLLAMA_TIMEOUT_MS', 30000),
    maxCharsPerFile: int('AI_MAX_CHARS', 6000),
    promptVersion: '1',
  },
});

module.exports = config;
