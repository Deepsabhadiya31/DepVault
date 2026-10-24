// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');

const config = require('./config');
const { ApiError } = require('./errors');
const { Limiter } = require('./scanner/cache');
const { catalog } = require('./scanner/rules');
const scanner = require('./scanner');
const ai = require('./scanner/ai');

function jsonError(res, status, code, message) {
  res.status(status).set('Cache-Control', 'no-store').json({ error: { code, message } });
}

/**
 * Build the Express app. `deps` lets tests swap the scanner for a stub.
 */
function createApp(deps = {}) {
  const scanPackage = deps.scanPackage || scanner.scanPackage;
  const limiter = new Limiter({ maxActive: config.concurrency.maxActiveScans, maxQueued: config.concurrency.maxQueuedScans });
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.set('json spaces', config.env === 'production' ? 0 : 2);

  // Request ID + minimal access log. No IPs, no bodies, no headers are logged.
  app.use((req, res, next) => {
    const id = crypto.randomUUID();
    const start = process.hrtime.bigint();
    res.set('X-Request-Id', id);
    res.on('finish', () => {
      if (config.env === 'test') return;
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      console.log(`${req.method} ${req.path} ${res.statusCode} ${ms.toFixed(0)}ms`);
    });
    next();
  });

  // This service returns JSON only, so the strictest browser policy applies.
  app.use(
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"], formAction: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  // CORS: explicit allowlist. Requests with no Origin (curl, CI, the CLI) are not browser requests and pass.
  app.use(
    cors({
      origin(origin, cb) {
        if (!origin || config.allowedOrigins.includes(origin)) return cb(null, true);
        return cb(null, false);
      },
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type'],
      exposedHeaders: ['X-Request-Id', 'RateLimit', 'RateLimit-Policy', 'Retry-After'],
      credentials: false,
      maxAge: 600,
    }),
  );

  const limitHandler = (req, res) => jsonError(res, 429, 'rate_limited', 'Too many requests. Please wait a minute and try again.');
  app.use(
    rateLimit({
      windowMs: config.rateLimit.windowMs,
      limit: config.rateLimit.requestsPerWindow,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      handler: limitHandler,
      skip: (req) => req.path === '/health',
    }),
  );
  const scanLimit = rateLimit({
    windowMs: config.rateLimit.windowMs,
    limit: config.rateLimit.scansPerWindow,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: limitHandler,
    identifier: 'scan',
  });

  app.use(express.json({ limit: '2kb', strict: true, type: 'application/json' }));

  // ---------------------------------------------------------------- routes

  app.get('/health', (req, res) => {
    res.set('Cache-Control', 'no-store').json({ status: 'ok' });
  });

  app.get(['/', '/api/v1'], (req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json({
      name: 'depvault-api',
      version: config.version,
      ecosystems: ['npm', 'pypi'],
      thresholds: config.thresholds,
      scoring: {
        formula: 'S = max(R, round(0.6 * R + 0.4 * A))',
        ruleScore: 'R = min(100, sum of rule points); metadata rules capped at 20',
        guarantee: 'The AI score can raise the final score but never lower it below R.',
      },
      ai: { enabled: ai.enabled(), model: ai.enabled() ? config.ai.model : null },
      endpoints: {
        scan: 'GET /api/v1/scan?package=npm:express@4.21.2  or  POST /api/v1/scan {"package":"pypi:requests==2.31.0"}',
        rules: 'GET /api/v1/rules',
        health: 'GET /health',
      },
      source: 'https://github.com/VaikunthAnkola/DepVault',
      license: 'GPL-3.0-or-later',
    });
  });

  app.get('/api/v1/rules', (req, res) => {
    res.set('Cache-Control', 'public, max-age=3600').json({ rules: catalog() });
  });

  async function handleScan(input, req, res, next) {
    try {
      const outcome = await limiter.run(() => scanPackage(input));
      if (outcome.rejected) return jsonError(res, 503, 'busy', 'The scanner is at capacity. Try again in a few seconds.');
      const cacheable = req.method === 'GET' && outcome.value.requested !== 'latest';
      res.set('Cache-Control', cacheable ? 'public, max-age=300' : 'no-store');
      return res.json(outcome.value);
    } catch (err) {
      return next(err);
    }
  }

  app.get('/api/v1/scan', scanLimit, (req, res, next) => {
    const pkg = req.query.package;
    if (typeof pkg !== 'string') return jsonError(res, 400, 'invalid_package', 'Add ?package=npm:<name>[@version] or pypi:<name>[==version].');
    return handleScan(pkg, req, res, next);
  });

  app.post('/api/v1/scan', scanLimit, (req, res, next) => {
    if (!req.is('application/json')) return jsonError(res, 415, 'unsupported_media_type', 'Send JSON with Content-Type: application/json.');
    const body = req.body || {};
    const input = typeof body.package === 'string' ? body.package : body.ecosystem ? { ecosystem: body.ecosystem, name: body.name, version: body.version } : null;
    if (!input) return jsonError(res, 400, 'invalid_package', 'Send {"package":"npm:<name>[@version]"} or {"ecosystem","name","version"}.');
    return handleScan(input, req, res, next);
  });

  // ---------------------------------------------------------------- errors

  app.use((req, res) => jsonError(res, 404, 'not_found', 'No such endpoint. See GET /api/v1.'));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof ApiError) return jsonError(res, err.status, err.code, err.message);
    if (err && err.type === 'entity.too.large') return jsonError(res, 413, 'payload_too_large', 'Request body is too large.');
    if (err && err.type === 'entity.parse.failed') return jsonError(res, 400, 'invalid_json', 'Request body is not valid JSON.');
    console.error('[api] unhandled error:', err && err.stack ? err.stack : err);
    return jsonError(res, 500, 'internal_error', 'Something went wrong on our side.');
  });

  return app;
}

module.exports = { createApp };
