// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const crypto = require('node:crypto');
const config = require('../config');
const { errors, ApiError } = require('../errors');
const { parseSpec } = require('./spec');
const { request } = require('./http');
const { resolveNpm, npmWeeklyDownloads } = require('./npm');
const { resolvePypi } = require('./pypi');
const { readTarGz, readZip } = require('./archive');
const { scanCode } = require('./checks/code');
const { checkTyposquat } = require('./checks/typosquat');
const { checkMetadata } = require('./checks/metadata');
const { checkOsv } = require('./checks/osv');
const { aggregate, ruleScore, finalScore, verdictFor, EXIT_CODES } = require('./scoring');
const ai = require('./ai');
const { TtlCache } = require('./cache');

const cache = new TtlCache(config.cache);
const inflight = new Map();

function verifyHash(buffer, expected) {
  if (!expected) return { verified: false, reason: 'registry published no hash' };
  const actual = crypto.createHash(expected.algo).update(buffer).digest(expected.encoding);
  return { verified: actual === expected.digest, actual };
}

/** Download, verify and read one archive. Never executes anything. */
async function fetchArtifact(artifact, ecosystem) {
  const result = { type: artifact.type, filename: artifact.filename, bytes: 0, hash: null, verified: false, files: null, findings: [] };

  const dl = await request(artifact.url, { maxBytes: config.limits.maxDownloadBytes, timeoutMs: 30000 });
  if (dl.tooLarge) {
    result.findings.push({ ruleId: 'R-ARCH-02', context: 'install', evidence: { file: artifact.filename, line: null, snippet: `download larger than ${Math.round(config.limits.maxDownloadBytes / 1048576)} MB, not scanned` } });
    return result;
  }
  result.bytes = dl.bytes;
  result.hash = crypto.createHash('sha256').update(dl.body).digest('hex');

  const check = verifyHash(dl.body, artifact.expected);
  result.verified = check.verified;
  if (artifact.expected && !check.verified) {
    // FR-3: a mismatched archive is never analyzed, only reported.
    result.findings.push({ ruleId: 'R-HASH-01', context: 'install', evidence: { file: artifact.filename, line: null, snippet: `expected ${artifact.expected.algo} ${artifact.expected.digest.slice(0, 16)}…` } });
    return result;
  }

  let reader;
  try {
    reader = artifact.filename.endsWith('.whl') || artifact.filename.endsWith('.zip')
      ? await readZip(dl.body, artifact.filename)
      : await readTarGz(dl.body, artifact.filename, { stripFirstDir: ecosystem === 'npm' });
  } catch (err) {
    result.findings.push({ ruleId: 'R-ARCH-02', context: 'install', evidence: { file: artifact.filename, line: null, snippet: err.message.slice(0, 160) } });
    return result;
  }

  for (const h of reader.findings) {
    result.findings.push({ ruleId: h.ruleId, context: 'install', evidence: { file: h.file, line: null, snippet: h.detail } });
  }
  result.files = reader.files;
  result.fileCount = reader.fileCount;
  result.unpackedBytes = reader.unpackedBytes;
  return result;
}

function summarize(verdict, findings, aiResult) {
  if (aiResult && aiResult.status === 'ok' && aiResult.summary) return aiResult.summary;
  const top = findings.filter((f) => f.points > 0).slice(0, 2).map((f) => f.title.toLowerCase());
  if (verdict === 'block') return `Do not install: ${top.join('; ') || 'high-risk signals found'}.`;
  if (verdict === 'warn') return `Review before installing: ${top.join('; ')}.`;
  if (top.length) return `Low risk. Minor signals: ${top.join('; ')}.`;
  return 'No install-time code or risky patterns found.';
}

async function runScan(pkgSpec) {
  const started = Date.now();
  let resolved;
  try {
    resolved = pkgSpec.ecosystem === 'npm' ? await resolveNpm(pkgSpec) : await resolvePypi(pkgSpec);
  } catch (err) {
    // A missing package with a look-alike name is worth pointing out: the user may have mistyped.
    const near = err.code === 'not_found' ? checkTyposquat(pkgSpec.ecosystem, pkgSpec.name) : null;
    if (near) err.message += ` Did you mean "${near.target}"?`;
    throw err;
  }
  const key = `${resolved.ecosystem}:${resolved.name}@${resolved.version}`;

  const cached = cache.get(key);
  if (cached) return { ...cached, cached: true, requested: pkgSpec.version };

  // Network checks run alongside the downloads.
  const [artifacts, osv, downloads] = await Promise.all([
    Promise.all(resolved.artifacts.map((a) => fetchArtifact(a, resolved.ecosystem))),
    checkOsv(resolved.ecosystem, resolved.name, resolved.version),
    resolved.ecosystem === 'npm' ? npmWeeklyDownloads(resolved.name) : Promise.resolve(null),
  ]);

  const raw = [];
  const hardBlocks = [];
  const installFiles = [];
  const scripts = [];
  let filesScanned = 0;
  const allFiles = new Map();

  for (const art of artifacts) {
    raw.push(...art.findings.map((f) => ({ ...f, evidence: { ...f.evidence, artifact: art.type } })));
    if (!art.files) continue;
    const code = scanCode(resolved.ecosystem, art.files);
    raw.push(...code.findings.map((f) => ({ ...f, evidence: { ...f.evidence, artifact: art.type } })));
    hardBlocks.push(...code.hardBlocks);
    installFiles.push(...code.installFiles);
    scripts.push(...code.scripts);
    filesScanned += code.filesScanned;
    for (const [p, v] of art.files) if (!allFiles.has(p)) allFiles.set(p, v);
  }

  const squat = checkTyposquat(resolved.ecosystem, resolved.name);
  if (squat) {
    raw.push({ ruleId: 'R-TYPO-01', context: 'metadata', evidence: { file: null, line: null, snippet: `"${resolved.name}" is ${squat.reason} from popular package "${squat.target}"` } });
  }
  raw.push(...checkMetadata(resolved.meta, { weeklyDownloads: downloads }));
  raw.push(...osv.findings);

  let findings = aggregate(raw);
  const rule = ruleScore(findings, hardBlocks);

  const shouldAskAi = ai.enabled() && (findings.some((f) => f.points > 0) || installFiles.length > 0);
  const aiResult = shouldAskAi ? await ai.analyze(resolved, findings, allFiles, installFiles) : { status: ai.enabled() ? 'skipped' : 'disabled', model: null };
  if (aiResult.status === 'ok' && aiResult.injectionDetected) {
    findings = aggregate([...raw, { ruleId: 'R-AI-01', context: 'metadata', evidence: { file: null, line: null, snippet: 'Reported by the local model' } }]);
  }

  const aiScore = aiResult.status === 'ok' ? aiResult.riskScore : null;
  const score = finalScore(rule, aiScore);
  const verdict = verdictFor(score);

  const report = {
    id: crypto.randomUUID(),
    package: { ecosystem: resolved.ecosystem, name: resolved.name, version: resolved.version },
    verdict,
    exitCode: EXIT_CODES[verdict],
    summary: summarize(verdict, findings, aiResult),
    score: { final: score, rule, ai: aiScore, hardBlock: rule === 100 && (hardBlocks.length > 0 || findings.some((f) => f.ruleId === 'R-HASH-01' || f.ruleId === 'R-MAL-01')) },
    thresholds: config.thresholds,
    findings: findings.map(({ occurrences, ...f }) => ({ ...f, occurrences })),
    installScripts: scripts,
    installFiles: [...new Set(installFiles)].slice(0, 50),
    ai: {
      status: aiResult.status,
      model: aiResult.model || null,
      summary: aiResult.status === 'ok' ? aiResult.summary : null,
      malicious: aiResult.status === 'ok' ? aiResult.malicious : null,
      injectionDetected: aiResult.status === 'ok' ? aiResult.injectionDetected : null,
      evidence: aiResult.status === 'ok' ? aiResult.evidence : [],
    },
    artifacts: artifacts.map((a) => ({
      type: a.type,
      filename: a.filename,
      bytes: a.bytes,
      sha256: a.hash,
      hashVerified: a.verified,
      fileCount: a.fileCount ?? null,
      unpackedBytes: a.unpackedBytes ?? null,
    })),
    metadata: {
      description: resolved.meta.description,
      license: resolved.meta.license,
      repository: resolved.meta.repository,
      createdAt: resolved.meta.createdAt,
      versionPublishedAt: resolved.meta.versionPublishedAt,
      versionCount: resolved.meta.versionCount,
      maintainers: resolved.meta.maintainers,
      weeklyDownloads: downloads,
    },
    vulnerabilities: { status: osv.status, items: osv.vulns.slice(0, 20) },
    stats: { filesScanned, durationMs: Date.now() - started },
    scannedAt: new Date().toISOString(),
    engine: { name: 'depvault-api', version: config.version, rulesVersion: '1' },
    disclaimer: 'One layer of defence, not a guarantee.',
  };

  cache.set(key, report);
  return { ...report, cached: false, requested: pkgSpec.version };
}

/** Public entry point: validation, de-duplication of identical in-flight scans, overall timeout. */
async function scanPackage(input) {
  const spec = parseSpec(input);
  const key = `${spec.ecosystem}:${spec.name}@${spec.version}`;

  if (inflight.has(key)) return inflight.get(key);

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(errors.timeout('The scan took too long and was stopped.')), config.limits.scanTimeoutMs);
  });

  const p = Promise.race([runScan(spec), timeout])
    .catch((err) => {
      if (err instanceof ApiError) throw err;
      console.error(`[scan] unexpected error for ${key}:`, err && err.stack ? err.stack : err);
      throw errors.upstream('The scan failed unexpectedly.');
    })
    .finally(() => {
      clearTimeout(timer);
      inflight.delete(key);
    });
  inflight.set(key, p);
  return p;
}

module.exports = { scanPackage, runScan, verifyHash, cache };
