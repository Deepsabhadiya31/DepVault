// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { getJson } = require('./http');
const { errors } = require('../errors');

const REGISTRY = 'https://registry.npmjs.org';

function encodeName(name) {
  // Scoped names keep the "@" and encode the slash, as the registry expects.
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

function pickExpectedHash(dist) {
  if (typeof dist.integrity === 'string') {
    const sha512 = dist.integrity.split(/\s+/).find((s) => s.startsWith('sha512-'));
    if (sha512) return { algo: 'sha512', encoding: 'base64', digest: sha512.slice(7) };
  }
  if (typeof dist.shasum === 'string' && /^[a-f0-9]{40}$/.test(dist.shasum)) {
    return { algo: 'sha1', encoding: 'hex', digest: dist.shasum };
  }
  return null;
}

function repoUrl(repository) {
  if (!repository) return null;
  if (typeof repository === 'string') return repository;
  return typeof repository.url === 'string' ? repository.url : null;
}

/** Resolve name + version/tag to a tarball and registry metadata (FR-1, FR-2). */
async function resolveNpm({ name, version }) {
  const base = `${REGISTRY}/${encodeName(name)}`;
  const doc = await getJson(base, { allow404: true });

  if (doc.status === 404) throw errors.notFound(`npm package "${name}" does not exist.`);

  let versionDoc;
  let resolved;
  let createdAt = null;
  let versionPublishedAt = null;
  let versionCount = null;

  if (doc.tooLarge) {
    // Very large packuments (huge packages): fall back to the single-version document.
    const single = await getJson(`${base}/${encodeURIComponent(version)}`, { allow404: true });
    if (single.status === 404 || !single.json) throw errors.versionNotFound(`Version "${version}" of "${name}" was not found.`);
    versionDoc = single.json;
    resolved = versionDoc.version;
  } else {
    const p = doc.json;
    const tags = p['dist-tags'] || {};
    resolved = tags[version] || version;
    versionDoc = p.versions && p.versions[resolved];
    if (!versionDoc) throw errors.versionNotFound(`Version "${version}" of "${name}" was not found.`);
    if (p.time) {
      createdAt = p.time.created || null;
      versionPublishedAt = p.time[resolved] || null;
    }
    versionCount = p.versions ? Object.keys(p.versions).length : null;
  }

  const dist = versionDoc.dist || {};
  if (typeof dist.tarball !== 'string') throw errors.noArtifact('The registry lists no tarball for this version.');

  return {
    ecosystem: 'npm',
    name,
    version: resolved,
    artifacts: [
      {
        type: 'tarball',
        filename: `${name.replace('/', '-')}-${resolved}.tgz`,
        url: dist.tarball,
        expected: pickExpectedHash(dist),
      },
    ],
    meta: {
      description: typeof versionDoc.description === 'string' ? versionDoc.description.slice(0, 300) : null,
      license: typeof versionDoc.license === 'string' ? versionDoc.license : null,
      repository: repoUrl(versionDoc.repository),
      homepage: typeof versionDoc.homepage === 'string' ? versionDoc.homepage : null,
      maintainers: Array.isArray(versionDoc.maintainers) ? versionDoc.maintainers.length : null,
      createdAt,
      versionPublishedAt,
      versionCount,
      deprecated: typeof versionDoc.deprecated === 'string' ? versionDoc.deprecated.slice(0, 300) : null,
      registryScripts: versionDoc.scripts && typeof versionDoc.scripts === 'object' ? versionDoc.scripts : {},
    },
  };
}

/** Weekly downloads; returns null when the stats API is unreachable. */
async function npmWeeklyDownloads(name) {
  try {
    const res = await getJson(`https://api.npmjs.org/downloads/point/last-week/${name}`, {
      allow404: true,
      timeoutMs: 5000,
      maxBytes: 64 * 1024,
    });
    return res.json && Number.isFinite(res.json.downloads) ? res.json.downloads : null;
  } catch {
    return null;
  }
}

module.exports = { resolveNpm, npmWeeklyDownloads, encodeName };
