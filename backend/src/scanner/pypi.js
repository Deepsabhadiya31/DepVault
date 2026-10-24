// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { getJson } = require('./http');
const { errors } = require('../errors');

const API = 'https://pypi.org/pypi';

/**
 * Choose what to scan (F3). pip installs a wheel when one fits, and builds the
 * sdist otherwise (running setup.py). We scan the most portable wheel AND the sdist,
 * so both install paths are covered.
 */
function pickArtifacts(files) {
  const usable = files.filter((f) => !f.yanked && typeof f.url === 'string' && f.digests && f.digests.sha256);
  const sdist = usable.find((f) => f.packagetype === 'sdist' && /\.(tar\.gz|tgz)$/i.test(f.filename));
  const wheels = usable.filter((f) => f.packagetype === 'bdist_wheel');
  const wheel =
    wheels.find((f) => /-py3-none-any\.whl$/i.test(f.filename)) ||
    wheels.find((f) => /-none-any\.whl$/i.test(f.filename)) ||
    wheels.find((f) => /manylinux.*x86_64\.whl$/i.test(f.filename)) ||
    wheels[0];

  const out = [];
  for (const f of [wheel, sdist]) {
    if (!f) continue;
    out.push({
      type: f.packagetype === 'sdist' ? 'sdist' : 'wheel',
      filename: f.filename,
      url: f.url,
      expected: { algo: 'sha256', encoding: 'hex', digest: f.digests.sha256 },
      declaredSize: f.size,
      uploadedAt: f.upload_time_iso_8601 || null,
    });
  }
  return out;
}

function earliestUpload(releases) {
  let min = null;
  for (const files of Object.values(releases || {})) {
    for (const f of files || []) {
      const t = f.upload_time_iso_8601;
      if (t && (!min || t < min)) min = t;
    }
  }
  return min;
}

function pickRepo(info) {
  const urls = info.project_urls && typeof info.project_urls === 'object' ? Object.values(info.project_urls) : [];
  const candidates = [...urls, info.home_page].filter((u) => typeof u === 'string');
  return candidates.find((u) => /github\.com|gitlab\.com|bitbucket\.org|codeberg\.org/i.test(u)) || null;
}

async function resolvePypi({ name, version }) {
  const project = await getJson(`${API}/${encodeURIComponent(name)}/json`, { allow404: true });
  if (project.status === 404) throw errors.notFound(`PyPI project "${name}" does not exist.`);

  let info;
  let files;
  let releases = null;

  if (project.tooLarge) {
    if (version === 'latest') throw errors.upstream('Project metadata is too large; specify an exact version.');
    const one = await getJson(`${API}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`, { allow404: true });
    if (one.status === 404) throw errors.versionNotFound(`Version "${version}" of "${name}" was not found.`);
    info = one.json.info;
    files = one.json.urls || [];
  } else {
    const p = project.json;
    releases = p.releases || {};
    if (version === 'latest') {
      info = p.info;
      files = p.urls || [];
    } else {
      if (!releases[version]) throw errors.versionNotFound(`Version "${version}" of "${name}" was not found.`);
      const one = await getJson(`${API}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
      info = one.json.info;
      files = one.json.urls || [];
    }
  }

  const artifacts = pickArtifacts(files);
  if (artifacts.length === 0) throw errors.noArtifact('No downloadable sdist or wheel for this version.');

  return {
    ecosystem: 'pypi',
    name,
    version: info.version,
    artifacts,
    meta: {
      description: typeof info.summary === 'string' ? info.summary.slice(0, 300) : null,
      license: typeof info.license === 'string' ? info.license.slice(0, 100) : null,
      repository: pickRepo(info),
      homepage: typeof info.home_page === 'string' ? info.home_page : null,
      maintainers: null,
      createdAt: releases ? earliestUpload(releases) : null,
      versionPublishedAt: artifacts[0].uploadedAt,
      versionCount: releases ? Object.keys(releases).length : null,
      deprecated: info.yanked ? `Yanked: ${info.yanked_reason || 'no reason given'}` : null,
      registryScripts: {},
    },
  };
}

module.exports = { resolvePypi, pickArtifacts };
