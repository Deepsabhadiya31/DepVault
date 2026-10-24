// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const DAY = 24 * 60 * 60 * 1000;

/** F10: metadata red flags. Returns findings with context "metadata". */
function checkMetadata(meta, { weeklyDownloads = null, now = Date.now() } = {}) {
  const findings = [];
  const add = (ruleId, snippet) => findings.push({ ruleId, context: 'metadata', evidence: { file: null, line: null, snippet } });

  if (meta.createdAt) {
    const ageDays = Math.floor((now - Date.parse(meta.createdAt)) / DAY);
    if (Number.isFinite(ageDays) && ageDays < 30) {
      add('R-META-01', `First published ${ageDays} day${ageDays === 1 ? '' : 's'} ago` + (meta.versionCount ? ` (${meta.versionCount} version${meta.versionCount === 1 ? '' : 's'})` : ''));
    }
  }
  if (!meta.repository) add('R-META-02', 'No repository URL in the package metadata');
  if (weeklyDownloads !== null && weeklyDownloads < 100) add('R-META-03', `${weeklyDownloads} downloads last week`);
  if (meta.deprecated) add('R-META-04', meta.deprecated);
  return findings;
}

module.exports = { checkMetadata };
