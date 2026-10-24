// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { getJson } = require('../http');

/**
 * F11: known vulnerabilities and known-malicious entries from OSV.dev.
 * OSV also carries the OpenSSF malicious-packages feed (IDs starting "MAL-").
 * Returns { status, vulns, findings }. Never throws: OSV is a bonus signal.
 */
async function checkOsv(ecosystem, name, version) {
  const body = JSON.stringify({
    version,
    package: { name, ecosystem: ecosystem === 'npm' ? 'npm' : 'PyPI' },
  });

  let res;
  try {
    res = await getJson('https://api.osv.dev/v1/query', {
      method: 'POST',
      body,
      headers: { 'content-type': 'application/json' },
      timeoutMs: 6000,
      maxBytes: 4 * 1024 * 1024,
    });
  } catch {
    return { status: 'unavailable', vulns: [], findings: [] };
  }
  if (!res.json) return { status: 'unavailable', vulns: [], findings: [] };

  const vulns = (Array.isArray(res.json.vulns) ? res.json.vulns : []).slice(0, 50).map((v) => ({
    id: String(v.id || '').slice(0, 60),
    summary: typeof v.summary === 'string' ? v.summary.slice(0, 200) : null,
    aliases: Array.isArray(v.aliases) ? v.aliases.slice(0, 5).map(String) : [],
    url: v.id ? `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}` : null,
  }));

  const findings = [];
  const malicious = vulns.filter((v) => v.id.startsWith('MAL-'));
  const regular = vulns.filter((v) => !v.id.startsWith('MAL-'));

  if (malicious.length) {
    findings.push({
      ruleId: 'R-MAL-01',
      context: 'metadata',
      evidence: { file: null, line: null, snippet: malicious.map((v) => v.id).join(', ') },
    });
  }
  if (regular.length) {
    findings.push({
      ruleId: 'R-VULN-01',
      context: 'metadata',
      evidence: {
        file: null,
        line: null,
        snippet: `${regular.length} advisor${regular.length === 1 ? 'y' : 'ies'}: ${regular.slice(0, 4).map((v) => v.aliases.find((a) => a.startsWith('CVE-')) || v.id).join(', ')}${regular.length > 4 ? ', …' : ''}`,
      },
    });
  }
  return { status: 'ok', vulns, findings };
}

module.exports = { checkOsv };
