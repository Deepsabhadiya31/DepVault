// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { RULES } = require('./rules');
const config = require('../config');

const META_CAP = 20;
const MAX_EVIDENCE = 5;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const HARD_BLOCK_RULES = new Set(['R-HASH-01', 'R-MAL-01']);

/**
 * Group raw hits into one finding per rule, then score (PRD section 6).
 *   R = min(100, sum of rule points)            metadata rules capped at 20 total
 *   S = max(R, round(0.6 R + 0.4 A))            the AI can raise, never lower (SEC-5)
 */
function aggregate(rawFindings) {
  const byRule = new Map();
  for (const f of rawFindings) {
    const rule = RULES[f.ruleId];
    if (!rule) continue;
    const pts = rule.points[f.context] ?? 0;
    let g = byRule.get(f.ruleId);
    if (!g) {
      g = { ruleId: f.ruleId, title: rule.title, severity: rule.severity, explanation: rule.explanation, points: 0, contexts: new Set(), evidence: [], occurrences: 0 };
      byRule.set(f.ruleId, g);
    }
    g.points = Math.max(g.points, pts);
    g.contexts.add(f.context);
    g.occurrences += 1;
    if (g.evidence.length < MAX_EVIDENCE && f.evidence) g.evidence.push(f.evidence);
  }

  const findings = [...byRule.values()].map((g) => ({
    ...g,
    contexts: [...g.contexts],
    // Install-time evidence is the most important, show it first.
    context: g.contexts.has('install') ? 'install' : g.contexts.has('runtime') ? 'runtime' : 'metadata',
  }));

  findings.sort((a, b) => b.points - a.points || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.ruleId.localeCompare(b.ruleId));
  return findings;
}

function ruleScore(findings, hardBlocks = []) {
  let code = 0;
  let meta = 0;
  for (const f of findings) {
    if (f.ruleId.startsWith('R-META-')) meta += f.points;
    else code += f.points;
  }
  const hard = hardBlocks.length > 0 || findings.some((f) => HARD_BLOCK_RULES.has(f.ruleId));
  return hard ? 100 : Math.min(100, code + Math.min(META_CAP, meta));
}

function finalScore(rule, ai) {
  if (typeof ai !== 'number') return rule;
  return Math.max(rule, Math.round(0.6 * rule + 0.4 * ai));
}

function verdictFor(score, thresholds = config.thresholds) {
  if (score > thresholds.block) return 'block';
  if (score >= thresholds.warn) return 'warn';
  return 'allow';
}

const EXIT_CODES = { allow: 0, warn: 1, block: 2 };

module.exports = { aggregate, ruleScore, finalScore, verdictFor, EXIT_CODES, META_CAP };
