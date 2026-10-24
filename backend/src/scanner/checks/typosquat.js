// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const POPULAR = {
  npm: new Set(require('../../../data/popular-npm.json')),
  pypi: new Set(require('../../../data/popular-pypi.json')),
};

/** Optimal string alignment distance with an early exit once it exceeds max. */
function osaDistance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev2 = new Array(b.length + 1).fill(0);
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    for (let j = 0; j <= b.length; j += 1) prev2[j] = prev[j];
    prev = cur;
  }
  return prev[b.length];
}

const squash = (s) => s.replace(/[-_.]/g, '');

/**
 * F9: is this name a close copy of a popular one?
 * Returns { target, distance, reason } or null.
 */
function checkTyposquat(ecosystem, name) {
  const list = POPULAR[ecosystem];
  if (!list || list.has(name)) return null;
  if (ecosystem === 'npm' && name.startsWith('@')) return null; // scoped names are owned by the scope

  const lower = name.toLowerCase();
  if (lower.length < 5) return null; // short names collide too often to be useful

  const max = lower.length >= 8 ? 2 : 1;
  let best = null;
  for (const pop of list) {
    if (pop.startsWith('@')) continue;
    if (squash(pop) === squash(lower)) {
      return { target: pop, distance: 0, reason: 'only separators differ' };
    }
    const d = osaDistance(lower, pop, max);
    if (d <= max && (!best || d < best.distance)) best = { target: pop, distance: d, reason: `${d} edit${d === 1 ? '' : 's'} away` };
  }
  return best;
}

module.exports = { checkTyposquat, osaDistance, POPULAR };
