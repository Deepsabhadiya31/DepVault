// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const path = require('node:path');
const { PATTERNS } = require('../rules');
const config = require('../../config');

/**
 * Static code checks (F4, F5). Reads file contents as text; never evaluates them.
 * Files are tagged "install" when they run automatically during installation,
 * otherwise "runtime".
 */

const NPM_INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];
const MAX_TOTAL_SCANNED = 60 * 1024 * 1024;
const MAX_EVIDENCE_PER_RULE = 5;
const NON_SHIPPED = /(?:^|\/)(?:tests?|__tests__|spec|specs|testing|docs?|examples?|benchmarks?|fixtures)\/|(?:^|\/)(?:test_[^/]*|[^/]*_test)\.py$|\.(?:test|spec)\.[cm]?[jt]s$/i;

function kindOf(file) {
  const base = path.posix.basename(file).toLowerCase();
  const ext = path.posix.extname(base);
  if (['.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts'].includes(ext)) return 'js';
  if (['.py', '.pyw', '.pth'].includes(ext) || base === 'setup.py') return 'py';
  if (['.sh', '.bash', '.ps1', '.bat', '.cmd'].includes(ext)) return 'sh';
  return 'text';
}

function cleanSnippet(line, index) {
  const start = Math.max(0, index - 60);
  const raw = line.slice(start, index + 100);
  // SEC-8: strip control characters and ANSI escapes before anything is displayed.
  const text = raw.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, ' ').trim();
  return (start > 0 ? '…' : '') + text + (index + 100 < line.length ? '…' : '');
}

/** Resolve "./lib/x" from a file to an archive path, trying Node's extension rules. */
function resolveLocal(files, fromFile, spec) {
  const baseDir = path.posix.dirname(fromFile);
  const target = path.posix.normalize(path.posix.join(baseDir, spec));
  const candidates = [target, `${target}.js`, `${target}.cjs`, `${target}.mjs`, `${target}/index.js`];
  return candidates.find((c) => files.has(c) && !c.startsWith('..')) || null;
}

function localImports(text) {
  const out = new Set();
  const re = /(?:require\(\s*|from\s+|import\s*\(\s*)['"](\.{1,2}\/[^'"]{1,200})['"]/g;
  let m;
  while ((m = re.exec(text)) !== null) out.add(m[1]);
  return out;
}

/**
 * Work out which files run at install time.
 * Returns { installFiles:Set, scripts:[{hook, command}], pseudoFiles:Map, findings:[] }.
 */
function installContext(ecosystem, files) {
  const installFiles = new Set();
  const pseudoFiles = new Map();
  const findings = [];
  const scripts = [];

  if (ecosystem === 'npm') {
    const pkgEntry = files.get('package.json');
    let pkg = {};
    if (pkgEntry && pkgEntry.content) {
      try {
        pkg = JSON.parse(pkgEntry.content.toString('utf8'));
      } catch {
        pkg = {};
      }
    }
    const hooks = (pkg && typeof pkg.scripts === 'object' && pkg.scripts) || {};
    for (const hook of NPM_INSTALL_HOOKS) {
      const command = typeof hooks[hook] === 'string' ? hooks[hook].slice(0, 2000) : null;
      if (!command) continue;
      scripts.push({ hook, command });
      // The command string itself is shell that runs on install.
      pseudoFiles.set(`package.json#scripts.${hook}`, Buffer.from(command));
      findings.push({
        ruleId: 'R-SCRIPT-01',
        context: 'install',
        evidence: { file: 'package.json', line: null, snippet: `${hook}: ${cleanSnippet(command, 0)}` },
      });
      // Files the command runs, e.g. "node scripts/setup.js".
      for (const token of command.split(/[\s;&|()]+/)) {
        const t = token.replace(/^['"]|['"]$/g, '').replace(/^\.\//, '');
        if (/\.(?:c|m)?js$/.test(t) && files.has(t)) installFiles.add(t);
      }
      const nodeDir = command.match(/\bnode\s+(?:\.\/)?([\w.-]+)\s*(?:$|[;&|])/);
      if (nodeDir) {
        const resolved = resolveLocal(files, 'package.json', `./${nodeDir[1]}`);
        if (resolved) installFiles.add(resolved);
      }
    }
    if (!hooks.install && !hooks.preinstall && files.has('binding.gyp')) {
      findings.push({
        ruleId: 'R-SCRIPT-02',
        context: 'install',
        evidence: { file: 'binding.gyp', line: null, snippet: 'npm runs "node-gyp rebuild" for this file' },
      });
    }

    // Follow local imports one level deep, where payloads often hide.
    for (const f of [...installFiles]) {
      const entry = files.get(f);
      if (!entry || !entry.content) continue;
      for (const spec of localImports(entry.content.toString('utf8'))) {
        const resolved = resolveLocal(files, f, spec);
        if (resolved) installFiles.add(resolved);
      }
    }
  } else {
    for (const [file, entry] of files) {
      const base = path.posix.basename(file).toLowerCase();
      const depth = file.split('/').length;
      // sdists have one top-level folder, so setup.py sits at depth 2.
      if (base === 'setup.py' && depth <= 2) {
        installFiles.add(file);
        const text = entry.content ? entry.content.toString('utf8') : '';
        // Only overrides of commands that pip actually runs; "test"/"publish" helpers are ignored.
        const m = /cmdclass\s*=\s*\{[^}]{0,500}['"](?:install|develop|egg_info|build|build_py|build_ext|bdist_wheel|bdist_egg)['"]|class\s+\w+\s*\(\s*(?:\w+\.)?(?:install|develop|egg_info|build_py|build_ext|bdist_wheel|bdist_egg)\s*\)/.exec(text);
        if (m) {
          const lineNo = text.slice(0, m.index).split('\n').length;
          const line = text.split('\n')[lineNo - 1] || '';
          findings.push({
            ruleId: 'R-SETUP-01',
            context: 'install',
            evidence: { file, line: lineNo, snippet: cleanSnippet(line, 0) },
          });
        }
      }
      if (base.endsWith('.pth') && entry.content) {
        const lines = entry.content.toString('utf8').split('\n');
        lines.forEach((line, i) => {
          if (/^\s*import\s/.test(line)) {
            installFiles.add(file);
            findings.push({
              ruleId: 'R-PTH-01',
              context: 'install',
              evidence: { file, line: i + 1, snippet: cleanSnippet(line, 0) },
            });
          }
        });
      }
    }
  }

  return { installFiles, pseudoFiles, scripts, findings };
}

/** Run pattern rules over every scannable file. */
function scanCode(ecosystem, files) {
  const ctx = installContext(ecosystem, files);
  const findings = [...ctx.findings];
  const perFile = new Map(); // file -> Set(ruleId), used for hard-block combos
  const counts = new Map();
  let budget = MAX_TOTAL_SCANNED;
  let skippedForBudget = 0;

  const targets = [];
  for (const [file, buf] of ctx.pseudoFiles) targets.push({ file, buf, kind: 'sh', context: 'install' });
  // Install files first, so the budget never skips the most important code.
  const ordered = [...files.entries()].sort(([a], [b]) => Number(ctx.installFiles.has(b)) - Number(ctx.installFiles.has(a)));
  for (const [file, entry] of ordered) {
    if (!entry.content) continue;
    if (/(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|CHANGELOG\.md|LICENSE[^/]*)$/i.test(file)) continue;
    if (file.endsWith('.map')) continue;
    const isInstall = ctx.installFiles.has(file) || file.toLowerCase().endsWith('.pth');
    targets.push({
      file,
      buf: entry.content,
      // Tests, docs and examples never run on install or import; only injection text is checked there.
      kind: !isInstall && NON_SHIPPED.test(file) ? 'text' : kindOf(file),
      context: isInstall ? 'install' : 'runtime',
    });
  }

  for (const t of targets) {
    if (budget <= 0) {
      skippedForBudget += 1;
      continue;
    }
    budget -= t.buf.length;
    const text = t.buf.toString('utf8');
    const lines = text.split('\n');

    lines.forEach((fullLine, i) => {
      // Long minified lines are scanned in chunks (SEC-7).
      for (let off = 0; off < fullLine.length || off === 0; off += config.limits.maxLineChunk) {
        const line = fullLine.slice(off, off + config.limits.maxLineChunk + 200);
        for (const p of PATTERNS) {
          if (!p.kinds.has(t.kind)) continue;
          if (p.installOnly && t.context !== 'install') continue;
          const m = p.re.exec(line);
          if (!m) continue;

          if (!perFile.has(t.file)) perFile.set(t.file, { context: t.context, rules: new Set() });
          perFile.get(t.file).rules.add(p.ruleId);

          const key = `${p.ruleId}|${t.context}`;
          const n = counts.get(key) || 0;
          counts.set(key, n + 1);
          if (n >= MAX_EVIDENCE_PER_RULE) continue;
          findings.push({
            ruleId: p.ruleId,
            context: t.context,
            evidence: { file: t.file, line: i + 1, snippet: cleanSnippet(line, m.index) },
          });
        }
        if (fullLine.length === 0) break;
      }
    });
  }

  // Hard block (PRD section 6): one install-time file both reads secrets and talks to the network.
  const hardBlocks = [];
  for (const [file, info] of perFile) {
    if (info.context !== 'install') continue;
    const secrets = info.rules.has('R-CRED-01') || info.rules.has('R-ENV-01');
    const network = info.rules.has('R-NET-01') || info.rules.has('R-NET-02');
    if (secrets && network) hardBlocks.push(file);
  }

  return {
    findings,
    hardBlocks,
    installFiles: [...ctx.installFiles],
    scripts: ctx.scripts,
    filesScanned: targets.length - skippedForBudget,
    skippedForBudget,
    totalOccurrences: Object.fromEntries(counts),
  };
}

module.exports = { scanCode, installContext, kindOf, cleanSnippet };
