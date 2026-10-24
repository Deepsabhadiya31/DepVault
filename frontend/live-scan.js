/**
 * DepVault Website — Live Scan
 * Calls the DepVault API and renders the real verdict in the hero terminal.
 * Security: API data is only ever written with textContent, never innerHTML,
 * so even a compromised API response cannot inject markup or script.
 */
(function () {
  'use strict';

  const meta = document.querySelector('meta[name="depvault-api"]');
  const API_URL = (meta && meta.content ? meta.content : '').replace(/\/+$/, '');

  const tab = document.getElementById('tab-live');
  const form = document.getElementById('live-scan-form');
  const input = document.getElementById('live-scan-input');
  const ecoSelect = document.getElementById('live-scan-eco');
  const submitBtn = document.getElementById('live-scan-submit');
  const output = document.getElementById('term-output');
  const termCmd = document.querySelector('.term-cmd');
  const replayBtn = document.getElementById('term-replay');
  const statusText = document.getElementById('term-status-text');
  const tabs = document.querySelectorAll('.scenario-tab');

  if (!tab || !form || !input || !output || !API_URL) return;

  const DEFAULT_STATUS = statusText ? statusText.textContent : '';
  const SYMBOL = { allow: '✔', warn: '▲', block: '✖' };
  let lastSpec = null;
  let inFlight = null;

  /* ----------------------------------------------------------- helpers */

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear() {
    while (output.firstChild) output.removeChild(output.firstChild);
  }

  function line(text, className) {
    output.appendChild(el('div', className || 'term-muted', text));
  }

  function spinner(text) {
    clear();
    const row = el('div');
    row.appendChild(el('span', 'term-spinner', '◐'));
    row.appendChild(document.createTextNode(' '));
    row.appendChild(el('span', 'term-muted', text));
    output.appendChild(row);
  }

  function buildSpec() {
    const raw = input.value.trim();
    if (!raw) return null;
    if (/^(npm|pypi):/i.test(raw)) return raw;
    return `${ecoSelect.value}:${raw}`;
  }

  /* ----------------------------------------------------------- rendering */

  function renderReport(r) {
    clear();
    const pkg = `${r.package.ecosystem}:${r.package.name}@${r.package.version}`;

    output.appendChild(
      el('div', `term-verdict-line term-verdict-${r.verdict}`, `${SYMBOL[r.verdict]} ${r.verdict.toUpperCase()} ${pkg} • risk ${r.score.final}/100`),
    );
    line(r.summary, 'live-summary');

    const scored = r.findings.filter((f) => f.points > 0);
    const info = r.findings.filter((f) => f.points === 0);

    if (scored.length === 0) {
      line('No suspicious install hooks, credential paths or exfiltration patterns found.');
    }
    scored.slice(0, 8).forEach((f) => {
      const block = el('div', 'live-finding');
      const head = el('div');
      head.appendChild(el('span', 'term-rule-id', f.ruleId));
      head.appendChild(document.createTextNode(`  ${f.title}  `));
      head.appendChild(el('span', 'term-muted', `+${f.points} · ${f.context}`));
      block.appendChild(head);
      f.evidence.slice(0, 2).forEach((e) => {
        const where = e.file ? `${e.file}${e.line ? `:${e.line}` : ''}  ` : '';
        block.appendChild(el('div', 'term-evidence-line', `${where}${e.snippet || ''}`));
      });
      output.appendChild(block);
    });
    info.forEach((f) => line(`ℹ ${f.title}: ${(f.evidence[0] && f.evidence[0].snippet) || ''}`));

    if (r.ai && r.ai.status === 'ok' && r.ai.summary) {
      const aiBlock = el('div', 'term-ai-block');
      aiBlock.appendChild(el('span', 'term-ai-label', `AI (${r.ai.model}): `));
      aiBlock.appendChild(document.createTextNode(r.ai.summary));
      output.appendChild(aiBlock);
    }

    const verified = r.artifacts.every((a) => a.hashVerified);
    const files = r.stats.filesScanned;
    line(
      `${r.artifacts.map((a) => a.type).join(' + ')} · hash ${verified ? 'verified' : 'NOT verified'} · ${files} files read · ` +
        `${r.cached ? 'cached' : `${(r.stats.durationMs / 1000).toFixed(1)}s`} · rule score ${r.score.rule}` +
        (r.score.ai !== null ? ` · AI score ${r.score.ai}` : ' · AI off on hosted demo'),
      'term-muted live-meta',
    );

    const exitLine =
      r.verdict === 'block'
        ? `⚠ guard would abort the install. Exit code ${r.exitCode}.`
        : r.verdict === 'warn'
          ? `guard would ask for confirmation. Exit code ${r.exitCode} if declined.`
          : `➜ guard would continue with the real install, pinned to ${r.package.version}.`;
    line(exitLine, r.verdict === 'block' ? 'term-aborted-line' : r.verdict === 'warn' ? 'live-warn-line' : 'live-allow-line');
  }

  function renderError(status, body) {
    clear();
    const msg = body && body.error ? body.error.message : 'The scan service could not be reached.';
    line(`✖ ${msg}`, 'term-aborted-line');
    if (status === 429) line('Rate limit: 10 live scans per minute. The demo tabs above work offline.');
    if (status === 0) line('The free server may be waking up. Try again in a moment, or use the CLI locally.');
  }

  /* ----------------------------------------------------------- scanning */

  async function scan(spec) {
    if (inFlight) inFlight.abort();
    const controller = new AbortController();
    inFlight = controller;
    lastSpec = spec;

    termCmd.textContent = `scan ${spec}`;
    submitBtn.disabled = true;
    spinner(`Resolving ${spec} and verifying the registry hash...`);
    const slow = setTimeout(() => spinner('Still working. A sleeping free-tier server can take up to a minute to wake...'), 6000);
    const timeout = setTimeout(() => controller.abort(), 75000);

    try {
      const res = await fetch(`${API_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: spec }),
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      let body = null;
      try {
        body = await res.json();
      } catch (e) {
        body = null;
      }
      if (controller !== inFlight) return;
      if (res.ok && body && body.verdict) renderReport(body);
      else renderError(res.status, body);
    } catch (err) {
      if (controller !== inFlight) return;
      renderError(0, null);
    } finally {
      clearTimeout(slow);
      clearTimeout(timeout);
      if (controller === inFlight) {
        inFlight = null;
        submitBtn.disabled = false;
      }
    }
  }

  /* ----------------------------------------------------------- wiring */

  function showLive(on) {
    form.hidden = !on;
    if (statusText) statusText.textContent = on ? 'Live scan via DepVault API • rules engine' : DEFAULT_STATUS;
    if (on) {
      if (inFlight) return;
      clear();
      termCmd.textContent = 'scan <package>';
      line('Type a package and press Scan. Only the package name is sent; the server downloads it from the public registry and never runs it.');
      input.focus();
    } else if (inFlight) {
      inFlight.abort();
      inFlight = null;
      submitBtn.disabled = false;
    }
  }

  // app.js handles tab styling; we only toggle the live form.
  tabs.forEach((t) => t.addEventListener('click', () => showLive(t === tab)));

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const spec = buildSpec();
    if (!spec) {
      input.focus();
      return;
    }
    scan(spec);
  });

  if (replayBtn) {
    replayBtn.addEventListener('click', () => {
      if (!form.hidden && lastSpec) scan(lastSpec);
    });
  }

  form.querySelectorAll('[data-example]').forEach((btn) => {
    btn.addEventListener('click', () => {
      input.value = btn.getAttribute('data-example');
      ecoSelect.value = btn.getAttribute('data-eco');
      scan(buildSpec());
    });
  });
})();
