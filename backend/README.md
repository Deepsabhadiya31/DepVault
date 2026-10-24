# DepVault API

The scan backend for [depvault.netlify.app](https://depvault.netlify.app). It downloads an npm or PyPI package from the official registry, verifies its hash, reads it in memory, and returns an Allow / Warn / Block verdict with evidence. **It never executes, imports or builds package code.**

Node.js 20+ · Express · GPL-3.0-or-later · 6 direct dependencies (all MIT; transitive ones are MIT, Apache-2.0, ISC or BSD, all GPL-3.0 compatible).

## Quick start

```bash
cd backend
npm ci
npm start                 # http://localhost:3000
npm test                  # unit + security tests, offline
npm run test:live         # adds real npm/PyPI scans (needs network)
```

```bash
curl "http://localhost:3000/api/v1/scan?package=npm:express@4.21.2"
curl -X POST http://localhost:3000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package":"pypi:requests==2.31.0"}'
```

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness check for Render. Returns `{"status":"ok"}` |
| GET | `/api/v1` | Version, thresholds, scoring formula, AI status |
| GET | `/api/v1/rules` | The full rule catalog (IDs, weights, explanations) |
| GET | `/api/v1/scan?package=<spec>` | Scan a package. Cacheable for 5 minutes when a version is pinned |
| POST | `/api/v1/scan` | Same, with `{"package":"<spec>"}` or `{"ecosystem","name","version"}` |

**Spec format:** `npm:<name>[@version|tag]` or `pypi:<name>[==version]`. Scoped npm names work (`npm:@babel/core@7.26.0`). No version means latest.

**Response (abridged):**

```json
{
  "package": { "ecosystem": "npm", "name": "esbuild", "version": "0.24.0" },
  "verdict": "warn",
  "exitCode": 1,
  "summary": "Review before installing: makes network requests during install; ...",
  "score": { "final": 50, "rule": 50, "ai": null, "hardBlock": false },
  "findings": [
    {
      "ruleId": "R-NET-01", "title": "Makes network requests during install",
      "severity": "medium", "points": 25, "context": "install",
      "evidence": [{ "file": "install.js", "line": 91, "snippet": "var https = require(\"https\");", "artifact": "tarball" }]
    }
  ],
  "artifacts": [{ "type": "tarball", "sha256": "…", "hashVerified": true, "fileCount": 6 }],
  "ai": { "status": "disabled" },
  "vulnerabilities": { "status": "ok", "items": [] },
  "cached": false
}
```

**Errors** always look like `{"error":{"code","message"}}`:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_package`, `invalid_json` | Bad spec or body |
| 404 | `not_found`, `version_not_found` | Not on the registry (with "Did you mean …?" for look-alike names) |
| 413 / 415 | `payload_too_large`, `unsupported_media_type` | Body over 2 KB, or not JSON |
| 429 | `rate_limited` | Over 10 scans or 120 requests per minute per IP |
| 502 / 503 / 504 | `upstream_error`, `busy`, `timeout` | Registry down, scanner at capacity, scan over 60 s |

## How a scan works

1. **Validate** the spec against strict name and version patterns, so nothing unexpected reaches a URL.
2. **Resolve** metadata from `registry.npmjs.org` or `pypi.org`. For PyPI, both the wheel and the sdist are scanned, because pip may install either.
3. **Download** with a 50 MB cap and **verify** the registry's sha512 or sha256. A mismatch is an automatic Block and the archive is never opened.
4. **Read in memory**: no extraction directory exists, so there is nothing to escape. Traversal, symlink and device entries are reported as findings. Limits are 200 MB unpacked, 10,000 files and 5 MB per scanned file.
5. **Find install-time code**: npm `preinstall` / `install` / `postinstall` and the files they run (followed one level through local `require`s), `setup.py`, and `.pth` files.
6. **Run rules**. Install-time code is weighted far higher than library code. Tests, docs and examples are only checked for prompt-injection text.
7. **Add signals**: typosquat distance, package age, missing repository, low downloads, and OSV.dev advisories. An OSV `MAL-` entry is an automatic Block.
8. **Score**: `S = max(R, round(0.6R + 0.4A))`. The AI can raise a score but never lower it.

Hard blocks (score 100): a single install-time file that both reads secrets and makes network calls; a hash mismatch; or a known-malicious OSV entry.

## Security model

| Threat | Control | Where |
| --- | --- | --- |
| SSRF through crafted registry metadata | HTTPS only, fixed host allowlist, redirects re-checked, no ports or credentials in URLs | `src/scanner/http.js` |
| Zip-slip, symlinks, devices | In-memory reading; hostile entries reported, never followed | `src/scanner/archive.js` |
| Decompression bombs | Byte counter on the gunzip stream, file-count cap | `src/scanner/archive.js` |
| Tampered downloads | Registry hash verified before reading | `src/scanner/index.js` |
| Regex DoS | No nested quantifiers; long lines scanned in chunks; total scan budget | `src/scanner/rules.js`, `checks/code.js` |
| Prompt injection against the AI | Content fenced and declared untrusted; delimiter stripped from content; AI cannot lower scores | `src/scanner/ai.js`, `scoring.js` |
| Terminal / HTML injection | Snippets stripped of control and ANSI codes; the website renders with `textContent` only | `checks/code.js`, `frontend/live-scan.js` |
| Abuse and DoS | Per-IP rate limits, 3 concurrent scans + queue of 20, 60 s scan timeout, 2 KB body limit, in-flight de-duplication | `src/app.js` |
| Browser attacks on the API | CORS allowlist, `default-src 'none'` CSP, `nosniff`, no `X-Powered-By` | `src/app.js` |
| Data leaks in logs | Logs record method, path, status and time only. No IPs, bodies or headers | `src/app.js` |

Tests in `test/` cover every control above except log contents and in-flight de-duplication. Run `npm test` before every PR.

## Deploying to Render

Either use the Blueprint in [`render.yaml`](../render.yaml) (**New → Blueprint**), or create a Web Service manually:

| Setting | Value |
| --- | --- |
| Root Directory | `backend` |
| Build Command | `npm ci --omit=dev` |
| Start Command | `npm start` |
| Health Check Path | `/health` |
| Environment | `NODE_ENV=production`, `ALLOWED_ORIGINS=https://depvault.netlify.app` |

Do not set `PORT`; Render provides it. After the first deploy, open `https://<your-service>.onrender.com/health`.

Then update **two lines** in the website's `index.html` if your service URL differs from `https://depvault-backend.onrender.com`:

1. `<meta name="depvault-api" content="…">`
2. `connect-src` inside the Content-Security-Policy meta tag

The site is plain HTML with no build step, so it reads the API URL from that meta tag rather than a `VITE_` variable.

**Free-tier note:** Render's free instances sleep when idle, so the first scan after a quiet period can take close to a minute. The website shows a "waking up" message for this.

## Configuration

All settings are environment variables; see [`.env.example`](.env.example). The main ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALLOWED_ORIGINS` | the Netlify site + localhost ports | Comma-separated browser origins |
| `RATE_LIMIT_SCANS_PER_MIN` | 10 | Per-IP scan limit |
| `MAX_ACTIVE_SCANS` / `MAX_QUEUED_SCANS` | 3 / 20 | Concurrency guard |
| `THRESHOLD_WARN` / `THRESHOLD_BLOCK` | 30 / 70 | Verdict thresholds |
| `OLLAMA_URL` / `OLLAMA_MODEL` | empty / `gemma2:2b` | Optional local AI; leave empty on Render |

## AI on a hosted server

Render does not run Ollama, so the hosted API runs **rules only**, and responses say `"ai": {"status": "disabled"}`. To add Gemma, run this API on a machine with Ollama and set `OLLAMA_URL=http://127.0.0.1:11434`. The AI step is tested against a fake Ollama in `test/ai.test.js`, including a model that tries to call a package safe.

## Privacy

The hosted API learns which package names people scan, and nothing else. Package code is fetched from public registries, not from users. The website says this next to the live-scan box. The CLI remains the fully local option.

## Project layout

```
backend/
  server.js              entry point (binds 0.0.0.0:$PORT)
  src/app.js             routes, CORS, headers, rate limits, errors
  src/config.js          all settings, from environment variables
  src/scanner/           spec parsing, registry clients, archive reader,
                         rules, scoring, optional AI, cache
  src/scanner/checks/    code, typosquat, metadata, OSV checks
  data/                  popular-package seed lists for typosquat checks
  test/                  node:test suites + harmless demo fixtures
```

## Adding a rule

1. Add the rule to `RULES` in `src/scanner/rules.js` (title, severity, points per context, plain-English explanation).
2. If it is a code pattern, add a regex to `PATTERNS`. Keep it simple: no nested quantifiers.
3. Add a harmless fixture to `test/fixtures/demo-packages.js` and a test in `test/code.test.js`, and include a "should not fire" case.
4. Run `npm test` and `npm run test:live` to check for new false positives on real packages.

The typosquat lists in `data/` are small seeds (about 240 npm and 200 PyPI names). The PRD target is the top 5,000 per ecosystem. Growing them is a good first contribution.
