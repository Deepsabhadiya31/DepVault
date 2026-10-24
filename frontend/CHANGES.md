# Website changes for the live scan

Drop these files over the current site. `app.js`, `style.css` and `logo.svg` are unchanged.

| File | Change |
| --- | --- |
| `index.html` | API URL meta tag; tighter CSP (adds `connect-src` for the API, drops `'unsafe-inline'` from `script-src`, adds `object-src`/`base-uri 'none'`); `no-referrer`; a fifth "Live scan" tab with a small form; an id on the terminal status text; loads `live-scan.css` and `live-scan.js` |
| `live-scan.js` | New. Posts to `/api/v1/scan` and renders the verdict in the terminal using `textContent` only. Handles cold starts, rate limits and errors |
| `live-scan.css` | New. Form styles using the existing terminal tokens, plus a layout fix (below) |

**If your Render URL is not `https://depvault-backend.onrender.com`**, change it in two places in `index.html`: the `depvault-api` meta tag and the `connect-src` list in the CSP. The browser will block calls to any origin missing from `connect-src`.

**Layout fix included:** on phones the terminal was wider than the screen and got clipped, because grid children default to `min-width: auto` and the tab row does not wrap. `min-width: 0` on the hero columns lets the tab row scroll as intended. Verified at 390 px wide.

**For local testing**, point both places at `http://127.0.0.1:3000` and start the API with `ALLOWED_ORIGINS=http://127.0.0.1:5500` (or whatever port your static server uses).

## Found while reviewing the site (not changed)

- `style.css` loads `bg-parallax.jpg` and `index.html` references `logo.png`; neither was in the files shared, so make sure both are deployed.
- `SECURITY.md`, "Verifying Releases": `pip install --dry-run --report` does not verify attestations or provenance. It only resolves the package. Either replace it with a command you have tested against a real release, or describe the check in words until releases are published with attestations.
- The trust card says only registries, OSV.dev and localhost are contacted. That is true of the CLI, but the live scan on the site sends the package name to the DepVault server. The live-scan tab says this, and the trust card could say "the CLI" to stay exact.
