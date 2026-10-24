## Security Policy

DepVault inspects untrusted, potentially malicious code before you install it, so security is our top priority. Because the tool deliberately handles hostile input, we design every part of the pipeline to protect your system from harm.

## Supported Versions

DepVault is currently pre-1.0 software. Only the latest minor release receives security patches and bug fixes.

| Version | Supported |
| --- | --- |
| {{VERSION}} | Yes |
| < {{VERSION}} | No |

If you are using an older version, please upgrade to {{VERSION}} before reporting an issue.

## Reporting a Vulnerability

Please do not open public GitHub issues, pull requests, or discussion threads for security vulnerabilities. Public disclosure puts all users at risk before a fix is available.

Report vulnerabilities through GitHub Private Vulnerability Reporting at:
https://github.com/{{GITHUB_ORG}}/DepVault/security/advisories/new

Backup security contact: {{SECURITY_EMAIL or "none, GitHub only"}}

Please include the following information in your report:
- DepVault version (`guard --version` or `depvault --version`)
- Operating system and architecture (for example, Ubuntu 24.04 x86_64, macOS arm64)
- Python version (`python --version`)
- A minimal reproducing package or test fixture, shared privately (never publish malicious fixtures to npm or PyPI)
- Exact reproduction steps
- Expected behavior versus actual behavior
- Potential security impact and attack scenario

## Response Timeline

DepVault is maintained by volunteers. The timeframes below are operational targets rather than legal guarantees.

| Stage | Target Time | Description |
| --- | --- | --- |
| Acknowledgement | Within 72 hours | We confirm receipt of your report. |
| Triage | Within 7 days | We determine validity and initial severity. |
| Status Updates | Every 14 days | We keep you informed on progress toward a patch. |
| Disclosure | Within 90 days | We publish a fix and a security advisory. |

Coordinated disclosure means we work with the reporter in private to develop a fix before releasing it publicly alongside an advisory. Reporters will be credited in the advisory unless they request anonymity.

## Scope

### In Scope
- Any package code execution during a scan (such as running setup scripts or build hooks)
- Archive extraction vulnerabilities, including path traversal (zip-slip) or writing outside the temporary directory
- Any package code or local data leaving your machine
- Prompt injection or parsing flaws that lower a risk score or convert a Block into an Allow
- Denial of service caused by crafted packages (crashes, memory exhaustion, unhandled infinite loops)
- Terminal escape sequence injection that manipulates terminal output
- Compromise of the DepVault build or release pipeline
- Detection bypasses where a clearly malicious package receives an Allow verdict (triaged as lower-severity security bugs, as DepVault is one defensive layer and not a guarantee)

### Out of Scope
- False positives where safe packages receive Warn or Block verdicts (please use the standard false-positive issue template)
- Vulnerabilities within packages you scan (please report those directly to npm, PyPI, or the package maintainers)
- Attacks requiring physical access or root privileges on the local machine
- Flaws in the underlying local AI model or runtime
- Social engineering or phishing directed at maintainers

## Safe Harbor

We support good-faith security research. If you make a reasonable effort to follow this policy, we will not pursue legal action against you.

To remain in safe harbor:
- Test only against your own systems and isolated local fixtures.
- Never publish malicious test packages to public registries such as npm or PyPI.
- Do not attempt to access, modify, or exfiltrate data belonging to others.
- Give maintainers reasonable time to fix an issue before public disclosure.

## Our Security Design

DepVault operates under three core rules:
1. Package archives are only downloaded and statically read. Package code is never executed, imported, or built.
2. Network calls connect only to official registries (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`), `api.osv.dev`, and localhost. There is no telemetry.
3. The local AI model can raise a risk score, but can never lower it below the rule-based score.

Hardening includes hash integrity verification, zip-slip and symlink rejection, decompression limits, regex execution timeouts, safe YAML loading, and output escaping. For full architectural details, see {{DOCS_URL}}.

## Verifying Releases

Every release of DepVault is published using PyPI Trusted Publishing and signed in GitHub Actions.

You can verify the cryptographic build attestation of the downloaded wheel using `pip`:

```bash
pip install --dry-run --report report.json depvault=={{VERSION}}
```

You can inspect the generated report to confirm hash integrity against the published release provenance.

Last updated: {{DATE}}
