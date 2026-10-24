// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

/**
 * Rule catalog. One entry per rule ID, shared by the scanner, the API's
 * /rules endpoint and the website. Points follow PRD section 6 and are
 * deliberately lower for "runtime" code (library code that only runs when
 * imported) than for "install" code (runs automatically on npm/pip install).
 *
 * Patterns are kept simple (no nested quantifiers) to avoid regex DoS (SEC-7).
 */

const RULES = {
  'R-SCRIPT-01': {
    title: 'Runs a script automatically on install',
    severity: 'low',
    points: { install: 10 },
    explanation: 'This package runs code the moment it is installed, before you ever import it.',
  },
  'R-SCRIPT-02': {
    title: 'Builds native code on install',
    severity: 'info',
    points: { install: 5 },
    explanation: 'A binding.gyp file makes npm run node-gyp during install. Common for native modules.',
  },
  'R-SETUP-01': {
    title: 'setup.py overrides install commands',
    severity: 'medium',
    points: { install: 15 },
    explanation: 'Custom install or build classes in setup.py run arbitrary code during pip install.',
  },
  'R-PTH-01': {
    title: '.pth file runs code on every Python start',
    severity: 'high',
    points: { install: 40 },
    explanation: 'Python executes "import" lines in .pth files each time the interpreter starts.',
  },
  'R-CRED-01': {
    title: 'Reads credential or secret files',
    severity: 'high',
    points: { install: 40, runtime: 10 },
    explanation: 'The code references SSH keys, cloud credentials, registry tokens or similar secrets.',
  },
  'R-ENV-01': {
    title: 'Collects all environment variables',
    severity: 'medium',
    points: { install: 30, runtime: 5 },
    explanation: 'Dumping the whole environment captures tokens and CI secrets stored there.',
  },
  'R-NET-01': {
    title: 'Makes network requests during install',
    severity: 'medium',
    points: { install: 25 },
    explanation: 'Install-time network calls can download a second-stage payload or send data out.',
  },
  'R-NET-02': {
    title: 'Contacts a known exfiltration endpoint',
    severity: 'high',
    points: { install: 40, runtime: 30 },
    explanation: 'Raw IP addresses, chat webhooks, paste sites and tunnels are common data-theft channels.',
  },
  'R-EXEC-01': {
    title: 'Spawns system commands during install',
    severity: 'medium',
    points: { install: 15 },
    explanation: 'Running shell commands at install time hands control to code outside the package.',
  },
  'R-OBF-01': {
    title: 'Executes decoded or hidden code',
    severity: 'high',
    points: { install: 30, runtime: 30 },
    explanation: 'Decoding a string and passing it to eval/exec is a classic way to hide a payload.',
  },
  'R-OBF-02': {
    title: 'Contains a large encoded blob',
    severity: 'medium',
    points: { install: 15, runtime: 15 },
    explanation: 'Long base64 or hex strings can hide code. Legitimate packages rarely need them.',
  },
  'R-INJECT-01': {
    title: 'Contains text aimed at AI scanners',
    severity: 'high',
    points: { install: 30, runtime: 30 },
    explanation: 'Text that tries to instruct an AI reviewer is a strong sign the author is hiding something.',
  },
  'R-ARCH-01': {
    title: 'Archive contains hostile entries',
    severity: 'high',
    points: { install: 30 },
    explanation: 'Path-traversal, symlink or device entries are never needed in a package.',
  },
  'R-ARCH-02': {
    title: 'Archive exceeds safety limits',
    severity: 'medium',
    points: { install: 30 },
    explanation: 'The archive is too large to scan fully, so parts of it were not checked.',
  },
  'R-HASH-01': {
    title: 'Download does not match the registry hash',
    severity: 'critical',
    points: { install: 100 },
    explanation: 'The file differs from what the registry published. It may have been tampered with.',
  },
  'R-MAL-01': {
    title: 'Listed as malicious in OSV',
    severity: 'critical',
    points: { metadata: 100 },
    explanation: 'This exact version appears in the OpenSSF malicious-packages database.',
  },
  'R-TYPO-01': {
    title: 'Name looks like a popular package',
    severity: 'medium',
    points: { metadata: 30 },
    explanation: 'Typosquats copy the name of a well-known package with a small spelling change.',
  },
  'R-META-01': {
    title: 'Very new package',
    severity: 'low',
    points: { metadata: 10 },
    explanation: 'Most malicious packages are removed within days, so brand-new packages carry more risk.',
  },
  'R-META-02': {
    title: 'No source repository linked',
    severity: 'low',
    points: { metadata: 10 },
    explanation: 'Without a public repository, there is no easy way to compare the package to its source.',
  },
  'R-META-03': {
    title: 'Very few downloads',
    severity: 'low',
    points: { metadata: 10 },
    explanation: 'Few people use this package, so problems are less likely to have been noticed.',
  },
  'R-META-04': {
    title: 'Deprecated or yanked',
    severity: 'info',
    points: { metadata: 0 },
    explanation: 'The maintainers have marked this version as deprecated or withdrawn.',
  },
  'R-VULN-01': {
    title: 'Has known vulnerabilities',
    severity: 'low',
    points: { metadata: 15 },
    explanation: 'Public advisories list security bugs in this version.',
  },
  'R-AI-01': {
    title: 'AI reviewer detected an injection attempt',
    severity: 'info',
    points: { metadata: 0 },
    explanation: 'The local model reported text that tried to manipulate it. Shown for context only.',
  },
};

/** Lowercase file kinds used by pattern rules. */
const CODE_KINDS = new Set(['js', 'py', 'sh']);

const PATTERNS = [
  {
    ruleId: 'R-CRED-01',
    kinds: CODE_KINDS,
    re: /\.ssh[\\/](?:id_[a-z0-9]+|authorized_keys|known_hosts)|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws[\\/]credentials|\.npmrc|\.pypirc|\.git-credentials|\.docker[\\/]config\.json|\.kube[\\/]config|\.netrc\b|\.config[\\/]gcloud|Login Data|\.bash_history|\/etc\/shadow|wallet\.dat|['"`\\/]\.env(?:\.[a-z]+)?['"`]/i,
  },
  {
    ruleId: 'R-ENV-01',
    kinds: CODE_KINDS,
    re: /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\bprintenv\b|\benv\s*\|/,
  },
  {
    ruleId: 'R-NET-01',
    kinds: new Set(['js']),
    installOnly: true,
    re: /\b(?:https?|http2|net|tls|dgram)\.(?:request|get|connect|createConnection)\s*\(|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bdns\.(?:lookup|resolve\w*)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net)['"]/,
  },
  {
    ruleId: 'R-NET-01',
    kinds: new Set(['py']),
    installOnly: true,
    re: /\burllib\.request\b|\burllib2\b|\brequests\.(?:get|post|put|request)\s*\(|\bhttp\.client\b|\bsocket\.socket\s*\(|\bhttpx\.|\baiohttp\b|\burlopen\s*\(/,
  },
  {
    ruleId: 'R-NET-01',
    kinds: new Set(['sh']),
    installOnly: true,
    re: /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|ncat)\b|\bnc\s+-/i,
  },
  {
    ruleId: 'R-NET-02',
    kinds: CODE_KINDS,
    re: /https?:\/\/(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com|hastebin\.com|ngrok(?:-free)?\.(?:io|app|dev)|webhook\.site|requestbin|pipedream\.net|interact\.sh|\.oast\.(?:fun|live|me|online|pro|site)|burpcollaborator\.net|transfer\.sh/i,
  },
  {
    ruleId: 'R-EXEC-01',
    kinds: new Set(['js']),
    installOnly: true,
    re: /child_process|\b(?:execSync|spawnSync|execFileSync|execFile)\s*\(/,
  },
  {
    ruleId: 'R-EXEC-01',
    kinds: new Set(['py']),
    installOnly: true,
    re: /\bsubprocess\.|\bos\.system\s*\(|\bos\.popen\s*\(|\bpty\.spawn\b|\bos\.exec[lv]p?e?\s*\(/,
  },
  {
    ruleId: 'R-OBF-01',
    kinds: new Set(['js']),
    re: /\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\b|new\s+Function\s*\(\s*(?:atob|Buffer\.from)\b|\beval\s*\(\s*['"`][A-Za-z0-9+/=]{60}/,
  },
  {
    ruleId: 'R-OBF-01',
    kinds: new Set(['py']),
    re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b(?:64|32|16)decode|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|bz2\.decompress|lzma\.decompress)\b|\bexec\s*\(\s*compile\s*\(\s*(?:base64|zlib)/,
  },
  {
    ruleId: 'R-OBF-01',
    kinds: new Set(['sh']),
    re: /base64\s+(?:-d|--decode)\s*\|\s*(?:ba)?sh\b|\|\s*(?:ba)?sh\s*$|FromBase64String/i,
  },
  {
    ruleId: 'R-OBF-02',
    kinds: CODE_KINDS,
    re: /(?<!data:[\w/+.-]{0,60};base64,)(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{1000,}={0,2}|(?:\\x[0-9a-fA-F]{2}){300,}/,
  },
  {
    ruleId: 'R-INJECT-01',
    kinds: new Set(['js', 'py', 'sh', 'text']),
    re: /ignore\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)|disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions|\b(?:rate|mark|classify|report|label)\s+(?:this\s+)?(?:package|code|file|library)?\s*as\s+(?:safe|benign|clean|harmless|not\s+malicious)\b|"?risk_score"?\s*[:=]\s*0\b|"?malicious"?\s*[:=]\s*false\b/i,
  },
];

function catalog() {
  return Object.entries(RULES).map(([id, r]) => ({ id, ...r }));
}

module.exports = { RULES, PATTERNS, catalog };
