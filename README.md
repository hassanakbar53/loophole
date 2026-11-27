# 🕳️ Loophole

🌐 **Website:** https://rootsiemen-portfolio-sf-c596.vercel.app · 📦 **Latest release:** [v1.2.0](https://github.com/rootsiemen/loophole/releases/tag/v1.2.0)

This project is tested with BrowserStack.

**Loophole** is a zero-dependency static security scanner that finds the holes
in your code — hardcoded secrets, SQL injection, XSS, command injection, weak
crypto and more — across **JavaScript/TypeScript, Python, Go and PHP**.
It also explains *why* each finding matters, suggests a fix, and can print
mechanical fix suggestions as diffs without ever touching your files.

```bash
python3 loophole.py scan ./src
# or, with the wrapper on your PATH:
loophole scan ./src
```

## Why another scanner?

Most scanners are either heavyweight SaaS products or regex grep-scripts with
noisy output. Loophole sits in the middle:

- **Single file, stdlib only** — no install, no dependencies, runs anywhere
  Python 3.8+ exists. Drop it into CI in seconds.
- **Taint-aware (v1)** — it doesn't just pattern-match sinks; it tracks
  variables assigned from request/user input (`req.query`, `request.args`,
  `$_GET`, `r.URL.Query()`, …) and flags when they *flow* into dangerous
  sinks, including direct `query($_GET['id'])` usage.
- **Near-zero false positives** — parameterized queries, `textContent`,
  `execFile` with literals, `crypto.randomUUID`, env-var secrets and friends
  are all recognized as safe.
- **Fix suggestions, not just findings** — `--fix-dry` prints unified diffs
  for safe mechanical fixes. It never modifies your files.

## Quick start

```bash
# scan a directory or file
python3 loophole.py scan ./src

# JSON report for tooling
python3 loophole.py scan ./src --json report.json

# SARIF for GitHub code scanning
python3 loophole.py scan ./src --sarif results.sarif

# self-contained HTML report (inline CSS, no external assets)
python3 loophole.py scan ./src --html report.html

# adopt on an existing codebase: record today's findings as a baseline,
# then fail CI only on NEW ones
python3 loophole.py scan ./src --write-baseline baseline.json
python3 loophole.py scan ./src --baseline baseline.json

# show suggested fixes as diffs (read-only)
python3 loophole.py scan ./src --fix-dry

# list all rules
python3 loophole.py scan --rules .

# only critical findings, skip tests
python3 loophole.py scan ./src --severity critical --exclude 'tests/*'
```

Exit code is **1** when any critical/high finding exists (CI-friendly),
**0** otherwise.

## Docker

No local Python needed — scan from the container image instead.
The image is `python:3.12-slim`, contains only `loophole.py`
(stdlib only, no extra dependencies), and runs as a non-root user.

```bash
docker build -t loophole .
docker run --rm -v "$PWD:/src" loophole scan /src
```

### Published image (GHCR)

On every release, the smoke-tested image is published to GitHub
Container Registry as `ghcr.io/rootsiemen/loophole:<tag>` and
`:latest` — no local build needed:

```bash
docker pull ghcr.io/rootsiemen/loophole:latest
docker run --rm -v "$PWD:/src" ghcr.io/rootsiemen/loophole:latest scan /src
```

For a specific release, replace `latest` with the tag, for
example `ghcr.io/rootsiemen/loophole:v1.2.0`. The entrypoint is
the same (`python3 loophole.py`), so all `scan` arguments work
unchanged.

That mounts the current directory at `/src` inside the container
and scans it. The exit code is the same as the local scanner:
**1** when any critical/high finding exists, **0** otherwise.

Scan a single file or a different directory the same way:

```bash
docker run --rm -v "$PWD:/src" loophole scan /src/tests/fixtures/py_vuln.py
docker run --rm -v "$PWD:/src" loophole scan /src --json /src/report.json
```

Note: with `--json`, `--sarif` or `--html`, write the report to a
path under `/src` so the file lands in your mounted directory.


## GitHub Action

Run Loophole on every push and pull request, with findings uploaded to
GitHub code scanning (your repo's **Security** tab):

```yaml
name: Security scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  loophole:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rootsiemen/loophole@v1
```

Options (all optional):

| Input | Default | What it does |
|-------|---------|--------------|
| `path` | `.` | File or directory to scan |
| `severity` | `medium` | Minimum severity to report: `critical`, `high` or `medium` |
| `exclude` | — | Comma-separated directory names to skip |
| `upload-sarif` | `true` | Upload the SARIF report to code scanning |
| `fail-on-findings` | `true` | Fail the step when critical/high findings exist |
| `python-version` | `3.12` | Python version used to run the scanner |

Example — scan only `src`, never block the build:

```yaml
      - uses: rootsiemen/loophole@v1
        with:
          path: src
          fail-on-findings: "false"
```

## Example output

```
Loophole found 3 issue(s): 1 critical, 2 high, 0 medium

── CRITICAL (1) ──────────────────────────────────────────────
  CMD001 Command injection via child_process (JS/TS)
  src/app.js:33
  › exec(cmd, (err, out) => res.send(out));
  taint: req.query.cmd -> cmd -> exec
  why: Passing user-influenced strings to a shell lets attackers append
  commands (`; rm -rf /`, `$(...)`) that run with the app's privileges.
  fix: Avoid shells entirely: use execFile/spawn with an argument array
  (no shell). Never concatenate input into a command string.
```

## Rules (62)

| ID | Severity | What it catches |
|----|----------|-----------------|
| SEC001 | high | Hardcoded API key / token / secret (pattern + length) |
| SEC002 | high | Hardcoded password assignment |
| SEC003 | critical | Private key material in source |
| SEC004 | high | AWS access key ID (`AKIA…`) |
| SEC005 | high | High-entropy secret-like string (Shannon entropy) |
| SQLI001 | high | SQL string building — JS/TS (`"…"+`, template literals) |
| SQLI002 | high | SQL string building — Python (f-strings, `%`, `.format`) |
| SQLI003 | high | SQL string building — Go (`fmt.Sprintf`, concat) |
| SQLI004 | high | SQL string building — PHP (`.` concat) |
| XSS001 | high | Dynamic `innerHTML` / `outerHTML` assignment |
| XSS002 | medium | Dynamic `document.write()` |
| XSS003 | high | React `dangerouslySetInnerHTML` with dynamic value |
| XSS004 | high | PHP `echo`/`<?=` of `$_GET`/`$_POST`/`$_COOKIE` |
| CMD001 | critical | JS `child_process.exec/spawn` with dynamic command |
| CMD002 | critical | Python `os.system` / `shell=True` with dynamic command |
| CMD003 | critical | Go `exec.Command("sh","-c", …)` / tainted args |
| CMD004 | critical | PHP `system/exec/shell_exec/passthru` with `$` input |
| PATH001 | high | File operation on user-influenced path |
| PATH002 | medium | `..` traversal combined with user input |
| RAND001 | medium | `Math.random()` for tokens/secrets (JS) |
| RAND002 | medium | `random` module for secrets (Python) |
| RAND003 | medium | `math/rand` for secrets (Go; `crypto/rand` aware) |
| CRY001 | high | MD5 for password hashing |
| CRY002 | high | SHA-1 for password hashing |
| CRY003 | high | DES / 3DES cipher use |
| CRY004 | medium | Hardcoded IV |
| EVAL001 | critical | `eval()` with dynamic input |
| EVAL002 | high | `new Function()` with dynamic input |
| SSRF001 | high | HTTP request URL built from user input |
| AUTH001 | medium | Sensitive route without visible auth (heuristic) |
| CORS001 | medium | Wildcard CORS (`Access-Control-Allow-Origin: *`) |
| JWT001 | high | JWT decoded without verification (`jwt.decode`) |
| TLS001 | high | Disabled TLS verification |
| DBG001 | medium | Debug mode enabled (`debug=True`, `DEBUG = True`) |
| ERR001 | medium | Stack traces / exception details sent to client |
| PROTO001 | high | Prototype pollution via deep-merge of user input (JS/TS) |
| DESER001 | high | Unsafe deserialization (`pickle`, `shelve`, `unserialize`, `yaml.load`) |
| NOSQL001 | high | NoSQL injection — input flowing into MongoDB-style queries |
| XXE001 | high | XML external entity — XML parsers without hardening |
| REDIR001 | medium | Open redirect — target taken from user input |
| ZIP001 | high | Zip Slip — archive extraction without path validation |
| CSRF001 | medium | State-changing routes, no CSRF protection (app-level heuristic) |
| UPL001 | high | File upload accepted without type validation |
| REDOS001 | medium | ReDoS — regex with nested quantifiers |
| JWT002 | high | JWT `none` algorithm / weak secret / verification disabled |
| TLS002 | medium | Weak/outdated TLS versions (SSLv3, TLS 1.0/1.1) |
| CRY005 | medium | ECB mode or zero/static IV |
| LOG001 | medium | Sensitive data (passwords/tokens) written to logs |
| LDAP001 | high | LDAP injection via unescaped input |
| HDR001 | medium | Missing security headers (Express/Flask, app-level heuristic) |
| SSTI001 | high | Server-side template injection — input used AS the template (EJS/Pug/Jinja2/Go templates/Twig) |
| COOKIE001 | medium | Cookie set without HttpOnly, or the flag explicitly disabled |
| RAND004 | medium | `rand()`/`mt_rand()`/`uniqid()` for tokens/secrets (PHP) |
| TLS003 | high | TLS validation off via `CERT_NONE`, unverified contexts, `VERIFYHOST=0`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| TLS004 | high | Go `tls.Config{InsecureSkipVerify: true}` |
| CORS002 | high | CORS reflects any request Origin, or credentials combined with a wildcard origin |
| CRLF001 | medium | HTTP header injection — user-influenced value written into a response header |
| CMP001 | medium | Secret/token compared with `==`/`===` instead of a constant-time compare |
| REDIR002 | medium | DOM open redirect — `location` assigned from user input (JS/TS) |
| XXE002 | high | XXE — libxmljs entity expansion enabled (`noent`/`dtdload`) |
| XSS005 | high | `insertAdjacentHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, Go `template.HTML()` on dynamic values |
| DESER002 | high | `jsonpickle.decode` (Python) / `v8.deserialize` (JS) on dynamic data |

Each finding carries: rule id, severity, `file:line`, code snippet, taint
path (when tracked), *why it matters*, and a *fix suggestion*.

## Taint tracking (v1)

Loophole performs lightweight intra-file taint analysis:

1. **Sources** — assignments from `req.query` / `req.body` / `req.params`,
   `request.args` / `request.form`, `$_GET` / `$_POST` / `$_REQUEST` /
   `$_COOKIE`, `r.URL.Query()`, `os.Args`, and friends mark a variable tainted.
2. **Direct sources** — `query($_GET['id'])` (no intermediate variable) is
   caught too.
3. **Formatted strings** — variables holding interpolated SQL/HTML
   (f-strings, template literals, `fmt.Sprintf`, `"…$x"`) are tracked so
   `q = f"…{x}"; cursor.execute(q)` still flags.
4. **Sinks** — SQL calls, `exec`/`system`, `eval`, file functions, HTTP
   clients. When tainted data reaches a sink, the finding shows the path:
   `req.query.cmd -> cmd -> exec`.

Scope is deliberately small (single file, ~2 hops, no inter-procedural
analysis). It catches the common cases with very few false positives;
deeper analysis is on the roadmap.

## CI example (GitHub Actions)

```yaml
name: security-scan
on: [push, pull_request]
jobs:
  loophole:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Run Loophole
        run: python3 loophole.py scan ./src --sarif loophole.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: loophole.sarif
```

The step fails (exit 1) when critical/high findings exist, and results
appear under your repo's **Security → Code scanning** tab.

## Suppressing findings

When a finding is a false positive (or a risk you've accepted), silence it
inline — no config file needed:

```python
token = derive_token(salt)  # loophole: skip=SEC005
```

```js
// loophole: skip=CORS001  (bare form silences every rule on the line)
res.setHeader('Access-Control-Allow-Origin', '*');
```

Comma-separated rule ids are supported: `# loophole: skip=SEC001,SEC005`.
Use suppressions sparingly — each one is a hole you're choosing not to see.

`loophole:ignore` is an alias with a space-separated form, handy in
languages where `=` looks odd in comments:

```js
res.cookie('session', id, opts);  // loophole:ignore COOKIE001
```

## Configuration

Drop a `.loophole.json` in the directory you scan (or point `--config`
at any file) to tune the scan per project:

```json
{
  "exclude": ["generated", "fixtures"],
  "disable": ["HDR001"],
  "severity": { "SEC001": "medium", "LOG001": "critical" }
}
```

- `exclude` — path names or glob patterns to skip (merged with the
  built-in excludes and any `--exclude` flags).
- `disable` — rule ids that never run for this project.
- `severity` — per-rule severity overrides (`critical`, `high`,
  `medium`); they affect the report order and the exit code.

A broken config file prints a warning and is ignored — a scan never
dies because of its config.

## Ignoring files (`.loopholeignore`)

Commit a `.loopholeignore` in the directory you scan to skip files
and directories, gitignore-style — one pattern per line:

```
# generated output and vendored files

generated/
*.min.js
legacy.py
```

- A bare `name` matches a file or directory name at any depth.
- A `path/` pattern matches everything under that directory.
- `*` and `?` globs match a path component (`*.min.js`) or, when the
  pattern contains a `/`, the path relative to the scanned root
  (`generated/*`).
- Blank lines and `#` comments are ignored.

Ignored files are skipped during the walk exactly like excluded
directories, and the count appears as `ignored` in the JSON summary
(`summary.ignored`) and on the terminal. `--exclude` and the config
`exclude` keep working and combine with the ignore file. Removing
`.loopholeignore` restores the skipped findings.

## Baseline

Adopting a scanner on an existing codebase usually means a wall of
findings you can't fix today. Record them once:

```bash
python3 loophole.py scan ./src --write-baseline baseline.json
```

Commit `baseline.json`, and later scans hide everything in it:

```bash
python3 loophole.py scan ./src --baseline baseline.json
```

CI then fails only on **new** findings. Entries are keyed by rule,
file and code snippet, so small line shifts don't resurrect them.

## Incremental cache (`--cache`)

Repeat scans of a large tree re-analyse every file. Opt in to a cache
to skip unchanged files:

```bash
python3 loophole.py scan ./src --cache .loophole-cache.json
```

- The first run is a cold cache (everything scanned); the second
  reuses stored findings for files that did not change.
- Entries are keyed by file path plus size, mtime and a SHA-256 of the
  contents, so editing a file invalidates only that file's entry.
- The cache also records the Loophole version and the scan config: a
  Loophole upgrade or a config change (disabled rules, severity
  overrides) invalidates the whole cache automatically.
- Baseline and severity filtering still apply after cache retrieval,
  so a cached run produces exactly the same findings as an uncached
  run. The JSON summary reports `summary.cached` — how many files were
  served from cache — and the terminal prints the same count.
- The cache is always opt-in: without `--cache` nothing is read or
  written and every scan is a full scan. There is no daemon or watch
  mode; a corrupt or unreadable cache file is ignored and the scan
  falls back to a full scan of the affected files.

## HTML report

```bash
python3 loophole.py scan ./src --html report.html
```

Produces a single self-contained HTML file — inline CSS, no external
assets, works offline — with findings grouped by severity, each with
file/line, the code snippet, why it matters and the fix.

## Project layout

```
loophole/
├── loophole.py            # the scanner (single file, stdlib only)
├── Dockerfile               # container image: python:3.12-slim, non-root, stdlib only
├── loophole                # shell wrapper: loophole scan <path>
├── README.md
└── tests/
    ├── selftest.py        # python3 tests/selftest.py
    └── fixtures/          # 20 fixtures (10 vulnerable + 10 clean)
```

## Contributing

1. New rules go in `loophole.py`: write a `rule_XXXnnn(ctx)` function
   returning a list of findings, register it in `RULES` with its languages.
2. Add a vulnerable fixture *and* a clean counterpart under
   `tests/fixtures/` — the clean one must produce **zero** findings.
3. Run `python3 tests/selftest.py` and the dogfood check below before
   submitting.

**Dogfood rule:** every change must keep `python3 loophole.py scan loophole.py`
clean (exit 0).

## License

MIT — see `LICENSE`. Loophole is free and non-commercial: no paid tiers, no telemetry, no usage restrictions beyond the MIT terms.

