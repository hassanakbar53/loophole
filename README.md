# 🕳️ Loophole

🌐 **Website:** https://frinjo.me/loophole · 📦 **Latest release:** [v1.2.2](https://github.com/rootsiemen/loophole/releases/tag/v1.2.2)

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

# JUnit XML for CI dashboards (Jenkins, GitLab CI, Azure DevOps, CircleCI)
python3 loophole.py scan ./src --junit report.xml

# GitLab SAST report for the Security Dashboard / merge request widget
python3 loophole.py scan ./src --gitlab gl-sast-report.json

# adopt on an existing codebase: record today's findings as a baseline,
# then fail CI only on NEW ones
python3 loophole.py scan ./src --write-baseline baseline.json
python3 loophole.py scan ./src --baseline baseline.json

# show suggested fixes as diffs (read-only)
python3 loophole.py scan ./src --fix-dry

# list all rules
python3 loophole.py scan --rules .

# show what one rule checks, its severity and how to fix it
python3 loophole.py scan --explain SEC001

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

Note: with `--json`, `--sarif`, `--html` or `--junit`, write the report to a
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

## Pre-commit

Catch findings before they are committed, with the
[pre-commit framework](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/rootsiemen/loophole
    rev: v1.2.2
    hooks:
      - id: loophole
```

The hook scans every staged JavaScript, TypeScript, Python, Go and PHP
file and fails the commit when a file has critical or high findings
(the scanner's default exit behaviour). Until the package is
pip-installable (issue #21), the hook runs from a checkout of this
repository via a small wrapper script, because `loophole scan` takes a
single path per invocation.

## Shell completions

Tab-completion for `bash` and `zsh` lives in `completions/`:

```bash
# bash — copy the script into your completions directory, then start
# a new shell (or `source` it for the current session only)
cp completions/loophole.bash ~/.local/share/bash-completion/completions/loophole

# zsh — copy the file to a directory on your fpath, then re-run compinit
mkdir -p ~/.zsh/completions
cp completions/_loophole ~/.zsh/completions/_loophole
rm -f ~/.zcompdump; compinit
```

If `~/.zsh/completions` is not already on your `fpath`, add this to
`~/.zshrc` before `compinit`:

```zsh
fpath=(~/.zsh/completions $fpath)
```

Both complete the `scan` subcommand, every `scan` flag, the
`--severity` choices (`critical`, `high`, `medium`), file paths for
the report/config options (`--json`, `--sarif`, `--html`, `--junit`,
`--gitlab`, `--config`, `--baseline`, `--write-baseline`, `--cache`), rule IDs for
`--explain`, and files/directories for the scan target. The selftest
suite checks that every flag in `loophole scan --help` appears in both
files, so the completions cannot silently drift from the CLI.

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
| <a name="rule-sec001"></a>SEC001 | high | Hardcoded API key / token / secret (pattern + length) |
| <a name="rule-sec002"></a>SEC002 | high | Hardcoded password assignment |
| <a name="rule-sec003"></a>SEC003 | critical | Private key material in source |
| <a name="rule-sec004"></a>SEC004 | high | AWS access key ID (`AKIA…`) |
| <a name="rule-sec005"></a>SEC005 | high | High-entropy secret-like string (Shannon entropy) |
| <a name="rule-sqli001"></a>SQLI001 | high | SQL string building — JS/TS (`"…"+`, template literals) |
| <a name="rule-sqli002"></a>SQLI002 | high | SQL string building — Python (f-strings, `%`, `.format`) |
| <a name="rule-sqli003"></a>SQLI003 | high | SQL string building — Go (`fmt.Sprintf`, concat) |
| <a name="rule-sqli004"></a>SQLI004 | high | SQL string building — PHP (`.` concat) |
| <a name="rule-xss001"></a>XSS001 | high | Dynamic `innerHTML` / `outerHTML` assignment |
| <a name="rule-xss002"></a>XSS002 | medium | Dynamic `document.write()` |
| <a name="rule-xss003"></a>XSS003 | high | React `dangerouslySetInnerHTML` with dynamic value |
| <a name="rule-xss004"></a>XSS004 | high | PHP `echo`/`<?=` of `$_GET`/`$_POST`/`$_COOKIE` |
| <a name="rule-cmd001"></a>CMD001 | critical | JS `child_process.exec/spawn` with dynamic command |
| <a name="rule-cmd002"></a>CMD002 | critical | Python `os.system` / `shell=True` with dynamic command |
| <a name="rule-cmd003"></a>CMD003 | critical | Go `exec.Command("sh","-c", …)` / tainted args |
| <a name="rule-cmd004"></a>CMD004 | critical | PHP `system/exec/shell_exec/passthru` with `$` input |
| <a name="rule-path001"></a>PATH001 | high | File operation on user-influenced path |
| <a name="rule-path002"></a>PATH002 | medium | `..` traversal combined with user input |
| <a name="rule-rand001"></a>RAND001 | medium | `Math.random()` for tokens/secrets (JS) |
| <a name="rule-rand002"></a>RAND002 | medium | `random` module for secrets (Python) |
| <a name="rule-rand003"></a>RAND003 | medium | `math/rand` for secrets (Go; `crypto/rand` aware) |
| <a name="rule-cry001"></a>CRY001 | high | MD5 for password hashing |
| <a name="rule-cry002"></a>CRY002 | high | SHA-1 for password hashing |
| <a name="rule-cry003"></a>CRY003 | high | DES / 3DES cipher use |
| <a name="rule-cry004"></a>CRY004 | medium | Hardcoded IV |
| <a name="rule-eval001"></a>EVAL001 | critical | `eval()` with dynamic input |
| <a name="rule-eval002"></a>EVAL002 | high | `new Function()` with dynamic input |
| <a name="rule-ssrf001"></a>SSRF001 | high | HTTP request URL built from user input |
| <a name="rule-auth001"></a>AUTH001 | medium | Sensitive route without visible auth (heuristic) |
| <a name="rule-cors001"></a>CORS001 | medium | Wildcard CORS (`Access-Control-Allow-Origin: *`) |
| <a name="rule-jwt001"></a>JWT001 | high | JWT decoded without verification (`jwt.decode`) |
| <a name="rule-tls001"></a>TLS001 | high | Disabled TLS verification |
| <a name="rule-dbg001"></a>DBG001 | medium | Debug mode enabled (`debug=True`, `DEBUG = True`) |
| <a name="rule-err001"></a>ERR001 | medium | Stack traces / exception details sent to client |
| <a name="rule-proto001"></a>PROTO001 | high | Prototype pollution via deep-merge of user input (JS/TS) |
| <a name="rule-deser001"></a>DESER001 | high | Unsafe deserialization (`pickle`, `shelve`, `unserialize`, `yaml.load`) — PHP `unserialize()` on dynamic data of unknown origin is medium |
| <a name="rule-nosql001"></a>NOSQL001 | high | NoSQL injection — input flowing into MongoDB-style queries |
| <a name="rule-xxe001"></a>XXE001 | high | XML external entity — XML parsers without hardening |
| <a name="rule-redir001"></a>REDIR001 | medium | Open redirect — target taken from user input |
| <a name="rule-zip001"></a>ZIP001 | high | Zip Slip — archive extraction without path validation |
| <a name="rule-csrf001"></a>CSRF001 | medium | State-changing routes, no CSRF protection (app-level heuristic) |
| <a name="rule-upl001"></a>UPL001 | high | File upload accepted without type validation |
| <a name="rule-redos001"></a>REDOS001 | medium | ReDoS — regex with nested quantifiers |
| <a name="rule-jwt002"></a>JWT002 | high | JWT `none` algorithm / weak secret / verification disabled |
| <a name="rule-tls002"></a>TLS002 | medium | Weak/outdated TLS versions (SSLv3, TLS 1.0/1.1) |
| <a name="rule-cry005"></a>CRY005 | medium | ECB mode or zero/static IV |
| <a name="rule-log001"></a>LOG001 | medium | Sensitive data (passwords/tokens) written to logs |
| <a name="rule-ldap001"></a>LDAP001 | high | LDAP injection via unescaped input |
| <a name="rule-hdr001"></a>HDR001 | medium | Missing security headers (Express/Flask, app-level heuristic) |
| <a name="rule-ssti001"></a>SSTI001 | high | Server-side template injection — input used AS the template (EJS/Pug/Jinja2/Go templates/Twig) |
| <a name="rule-cookie001"></a>COOKIE001 | medium | Cookie set without HttpOnly, or the flag explicitly disabled |
| <a name="rule-rand004"></a>RAND004 | medium | `rand()`/`mt_rand()`/`uniqid()` for tokens/secrets (PHP) |
| <a name="rule-tls003"></a>TLS003 | high | TLS validation off via `CERT_NONE`, unverified contexts, `VERIFYHOST=0`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| <a name="rule-tls004"></a>TLS004 | high | Go `tls.Config{InsecureSkipVerify: true}` |
| <a name="rule-cors002"></a>CORS002 | high | CORS reflects any request Origin, or credentials combined with a wildcard origin |
| <a name="rule-crlf001"></a>CRLF001 | medium | HTTP header injection — user-influenced value written into a response header |
| <a name="rule-cmp001"></a>CMP001 | medium | Secret/token compared with `==`/`===` instead of a constant-time compare |
| <a name="rule-redir002"></a>REDIR002 | medium | DOM open redirect — `location` assigned from user input (JS/TS) |
| <a name="rule-xxe002"></a>XXE002 | high | XXE — libxmljs entity expansion enabled (`noent`/`dtdload`) |
| <a name="rule-xss005"></a>XSS005 | high | `insertAdjacentHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, Go `template.HTML()` on dynamic values |
| <a name="rule-deser002"></a>DESER002 | high | `jsonpickle.decode` (Python) / `v8.deserialize` (JS) on dynamic data |

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

## JUnit report

```bash
python3 loophole.py scan ./src --junit report.xml
```

Produces a JUnit XML report for CI systems that ingest test-style
results (Jenkins, GitLab CI, Azure DevOps, CircleCI): one
`<testsuite>` for the scan, one `<testcase>` per finding with
`classname` set to the rule ID and `name` set to `path:line`, and a
`<failure>` whose message includes the severity, rule ID and finding
title. A clean scan emits an empty suite (`tests="0" failures="0"`).

## GitLab SAST report

```bash
python3 loophole.py scan ./src --gitlab gl-sast-report.json
```

Produces a GitLab SAST report (schema 15.x) for the Security
Dashboard and the merge request widget: one `vulnerability` per
finding, with a stable `id` (a hash of rule + file + snippet, so the
same finding keeps the same id across scans), `category: "sast"`,
`severity` mapped from Loophole's `critical`/`high`/`medium` onto
GitLab's `Critical`/`High`/`Medium`, the rule id in `identifiers`
(with a link to the rule docs), and `location` (`file`,
`start_line`). A clean scan emits an empty `vulnerabilities` list.
Wire it into `.gitlab-ci.yml`:

```yaml
loophole:
  image: python:3.12-slim
  script:
    - python3 loophole.py scan ./src --gitlab gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Project layout

```
loophole/
├── loophole.py            # the scanner (single file, stdlib only)
├── completions/           # shell completions for bash and zsh
│   ├── loophole.bash
│   └── _loophole
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

