# Changelog

All notable changes to Loophole are documented here.

## Unreleased

### New features

- **JUnit XML report (`--junit`)** — test-style XML output for CI
  dashboards (Jenkins, GitLab CI, Azure DevOps, CircleCI): one
  `<testsuite>` per scan, one `<testcase>` per finding.

### Taint & coverage

- **DESER001 (PHP)** — `unserialize()` is now taint-aware (fixes #10):
  input from a request superglobal (`$_GET`/`$_POST`/`$_REQUEST`/
  `$_COOKIE`/`$_FILES`, `php://input`) or a variable assigned from one
  is flagged **high** with the taint flow noted; dynamic data of unknown
  origin is still flagged, at **medium**. String literals,
  `['allowed_classes' => false]` and `json_decode()` stay silent.
  Review fixes: multiline calls keep their severity, only
  `allowed_classes => false` silences a call, taint propagates through
  plain copies and is dropped on reassignment to trusted data, taint is
  checked on the payload argument only, and sources named only in
  comments do not taint a variable.
## 1.2.0 — 2026-11-27

### New rules (61 → 62)

- **TLS004** (high) — Go `tls.Config{InsecureSkipVerify: true}` flagged
  directly; the Go pattern moved out of TLS001 so Go files are no
  longer double-flagged.

### New features

- **`.loopholeignore`** — gitignore-style file/directory exclusions at
  the scanned root; ignored files are counted and reported.
- **Official Dockerfile** — run Loophole in a container as a non-root
  user.
- **CI** — the full selftest suite now runs in GitHub Actions on every
  push and pull request.

### Taint & coverage

- **Django / FastAPI taint sources (Python)** — `request.GET/POST/
  FILES/body/COOKIES/META/headers`, `query_params` / `path_params`,
  and `await request.json()` / `await request.form()` are now tracked
  into sinks, with guards against look-alike names.
- **PHP taint sources** — `$_FILES` and `php://input` now tracked.
- **DESER001** — Python `shelve.open()` with a dynamic path flagged.
- **XSS001** — `innerHTML` / `outerHTML` `+=` with dynamic content
  flagged; `==` / `===` comparisons excluded.
- **XSS005** — Go `template.HTML()` on dynamic values covered.
- Selftest fixture coverage completed for CRY002, EVAL002 and XSS002 —
  every rule now has fixtures.

### Fixes

- **`--severity` crash** — an unsupported severity value (e.g. `low`)
  crashed with a `KeyError`; the CLI now validates choices and config
  severities are normalised with a named warning.
- **XSS002** — the `document.write` pattern could never match
  `document.write` (only `writeln`); fixed to `document.write(?:ln)?`.

## 1.1.0 — 2026-11-16

### New rules (50 → 61)

- **SSTI001** (high) — server-side template injection: user input used
  *as* the template in EJS/Pug/Nunjucks/Handlebars (JS), Jinja2
  `Template`/`render_template_string` (Python), `text/template` /
  `html/template` `.Parse` (Go), Twig `createTemplate` / `Blade::render`
  (PHP).
- **COOKIE001** (medium) — cookies set without `HttpOnly`, or the flag
  explicitly disabled (`httpOnly: false`, Django
  `SESSION_COOKIE_HTTPONLY = False`, …).
- **RAND004** (medium) — PHP `rand()`/`mt_rand()`/`uniqid()` and friends
  used for tokens, OTPs and other security-sensitive values.
- **TLS003** (high) — TLS validation disabled via `ssl.CERT_NONE`,
  `_create_unverified_context()`, `check_hostname = False`,
  `CURLOPT_SSL_VERIFYHOST 0`, or `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- **CORS002** (high) — CORS that reflects any request `Origin`, or
  combines credentials with a wildcard origin (CORS001 covers the
  plain wildcard).
- **CRLF001** (medium) — HTTP header injection: user-influenced values
  written into response headers (response splitting).
- **CMP001** (medium) — secrets/tokens compared with `==`/`===`
  instead of a constant-time comparison (timing side channel; PHP
  type juggling).
- **REDIR002** (medium) — DOM open redirect: `location` assigned or
  navigated from user input in JS/TS (REDIR001 covers server-side).
- **XXE002** (high) — libxmljs entity expansion enabled
  (`noent: true`, `dtdload: true`, `nonet: false`).
- **XSS005** (high) — `insertAdjacentHTML` with dynamic content, Vue
  `v-html`, Angular `bypassSecurityTrust*`.
- **DESER002** (high) — `jsonpickle.decode` (Python) and
  `v8.deserialize` (JS) on dynamic data.

### New features

- **Config file** — `.loophole.json` in the scanned root (or
  `--config FILE`): `exclude` paths, `disable` rule ids, per-rule
  `severity` overrides.
- **Inline suppression alias** — `// loophole:ignore RULEID` (space or
  `=` form, or bare) now works alongside the existing
  `loophole: skip` comments.
- **Baseline** — `--write-baseline baseline.json` records current
  findings; `--baseline baseline.json` hides them so CI fails only on
  new issues.
- **HTML report** — `--html report.html` writes a single
  self-contained HTML report (inline CSS, no external assets) with
  findings grouped by severity.

### Changed

- `VERSION` in `loophole.py` synced with the release line (was stuck
  at `0.1.0`).

## 1.0.0

- First public release: 50 rules across JavaScript/TypeScript, Python,
  Go and PHP; taint tracking; terminal, JSON and SARIF output;
  `--fix-dry` patch suggestions; inline `loophole: skip` suppressions;
  GitHub Action with SARIF upload to code scanning.
