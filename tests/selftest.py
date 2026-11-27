#!/usr/bin/env python3
"""Loophole self-test: vulnerable fixtures must be caught, clean ones pass.

Run:  python3 tests/selftest.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER = os.path.join(ROOT, "loophole.py")
FIX = os.path.join(HERE, "fixtures")


def scan(path, *extra):
    """Run the scanner, return (exit_code, parsed_json_findings)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        cmd = [sys.executable, SCANNER, "scan", path,
               "--json", out, "--no-color"] + list(extra)
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        with open(out) as fh:
            data = json.load(fh)
        return proc.returncode, data["findings"]
    finally:
        os.unlink(out)


def rule_ids(findings):
    return {f["rule_id"] for f in findings}


def scan_json(path, *extra):
    """Run the scanner, return (exit_code, full parsed JSON report)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        cmd = [sys.executable, SCANNER, "scan", path,
               "--json", out, "--no-color"] + list(extra)
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        with open(out) as fh:
            data = json.load(fh)
        return proc.returncode, data
    finally:
        os.unlink(out)


# rule -> fixtures that must trigger it (subset assertion: each listed rule
# must appear at least once in the fixture's findings)
EXPECTED = {
    "js_vuln.js": {"SEC001", "SQLI001", "AUTH001", "XSS001", "XSS002", "XSS003",
                   "CMD001", "EVAL001", "EVAL002", "JWT001", "CORS001", "TLS001",
                   "ERR001", "RAND001",
                   "PROTO001", "NOSQL001", "REDIR001", "JWT002", "UPL001",
                   "REDOS001", "LOG001", "ZIP001", "TLS002", "CRY005",
                   "LDAP001", "CSRF001", "HDR001"},
    "ts_vuln.ts": {"SQLI001", "SSRF001", "PATH001", "PATH002", "HDR001"},
    "py_vuln.py": {"SEC002", "SQLI002", "CMD002", "SSRF001", "TLS001",
                   "PATH001", "EVAL001", "RAND002", "CRY001", "CRY002",
                   "AUTH001", "DBG001",
                   "DESER001", "NOSQL001", "XXE001", "REDIR001", "ZIP001",
                   "CSRF001", "UPL001", "REDOS001", "JWT002", "TLS002",
                   "CRY005", "LOG001", "LDAP001", "HDR001"},
    "go_vuln.go": {"SQLI003", "CMD003", "CRY003", "CRY004", "RAND003",
                   "TLS004", "TLS002", "REDOS001", "LOG001", "XSS005"},
    "php_vuln.php": {"SEC001", "SQLI004", "XSS004", "CMD004", "EVAL001",
                     "CRY001", "SSRF001", "TLS001", "PATH001",
                     "DESER001", "XXE001", "REDIR001", "ZIP001", "UPL001",
                     "REDOS001", "TLS002", "CRY005", "LOG001", "LDAP001",
                     "RAND004"},
    "mixed_vuln.py": {"SEC003", "SEC004", "SEC005", "PATH002", "CORS001",
                      "DBG001"},
    "v2_vuln.js": {"SSTI001", "COOKIE001", "TLS003", "CORS002", "CRLF001",
                   "CMP001", "REDIR002", "XXE002", "XSS005", "DESER002"},
    "v2_vuln.py": {"SSTI001", "COOKIE001", "TLS003", "CORS002", "CRLF001",
                   "CMP001", "DESER002"},
    "v2_vuln.php": {"SSTI001", "COOKIE001", "TLS003", "CORS002", "CRLF001",
                    "CMP001", "RAND004"},
    "v2_vuln.go": {"SSTI001", "CORS002", "CMP001"},
}

CLEAN = ["js_clean.js", "ts_clean.ts", "py_clean.py", "go_clean.go",
         "php_clean.php", "all_clean.js", "v2_clean.js", "v2_clean.py",
         "v2_clean.php", "v2_clean.go"]


class TestFixtures(unittest.TestCase):
    def test_vulnerable_fixtures(self):
        for name, expected in EXPECTED.items():
            with self.subTest(fixture=name):
                code, findings = scan(os.path.join(FIX, name))
                got = rule_ids(findings)
                missing = expected - got
                self.assertFalse(
                    missing,
                    f"{name}: expected rules not fired: {sorted(missing)} "
                    f"(got {sorted(got)})")
                self.assertEqual(
                    code, 1,
                    f"{name}: exit code should be 1 (critical/high present)")

    def test_clean_fixtures(self):
        for name in CLEAN:
            with self.subTest(fixture=name):
                code, findings = scan(os.path.join(FIX, name))
                self.assertEqual(
                    findings, [],
                    f"{name}: clean fixture produced findings: "
                    f"{[(f['rule_id'], f['line']) for f in findings]}")
                self.assertEqual(code, 0, f"{name}: exit code should be 0")

    def test_sarif_output(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif",
                                         delete=False) as tmp:
            out = tmp.name
        try:
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan",
                 os.path.join(FIX, "py_vuln.py"),
                 "--sarif", out, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 1)
            with open(out) as fh:
                sarif = json.load(fh)
            self.assertEqual(sarif["version"], "2.1.0")
            results = sarif["runs"][0]["results"]
            self.assertTrue(results, "SARIF has no results")
            self.assertTrue(all("ruleId" in r for r in results))
        finally:
            os.unlink(out)

    def test_fix_dry_does_not_modify(self):
        target = os.path.join(FIX, "py_vuln.py")
        with open(target, "rb") as fh:
            before = fh.read()
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", target,
             "--fix-dry", "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        with open(target, "rb") as fh:
            after = fh.read()
        self.assertEqual(before, after, "--fix-dry modified the file!")
        self.assertIn("---", proc.stdout,
                      "--fix-dry printed no diff suggestions")

    def test_rules_list(self):
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--rules", "."],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("62 rules total", proc.stdout)

    def test_explain_every_rule(self):
        """--explain works for every ID from --rules: non-empty
        description and fix text for each, exit 0."""
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--rules", "."],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0)
        ids = sorted(set(re.findall(r"\b[A-Z]+\d{3}\b", proc.stdout)))
        self.assertEqual(len(ids), 62,
                         "--rules should list 62 rule IDs")
        for rid in ids:
            with self.subTest(rule=rid):
                proc = subprocess.run(
                    [sys.executable, SCANNER, "scan", "--explain", rid],
                    capture_output=True, text=True, cwd=ROOT)
                self.assertEqual(
                    proc.returncode, 0,
                    f"--explain {rid} failed: {proc.stderr}")
                self.assertIn(rid, proc.stdout)
                self.assertIn("Languages:", proc.stdout)
                self.assertIn("Severity:", proc.stdout)
                why = [ln for ln in proc.stdout.splitlines()
                       if ln.strip().startswith("Why:")]
                fix = [ln for ln in proc.stdout.splitlines()
                       if ln.strip().startswith("Fix:")]
                self.assertTrue(why,
                                f"--explain {rid} printed no Why line")
                self.assertTrue(fix,
                                f"--explain {rid} printed no Fix line")
                self.assertTrue(
                    all(ln.split("Why:", 1)[1].strip() for ln in why),
                    f"--explain {rid} has an empty description")
                self.assertTrue(
                    all(ln.split("Fix:", 1)[1].strip() for ln in fix),
                    f"--explain {rid} has empty fix guidance")

    def test_explain_unknown_rule(self):
        """An unknown rule ID fails with exit 2 and a clean stderr
        message (no traceback)."""
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--explain", "NOPE123"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown rule", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_explain_close_match_and_case(self):
        """Rule IDs match case-insensitively, and a near-miss suggests
        the closest valid IDs."""
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--explain", "sec001"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0,
                         "IDs should match case-insensitively")
        self.assertIn("SEC001", proc.stdout)
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--explain", "SEC01"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("SEC001", proc.stderr,
                      "close matches should be suggested")

    def test_no_rule_crashes(self):
        """Every rule function must run without raising (regression net for
        bad-regex crashes that scan_file would otherwise swallow)."""
        sys.path.insert(0, ROOT)
        import loophole
        bad = []
        for rule_id, langs, func in loophole.RULES:
            for lang in langs:
                ctx = loophole.Ctx("t." + lang, lang, ["x = 1"])
                try:
                    func(ctx)
                except Exception as exc:  # noqa: BLE001
                    bad.append((rule_id, lang, repr(exc)))
        self.assertFalse(bad, f"rules crashed: {bad}")

    def test_inline_suppression(self):
        sys.path.insert(0, ROOT)
        import loophole
        with tempfile.NamedTemporaryFile(
                suffix=".py", mode="w", delete=False) as tmp:
            tmp.write('API_KEY = "sk-live-abcdef1234567890"  '
                      '# loophole: skip=SEC001\n')
            tmp.write('SECRET_KEY = "sk-live-abcdef1234567890"\n')
            path = tmp.name
        try:
            findings = loophole.scan_file(path)
            line1 = {f.rule_id for f in findings if f.line == 1}
            line2 = {f.rule_id for f in findings if f.line == 2}
            self.assertNotIn("SEC001", line1,
                             "suppression comment did not silence line 1")
            self.assertIn("SEC001", line2,
                          "unsuppressed twin line should still fire")
        finally:
            os.unlink(path)


    def test_ignore_suppression(self):
        """loophole:ignore (space and = forms, plus bare) silences rules."""
        sys.path.insert(0, ROOT)
        import loophole
        with tempfile.NamedTemporaryFile(
                suffix=".py", mode="w", delete=False) as tmp:
            tmp.write('API_KEY = "sk-live-abcdef1234567890"  '
                      '# loophole:ignore SEC001\n')
            tmp.write('API_SECRET = "sk-live-abcdef1234567890"  '
                      '# loophole:ignore=SEC001\n')
            tmp.write('AUTH_TOKEN = "sk-live-abcdef1234567890"  '
                      '# loophole:ignore\n')
            tmp.write('CLIENT_SECRET = "sk-live-abcdef1234567890"\n')
            path = tmp.name
        try:
            findings = loophole.scan_file(path)
            by_line = {}
            for f in findings:
                by_line.setdefault(f.line, set()).add(f.rule_id)
            for ln in (1, 2, 3):
                self.assertNotIn(
                    "SEC001", by_line.get(ln, set()),
                    f"loophole:ignore did not silence line {ln}")
            self.assertIn("SEC001", by_line.get(4, set()),
                          "unsuppressed line should still fire")
        finally:
            os.unlink(path)

    def test_config_file(self):
        """A .loophole.json can disable rules, override severities and
        exclude paths — picked up automatically from the scanned root."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write('API_KEY = "sk-live-abcdef1234567890"\n')
                fh.write('DB_PASSWORD = "hunter2hunter2"\n')
            with open(os.path.join(d, "skipme.py"), "w") as fh:
                fh.write('API_KEY = "sk-live-abcdef1234567890"\n')
            with open(os.path.join(d, ".loophole.json"), "w") as fh:
                json.dump({"disable": ["SEC002"],
                           "severity": {"SEC001": "medium"},
                           "exclude": ["skipme.py"]}, fh)
            code, findings = scan(d)
            ids = rule_ids(findings)
            self.assertIn("SEC001", ids)
            self.assertNotIn("SEC002", ids,
                             "config disable did not apply")
            self.assertTrue(
                all("skipme.py" not in f["path"] for f in findings),
                "config exclude did not apply")
            sec1 = [f for f in findings if f["rule_id"] == "SEC001"]
            self.assertTrue(
                all(f["severity"] == "medium" for f in sec1),
                "config severity override did not apply")
            self.assertEqual(code, 0,
                             "only-medium findings should exit 0")

    def test_loopholeignore(self):
        """A .loopholeignore in the scanned root skips matching files
        (name match, glob match, directory prefix); comments and blank
        lines are ignored; removing the file restores the findings; the
        JSON summary counts ignored files; --exclude still combines."""
        vuln = 'API_KEY = "sk-live-abcdef1234567890"\n'
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, "skipme.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, "app.min.js"), "w") as fh:
                fh.write(vuln)
            os.mkdir(os.path.join(d, "generated"))
            with open(os.path.join(d, "generated", "gen.py"), "w") as fh:
                fh.write(vuln)
            ignore = os.path.join(d, ".loopholeignore")
            with open(ignore, "w") as fh:
                fh.write("# ignore generated output and vendored files\n"
                         "\n"
                         "skipme.py\n"
                         "*.min.js\n"
                         "generated/\n")
            code, findings = scan(d)
            paths = {f["path"] for f in findings}
            self.assertTrue(
                any(p.endswith("app.py") for p in paths),
                "app.py findings missing under .loopholeignore")
            self.assertFalse(
                any("skipme.py" in p or "app.min.js" in p or
                    "generated" in p for p in paths),
                f"ignored files still scanned: {sorted(paths)}")
            self.assertEqual(code, 1)

            with tempfile.NamedTemporaryFile(suffix=".json",
                                             delete=False) as tmp:
                out = tmp.name
            try:
                proc = subprocess.run(
                    [sys.executable, SCANNER, "scan", d,
                     "--json", out, "--no-color"],
                    capture_output=True, text=True, cwd=ROOT)
                self.assertEqual(proc.returncode, 1)
                with open(out) as fh:
                    data = json.load(fh)
                self.assertEqual(data["summary"]["ignored"], 3,
                                 "JSON summary should count the 3 "
                                 "ignored files")
            finally:
                os.unlink(out)

            # --exclude combines with the ignore file
            code, findings = scan(d, "--exclude", "app.py")
            self.assertEqual(findings, [],
                             "--exclude did not combine with "
                             ".loopholeignore")

            # removing the file restores every finding
            os.unlink(ignore)
            code, findings = scan(d)
            paths = {f["path"] for f in findings}
            for name in ("app.py", "skipme.py", "app.min.js",
                         os.path.join("generated", "gen.py")):
                self.assertTrue(
                    any(p.endswith(name) for p in paths),
                    f"{name} findings did not return after removing "
                    f".loopholeignore")

    def test_severity_validation(self):
        """An unsupported --severity fails fast with a clean CLI error
        (no traceback), and a bad severity level in .loophole.json is
        ignored with a warning naming the rule — never a crash."""
        target = os.path.join(FIX, "py_vuln.py")
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", target,
             "--severity", "low", "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2,
                         "--severity low should be an argparse error")
        self.assertIn("invalid choice", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write('API_KEY = "sk-live-abcdef1234567890"\n')
            with open(os.path.join(d, ".loophole.json"), "w") as fh:
                json.dump({"severity": {"SEC001": "low",
                                        "SEC002": ["high"]}}, fh)
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan", d, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertNotIn("Traceback", proc.stderr,
                             "bad config severity crashed the scan")
            self.assertIn("SEC001", proc.stderr,
                          "warning should name the offending rule id")
            self.assertIn("SEC002", proc.stderr,
                          "warning should name the offending rule id")

    def test_baseline_roundtrip(self):
        """--write-baseline records findings; --baseline then hides them."""
        target = os.path.join(FIX, "py_vuln.py")
        with tempfile.NamedTemporaryFile(suffix=".json",
                                         delete=False) as tmp:
            base = tmp.name
        try:
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan", target,
                 "--write-baseline", base, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 0)
            with open(base) as fh:
                data = json.load(fh)
            self.assertTrue(data["entries"],
                            "baseline file has no entries")
            code, findings = scan(target, "--baseline", base)
            self.assertEqual(findings, [],
                             "baseline did not suppress known findings")
            self.assertEqual(code, 0)
        finally:
            os.unlink(base)

    def test_html_report(self):
        with tempfile.NamedTemporaryFile(suffix=".html",
                                         delete=False) as tmp:
            out = tmp.name
        try:
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan",
                 os.path.join(FIX, "js_vuln.js"),
                 "--html", out, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 1)
            with open(out) as fh:
                page = fh.read()
            self.assertIn("Loophole", page)
            self.assertIn("SEC001", page)
            self.assertNotIn("http://", page.replace(
                "http://www.w3.org", ""),
                "HTML report must not reference external assets")
        finally:
            os.unlink(out)


class TestCache(unittest.TestCase):
    """--cache: cold cache, warm cache, invalidation on file change,
    stale-version fallback, and baseline filtering after retrieval."""
    VULN = 'API_KEY = "sk-live-abcdef1234567890"\n'

    def _tree(self, d):
        with open(os.path.join(d, "vuln.py"), "w") as fh:
            fh.write(self.VULN)
        with open(os.path.join(d, "clean.py"), "w") as fh:
            fh.write("def greet(name):\n    return 'hello ' + name\n")

    def test_cache_cold_then_warm(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            cache = os.path.join(d, "cache.json")
            code1, data1 = scan_json(d, "--cache", cache)
            self.assertEqual(data1["summary"]["cached"], 0,
                             "cold cache should serve nothing")
            self.assertTrue(os.path.isfile(cache),
                            "first --cache run should write the cache")
            sys.path.insert(0, ROOT)
            import loophole
            with open(cache) as fh:
                stored = json.load(fh)
            self.assertEqual(stored["version"], loophole.VERSION,
                             "cache must record the ruleset version")
            code2, data2 = scan_json(d, "--cache", cache)
            self.assertEqual(data2["summary"]["cached"], 2,
                             "warm cache should serve both files")
            self.assertEqual(data1["findings"], data2["findings"],
                             "cached run must produce identical findings")
            self.assertEqual(code1, code2)

    def test_cache_invalidation_on_change(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            cache = os.path.join(d, "cache.json")
            scan_json(d, "--cache", cache)
            _, warm = scan_json(d, "--cache", cache)
            self.assertEqual(warm["summary"]["cached"], 2)
            # edit only clean.py: it becomes vulnerable
            with open(os.path.join(d, "clean.py"), "w") as fh:
                fh.write(self.VULN)
            _, data = scan_json(d, "--cache", cache)
            self.assertEqual(
                data["summary"]["cached"], 1,
                "only the unchanged file should be served from cache")
            self.assertTrue(
                any(f["path"].endswith("clean.py")
                    for f in data["findings"]),
                "edited file must be rescanned and its finding shown")
            _, data2 = scan_json(d, "--cache", cache)
            self.assertEqual(data2["summary"]["cached"], 2,
                             "cache should be warm again after the rescan")
            self.assertEqual(data["findings"], data2["findings"])

    def test_cache_version_mismatch_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            cache = os.path.join(d, "cache.json")
            with open(cache, "w") as fh:
                json.dump(
                    {"tool": "loophole", "version": "0.0.0",
                     "config": "bogus",
                     "entries": {"vuln.py": {
                         "key": {"size": 0, "mtime_ns": 0, "sha256": "x"},
                         "findings": [{"rule_id": "FAKE001",
                                       "severity": "high", "title": "fake",
                                       "path": "vuln.py", "line": 1,
                                       "snippet": "x", "why": "y",
                                       "fix": "z"}]}}}, fh)
            _, data = scan_json(d, "--cache", cache)
            self.assertEqual(
                data["summary"]["cached"], 0,
                "stale-version cache must not be trusted")
            self.assertFalse(
                any(f["rule_id"] == "FAKE001" for f in data["findings"]),
                "stale cache entries must never be served")
            self.assertIn("SEC001", rule_ids(data["findings"]),
                          "real findings must still be produced")

    def test_cache_with_baseline(self):
        """Baseline filtering applies after cache retrieval, so a warm
        cached run hides baselined findings exactly like a fresh run."""
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            cache = os.path.join(d, "cache.json")
            base = os.path.join(d, "base.json")
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan", d,
                 "--write-baseline", base, "--cache", cache, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 0)
            _, data = scan_json(d, "--cache", cache, "--baseline", base)
            self.assertEqual(data["findings"], [],
                             "baseline must hide cached findings too")
            self.assertEqual(data["summary"]["cached"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

