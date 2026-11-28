#!/usr/bin/env python3
"""Loophole self-test: vulnerable fixtures must be caught, clean ones pass.

Run:  python3 tests/selftest.py
"""
import hashlib
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

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


def run_scan_full(path, *extra):
    """Run the scanner, return (CompletedProcess, parsed JSON report).

    The JSON report is None when the scanner exits before writing one
    (for example exit code 2 on an unreadable baseline); the process
    result still carries the exit code and stderr.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", path,
             "--json", out, "--no-color"] + list(extra),
            capture_output=True, text=True, cwd=ROOT)
        try:
            with open(out) as fh:
                return proc, json.load(fh)
        except (OSError, ValueError):
            return proc, None
    finally:
        os.unlink(out)


def scan_sarif(path):
    """Run the scanner with --sarif, return (exit_code, parsed SARIF)."""
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out = tmp.name
    try:
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", path,
             "--sarif", out, "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        with open(out) as fh:
            return proc.returncode, json.load(fh)
    finally:
        os.unlink(out)


def scan_gitlab(path):
    """Run the scanner with --gitlab, return (exit_code, parsed report)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", path,
             "--gitlab", out, "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        with open(out) as fh:
            return proc.returncode, json.load(fh)
    finally:
        os.unlink(out)


def scan_annotations(path, *extra):
    """Run the scanner with --format annotations, return (exit_code, lines)."""
    proc = subprocess.run(
        [sys.executable, SCANNER, "scan", path,
         "--format", "annotations", "--no-color"] + list(extra),
        capture_output=True, text=True, cwd=ROOT)
    return proc.returncode, proc.stdout.splitlines()
# SARIF level values (SARIF 2.1.0, section 3.27.9). write_sarif only
# emits "error" and "warning", but any of these is structurally valid.
SARIF_LEVELS = {"error", "warning", "note", "none"}


def validate_sarif(sarif, testcase):
    """Hand-rolled SARIF 2.1.0 structural validation (issue #50).

    No jsonschema package — plain assertions, per the project's
    zero-dependency rule. Raises AssertionError on the first defect.
    Returns the set of rule IDs that produced a result.
    """
    # the document round-trips through JSON and carries $schema/version
    testcase.assertEqual(json.loads(json.dumps(sarif)), sarif,
                         "SARIF document does not round-trip through JSON")
    testcase.assertEqual(
        sarif.get("$schema"),
        "https://json.schemastore.org/sarif-2.1.0.json",
        "SARIF $schema is missing or wrong")
    testcase.assertEqual(sarif.get("version"), "2.1.0",
                         "SARIF version is not 2.1.0")
    runs = sarif.get("runs")
    testcase.assertIsInstance(runs, list, "SARIF runs is not a list")
    testcase.assertEqual(len(runs), 1, "SARIF must have exactly one run")
    run = runs[0]
    driver = run["tool"]["driver"]
    testcase.assertEqual(driver.get("name"), "Loophole",
                         "SARIF driver name is not Loophole")
    version = driver.get("version")
    testcase.assertIsInstance(version, str, "SARIF driver version is not a string")
    testcase.assertTrue(version.strip(), "SARIF driver version is empty")
    rules = driver.get("rules")
    testcase.assertIsInstance(rules, list, "SARIF driver rules is not a list")
    testcase.assertTrue(rules, "SARIF driver rules is empty")
    rule_ids = [r["id"] for r in rules]
    testcase.assertEqual(len(rule_ids), len(set(rule_ids)),
                         "SARIF driver rule IDs are not unique")
    rule_by_id = {r["id"]: r for r in rules}
    results = run.get("results")
    testcase.assertIsInstance(results, list, "SARIF results is not a list")
    testcase.assertTrue(results, "SARIF scan produced no results")
    fired = {r["ruleId"] for r in results}
    testcase.assertTrue(
        fired <= set(rule_ids),
        "a result references a rule missing from driver rules: "
        f"{sorted(fired - set(rule_ids))}")
    # every rule that fired carries full metadata on its driver entry
    for rid in sorted(fired):
        entry = rule_by_id[rid]
        for key in ("shortDescription", "fullDescription",
                    "help", "helpUri", "defaultConfiguration"):
            testcase.assertIn(key, entry,
                              f"firing rule {rid}: missing {key}")
            if key in ("shortDescription", "fullDescription", "help"):
                testcase.assertTrue(entry[key]["text"].strip(),
                                    f"firing rule {rid}: empty {key}")
    # per-result checks, with regions bounded by the scanned files
    file_lines = {}
    for result in results:
        testcase.assertIn(result.get("level"), SARIF_LEVELS,
                          f"{result.get('ruleId')}: invalid SARIF level "
                          f"{result.get('level')!r}")
        message = result.get("message", {}).get("text", "")
        testcase.assertIsInstance(message, str,
                                  f"{result.get('ruleId')}: message is not text")
        testcase.assertTrue(message.strip(),
                            f"{result.get('ruleId')}: empty result message")
        locations = result.get("locations")
        testcase.assertIsInstance(locations, list,
                                  f"{result.get('ruleId')}: locations is not a list")
        testcase.assertTrue(locations,
                            f"{result.get('ruleId')}: result has no locations")
        for loc in locations:
            phys = loc["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            testcase.assertTrue(uri, "SARIF location has an empty uri")
            if uri not in file_lines:
                with open(uri, encoding="utf-8", errors="replace") as fh:
                    file_lines[uri] = fh.read().splitlines()
            lines = file_lines[uri]
            region = phys["region"]
            start_line = region.get("startLine")
            testcase.assertIsInstance(start_line, int,
                                      f"{uri}: startLine is not an integer")
            testcase.assertGreaterEqual(start_line, 1,
                                        f"{uri}: startLine {start_line} < 1")
            testcase.assertLessEqual(
                start_line, len(lines),
                f"{uri}: startLine {start_line} is past end of file "
                f"({len(lines)} lines)")
            if "startColumn" in region:
                column = region["startColumn"]
                testcase.assertIsInstance(column, int,
                                          f"{uri}: startColumn is not an integer")
                testcase.assertGreaterEqual(column, 1,
                                            f"{uri}: startColumn {column} < 1")
                testcase.assertLessEqual(
                    column, len(lines[start_line - 1]) + 1,
                    f"{uri}:{start_line}: startColumn {column} is past "
                    f"end of line")
            if "endLine" in region:
                testcase.assertGreaterEqual(region["endLine"], start_line,
                                            f"{uri}: endLine < startLine")
                testcase.assertLessEqual(region["endLine"], len(lines),
                                         f"{uri}: endLine is past end of file")
            snippet = region.get("snippet", {}).get("text")
            if snippet is not None:
                testcase.assertTrue(snippet.strip(),
                                    f"{uri}:{start_line}: empty snippet")
                testcase.assertEqual(
                    snippet.strip(), lines[start_line - 1].strip(),
                    f"{uri}:{start_line}: snippet does not match the "
                    f"source line")
    return fired


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
    "ts_vuln.mts": {"SQLI001", "SSRF001", "PATH001", "PATH002", "HDR001"},
    "ts_vuln.cts": {"SQLI001", "SSRF001", "PATH001", "PATH002", "HDR001"},
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

# Same rules must fire for the alternate extensions as for their .php counterpart.
EXPECTED["php_vuln.phtml"] = EXPECTED["php_vuln.php"]

CLEAN = ["js_clean.js", "ts_clean.ts", "ts_clean.mts", "php_clean.phtml", "py_clean.py", "go_clean.go",
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
        code, sarif = scan_sarif(os.path.join(FIX, "py_vuln.py"))
        self.assertEqual(code, 1)
        self.assertEqual(sarif["version"], "2.1.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        rules = driver["rules"]
        results = sarif["runs"][0]["results"]
        self.assertTrue(results, "SARIF has no results")
        self.assertTrue(all("ruleId" in r for r in results))
        # every rule carries full metadata, not just the ones that fired
        self.assertEqual(len(rules), 62, "SARIF should list all 62 rules")
        self.assertEqual(len({r["id"] for r in rules}), 62,
                         "SARIF rule IDs must be unique")
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                for key in ("shortDescription", "fullDescription",
                            "help", "helpUri", "defaultConfiguration"):
                    self.assertIn(key, rule,
                                  f"{rule['id']}: missing {key}")
                self.assertTrue(
                    rule["shortDescription"]["text"].strip(),
                    f"{rule['id']}: empty shortDescription")
                self.assertTrue(
                    rule["fullDescription"]["text"].strip(),
                    f"{rule['id']}: empty fullDescription")
                self.assertTrue(rule["help"]["text"].strip(),
                                f"{rule['id']}: empty help")
                self.assertEqual(
                    rule["helpUri"],
                    "https://github.com/rootsiemen/loophole#rule-"
                    + rule["id"].lower())
                self.assertIn(rule["defaultConfiguration"]["level"],
                              ("error", "warning"))
                self.assertIn(rule["properties"]["severity"],
                              ("critical", "high", "medium"))
        rule_ids = {r["id"] for r in rules}
        self.assertTrue(all(r["ruleId"] in rule_ids for r in results),
                        "a result references a rule missing from rules")

    def test_annotations_output(self):
        """Issue #27: --format annotations emits one workflow command
        per finding — ::error for critical/high, ::warning for medium —
        with workflow-command escaping, and exit code unchanged."""
        code, lines = scan_annotations(os.path.join(FIX, "py_vuln.py"))
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 35)
        errors = [l for l in lines if l.startswith("::error ")]
        warnings = [l for l in lines if l.startswith("::warning ")]
        self.assertEqual(len(errors), 25)
        self.assertEqual(len(warnings), 10)
        for line in lines:
            self.assertRegex(
                line,
                r"^::(error|warning) file=[^,]+,line=\d+,title=[A-Z0-9]+::.+",
                f"malformed annotation line: {line!r}")
        # exact line for a known fixture finding, including % escaping
        fixture = os.path.join(FIX, "py_vuln.py")
        self.assertIn(
            f"::error file={fixture},line=20,title=SQLI002::"
            "SQL injection via string formatting (Python) — "
            "cursor.execute(\"SELECT * FROM orders WHERE id = %25s\" %25 oid)"
            "  # SQLI002 %25 format",
            lines)
        # medium findings become ::warning, e.g. DBG001
        self.assertIn(
            f"::warning file={fixture},line=73,title=DBG001::"
            "Debug mode enabled — app.run(debug=True)  # DBG001",
            lines)
        # no unescaped % may survive: every % starts %25, %0D or %0A
        for line in lines:
            self.assertIsNone(
                re.search(r"%(?!25|0D|0A)", line),
                f"unescaped % in annotation line: {line!r}")
        # annotations replace the human report, not duplicate it
        self.assertFalse(any("Loophole found" in l for l in lines))

    def test_annotations_severity_filter(self):
        """Issue #27: --severity filters annotations like the human
        report, and the exit code still reflects critical/high."""
        code, lines = scan_annotations(os.path.join(FIX, "py_vuln.py"),
                                       "--severity", "high")
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 25)
        self.assertFalse(any(l.startswith("::warning ") for l in lines))

    def test_annotations_flag_alias(self):
        """Issue #27: --annotations is shorthand for --format annotations."""
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan",
             os.path.join(FIX, "py_vuln.py"),
             "--annotations", "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        _code, lines = scan_annotations(os.path.join(FIX, "py_vuln.py"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout.splitlines(), lines)

    def test_annotation_escaping(self):
        """Issue #27: workflow-command escaping escapes % first, so the
        % introduced by later steps is not double-escaped."""
        sys.path.insert(0, ROOT)
        import loophole
        self.assertEqual(
            loophole._escape_workflow_data("100% sure\r\nnext"),
            "100%25 sure%0D%0Anext")
        self.assertEqual(
            loophole._escape_workflow_property("a:b,c%d"),
            "a%3Ab%2Cc%25d")
        self.assertEqual(
            loophole._escape_workflow_property("%3A"), "%253A")
        finding = loophole.Finding(
            "SEC002", "high", "Hardcoded password", "we,ird:path.py", 3,
            "x = 100% ok", "why", "fix")
        self.assertEqual(
            loophole.annotation_line(finding),
            "::error file=we%2Cird%3Apath.py,line=3,title=SEC002::"
            "Hardcoded password — x = 100%25 ok")

    def test_sarif_structure_validation(self):
        """Issue #50: write_sarif output is structurally valid SARIF
        2.1.0 — driver metadata, unique rules covering every firing
        rule, valid levels and messages, and regions inside the scanned
        files' bounds — checked over a multi-language fixture scan."""
        fixtures = ["py_vuln.py", "js_vuln.js", "ts_vuln.ts",
                    "go_vuln.go", "php_vuln.php"]
        all_fired = set()
        for name in fixtures:
            with self.subTest(fixture=name):
                code, sarif = scan_sarif(os.path.join(FIX, name))
                self.assertEqual(code, 1,
                                 f"{name}: SARIF scan should exit 1")
                all_fired |= validate_sarif(sarif, self)
        families = {rid.rstrip("0123456789") for rid in all_fired}
        self.assertGreaterEqual(
            len(all_fired), 40,
            "multi-language SARIF scan fired too few rules: "
            f"{sorted(all_fired)}")
        self.assertGreaterEqual(
            len(families), 10,
            "multi-language SARIF scan covered too few rule families: "
            f"{sorted(families)}")

    def test_sarif_structure_validation_rejects_broken(self):
        """Issue #50: the structural validator is load-bearing — it must
        reject a SARIF document with a required field removed."""
        _code, sarif = scan_sarif(os.path.join(FIX, "py_vuln.py"))
        fired = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        first_fired = sorted(fired)[0]

        bad_docs = []

        doc = copy.deepcopy(sarif)
        doc.pop("$schema")
        bad_docs.append(("missing $schema", doc))

        doc = copy.deepcopy(sarif)
        doc["runs"][0]["results"][0]["message"] = {"text": ""}
        bad_docs.append(("empty result message", doc))

        doc = copy.deepcopy(sarif)
        doc["runs"][0]["results"][0]["level"] = "fatal"
        bad_docs.append(("invalid result level", doc))

        doc = copy.deepcopy(sarif)
        doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["region"]["startLine"] = 99999
        bad_docs.append(("startLine past end of file", doc))

        doc = copy.deepcopy(sarif)
        doc["runs"][0]["tool"]["driver"]["rules"] = [
            r for r in doc["runs"][0]["tool"]["driver"]["rules"]
            if r["id"] != first_fired]
        bad_docs.append(("driver rules missing a firing rule", doc))

        doc = copy.deepcopy(sarif)
        doc["runs"][0]["tool"]["driver"]["rules"].append(
            copy.deepcopy(doc["runs"][0]["tool"]["driver"]["rules"][0]))
        bad_docs.append(("duplicate rule id in driver rules", doc))

        for label, doc in bad_docs:
            with self.subTest(case=label):
                with self.assertRaises(AssertionError):
                    validate_sarif(doc, self)

    def test_sarif_zero_findings_full_rules(self):
        """A clean scan (0 results) still lists all 62 rules with full
        descriptions and help links (issue #7)."""
        code, sarif = scan_sarif(os.path.join(FIX, "py_clean.py"))
        self.assertEqual(code, 0)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(len(rules), 62)
        self.assertTrue(all(
            r.get("fullDescription", {}).get("text", "").strip()
            and r.get("help", {}).get("text", "").strip()
            and r.get("helpUri", "").startswith(
                "https://github.com/rootsiemen/loophole#rule-")
            for r in rules),
            "0-finding SARIF must still carry full rule metadata")

    def test_sarif_help_uris_match_readme(self):
        """Every SARIF helpUri fragment has a matching named anchor in
        the README rules table, so the links actually land on the rule."""
        _code, sarif = scan_sarif(os.path.join(FIX, "py_clean.py"))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        with open(os.path.join(ROOT, "README.md")) as fh:
            readme = fh.read()
        anchors = set(re.findall(r'<a name="(rule-[a-z0-9]+)">', readme))
        missing = [r["id"] for r in rules
                   if "rule-" + r["id"].lower() not in anchors]
        self.assertFalse(missing,
                         f"README has no anchor for: {missing}")

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

    def test_dedupe_identical_findings(self):
        """Issue #55: a rule double-emitting the same finding on one
        line must be reported once across text, JSON and SARIF outputs,
        while genuinely different messages from the same rule on the
        same line stay separate."""
        sys.path.insert(0, ROOT)
        import loophole
        # --- unit level: the dedupe helper itself ---------------------
        def mk(**kw):
            return loophole.Finding(
                kw.get("rule_id", "SEC001"), kw.get("severity", "high"),
                kw.get("title", "Hardcoded API key / token / secret"),
                kw.get("path", "app.py"), kw.get("line", 3),
                kw.get("snippet", 'API_KEY = "sk-live-" + "abcdef1234567890"'),
                kw.get("why", "why"), kw.get("fix", "fix"),
                kw.get("taint"))
        dup = mk()
        deduped = loophole._dedupe_findings([
            dup,
            mk(rule_id="SEC002"),            # different rule: kept
            mk(),                             # exact duplicate: dropped
            mk(line=4),                       # different line: kept
            mk(title="Different title"),      # different message: kept
            mk(taint="req.query.q -> query"),  # different taint: kept
        ])
        self.assertEqual(len(deduped), 5,
                         f"dedupe collapsed the wrong findings: "
                         f"{[(f.rule_id, f.line, f.title, f.taint) for f in deduped]}")
        self.assertIs(deduped[0], dup, "first occurrence must be kept")
        # --- integration: scan_path collapses a double-emit ----------
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "vuln.py")
            with open(target, "w") as fh:
                # Built at runtime so this test file itself carries no
                # literal secret for the scanner to flag.
                fh.write('API_KEY = "' + "sk-live-" + "abcdef1234567890"
                         + '"\n')
            baseline, _ = loophole.scan_path(tmp, [])
            self.assertTrue(
                any(f.rule_id == "SEC001" for f in baseline),
                "fixture did not trigger SEC001 as expected")
            orig_scan_file = loophole.scan_file

            def double_emit(path, config=None):
                # Simulate a rule double-emitting the same finding.
                return orig_scan_file(path, config) * 2

            loophole.scan_file = double_emit
            try:
                doubled, _ = loophole.scan_path(tmp, [])
            finally:
                loophole.scan_file = orig_scan_file
            self.assertEqual(
                [(f.rule_id, f.path, f.line) for f in doubled],
                [(f.rule_id, f.path, f.line) for f in baseline],
                "scan_path must report a double-emitted finding once")
            self.assertEqual(
                {loophole._baseline_key(f) for f in doubled},
                {loophole._baseline_key(f) for f in baseline},
                "baseline keys must be unchanged by dedupe")
            # --- every output format sees the finding once -----------
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                loophole.print_report(doubled, loophole.Color(False))
            self.assertEqual(buf.getvalue().count("SEC001"), 1,
                             "text report repeated the finding")
            json_path = os.path.join(tmp, "out.json")
            loophole.write_json(doubled, json_path)
            with open(json_path) as fh:
                data = json.load(fh)
            self.assertEqual(
                [f["rule_id"] for f in data["findings"]].count("SEC001"),
                1, "JSON report repeated the finding")
            sarif_path = os.path.join(tmp, "out.sarif")
            loophole.write_sarif(doubled, sarif_path)
            with open(sarif_path) as fh:
                sarif = json.load(fh)
            results = sarif["runs"][0]["results"]
            self.assertEqual(
                [r["ruleId"] for r in results].count("SEC001"), 1,
                "SARIF report repeated the finding")

    def test_deser001_php_taint(self):
        """DESER001 (PHP): unserialize() is high + tainted on user input,
        medium on dynamic data of unknown origin, and silent on string
        literals, allowed_classes and json_decode (issue #10)."""
        sys.path.insert(0, ROOT)
        import loophole
        src = (
            "<?php\n"
            "$a = unserialize($_COOKIE['prefs']);\n"
            "$prefs = $_POST['prefs'];\n"
            "$b = unserialize($prefs);\n"
            "$c = unserialize($stored);\n"
            "$d = unserialize('a:1:{i:0;s:3:\"foo\";}');\n"
            "$e = unserialize($x, ['allowed_classes' => false]);\n"
            "$f = json_decode($_GET['data'], true);\n"
            "$g = unserialize(file_get_contents('php://input'));\n"
        )
        with tempfile.NamedTemporaryFile(
                suffix=".php", mode="w", delete=False) as tmp:
            tmp.write(src)
            path = tmp.name
        try:
            findings = [f for f in loophole.scan_file(path)
                        if f.rule_id == "DESER001"]
            by_line = {f.line: f for f in findings}
            for ln in (2, 4, 9):
                self.assertIn(ln, by_line,
                              f"line {ln}: tainted unserialize() not "
                              "flagged")
                self.assertEqual(by_line[ln].severity, "high",
                                 f"line {ln}: tainted unserialize() "
                                 "should be high")
                self.assertTrue(by_line[ln].taint,
                                f"line {ln}: finding should carry a "
                                "taint flow note")
                self.assertIn("unserialize", by_line[ln].taint)
            # The taint note must name the real source and variable chain,
            # not just the sink — otherwise broken flow reporting passes.
            self.assertIn("$_COOKIE", by_line[2].taint,
                          "line 2: taint note should name the $_COOKIE source")
            self.assertIn("$prefs", by_line[4].taint,
                          "line 4: taint note should name the $prefs variable")
            self.assertIn("$_POST", by_line[4].taint,
                          "line 4: taint note should name the $_POST source")
            self.assertIn("php://input", by_line[9].taint,
                          "line 9: taint note should name the php://input source")
            self.assertIn(5, by_line,
                          "line 5: dynamic unserialize() not flagged")
            self.assertEqual(by_line[5].severity, "medium",
                             "line 5: untainted dynamic data should be "
                             "medium, not high")
            self.assertFalse(by_line[5].taint,
                             "line 5: no taint flow should be recorded")
            for ln in (6, 7, 8):
                self.assertNotIn(ln, by_line,
                                 f"line {ln}: safe counterpart flagged")
        finally:
            os.unlink(path)

    def test_deser001_php_review_fixes(self):
        """DESER001 (PHP): review fixes on PR #56 — multiline calls,
        allowed_classes values, copied/reassigned taint, taint confined
        to the payload argument, comment-only sources, and literal
        payloads with an options argument."""
        sys.path.insert(0, ROOT)
        import loophole
        src = (
            "<?php\n"                                              # 1
            "$a = $_GET['data'];\n"                               # 2
            "$b = $a;\n"                                          # 3
            "$c = unserialize($b);\n"                             # 4 high (copy)
            "$d = unserialize(\n"                                 # 5 high (multiline)
            "    $_COOKIE['prefs']\n"                             # 6
            ");\n"                                                 # 7
            "$e = unserialize('a:0:{}', ['allowed_classes' => ['A']]);\n"  # 8 silent
            "$f = unserialize($x, ['allowed_classes' => true]);\n"  # 9 medium
            "$g = unserialize($y); // allowed_classes => false\n"  # 10 medium
            "$h = $clean; // copied from $_GET\n"                 # 11
            "$i = unserialize($h);\n"                            # 12 medium
            "$j = $_POST['x'];\n"                                # 13
            "$j = 'safe';\n"                                     # 14
            "$k = unserialize($j);\n"                            # 15 medium
            "$l = unserialize($m);\n"                            # 16 medium
            "$m = $_GET['x'];\n"                                 # 17
            "$n = 'a:0:{}';\n"                                   # 18
            "$o = unserialize($n, $_GET['opts']);\n"             # 19 medium
            "$p = unserialize($u); $q = unserialize($_GET['z']);\n"  # 20 medium+high
        )
        with tempfile.NamedTemporaryFile(
                suffix=".php", mode="w", delete=False) as tmp:
            tmp.write(src)
            path = tmp.name
        try:
            findings = [f for f in loophole.scan_file(path)
                        if f.rule_id == "DESER001"]
            by_line = {f.line: f for f in findings}
            self.assertEqual(by_line[4].severity, "high",
                             "line 4: copied taint should stay high")
            self.assertIn("$b", by_line[4].taint)
            self.assertIn("$_GET", by_line[4].taint)
            self.assertEqual(by_line[5].severity, "high",
                             "line 5: multiline tainted call should be high")
            self.assertIn("$_COOKIE", by_line[5].taint)
            self.assertNotIn(8, by_line,
                             "line 8: literal payload with options flagged")
            for ln in (9, 10, 12, 15, 16, 19):
                self.assertIn(ln, by_line,
                              f"line {ln}: unserialize() not flagged")
                self.assertEqual(by_line[ln].severity, "medium",
                                 f"line {ln}: should be medium, not high")
                self.assertFalse(by_line[ln].taint,
                                 f"line {ln}: no taint flow should be recorded")
            line20 = [f for f in findings if f.line == 20]
            self.assertEqual(len(line20), 2,
                             "line 20: both calls on the line should be flagged")
            self.assertEqual({f.severity for f in line20},
                             {"medium", "high"},
                             "line 20: second call (tainted) should be high")
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

    def test_config_parser_edge_cases(self):
        """Issue #51: a broken .loophole.json warns on stderr and is
        ignored — the scan still completes with the same findings and
        no traceback. Covers malformed JSON, a JSON array, wrong-type
        exclude / disable / severity values, a severity override for
        an unknown rule id, and --config pointing at a directory."""
        vuln = ('API_KEY = "sk-live-abcdef1234567890"\n'
                'DB_PASSWORD = "hunter2hunter2"\n')  # loophole: skip=SEC002
        cases = [
            ("malformed JSON", "{not json", "cannot read config"),
            ("JSON array", '["SEC001"]', "not a JSON object"),
            ("exclude as a string",
             json.dumps({"exclude": "skipme.py"}), "exclude"),
            ("disable as a string",
             json.dumps({"disable": "SEC002"}), "disable"),
            ("severity for an unknown rule",
             json.dumps({"severity": {"NOPE999": "medium"}}), "NOPE999"),
            ("severity not an object",
             json.dumps({"severity": "high"}), "severity"),
        ]
        for label, content, needle in cases:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as d:
                    with open(os.path.join(d, "app.py"), "w") as fh:
                        fh.write(vuln)
                    with open(os.path.join(d, "skipme.py"), "w") as fh:
                        fh.write(vuln)
                    _, base = scan(d)
                    base_keys = sorted(
                        (f["rule_id"], os.path.basename(f["path"]),
                         f["line"], f["severity"]) for f in base)
                    with open(os.path.join(d, ".loophole.json"),
                              "w") as fh:
                        fh.write(content)
                    proc, data = run_scan_full(d)
                    self.assertIsNotNone(
                        data, "broken config stopped the JSON report")
                    self.assertNotIn("Traceback", proc.stderr,
                                     f"{label}: scan crashed")
                    self.assertIn("warning", proc.stderr,
                                  f"{label}: broken config did not warn")
                    self.assertIn(needle, proc.stderr,
                                  f"{label}: warning did not name the "
                                  f"problem ({needle!r})")
                    got_keys = sorted(
                        (f["rule_id"], os.path.basename(f["path"]),
                         f["line"], f["severity"])
                        for f in data["findings"])
                    self.assertEqual(
                        got_keys, base_keys,
                        f"{label}: findings changed under broken config")
                    if label == "exclude as a string":
                        self.assertTrue(
                            any(f["rule_id"] == "SEC001" and
                                f["path"].endswith("skipme.py")
                                for f in data["findings"]),
                            "string exclude must not exclude anything")
                    if label == "disable as a string":
                        self.assertIn(
                            "SEC002", rule_ids(data["findings"]),
                            "string disable must not disable anything")
                    if label == "severity for an unknown rule":
                        sec1 = [f for f in data["findings"]
                                if f["rule_id"] == "SEC001"]
                        base_sec1 = [f for f in base
                                     if f["rule_id"] == "SEC001"]
                        self.assertEqual(
                            [f["severity"] for f in sec1],
                            [f["severity"] for f in base_sec1],
                            "unknown-rule severity must not change "
                            "any finding")

        with self.subTest(case="--config is a directory"):
            with tempfile.TemporaryDirectory() as d:
                with open(os.path.join(d, "app.py"), "w") as fh:
                    fh.write(vuln)
                _, base = scan(d)
                base_keys = sorted(
                    (f["rule_id"], os.path.basename(f["path"]),
                     f["line"], f["severity"]) for f in base)
                cfgdir = os.path.join(d, "cfgdir")
                os.mkdir(cfgdir)
                proc, data = run_scan_full(d, "--config", cfgdir)
                self.assertIsNotNone(
                    data, "--config directory stopped the JSON report")
                self.assertNotIn("Traceback", proc.stderr,
                                 "--config directory crashed the scan")
                self.assertIn("warning", proc.stderr,
                              "--config directory did not warn")
                self.assertIn("cannot read config", proc.stderr)
                got_keys = sorted(
                    (f["rule_id"], os.path.basename(f["path"]),
                     f["line"], f["severity"])
                    for f in data["findings"])
                self.assertEqual(got_keys, base_keys,
                                 "--config directory changed findings")

    def test_loopholeignore_edge_cases(self):
        """Issue #51: CRLF line endings, blank lines and '#' comments
        interleaved with patterns, and a pattern naming a file that
        does not exist must never crash a scan — ignored files stay
        skipped and the rest scan as normal."""
        vuln = 'API_KEY = "sk-live-abcdef1234567890"\n'
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, "skipme.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, "app.min.js"), "w") as fh:
                fh.write(vuln)
            os.mkdir(os.path.join(d, "generated"))
            with open(os.path.join(d, "generated", "gen.py"),
                      "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, ".loopholeignore"), "wb") as fh:
                fh.write(b"# ignore generated output\r\n"
                         b"\r\n"
                         b"skipme.py\r\n"
                         b"# vendored files\r\n"
                         b"\r\n"
                         b"*.min.js\r\n"
                         b"generated/\r\n")
            proc, data = run_scan_full(d)
            self.assertIsNotNone(
                data, "CRLF .loopholeignore stopped the JSON report")
            self.assertNotIn("Traceback", proc.stderr,
                             "CRLF .loopholeignore crashed the scan")
            self.assertEqual(proc.returncode, 1)
            paths = {f["path"] for f in data["findings"]}
            self.assertTrue(
                any(p.endswith("app.py") for p in paths),
                "app.py findings missing under CRLF .loopholeignore")
            self.assertFalse(
                any("skipme.py" in p or "app.min.js" in p or
                    "generated" in p for p in paths),
                f"ignored files still scanned: {sorted(paths)}")
            self.assertEqual(data["summary"]["ignored"], 3,
                             "JSON summary should count the 3 ignored "
                             "files under a CRLF ignore file")

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, "skipme.py"), "w") as fh:
                fh.write(vuln)
            with open(os.path.join(d, ".loopholeignore"), "w") as fh:
                fh.write("skipme.py\nno-such-file.py\n")
            proc, data = run_scan_full(d)
            self.assertIsNotNone(
                data, "nonexistent ignore pattern stopped the report")
            self.assertNotIn("Traceback", proc.stderr,
                             "nonexistent ignore pattern crashed the "
                             "scan")
            paths = {f["path"] for f in data["findings"]}
            self.assertTrue(
                any(p.endswith("app.py") for p in paths),
                "app.py findings missing with a nonexistent pattern")
            self.assertFalse(
                any("skipme.py" in p for p in paths),
                "skipme.py was not ignored")
            self.assertEqual(data["summary"]["ignored"], 1,
                             "a pattern naming no file must not inflate "
                             "the ignored count")

    def test_baseline_edge_cases(self):
        """Issue #51: a baseline whose entries miss keys exits 2 with
        a clear 'cannot read baseline' message and no traceback,
        while extra keys in entries (or at the top level) are ignored
        and suppression still works."""
        target = os.path.join(FIX, "py_vuln.py")
        missing_key_cases = [
            ("entry missing path and snippet",
             [{"rule_id": "SEC001"}]),
            ("entry missing rule_id",
             [{"path": "py_vuln.py", "snippet": "x"}]),
        ]
        for label, entries in missing_key_cases:
            with self.subTest(case=label):
                with tempfile.NamedTemporaryFile(
                        suffix=".json", delete=False, mode="w") as tmp:
                    json.dump({"tool": "loophole", "version": "1.2.0",
                               "entries": entries}, tmp)
                    base = tmp.name
                try:
                    proc = subprocess.run(
                        [sys.executable, SCANNER, "scan", target,
                         "--baseline", base, "--no-color"],
                        capture_output=True, text=True, cwd=ROOT)
                    self.assertEqual(proc.returncode, 2,
                                     f"{label}: bad baseline did not "
                                     f"exit 2")
                    self.assertIn("cannot read baseline", proc.stderr,
                                  f"{label}: no clear baseline error")
                    self.assertNotIn("Traceback", proc.stderr,
                                     f"{label}: bad baseline crashed "
                                     f"with a traceback")
                finally:
                    os.unlink(base)

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
            for entry in data["entries"]:
                entry["extra_key"] = "ignored"
            data["extra_top_level"] = True
            with open(base, "w") as fh:
                json.dump(data, fh)
            code, findings = scan(target, "--baseline", base)
            self.assertEqual(findings, [],
                             "extra baseline keys broke suppression")
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

    def test_junit_report(self):
        with tempfile.NamedTemporaryFile(suffix=".xml",
                                         delete=False) as tmp:
            out = tmp.name
        try:
            target = os.path.join(FIX, "js_vuln.js")
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan", target,
                 "--junit", out, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 1)
            suite = ET.parse(out).getroot()
            self.assertEqual(suite.tag, "testsuite")
            cases = suite.findall("testcase")
            _, findings = scan(target)
            self.assertEqual(len(cases), len(findings),
                             "JUnit testcase count != JSON findings count")
            self.assertEqual(suite.get("tests"), str(len(findings)))
            self.assertEqual(suite.get("failures"), str(len(findings)))
            for case in cases:
                failure = case.find("failure")
                self.assertIsNotNone(failure, "testcase has no <failure>")
                self.assertEqual(case.get("classname"),
                                 failure.get("type"))
                self.assertIn(case.get("classname"),
                              failure.get("message"),
                              "failure message must name the rule")
                self.assertIn("[", failure.get("message"),
                              "failure message must include the severity")
            # clean fixture: an empty suite
            with tempfile.NamedTemporaryFile(suffix=".xml",
                                             delete=False) as tmp2:
                clean_out = tmp2.name
            try:
                proc = subprocess.run(
                    [sys.executable, SCANNER, "scan",
                     os.path.join(FIX, "js_clean.js"),
                     "--junit", clean_out, "--no-color"],
                    capture_output=True, text=True, cwd=ROOT)
                self.assertEqual(proc.returncode, 0)
                clean_suite = ET.parse(clean_out).getroot()
                self.assertEqual(clean_suite.get("tests"), "0")
                self.assertEqual(clean_suite.get("failures"), "0")
                self.assertEqual(clean_suite.findall("testcase"), [])
            finally:
                os.unlink(clean_out)
        finally:
            os.unlink(out)

    def test_gitlab_output(self):
        """--gitlab emits a schema-15.x SAST report (issue #26): one
        vulnerability per finding, stable hashed ids, GitLab severity
        names, rule identifiers and file/start_line locations."""
        target = os.path.join(FIX, "py_vuln.py")
        code, report = scan_gitlab(target)
        self.assertEqual(code, 1)
        self.assertEqual(report["version"], "15.0.0")
        self.assertTrue(report["schema"].endswith(
            "sast-report-format.json"))
        scan_block = report["scan"]
        self.assertEqual(scan_block["type"], "sast")
        self.assertEqual(scan_block["status"], "success")
        self.assertEqual(scan_block["scanner"]["id"], "loophole")
        self.assertEqual(scan_block["scanner"]["name"], "Loophole")
        self.assertTrue(scan_block["scanner"]["version"])
        _, findings = scan(target)
        vulns = report["vulnerabilities"]
        self.assertEqual(len(vulns), len(findings),
                         "GitLab vulnerability count != JSON findings count")
        expected_sev = {"critical": "Critical", "high": "High",
                        "medium": "Medium"}
        by_key = {(f["rule_id"], f["path"], f["line"]): f
                  for f in findings}
        seen_ids = set()
        for vuln in vulns:
            with self.subTest(vuln=vuln.get("id")):
                for key in ("id", "category", "name", "message",
                            "severity", "scanner", "identifiers",
                            "location"):
                    self.assertIn(key, vuln, f"missing {key}")
                self.assertEqual(vuln["category"], "sast")
                self.assertIn(vuln["severity"],
                              ("Critical", "High", "Medium"))
                self.assertEqual(vuln["scanner"]["id"], "loophole")
                rule_id = vuln["identifiers"][0]["value"]
                self.assertEqual(
                    vuln["identifiers"][0]["type"], "loophole_rule")
                self.assertTrue(vuln["identifiers"][0]["url"].endswith(
                    "#rule-" + rule_id.lower()))
                loc = vuln["location"]
                f = by_key[(rule_id, loc["file"], loc["start_line"])]
                self.assertEqual(vuln["severity"],
                                 expected_sev[f["severity"]],
                                 "severity mapping is wrong")
                self.assertTrue(vuln["name"].strip())
                self.assertTrue(vuln["message"].strip())
                # id is the stable hash of rule|path|snippet
                key = "|".join((f["rule_id"], f["path"], f["snippet"]))
                self.assertEqual(
                    vuln["id"],
                    hashlib.sha256(key.encode("utf-8")).hexdigest())
                self.assertNotIn(vuln["id"], seen_ids,
                                 "vulnerability ids must be unique")
                seen_ids.add(vuln["id"])
        # ids are stable across scans
        _, report2 = scan_gitlab(target)
        self.assertEqual(
            {v["id"] for v in report2["vulnerabilities"]}, seen_ids,
            "vulnerability ids must be stable across scans")
        # clean fixture: an empty vulnerabilities list, scan block intact
        clean_code, clean_report = scan_gitlab(
            os.path.join(FIX, "py_clean.py"))
        self.assertEqual(clean_code, 0)
        self.assertEqual(clean_report["vulnerabilities"], [])
        self.assertEqual(clean_report["scan"]["type"], "sast")
        self.assertEqual(clean_report["scan"]["status"], "success")


class TestPrecommit(unittest.TestCase):
    """pre-commit hook (issue #53): the hooks file parses, the hook
    entry is executable, and the entry fails on vulnerable fixtures
    while passing clean ones. This is the local simulation of
    `pre-commit try-repo . loophole --files <fixture>`, since pre-commit
    itself is a dev-side tool and is not installed in CI."""

    HOOKS_FILE = os.path.join(ROOT, ".pre-commit-hooks.yaml")
    ENTRY = os.path.join(ROOT, "scripts", "loophole-pre-commit.sh")

    def test_hooks_yaml_parses(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed; cannot parse YAML")
        with open(self.HOOKS_FILE) as fh:
            data = yaml.safe_load(fh)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        hook = data[0]
        self.assertEqual(hook["id"], "loophole")
        self.assertEqual(hook["name"], "Loophole security scan")
        self.assertEqual(hook["language"], "script")
        self.assertEqual(hook["entry"], "scripts/loophole-pre-commit.sh")
        for tag in ("javascript", "jsx", "ts", "tsx", "python", "go",
                    "php"):
            self.assertIn(tag, hook["types_or"],
                          f"types_or is missing {tag}")

    def test_hooks_yaml_structure_without_yaml(self):
        """The hook definition is present even where PyYAML is missing."""
        with open(self.HOOKS_FILE) as fh:
            text = fh.read()
        for needle in ("id: loophole", "name: Loophole security scan",
                       "entry: scripts/loophole-pre-commit.sh",
                       "language: script", "types_or:"):
            self.assertIn(needle, text)

    def test_hook_entry_is_executable(self):
        self.assertTrue(os.path.isfile(self.ENTRY),
                        "hook entry script is missing")
        self.assertTrue(os.access(self.ENTRY, os.X_OK),
                        "hook entry must be executable")

    def _run_hook(self, *files):
        proc = subprocess.run([self.ENTRY] + list(files),
                              capture_output=True, text=True, cwd=ROOT)
        return proc

    def test_hook_fails_on_vulnerable_fixture(self):
        proc = self._run_hook(os.path.join(FIX, "py_vuln.py"))
        self.assertEqual(proc.returncode, 1,
                         "hook should fail on py_vuln.py:\n" + proc.stdout)

    def test_hook_passes_on_clean_fixture(self):
        proc = self._run_hook(os.path.join(FIX, "py_clean.py"))
        self.assertEqual(proc.returncode, 0,
                         "hook should pass on py_clean.py:\n" + proc.stdout)

    def test_hook_scans_each_staged_file(self):
        """Several staged files in one invocation: the hook scans each
        one instead of failing with an argparse error (the scanner takes
        a single path)."""
        proc = self._run_hook(os.path.join(FIX, "py_clean.py"),
                              os.path.join(FIX, "py_vuln.py"))
        self.assertEqual(proc.returncode, 1,
                         "hook should fail when any file is vulnerable")
        proc = self._run_hook(os.path.join(FIX, "py_clean.py"),
                              os.path.join(FIX, "js_clean.js"))
        self.assertEqual(proc.returncode, 0,
                         "hook should pass when every file is clean:\n"
                         + proc.stdout)


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


class TestShellCompletions(unittest.TestCase):
    """Shell completions stay in sync with the CLI (issue #52).

    Every long flag in `loophole scan --help` must appear in both
    completion files, so a new flag cannot land without completion
    support. `bash -n` guards the bash script's syntax.
    """

    COMPLETIONS = ("completions/loophole.bash", "completions/_loophole")

    def _scan_help_flags(self):
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--help"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0,
                         "loophole scan --help must exit 0")
        return sorted(set(re.findall(r"--[a-z][a-z-]*", proc.stdout)))

    def _completion_text(self, name):
        path = os.path.join(ROOT, name)
        self.assertTrue(os.path.exists(path), f"{name} is missing")
        with open(path) as fh:
            return fh.read()

    def test_completions_cover_all_scan_flags(self):
        flags = self._scan_help_flags()
        self.assertIn("--severity", flags)
        for name in self.COMPLETIONS:
            text = self._completion_text(name)
            self.assertIn("scan", text,
                          f"{name} does not complete the scan subcommand")
            missing = [f for f in flags if f not in text]
            self.assertFalse(
                missing, f"{name} is missing flags: {missing}")

    def test_completions_cover_severity_choices(self):
        for name in self.COMPLETIONS:
            text = self._completion_text(name)
            for choice in ("critical", "high", "medium"):
                self.assertIn(
                    choice, text,
                    f"{name} does not offer --severity choice {choice}")

    def test_bash_completion_syntax(self):
        proc = subprocess.run(
            ["bash", "-n",
             os.path.join(ROOT, "completions", "loophole.bash")],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"bash -n failed: {proc.stderr}")

    @unittest.skipUnless(shutil.which("zsh"), "zsh not installed")
    def test_zsh_completion_syntax(self):
        proc = subprocess.run(
            ["zsh", "-n", os.path.join(ROOT, "completions", "_loophole")],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"zsh -n failed: {proc.stderr}")


class TestVersionMetadata(unittest.TestCase):
    """The self-reported version must match the newest CHANGELOG release."""

    def test_version_matches_latest_changelog_release(self):
        sys.path.insert(0, ROOT)
        import loophole
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
        releases = re.findall(r"^## (\d+\.\d+\.\d+)\b", changelog,
                              re.MULTILINE)
        self.assertTrue(releases,
                        "CHANGELOG.md has no versioned release heading")
        latest = max(releases,
                     key=lambda v: tuple(int(p) for p in v.split(".")))
        self.assertEqual(
            loophole.VERSION, latest,
            f"VERSION is {loophole.VERSION} but the newest CHANGELOG "
            f"release is {latest}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

