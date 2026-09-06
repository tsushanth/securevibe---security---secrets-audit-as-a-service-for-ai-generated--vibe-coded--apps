import os
import unittest

from scanner.engine import scan_repo

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vibe-coded-demo-app")


class TestEngineOnFixture(unittest.TestCase):
    def test_finds_exactly_five_seeded_issues(self):
        findings = scan_repo(FIXTURE_DIR)
        self.assertEqual(
            len(findings), 5,
            f"expected exactly 5 findings, got {len(findings)}: {[(f.rule, f.file, f.line) for f in findings]}",
        )

    def test_one_finding_per_seeded_pattern_and_file(self):
        findings = scan_repo(FIXTURE_DIR)
        by_rule_and_file = {(f.rule, f.file) for f in findings}
        self.assertIn(("hardcoded_secret", os.path.join("lib", "db.js")), by_rule_and_file)
        self.assertIn(("missing_auth", os.path.join("pages", "api", "users.js")), by_rule_and_file)
        self.assertIn(("error_leakage", os.path.join("pages", "api", "users.js")), by_rule_and_file)
        self.assertIn(("missing_rate_limit", os.path.join("pages", "api", "admin.js")), by_rule_and_file)
        self.assertIn(
            ("missing_rls", os.path.join("supabase", "migrations", "0001_init.sql")),
            by_rule_and_file,
        )


if __name__ == "__main__":
    unittest.main()
