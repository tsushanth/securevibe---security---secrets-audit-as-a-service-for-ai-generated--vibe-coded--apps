import unittest

from scanner import rules


def _lines(content):
    return content.splitlines()


class TestHardcodedSecrets(unittest.TestCase):
    def test_true_positive(self):
        content = 'const apiKey = "sk-liveSECRETVALUE1234567890";\n'
        findings = rules.find_hardcoded_secrets("lib/config.js", content, _lines(content))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "hardcoded_secret")

    def test_true_negative(self):
        content = "const apiKey = process.env.API_KEY;\n"
        findings = rules.find_hardcoded_secrets("lib/config.js", content, _lines(content))
        self.assertEqual(findings, [])

    def test_committed_env_file(self):
        content = "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        findings = rules.find_hardcoded_secrets(".env", content, _lines(content))
        self.assertEqual(len(findings), 1)

    def test_env_example_is_ignored(self):
        content = "SUPABASE_SERVICE_ROLE_KEY=your-key-here\n"
        findings = rules.find_hardcoded_secrets(".env.example", content, _lines(content))
        self.assertEqual(findings, [])


class TestMissingRls(unittest.TestCase):
    def test_true_positive(self):
        content = "CREATE TABLE secrets (\n  id uuid PRIMARY KEY\n);\n"
        findings = rules.find_missing_rls("migrations/0001_init.sql", content, _lines(content))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "missing_rls")

    def test_true_negative(self):
        content = (
            "CREATE TABLE secrets (\n"
            "  id uuid PRIMARY KEY\n"
            ");\n"
            "ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n"
        )
        findings = rules.find_missing_rls("migrations/0001_init.sql", content, _lines(content))
        self.assertEqual(findings, [])


class TestMissingAuth(unittest.TestCase):
    def test_true_positive(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  res.status(200).json({ ok: true });\n"
            "}\n"
        )
        findings = rules.find_missing_auth("pages/api/foo.js", content, _lines(content))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "missing_auth")

    def test_true_negative(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  const session = await getServerSession(req, res);\n"
            "  if (!session) return res.status(401).end();\n"
            "  res.status(200).json({ ok: true });\n"
            "}\n"
        )
        findings = rules.find_missing_auth("pages/api/foo.js", content, _lines(content))
        self.assertEqual(findings, [])


class TestMissingRateLimit(unittest.TestCase):
    def test_true_positive(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  res.status(200).json({ ok: true });\n"
            "}\n"
        )
        findings = rules.find_missing_rate_limit("pages/api/foo.js", content, _lines(content))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "missing_rate_limit")

    def test_true_negative(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  await rateLimit(req);\n"
            "  res.status(200).json({ ok: true });\n"
            "}\n"
        )
        findings = rules.find_missing_rate_limit("pages/api/foo.js", content, _lines(content))
        self.assertEqual(findings, [])


class TestErrorLeakage(unittest.TestCase):
    def test_true_positive(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  try {\n"
            "    doStuff();\n"
            "  } catch (err) {\n"
            "    res.status(500).json({ error: err.message });\n"
            "  }\n"
            "}\n"
        )
        findings = rules.find_error_leakage("pages/api/foo.js", content, _lines(content))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "error_leakage")

    def test_true_negative(self):
        content = (
            "export default async function handler(req, res) {\n"
            "  try {\n"
            "    doStuff();\n"
            "  } catch (err) {\n"
            "    console.error(err);\n"
            "    res.status(500).json({ error: 'Internal server error' });\n"
            "  }\n"
            "}\n"
        )
        findings = rules.find_error_leakage("pages/api/foo.js", content, _lines(content))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
