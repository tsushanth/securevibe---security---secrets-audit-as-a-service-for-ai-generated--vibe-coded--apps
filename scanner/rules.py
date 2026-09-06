"""The 5 detection rules for vibe-coded-app failure patterns.

Each rule is a plain function: (rel_path, content, lines) -> list[Finding].
Detection is regex/heuristic based on purpose (see plan.md) -- good enough
to prove the scan -> fix loop, not a substitute for real AST-level analysis.
"""
import os
import re
from dataclasses import dataclass

CODE_EXTENSIONS = ('.js', '.jsx', '.ts', '.tsx')
ENV_FILENAMES_TO_SKIP = {'.env.example', '.env.sample', '.env.template'}

PUBLIC_ENV_PREFIXES = ('NEXT_PUBLIC_', 'VITE_', 'REACT_APP_')
SECRET_KEY_HINT = re.compile(r'(?i)(KEY|SECRET|TOKEN|PASSWORD)')

# name=value assignment inside a .env file
ENV_ASSIGNMENT_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')

# an identifier assigned a quoted literal directly in source, e.g.
# const apiKey = "sk-abc123..."  or  SUPABASE_SERVICE_ROLE_KEY: "eyJ..."
# -- filtered down to secret-looking identifiers via SECRET_KEY_HINT below.
INLINE_SECRET_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\'"]([A-Za-z0-9\-_.]{16,})[\'"]'
)

CREATE_TABLE_RE = re.compile(r'(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?["`]?([a-zA-Z0-9_.]+)["`]?')
ENABLE_RLS_RE = re.compile(r'(?i)alter\s+table\s+["`]?([a-zA-Z0-9_.]+)["`]?\s+enable\s+row\s+level\s+security')

AUTH_HINT_RE = re.compile(
    r'(?i)(getServerSession|requireAuth|verifyToken|checkAuth|isAuthenticated|'
    r'supabase\.auth\.getUser|jwt\.verify|req\.headers\.authorization|session\.user|Bearer\s)'
)

RATE_LIMIT_HINT_RE = re.compile(
    r'(?i)(rate[_-]?limit|ratelimit|express-rate-limit|limiter|upstash|slidingwindow)'
)

CATCH_VAR_RE = re.compile(r'catch\s*\(\s*(\w+)\s*\)')
RESPONSE_CALL_RE = re.compile(r'(?i)res\s*\.\s*(?:status\([^)]*\)\s*\.\s*)?(?:json|send)\s*\(')
HANDLER_ANCHOR_RE = re.compile(r'(?i)(export\s+default|export\s+(?:async\s+)?function|module\.exports)')


@dataclass
class Finding:
    id: int
    rule: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str


def _first_line_matching(lines, pattern):
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            return i
    return 1


def _is_api_route(rel_path):
    normalized = rel_path.replace(os.sep, '/')
    return '/api/' in normalized or normalized.startswith('api/')


def find_hardcoded_secrets(rel_path, content, lines):
    """Pattern 1: hardcoded secrets, incl. client-exposed env vars and committed .env files."""
    findings = []
    basename = os.path.basename(rel_path)

    if basename == '.env' or basename.startswith('.env.'):
        if basename in ENV_FILENAMES_TO_SKIP:
            return findings
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            m = ENV_ASSIGNMENT_RE.match(stripped)
            if not m:
                continue
            key = m.group(1)
            if not SECRET_KEY_HINT.search(key):
                continue
            if key.startswith(PUBLIC_ENV_PREFIXES):
                message = (
                    f"Secret '{key}' is committed in {basename} and exposed to the "
                    f"client bundle via a public env prefix"
                )
            else:
                message = f"Secret '{key}' is hardcoded in the committed {basename} file"
            findings.append(Finding(0, 'hardcoded_secret', 'critical', rel_path, i, message, stripped))
        return findings

    for i, line in enumerate(lines, start=1):
        m = INLINE_SECRET_RE.search(line)
        if m and SECRET_KEY_HINT.search(m.group(1)):
            findings.append(Finding(
                0, 'hardcoded_secret', 'critical', rel_path, i,
                f"Hardcoded secret literal assigned to '{m.group(1)}' in source",
                line.strip(),
            ))
    return findings


def find_missing_rls(rel_path, content, lines):
    """Pattern 2: Supabase/Postgres tables created without Row Level Security."""
    if not rel_path.endswith('.sql'):
        return []

    tables_created = {}
    for i, line in enumerate(lines, start=1):
        m = CREATE_TABLE_RE.search(line)
        if m:
            tables_created.setdefault(m.group(1).lower(), i)

    rls_enabled = set()
    for line in lines:
        m = ENABLE_RLS_RE.search(line)
        if m:
            rls_enabled.add(m.group(1).lower())

    findings = []
    for table, line_no in tables_created.items():
        if table not in rls_enabled:
            findings.append(Finding(
                0, 'missing_rls', 'critical', rel_path, line_no,
                f"Table '{table}' is created without Row Level Security enabled",
                lines[line_no - 1].strip(),
            ))
    return findings


def find_missing_auth(rel_path, content, lines):
    """Pattern 3: API route handler with no auth check."""
    if not (rel_path.endswith(CODE_EXTENSIONS) and _is_api_route(rel_path)):
        return []
    if AUTH_HINT_RE.search(content):
        return []
    line_no = _first_line_matching(lines, HANDLER_ANCHOR_RE)
    return [Finding(
        0, 'missing_auth', 'high', rel_path, line_no,
        "API route handler has no auth check",
        lines[line_no - 1].strip() if lines else '',
    )]


def find_missing_rate_limit(rel_path, content, lines):
    """Pattern 4: API route handler with no rate limiting."""
    if not (rel_path.endswith(CODE_EXTENSIONS) and _is_api_route(rel_path)):
        return []
    if RATE_LIMIT_HINT_RE.search(content):
        return []
    line_no = _first_line_matching(lines, HANDLER_ANCHOR_RE)
    return [Finding(
        0, 'missing_rate_limit', 'medium', rel_path, line_no,
        "API route handler has no rate limiting",
        lines[line_no - 1].strip() if lines else '',
    )]


def find_error_leakage(rel_path, content, lines):
    """Pattern 5: error handler leaks raw exception/stack trace to the client."""
    if not (rel_path.endswith(CODE_EXTENSIONS) and _is_api_route(rel_path)):
        return []

    catch_vars = set(CATCH_VAR_RE.findall(content))
    if not catch_vars:
        return []

    findings = []
    for i, line in enumerate(lines, start=1):
        if not RESPONSE_CALL_RE.search(line):
            continue
        for var in catch_vars:
            # bare var used as a value (not as a `varname: ...` object key) --
            # covers both `err.message` / `err.stack` and passing the raw error object
            leak_re = re.compile(r'\b' + re.escape(var) + r'\b(?!\s*:)')
            if leak_re.search(line):
                findings.append(Finding(
                    0, 'error_leakage', 'medium', rel_path, i,
                    f"Raw exception ('{var}') sent directly to the client response",
                    line.strip(),
                ))
                break
    return findings


ALL_RULES = (
    find_hardcoded_secrets,
    find_missing_rls,
    find_missing_auth,
    find_missing_rate_limit,
    find_error_leakage,
)


def apply_rules(rel_path, content, lines):
    findings = []
    for rule_fn in ALL_RULES:
        findings.extend(rule_fn(rel_path, content, lines))
    return findings
