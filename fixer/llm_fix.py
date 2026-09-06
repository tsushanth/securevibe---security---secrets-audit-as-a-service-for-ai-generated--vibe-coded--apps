"""Generates a fix for a single Finding.

If ANTHROPIC_API_KEY is set, asks Claude to rewrite the offending line range.
Otherwise (or if the API call fails), falls back to a deterministic template
fix per rule type, so the scan -> fix -> branch/commit loop always runs.
"""
import json
import os
import re
import urllib.error
import urllib.request

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-opus-5"
CONTEXT_LINES = 6


def get_line_range(total_lines, finding_line, context_lines=CONTEXT_LINES):
    """0-indexed, half-open [start, end) window around a 1-indexed finding line."""
    start = max(0, finding_line - 1 - context_lines)
    end = min(total_lines, finding_line + context_lines)
    return start, end


def generate_fix(target_dir, finding):
    """Returns (start, end, replacement_text, source) where source is
    'llm' or 'template', and lines[start:end] should be replaced with
    replacement_text.splitlines()."""
    filepath = os.path.join(target_dir, finding.file)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        original_lines = f.read().splitlines()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        start, end = get_line_range(len(original_lines), finding.line)
        try:
            replacement = _call_llm(api_key, finding, original_lines, start, end)
            if replacement:
                return start, end, replacement, "llm"
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            print(f"  (LLM fix generation failed: {exc}; using template fallback)")

    start, end, replacement = _template_fix(finding, original_lines)
    return start, end, replacement, "template"


def _call_llm(api_key, finding, lines, start, end):
    numbered_context = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
    prompt = (
        "You are an automated security-fix generator for a static analysis tool.\n"
        f"File: {finding.file}\n"
        f"Vulnerability ({finding.rule}): {finding.message}\n\n"
        f"Surrounding code, 1-indexed:\n{numbered_context}\n\n"
        f"Replace ONLY lines {start + 1}-{end} (inclusive) with a corrected "
        "version that fixes this specific issue while preserving all other "
        "behavior and code style. Reply with ONLY the replacement code for "
        "those lines -- no line numbers, no markdown code fences, no "
        "explanation."
    )
    body = json.dumps({
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    text = "".join(
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ).strip()

    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text)

    return text or None


def _to_env_name(identifier):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", identifier).upper()


def _template_hardcoded_secret(finding, lines):
    idx = finding.line - 1
    line = lines[idx]
    m = re.search(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]", line
    )
    if m:
        env_name = _to_env_name(m.group(1))
        fixed = re.sub(
            r"['\"]" + re.escape(m.group(2)) + r"['\"]",
            f"process.env.{env_name}",
            line,
        )
    else:
        fixed = f"// SECUREVIBE: move this secret to an environment variable\n{line}"
    return idx, idx + 1, fixed


def _template_missing_rls(finding, lines):
    idx = finding.line - 1
    m = re.search(r"Table '([a-zA-Z0-9_.]+)'", finding.message)
    table = m.group(1) if m else "your_table"

    end_idx = idx
    for i in range(idx, min(idx + 20, len(lines))):
        if lines[i].rstrip().endswith(");"):
            end_idx = i
            break

    replacement = lines[end_idx] + f"\nALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
    return end_idx, end_idx + 1, replacement


def _template_missing_auth(finding, lines):
    idx = finding.line - 1
    anchor_line = lines[idx]
    insertion = (
        "  const session = await getServerSession(req, res);\n"
        "  if (!session) {\n"
        "    return res.status(401).json({ error: 'Unauthorized' });\n"
        "  }"
    )
    return idx, idx + 1, anchor_line + "\n" + insertion


def _template_missing_rate_limit(finding, lines):
    idx = finding.line - 1
    anchor_line = lines[idx]
    insertion = (
        "  const allowed = await rateLimit(req);\n"
        "  if (!allowed) {\n"
        "    return res.status(429).json({ error: 'Too many requests' });\n"
        "  }"
    )
    return idx, idx + 1, anchor_line + "\n" + insertion


def _template_error_leakage(finding, lines):
    idx = finding.line - 1
    line = lines[idx]
    fixed = re.sub(r"\{\s*error\s*:\s*[^}]*\}", "{ error: 'Internal server error' }", line)
    if fixed == line:
        fixed = re.sub(r"res\.(json|send)\([^)]*\)", r"res.\1({ error: 'Internal server error' })", line)
    return idx, idx + 1, fixed


_TEMPLATE_FIXERS = {
    "hardcoded_secret": _template_hardcoded_secret,
    "missing_rls": _template_missing_rls,
    "missing_auth": _template_missing_auth,
    "missing_rate_limit": _template_missing_rate_limit,
    "error_leakage": _template_error_leakage,
}


def _template_fix(finding, lines):
    fixer = _TEMPLATE_FIXERS.get(finding.rule)
    if fixer is None:
        raise ValueError(f"No template fixer registered for rule: {finding.rule}")
    return fixer(finding, lines)
