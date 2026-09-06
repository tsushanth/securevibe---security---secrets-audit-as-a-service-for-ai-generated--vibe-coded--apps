"""Walks a target repo and dispatches each file to the applicable rules."""
import os

from scanner import rules

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}


def scan_repo(root):
    """Returns a list of scanner.rules.Finding, with sequential ids assigned."""
    findings = []
    next_id = 1

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, root)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except OSError:
                continue

            lines = content.splitlines()
            for finding in rules.apply_rules(rel_path, content, lines):
                finding.id = next_id
                findings.append(finding)
                next_id += 1

    return findings
