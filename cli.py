#!/usr/bin/env python3
"""SecureVibe CLI -- scan a repo for vibe-coding security failure patterns
and generate a verified, applied fix on a new git branch.

Usage:
    python3 cli.py scan <path-to-repo>
    python3 cli.py report
    python3 cli.py fix --finding-id <id>
"""
import argparse
import dataclasses
import json
import os
import sys

from scanner.engine import scan_repo
from scanner.rules import Finding
from fixer import apply_patch, llm_fix

DEFAULT_REPORT = "findings.json"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _print_table(findings):
    if not findings:
        print("No issues found.")
        return
    header = f"{'ID':<4} {'SEVERITY':<10} {'RULE':<20} LOCATION"
    print(header)
    print("-" * len(header))
    for f in sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id)):
        print(f"{f.id:<4} {f.severity:<10} {f.rule:<20} {f.file}:{f.line}")
        print(f"      {f.message}")
    print(f"\n{len(findings)} finding(s).")


def _write_report(path, target_dir, findings):
    data = {
        "target_dir": os.path.abspath(target_dir),
        "findings": [dataclasses.asdict(f) for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _load_report(path):
    if not os.path.exists(path):
        print(f"No report found at {path}. Run `scan` first.", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = [Finding(**item) for item in data["findings"]]
    return data["target_dir"], findings


def cmd_scan(args):
    if not os.path.isdir(args.target):
        print(f"Not a directory: {args.target}", file=sys.stderr)
        sys.exit(1)
    findings = scan_repo(args.target)
    _print_table(findings)
    _write_report(args.report, args.target, findings)
    print(f"\nReport written to {args.report}")


def cmd_report(args):
    _, findings = _load_report(args.report)
    _print_table(findings)


def cmd_fix(args):
    target_dir, findings = _load_report(args.report)
    match = next((f for f in findings if f.id == args.finding_id), None)
    if match is None:
        print(f"No finding with id {args.finding_id} in {args.report}", file=sys.stderr)
        sys.exit(1)

    print(f"Generating fix for finding #{match.id} ({match.rule}) in {match.file}...")
    start, end, replacement, source = llm_fix.generate_fix(target_dir, match)
    print(f"  fix source: {source}")

    branch_name, base_branch, file_relpath = apply_patch.apply_fix(
        target_dir, match, start, end, replacement
    )
    print(f"\nCreated branch '{branch_name}' off '{base_branch}'.")
    print(f"Applied fix to {file_relpath} and committed.")
    print(f"\nRun: git diff {base_branch}..{branch_name} -- {file_relpath}")


def main():
    parser = argparse.ArgumentParser(
        prog="securevibe",
        description="Static security/secrets scanner + auto-fix for vibe-coded apps.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--report", default=DEFAULT_REPORT,
        help=f"Path to the findings JSON report (default: {DEFAULT_REPORT})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="Scan a repo for the 5 vibe-coding vulnerability patterns")
    p_scan.add_argument("target", help="Path to the repo to scan")
    p_scan.set_defaults(func=cmd_scan)

    p_report = sub.add_parser("report", parents=[common], help="Re-print the findings from the last scan")
    p_report.set_defaults(func=cmd_report)

    p_fix = sub.add_parser("fix", parents=[common], help="Generate and apply a fix for one finding, on a new git branch")
    p_fix.add_argument("--finding-id", type=int, required=True, help="Finding id from the scan report")
    p_fix.set_defaults(func=cmd_fix)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
