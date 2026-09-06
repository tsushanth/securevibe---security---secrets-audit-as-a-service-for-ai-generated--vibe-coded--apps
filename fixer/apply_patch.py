"""Applies a generated fix as a real commit on a new local git branch.

This is the "verified fix PR" mechanic without any GitHub auth: the target
repo (found by walking up from the scanned directory to its enclosing git
repo) gets a new branch, the fix is written to disk, and it's committed.
`git diff <base>..<branch>` then shows a real, reviewable patch.
"""
import os
import subprocess


def _run_git(args, cwd):
    result = subprocess.run(
        ["git"] + args, cwd=cwd, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _git_root(path):
    return _run_git(["rev-parse", "--show-toplevel"], cwd=path)


def apply_fix(target_dir, finding, start, end, replacement_text):
    """Returns (branch_name, base_branch, file_relpath_from_repo_root)."""
    repo_root = _git_root(target_dir)
    filepath = os.path.join(target_dir, finding.file)
    file_relpath = os.path.relpath(filepath, repo_root)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        original_lines = f.read().splitlines()

    new_lines = original_lines[:start] + replacement_text.splitlines() + original_lines[end:]
    new_content = "\n".join(new_lines) + "\n"

    base_branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)
    branch_name = f"securevibe/fix-{finding.id}-{finding.rule}".replace("_", "-")

    _run_git(["checkout", "-b", branch_name], cwd=repo_root)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
        _run_git(["add", file_relpath], cwd=repo_root)
        _run_git(
            [
                "commit",
                "-m",
                f"securevibe: fix {finding.rule} in {file_relpath} (finding #{finding.id})",
            ],
            cwd=repo_root,
        )
    except Exception:
        _run_git(["checkout", base_branch], cwd=repo_root)
        _run_git(["branch", "-D", branch_name], cwd=repo_root)
        raise

    return branch_name, base_branch, file_relpath
