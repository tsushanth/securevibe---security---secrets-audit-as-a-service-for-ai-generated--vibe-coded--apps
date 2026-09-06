# SecureVibe (local MVP scaffold)

SecureVibe is a security & secrets scanner purpose-built for the failure
patterns AI coding agents (Claude Code, Cursor, Replit, Lovable, ...) keep
reproducing in "vibe-coded" apps. This is a **local, stdlib-only CLI
scaffold** that proves the core loop: **scan a repo -> detect the 5
patterns -> generate and apply a verified fix on a real git branch.**

See [`plan.md`](plan.md) for the full scoping rationale, including what's
explicitly deferred (GitHub PRs, dashboard, billing, hosting, dynamic
endpoint scanning) for this scaffold.

## The 5 patterns it detects

1. **Hardcoded secrets** -- API keys/tokens/passwords hardcoded in source,
   secrets exposed to the client via `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*`
   env prefixes, or a `.env` file committed to the repo.
2. **Missing Row Level Security** -- Supabase/Postgres tables created
   (`CREATE TABLE`) without a matching `ALTER TABLE ... ENABLE ROW LEVEL
   SECURITY`.
3. **Missing auth** -- API route handlers with no auth check.
4. **Missing rate limiting** -- API route handlers with no rate limiting.
5. **Error leakage** -- error handlers that send raw exception
   objects/messages/stack traces straight to the client response.

Detection is regex/heuristic-based over file contents -- good enough to
prove the concept; a real product would move to proper per-language AST
parsing.

## Requirements

Just **Python 3** (standard library only -- no `pip install`, no `npm
install`, no build step). Optionally, an `ANTHROPIC_API_KEY` environment
variable for LLM-generated fixes (see below).

## Quick start

```bash
# 1. Scan the seeded demo app (contains one instance of each of the 5 patterns)
python3 cli.py scan fixtures/vibe-coded-demo-app

# -> prints a table of findings and writes findings.json in the current directory

# 2. Generate and apply a verified fix for one finding
python3 cli.py fix --finding-id 1

# -> creates a new local git branch, applies the fix, and commits it
# -> follow the printed `git diff <base>..<branch>` command to review it
```

To see the findings from the last scan again without rescanning:

```bash
python3 cli.py report
```

## How `fix` works

`fix` looks up the finding by id in `findings.json` (written by `scan`),
then:

1. **Generates a fix.** If `ANTHROPIC_API_KEY` is set, it sends the
   flagged code (plus a few lines of surrounding context) to the Claude
   API and asks for a corrected replacement. If the key is unset, or the
   API call fails, it falls back to a deterministic template fix for that
   pattern type -- so the full loop runs end-to-end with zero setup.
2. **Applies it for real.** It resolves the git repository that contains
   the scanned directory (`git rev-parse --show-toplevel`), creates a new
   branch off the current `HEAD` (e.g. `securevibe/fix-1-hardcoded-secret`),
   writes the fix to disk, and commits it. Nothing is simulated -- it's a
   real diff on a real branch, which is the same mechanic a hosted product
   would use to open a fix PR, minus the GitHub API call.

Since the demo app lives inside this repo (not a separate git repo), the
`fix` command creates branches/commits **in this repo** -- that's expected
and is what "a real diff on a real git branch" means for this scaffold.

## Running the tests

```bash
python3 -m unittest discover tests
```

This covers:
- **`tests/test_rules.py`** -- one true-positive and one true-negative
  snippet per rule.
- **`tests/test_engine.py`** -- asserts the engine finds exactly the 5
  seeded issues in `fixtures/vibe-coded-demo-app`, one per pattern.

## Layout

```
cli.py                 # argparse entry point: scan / fix / report
scanner/
  rules.py             # the 5 detection rules
  engine.py            # walks a repo, dispatches files to applicable rules
fixer/
  llm_fix.py           # builds a fix via the Anthropic API, or a template fallback
  apply_patch.py       # creates a git branch, applies the fix, commits it
fixtures/vibe-coded-demo-app/  # seeded sample app, one instance of each pattern
tests/                 # unit tests + fixture-based integration check
```

## Explicitly out of scope for this scaffold

No GitHub Action, no real GitHub PR creation (OAuth/PAT), no dashboard, no
accounts/billing, no hosting, no dynamic/live endpoint scanning, no
persistent database. See `plan.md` section 2 for the full list and
rationale -- this scaffold exists to prove the scan -> detect -> auto-fix
loop, with everything else deferred as packaging.
