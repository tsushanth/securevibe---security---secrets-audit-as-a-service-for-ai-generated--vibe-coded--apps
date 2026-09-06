# SecureVibe — Local MVP Scaffold Plan

## Core value being demoed
A CLI that (1) statically scans a repo for the 5 failure patterns AI coding
agents keep reproducing, and (2) uses an LLM to generate a **verified,
applied fix** (a real diff on a real git branch) for at least one finding —
not just a text report. Everything else (GitHub PRs, dashboard, billing,
hosting) is packaging around this loop and is deferred.

The 5 patterns to detect:
1. Hardcoded API keys/secrets (incl. secrets exposed to the client via
   `NEXT_PUBLIC_*` / `VITE_*` prefixes, `.env` committed to the repo)
2. Supabase/Postgres tables created without Row Level Security enabled
3. API route handlers with no auth check
4. API route handlers with no rate limiting
5. Error handlers that leak raw exceptions/stack traces to the client

## 1. Stack decision
**Plain Python 3, standard library only.** No npm install, no build step,
no framework, no external pip dependencies — `python3 cli.py scan ./some-repo`
just works on any machine with Python.

- Detection = regex/heuristic pattern matching over file contents
  (`re`, `os.walk`). Good enough to prove the concept; a real product would
  later move to proper AST parsing per language. Not needed for the demo.
- The "LLM opens a fix" step calls the Anthropic Messages API directly via
  `urllib.request` (stdlib) — no `anthropic` SDK dependency needed for a
  single API call.
- "Opens a fix PR" is simulated locally: create a new git branch, apply the
  LLM-generated patch, commit it. This is the real mechanic of a PR (a diff
  on a branch) without needing GitHub API auth/tokens or a hosted repo.
- Rejected alternatives: Node/TS CLI (would need `npm install`, a
  tsconfig, and a bundler for zero benefit at this stage — regex scanning
  doesn't need JS's ecosystem); Go single-binary (compilation step adds
  friction for a scaffold that will be iterated on rapidly).

## 2. Explicitly out of scope (for this local scaffold)
- **No GitHub Action / CI YAML** — the CLI is the product core; wiring it
  into Actions is packaging, not the value being tested.
- **No real GitHub PR creation** — no GitHub App, no OAuth, no PAT handling.
  A local git branch + commit proves the "verified fix" mechanic just as
  well without any auth flow.
- **No dashboard / web UI** — findings are printed to terminal + written to
  a JSON report file.
- **No accounts, no multi-tenancy, no billing/Stripe** — single local user,
  single repo, one run at a time.
- **No hosting/deploy** — runs on localhost only.
- **No live/dynamic endpoint scanning** (hitting deployed URLs to probe for
  open endpoints) — static repo scanning only. Dynamic scanning is a
  believable v2 feature, not required to prove the core static-scan +
  auto-fix loop.
- **No persistent database or telemetry** — findings live in a JSON file
  on disk for the duration of the demo.
- The only "credential-like" thing needed is an `ANTHROPIC_API_KEY` env var
  for the fix-generation step, since the core value literally requires
  calling an LLM. If it's unset, `fix` falls back to a canned template
  patch per pattern type so the end-to-end flow (scan → fix → branch/commit)
  still runs without network access, for demo reliability.

## 3. File/directory layout
```
securevibe/
  cli.py                      # argparse entry point: scan / fix / report subcommands
  scanner/
    __init__.py
    rules.py                  # one function per pattern (5 rules), returns Finding objects
    engine.py                 # walks target repo, dispatches files to applicable rules
  fixer/
    __init__.py
    llm_fix.py                # builds prompt from a Finding + surrounding code, calls
                               #   Anthropic API via urllib, returns a unified diff;
                               #   falls back to a static template patch if no API key
    apply_patch.py            # git checkout -b, apply diff, git commit (via subprocess)
  fixtures/
    vibe-coded-demo-app/      # small seeded sample repo, one instance of each of the
                               #   5 vulnerabilities, used for manual run-through + tests
      .env
      package.json
      pages/api/users.js      # missing auth + verbose error leakage
      pages/api/admin.js      # missing rate limit
      lib/db.js               # hardcoded Supabase service key
      supabase/migrations/0001_init.sql   # CREATE TABLE with no RLS enabled
  tests/
    test_rules.py             # unit tests: one true-positive + one true-negative
                               #   snippet per rule
    test_engine.py            # asserts engine finds exactly the 5 seeded issues
                               #   in fixtures/vibe-coded-demo-app
```

## 4. Verification plan
- **Unit tests** (`python -m unittest discover tests`): for each of the 5
  rules, assert it fires on a known-bad inline snippet and stays silent on
  a known-clean equivalent (e.g. a route file that *does* check auth).
- **Fixture-based integration check**: run the engine against
  `fixtures/vibe-coded-demo-app` and assert it returns exactly 5 findings,
  one per seeded pattern, with correct file/line — catches both
  under-detection and false-positive noise.
- **Manual run-through**:
  ```
  python cli.py scan fixtures/vibe-coded-demo-app
  # expect: human-readable table of 5 findings + findings.json written

  python cli.py fix --finding-id 1
  # expect: new local git branch created, patch applied, committed;
  # `git diff main..<branch>` shows a real, readable fix
  ```
- Success bar for the scaffold: a stranger can clone the repo, run those
  two commands with zero setup beyond `python3`, and see the full
  scan → detect → auto-fix-branch loop with their own eyes.
