---
name: ship-audit
description: >
  Use before showing a build to a real user, before a public deploy, or when
  the user asks "is this safe to ship / show to a customer". Runs a staged
  pre-launch audit, blocks on hard failures, warns on soft ones, and keeps
  dynamic checks honest (marking what was actually verified versus what
  needs a human).
---

# Ship Audit: Pre-Launch Checklist Gate

Answers one question: is this safe to show a real user? The audit has two
stages: static checks the script can run, and dynamic checks the agent runs
honestly. Verdict per check is PASS, WARN, or FAIL. Overall verdict:
BLOCK, WARN, or GO.

- Hard FAIL (secrets in tracked files, missing env vars that the code
  reads on boot, debug mode enabled in production config) -> BLOCK.
- Any WARN -> launch may proceed but must list the warnings first.
- Dynamic checks that were not actually executed are never marked PASS.
  They are listed under "needs manual verification".

## Inputs

- Project root (default: working directory).
- Optional: framework hints (Next.js, Django, Express, Flask...) to tune
  the dynamic checks. Without hints, the skill uses what the code shows.

## Stage 1: static scan

Run the script. It exits 0 (all PASS/WARN only), 1 (at least one FAIL),
or 2 (not a project it can scan, e.g. no source files found).

```bash
python3 skills/ship-audit/scripts/audit_scan.py <project-root> \
  [--report ship-audit-report.md] [--json ship-audit.json]
```

It performs:
1. **Secrets**: regex set over tracked files (API keys, tokens, private
   key blocks, long high-entropy assignments). Also flags `.env` files
   committed to git, and any file matching `*.pem`, `*.p12`, or a
   hardcoded password assignment. `.env.example` (and other
   documentation variants: `.env.sample`, `.env.template`,
   `.env.dist`) are exempt from the committed-.env flag: tracking them
   is by design, and placeholder values are exempt from the secret
   regexes.
2. **Env completeness**: collects `process.env.X`, `os.environ[...]`,
   `getenv("X")` references from source, then diffs them against
   `.env.example` / `.env` / `.env.template` keys. A var the code reads
   that no env file documents is FAIL; a var documented but never read
   is WARN.
3. **Debug flags**: `NODE_ENV=development`, `DEBUG=`, `--debug`,
   `app.debug(True)`, `console.log` density in shipped bundles,
   `print(...)` in hot paths, debug routers mounted in production
   config.
4. **Stack-trace leaks**: error handlers that send `err.stack` or full
   exception objects to the response, unhandled promise rejection
   handlers that log raw stacks to a client-visible channel.
5. **Rate limiting**: for detected public HTTP endpoints, whether a
   limiter (express-rate-limit, django-ratelimit, flask-limiter,
   fastapi limit decorators, nginx `limit_req`) is in the dependency
   list or middleware chain.
6. **Auth basics**: whether the framework's auth middleware is present
   and whether public routes are actually public by design (router
   definitions that lack auth on non-public paths).
7. **HTTPS/headers**: for web servers, whether production config forces
   TLS or sits behind a documented proxy, and whether security
   headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) are set.
8. **Dependency audit hook**: detects the package manager (npm, pnpm,
   yarn, pip, poetry, uv, cargo, go) and delegates to its audit
   command if available (`npm audit --json`, `pip-audit`,
   `cargo audit`, `govulncheck`). If the tool is not installed the
   check is reported as "skipped: tool not available", never PASS.

Write the markdown report to the project root (default
`ship-audit-report.md`). The report has one line per check:
`PASS/WARN/FAIL | check | detail | evidence`.

## Stage 2: dynamic checks (agent-run, keep honest)

The agent performs what is checkable in the repo and says so. Each item
below ends as one of:
- `PASS (checked: <how>)`
- `FAIL (checked: <how>)`
- `needs manual verification: <what a human must do>`

1. **Auth flow**: read the login, session refresh, and logout routes.
   Confirm the token/cookie is not stored in localStorage for a
   sensitive app, that sessions expire, and that logout actually
   invalidates the server-side session. Check the code, not the docs.
2. **Live endpoint behavior**: if a dev server can be started in this
   environment, start it, hit the public endpoints, and record the
   actual responses (status, headers). If it cannot be started, list the
   endpoints that need a human curl against the deployed environment.
3. **Migration reversibility**: for DB projects, check that every
   migration has a down path (or is explicitly marked forward-only in a
   comment) and that destructive statements (`DROP`, `ALTER COLUMN`
   without a backfill plan) are called out. Unresolvable destructive
   migrations are WARN: the agent cannot verify the down path at runtime,
   so it flags them for a human rollback or backfill plan instead of
   blocking the launch on its own.
4. **Error pages**: confirm the production error page does not print
   stack traces or query strings (read the error middleware; do not
   assume).
5. **CORS**: for multi-origin apps, check the CORS allowlist is not a
   bare `*` with credentials.

## Stages 3..N: optional deep dives

Only if the user asks: dependency advisories by severity, secrets
rotation plan (which keys from Stage 1 must be considered burned), and a
rollback procedure for the deploy.

## Guardrails

- The overall verdict line format:
  `SHIP: BLOCK | SHIP: GO with N warnings | SHIP: GO`.
- BLOCK lists every FAIL with its evidence line. GO-with-warnings lists
  every WARN.
- Never convert a "needs manual verification" item into PASS in the
  verdict line. Count it separately: `N items need manual
  verification`.
- A missing dependency-audit tool is never reported as "no vulnerable
  dependencies". It is `skipped: <tool> not available`.
- The audit scans tracked content only by default; it can be pointed at
  untracked files with `--include-untracked`, but the report labels
  which files were untracked so secrets found there are not silently
  reported as committed.

## Script notes

`scripts/audit_scan.py` is stdlib-only, cross-OS. It produces a
markdown report and optional JSON. It reads source as text; it does not
execute project code, so "debug flag on" means the flag is set in
config or code that a human would ship, not that a live server was
measured.
