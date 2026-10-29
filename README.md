# Ship Audit

<p align="center">
  <a href="https://z.ai/subscribe?ic=R0K78RJKNW"><img alt="z.ai coding plans - 10% OFF coupon" src="https://img.shields.io/badge/z.ai%20coding%20plans-10%25%20OFF%20coupon-blueviolet" /></a>
  <a href="https://zcode.z.ai/invite/ALWM9JUA"><img alt="Try ZCode free" src="https://img.shields.io/badge/Try%20ZCode-free%20invite-0969da" /></a>
</p>

Answer "is it safe to show a real user?" with a checklist, not with vibes.

## Why

Pre-launch reviews usually happen as a wall of prose where everything
"looks fine", and the real problems (a committed `.env`, a dead debug
flag, a `DROP TABLE` migration) hide inside it. The agent's temptation
is to rubber-stamp the dynamic checks: it cannot run your production
server, so it claims they passed. This plugin blocks the launch on hard
failures, keeps a static baseline in a script, and forces dynamic
checks to say what was actually verified, so unverified items show up as
"needs manual verification" rather than PASS.

## How it works

| Stage | What |
| ---- | ---- |
| 1. static scan | `audit_scan.py`: secrets in tracked files, env completeness, debug flags, stack-trace leaks, rate limiting, auth basics, HTTPS/headers, migration reversibility, dependency audit hook |
| 2. dynamic | agent verifies in code: auth flow, live endpoints, error pages, CORS; each item is PASS (checked: ...), FAIL (checked: ...), or needs manual verification |
| 3. deep dives | optional: advisories by severity, rotation plan, rollback procedure |

Verdict: `SHIP: BLOCK`, `SHIP: GO with N warnings`, or `SHIP: GO`,
plus a count of items that need manual verification.

## Install

Option A (self-installable marketplace):

1. Download or clone this repo folder to your machine.
2. Open ZCode, Plugin Marketplace, Add, Add Plugin Marketplace.
3. Paste the path to this folder and pick `ship-audit`.
4. Install.

Option B (manual): copy this folder into your ZCode workspace `plugins/`
directory and restart ZCode.

## Try it

```
/ship-audit . nextjs
```

Expected result: the static scan writes `ship-audit-report.md` with one
PASS/WARN/FAIL line per check and the evidence behind each; the dynamic
stage checks the auth flow, the error page, CORS, and the migration
down paths in the code, marks live-server items as "needs manual
verification", and ends with `SHIP: GO with 2 warnings` or
`SHIP: BLOCK` with the failing lines.

## Requirements

- Python 3 (stdlib only, for `audit_scan.py`)
- git recommended (the scanner is git-aware; it degrades to a full tree
  scan without a repo)

---

<p align="center">
  <a href="https://z.ai/subscribe?ic=R0K78RJKNW"><img alt="z.ai coding plans - 10% OFF coupon" src="https://img.shields.io/badge/z.ai%20coding%20plans-10%25%20OFF%20coupon-blueviolet" /></a>
  <a href="https://zcode.z.ai/invite/ALWM9JUA"><img alt="Try ZCode free" src="https://img.shields.io/badge/Try%20ZCode-free%20invite-0969da" /></a>
</p>

## License

MIT
