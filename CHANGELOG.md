# Changelog

## 0.1.1 - 2026-10-29

- Fix: OpenAI key pattern now matches sk-proj- keys (hyphenated), which 0.1.0 silently missed.
- Fix: .env.example and friends no longer false-positive as committed .env files.
- Change: migration check warns instead of failing, per spec.

## 0.1.0 - 2026-10-29

- Initial release: staged pre-launch gate that BLOCKS on hard failures
  and WARNs on soft ones, with an explicit "needs manual verification"
  bucket so dynamic checks are never claimed as PASS.
- `audit_scan.py`: static scan for secrets in tracked files, env var
  completeness, debug flags, stack-trace leaks, rate limiting, auth
  basics, HTTPS/security headers, and destructive-migration detection;
  exits 0/1/2 and writes a markdown report plus optional JSON.
- Dependency audit hook: detects the package manager and delegates to
  its audit command, reporting "skipped: tool not available" when the
  tool is missing.
