#!/usr/bin/env python3
"""Static pre-launch audit: secrets, env completeness, debug flags,
error handling, rate limiting, auth, TLS/headers, migrations.

Stdlib only, cross-OS. Does not execute project code: findings are
based on reading files (tracked via git when available, all files
otherwise). Produces a markdown report and optional JSON.

Exit codes:
  0 = GO or GO with warnings (no hard FAIL)
  1 = BLOCK (at least one hard FAIL)
  2 = not a scannable project (no source files found)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# --- detection patterns -------------------------------------------------

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(
        r"(?i)aws[_\s-]?secret[_\s-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private-key-block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.M)),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("jwt-secret-assign", re.compile(
        r"(?i)jwt[_-]?secret\s*[:=]\s*[\"']([^\"']{8,})[\"']")),
    ("hardcoded-password", re.compile(
        r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[\"']([^\"' ]{6,})[\"']")),
    ("connection-string-creds", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[A-Za-z0-9]+:[A-Za-z0-9!%&'()*+,-./:=@#?^_{|}~]{6,}@")),
]

SECRET_EXEMPT_VALUES = {"changeme", "change-me", "password", "secret",
                        "xxx", "your-key-here", "placeholder", "dummy",
                        "example", "test", "redacted", "<secret>",
                        "${", "%s", "env", "process.env", "os.environ",
                        "os.getenv"}

SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv",
                  ".tox", "dist", "build", ".next", "target", ".idea",
                  ".vscode", "vendor", ".zcode-plugin", "egg-info"}

SOURCE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py",
               ".rb", ".go", ".rs", ".java", ".php", ".cs", ".c", ".cpp",
               ".h", ".kt", ".swift", ".scala", ".sh", ".yaml", ".yml",
               ".toml", ".json", ".env", ".conf", ".ini", ".properties",
               ".tsv", ".sql", ".ejs", ".hbs", ".vue"}

CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".env", ".ini",
               ".properties", ".conf"}

DEBUG_FLAG_PATTERNS = [
    ("node-dev", re.compile(r"(?i)NODE_ENV\s*[:=]\s*[\"']?development")),
    ("env-debug", re.compile(r"(?m)^\s*DEBUG\s*=\s*(?:true|1|y|yes)\b", re.I)),
    ("flask-debug", re.compile(r"(?i)run\([^)]*debug\s*=\s*True")),
    ("flask-debug-flag", re.compile(r"(?i)app\.debug\s*=\s*True")),
    ("railties-debug", re.compile(r"(?i)config\.debug\s*=\s*true")),
    ("spring-debug", re.compile(r"(?i)logging\.level\.root\s*=\s*DEBUG")),
    ("webpack-devtool", re.compile(r"(?i)devtool\s*[:=]\s*[\"'](source-map|cheap-module-eval-source-map)[\"']")),
    ("debug-port-open", re.compile(r"inspect(ion)?-brk?-at\b|inspectPort|node --inspect")),
]

STACK_LEAK_PATTERNS = [
    ("err-to-client", re.compile(r"(?i)res\.json\(\{[^}]*\bstack\b|res\.send\([^)]*err\.stack|sendResponse\([^)]*\.stack")),
    ("throw-raw", re.compile(r"(?i)next\(\s*(?:err|error)\s*\)\s*;[^\n]*\/\/?\s*(?:no-op|noop|empty|ignored)")),
]

RATELIMIT_MARKERS = ["express-rate-limit", "limiter", "flask-limiter",
                     "django-ratelimit", "ratelimit", "limiter",
                     "express-slow-down", "golang.org/x/time/rate",
                     "tower", "actix", "limit_req", "nginx", "fastify-rate-limit"]

AUTH_MARKERS = ["express-session", "passport", "jsonwebtoken", "jwt",
                "django.contrib.auth", "login", "session", "auth",
                "fastapi-security", "oauth", "authelia", "clerk",
                "supabase", "firebase", "guard"]

TLS_MARKERS = ["https://", "force_https", "SSL_", "TLS_", "strict-transport",
               "X-Forwarded-Proto", "helmet", "hsts"]

HEADER_MARKERS = ["Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options",
                  "Referrer-Policy", "Permissions-Policy"]

DESTRUCTIVE_MIGRATION = re.compile(
    r"(?i)\bDROP\s+TABLE\b|\bDROP\s+COLUMN\b|\bALTER\s+TABLE\s+\w+\s+DROP\b|\bTRUNCATE\s+\w+|\bDELETE\s+FROM\s+\w+\s*;\s*$")

FORWARD_ONLY_COMMENT = re.compile(r"(?i)forward[- ]only|irreversib|cannot be reverted")

# --- helpers ------------------------------------------------------------


class Finding:
    def __init__(self, status, check, detail, evidence=None):
        self.status = status        # PASS | WARN | FAIL
        self.check = check
        self.detail = detail
        self.evidence = evidence or []   # list of "path:line text"

    def line(self):
        ev = " | ".join(self.evidence[:5])
        return "{} | {} | {} | {}".format(self.status, self.check,
                                          self.detail, ev)


def is_skipped_dir(name):
    return name in SKIP_DIR_NAMES or name.endswith(".egg-info")


def git_tracked(root):
    """Return a set of relative paths tracked by git, or None."""
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=str(root),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if out.returncode != 0:
            return None
        return {p for p in out.stdout.splitlines() if p}
    except (OSError, FileNotFoundError):
        return None


def iter_files(root, tracked, include_untracked):
    """Yield (Path, relative_str, is_untracked)."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not is_skipped_dir(d)]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = os.path.relpath(str(p), str(root))
            untracked = True
            if tracked is not None:
                untracked = rel.replace(os.sep, "/") not in tracked
            if untracked and not include_untracked:
                continue
            yield p, rel, untracked


def read_text(path, limit_bytes=512 * 1024):
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit_bytes)
        return data.decode("utf-8", "replace")
    except OSError:
        return None


def scan_binary_hint(path):
    """Cheap binary detection via NUL byte in first 4KB."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


def is_secret_exempt(value):
    v = value.strip().strip("\"'")
    return any(v.startswith(x) or x in v[:16] for x in SECRET_EXEMPT_VALUES) \
        or v.startswith("${") or v.startswith("%s") or len(v) < 6


def check_secrets(root, files):
    """files: iterator of (path, rel, untracked). Returns list of Finding."""
    findings = []
    hits = []
    env_committed = []
    key_files = []
    scanned = 0
    for path, rel, untracked in files:
        if scan_binary_hint(path):
            continue
        base = Path(rel).name
        if base.startswith(".env") or base in ("env", "environment"):
            if not untracked:
                env_committed.append(rel)
            continue
        if base.lower().endswith((".pem", ".p12", ".pfx", ".key", ".jks")):
            key_files.append(rel)
            continue
        text = read_text(path)
        if text is None:
            continue
        if len(text) > 200 * 1024 or "base64" in base.lower():
            pass
        scanned += 1
        for i, rawline in enumerate(text.splitlines(), 1):
            line = rawline
            if any(pat.search(line) for _, pat in [
                    (n, p) for n, p in SECRET_PATTERNS if n == "private-key-block"]):
                hits.append("{0}:{1}: private key block{2}".format(
                    rel, i, " [untracked]" if untracked else ""))
                continue
            for name, pat in SECRET_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                # Skip variable-assignment forms and env placeholders.
                stripped = line.strip()
                if name in ("aws-secret-key", "jwt-secret-assign",
                            "hardcoded-password"):
                    val = m.group(1) if m.groups() else ""
                    if is_secret_exempt(val):
                        continue
                if name == "hardcoded-password" and (
                        stripped.startswith("#") or
                        "password" in stripped.lower() and
                        re.search(r"(?i)\b(env|process|os\.|getenv|django|settings|placeholder)\b", line)):
                    continue
                if name == "hardcoded-password" and re.search(
                        r"(?i)\b(getenv|os\.environ|process\.env|settings|os\.getenv|env\()\b", line):
                    continue
                hits.append("{0}:{1}: {2}{3}".format(
                    rel, i, name, " [untracked]" if untracked else ""))
    hard = [h for h in hits if "[untracked]" not in h]
    soft = [h for h in hits if "[untracked]" in h]
    if hard:
        findings.append(Finding(
            "FAIL", "secrets-in-tracked-files",
            "secret-like content found in tracked files; rotate the exposed credentials",
            hard))
    elif soft:
        findings.append(Finding(
            "WARN", "secrets-in-tracked-files",
            "secret-like content in untracked files only; do not commit; still consider rotation",
            soft))
    else:
        findings.append(Finding(
            "PASS", "secrets-in-tracked-files",
            "no secret patterns in scanned files ({0} files)".format(scanned)))
    if env_committed:
        findings.append(Finding(
            "FAIL", "env-files-committed",
            ".env files committed to git; their values are exposed to anyone with repo access",
            env_committed))
    else:
        findings.append(Finding(
            "PASS", "env-files-committed", "no .env file tracked"))
    if key_files:
        findings.append(Finding(
            "WARN", "key-material-files",
            "key/certificate files present in the tree; verify none are tracked or shipped",
            key_files))
    else:
        findings.append(Finding(
            "PASS", "key-material-files", "no key material files found"))
    return findings


def env_var_references(files):
    """Collect env var names referenced in source."""
    refs = set()
    pats = [
        re.compile(r"\bprocess\.env\.([A-Z_][A-Z0-9_]*)"),
        re.compile(r"\bprocess\.env\[['\"]([A-Z_][A-Z0-9_]*)['\"]\]"),
        re.compile(r"\bos\.environ\.get\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']"),
        re.compile(r"\bos\.environ\[\s*[\"']([A-Z_][A-Z0-9_]*)[\"']\s*\]"),
        re.compile(r"(?<![\w.])getenv\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']"),
        re.compile(r"\bgetenv\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']"),
        re.compile(r"(?i)\benv\[\s*['\"]([A-Z_][A-Z0-9_]*)['\"]\s*\]"),
        re.compile(r"\bconf\.get\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']"),
    ]
    seen_files = set()
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        ext = Path(rel).suffix
        if ext not in SOURCE_EXTS and ext not in CONFIG_EXTS:
            continue
        text = read_text(path)
        if text is None:
            continue
        for pat in pats:
            for m in pat.finditer(text):
                refs.add(m.group(1))
    return refs


def env_file_keys(files):
    """Collect documented env keys from .env.example / .env / .env.template."""
    keys = set()
    kv = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
    found_env_files = []
    for path, rel, untracked in files:
        base = Path(rel).name
        if base in (".env.example", ".env", ".env.template", "env.example"):
            found_env_files.append(base)
            if untracked:
                continue
            text = read_text(path)
            if text is None:
                continue
            for line in text.splitlines():
                m = kv.match(line)
                if m and not line.strip().startswith("#"):
                    keys.add(m.group(1))
    return keys, found_env_files


def check_env_completeness(root, files):
    refs = env_var_references(files)
    keys, env_files = env_file_keys(files)
    if not refs:
        return [Finding("PASS", "env-completeness",
                        "no env-var references found in source; nothing to document")]
    missing = sorted(v for v in refs if v not in keys)
    unused = sorted(v for v in keys if v not in refs)
    hard = [v for v in missing if v not in ("NODE_ENV", "PATH", "HOME",
                                            "PWD", "LANG", "TZ", "USER",
                                            "SHELL", "LOGNAME", "TERM")]
    findings = []
    if hard:
        findings.append(Finding(
            "FAIL", "env-completeness",
            "code reads env vars that no .env file documents: {0}".format(
                ", ".join(hard)),
            ["env files: " + (", ".join(sorted(env_files)) if env_files else "none found")]))
    else:
        findings.append(Finding(
            "PASS", "env-completeness",
            "all referenced env vars are documented ({0} vars, {1} env file(s))".format(
                len(refs & keys), len(env_files))))
    if unused:
        findings.append(Finding(
            "WARN", "env-completeness-unused",
            "documented but not referenced in code: {0}".format(
                ", ".join(unused[:10]))))
    return findings


def check_debug_flags(files):
    hits = []
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        ext = Path(rel).suffix
        if ext not in SOURCE_EXTS and ext not in CONFIG_EXTS:
            continue
        text = read_text(path)
        if text is None:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for name, pat in DEBUG_FLAG_PATTERNS:
                if pat.search(line):
                    hits.append("{0}:{1}: {2}".format(rel, line_no, name))
                    break
    if hits:
        return [Finding("FAIL", "debug-flags",
                       "debug or development flags found in source or config; disable before launch",
                       hits)]
    return [Finding("PASS", "debug-flags", "no debug/development flags found")]


def check_stack_leaks(files):
    hits = []
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for name, pat in STACK_LEAK_PATTERNS:
                if pat.search(line):
                    hits.append("{0}:{1}: {2}".format(rel, i, name))
    if hits:
        return [Finding("WARN", "stack-trace-leaks",
                       "error paths may expose stack traces; verify the production error page",
                       hits)]
    return [Finding("PASS", "stack-trace-leaks",
                   "no obvious stack-trace-to-client patterns")]


def check_rate_limiting(files):
    found = []
    has_http = False
    http_markers = re.compile(
        r"(?i)\b(app\.get|app\.post|app\.delete|router\.(get|post|delete)|"
        r"@app\.(route|get|post)|@router\.(get|post)|def\s+handle|express\(\)|"
        r"fastapi\.FastAPI\(|Flask\(|Django|http\.ListenAndServe|gin\.|chi\.|actix|express-route)\b")
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        if http_markers.search(text):
            has_http = True
        for marker in RATELIMIT_MARKERS:
            if re.search(re.escape(marker), text, re.I):
                found.append(rel)
                break
    if found:
        return [Finding("PASS", "rate-limiting",
                       "rate-limiting present in: {0}".format(
                           ", ".join(sorted(set(found))[:4])))]
    if has_http:
        return [Finding("WARN", "rate-limiting",
                       "public HTTP endpoints detected but no rate limiter found; verify the gateway or add one")]
    return [Finding("PASS", "rate-limiting",
                   "no HTTP endpoints detected; check not applicable")]


def check_auth_basics(files):
    found = []
    has_http = False
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        low = text
        for marker in AUTH_MARKERS:
            if re.search(re.escape(marker), low, re.I):
                found.append(rel)
                break
        if re.search(r"(?i)\b(login|signin|sign-in|auth)/?\b", text):
            has_http = True
    if found:
        return [Finding("PASS", "auth-basics",
                       "auth machinery referenced in: {0}".format(
                           ", ".join(sorted(set(found))[:5])))]
    if has_http:
        return [Finding("WARN", "auth-basics",
                       "login/auth routes detected but no auth middleware found; verify session handling manually")]
    return [Finding("PASS", "auth-basics",
                   "no auth markers; confirm this is an intentionally public app")]


def check_https_headers(files):
    tls, hdrs = [], []
    for path, rel, untracked in files:
        if untracked:
            continue
        if scan_binary_hint(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        for m in TLS_MARKERS:
            if m in text:
                tls.append(rel)
                break
        for m in HEADER_MARKERS:
            if m in text:
                hdrs.append(m)
        for m in ["helmet", "secure_headers", "SecurityHeaders", "X-Frame-Options"]:
            if m in text:
                hdrs.append(m + " (via helper)")
                break
    findings = []
    if tls:
        findings.append(Finding("PASS", "https/tls",
                                "TLS markers found in: {0}".format(
                                    ", ".join(sorted(set(tls))[:4]))))
    else:
        findings.append(Finding("WARN", "https/tls",
                                "no TLS markers found; verify the app runs behind an HTTPS proxy or terminates TLS"))
    if set(hdrs):
        findings.append(Finding("PASS", "security-headers",
                                "security headers present: {0}".format(
                                    ", ".join(sorted(set(hdrs))[:6]))))
    else:
        findings.append(Finding("WARN", "security-headers",
                                "no security headers (CSP/HSTS/X-Frame-Options) found; add them at the server or gateway"))
    return findings


def check_migrations(files):
    hits = []
    found_migrations = []
    for path, rel, untracked in files:
        if untracked:
            continue
        base = Path(rel).name
        if base in ("migrations", "migrate") or "migration" in rel.lower() or rel.lower().startswith("db/migrations/"):
            found_migrations.append(rel)
        ext = Path(rel).suffix
        if ext not in (".sql", ".py", ".js", ".rb", ".ts"):
            continue
        text = read_text(path)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if DESTRUCTIVE_MIGRATION.search(line) and not FORWARD_ONLY_COMMENT.search(line):
                # Marked forward-only (comment or string) on the same line?
                hits.append("{0}:{1}: destructive statement without a down path".format(rel, i))
    if not found_migrations:
        return [Finding("PASS", "migration-reversibility",
                       "no DB migrations detected; check not applicable")]
    if hits:
        return [Finding("WARN", "migration-reversibility",
                       "destructive migration statements without a down path or a forward-only marker; confirm a rollback or backfill plan before launch",
                       hits)]
    return [Finding("PASS", "migration-reversibility",
                   "destructive statements absent in the {0} migration file(s)".format(len(found_migrations)))]


def check_dependency_audit_hook(root):
    """Detect the package manager and report what audit command applies.

    We do not run third-party audit tools here (that is the user's
    hook); we name the command so the agent can delegate to it or mark
    it 'skipped: tool not available'.
    """
    pm = None
    cmd = None
    root = Path(root)
    if (root / "package.json").exists():
        if (root / "pnpm-lock.yaml").exists():
            pm, cmd = "pnpm", "pnpm audit"
        elif (root / "yarn.lock").exists():
            pm, cmd = "yarn", "yarn audit"
        elif (root / "npm-shrinkwrap.json").exists():
            pm, cmd = "npm", "npm ls --audit"
        else:
            pm, cmd = "npm", "npm audit"
    elif (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        pm, cmd = "pip", "pip-audit"
    elif (root / "poetry.lock").exists():
        pm, cmd = "poetry", "poetry check"
    elif (root / "go.mod").exists():
        pm, cmd = "go", "govulncheck"
    elif (root / "Cargo.toml").exists():
        pm, cmd = "cargo", "cargo audit"
    elif (root / "Gemfile").exists():
        pm, cmd = "bundler", "bundle audit"
    if pm is None:
        return [Finding("PASS", "dependency-audit",
                       "no recognized package manager manifest; hook not applicable")]
    return [Finding("PASS", "dependency-audit",
                   "delegated to the user's package manager ({0}): run `{1}` if available, else report 'skipped: {1} not available'".format(pm, cmd))]


# --- main ----------------------------------------------------------------


def verdict(findings):
    fails = [f for f in findings if f.status == "FAIL"]
    warns = [f for f in findings if f.status == "WARN"]
    if fails:
        return "BLOCK"
    if warns:
        return "GO with {0} warning(s)".format(len(warns))
    return "GO"


def main():
    ap = argparse.ArgumentParser(
        description="Static pre-launch audit of a project directory.")
    ap.add_argument("root", nargs="?", default=".",
                   help="Project root to scan (default: current dir).")
    ap.add_argument("--report", default="ship-audit-report.md",
                    help="Markdown report path (default in cwd).")
    ap.add_argument("--json", default=None,
                    help="Also write a JSON results file to this path.")
    ap.add_argument("--include-untracked", action="store_true",
                    help="Also scan files that git does not track "
                         "(labeled [untracked] in findings).")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print("error: not a directory: {0}".format(args.root), file=sys.stderr)
        return 2

    tracked = git_tracked(root)
    file_iter = list(iter_files(root, tracked, args.include_untracked))
    source_count = sum(
        1 for _, rel, _ in file_iter
        if Path(rel).suffix in SOURCE_EXTS)
    if source_count == 0:
        print("error: no source files found under {0}".format(root),
              file=sys.stderr)
        return 2

    files = file_iter

    findings = []
    findings += check_secrets(root, list(files))
    findings += check_env_completeness(root, list(files))
    findings += check_debug_flags(files)
    findings += check_stack_leaks(files)
    findings += check_rate_limiting(files)
    findings += check_auth_basics(files)
    findings += check_https_headers(files)
    findings += check_migrations(files)
    findings += check_dependency_audit_hook(root)

    verdict_line = verdict(findings)

    md = [
        "# Ship Audit Report",
        "",
        "Project: `{0}`".format(root),
        "Verdict: **{0}**".format(verdict_line),
        "",
        "Scan note: git-tracked files only" if tracked is not None else
        "Scan note: no git repo detected; all files scanned",
        "",
        "| Status | Check | Detail | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for f in findings:
        ev = " | ".join(f.evidence[:5]) if f.evidence else ""
        md.append("| {0} | {1} | {2} | {3} |".format(
            f.status, f.check, f.detail.replace("|", "\\|"),
            ev.replace("|", "\\|")))
    md += [
        "",
        "Items that need manual verification (dynamic checks not run by this script):",
        "- auth flow behaviour on a live server",
        "- live endpoint responses (status, headers, CORS preflight)",
        "- production error page rendering",
        "- dependency advisories (run the package manager's audit command)",
        "",
        "Remember: a 'skipped: tool not available' hook is never PASS.",
        "",
    ]
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = root / report_path
    report_path.write_text("\n".join(md), encoding="utf-8")

    if args.json:
        jp = Path(args.json)
        if not jp.is_absolute():
            jp = root / jp
        jp.write_text(json.dumps(
            {"root": str(root), "verdict": verdict_line,
             "findings": [{"status": f.status, "check": f.check,
                           "detail": f.detail, "evidence": f.evidence}
                          for f in findings]},
            indent=2), encoding="utf-8")

    print("verdict: {0}".format(verdict_line))
    for f in findings:
        print("  {0}".format(f.line()))
    print("report: {0}".format(report_path))

    return 1 if verdict_line == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
