#!/usr/bin/env python3
"""Offline security verification gate for echo-crm.

Static scans + unit suite. Exit 0 on full pass. No network required for
static checks; HTTP tests use FastAPI TestClient against local app.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("ECHO_CRM_DEV_MODE", "1")
os.environ.setdefault("PGPASSWORD", "echo")
os.environ.setdefault("PGHOST", "127.0.0.1")
os.environ.setdefault("PGUSER", "echo")
os.environ.setdefault("PGDATABASE", "echo")
os.environ.setdefault("ECHO_CRM_API_KEY", "test-security-key-12345")
os.environ.setdefault("ECHO_API_KEY", "test-security-key-12345")

import security as sec  # noqa: E402


def _fail(msg: str) -> int:
    print(f"FAIL: {msg}")
    return 1


def main() -> int:
    print("=== echo-crm security verification ===")
    app_src = (ROOT / "app.py").read_text(encoding="utf-8")
    sec_src = (ROOT / "security.py").read_text(encoding="utf-8")
    svc = (ROOT / "echo-crm.service").read_text(encoding="utf-8")

    hard = sec.scan_for_hardcoded_secrets(app_src) + sec.scan_for_hardcoded_secrets(sec_src)
    sql = sec.scan_for_unsafe_sql(app_src)
    print(f"  hardcoded secrets: {hard or 'none'}")
    print(f"  unsafe SQL:        {sql or 'none'}")
    if hard or sql:
        return _fail("static scan")

    if "PGPASSWORD=echo" in svc:
        return _fail("service unit hardcodes PGPASSWORD=echo")
    if re.search(r'get\(["\']PGPASSWORD["\']\s*,\s*["\']echo["\']\)', app_src):
        return _fail("app.py has hardcoded PGPASSWORD default")
    if 'execute(f"' in app_src or "execute(f'" in app_src:
        return _fail("f-string execute in app.py")
    print("  unit + source:     no hardcoded PG password")

    # Authz map integrity
    assert sec.ENDPOINT_AUTH["health"] == sec.AUTH_PUBLIC
    assert sec.ENDPOINT_AUTH["root"] == sec.AUTH_PUBLIC
    assert sec.ENDPOINT_AUTH["plans.upgrade"] == sec.AUTH_ADMIN
    assert sec.ENDPOINT_AUTH["admin.migrate_stripe"] == sec.AUTH_ADMIN
    assert sec.ENDPOINT_AUTH["internal.weekly_digest"] == sec.AUTH_ADMIN
    assert sec.ENDPOINT_AUTH["webhooks.stripe"] == sec.AUTH_WEBHOOK
    for ep, tier in sec.ENDPOINT_AUTH.items():
        if ep in ("health", "root"):
            assert tier == sec.AUTH_PUBLIC, ep
        elif ep == "webhooks.stripe":
            assert tier == sec.AUTH_WEBHOOK
        else:
            assert tier in (
                sec.AUTH_READ,
                sec.AUTH_WRITE,
                sec.AUTH_ADMIN,
            ), f"{ep}={tier}"
    print(f"  authz map:         OK ({len(sec.ENDPOINT_AUTH)} endpoints)")

    # Global path auth wired
    if "path_auth_dependency()" not in app_src:
        return _fail("path_auth_dependency not wired on FastAPI app")
    if "dependencies=[Depends(path_auth_dependency())]" not in app_src:
        return _fail("global Depends(path_auth_dependency) missing")
    print("  path authz:        wired globally")

    routes = re.findall(r'@app\.(get|post|put|patch|delete)\("([^"]+)"', app_src)
    print(f"  routes found:      {len(routes)}")
    if len(routes) < 40:
        return _fail(f"expected ≥40 routes, found {len(routes)}")

    # vault map present
    vault_map = ROOT / "vault_paths.json"
    if not vault_map.is_file():
        return _fail("vault_paths.json missing")
    print("  vault_paths.json:  present")

    # secure_compare present (length-oracle fix)
    if "def secure_compare" not in sec_src:
        return _fail("secure_compare missing from security.py")
    print("  secure_compare:    present")

    # Version gate
    if "2.1.0-security" not in app_src:
        return _fail("CRM_VERSION not bumped to 2.1.0-security")
    print("  version:           2.1.0-security")

    # Security headers middleware
    if "SecurityHeadersMiddleware" not in app_src:
        return _fail("SecurityHeadersMiddleware missing")
    print("  security headers:  present")

    # Stripe via vault helpers
    if "stripe_webhook_secret()" not in app_src or "stripe_secret_key()" not in app_src:
        return _fail("Stripe secrets not loaded via vault helpers")
    print("  stripe secrets:    vault/env helpers")

    print("  running test_security.py ...")
    r = subprocess.run(
        [sys.executable, str(ROOT / "test_security.py")],
        cwd=str(ROOT),
        env={**os.environ},
    )
    if r.returncode != 0:
        return _fail("test_security.py")

    print("PASS security verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
