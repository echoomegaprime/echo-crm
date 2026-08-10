#!/usr/bin/env python3
"""Security audit tests for echo-crm.

Covers: vault/env secrets (no hardcoded defaults), tiered authz, input validation,
parameterized SQL patterns, Stripe webhook signature verification.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("ECHO_CRM_DEV_MODE", "1")
os.environ.setdefault("PGPASSWORD", "echo")
os.environ.setdefault("PGHOST", "127.0.0.1")
os.environ.setdefault("PGUSER", "echo")
os.environ.setdefault("PGDATABASE", "echo")
os.environ.setdefault("ECHO_CRM_API_KEY", "test-security-key-12345")
os.environ.setdefault("ECHO_API_KEY", "test-security-key-12345")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import security  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app  # noqa: E402


def test_no_hardcoded_pg_password_in_app_source():
    print("\n[TEST] No hardcoded PG password in app.py / service unit...")
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    findings = security.scan_for_hardcoded_secrets(source)
    assert "hardcoded PG password" not in findings, f"found: {findings}"
    assert "hardcoded PG password default" not in findings, f"found: {findings}"
    svc = (ROOT / "echo-crm.service").read_text(encoding="utf-8")
    assert "PGPASSWORD=echo" not in svc, "service unit hardcodes PGPASSWORD=echo"
    findings_svc = security.scan_for_hardcoded_secrets(svc)
    assert "hardcoded PG password in service file" not in findings_svc, findings_svc
    print("  ✓ app.py and service unit have no hardcoded echo password")
    return True


def test_no_unsafe_sql():
    print("\n[TEST] No unsafe SQL construction in app.py...")
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    findings = security.scan_for_unsafe_sql(source)
    assert not findings, f"unsafe SQL: {findings}"
    assert 'execute(f"' not in source and "execute(f'" not in source
    print("  ✓ no f-string / format SQL execute")
    return True


def test_pg_config_requires_secret_outside_dev():
    print("\n[TEST] PG config requires vault/env password...")
    security.clear_secret_cache()
    with patch.dict(
        os.environ,
        {
            "ECHO_CRM_DEV_MODE": "",
            "PGPASSWORD": "",
            "ECHO_CRM_PG_PASSWORD": "",
            "ECHO_CRM_API_KEY": "test-security-key-12345",
            "PGHOST": "127.0.0.1",
            "PGUSER": "echo",
            "PGDATABASE": "echo",
        },
        clear=False,
    ):
        security.clear_secret_cache()
        with patch.object(security, "vault_read_secret", return_value=""):
            try:
                security.pg_config()
                print("  ERROR: should require password")
                return False
            except ValueError as exc:
                assert "PGPASSWORD" in str(exc)
                print("  ✓ pg_config() rejects missing password")
    return True


def test_pg_config_from_env():
    print("\n[TEST] PG config loads from environment...")
    security.clear_secret_cache()
    with patch.dict(
        os.environ,
        {
            "ECHO_CRM_PG_PASSWORD": "vault-sourced-pw",
            "PGHOST": "127.0.0.1",
            "PGUSER": "echo",
            "PGDATABASE": "echo",
            "ECHO_CRM_DEV_MODE": "1",
        },
        clear=False,
    ):
        with patch.object(security, "vault_read_secret", return_value=""):
            security.clear_secret_cache()
            cfg = security.pg_config()
            assert cfg["password"] == "vault-sourced-pw"
            print("  ✓ password loaded from ECHO_CRM_PG_PASSWORD")
    return True


def test_input_validation():
    print("\n[TEST] Input validation...")
    assert security.validate_id("abc123def456") == "abc123def456"
    try:
        security.validate_id("'; DROP TABLE--")
        return False
    except ValueError:
        print("  ✓ rejects SQL-injection-like id")

    assert security.validate_email("user@echo-op.com") == "user@echo-op.com"
    try:
        security.validate_email("not-an-email")
        return False
    except ValueError:
        print("  ✓ rejects invalid email")

    assert security.validate_deal_status("open") == "open"
    try:
        security.validate_deal_status("won'; DROP--")
        return False
    except ValueError:
        print("  ✓ rejects invalid deal status")

    assert security.validate_plan("starter") == "starter"
    try:
        security.validate_plan("free'; DROP--")
        return False
    except ValueError:
        print("  ✓ rejects invalid plan")

    escaped = security.sanitize_like_pattern("100%_evil")
    assert "\\%" in escaped and "\\_" in escaped
    print("  ✓ escapes LIKE wildcards")

    try:
        security.validate_name("evil<script>")
        return False
    except ValueError:
        print("  ✓ rejects angle brackets in names")

    try:
        security.validate_search("bad; DROP--")
        return False
    except ValueError:
        print("  ✓ rejects dangerous search")
    return True


def test_secure_compare_length_oracle():
    print("\n[TEST] secure_compare length-safe...")
    assert security.secure_compare("abc", "abc") is True
    assert security.secure_compare("abc", "abcd") is False
    assert security.secure_compare(None, "x") is False
    assert security.secure_compare("x", None) is False
    print("  ✓ unequal lengths do not raise")
    return True


def test_stripe_signature_verify():
    print("\n[TEST] Stripe webhook signature verification...")
    secret = "whsec_test_secret_key_for_unit_tests"
    payload = b'{"id":"evt_test","type":"checkout.session.completed"}'
    ts = str(int(time.time()))
    signed = f"{ts}.{payload.decode()}"
    mac = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    header = f"t={ts},v1={mac}"
    assert security.verify_stripe_signature(payload, header, secret)
    assert not security.verify_stripe_signature(payload, header, "wrong-secret")
    assert not security.verify_stripe_signature(payload, "t=bad,v1=deadbeef", secret)
    print("  ✓ HMAC verification accepts valid / rejects invalid")
    return True


def test_authz_map():
    print("\n[TEST] Authz map integrity...")
    assert security.ENDPOINT_AUTH["health"] == security.AUTH_PUBLIC
    assert security.ENDPOINT_AUTH["root"] == security.AUTH_PUBLIC
    assert security.ENDPOINT_AUTH["webhooks.stripe"] == security.AUTH_WEBHOOK
    assert security.ENDPOINT_AUTH["plans.upgrade"] == security.AUTH_ADMIN
    assert security.ENDPOINT_AUTH["admin.migrate_stripe"] == security.AUTH_ADMIN
    assert security.ENDPOINT_AUTH["internal.weekly_digest"] == security.AUTH_ADMIN
    assert security.ENDPOINT_AUTH["contacts.list"] == security.AUTH_READ
    assert security.ENDPOINT_AUTH["contacts.create"] == security.AUTH_WRITE
    for ep, tier in security.ENDPOINT_AUTH.items():
        assert tier in (
            security.AUTH_PUBLIC,
            security.AUTH_READ,
            security.AUTH_WRITE,
            security.AUTH_ADMIN,
            security.AUTH_WEBHOOK,
        ), f"{ep}={tier}"
    print(f"  ✓ {len(security.ENDPOINT_AUTH)} endpoints mapped")
    return True


def test_resolve_endpoint():
    print("\n[TEST] Path → endpoint resolver...")
    assert security.resolve_endpoint("GET", "/health") == "health"
    assert security.resolve_endpoint("GET", "/contacts") == "contacts.list"
    assert security.resolve_endpoint("POST", "/contacts") == "contacts.create"
    assert security.resolve_endpoint("DELETE", "/contacts/abc") == "contacts.delete"
    assert security.resolve_endpoint("POST", "/deals/x/move") == "deals.move"
    assert security.resolve_endpoint("POST", "/webhooks/stripe") == "webhooks.stripe"
    assert security.resolve_endpoint("POST", "/admin/migrate-stripe") == "admin.migrate_stripe"
    print("  ✓ resolver covers key routes")
    return True


def test_authz_http_layer():
    print("\n[TEST] HTTP authz layer...")
    security.clear_secret_cache()
    with patch.dict(
        os.environ,
        {
            "ECHO_CRM_DEV_MODE": "",
            "ECHO_CRM_API_KEY": "test-security-key-12345",
            "ECHO_API_KEY": "test-security-key-12345",
            "PGPASSWORD": "echo",
            "PGHOST": "127.0.0.1",
            "PGUSER": "echo",
            "PGDATABASE": "echo",
        },
        clear=False,
    ):
        security.clear_secret_cache()
        client = TestClient(app.app)

        r = client.get("/health")
        assert r.status_code == 200, r.text
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        print("  ✓ /health is public + security headers")

        r = client.get("/")
        assert r.status_code == 200, r.text
        print("  ✓ / is public")

        r = client.get("/plans")
        assert r.status_code == 401, r.text
        print("  ✓ /plans rejects missing API key")

        r = client.get("/plans", headers={"X-Echo-API-Key": "wrong-key"})
        assert r.status_code == 401, r.text
        print("  ✓ /plans rejects wrong API key")

        r = client.get("/plans", headers={"X-Echo-API-Key": "test-security-key-12345"})
        assert r.status_code in (200, 500), r.text
        print("  ✓ /plans accepts valid API key")

        r = client.get("/contacts")
        assert r.status_code == 401, r.text
        print("  ✓ /contacts requires auth")

        r = client.post("/admin/migrate-stripe")
        assert r.status_code == 401, r.text
        print("  ✓ /admin/migrate-stripe requires auth")

        r = client.post("/plans/upgrade", json={"tenant_id": "t1", "plan_id": "starter"})
        assert r.status_code == 401, r.text
        print("  ✓ /plans/upgrade requires admin auth")

        r = client.post("/internal/cron/weekly-digest")
        assert r.status_code == 401, r.text
        print("  ✓ weekly-digest requires admin auth")

        # Invalid id rejected after auth
        r = client.get(
            "/contacts/'; DROP--",
            headers={"X-Echo-API-Key": "test-security-key-12345"},
        )
        assert r.status_code == 400, r.text
        print("  ✓ invalid contact id rejected")
    return True


def test_version_security_tag():
    print("\n[TEST] Version reflects a completed hardening pass...")
    # The version string moved from the 2.1.0-security checkpoint (this
    # test's original assertion) to 2.2.0-resilience after a later
    # resilience pass was layered on top of the same hardened baseline --
    # both tags are valid evidence of hardening, so accept either rather
    # than pin to one that inevitably goes stale on the next pass.
    hardening_tags = ("-security", "-resilience")
    assert app.CRM_VERSION.endswith(hardening_tags), (
        f"CRM_VERSION={app.CRM_VERSION!r} does not end with any of {hardening_tags}"
    )
    print(f"  ✓ version={app.CRM_VERSION}")
    return True


def test_vault_paths_present():
    print("\n[TEST] vault_paths.json inventory...")
    import json

    data = json.loads((ROOT / "vault_paths.json").read_text(encoding="utf-8"))
    assert data["service"] == "echo-crm"
    keys = {k["vault_key"] for k in data["keys"]}
    assert "PGPASSWORD" in keys
    assert "ECHO_CRM_API_KEY" in keys
    print("  ✓ vault map complete")
    return True


def main() -> int:
    tests = [
        test_no_hardcoded_pg_password_in_app_source,
        test_no_unsafe_sql,
        test_pg_config_requires_secret_outside_dev,
        test_pg_config_from_env,
        test_input_validation,
        test_secure_compare_length_oracle,
        test_stripe_signature_verify,
        test_authz_map,
        test_resolve_endpoint,
        test_authz_http_layer,
        test_version_security_tag,
        test_vault_paths_present,
    ]
    passed = failed = 0
    for t in tests:
        try:
            ok = t()
            if ok:
                passed += 1
            else:
                failed += 1
                print(f"FAIL {t.__name__}")
        except Exception as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
            import traceback

            traceback.print_exc()
    print(f"\n=== {passed}/{passed + failed} security tests passed ===")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
