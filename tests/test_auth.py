"""Authz surface: public vs read/write, bad keys, path resolution."""
from __future__ import annotations

import pytest

import security as sec


class TestAuthHTTP:
    def test_public_routes_without_key(self, client):
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 200

    def test_read_routes_require_key(self, client):
        for path in ("/status", "/metrics", "/pipelines", "/contacts", "/plans"):
            r = client.get(path)
            assert r.status_code == 401, path

    def test_write_routes_require_key(self, client):
        r = client.post("/contacts", json={"first_name": "X"})
        assert r.status_code == 401

    def test_wrong_key_rejected(self, client):
        r = client.get(
            "/plans",
            headers={"X-Echo-API-Key": "definitely-wrong-key-value"},
        )
        assert r.status_code == 401

    def test_correct_key_accepted(self, client, auth_headers):
        r = client.get("/plans", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_oversized_key_rejected(self, client):
        r = client.get(
            "/plans",
            headers={"X-Echo-API-Key": "k" * 3000},
        )
        assert r.status_code == 401


class TestResolveEndpoint:
    def test_exact_routes(self):
        assert sec.resolve_endpoint("GET", "/") == "root"
        assert sec.resolve_endpoint("GET", "/health") == "health"
        assert sec.resolve_endpoint("POST", "/contacts") == "contacts.create"
        assert sec.resolve_endpoint("GET", "/deals/board") == "deals.board"
        assert sec.resolve_endpoint("POST", "/webhooks/stripe") == "webhooks.stripe"

    def test_path_params(self):
        assert sec.resolve_endpoint("GET", "/contacts/abc123") == "contacts.get"
        assert sec.resolve_endpoint("DELETE", "/deals/xyz") == "deals.delete"
        assert sec.resolve_endpoint("POST", "/deals/xyz/move") == "deals.move"
        assert sec.resolve_endpoint("GET", "/pipelines/p1/stages") == "stages.list"

    def test_unknown_defaults_to_write(self):
        assert sec.resolve_endpoint("GET", "/no/such/path") == "unknown.write"

    def test_check_auth_public(self):
        ctx = sec._check_auth("health", None)
        assert ctx["authenticated"] is True
        assert ctx["tier"] == sec.AUTH_PUBLIC

    def test_check_auth_missing_key(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            sec._check_auth("contacts.list", None)
        assert ei.value.status_code == 401


class TestFleetKeyAcceptance:
    """Gate proxies with fleet SOVEREIGN_KEY ≠ process ECHO_CRM_API_KEY."""

    def test_accepted_api_keys_includes_service_and_fleet(
        self, monkeypatch, api_key
    ):
        sec.clear_secret_cache()
        monkeypatch.setenv("ECHO_CRM_API_KEY", api_key)
        monkeypatch.setenv("SOVEREIGN_KEY", "fleet-sovereign-key-for-gate-proxy")
        monkeypatch.delenv("ECHO_ACCEPTED_API_KEYS", raising=False)
        keys = sec.accepted_api_keys()
        assert api_key in keys
        assert "fleet-sovereign-key-for-gate-proxy" in keys

    def test_check_auth_accepts_fleet_key(self, monkeypatch, api_key):
        sec.clear_secret_cache()
        monkeypatch.setenv("ECHO_CRM_API_KEY", api_key)
        monkeypatch.setenv("SOVEREIGN_KEY", "fleet-sovereign-key-for-gate-proxy")
        ctx = sec._check_auth(
            "deals.list", "fleet-sovereign-key-for-gate-proxy"
        )
        assert ctx["authenticated"] is True
        assert ctx["principal"] == "api_key"

    def test_check_auth_accepts_service_key(self, monkeypatch, api_key):
        sec.clear_secret_cache()
        monkeypatch.setenv("ECHO_CRM_API_KEY", api_key)
        ctx = sec._check_auth("deals.list", api_key)
        assert ctx["authenticated"] is True

    def test_check_auth_accepts_extra_csv(self, monkeypatch, api_key):
        sec.clear_secret_cache()
        monkeypatch.setenv("ECHO_CRM_API_KEY", api_key)
        monkeypatch.setenv("ECHO_ACCEPTED_API_KEYS", "extra-a, extra-b")
        monkeypatch.delenv("SOVEREIGN_KEY", raising=False)
        ctx = sec._check_auth("deals.list", "extra-b")
        assert ctx["authenticated"] is True

    def test_http_deals_list_with_fleet_key(self, client, monkeypatch, api_key):
        """End-to-end: /deals must accept a non-service fleet key (gate shape)."""
        sec.clear_secret_cache()
        # client fixture already has service key in env; add fleet key
        fleet = "fleet-http-smoke-key-324c3a"
        monkeypatch.setenv("SOVEREIGN_KEY", fleet)
        sec.clear_secret_cache()
        r = client.get("/deals", headers={"X-Echo-API-Key": fleet})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True
        assert "deals" in body
