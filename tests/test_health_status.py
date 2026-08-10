"""Health, root, status, metrics, plans — operational surface."""
from __future__ import annotations

from unittest.mock import patch

import psycopg2
import pytest


class TestRootAndHealth:
    def test_root_ok(self, client):
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["service"] == "echo-crm"
        assert "version" in body
        assert body["status"] == "operational"

    def test_health_public_no_key(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["service"] == "echo-crm"
        assert "checks" in body
        assert "database" in body["checks"]
        assert body["checks"]["database"]["status"] in ("healthy", "unhealthy")

    def test_health_db_healthy_when_pg_up(self, client):
        r = client.get("/health")
        body = r.json()
        # Workspace has Postgres; suite requires it for integration tests.
        assert body["ok"] is True
        assert body["checks"]["database"]["status"] == "healthy"
        assert body["checks"]["database"]["latency_ms"] >= 0

    def test_health_db_failure_mode(self, client, app_module):
        with patch.object(app_module, "_db") as mock_db:
            mock_db.side_effect = psycopg2.OperationalError("connection refused")
            r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert body["checks"]["database"]["status"] == "unhealthy"

    def test_security_headers_present(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("X-Echo-Service") == "echo-crm"
        assert r.headers.get("Cache-Control") == "no-store"


class TestStatusMetricsPlans:
    def test_status_requires_auth(self, client):
        r = client.get("/status")
        assert r.status_code == 401

    def test_status_ok_with_key(self, client, auth_headers):
        r = client.get("/status", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert "contacts" in body
        assert "open_deals" in body
        assert "pipelines" in body
        assert body["status"] == "operational"

    def test_status_db_failure_returns_error_envelope(self, client, auth_headers, app_module):
        # Clear last-good so pure-error path is observable; resilience may still
        # serve a prior warm cache as degraded (ok=True, stale=True).
        try:
            app_module.crm_runtime.cache.set_status(None)  # type: ignore[arg-type]
        except Exception:
            pass
        # Force empty cache by replacing status snapshot with None via internal clear
        cache = app_module.crm_runtime.cache
        with cache._lock:
            cache._search.pop("__status__", None)
            cache._stats = None
        with patch.object(app_module, "_db") as mock_db:
            mock_db.side_effect = RuntimeError("db down")
            r = client.get("/status", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        # Resilience fail-open: error envelope when no cache; degraded last-good otherwise.
        if body.get("ok") is True:
            assert body.get("degraded") is True or body.get("stale") is True
        else:
            assert body["ok"] is False
            assert "error" in body

    def test_metrics_ok(self, client, auth_headers):
        # generate a request so counters move
        client.get("/health")
        r = client.get("/metrics", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["service"] == "echo-crm"
        assert "metrics" in body
        m = body["metrics"]
        assert "uptime_seconds" in m
        assert "requests_total" in m
        assert m["requests_total"] >= 1

    def test_plans_catalog(self, client, auth_headers):
        r = client.get("/plans", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        plans = body["plans"]
        assert len(plans) == 4
        assert {p["id"] for p in plans} == {
            "free",
            "starter",
            "professional",
            "enterprise",
        }
