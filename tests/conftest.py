"""Shared fixtures for the echo-crm pytest suite.

Uses real Postgres (schema ``echo_crm``) for integration fidelity.
Secrets and API key come from env; no production defaults are hardcoded
in application code. Tests create uniquely-named entities and clean up
created primary keys via the ``tracker`` fixture.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Generator

import pytest

# Force env BEFORE importing app (module-level secrets / FastAPI deps).
os.environ.setdefault("PGHOST", "127.0.0.1")
os.environ.setdefault("PGPORT", "5432")
os.environ.setdefault("PGUSER", "echo")
os.environ.setdefault("PGPASSWORD", "echo")
os.environ.setdefault("PGDATABASE", "echo")
os.environ["ECHO_CRM_DEV_MODE"] = "1"
os.environ["ECHO_CRM_API_KEY"] = "pytest-echo-crm-api-key-secure-32c"
os.environ["ECHO_API_KEY"] = os.environ["ECHO_CRM_API_KEY"]
# Resilience defaults for the suite (fast retries, fail-open, isolated state).
os.environ.setdefault("CRM_FAIL_OPEN", "1")
os.environ.setdefault("CRM_STATE_DIR", "/tmp/echo-crm-pytest-state")
os.environ.setdefault("CRM_RETRY_JITTER", "0")
os.environ.setdefault("CRM_RETRY_BASE_DELAY", "0.01")
os.environ.setdefault("CRM_RETRY_MAX_DELAY", "0.05")
os.environ.setdefault("CRM_REQ_RETRY_JITTER", "0")
os.environ.setdefault("CRM_REQ_RETRY_BASE_DELAY", "0.01")
os.environ.setdefault("CRM_REQ_RETRY_MAX_DELAY", "0.05")
os.environ.setdefault("MINIO_ENDPOINT", "")
# Keep optional integrations off unless a test enables them.
os.environ.pop("ECHO_ENGINE_RUNTIME_URL", None)
os.environ.pop("ECHO_SHARED_BRAIN_URL", None)
os.environ.pop("STRIPE_SECRET_KEY", None)
os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
os.environ.pop("ECHO_CRM_STRIPE_WEBHOOK_SECRET", None)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import security as secmod  # noqa: E402

secmod.clear_secret_cache()

import app as appmod  # noqa: E402


@pytest.fixture(scope="session")
def api_key() -> str:
    return os.environ["ECHO_CRM_API_KEY"]


@pytest.fixture(scope="session")
def auth_headers(api_key: str) -> dict[str, str]:
    return {"X-Echo-API-Key": api_key, "Content-Type": "application/json"}


@pytest.fixture(scope="session")
def app_module():
    secmod.clear_secret_cache()
    return appmod


@pytest.fixture(scope="session")
def client(app_module):
    """FastAPI TestClient with lifespan (runs schema DDL on startup)."""
    from fastapi.testclient import TestClient

    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture
def unique(api_key: str) -> str:
    """Short unique token for entity names/emails per test."""
    return uuid.uuid4().hex[:12]


class EntityTracker:
    """Track created entity ids for best-effort cleanup."""

    def __init__(self) -> None:
        self.contacts: list[str] = []
        self.companies: list[str] = []
        self.deals: list[str] = []
        self.pipelines: list[str] = []
        self.stages: list[str] = []
        self.activities: list[str] = []
        self.notes: list[str] = []
        self.tags: list[str] = []
        self.rules: list[str] = []
        self.email_events: list[str] = []

    def add(self, kind: str, entity_id: str | None) -> str | None:
        if not entity_id:
            return entity_id
        bucket = getattr(self, kind, None)
        if isinstance(bucket, list):
            bucket.append(entity_id)
        return entity_id


@pytest.fixture
def tracker(client, auth_headers) -> Generator[EntityTracker, None, None]:
    t = EntityTracker()
    yield t
    # Cleanup in FK-safe order (best effort; ignore failures).
    for did in t.deals:
        try:
            client.delete(f"/deals/{did}", headers=auth_headers)
        except Exception:
            pass
    for aid in t.activities:
        try:
            client.delete(f"/activities/{aid}", headers=auth_headers)
        except Exception:
            pass
    for nid in t.notes:
        try:
            client.delete(f"/notes/{nid}", headers=auth_headers)
        except Exception:
            pass
    for cid in t.contacts:
        try:
            client.delete(f"/contacts/{cid}", headers=auth_headers)
        except Exception:
            pass
    for cid in t.companies:
        try:
            client.delete(f"/companies/{cid}", headers=auth_headers)
        except Exception:
            pass
    for rid in t.rules:
        try:
            client.delete(f"/lead-scoring/rules/{rid}", headers=auth_headers)
        except Exception:
            pass
    for tid in t.tags:
        try:
            client.delete(f"/tags/{tid}", headers=auth_headers)
        except Exception:
            pass
    for sid in t.stages:
        try:
            client.delete(f"/stages/{sid}", headers=auth_headers)
        except Exception:
            pass
    for pid in t.pipelines:
        try:
            client.delete(f"/pipelines/{pid}", headers=auth_headers)
        except Exception:
            pass


@pytest.fixture
def default_pipeline(client, auth_headers) -> dict[str, Any]:
    """Return the default pipeline + first stage (created by startup seed)."""
    r = client.get("/pipelines", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    pipelines = body.get("pipelines") or []
    assert pipelines, "expected default pipeline from startup seed"
    pid = pipelines[0]["id"]
    r2 = client.get(f"/pipelines/{pid}", headers=auth_headers)
    assert r2.status_code == 200, r2.text
    data = r2.json()
    stages = data.get("stages") or []
    assert stages, "expected default stages"
    return {
        "pipeline_id": pid,
        "stage_id": stages[0]["id"],
        "stages": stages,
        "pipeline": data.get("pipeline") or pipelines[0],
    }


@pytest.fixture
def make_contact(client, auth_headers, tracker, unique):
    def _make(**overrides: Any) -> dict[str, Any]:
        payload = {
            "first_name": f"PyT{unique}",
            "last_name": "Contact",
            "email": f"pytest.{unique}@example.com",
            "source": "manual",
            "lead_status": "new",
        }
        payload.update(overrides)
        r = client.post("/contacts", headers=auth_headers, json=payload)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True
        tracker.add("contacts", body["id"])
        return {"id": body["id"], "payload": payload, "response": body}

    return _make


@pytest.fixture
def make_company(client, auth_headers, tracker, unique):
    def _make(**overrides: Any) -> dict[str, Any]:
        payload = {
            "name": f"PyCo {unique}",
            "domain": f"{unique}.example.com",
            "industry": "software",
        }
        payload.update(overrides)
        r = client.post("/companies", headers=auth_headers, json=payload)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True
        tracker.add("companies", body["id"])
        return {"id": body["id"], "payload": payload, "response": body}

    return _make


@pytest.fixture
def make_deal(client, auth_headers, tracker, default_pipeline, unique):
    def _make(**overrides: Any) -> dict[str, Any]:
        payload = {
            "title": f"PyDeal {unique}",
            "pipeline_id": default_pipeline["pipeline_id"],
            "stage_id": default_pipeline["stage_id"],
            "value": 1000.0,
            "currency": "USD",
            "status": "open",
        }
        payload.update(overrides)
        r = client.post("/deals", headers=auth_headers, json=payload)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True
        tracker.add("deals", body["id"])
        return {"id": body["id"], "payload": payload, "response": body}

    return _make
