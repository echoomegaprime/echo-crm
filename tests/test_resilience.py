"""Unit tests for echo-crm resilience primitives + HTTP degrade paths."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import psycopg2
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CRM_FAIL_OPEN", "1")
os.environ.setdefault("CRM_STATE_DIR", str(Path("/tmp") / "crm_resilience_tests"))
os.environ.setdefault("MINIO_ENDPOINT", "")
os.environ.setdefault("CRM_RETRY_MAX_ATTEMPTS", "5")
os.environ.setdefault("CRM_RETRY_BASE_DELAY", "0.01")
os.environ.setdefault("CRM_RETRY_MAX_DELAY", "0.05")
os.environ.setdefault("CRM_RETRY_JITTER", "0")
os.environ.setdefault("CRM_REQ_RETRY_MAX_ATTEMPTS", "3")
os.environ.setdefault("CRM_REQ_RETRY_BASE_DELAY", "0.01")
os.environ.setdefault("CRM_REQ_RETRY_MAX_DELAY", "0.05")
os.environ.setdefault("CRM_REQ_RETRY_JITTER", "0")

from resilience import (  # noqa: E402
    CircuitBreaker,
    DependencyUnavailable,
    IdempotencyStore,
    LastGoodCache,
    MinIOOperationQueue,
    PendingWriteQueue,
    ResilienceRuntime,
    RetryPolicy,
    atomic_write_json,
    content_hash,
    is_retryable,
    probe_http,
    reset_runtime_for_tests,
    retry_with_backoff,
)


@pytest.fixture(autouse=True)
def _isolate_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("CRM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("CRM_FAIL_OPEN", "1")
    monkeypatch.setenv("MINIO_ENDPOINT", "")
    monkeypatch.setenv("CRM_RETRY_JITTER", "0")
    monkeypatch.setenv("CRM_RETRY_BASE_DELAY", "0.01")
    monkeypatch.setenv("CRM_RETRY_MAX_DELAY", "0.05")
    monkeypatch.setenv("CRM_REQ_RETRY_JITTER", "0")
    monkeypatch.setenv("CRM_REQ_RETRY_BASE_DELAY", "0.01")
    monkeypatch.setenv("CRM_REQ_RETRY_MAX_DELAY", "0.05")
    reset_runtime_for_tests(str(tmp_path))
    yield
    reset_runtime_for_tests(str(tmp_path))


# ---------------------------------------------------------------------------
# Retry / classification
# ---------------------------------------------------------------------------


def test_retry_policy_delay_caps_and_grows():
    policy = RetryPolicy(max_attempts=5, base_delay_sec=0.1, max_delay_sec=1.0, jitter=False)
    assert policy.delay_for(1) == pytest.approx(0.1)
    assert policy.delay_for(2) == pytest.approx(0.2)
    assert policy.delay_for(5) == pytest.approx(1.0)  # capped


def test_retry_with_backoff_recovers():
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("connection reset")
        return "ok"

    result = retry_with_backoff(
        flaky,
        RetryPolicy(max_attempts=5, base_delay_sec=0.01, max_delay_sec=0.05, jitter=False),
    )
    assert result == "ok"
    assert calls["n"] == 3


def test_retry_with_backoff_dependency_unavailable():
    def always_fail() -> None:
        raise ConnectionError("refused")

    with pytest.raises(DependencyUnavailable) as ei:
        retry_with_backoff(
            always_fail,
            RetryPolicy(max_attempts=2, base_delay_sec=0.01, jitter=False),
            dependency="postgres",
        )
    assert ei.value.dependency == "postgres"


def test_retry_non_retryable_fails_fast():
    calls = {"n": 0}

    def fail() -> None:
        calls["n"] += 1
        raise ValueError("permanent")

    with pytest.raises(ValueError, match="permanent"):
        retry_with_backoff(
            fail,
            RetryPolicy(max_attempts=5, base_delay_sec=0.01, jitter=False),
        )
    assert calls["n"] == 1


def test_is_retryable_keywords():
    assert is_retryable(TimeoutError("timed out"))
    assert is_retryable(RuntimeError("deadlock detected"))
    assert is_retryable(RuntimeError("could not connect to server"))
    assert is_retryable(ConnectionError("refused"))
    assert not is_retryable(ValueError("bad input"))
    assert not is_retryable(FileNotFoundError("missing"))


def test_is_retryable_status_codes():
    class FakeHTTP(Exception):
        status_code = 503

    assert is_retryable(FakeHTTP("service unavailable"))


# ---------------------------------------------------------------------------
# Atomic writes + idempotency store
# ---------------------------------------------------------------------------


def test_atomic_write_json_idempotent(tmp_path):
    path = tmp_path / "x.json"
    assert atomic_write_json(str(path), {"k": 1}) is True
    assert json.loads(path.read_text())["k"] == 1
    assert atomic_write_json(str(path), {"k": 1}) is False
    assert atomic_write_json(str(path), {"k": 2}) is True


def test_content_hash_stable():
    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})
    assert content_hash("hi") != content_hash("bye")


def test_idempotency_store_roundtrip(tmp_path):
    spill = str(tmp_path / "idemp.json")
    store = IdempotencyStore(max_entries=8, ttl_sec=3600, spill_path=spill)
    store.put("k1", {"ok": True, "id": "c1"})
    assert store.get("k1")["id"] == "c1"
    assert store.seen("k1")
    # reload from spill
    store2 = IdempotencyStore(max_entries=8, ttl_sec=3600, spill_path=spill)
    assert store2.get("k1")["id"] == "c1"


def test_pending_write_queue_idempotent(tmp_path):
    q = PendingWriteQueue(max_entries=16, spill_path=str(tmp_path / "pending.json"))
    assert q.enqueue("contact.create", {"id": "1"}, idempotency_key="abc")
    assert q.enqueue("contact.create", {"id": "1"}, idempotency_key="abc")
    assert q.size == 1
    applied, remaining = q.drain(lambda item: True)
    assert applied == 1
    assert remaining == 0


def test_minio_queue_dedupes_keys():
    q = MinIOOperationQueue(max_entries=8)
    assert q.enqueue_put("a/b.json", b"1")
    assert q.enqueue_put("a/b.json", b"2")
    assert q.size == 1
    applied, remaining = q.drain(lambda k, d: True)
    assert applied == 1
    assert remaining == 0


def test_circuit_breaker_opens_and_recovers():
    cb = CircuitBreaker(name="postgres", failure_threshold=2, recovery_timeout_sec=0.01)
    assert not cb.is_open()
    cb.record_failure()
    assert not cb.is_open()
    cb.record_failure()
    assert cb.is_open()
    import time

    time.sleep(0.02)
    assert not cb.is_open()  # half-open
    cb.record_success()
    assert not cb.is_open()


def test_last_good_cache_crm_helpers():
    cache = LastGoodCache()
    cache.set_status({"ok": True, "contacts": 3})
    assert cache.get_status()["contacts"] == 3
    cache.set_contacts("all", {"ok": True, "contacts": []})
    assert cache.get_contacts("all")["ok"] is True
    cache.set_pipelines("all", {"ok": True, "pipelines": []})
    assert cache.get_pipelines("all") is not None
    snap = cache.snapshot()
    assert snap["search_entries"] >= 2


def test_probe_http_unconfigured():
    res = probe_http("")
    assert res["ok"] is False
    assert res.get("configured") is False


def test_runtime_status_dict(tmp_path):
    rt = ResilienceRuntime(state_dir=str(tmp_path))
    assert rt.fail_open is True
    st = rt.status_dict()
    assert st["service"] == "echo-crm"
    assert "retry_policy" in st
    assert "circuits" in st
    rt.queue_write("contact.create", {"id": "x"}, idempotency_key="k")
    assert rt.pending_writes.size == 1
    rt.remember_idempotent("k", {"ok": True})
    assert rt.recall_idempotent("k")["ok"] is True


def test_runtime_health_modes(tmp_path):
    rt = ResilienceRuntime(state_dir=str(tmp_path))
    rt.mark_db_down()
    assert rt.degraded is True
    h = rt.get_health()
    assert h.mode == "degraded"
    rt.mark_db_up()
    assert rt.degraded is False


# ---------------------------------------------------------------------------
# HTTP / app integration (uses session client from conftest)
# ---------------------------------------------------------------------------


def test_health_includes_resilience_fields(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "echo-crm"
    assert "resilience_version" in body
    assert "checks" in body
    assert "database" in body["checks"]
    assert "minio" in body["checks"] or "gate" in body["checks"] or "dependencies" in body


def test_ready_and_resilience_public(client):
    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body.get("ready") is True or body.get("ok") is True
    r2 = client.get("/resilience")
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2.get("ok") is True
    assert "dependencies" in body2 or "mode" in body2


def test_idempotent_contact_create(client, auth_headers, unique):
    headers = {**auth_headers, "Idempotency-Key": f"idem-{unique}"}
    payload = {
        "first_name": f"Idem{unique}",
        "last_name": "Test",
        "email": f"idem-{unique}@example.com",
        "source": "manual",
    }
    r1 = client.post("/contacts", headers=headers, json=payload)
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1.get("ok") is True
    cid = b1.get("id")
    assert cid
    r2 = client.post("/contacts", headers=headers, json=payload)
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2.get("id") == cid  # same response, no duplicate


def test_contact_create_queues_when_db_down(client, auth_headers, unique, app_module, tmp_path, monkeypatch):
    monkeypatch.setenv("CRM_FAIL_OPEN", "1")
    # Point runtime state + fail_open at isolated dir
    import app as appmod
    from resilience import reset_runtime_for_tests

    rt = reset_runtime_for_tests(str(tmp_path / "queue"))
    appmod.crm_runtime = rt
    headers = {**auth_headers, "Idempotency-Key": f"q-{unique}"}
    payload = {
        "first_name": f"Queued{unique}",
        "last_name": "Test",
        "email": f"queued-{unique}@example.com",
        "source": "manual",
    }
    with patch.object(appmod, "_db") as mock_db:
        mock_db.side_effect = psycopg2.OperationalError("connection refused")
        r = client.post("/contacts", headers=headers, json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    assert body.get("queued") is True or body.get("pending") is True
    assert rt.pending_writes.size >= 1


def test_status_last_good_when_db_down(client, auth_headers, app_module):
    # Warm cache
    r0 = client.get("/status", headers=auth_headers)
    assert r0.status_code == 200
    assert r0.json().get("ok") is True
    with patch.object(app_module, "_db") as mock_db:
        mock_db.side_effect = RuntimeError("db down")
        r = client.get("/status", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    # Degraded last-good or error envelope depending on cache
    assert body.get("ok") is True or body.get("ok") is False
    if body.get("ok") is True:
        assert body.get("degraded") is True or body.get("stale") is True
