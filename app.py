#!/usr/bin/env python3
"""Echo CRM — FORGE migration of the legacy CF worker `echo-crm`.

CF-migrate echo-crm -> Echo FORGE service (ShadowGlass template).
Reconstructs the full route surface and business logic faithfully:
pipelines, contacts, companies, deals (with board + move), activities, notes,
tags, email-events, lead-scoring (rules + AI boost via engine), analytics,
import/export (json), activity-log, Stripe plans + webhooks + upgrade,
weekly digest (cron endpoint).

NO CLOUDFLARE: D1/KV (no KV usage in core paths) -> Postgres (schema echo_crm).
R2 not used. Service bindings (ENGINE_RUNTIME, SHARED_BRAIN) -> optional HTTP
via env ECHO_ENGINE_RUNTIME_URL / ECHO_SHARED_BRAIN_URL (best-effort, matches
original try/catch).

Run: uvicorn app:app --host 0.0.0.0 --port 8142   (systemd: echo-crm)
Auth: X-Echo-API-Key via tiered authz (security.py). Secrets from vault/env
(no hardcoded credentials). SQL fully parameterized. Version 2.2.0-resilience.
Structured JSON logs + Prometheus requests_total/errors_total + /health status ok.
Resilience: graceful degradation (DB/MinIO/gate), Idempotency-Key ledger,
pending write queue, exponential retry/backoff + circuit breakers (resilience.py).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional, Generator, Annotated, Callable
from collections import defaultdict

import psycopg2  # type: ignore[import-untyped]
import psycopg2.extras  # type: ignore[import-untyped]
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

import security as _sec
from security import (
    api_key as _security_api_key,
    auth_dependency,
    path_auth_dependency,
    pg_config,
    require_auth as security_require_auth,
    sanitize as sec_sanitize,
    sanitize_like_pattern,
    secure_compare,
    stripe_secret_key,
    stripe_webhook_secret,
    validate_activity_type,
    validate_amount,
    validate_country,
    validate_currency,
    validate_deal_status,
    validate_email,
    validate_entity_type,
    validate_id,
    validate_json_object,
    validate_lead_status,
    validate_limit,
    validate_name,
    validate_offset,
    validate_operator,
    validate_optional_id,
    validate_phone,
    validate_plan,
    validate_position,
    validate_probability,
    validate_score,
    validate_search,
    validate_source,
    validate_text,
    verify_stripe_signature,
)

import logging_config
import metrics as prom_metrics
from resilience import (
    RESILIENCE_VERSION,
    DependencyUnavailable,
    PendingWrite,
    is_retryable,
    pg_connect_kwargs as resilience_pg_kwargs,
    reset_runtime_for_tests,
    retry_with_backoff,
    runtime as crm_runtime,
)

# Structured JSON logging -> stdout + O:\ECHO_OMEGA_PRIME\logs\echo-crm.log
logger = logging_config.configure()


class MetricsCollector:
    """Track operational metrics for fleet observability."""
    def __init__(self) -> None:
        self.request_total = defaultdict(int)
        self.request_errors = defaultdict(int)
        self.request_duration_ms: list[float] = []
        self.db_queries_total = 0
        self.db_errors_total = 0
        self.last_db_check_ok = True
        self.last_db_check_time = time.time()
        self.start_time = time.time()

    def record_request(self, method: str, path: str, status_code: int, duration_ms: float) -> None:
        """Record an HTTP request method, path, status, and latency.

        Args:
            method: HTTP method.
            path: Request path (template or raw).
            status: HTTP status code.
            latency_ms: Request duration in milliseconds.
        """
        key = f"{method}:{path}"
        self.request_total[key] += 1
        self.request_duration_ms.append(duration_ms)
        if status_code >= 400:
            self.request_errors[key] += 1

    def record_db_query(self, success: bool) -> None:
        """Record a database query outcome and latency sample.

        Args:
            name: Logical query label (e.g. health_check, select_contacts).
            success: Whether the query completed without error.
            latency_ms: Query duration in milliseconds.
            error: Optional error class/message when success is False.
        """
        self.db_queries_total += 1
        if not success:
            self.db_errors_total += 1
        self.last_db_check_time = time.time()
        self.last_db_check_ok = success

    def get_metrics(self) -> dict[str, Any]:
        """Return a snapshot of in-process request and database metrics.

        Returns:
            Dict of counters, latency stats, and error tallies for /metrics.
        """
        uptime_sec = time.time() - self.start_time
        avg_duration_ms = (
            sum(self.request_duration_ms) / len(self.request_duration_ms)
            if self.request_duration_ms else 0
        )
        err_total = sum(self.request_errors.values())
        return {
            "uptime_seconds": uptime_sec,
            "requests_total": sum(self.request_total.values()),
            "requests_by_path": dict(self.request_total),
            "request_errors_total": err_total,
            "errors_total": err_total,
            "errors_by_path": dict(self.request_errors),
            "avg_request_duration_ms": avg_duration_ms,
            "db_queries_total": self.db_queries_total,
            "db_errors_total": self.db_errors_total,
            "db_healthy": self.last_db_check_ok,
        }


metrics = MetricsCollector()

def _get_db_config() -> dict[str, Any]:
    """Get database config via security.pg_config (vault/env, no hardcoded defaults)."""
    return pg_config()


# Lazy DB config — resolved at connection time so tests can set env before first use.
ENGINE_URL = os.environ.get("ECHO_ENGINE_RUNTIME_URL", "")
BRAIN_URL = os.environ.get("ECHO_SHARED_BRAIN_URL", "")
CRM_VERSION = os.environ.get(
    "ECHO_CRM_VERSION",
    os.environ.get("CRM_VERSION", "2.2.0-resilience"),
)

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS echo_crm;

CREATE TABLE IF NOT EXISTS echo_crm.pipelines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_default INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.deal_stages (
    id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL REFERENCES echo_crm.pipelines(id),
    name TEXT NOT NULL,
    position INTEGER DEFAULT 0,
    probability REAL DEFAULT 0,
    rotting_days INTEGER DEFAULT 30,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.contacts (
    id TEXT PRIMARY KEY,
    company_id TEXT,
    first_name TEXT NOT NULL,
    last_name TEXT,
    email TEXT,
    phone TEXT,
    title TEXT,
    source TEXT DEFAULT 'manual',
    lead_score INTEGER DEFAULT 0,
    lead_status TEXT DEFAULT 'new',
    tags TEXT DEFAULT '[]',
    custom_fields TEXT DEFAULT '{}',
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    country TEXT DEFAULT 'US',
    notes TEXT,
    last_contacted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.companies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT,
    industry TEXT,
    size TEXT,
    revenue TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    country TEXT DEFAULT 'US',
    tags TEXT DEFAULT '[]',
    custom_fields TEXT DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.deals (
    id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL REFERENCES echo_crm.pipelines(id),
    stage_id TEXT NOT NULL REFERENCES echo_crm.deal_stages(id),
    contact_id TEXT REFERENCES echo_crm.contacts(id),
    company_id TEXT REFERENCES echo_crm.companies(id),
    title TEXT NOT NULL,
    value REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    probability REAL DEFAULT 0,
    expected_close_date TIMESTAMPTZ,
    actual_close_date TIMESTAMPTZ,
    status TEXT DEFAULT 'open',
    lost_reason TEXT,
    won_reason TEXT,
    owner TEXT,
    tags TEXT DEFAULT '[]',
    custom_fields TEXT DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.activities (
    id TEXT PRIMARY KEY,
    contact_id TEXT REFERENCES echo_crm.contacts(id),
    company_id TEXT REFERENCES echo_crm.companies(id),
    deal_id TEXT REFERENCES echo_crm.deals(id),
    type TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT,
    due_date TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_minutes INTEGER,
    is_done INTEGER DEFAULT 0,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.notes (
    id TEXT PRIMARY KEY,
    contact_id TEXT REFERENCES echo_crm.contacts(id),
    company_id TEXT REFERENCES echo_crm.companies(id),
    deal_id TEXT REFERENCES echo_crm.deals(id),
    body TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.tags (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    color TEXT DEFAULT '#6366f1',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.email_events (
    id TEXT PRIMARY KEY,
    contact_id TEXT REFERENCES echo_crm.contacts(id),
    deal_id TEXT,
    type TEXT NOT NULL,
    subject TEXT,
    opened_at TIMESTAMPTZ,
    clicked_at TIMESTAMPTZ,
    bounced INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.lead_scoring_rules (
    id TEXT PRIMARY KEY,
    field TEXT NOT NULL,
    operator TEXT NOT NULL,
    value TEXT NOT NULL,
    score INTEGER NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.imports (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    file_name TEXT,
    total_rows INTEGER DEFAULT 0,
    imported INTEGER DEFAULT 0,
    skipped INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.activity_log (
    id SERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_crm.tenants (
    id TEXT PRIMARY KEY,
    name TEXT,
    plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes (match original + PG friendly)
CREATE INDEX IF NOT EXISTS idx_crm_contacts_company ON echo_crm.contacts(company_id);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_email ON echo_crm.contacts(email);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_lead_status ON echo_crm.contacts(lead_status);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_lead_score ON echo_crm.contacts(lead_score DESC);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_source ON echo_crm.contacts(source);
CREATE INDEX IF NOT EXISTS idx_crm_companies_domain ON echo_crm.companies(domain);
CREATE INDEX IF NOT EXISTS idx_crm_companies_industry ON echo_crm.companies(industry);
CREATE INDEX IF NOT EXISTS idx_crm_deals_pipeline ON echo_crm.deals(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_crm_deals_stage ON echo_crm.deals(stage_id);
CREATE INDEX IF NOT EXISTS idx_crm_deals_contact ON echo_crm.deals(contact_id);
CREATE INDEX IF NOT EXISTS idx_crm_deals_company ON echo_crm.deals(company_id);
CREATE INDEX IF NOT EXISTS idx_crm_deals_status ON echo_crm.deals(status);
CREATE INDEX IF NOT EXISTS idx_crm_deals_value ON echo_crm.deals(value DESC);
CREATE INDEX IF NOT EXISTS idx_crm_activities_contact ON echo_crm.activities(contact_id);
CREATE INDEX IF NOT EXISTS idx_crm_activities_deal ON echo_crm.activities(deal_id);
CREATE INDEX IF NOT EXISTS idx_crm_activities_type ON echo_crm.activities(type);
CREATE INDEX IF NOT EXISTS idx_crm_activities_due ON echo_crm.activities(due_date);
CREATE INDEX IF NOT EXISTS idx_crm_notes_contact ON echo_crm.notes(contact_id);
CREATE INDEX IF NOT EXISTS idx_crm_notes_deal ON echo_crm.notes(deal_id);
CREATE INDEX IF NOT EXISTS idx_crm_email_events_contact ON echo_crm.email_events(contact_id);
CREATE INDEX IF NOT EXISTS idx_crm_stages_pipeline ON echo_crm.deal_stages(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_crm_stages_position ON echo_crm.deal_stages(position);
CREATE INDEX IF NOT EXISTS idx_crm_activity_log_entity ON echo_crm.activity_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_crm_activity_log_time ON echo_crm.activity_log(created_at DESC);
"""

# Stripe Plans (exact match to worker)
PlanDict = dict[str, Any]
CRM_PLANS: list[PlanDict] = [
    {"id": "free", "name": "Free", "price": 0, "interval": "month",
     "features": ["50 contacts", "1 pipeline", "Basic analytics", "Email support"],
     "limits": {"contacts": 50, "pipelines": 1, "deals": 20}},
    {"id": "starter", "name": "Starter", "price": 29.99, "interval": "month",
     "features": ["500 contacts", "3 pipelines", "Lead scoring", "Import/export", "Priority support"],
     "limits": {"contacts": 500, "pipelines": 3, "deals": 200}},
    {"id": "professional", "name": "Professional", "price": 79.99, "interval": "month",
     "features": ["5,000 contacts", "10 pipelines", "AI lead scoring", "Custom fields", "API access", "Integrations"],
     "limits": {"contacts": 5000, "pipelines": 10, "deals": 2000}},
    {"id": "enterprise", "name": "Enterprise", "price": 199.99, "interval": "month",
     "features": ["Unlimited contacts", "Unlimited pipelines", "Dedicated support", "Custom integrations", "White-label", "SLA"],
     "limits": {"contacts": -1, "pipelines": -1, "deals": -1}},
]


def uid() -> str:
    """Generate a 16-character hex unique identifier for CRM entity primary keys.

    Returns:
        A random UUID4 hex string truncated to 16 characters.
    """
    import uuid
    return uuid.uuid4().hex[:16]


def now_iso() -> str:
    """Return the current UTC timestamp as an ISO-like string (space separator).

    Returns:
        Timestamp string suitable for Postgres TIMESTAMPTZ text columns.
    """
    return datetime.utcnow().isoformat(sep=" ", timespec="seconds")


def log(level: str, msg: str, extra: dict[str, Any] | None = None) -> None:
    """Emit a structured JSON log line for the echo-crm service.

    Uses ``logging_config.JsonFormatter`` so each line is a single JSON object
    with ts/level/service/version plus any *extra* context fields.

    Args:
        level: Log severity (info, warn, error, debug).
        msg: Human-readable message.
        extra: Optional key/value fields merged into the JSON payload.
    """
    context: dict[str, Any] = {"service_version": CRM_VERSION}
    if extra:
        context.update(extra)
    logging_config.log_event(logger, level, msg, **context)


CORS_HEADERS = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Echo-API-Key",
}


def ok(data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a successful API envelope with ``ok: True``.

    Args:
        data: Optional fields to merge into the response body.

    Returns:
        Dict starting with ``ok: True`` plus any provided fields.
    """
    return {"ok": True, **(data or {})}


def fail(error: str, status: int = 400) -> JSONResponse:
    """Build a failure API envelope with ``ok: False``.

    Args:
        error: Human-readable error message.
        status: Suggested HTTP status (documented for callers; body always includes error).

    Returns:
        Dict with ``ok: False`` and ``error``.
    """
    return JSONResponse({"ok": False, "error": error}, status_code=status)


def require_body(body: Any, *fields: str) -> Optional[str]:
    """Validate that *body* is a dict containing the required fields.

    Args:
        body: Parsed JSON body (any type).
        *fields: Required top-level keys.

    Returns:
        Error string if invalid/missing, otherwise None.
    """
    if not body or not isinstance(body, dict):
        return "Missing request body"
    for f in fields:
        if body.get(f) is None:
            return f"Missing required field: {f}"
    return None


def paginate_params(request: Request) -> tuple[int, int]:
    """Parse limit/offset query parameters with safe bounds.

    Args:
        request: Incoming FastAPI/Starlette request.

    Returns:
        Tuple of (limit, offset) where limit is clamped to 1..200.
    """
    q = request.query_params
    try:
        raw_limit = int(q.get("limit", 50) or 50)
    except (TypeError, ValueError):
        raw_limit = 50
    try:
        raw_offset = int(q.get("offset", 0) or 0)
    except (TypeError, ValueError):
        raw_offset = 0
    return validate_limit(raw_limit), validate_offset(raw_offset)


def sanitize(val: Any, max_len: int = 2000) -> str:
    """Coerce a value to a safe string and strip control characters."""
    return sec_sanitize(val, max_len)


def _connect_kwargs() -> dict[str, Any]:
    """Merge vault/env pg_config with resilience connect_timeout options."""
    cfg = dict(pg_config())
    res = resilience_pg_kwargs()
    # Prefer vault/env credentials from security.pg_config; inject timeouts.
    cfg["connect_timeout"] = res.get("connect_timeout", 5)
    if "options" in res and "options" not in cfg:
        cfg["options"] = res["options"]
    return cfg


def _raw_connect() -> Any:
    """Open a raw Postgres connection (no retry). Used by resilience probes."""
    return psycopg2.connect(**_connect_kwargs())


def _connect_with_retry() -> Any:
    """Open Postgres with request-path exponential backoff."""

    def _once() -> Any:
        if crm_runtime.circuit_pg.is_open():
            raise DependencyUnavailable("postgres", "circuit_open")
        return _raw_connect()

    def _on_retry(attempt: int, exc: BaseException, delay: float) -> None:
        crm_runtime._inc("db_retries")
        log(
            "warn",
            "postgres connect retry",
            {
                "attempt": attempt,
                "delay_sec": round(delay, 3),
                "error": str(exc)[:160],
            },
        )

    try:
        con = retry_with_backoff(
            _once,
            crm_runtime.request_retry,
            on_retry=_on_retry,
            op_name="pg_connect",
            dependency="postgres",
        )
        crm_runtime.circuit_pg.record_success()
        return con
    except Exception:
        crm_runtime.mark_db_down()
        raise


@contextmanager
def _db() -> Generator[Any, None, None]:
    """Postgres connection context with retry/backoff and metrics."""
    con = _connect_with_retry()
    try:
        yield con
        con.commit()
        metrics.record_db_query(True)
        prom_metrics.record_db_query(True)
        crm_runtime.mark_db_up()
    except Exception as exc:
        metrics.record_db_query(False)
        prom_metrics.record_db_query(False)
        try:
            con.rollback()
        except Exception:
            pass
        if is_retryable(exc):
            crm_runtime.mark_db_down()
        raise
    finally:
        try:
            con.close()
        except Exception:
            pass


def _idempotency_lookup(key: Optional[str]) -> Optional[dict[str, Any]]:
    if not key or not str(key).strip():
        return None
    return crm_runtime.recall_idempotent(str(key).strip())


def _idempotency_store(key: Optional[str], body: dict[str, Any]) -> None:
    if key and str(key).strip():
        crm_runtime.remember_idempotent(str(key).strip(), body)


def _queue_or_fail(
    kind: str,
    payload: dict[str, Any],
    *,
    soft_key: Optional[str] = None,
    entity_hint: Optional[str] = None,
) -> dict[str, Any] | JSONResponse:
    """When DB is down and fail_open is set, queue write and return accepted."""
    if not crm_runtime.fail_open:
        return fail("database unavailable", 503)
    qkey = soft_key or crm_runtime.idempotency.make_key(kind, payload)
    queued = crm_runtime.queue_write(kind, payload, idempotency_key=qkey)
    if not queued:
        return fail("pending write queue full", 503)
    body = ok(
        {
            "queued": True,
            "degraded": True,
            "kind": kind,
            "idempotency_key": soft_key or qkey,
            "id": entity_hint or payload.get("id"),
            "pending": True,
        }
    )
    if soft_key:
        _idempotency_store(soft_key, body)
    return body


def _apply_pending_write(item: PendingWrite) -> bool:
    """Replay a queued CRM write against Postgres. Returns True on success.

    Payload shape (preferred)::
        {
          "id": str,
          "sql": str,            # INSERT … ON CONFLICT DO NOTHING
          "params": list,
          "activity": optional {entity_type, entity_id, action, details}
        }
    """
    kind = item.kind
    p = item.payload
    sql = p.get("sql")
    params = p.get("params")
    if not sql or params is None:
        log("warn", "pending write missing sql/params", {"kind": kind})
        return False
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(sql, tuple(params))
            act = p.get("activity") or {}
            if act.get("entity_type") and act.get("entity_id") and act.get("action"):
                _log_activity(
                    cur,
                    str(act["entity_type"]),
                    str(act["entity_id"]),
                    str(act["action"]),
                    act.get("details"),
                )
        if item.idempotency_key:
            _idempotency_store(
                item.idempotency_key,
                ok({"id": p.get("id"), "replayed": True, "queued": False}),
            )
        return True
    except Exception as exc:
        log("warn", "pending write apply failed", {"kind": kind, "error": str(exc)[:160]})
        return False


def _log_activity(cur: Any, entity_type: str, entity_id: str, action: str, details: str | None = None, created_by: str | None = None) -> None:
    cur.execute(
        "INSERT INTO echo_crm.activity_log (entity_type, entity_id, action, details, created_by, created_at) "
        "VALUES (%s, %s, %s, %s, %s, now())",
        (entity_type, entity_id, action, details, created_by)
    )


def _ensure_pipeline_defaults(cur: Any) -> None:
    cur.execute("SELECT COUNT(*) FROM echo_crm.pipelines")
    if (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone()) == 0:
        pid = uid()
        cur.execute(
            "INSERT INTO echo_crm.pipelines (id, name, is_default) VALUES (%s, %s, 1)",
            (pid, "Default Pipeline")
        )
        stages = [
            ("New", 0, 10),
            ("Qualified", 1, 25),
            ("Proposal", 2, 50),
            ("Negotiation", 3, 75),
            ("Closed Won", 4, 100),
            ("Closed Lost", 5, 0),
        ]
        for i, (name, pos, prob) in enumerate(stages):
            sid = uid()
            cur.execute(
                "INSERT INTO echo_crm.deal_stages (id, pipeline_id, name, position, probability) "
                "VALUES (%s, %s, %s, %s, %s)",
                (sid, pid, name, pos, prob)
            )


def _parse_json_field(val: str | None, default: Any) -> Any:
    if not val:
        return default
    try:
        return json.loads(val)
    except Exception:
        return default


def _call_engine(prompt: str) -> Optional[float]:
    if not ENGINE_URL:
        return None
    try:
        data = json.dumps({"query": prompt, "domain": "sales", "limit": 1}).encode()
        req = urllib.request.Request(ENGINE_URL.rstrip("/") + "/query", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                j = json.loads(resp.read())
                engines = j.get("engines") or []
                if engines and engines[0].get("relevance_score") is not None:
                    return float(engines[0]["relevance_score"])
    except Exception as e:
        log("warn", "Engine runtime call failed", {"error": str(e)[:120]})
    return None


def _ingest_brain(content: str, tags: list[str] | None = None) -> None:
    if not BRAIN_URL:
        return
    try:
        data = json.dumps({
            "instance_id": "echo-crm",
            "role": "system",
            "content": content,
            "importance": 6,
            "tags": tags or ["crm", "digest"]
        }).encode()
        req = urllib.request.Request(BRAIN_URL.rstrip("/") + "/ingest", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=4)
    except Exception as e:
        log("warn", "Shared brain ingest failed", {"error": str(e)[:120]})


def require_auth(x_echo_api_key: str | None = Header(None), endpoint: str = "unknown.write") -> dict[str, Any]:
    """Validate API key via security layer (tiered authz)."""
    return security_require_auth(endpoint, x_echo_api_key)


# FastAPI app — global path-based authz; webhooks self-verify signatures
_docs = "/docs" if os.environ.get("ECHO_CRM_DEV_MODE", "") in ("1", "true", "yes") else None
app = FastAPI(
    title="Echo CRM",
    version=CRM_VERSION,
    docs_url=_docs,
    redoc_url=_docs,
    openapi_url="/openapi.json" if _docs else None,
    dependencies=[Depends(path_auth_dependency())],
)


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to track request metrics (in-process + Prometheus counters)."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        """ASGI middleware dispatch: time the request and record metrics.

        Args:
            request: Incoming Starlette request.
            call_next: Downstream ASGI callable.

        Returns:
            Downstream HTTP response after metrics recording.
        """
        start_time = time.time()
        path = request.url.path
        method = request.method

        try:
            response = await call_next(request)
            duration_ms = (time.time() - start_time) * 1000
            metrics.record_request(method, path, response.status_code, duration_ms)
            prom_metrics.record_request(method, path, response.status_code, duration_ms)
            log(
                "info",
                "http request",
                {
                    "event": "http_request",
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                },
            )
            return response
        except Exception:
            duration_ms = (time.time() - start_time) * 1000
            metrics.record_request(method, path, 500, duration_ms)
            prom_metrics.record_error(method, path)
            log(
                "error",
                "http request failed",
                {
                    "event": "http_request_error",
                    "method": method,
                    "path": path,
                    "status_code": 500,
                    "duration_ms": round(duration_ms, 2),
                },
            )
            raise


app.add_middleware(RequestMetricsMiddleware)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add baseline security headers to every response."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Echo-Service", "echo-crm")
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.on_event("startup")
def _startup() -> None:
    """Schema bootstrap + resilience background loops (fail-open when DB down)."""
    db_ready = False
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(SCHEMA)
            _ensure_pipeline_defaults(cur)
        db_ready = True
        log("info", "echo_crm schema ready (Postgres)", {"db_ready": True})
    except Exception as exc:
        crm_runtime.mark_db_down()
        log(
            "error",
            "echo_crm schema bootstrap failed — running degraded" if crm_runtime.fail_open else "echo_crm schema bootstrap failed",
            {"error": str(exc)[:200], "fail_open": crm_runtime.fail_open},
        )
        if not crm_runtime.fail_open:
            raise

    try:
        crm_runtime.refresh_health(connect_fn=_raw_connect)
    except Exception as exc:
        log("warn", "initial dependency probe failed", {"error": str(exc)[:160]})

    crm_runtime.start_flusher(_apply_pending_write, interval_sec=float(os.environ.get("CRM_FLUSH_INTERVAL", "5")))
    crm_runtime.start_probe_loop(_raw_connect, interval_sec=float(os.environ.get("CRM_PROBE_INTERVAL", "30")))
    log(
        "info",
        "resilience runtime ready",
        {
            "resilience_version": RESILIENCE_VERSION,
            "fail_open": crm_runtime.fail_open,
            "db_ready": db_ready,
            "mode": crm_runtime.get_health().mode,
        },
    )


@app.get("/")
def root() -> dict[str, Any]:
    """Service root: identify echo-crm and operational status.

    Returns:
        Envelope with service name, version, and status.
    """
    mode = crm_runtime.get_health().mode
    if crm_runtime.degraded or mode in ("degraded", "unavailable"):
        status_label = "degraded" if crm_runtime.fail_open else "unavailable"
    else:
        status_label = "operational"
    return ok(
        {
            "service": "echo-crm",
            "version": CRM_VERSION,
            "status": status_label,
            "security": "hardened",
            "resilience_version": RESILIENCE_VERSION,
            "mode": mode if mode != "unknown" else ("degraded" if crm_runtime.degraded else "healthy"),
        }
    )


@app.get("/health")
def health() -> dict[str, Any]:
    """Health probe: returns ``status: "ok"`` + ``version`` when healthy.

    Also includes legacy ``ok`` / ``checks`` / ``service`` fields so existing
    fleet clients and the pytest suite continue to work. When Postgres is down
    but fail-open is enabled, ``status`` is ``degraded`` (HTTP 200) with full
    dependency diagnostics for MinIO and the SDK gate.
    """
    db_ok = False
    db_latency_ms = 0.0
    try:
        start = time.time()
        with _db() as con, con.cursor() as cur:
            cur.execute("SELECT 1")
        db_latency_ms = (time.time() - start) * 1000
        db_ok = True
        crm_runtime.mark_db_up()
    except Exception as e:
        log("warn", "Health check: DB connection failed", {"error": str(e)[:100]})
        crm_runtime.mark_db_down()

    # Refresh non-DB dependency probes (cached circuits inside runtime).
    try:
        health_snap = crm_runtime.refresh_health(connect_fn=None if not db_ok else _raw_connect)
    except Exception:
        health_snap = crm_runtime.get_health()
        if db_ok:
            health_snap.postgres = {"ok": True, "latency_ms": round(db_latency_ms, 3)}
            health_snap.mode = "healthy"
        else:
            health_snap.postgres = {"ok": False, "latency_ms": round(db_latency_ms, 3)}
            health_snap.mode = "degraded" if crm_runtime.fail_open else "unavailable"

    # Optional deps (MinIO archival, SDK gate): surface soft-degrade without failing liveness.
    minio_check = getattr(health_snap, "minio", {}) or {}
    gate_check = getattr(health_snap, "gate", {}) or {}
    optional_degraded = bool(
        (minio_check.get("configured") and not minio_check.get("ok"))
        or (gate_check.get("configured") and not gate_check.get("ok"))
    )
    core_degraded = (not db_ok) and crm_runtime.fail_open
    mode = health_snap.mode if hasattr(health_snap, "mode") else ("healthy" if db_ok else "degraded")
    if db_ok and optional_degraded and mode == "healthy":
        # Postgres is up; optional deps soft-degrade keeps accepting traffic.
        mode = "healthy"

    # Preserve legacy contract: ok tracks DB liveness (tests assert ok=False when DB down).
    payload = prom_metrics.build_health_payload(
        healthy=db_ok,
        version=CRM_VERSION,
        extra={
            "checks": {
                "database": {
                    "status": "healthy" if db_ok else "unhealthy",
                    "latency_ms": round(db_latency_ms, 3),
                },
                "postgres": health_snap.postgres,
                "minio": health_snap.minio,
                "gate": health_snap.gate,
            },
            "degraded": core_degraded,
            "optional_degraded": optional_degraded,
            "mode": mode,
            "resilience_version": RESILIENCE_VERSION,
            "fail_open": crm_runtime.fail_open,
            "pending_writes": crm_runtime.pending_writes.size,
            "dependencies": health_snap.to_dict() if hasattr(health_snap, "to_dict") else {},
        },
    )
    crm_runtime.cache.set_health(payload)
    return payload


@app.get("/ready")
def ready() -> dict[str, Any]:
    """Readiness: process is accepting traffic (fail-open allows degraded)."""
    h = crm_runtime.get_health()
    ready_ok = h.mode in ("healthy", "degraded") or crm_runtime.fail_open
    return {
        "ok": ready_ok,
        "ready": ready_ok,
        "service": "echo-crm",
        "version": CRM_VERSION,
        "mode": h.mode,
        "fail_open": crm_runtime.fail_open,
        "resilience_version": RESILIENCE_VERSION,
    }


@app.get("/resilience")
def resilience_status() -> dict[str, Any]:
    """Full resilience runtime status (dependencies, queues, retry policy)."""
    out = crm_runtime.status_dict()
    out["ok"] = True
    out["version"] = CRM_VERSION
    out["resilience_version"] = RESILIENCE_VERSION
    return out


@app.post("/resilience/flush")
def resilience_flush() -> dict[str, Any]:
    """Manually drain pending write + MinIO queues (admin/ops)."""
    applied, remaining = crm_runtime.pending_writes.drain(_apply_pending_write)
    return ok(
        {
            "flushed": applied,
            "remaining": remaining,
            "pending_writes": crm_runtime.pending_writes.size,
            "minio_queue": crm_runtime.minio_queue.size,
        }
    )


@app.get("/status")
def status() -> dict[str, Any]:
    """High-level CRM counts: contacts, open deals, pipelines.

    Returns:
        Envelope with aggregate counts and operational status.
        On DB failure, serves last-good cache when available (degraded).
    """
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM echo_crm.contacts")
            contacts = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
            cur.execute("SELECT COUNT(*) FROM echo_crm.deals WHERE status='open'")
            open_deals = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
            cur.execute("SELECT COUNT(*) FROM echo_crm.pipelines")
            pipelines = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
        body = ok({
            "contacts": contacts,
            "open_deals": open_deals,
            "pipelines": pipelines,
            "status": "operational",
            "degraded": False,
        })
        crm_runtime.cache.set_status(body)
        return body
    except Exception as e:
        cached = crm_runtime.cache.get_status()
        if cached is not None and crm_runtime.fail_open:
            crm_runtime.degraded_read("status")
            out = dict(cached)
            out["degraded"] = True
            out["status"] = "degraded"
            out["stale"] = True
            out["error"] = str(e)[:120]
            return out
        return {"ok": False, "error": str(e)[:120]}


@app.get("/metrics")
def metrics_endpoint(request: Request) -> Any:
    """Export operational metrics for fleet dashboard / Prometheus scrapers.

    Default response is JSON (legacy clients + pytest). Pass
    ``?format=prometheus`` or ``Accept: text/plain`` for Prometheus text.
    """
    accept = (request.headers.get("accept") or "").lower()
    fmt = (request.query_params.get("format") or "").lower()
    if fmt in ("prometheus", "prom", "text") or "text/plain" in accept:
        from fastapi.responses import Response

        return Response(
            content=prom_metrics.render_prometheus(),
            media_type=prom_metrics.metrics_content_type(),
        )

    m = metrics.get_metrics()
    counters = prom_metrics.counter_values()
    m["errors_total"] = counters["errors_total"]
    m["prometheus_requests_total"] = counters["requests_total"]
    return {
        "ok": True,
        "service": "echo-crm",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "metrics": m,
        "requests_total": counters["requests_total"],
        "errors_total": counters["errors_total"],
    }


# Pipelines
@app.get("/pipelines")
def get_pipelines() -> dict[str, Any]:
    """List all sales pipelines ordered by creation time.

    Returns:
        Envelope with ``pipelines`` array. Serves last-good when DB is down.
    """
    cache_key = "all"
    try:
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM echo_crm.pipelines ORDER BY created_at")
            body = ok({"pipelines": [dict(r) for r in cur.fetchall()], "degraded": False})
            crm_runtime.cache.set_pipelines(cache_key, body)
            return body
    except Exception as exc:
        cached = crm_runtime.cache.get_pipelines(cache_key)
        if cached is not None and crm_runtime.fail_open:
            crm_runtime.degraded_read("pipelines")
            out = dict(cached)
            out["degraded"] = True
            out["stale"] = True
            out["error"] = str(exc)[:120]
            return out
        if crm_runtime.fail_open:
            return ok({"pipelines": [], "degraded": True, "error": str(exc)[:120]})
        raise


@app.post("/pipelines")
def create_pipeline(body: dict[str, Any]) -> dict[str, Any]:
    """Create a pipeline and seed default deal stages.

    Args:
        body: JSON with required ``name`` and optional ``is_default``.

    Returns:
        Envelope with new pipeline ``id``.
    """
    err = require_body(body, "name")
    if err:
        return fail(err)
    pid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.pipelines (id, name, is_default) VALUES (%s, %s, %s)",
            (pid, validate_name(body["name"], "name", 200), 1 if body.get("is_default") else 0)
        )
        # seed default stages
        stages = [("New", 0, 10), ("Qualified", 1, 25), ("Proposal", 2, 50),
                  ("Negotiation", 3, 75), ("Closed Won", 4, 100), ("Closed Lost", 5, 0)]
        for name, pos, prob in stages:
            sid = uid()
            cur.execute(
                "INSERT INTO echo_crm.deal_stages (id, pipeline_id, name, position, probability) "
                "VALUES (%s, %s, %s, %s, %s)",
                (sid, pid, name, pos, prob)
            )
        return ok({"id": pid})


@app.get("/pipelines/{pid}")
def get_pipeline(pid: str) -> dict[str, Any]:
    try:
        pid = validate_id(pid, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Fetch a pipeline and its ordered stages.

    Args:
        pid: Pipeline primary key.

    Returns:
        Envelope with pipeline row and ``stages`` list, or error if missing.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.pipelines WHERE id=%s", (pid,))
        p = cur.fetchone()
        if not p:
            return fail("Pipeline not found", 404)
        cur.execute("SELECT * FROM echo_crm.deal_stages WHERE pipeline_id=%s ORDER BY position", (pid,))
        stages = [dict(r) for r in cur.fetchall()]
        return ok({"pipeline": dict(p), "stages": stages})


@app.delete("/pipelines/{pid}")
def delete_pipeline(pid: str) -> dict[str, Any]:
    try:
        pid = validate_id(pid, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a pipeline by id (does not cascade-delete deals).

    Args:
        pid: Pipeline primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.pipelines WHERE id=%s", (pid,))
        return ok({"deleted": True})


@app.get("/pipelines/{pid}/stages")
def get_stages(pid: str) -> dict[str, Any]:
    try:
        pid = validate_id(pid, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """List deal stages for a pipeline ordered by position.

    Args:
        pid: Pipeline primary key.

    Returns:
        Envelope with ``stages`` array.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.deal_stages WHERE pipeline_id=%s ORDER BY position", (pid,))
        return ok({"stages": [dict(r) for r in cur.fetchall()]})


@app.post("/pipelines/{pid}/stages")
def create_stage(pid: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        pid = validate_id(pid, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Create a deal stage under a pipeline.

    Args:
        pid: Parent pipeline id.
        body: JSON with required ``name``; optional position/probability/rotting_days.

    Returns:
        Envelope with new stage ``id``.
    """
    err = require_body(body, "name")
    if err:
        return fail(err)
    sid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.deal_stages (id, pipeline_id, name, position, probability) "
            "VALUES (%s, %s, %s, COALESCE(%s,0), COALESCE(%s,0))",
            (sid, pid, sanitize(body["name"]), body.get("position"), body.get("probability"))
        )
        return ok({"id": sid})


@app.put("/stages/{sid}")
def update_stage(sid: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        sid = validate_id(sid, "stage_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Partial-update a deal stage.

    Args:
        sid: Stage primary key.
        body: Fields to update (name, position, probability, rotting_days).

    Returns:
        Envelope confirming update.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_crm.deal_stages SET name=COALESCE(%s,name), position=COALESCE(%s,position), "
            "probability=COALESCE(%s,probability) WHERE id=%s",
            (body.get("name"), body.get("position"), body.get("probability"), sid)
        )
        return ok({"updated": True})


@app.delete("/stages/{sid}")
def delete_stage(sid: str) -> dict[str, Any]:
    try:
        sid = validate_id(sid, "stage_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a deal stage by id.

    Args:
        sid: Stage primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.deal_stages WHERE id=%s", (sid,))
        return ok({"deleted": True})


# Contacts
@app.get("/contacts")
def list_contacts(request: Request, x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    """List/search contacts with optional filters and pagination.

    Query params: ``q``, ``status``, ``source``, ``limit``, ``offset``.
    Requires ``X-Echo-API-Key`` when auth is enabled.

    Args:
        request: HTTP request (query params).
        x_echo_api_key: Optional API key header.

    Returns:
        Envelope with ``contacts`` array and pagination metadata when present.
    """
    limit, offset = paginate_params(request)
    q = request.query_params
    search = q.get("q")
    status = q.get("status")
    source = q.get("source")

    where_parts: list[str] = ["1=1"]
    binds: list[Any] = []
    if search:
        s = f"%{search}%"
        where_parts.append("(first_name ILIKE %s OR last_name ILIKE %s OR email ILIKE %s)")
        binds.extend([s, s, s])
    if status:
        where_parts.append("lead_status = %s")
        binds.append(status)
    if source:
        where_parts.append("source = %s")
        binds.append(source)

    where = " AND ".join(where_parts)
    binds2 = binds + [limit, offset]
    cache_key = f"q={search}|s={status}|src={source}|l={limit}|o={offset}"
    try:
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _sql_contacts = (
                "SELECT c.*, co.name AS company_name FROM echo_crm.contacts c "
                "LEFT JOIN echo_crm.companies co ON c.company_id = co.id WHERE "
                + where
                + " ORDER BY c.created_at DESC LIMIT %s OFFSET %s"
            )
            cur.execute(_sql_contacts, binds2)
            rows = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT COUNT(*) FROM echo_crm.contacts WHERE " + where, binds)
            total = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
            body = ok({"contacts": rows, "total": total, "degraded": False})
            crm_runtime.cache.set_contacts(cache_key, body)
            return body
    except Exception as exc:
        cached = crm_runtime.cache.get_contacts(cache_key)
        if cached is not None and crm_runtime.fail_open:
            crm_runtime.degraded_read("contacts")
            out = dict(cached)
            out["degraded"] = True
            out["stale"] = True
            out["error"] = str(exc)[:120]
            return out
        if crm_runtime.fail_open:
            return ok({"contacts": [], "total": 0, "degraded": True, "error": str(exc)[:120]})
        raise


@app.post("/contacts")
def create_contact(
    body: dict[str, Any],
    x_echo_api_key: str | None = Header(None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """Create a contact record.

    Args:
        body: JSON with required ``first_name`` plus optional CRM fields.
        x_echo_api_key: Optional API key header.
        idempotency_key: Optional Idempotency-Key for safe retries.

    Returns:
        Envelope with new contact ``id``. Queues when DB is down (fail-open).
    """
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached
    err = require_body(body, "first_name")
    if err:
        return fail(err)
    try:
        first_name = validate_name(body["first_name"], "first_name", 100)
        last_name = validate_text(body.get("last_name"), "last_name", 100) or ""
        email = validate_email(body.get("email")) or ""
        phone = validate_phone(body.get("phone")) or ""
        company_id = validate_optional_id(body.get("company_id"), "company_id")
        source = validate_source(body.get("source"))
        lead_status = validate_lead_status(body.get("lead_status") or "new") or "new"
        country = validate_country(body.get("country"))
        tags = validate_json_object(body.get("tags") if isinstance(body.get("tags"), (list, dict)) else body.get("tags") or [])
        custom = validate_json_object(body.get("custom_fields") if isinstance(body.get("custom_fields"), dict) else body.get("custom_fields") or {})
        notes = validate_text(body.get("notes"), "notes", 5000) or ""
    except ValueError as exc:
        return fail(str(exc), 400)
    cid = uid()
    now = now_iso()
    row = (
        cid, company_id, first_name,
        last_name, email,
        phone, sanitize(body.get("title") or "", 100),
        source, lead_status,
        json.dumps(tags if tags is not None else []), json.dumps(custom if custom is not None else {}),
        sanitize(body.get("address") or "", 200), sanitize(body.get("city") or "", 100),
        sanitize(body.get("state") or "", 50), sanitize(body.get("zip") or "", 20),
        country, notes, now, now,
    )
    sql = (
        "INSERT INTO echo_crm.contacts (id, company_id, first_name, last_name, email, phone, title, "
        "source, lead_status, tags, custom_fields, address, city, state, zip, country, notes, "
        "created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (id) DO NOTHING"
    )
    details = f"{body['first_name']} {body.get('last_name') or ''}"
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(sql, row)
            _log_activity(cur, "contact", cid, "created", details)
            out = ok({"id": cid})
            _idempotency_store(soft_key, out)
            return out
    except Exception as exc:
        if crm_runtime.fail_open and (
            isinstance(exc, DependencyUnavailable) or is_retryable(exc)
        ):
            return _queue_or_fail(
                "contact.create",
                {
                    "id": cid,
                    "sql": sql,
                    "params": list(row),
                    "activity": {
                        "entity_type": "contact",
                        "entity_id": cid,
                        "action": "created",
                        "details": details,
                    },
                },
                soft_key=soft_key,
                entity_hint=cid,
            )
        raise


@app.get("/contacts/{cid}")
def get_contact(cid: str) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "contact_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Fetch a contact with recent related deals and activities.

    Args:
        cid: Contact primary key.

    Returns:
        Envelope with contact detail or not-found error.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT c.*, co.name AS company_name FROM echo_crm.contacts c "
            "LEFT JOIN echo_crm.companies co ON c.company_id = co.id WHERE c.id = %s", (cid,)
        )
        row = cur.fetchone()
        if not row:
            return fail("Contact not found", 404)
        cur.execute("SELECT id, title, value, status, stage_id FROM echo_crm.deals WHERE contact_id=%s ORDER BY created_at DESC LIMIT 10", (cid,))
        deals = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM echo_crm.activities WHERE contact_id=%s ORDER BY created_at DESC LIMIT 10", (cid,))
        acts = [dict(r) for r in cur.fetchall()]
        return ok({"contact": dict(row), "deals": deals, "activities": acts})


@app.put("/contacts/{cid}")
def update_contact(cid: str, body: dict[str, Any], x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "contact_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Partial-update a contact.

    Args:
        cid: Contact primary key.
        body: Fields to update.
        x_echo_api_key: Optional API key header.

    Returns:
        Envelope confirming update.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_crm.contacts SET first_name=COALESCE(%s,first_name), last_name=COALESCE(%s,last_name), "
            "email=COALESCE(%s,email), phone=COALESCE(%s,phone), title=COALESCE(%s,title), "
            "lead_status=COALESCE(%s,lead_status), tags=COALESCE(%s,tags), custom_fields=COALESCE(%s,custom_fields), "
            "updated_at=now() WHERE id=%s",
            (body.get("first_name"), body.get("last_name"), body.get("email"), body.get("phone"),
             body.get("title"), body.get("lead_status"),
             json.dumps(body["tags"]) if "tags" in body else None,
             json.dumps(body["custom_fields"]) if "custom_fields" in body else None,
             cid)
        )
        _log_activity(cur, "contact", cid, "updated")
        return ok({"updated": True})


@app.delete("/contacts/{cid}")
def delete_contact(cid: str) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "contact_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a contact by id (tier-2 style destructive op).

    Args:
        cid: Contact primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.contacts WHERE id=%s", (cid,))
        return ok({"deleted": True})


# Companies
@app.get("/companies")
def list_companies(request: Request, x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    """List/search companies with pagination.

    Query params: ``q``, ``limit``, ``offset``.
    Requires API key when auth is enabled.

    Args:
        request: HTTP request.
        x_echo_api_key: Optional API key header.

    Returns:
        Envelope with ``companies`` array.
    """
    limit, offset = paginate_params(request)
    try:
        q = validate_search(request.query_params.get("q"))
    except ValueError as exc:
        return fail(str(exc), 400)
    where_parts: list[str] = ["1=1"]
    binds: list[Any] = []
    if q:
        s = "%" + sanitize_like_pattern(q) + "%"
        where_parts.append("(name ILIKE %s OR domain ILIKE %s OR industry ILIKE %s)")
        binds.extend([s, s, s])
    where = " AND ".join(where_parts)
    binds += [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.companies WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds,
        )
        rows = [dict(r) for r in cur.fetchall()]
        return ok({"companies": rows})


@app.post("/companies")
def create_company(
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """Create a company record.

    Args:
        body: JSON with required ``name`` plus optional firmographic fields.
        idempotency_key: Optional Idempotency-Key for safe retries.

    Returns:
        Envelope with new company ``id``. Queues when DB is down (fail-open).
    """
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached
    err = require_body(body, "name")
    if err:
        return fail(err)
    cid = uid()
    now = now_iso()
    row = (
        cid, sanitize(body["name"], 200), sanitize(body.get("domain") or "", 200),
        sanitize(body.get("industry") or "", 100), body.get("size"), body.get("revenue"),
        sanitize(body.get("phone") or "", 30), sanitize(body.get("address") or "", 200),
        sanitize(body.get("city") or "", 100), sanitize(body.get("state") or "", 50),
        sanitize(body.get("zip") or "", 20), body.get("country") or "US",
        json.dumps(body.get("tags") or []), json.dumps(body.get("custom_fields") or {}),
        sanitize(body.get("notes") or "", 5000), now, now,
    )
    sql = (
        "INSERT INTO echo_crm.companies (id, name, domain, industry, size, revenue, phone, "
        "address, city, state, zip, country, tags, custom_fields, notes, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (id) DO NOTHING"
    )
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(sql, row)
            out = ok({"id": cid})
            _idempotency_store(soft_key, out)
            return out
    except Exception as exc:
        if crm_runtime.fail_open and (
            isinstance(exc, DependencyUnavailable) or is_retryable(exc)
        ):
            return _queue_or_fail(
                "company.create",
                {"id": cid, "sql": sql, "params": list(row)},
                soft_key=soft_key,
                entity_hint=cid,
            )
        raise


@app.get("/companies/{cid}")
def get_company(cid: str) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "company_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Fetch a single company by id.

    Args:
        cid: Company primary key.

    Returns:
        Envelope with company row or not-found error.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.companies WHERE id=%s", (cid,))
        row = cur.fetchone()
        if not row:
            return fail("Company not found", 404)
        return ok({"company": dict(row)})


@app.put("/companies/{cid}")
def update_company(cid: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "company_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Partial-update a company.

    Args:
        cid: Company primary key.
        body: Fields to update.

    Returns:
        Envelope confirming update.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_crm.companies SET name=COALESCE(%s,name), domain=COALESCE(%s,domain), "
            "updated_at=now() WHERE id=%s",
            (body.get("name"), body.get("domain"), cid)
        )
        return ok({"updated": True})


@app.delete("/companies/{cid}")
def delete_company(cid: str) -> dict[str, Any]:
    try:
        cid = validate_id(cid, "company_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a company by id.

    Args:
        cid: Company primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.companies WHERE id=%s", (cid,))
        return ok({"deleted": True})


# Deals + board + move
@app.get("/deals")
def list_deals(request: Request) -> dict[str, Any]:
    """List deals with optional pipeline/stage/status filters.

    Query params: ``pipeline_id``, ``stage_id``, ``status``, ``limit``, ``offset``.

    Args:
        request: HTTP request.

    Returns:
        Envelope with ``deals`` array.
    """
    limit, offset = paginate_params(request)
    try:
        pipeline = validate_optional_id(request.query_params.get("pipeline_id"), "pipeline_id")
        stage = validate_optional_id(request.query_params.get("stage_id"), "stage_id")
        status = validate_deal_status(request.query_params.get("status") or "open")
    except ValueError as exc:
        return fail(str(exc), 400)
    where = "1=1"
    binds: list[Any] = []
    if pipeline:
        where += " AND pipeline_id = %s"
        binds.append(pipeline)
    if stage:
        where += " AND stage_id = %s"
        binds.append(stage)
    if status:
        where += " AND status = %s"
        binds.append(status)
    binds2 = binds + [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.deals WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds2,
        )
        return ok({"deals": [dict(r) for r in cur.fetchall()]})


@app.get("/deals/board")
def deals_board(pipeline_id: str | None = None) -> dict[str, Any]:
    """Kanban board view: stages with deal counts and total values.

    Args:
        pipeline_id: Optional pipeline filter; default pipeline used when omitted.

    Returns:
        Envelope with board columns (stages + aggregates).
    """
    try:
        pipeline_id = validate_optional_id(pipeline_id, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        where = ""
        binds: list[Any] = []
        if pipeline_id:
            where = " AND d.pipeline_id = %s"
            binds.append(pipeline_id)
        cur.execute(
            "SELECT ds.id, ds.name, ds.position, ds.probability, "
            "COUNT(d.id) AS deal_count, COALESCE(SUM(d.value),0) AS total_value "
            "FROM echo_crm.deal_stages ds LEFT JOIN echo_crm.deals d "
            "ON ds.id = d.stage_id AND d.status = 'open' " + where +
            " GROUP BY ds.id ORDER BY ds.position",
            binds
        )
        stages = [dict(r) for r in cur.fetchall()]
        return ok({"board": stages})


@app.post("/deals")
def create_deal(
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """Create a deal in a pipeline stage.

    Args:
        body: JSON with required ``title``, ``pipeline_id``, ``stage_id``.
        idempotency_key: Optional Idempotency-Key for safe retries.

    Returns:
        Envelope with new deal ``id``. Queues when DB is down (fail-open).
    """
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached
    err = require_body(body, "title", "pipeline_id", "stage_id")
    if err:
        return fail(err)
    try:
        title = validate_name(body["title"], "title", 300)
        pipeline_id = validate_id(body["pipeline_id"], "pipeline_id")
        stage_id = validate_id(body["stage_id"], "stage_id")
        contact_id = validate_optional_id(body.get("contact_id"), "contact_id")
        company_id = validate_optional_id(body.get("company_id"), "company_id")
        value = validate_amount(body.get("value") or 0, "value")
        currency = validate_currency(body.get("currency"))
        status = validate_deal_status(body.get("status") or "open") or "open"
        notes = validate_text(body.get("notes"), "notes", 5000) or ""
    except ValueError as exc:
        return fail(str(exc), 400)
    did = uid()
    now = now_iso()
    sql = (
        "INSERT INTO echo_crm.deals (id, pipeline_id, stage_id, contact_id, company_id, title, "
        "value, currency, probability, expected_close_date, status, owner, tags, custom_fields, notes, "
        "created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (id) DO NOTHING"
    )
    try:
        with _db() as con, con.cursor() as cur:
            # get stage prob
            cur.execute("SELECT probability FROM echo_crm.deal_stages WHERE id=%s", (stage_id,))
            prob = (cur.fetchone() or [0])[0]
            row = (
                did, pipeline_id, stage_id, contact_id, company_id,
                title, value, currency,
                prob, body.get("expected_close_date"), status,
                sanitize(body.get("owner") or "", 100) or None, json.dumps(body.get("tags") or []),
                json.dumps(body.get("custom_fields") or {}), notes,
                now, now,
            )
            cur.execute(sql, row)
            _log_activity(cur, "deal", did, "created", body["title"])
            out = ok({"id": did})
            _idempotency_store(soft_key, out)
            return out
    except Exception as exc:
        if crm_runtime.fail_open and (
            isinstance(exc, DependencyUnavailable) or is_retryable(exc)
        ):
            # Stage probability may be unknown offline — default 0.
            row = (
                did, pipeline_id, stage_id, contact_id, company_id,
                title, value, currency,
                0, body.get("expected_close_date"), status,
                sanitize(body.get("owner") or "", 100) or None, json.dumps(body.get("tags") or []),
                json.dumps(body.get("custom_fields") or {}), notes,
                now, now,
            )
            return _queue_or_fail(
                "deal.create",
                {
                    "id": did,
                    "sql": sql,
                    "params": list(row),
                    "activity": {
                        "entity_type": "deal",
                        "entity_id": did,
                        "action": "created",
                        "details": body["title"],
                    },
                },
                soft_key=soft_key,
                entity_hint=did,
            )
        raise


@app.get("/deals/{did}")
def get_deal(did: str) -> dict[str, Any]:
    try:
        did = validate_id(did, "deal_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Fetch a single deal by id.

    Args:
        did: Deal primary key.

    Returns:
        Envelope with deal row or not-found error.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.deals WHERE id=%s", (did,))
        row = cur.fetchone()
        if not row:
            return fail("Deal not found", 404)
        return ok({"deal": dict(row)})


@app.put("/deals/{did}")
def update_deal(did: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        did = validate_id(did, "deal_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Partial-update a deal.

    Args:
        did: Deal primary key.
        body: Fields to update (value, status, owner, etc.).

    Returns:
        Envelope confirming update.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_crm.deals SET title=COALESCE(%s,title), value=COALESCE(%s,value), "
            "status=COALESCE(%s,status), notes=COALESCE(%s,notes), updated_at=now() WHERE id=%s",
            (body.get("title"), body.get("value"), body.get("status"),
             sanitize(body.get("notes") or "", 5000) if "notes" in body else None, did)
        )
        return ok({"updated": True})


@app.delete("/deals/{did}")
def delete_deal(did: str) -> dict[str, Any]:
    try:
        did = validate_id(did, "deal_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a deal by id.

    Args:
        did: Deal primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.deals WHERE id=%s", (did,))
        return ok({"deleted": True})


@app.post("/deals/{did}/move")
def move_deal(did: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        did = validate_id(did, "deal_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Move a deal to a new stage and refresh probability.

    Args:
        did: Deal primary key.
        body: JSON with required ``stage_id``.

    Returns:
        Envelope confirming move and updated probability when available.
    """
    err = require_body(body, "stage_id")
    if err:
        return fail(err)
    try:
        stage_id = validate_id(body["stage_id"], "stage_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    with _db() as con, con.cursor() as cur:
        cur.execute("SELECT probability FROM echo_crm.deal_stages WHERE id=%s", (stage_id,))
        row = cur.fetchone()
        if not row:
            return fail("Stage not found", 404)
        prob = row[0]
        cur.execute(
            "UPDATE echo_crm.deals SET stage_id=%s, probability=%s, updated_at=now() WHERE id=%s",
            (stage_id, prob, did)
        )
        _log_activity(cur, "deal", did, "stage_moved")
        return ok({"moved": True})


# Activities
@app.get("/activities")
def list_activities(request: Request) -> dict[str, Any]:
    """List activities with optional contact/deal filters and pagination.

    Args:
        request: HTTP request.

    Returns:
        Envelope with ``activities`` array.
    """
    limit, offset = paginate_params(request)
    q = request.query_params
    typ = q.get("type")
    contact = q.get("contact_id")
    deal = q.get("deal_id")
    upcoming = q.get("upcoming")
    where = "1=1"
    binds: list[Any] = []
    if typ:
        where += " AND type = %s"
        binds.append(typ)
    if contact:
        where += " AND contact_id = %s"
        binds.append(contact)
    if deal:
        where += " AND deal_id = %s"
        binds.append(deal)
    if upcoming:
        where += " AND is_done = 0 AND due_date IS NOT NULL"
    binds2 = binds + [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.activities WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds2,
        )
        return ok({"activities": [dict(r) for r in cur.fetchall()]})


@app.post("/activities")
def create_activity(
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """Create an activity (call, meeting, task, etc.).

    Args:
        body: JSON with required ``type`` and ``subject``; optional links.
        idempotency_key: Optional Idempotency-Key for safe retries.

    Returns:
        Envelope with new activity ``id``. Queues when DB is down (fail-open).
    """
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached
    err = require_body(body, "type", "subject")
    if err:
        return fail(err)
    try:
        act_type = validate_activity_type(body["type"])
        subject = validate_name(body["subject"], "subject", 300)
        contact_id = validate_optional_id(body.get("contact_id"), "contact_id")
        company_id = validate_optional_id(body.get("company_id"), "company_id")
        deal_id = validate_optional_id(body.get("deal_id"), "deal_id")
        act_body = validate_text(body.get("body"), "body", 5000) or ""
    except ValueError as exc:
        return fail(str(exc), 400)
    aid = uid()
    row = (
        aid, contact_id, company_id, deal_id,
        act_type, subject,
        act_body, body.get("due_date"),
        body.get("duration_minutes"), 1 if body.get("is_done") else 0,
        sanitize(body.get("created_by") or "", 100) or None,
    )
    sql = (
        "INSERT INTO echo_crm.activities (id, contact_id, company_id, deal_id, type, subject, body, "
        "due_date, duration_minutes, is_done, created_by, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()) "
        "ON CONFLICT (id) DO NOTHING"
    )
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(sql, row)
            _log_activity(cur, "activity", aid, "created", body["subject"])
            out = ok({"id": aid})
            _idempotency_store(soft_key, out)
            return out
    except Exception as exc:
        if crm_runtime.fail_open and (
            isinstance(exc, DependencyUnavailable) or is_retryable(exc)
        ):
            return _queue_or_fail(
                "activity.create",
                {
                    "id": aid,
                    "sql": sql,
                    "params": list(row),
                    "activity": {
                        "entity_type": "activity",
                        "entity_id": aid,
                        "action": "created",
                        "details": body["subject"],
                    },
                },
                soft_key=soft_key,
                entity_hint=aid,
            )
        raise


@app.put("/activities/{aid}")
def update_activity(aid: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        aid = validate_id(aid, "activity_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Partial-update an activity (including completion flags).

    Args:
        aid: Activity primary key.
        body: Fields to update.

    Returns:
        Envelope confirming update.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_crm.activities SET subject=COALESCE(%s,subject), body=COALESCE(%s,body), "
            "is_done=COALESCE(%s,is_done), completed_at=CASE WHEN %s=1 THEN now() ELSE completed_at END "
            "WHERE id=%s",
            (body.get("subject"), sanitize(body.get("body") or "", 5000) if "body" in body else None,
             1 if body.get("is_done") else 0, 1 if body.get("is_done") else 0, aid)
        )
        return ok({"updated": True})


@app.delete("/activities/{aid}")
def delete_activity(aid: str) -> dict[str, Any]:
    try:
        aid = validate_id(aid, "activity_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete an activity by id.

    Args:
        aid: Activity primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.activities WHERE id=%s", (aid,))
        return ok({"deleted": True})


# Notes
@app.get("/notes")
def list_notes(request: Request) -> dict[str, Any]:
    """List notes filtered by contact, company, or deal.

    Args:
        request: HTTP request.

    Returns:
        Envelope with ``notes`` array.
    """
    limit, offset = paginate_params(request)
    contact = request.query_params.get("contact_id")
    deal = request.query_params.get("deal_id")
    where = "1=1"
    binds: list[Any] = []
    if contact:
        where += " AND contact_id=%s"
        binds.append(contact)
    if deal:
        where += " AND deal_id=%s"
        binds.append(deal)
    binds2 = binds + [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.notes WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds2,
        )
        return ok({"notes": [dict(r) for r in cur.fetchall()]})


@app.post("/notes")
def create_note(body: dict[str, Any]) -> dict[str, Any]:
    """Create a free-text note linked to CRM entities.

    Args:
        body: JSON with required ``body``; optional contact/company/deal ids.

    Returns:
        Envelope with new note ``id``.
    """
    err = require_body(body, "body")
    if err:
        return fail(err)
    nid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.notes (id, contact_id, company_id, deal_id, body, created_by, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,now())",
            (nid, body.get("contact_id"), body.get("company_id"), body.get("deal_id"),
             sanitize(body["body"], 10000), body.get("created_by"))
        )
        _log_activity(cur, "note", nid, "created")
        return ok({"id": nid})


@app.delete("/notes/{nid}")
def delete_note(nid: str) -> dict[str, Any]:
    try:
        nid = validate_id(nid, "note_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a note by id.

    Args:
        nid: Note primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.notes WHERE id=%s", (nid,))
        return ok({"deleted": True})


# Tags
@app.get("/tags")
def list_tags() -> dict[str, Any]:
    """List all CRM tags.

    Returns:
        Envelope with ``tags`` array.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.tags ORDER BY name")
        return ok({"tags": [dict(r) for r in cur.fetchall()]})


@app.post("/tags")
def create_tag(body: dict[str, Any]) -> dict[str, Any]:
    """Create a named tag with optional color.

    Args:
        body: JSON with required ``name``; optional ``color``.

    Returns:
        Envelope with new tag ``id``.
    """
    err = require_body(body, "name")
    if err:
        return fail(err)
    tid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.tags (id, name, color) VALUES (%s,%s,%s) ON CONFLICT (name) DO NOTHING",
            (tid, sanitize(body["name"], 100), body.get("color") or "#6366f1")
        )
        return ok({"id": tid})


@app.delete("/tags/{tid}")
def delete_tag(tid: str) -> dict[str, Any]:
    try:
        tid = validate_id(tid, "tag_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Delete a tag by id.

    Args:
        tid: Tag primary key.

    Returns:
        Envelope confirming deletion.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM echo_crm.tags WHERE id=%s", (tid,))
        return ok({"deleted": True})


# Email events
@app.post("/email-events")
def create_email_event(body: dict[str, Any]) -> dict[str, Any]:
    """Record an email engagement event (open/click/bounce).

    Args:
        body: JSON with required ``type``; optional contact/deal/subject.

    Returns:
        Envelope with new event ``id``.
    """
    err = require_body(body, "type")
    if err:
        return fail(err)
    eid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.email_events (id, contact_id, deal_id, type, subject, opened_at, clicked_at, bounced) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (eid, body.get("contact_id"), body.get("deal_id"), sanitize(body["type"], 50),
             sanitize(body.get("subject") or "", 300), body.get("opened_at"), body.get("clicked_at"),
             1 if body.get("bounced") else 0)
        )
        return ok({"id": eid})


@app.get("/email-events")
def list_email_events(request: Request) -> dict[str, Any]:
    """List email events with optional contact filter and pagination.

    Args:
        request: HTTP request.

    Returns:
        Envelope with ``events`` array.
    """
    limit, offset = paginate_params(request)
    contact = request.query_params.get("contact_id")
    where = "1=1"
    binds: list[Any] = []
    if contact:
        where += " AND contact_id=%s"
        binds.append(contact)
    binds2 = binds + [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.email_events WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds2,
        )
        return ok({"events": [dict(r) for r in cur.fetchall()]})


# Lead scoring
@app.get("/lead-scoring/rules")
def list_lead_rules() -> dict[str, Any]:
    """List active lead-scoring rules.

    Returns:
        Envelope with ``rules`` array.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.lead_scoring_rules WHERE is_active=1 ORDER BY created_at")
        return ok({"rules": [dict(r) for r in cur.fetchall()]})


@app.post("/lead-scoring/rules")
def create_lead_rule(body: dict[str, Any]) -> dict[str, Any]:
    """Create a lead-scoring rule (field/operator/value/score).

    Args:
        body: JSON with required field, operator, value, score.

    Returns:
        Envelope with new rule ``id``.
    """
    err = require_body(body, "field", "operator", "value", "score")
    if err:
        return fail(err)
    try:
        field = sanitize(body["field"], 100)
        if not field:
            raise ValueError("invalid field")
        operator = validate_operator(str(body["operator"]))
        value = sanitize(str(body["value"]), 200)
        score = validate_score(body["score"])
    except ValueError as exc:
        return fail(str(exc), 400)
    rid = uid()
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "INSERT INTO echo_crm.lead_scoring_rules (id, field, operator, value, score, is_active) "
            "VALUES (%s,%s,%s,%s,%s,1)",
            (rid, field, operator, value, score),
        )
        return ok({"id": rid})


@app.delete("/lead-scoring/rules/{rid}")
def delete_lead_rule(rid: str) -> dict[str, Any]:
    try:
        rid = validate_id(rid, "rule_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    """Soft-deactivate a lead-scoring rule (is_active=0).

    Args:
        rid: Rule primary key.

    Returns:
        Envelope confirming deactivation.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("UPDATE echo_crm.lead_scoring_rules SET is_active=0 WHERE id=%s", (rid,))
        return ok({"deleted": True})


@app.post("/lead-scoring/score")
def score_lead(body: dict[str, Any]) -> dict[str, Any]:
    """Score a contact using rules, activity bonuses, and optional AI boost.

    Combines active lead_scoring_rules, activity/email bonuses, and optional
    engine-runtime relevance when ``ECHO_ENGINE_RUNTIME_URL`` is set. Clamps
    score to 0..100 and persists on the contact.

    Args:
        body: JSON with required ``contact_id``.

    Returns:
        Envelope with ``contact_id`` and computed ``score``.
    """
    err = require_body(body, "contact_id")
    if err:
        return fail(err)
    try:
        cid = validate_id(str(body["contact_id"]), "contact_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.contacts WHERE id=%s", (cid,))
        contact = cur.fetchone()
        if not contact:
            return fail("Contact not found", 404)
        contact = dict(contact)
        cur.execute("SELECT * FROM echo_crm.lead_scoring_rules WHERE is_active=1")
        rules = [dict(r) for r in cur.fetchall()]

        score = int(contact.get("lead_score") or 0)
        tags = _parse_json_field(contact.get("tags"), [])
        custom = _parse_json_field(contact.get("custom_fields"), {})

        for rule in rules:
            field_val = contact.get(rule["field"]) or tags if rule["field"] == "tags" else custom.get(rule["field"])
            if field_val is None:
                continue
            op = rule["operator"]
            rv = rule["value"]
            if op == "equals" and str(field_val) == rv:
                score += rule["score"]
            elif op == "contains" and rv in str(field_val):
                score += rule["score"]
            elif op == "not_empty" and field_val:
                score += rule["score"]

        # activity bonus
        cur.execute("SELECT COUNT(*) FROM echo_crm.activities WHERE contact_id=%s", (cid,))
        act_n = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone()) or 0
        cur.execute("SELECT COUNT(*) FROM echo_crm.email_events WHERE contact_id=%s AND type='opened'", (cid,))
        email_n = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone()) or 0
        score += (act_n * 5) + (email_n * 10)

        # AI boost (best effort)
        try:
            ai_score = _call_engine(
                f"Score this lead: {contact.get('first_name')} {contact.get('last_name') or ''}, "
                f"title: {contact.get('title') or 'unknown'}, source: {contact.get('source')}, "
                f"company: {'has' if contact.get('company_id') else 'no'}, "
                f"activities: {act_n}"
            )
            if ai_score is not None:
                score += int(ai_score * 20)
        except Exception:
            pass

        score = max(0, min(100, score))
        cur.execute(
            "UPDATE echo_crm.contacts SET lead_score=%s, updated_at=now() WHERE id=%s",
            (score, cid)
        )
        _log_activity(cur, "contact", cid, "lead_scored", str(score))
        return ok({"contact_id": cid, "score": score})


# Analytics (faithful ports)
@app.get("/analytics/pipeline")
def analytics_pipeline(pipeline_id: str) -> dict[str, Any]:
    """Pipeline analytics: stage counts/values, won/lost, weighted open value.

    Args:
        pipeline_id: Pipeline primary key (required).

    Returns:
        Envelope with stages, won/lost aggregates, open and weighted values.
    """
    try:
        pipeline_id = validate_id(pipeline_id, "pipeline_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT ds.id, ds.name, ds.position, ds.probability, COUNT(d.id) AS deal_count, "
            "COALESCE(SUM(d.value),0) AS total_value FROM echo_crm.deal_stages ds "
            "LEFT JOIN echo_crm.deals d ON ds.id=d.stage_id AND d.status='open' "
            "WHERE ds.pipeline_id=%s GROUP BY ds.id ORDER BY ds.position",
            (pipeline_id,)
        )
        stages = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
        cur.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(value),0) total FROM echo_crm.deals "
            "WHERE pipeline_id=%s AND status='won'", (pipeline_id,)
        )
        won = dict(zip([c[0] for c in cur.description], cur.fetchone() or []))
        cur.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(value),0) total FROM echo_crm.deals "
            "WHERE pipeline_id=%s AND status='lost'", (pipeline_id,)
        )
        lost = dict(zip([c[0] for c in cur.description], cur.fetchone() or []))
        cur.execute(
            "SELECT COALESCE(SUM(value),0) total FROM echo_crm.deals "
            "WHERE pipeline_id=%s AND status='open'", (pipeline_id,)
        )
        open_v = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
        cur.execute(
            "SELECT COALESCE(SUM(d.value * ds.probability / 100.0),0) FROM echo_crm.deals d "
            "JOIN echo_crm.deal_stages ds ON d.stage_id=ds.id WHERE d.pipeline_id=%s AND d.status='open'",
            (pipeline_id,)
        )
        weighted = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
        return ok({
            "stages": stages,
            "won": won,
            "lost": lost,
            "open_value": open_v,
            "weighted_value": weighted
        })


@app.get("/analytics/contacts")
def analytics_contacts() -> dict[str, Any]:
    """Contact analytics: counts by lead_status and new contacts (7d).

    Returns:
        Envelope with ``by_status`` map and ``new_7d`` count.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT lead_status, COUNT(*) n FROM echo_crm.contacts GROUP BY lead_status"
        )
        by_status = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM echo_crm.contacts WHERE created_at >= now() - interval '7 days'")
        new_7d = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone())
        return ok({"by_status": by_status, "new_7d": new_7d})


@app.get("/analytics/activity")
def analytics_activity() -> dict[str, Any]:
    """Activity analytics: counts grouped by activity type.

    Returns:
        Envelope with ``by_type`` map.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT type, COUNT(*) n FROM echo_crm.activities GROUP BY type ORDER BY n DESC LIMIT 20"
        )
        by_type = {r[0]: r[1] for r in cur.fetchall()}
        return ok({"by_type": by_type})


@app.get("/analytics/revenue")
def analytics_revenue() -> dict[str, Any]:
    """Revenue analytics: monthly won-deal totals (last 12 months).

    Returns:
        Envelope with ``monthly_won`` series.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT DATE_TRUNC('month', created_at) m, COALESCE(SUM(value),0) v "
            "FROM echo_crm.deals WHERE status='won' GROUP BY m ORDER BY m DESC LIMIT 12"
        )
        monthly = [{"month": str(r[0]), "value": float(r[1])} for r in cur.fetchall()]
        return ok({"monthly_won": monthly})


# Import / Export
@app.post("/import/contacts")
def import_contacts(body: dict[str, Any]) -> dict[str, Any]:
    """Bulk-import contacts from a JSON array (max 500 rows).

    Args:
        body: JSON with required ``contacts`` array of contact objects.

    Returns:
        Envelope with import_id and imported/skipped/errors counts.
    """
    err = require_body(body, "contacts")
    if err:
        return fail(err)
    contacts = body["contacts"]
    if not isinstance(contacts, list):
        return fail("contacts must be an array")
    if len(contacts) > 500:
        return fail("Max 500 contacts per import")
    import_id = uid()
    imported = skipped = errors = 0
    with _db() as con, con.cursor() as cur:
        for c in contacts:
            try:
                if not c.get("first_name"):
                    skipped += 1
                    continue
                cid = uid()
                now = now_iso()
                cur.execute(
                    "INSERT INTO echo_crm.contacts (id, first_name, last_name, email, phone, title, "
                    "source, lead_status, company_id, created_at, updated_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (cid, sanitize(c["first_name"], 100), sanitize(c.get("last_name") or "", 100),
                     sanitize(c.get("email") or "", 200), sanitize(c.get("phone") or "", 30),
                     sanitize(c.get("title") or "", 100), c.get("source") or "import", "new",
                     c.get("company_id"), now, now)
                )
                imported += 1
            except Exception:
                errors += 1
        status = "partial" if errors else "completed"
        cur.execute(
            "INSERT INTO echo_crm.imports (id, type, total_rows, imported, skipped, errors, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,now())",
            (import_id, "contacts", len(contacts), imported, skipped, errors, status)
        )
        _log_activity(cur, "import", import_id, "completed", f"imported={imported}")
    log("info", "Contacts imported", {"import_id": import_id, "imported": imported, "errors": errors})
    return ok({"import_id": import_id, "imported": imported, "skipped": skipped, "errors": errors})


@app.get("/export/contacts")
def export_contacts() -> dict[str, Any]:
    """Export contacts as JSON (capped at 5000 rows).

    Returns:
        Envelope with ``contacts`` array and ``count``.
    """
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_crm.contacts ORDER BY created_at DESC LIMIT 5000")
        rows = [dict(r) for r in cur.fetchall()]
        return ok({"contacts": rows, "count": len(rows)})


# Activity log
@app.get("/activity-log")
def activity_log(request: Request) -> dict[str, Any]:
    """Query the CRM activity_log audit trail.

    Query params: ``entity_type``, ``entity_id``, ``limit``, ``offset``.

    Args:
        request: HTTP request.

    Returns:
        Envelope with ``log`` array ordered newest-first.
    """
    limit, offset = paginate_params(request)
    try:
        et = validate_entity_type(request.query_params.get("entity_type"))
        eid = validate_optional_id(request.query_params.get("entity_id"), "entity_id")
    except ValueError as exc:
        return fail(str(exc), 400)
    where = "1=1"
    binds: list[Any] = []
    if et:
        where += " AND entity_type=%s"
        binds.append(et)
    if eid:
        where += " AND entity_id=%s"
        binds.append(eid)
    binds2 = binds + [limit, offset]
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM echo_crm.activity_log WHERE " + where + " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            binds2,
        )
        return ok({"log": [dict(r) for r in cur.fetchall()]})


# Plans + Stripe (note: tenants table created on demand by admin/migrate)
@app.get("/plans")
def get_plans() -> dict[str, Any]:
    """List Echo CRM subscription plans (Free/Starter/Professional/Enterprise).

    Returns:
        Envelope with ``plans`` catalog.
    """
    return ok({"plans": CRM_PLANS, "service": "echo-crm"})


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> dict[str, Any]:
    """Handle Stripe webhook events with signature verification.

    Verifies ``Stripe-Signature`` against ``STRIPE_WEBHOOK_SECRET`` (5-minute
    replay window). Updates tenant plan on checkout.session.completed and
    downgrades on customer.subscription.deleted.

    Args:
        request: Raw HTTP request (body + signature header).

    Returns:
        Envelope confirming receipt, or auth/processing error.
    """
    raw = await request.body()
    if len(raw) > 1_048_576:
        return fail("payload too large", 413)
    body = raw.decode("utf-8", errors="replace")
    sig = request.headers.get("stripe-signature", "")
    secret = stripe_webhook_secret()
    if not secret:
        return fail("Webhook secret not configured", 503)
    if not verify_stripe_signature(body, sig, secret):
        log("warn", "Stripe webhook signature invalid")
        return fail("Invalid signature", 401)
    try:
        event = json.loads(body)
        log("info", "Stripe webhook received", {"type": event.get("type")})
        et = event.get("type")
        obj = (event.get("data") or {}).get("object") or {}
        with _db() as con, con.cursor() as cur:
            if et == "checkout.session.completed":
                meta = obj.get("metadata") or {}
                tenant_id = meta.get("tenant_id")
                plan_id = meta.get("plan_id")
                try:
                    if tenant_id:
                        tenant_id = validate_id(str(tenant_id), "tenant_id")
                    if plan_id:
                        plan_id = validate_plan(str(plan_id))
                except ValueError:
                    tenant_id = plan_id = None
                if tenant_id and plan_id:
                    cur.execute(
                        "UPDATE echo_crm.tenants SET plan=%s, stripe_customer_id=%s, "
                        "stripe_subscription_id=%s, updated_at=now() WHERE id=%s",
                        (plan_id, obj.get("customer"), obj.get("subscription"), tenant_id)
                    )
                    log("info", "Tenant upgraded via Stripe", {"tenant": tenant_id, "plan": plan_id})
            elif et == "customer.subscription.deleted":
                cust = obj.get("customer")
                if cust:
                    cur.execute(
                        "UPDATE echo_crm.tenants SET plan='free', stripe_subscription_id=NULL, "
                        "updated_at=now() WHERE stripe_customer_id=%s",
                        (cust,)
                    )
                    log("info", "Tenant downgraded to free", {"customer": cust})
        return ok({"received": True})
    except Exception as e:
        log("error", "Stripe webhook processing failed", {"error": str(e)[:200]})
        return fail("Webhook processing error", 500)


@app.post("/plans/upgrade")
async def plans_upgrade(body: dict[str, Any]) -> dict[str, Any]:
    """Create a Stripe Checkout session for a tenant plan upgrade.

    Args:
        body: JSON with required ``tenant_id`` and ``plan_id``.

    Returns:
        Envelope with ``checkout_url`` and ``session_id`` when Stripe is configured.
    """
    err = require_body(body, "tenant_id", "plan_id")
    if err:
        return fail(err)
    try:
        tenant_id = validate_id(str(body["tenant_id"]), "tenant_id")
        plan_id = validate_plan(str(body["plan_id"]))
    except ValueError as exc:
        return fail(str(exc), 400)
    plan = next((p for p in CRM_PLANS if p["id"] == plan_id), None)
    if not plan:
        return fail("Invalid plan_id")
    secret = stripe_secret_key()
    if not secret:
        return fail("Stripe not configured", 503)
    try:
        price: float | int = plan["price"]
        params = urllib.parse.urlencode({
            "mode": "subscription",
            "success_url": "https://echo-ept.com/dashboard?upgrade=success",
            "cancel_url": "https://echo-ept.com/dashboard?upgrade=cancel",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(int(round(price * 100))),
            "line_items[0][price_data][recurring][interval]": "month",
            "line_items[0][price_data][product_data][name]": f"Echo CRM - {plan['name']}",
            "metadata[tenant_id]": tenant_id,
            "metadata[plan_id]": plan["id"],
        })
        req = urllib.request.Request(
            "https://api.stripe.com/v1/checkout/sessions",
            data=params.encode(),
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            session = json.loads(resp.read())
        if resp.status >= 400:
            return fail("Stripe checkout creation failed", 500)
        return ok({"checkout_url": session.get("url"), "session_id": session.get("id")})
    except Exception as e:
        log("error", "Stripe API error", {"error": str(e)[:200]})
        return fail("Payment service unavailable", 503)


@app.post("/admin/migrate-stripe")
def admin_migrate_stripe() -> dict[str, Any]:
    """Ensure the ``echo_crm.tenants`` table exists (idempotent admin op).

    Returns:
        Envelope confirming migration of tenants table.
    """
    with _db() as con, con.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS echo_crm.tenants (
                id TEXT PRIMARY KEY, name TEXT, plan TEXT DEFAULT 'free',
                stripe_customer_id TEXT, stripe_subscription_id TEXT,
                created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now()
            )
        """)
        log("info", "Stripe migration complete")
        return ok({"migrated": True, "tables": ["tenants"]})


# Weekly digest (invokable; real cron via systemd timer or external scheduler)
@app.post("/internal/cron/weekly-digest")
def weekly_digest() -> dict[str, Any]:
    """Build a weekly CRM digest and optionally ingest it to Shared Brain.

    Aggregates open deal value, wins this week, overdue activities, and new
    contacts. Posts to ``ECHO_SHARED_BRAIN_URL`` when configured.

    Returns:
        Envelope with the digest text.
    """
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute("SELECT COUNT(*) n, COALESCE(SUM(value),0) total FROM echo_crm.deals WHERE status='open'")
            open_d = cur.fetchone()
            cur.execute(
                "SELECT COUNT(*) n, COALESCE(SUM(value),0) total FROM echo_crm.deals "
                "WHERE status='won' AND actual_close_date >= now() - interval '7 days'"
            )
            won = cur.fetchone()
            cur.execute(
                "SELECT COUNT(*) n FROM echo_crm.activities WHERE is_done=0 AND due_date < now()"
            )
            overdue = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone()) or 0
            cur.execute(
                "SELECT COUNT(*) n FROM echo_crm.contacts WHERE created_at >= now() - interval '7 days'"
            )
            new_c = (lambda _r: (list(_r.values()) if hasattr(_r, "values") else (_r or [0]))[0])(cur.fetchone()) or 0

            digest = (
                f"CRM Weekly: {open_d[0] or 0} open deals (${open_d[1] or 0}), "
                f"{won[0] or 0} won this week (${won[1] or 0}), "
                f"{overdue} overdue activities, {new_c} new contacts"
            )
            log("info", digest)
            _ingest_brain(digest, ["crm", "digest"])
        return ok({"digest": digest})
    except Exception as e:
        log("error", "Weekly digest failed", {"error": str(e)[:200]})
        return fail("Digest failed", 500)


@app.on_event("shutdown")
def _shutdown() -> None:
    m = metrics.get_metrics()
    log("info", "echo-crm shutting down", {
        "uptime_sec": m["uptime_seconds"],
        "total_requests": m["requests_total"],
        "total_errors": m["request_errors_total"],
        "db_queries": m["db_queries_total"],
        "db_errors": m["db_errors_total"]
    })
