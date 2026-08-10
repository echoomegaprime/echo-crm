#!/usr/bin/env python3
"""Prometheus metrics for echo-crm.

Defines the fleet-required bare counters ``requests_total`` and ``errors_total``
plus namespaced labelled series for richer scrapers. Uses a dedicated
``CollectorRegistry`` so tests/reloads do not collide with process-global
collectors.

No new third-party dependencies beyond ``prometheus_client`` (already on FORGE).
"""
from __future__ import annotations

import time
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    generate_latest,
)

import logging_config

SERVICE = logging_config.SERVICE
VERSION = logging_config.VERSION

# Dedicated registry avoids multi-import / TestClient reload collisions.
REGISTRY = CollectorRegistry(auto_describe=True)

# ---------------------------------------------------------------------------
# Fleet-scraper friendly bare counters (exact names from build prompt)
# ---------------------------------------------------------------------------

REQUESTS_TOTAL = Counter(
    "requests_total",
    "Total HTTP requests handled by echo-crm",
    registry=REGISTRY,
)

ERRORS_TOTAL = Counter(
    "errors_total",
    "Total HTTP error responses (status >= 400) and unhandled exceptions",
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# Namespaced labelled series for Grafana / multi-service scrapers
# ---------------------------------------------------------------------------

HTTP_REQUESTS = Counter(
    "echo_crm_http_requests_total",
    "HTTP requests labelled by method, path template, and status class",
    ["method", "path", "status_class"],
    registry=REGISTRY,
)

HTTP_ERRORS = Counter(
    "echo_crm_http_errors_total",
    "HTTP errors labelled by method and path template",
    ["method", "path"],
    registry=REGISTRY,
)

DB_QUERIES = Counter(
    "echo_crm_db_queries_total",
    "Database query attempts by outcome",
    ["outcome"],
    registry=REGISTRY,
)

SERVICE_UP = Gauge(
    "echo_crm_up",
    "1 if the process is serving traffic",
    registry=REGISTRY,
)

SERVICE_INFO = Gauge(
    "echo_crm_info",
    "Service metadata (always 1); labels carry version",
    ["service", "version"],
    registry=REGISTRY,
)

UPTIME_SECONDS = Gauge(
    "echo_crm_uptime_seconds",
    "Process uptime in seconds",
    registry=REGISTRY,
)

_PROCESS_START = time.time()
SERVICE_UP.set(1)
SERVICE_INFO.labels(service=SERVICE, version=VERSION).set(1)

# Paths that should not inflate high-cardinality series (exact match only).
_SKIP_PATH_NORMALIZE = frozenset(
    {"/metrics", "/health", "/", "/healthz", "/ready", "/status", "/resilience", "/resilience/flush"}
)


def normalize_path(path: str) -> str:
    """Collapse path params to keep Prometheus label cardinality bounded."""
    raw = (path or "/").split("?", 1)[0] or "/"
    if raw in _SKIP_PATH_NORMALIZE:
        return raw
    parts = raw.strip("/").split("/")
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        # Numeric ids, UUIDs, and long tokens -> :id
        if part.isdigit() or (len(part) > 24 and part.replace("-", "").isalnum()):
            out.append(":id")
        else:
            out.append(part)
    return "/" + "/".join(out) if out else "/"


def status_class(status_code: int) -> str:
    """Map HTTP status code to a coarse class label (2xx/4xx/5xx)."""
    if status_code < 100:
        return "unknown"
    return f"{status_code // 100}xx"


def record_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float = 0.0,
) -> None:
    """Increment request/error counters for one completed HTTP exchange."""
    path_label = normalize_path(path)
    method_label = (method or "GET").upper()
    code = int(status_code)
    REQUESTS_TOTAL.inc()
    HTTP_REQUESTS.labels(
        method=method_label,
        path=path_label,
        status_class=status_class(code),
    ).inc()
    if code >= 400:
        ERRORS_TOTAL.inc()
        HTTP_ERRORS.labels(method=method_label, path=path_label).inc()
    UPTIME_SECONDS.set(max(0.0, time.time() - _PROCESS_START))
    _ = duration_ms  # reserved for future histogram series


def record_error(method: str = "GET", path: str = "/") -> None:
    """Increment error counters for unhandled handler exceptions."""
    path_label = normalize_path(path)
    method_label = (method or "GET").upper()
    REQUESTS_TOTAL.inc()
    ERRORS_TOTAL.inc()
    HTTP_REQUESTS.labels(
        method=method_label, path=path_label, status_class="5xx"
    ).inc()
    HTTP_ERRORS.labels(method=method_label, path=path_label).inc()
    UPTIME_SECONDS.set(max(0.0, time.time() - _PROCESS_START))


def record_db_query(success: bool) -> None:
    """Record a database query outcome on the Prometheus counter."""
    DB_QUERIES.labels(outcome="ok" if success else "error").inc()


def render_prometheus() -> bytes:
    """Return Prometheus exposition format body."""
    UPTIME_SECONDS.set(max(0.0, time.time() - _PROCESS_START))
    SERVICE_UP.set(1)
    return generate_latest(REGISTRY)


def metrics_content_type() -> str:
    """Content-Type for Prometheus exposition responses."""
    return CONTENT_TYPE_LATEST


def uptime_seconds() -> float:
    """Seconds since metrics module import (process start proxy)."""
    return max(0.0, time.time() - _PROCESS_START)


def counter_values() -> dict[str, float]:
    """Snapshot of bare counter values for health/status JSON payloads."""
    try:
        req = float(REQUESTS_TOTAL._value.get())  # type: ignore[attr-defined]
    except Exception:
        req = 0.0
    try:
        err = float(ERRORS_TOTAL._value.get())  # type: ignore[attr-defined]
    except Exception:
        err = 0.0
    return {
        "requests_total": req,
        "errors_total": err,
        "uptime_seconds": round(uptime_seconds(), 3),
    }


def build_health_payload(
    *,
    healthy: bool,
    version: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical /health JSON body.

    Success criteria require ``status: "ok"`` and ``version`` when healthy.
    Degraded responses use ``status: "degraded"`` while remaining HTTP 200 so
    load balancers can still read diagnostics. Legacy ``ok`` / ``checks`` fields
    are preserved for existing clients and tests.
    """
    from datetime import datetime, timezone

    counters = counter_values()
    body: dict[str, Any] = {
        "status": "ok" if healthy else "degraded",
        "ok": healthy,
        "service": SERVICE,
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "observability": {
            "structured_logging": True,
            "metrics": True,
            "prometheus": True,
            "log_file": str(logging_config.log_file_path()),
        },
        "metrics_counters": counters,
        "requests_total": counters["requests_total"],
        "errors_total": counters["errors_total"],
        "uptime_seconds": counters["uptime_seconds"],
    }
    if extra:
        body.update(extra)
    return body
