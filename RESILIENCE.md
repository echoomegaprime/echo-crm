# echo-crm resilience

Production resilience for the FORGE CRM service (`:8142`). Module version: **1.0.1-resilience** (app: `2.2.0-resilience`).

## Goals

1. **Graceful degradation** when Postgres, MinIO, or the SDK gate is down — process stays up (`CRM_FAIL_OPEN=1`).
2. **Idempotent writes** via `Idempotency-Key` header ledger (in-process + disk spill).
3. **Clean retry/backoff** on transient DB/network errors (exponential + jitter, circuit breakers).

## Components (`resilience.py`)

| Primitive | Role |
|-----------|------|
| `RetryPolicy` / `retry_with_backoff` | Exponential backoff (prod: 5×, base 1s, cap 64s; request-path: 3×, 0.1–2s) |
| `is_retryable` | Classifies Postgres/network/MinIO/rate-limit errors |
| `CircuitBreaker` | Fail-fast for postgres / gate / minio after repeated failures |
| `IdempotencyStore` | Replays prior response for the same `Idempotency-Key` |
| `PendingWriteQueue` | Queues contact/company/deal/activity inserts when DB is down; flushes on recovery |
| `LastGoodCache` | Serves last-good `/status`, pipelines, contacts when DB is down |
| `MinIOOperationQueue` | Optional export/receipt put queue when MinIO is unavailable |
| `probe_*` | Dependency probes for health diagnostics |

## HTTP surface

| Path | Auth | Notes |
|------|------|-------|
| `GET /health` | public | DB ok + minio/gate checks, `resilience_version`, `mode`, `degraded`, `optional_degraded` |
| `GET /ready` | public | Accepts traffic under fail-open |
| `GET /resilience` | public | Full runtime status (queues, circuits, policies) |
| `POST /resilience/flush` | admin | Drain pending write queue |
| `POST /contacts` etc. | write | Optional `Idempotency-Key`; queues on DB failure |

Legacy contract preserved: when Postgres is down, `/health` still returns HTTP 200 with `ok=false` / `status=degraded` and `checks.database.status=unhealthy` so existing fleet tests and probes continue to work. Under fail-open the process remains up and write endpoints return `queued=true` instead of crashing.

Core degrade (`degraded=true`) tracks **Postgres**. Optional deps (configured MinIO / gate) surface as `optional_degraded=true` without failing liveness — CRM core keeps serving.

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `CRM_FAIL_OPEN` | `1` | Stay up when DB down; queue writes |
| `CRM_STATE_DIR` | `~/.cache/echo-crm` | Idempotency + pending spill files |
| `CRM_RETRY_MAX_ATTEMPTS` | `5` | Background / connect policy |
| `CRM_RETRY_BASE_DELAY` | `1.0` | Seconds |
| `CRM_RETRY_MAX_DELAY` | `64.0` | Cap seconds |
| `CRM_REQ_RETRY_*` | 3 / 0.1 / 2.0 | Request-path connect retries |
| `SDK_GATE_URL` | `http://127.0.0.1:8000` | Gate health probe |
| `MINIO_ENDPOINT` | _(empty)_ | Optional; when set, probed + queueable |

## Verify

```bash
cd SYSTEMS/echo-crm
python3 verify_resilience.py

# live
curl -sS http://127.0.0.1:8142/health | python3 -m json.tool
curl -sS http://127.0.0.1:8142/ready | python3 -m json.tool
curl -sS http://127.0.0.1:8142/resilience | python3 -m json.tool
```

## Library-first lineage

Adapted from `echo-customer-success` / `echo-analytics` fleet-standard resilience modules (not a ground-up rewrite). CRM-specific last-good helpers cover status, pipelines, contacts, companies, deals.
