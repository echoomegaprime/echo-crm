"""Security layer for echo-crm — vault-backed secrets, authz, input validation.

Secrets load order: vault (echo-crm service via vault.read_secret / echo.vault.get)
  -> environment -> sovereign key file. No hardcoded credential defaults in production paths.

Authz tiers (ENDPOINT_AUTH):
  public  — root, health
  read    — list/get CRM entities, analytics, metrics, plans catalog
  write   — create/update CRM entities, import, lead scoring
  admin   — plan upgrade, stripe migrate, weekly digest cron, destructive admin
  webhook — Stripe signature verification (not API key)
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import Header, HTTPException, Request

logger = logging.getLogger("echo_crm.security")

VAULT_SERVICE = "echo-crm"
SDK_GATE_URL = os.environ.get("SDK_GATE_URL", os.environ.get("ECHO_SDK_GATE_URL", "http://127.0.0.1:8000"))
VAULT_URL = os.environ.get("VAULT_API_URL", os.environ.get("ECHO_VAULT_URL", ""))
DEV_MODE_ENV = "ECHO_CRM_DEV_MODE"

AUTH_PUBLIC = "public"
AUTH_READ = "read"
AUTH_WRITE = "write"
AUTH_ADMIN = "admin"
AUTH_WEBHOOK = "webhook"

# Logical endpoint keys → auth tier
ENDPOINT_AUTH: dict[str, str] = {
    "root": AUTH_PUBLIC,
    "health": AUTH_PUBLIC,
    "ready": AUTH_PUBLIC,
    "resilience": AUTH_PUBLIC,
    "resilience.flush": AUTH_ADMIN,
    "status": AUTH_READ,
    "metrics": AUTH_READ,
    "pipelines.list": AUTH_READ,
    "pipelines.create": AUTH_WRITE,
    "pipelines.get": AUTH_READ,
    "pipelines.delete": AUTH_WRITE,
    "stages.list": AUTH_READ,
    "stages.create": AUTH_WRITE,
    "stages.update": AUTH_WRITE,
    "stages.delete": AUTH_WRITE,
    "contacts.list": AUTH_READ,
    "contacts.create": AUTH_WRITE,
    "contacts.get": AUTH_READ,
    "contacts.update": AUTH_WRITE,
    "contacts.delete": AUTH_WRITE,
    "companies.list": AUTH_READ,
    "companies.create": AUTH_WRITE,
    "companies.get": AUTH_READ,
    "companies.update": AUTH_WRITE,
    "companies.delete": AUTH_WRITE,
    "deals.list": AUTH_READ,
    "deals.board": AUTH_READ,
    "deals.create": AUTH_WRITE,
    "deals.get": AUTH_READ,
    "deals.update": AUTH_WRITE,
    "deals.delete": AUTH_WRITE,
    "deals.move": AUTH_WRITE,
    "activities.list": AUTH_READ,
    "activities.create": AUTH_WRITE,
    "activities.update": AUTH_WRITE,
    "activities.delete": AUTH_WRITE,
    "notes.list": AUTH_READ,
    "notes.create": AUTH_WRITE,
    "notes.delete": AUTH_WRITE,
    "tags.list": AUTH_READ,
    "tags.create": AUTH_WRITE,
    "tags.delete": AUTH_WRITE,
    "email_events.create": AUTH_WRITE,
    "email_events.list": AUTH_READ,
    "lead_scoring.rules.list": AUTH_READ,
    "lead_scoring.rules.create": AUTH_WRITE,
    "lead_scoring.rules.delete": AUTH_WRITE,
    "lead_scoring.score": AUTH_WRITE,
    "analytics.pipeline": AUTH_READ,
    "analytics.contacts": AUTH_READ,
    "analytics.activity": AUTH_READ,
    "analytics.revenue": AUTH_READ,
    "import.contacts": AUTH_WRITE,
    "export.contacts": AUTH_READ,
    "activity_log.list": AUTH_READ,
    "plans.list": AUTH_READ,
    "plans.upgrade": AUTH_ADMIN,
    "webhooks.stripe": AUTH_WEBHOOK,
    "admin.migrate_stripe": AUTH_ADMIN,
    "internal.weekly_digest": AUTH_ADMIN,
}

# Identifiers: alphanumerics, underscore, hyphen, colon, dot — no spaces/SQL metachar
ID_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,128}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^[0-9+\-\s().]{0,40}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{3,8}$")
SAFE_NAME_RE = re.compile(r"^[\w\s\-\.'&,/()+#]{1,200}$", re.UNICODE)
SEARCH_RE = re.compile(r"^[\w\s@.\-+#']{1,200}$", re.UNICODE)

LEAD_STATUS_WHITELIST = frozenset(
    {"new", "contacted", "qualified", "unqualified", "nurturing", "converted", "lost", "open"}
)
DEAL_STATUS_WHITELIST = frozenset({"open", "won", "lost", "pending"})
ACTIVITY_TYPE_WHITELIST = frozenset(
    {"call", "email", "meeting", "task", "note", "demo", "follow_up", "other", "sms", "linkedin"}
)
SOURCE_WHITELIST = frozenset(
    {"manual", "import", "web", "referral", "ads", "organic", "partner", "event", "api", "stripe", "zoho"}
)
PLAN_WHITELIST = frozenset({"free", "starter", "professional", "enterprise"})
OPERATOR_WHITELIST = frozenset({"equals", "contains", "not_empty", "gt", "lt", "gte", "lte"})
ENTITY_TYPE_WHITELIST = frozenset(
    {"contact", "company", "deal", "activity", "note", "tag", "pipeline", "stage", "import", "email_event"}
)

_secret_cache: dict[str, tuple[str, float]] = {}
_CACHE_TTL = 300.0


def _cache_get(key: str) -> str | None:
    entry = _secret_cache.get(key)
    if not entry:
        return None
    value, expires = entry
    if time.time() > expires:
        _secret_cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value: str) -> None:
    _secret_cache[key] = (value, time.time() + _CACHE_TTL)


def clear_secret_cache() -> None:
    """Test helper — drop all cached secrets."""
    _secret_cache.clear()


def _dev_mode() -> bool:
    return os.environ.get(DEV_MODE_ENV, "") in ("1", "true", "yes")


def secure_compare(a: str | None, b: str | None) -> bool:
    """Constant-time string compare resistant to length-oracle timing attacks."""
    if a is None or b is None:
        return False
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    # Hash first so compare_digest never raises on unequal lengths
    ha = hashlib.sha256(a.encode("utf-8", errors="replace")).digest()
    hb = hashlib.sha256(b.encode("utf-8", errors="replace")).digest()
    return hmac.compare_digest(ha, hb)


def _load_sovereign_key() -> str:
    cached = _cache_get("ECHO_API_KEY")
    if cached is not None:
        return cached
    for env_name in ("ECHO_CRM_API_KEY", "ECHO_API_KEY", "SOVEREIGN_KEY"):
        val = os.environ.get(env_name, "")
        if val:
            _cache_put("ECHO_API_KEY", val)
            return val
    for path in (
        "/home/forge/.echo_sovereign_key",
        os.path.expanduser("~/.echo_sovereign_key"),
    ):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
                if raw.startswith("SOVEREIGN_KEY="):
                    val = raw.split("=", 1)[1].strip()
                else:
                    # Support multi-line files with SOVEREIGN_KEY=
                    for line in raw.splitlines():
                        if line.startswith("SOVEREIGN_KEY="):
                            val = line.split("=", 1)[1].strip()
                            break
                    else:
                        val = raw
                if val:
                    _cache_put("ECHO_API_KEY", val)
                    return val
        except OSError:
            continue
    return ""


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 8,
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw[:200]}
        return exc.code, parsed
    except Exception as exc:
        logger.warning("http %s %s failed: %s", method, url, exc)
        return 0, {}


def _sdk_invoke(capability: str, params: dict[str, Any], timeout: int = 8) -> Any:
    api_key = _load_sovereign_key()
    if not api_key:
        return None
    status, data = _http_json(
        f"{SDK_GATE_URL.rstrip('/')}/sdk/invoke",
        method="POST",
        headers={"X-Echo-API-Key": api_key, "Content-Type": "application/json"},
        body={"envelope_version": 1, "capability": capability, "params": params},
        timeout=timeout,
    )
    if status and status < 300 and isinstance(data, dict) and data.get("status") == "ok":
        result = data.get("result") or {}
        if isinstance(result, dict) and "body" in result:
            return result.get("body")
        return result
    return None


def vault_read_secret(service: str, key_name: str | None = None) -> str:
    """Read a secret from Echo Vault (SDK capabilities then optional HTTP/sqlite)."""
    cache_key = f"vault:{service}:{key_name or '*'}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    for capability, params in (
        (
            "vault.read_secret",
            {"command": "read_secret", "service": service, "key_name": key_name},
        ),
        (
            "echo.vault.get",
            {"command": "get", "service": service, "key_name": key_name},
        ),
    ):
        body = _sdk_invoke(capability, params, timeout=8)
        if isinstance(body, dict):
            for field in (key_name, "secret", "password", "api_key", "value"):
                if field and body.get(field):
                    val = str(body[field])
                    _cache_put(cache_key, val)
                    return val
            creds = body.get("credentials")
            if isinstance(creds, dict) and key_name and creds.get(key_name):
                val = str(creds[key_name])
                _cache_put(cache_key, val)
                return val

    if VAULT_URL:
        url = f"{VAULT_URL.rstrip('/')}/credentials/{urllib.parse.quote(service)}"
        if key_name:
            url += f"/{urllib.parse.quote(key_name)}"
        status, data = _http_json(
            url,
            headers={"X-Echo-API-Key": _load_sovereign_key()},
            timeout=6,
        )
        if status and status < 300 and isinstance(data, dict):
            for field in ("secret", "password", "api_key", "value", key_name or ""):
                if field and data.get(field):
                    val = str(data[field])
                    _cache_put(cache_key, val)
                    return val

    # Direct sqlite vault read (FORGE local) — read-only
    vault_path = os.environ.get("ECHO_VAULT_PATH", "/home/forge/master_vault.db")
    if key_name and os.path.exists(vault_path):
        try:
            import sqlite3

            db = sqlite3.connect(vault_path)
            try:
                row = db.execute(
                    "SELECT secret FROM credentials WHERE service=? AND username=? LIMIT 1",
                    (service, key_name),
                ).fetchone()
                if row and row[0]:
                    val = str(row[0])
                    _cache_put(cache_key, val)
                    return val
            finally:
                db.close()
        except Exception as exc:
            logger.warning("vault sqlite read failed (non-fatal): %s", type(exc).__name__)

    return ""


def load_secret(name: str, *, env_names: tuple[str, ...] = (), vault_key: str | None = None) -> str:
    """Resolve a secret: vault.read_secret -> env chain. Never returns hardcoded defaults."""
    cache_key = f"secret:{name}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    vk = vault_key or name
    val = vault_read_secret(VAULT_SERVICE, vk)
    if val:
        _cache_put(cache_key, val)
        return val

    for env_name in env_names or (name,):
        val = os.environ.get(env_name, "")
        if val:
            _cache_put(cache_key, val)
            return val

    return ""


def pg_config() -> dict[str, Any]:
    """Build psycopg2 connect kwargs; password required from vault/env (no default)."""
    password = load_secret(
        "PGPASSWORD",
        env_names=("ECHO_CRM_PG_PASSWORD", "PGPASSWORD"),
        vault_key="PGPASSWORD",
    )
    if not password:
        if _dev_mode():
            password = os.environ.get("PGPASSWORD", "")
        if not password:
            raise ValueError(
                "PGPASSWORD not configured — set ECHO_CRM_PG_PASSWORD env "
                "or vault echo-crm:PGPASSWORD via vault.read_secret"
            )
    host = os.environ.get("PGHOST") or ("localhost" if _dev_mode() else None)
    user = os.environ.get("PGUSER") or ("echo" if _dev_mode() else None)
    dbname = os.environ.get("PGDATABASE") or ("echo" if _dev_mode() else None)
    if not all([host, user, dbname]):
        raise ValueError("Missing required DB config: PGHOST, PGUSER, PGDATABASE")
    port = int(os.environ.get("PGPORT", "5432"))
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "dbname": dbname,
        "connect_timeout": 8,
    }


def stripe_secret_key() -> str:
    return load_secret(
        "STRIPE_SECRET_KEY",
        env_names=("ECHO_CRM_STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY"),
        vault_key="STRIPE_SECRET_KEY",
    )


def stripe_webhook_secret() -> str:
    return load_secret(
        "STRIPE_WEBHOOK_SECRET",
        env_names=("ECHO_CRM_STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET"),
        vault_key="STRIPE_WEBHOOK_SECRET",
    )


def api_key() -> str:
    """Service API key (vault/env/sovereign file).

    This is the *primary* process key (ECHO_CRM_API_KEY). Gate-proxied fleet
    traffic often presents a different SOVEREIGN_KEY — see ``accepted_api_keys``.
    """
    cached = _cache_get("CRM_API_KEY")
    if cached is not None:
        return cached
    # Prefer CRM-specific vault key, then shared sovereign chain
    val = load_secret(
        "ECHO_CRM_API_KEY",
        env_names=("ECHO_CRM_API_KEY", "ECHO_API_KEY", "SOVEREIGN_KEY"),
        vault_key="ECHO_CRM_API_KEY",
    )
    if not val:
        val = _load_sovereign_key()
    if val:
        _cache_put("CRM_API_KEY", val)
    return val


def _read_sovereign_key_file() -> str:
    """Load fleet SOVEREIGN_KEY from well-known key files (not process CRM key)."""
    for path in (
        "/home/forge/.echo_sovereign_key",
        "/home/forge/.sovereign_key",
        os.path.expanduser("~/.echo_sovereign_key"),
        os.path.expanduser("~/.sovereign_key"),
    ):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
            if not raw:
                continue
            if raw.startswith("SOVEREIGN_KEY="):
                return raw.split("=", 1)[1].strip()
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("SOVEREIGN_KEY="):
                    return line.split("=", 1)[1].strip()
            # bare key file
            if raw and "=" not in raw.splitlines()[0]:
                return raw
        except OSError:
            continue
    return ""


def accepted_api_keys() -> list[str]:
    """Keys accepted for read/write/admin endpoints.

    The SDK gate proxies ``echo.crm.*`` (handler_kind=http → :8142) with the
    caller's ``X-Echo-API-Key`` — typically the fleet SOVEREIGN key. That key
    often differs from process-local ``ECHO_CRM_API_KEY`` in echo-crm.env, which
    previously made every authenticated CRM route return 401 through the gate
    and broke composites such as ``echo.composite.list_health_324c3a``
    (deals.list → health).

    Accept the service key AND fleet keys (env + sovereign key file + optional
    comma-list ``ECHO_ACCEPTED_API_KEYS``), matching the echo-scheduler pattern
    used for ``echo.composite.health_stats_db86c9``.
    """
    cached = _cache_get("ACCEPTED_API_KEYS")
    if cached is not None:
        # cached as newline-joined for the simple secret cache (str values)
        return [k for k in cached.split("\n") if k]

    keys: list[str] = []
    seen: set[str] = set()

    def _add(val: str | None) -> None:
        v = (val or "").strip()
        if not v or v in seen:
            return
        seen.add(v)
        keys.append(v)

    # Primary CRM service key (vault/env chain)
    _add(api_key())

    for env_name in (
        "ECHO_CRM_API_KEY",
        "ECHO_API_KEY",
        "SOVEREIGN_KEY",
        "ECHO_SOVEREIGN_KEY",
        "ECHO_FLEET_API_KEY",
    ):
        _add(os.environ.get(env_name))

    extra = (os.environ.get("ECHO_ACCEPTED_API_KEYS") or "").strip()
    if extra:
        for part in extra.split(","):
            _add(part)

    # Fleet sovereign key file — CRM unit often does not inject SOVEREIGN_KEY
    _add(_read_sovereign_key_file())

    if keys:
        # Cache joined with newlines (keys themselves never contain newlines)
        _cache_put("ACCEPTED_API_KEYS", "\n".join(keys))
    return keys


def _key_accepted(presented: str, accepted: list[str]) -> bool:
    """Timing-safe membership: compare against every accepted key."""
    ok = False
    for expected in accepted:
        # OR without short-circuit on first match so every compare runs
        if secure_compare(presented, expected):
            ok = True
    return ok


def _check_auth(endpoint: str, x_echo_api_key: str | None) -> dict[str, Any]:
    """Core authz check for an endpoint tier."""
    tier = ENDPOINT_AUTH.get(endpoint, AUTH_WRITE)
    ctx: dict[str, Any] = {
        "authenticated": False,
        "tier": tier,
        "principal": "anonymous",
        "endpoint": endpoint,
    }

    if tier == AUTH_PUBLIC:
        ctx["authenticated"] = True
        return ctx

    if tier == AUTH_WEBHOOK:
        # Webhook handlers verify signatures themselves.
        raise HTTPException(500, "webhook endpoints use signature auth, not API key")

    accepted = accepted_api_keys()
    if not accepted:
        if _dev_mode():
            logger.warning("dev_mode: auth bypass for endpoint=%s", endpoint)
            ctx["authenticated"] = True
            ctx["principal"] = "dev"
            return ctx
        logger.error("auth misconfigured: API key not set for endpoint=%s", endpoint)
        raise HTTPException(503, "service auth not configured")

    if not x_echo_api_key:
        raise HTTPException(401, "unauthorized")

    if len(x_echo_api_key) > 2048:
        raise HTTPException(401, "invalid api key")

    if not _key_accepted(x_echo_api_key, accepted):
        logger.warning(
            "auth_failure endpoint=%s reason=key_mismatch key_hash=%s accepted_n=%s",
            endpoint,
            hashlib.sha256(x_echo_api_key.encode()).hexdigest()[:16],
            len(accepted),
        )
        raise HTTPException(401, "unauthorized")

    ctx["authenticated"] = True
    ctx["principal"] = "api_key"
    return ctx


def auth_dependency(endpoint: str):
    """FastAPI dependency factory: enforce tiered authz per endpoint."""

    def _dependency(
        x_echo_api_key: str | None = Header(default=None, alias="X-Echo-API-Key"),
    ) -> dict[str, Any]:
        return _check_auth(endpoint, x_echo_api_key)

    return _dependency


def require_auth(endpoint: str, x_echo_api_key: str | None) -> dict[str, Any]:
    """Programmatic authz gate (non-Depends callers)."""
    return _check_auth(endpoint, x_echo_api_key)


def resolve_endpoint(method: str, path: str) -> str:
    """Map HTTP method+path to ENDPOINT_AUTH key."""
    method = (method or "GET").upper()
    path = (path or "/").rstrip("/") or "/"

    exact: dict[tuple[str, str], str] = {
        ("GET", "/"): "root",
        ("GET", "/health"): "health",
        ("GET", "/ready"): "ready",
        ("GET", "/resilience"): "resilience",
        ("POST", "/resilience/flush"): "resilience.flush",
        ("GET", "/status"): "status",
        ("GET", "/metrics"): "metrics",
        ("GET", "/pipelines"): "pipelines.list",
        ("POST", "/pipelines"): "pipelines.create",
        ("GET", "/deals"): "deals.list",
        ("GET", "/deals/board"): "deals.board",
        ("POST", "/deals"): "deals.create",
        ("GET", "/contacts"): "contacts.list",
        ("POST", "/contacts"): "contacts.create",
        ("GET", "/companies"): "companies.list",
        ("POST", "/companies"): "companies.create",
        ("GET", "/activities"): "activities.list",
        ("POST", "/activities"): "activities.create",
        ("GET", "/notes"): "notes.list",
        ("POST", "/notes"): "notes.create",
        ("GET", "/tags"): "tags.list",
        ("POST", "/tags"): "tags.create",
        ("POST", "/email-events"): "email_events.create",
        ("GET", "/email-events"): "email_events.list",
        ("GET", "/lead-scoring/rules"): "lead_scoring.rules.list",
        ("POST", "/lead-scoring/rules"): "lead_scoring.rules.create",
        ("POST", "/lead-scoring/score"): "lead_scoring.score",
        ("GET", "/analytics/pipeline"): "analytics.pipeline",
        ("GET", "/analytics/contacts"): "analytics.contacts",
        ("GET", "/analytics/activity"): "analytics.activity",
        ("GET", "/analytics/revenue"): "analytics.revenue",
        ("POST", "/import/contacts"): "import.contacts",
        ("GET", "/export/contacts"): "export.contacts",
        ("GET", "/activity-log"): "activity_log.list",
        ("GET", "/plans"): "plans.list",
        ("POST", "/plans/upgrade"): "plans.upgrade",
        ("POST", "/webhooks/stripe"): "webhooks.stripe",
        ("POST", "/admin/migrate-stripe"): "admin.migrate_stripe",
        ("POST", "/internal/cron/weekly-digest"): "internal.weekly_digest",
    }
    hit = exact.get((method, path))
    if hit:
        return hit

    # Path-param routes
    if method == "GET" and path.startswith("/pipelines/") and path.endswith("/stages"):
        return "stages.list"
    if method == "POST" and path.startswith("/pipelines/") and path.endswith("/stages"):
        return "stages.create"
    if method == "GET" and path.startswith("/pipelines/"):
        return "pipelines.get"
    if method == "DELETE" and path.startswith("/pipelines/"):
        return "pipelines.delete"
    if method == "PUT" and path.startswith("/stages/"):
        return "stages.update"
    if method == "DELETE" and path.startswith("/stages/"):
        return "stages.delete"
    if method == "GET" and path.startswith("/contacts/"):
        return "contacts.get"
    if method == "PUT" and path.startswith("/contacts/"):
        return "contacts.update"
    if method == "DELETE" and path.startswith("/contacts/"):
        return "contacts.delete"
    if method == "GET" and path.startswith("/companies/"):
        return "companies.get"
    if method == "PUT" and path.startswith("/companies/"):
        return "companies.update"
    if method == "DELETE" and path.startswith("/companies/"):
        return "companies.delete"
    if method == "POST" and path.startswith("/deals/") and path.endswith("/move"):
        return "deals.move"
    if method == "GET" and path.startswith("/deals/"):
        return "deals.get"
    if method == "PUT" and path.startswith("/deals/"):
        return "deals.update"
    if method == "DELETE" and path.startswith("/deals/"):
        return "deals.delete"
    if method == "PUT" and path.startswith("/activities/"):
        return "activities.update"
    if method == "DELETE" and path.startswith("/activities/"):
        return "activities.delete"
    if method == "DELETE" and path.startswith("/notes/"):
        return "notes.delete"
    if method == "DELETE" and path.startswith("/tags/"):
        return "tags.delete"
    if method == "DELETE" and path.startswith("/lead-scoring/rules/"):
        return "lead_scoring.rules.delete"

    # Default deny-ish: require write auth
    return "unknown.write"


def path_auth_dependency():
    """App-level dependency: resolve path → endpoint and enforce authz."""

    def _dependency(
        request: Request,
        x_echo_api_key: str | None = Header(default=None, alias="X-Echo-API-Key"),
    ) -> dict[str, Any]:
        if request.method.upper() == "OPTIONS":
            return {
                "authenticated": True,
                "tier": AUTH_PUBLIC,
                "principal": "cors_preflight",
                "endpoint": "options",
            }
        endpoint = resolve_endpoint(request.method, request.url.path)
        tier = ENDPOINT_AUTH.get(endpoint, AUTH_WRITE)
        if tier == AUTH_WEBHOOK:
            return {
                "authenticated": False,
                "tier": AUTH_WEBHOOK,
                "principal": "webhook",
                "endpoint": endpoint,
            }
        return _check_auth(endpoint, x_echo_api_key)

    return _dependency


def verify_stripe_signature(payload: bytes | str, sig_header: str, secret: str) -> bool:
    """Stripe webhook HMAC verification (v1 scheme, 5-minute tolerance)."""
    if not sig_header or not secret:
        return False
    if isinstance(payload, str):
        payload_b = payload.encode("utf-8")
        payload_s = payload
    else:
        payload_b = payload
        payload_s = payload.decode("utf-8", errors="replace")
    try:
        parts = dict(part.split("=", 1) for part in sig_header.split(",") if "=" in part)
        timestamp = parts.get("t", "")
        signatures = [part.split("=", 1)[1] for part in sig_header.split(",") if part.startswith("v1=")]
        if not timestamp or not signatures:
            return False
        if abs(time.time() - int(timestamp)) > 300:
            return False
        signed = timestamp.encode() + b"." + payload_b
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return any(hmac.compare_digest(expected, sig) for sig in signatures)
    except Exception:
        try:
            parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
            ts = parts.get("t")
            v1 = parts.get("v1")
            if not ts or not v1:
                return False
            if abs(int(time.time()) - int(ts)) > 300:
                return False
            signed = f"{ts}.{payload_s}".encode()
            mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
            return hmac.compare_digest(mac, v1)
        except Exception:
            return False


# --- Input validation / escaping -------------------------------------------------


def validate_id(value: str, field: str = "id") -> str:
    value = (value or "").strip()
    if not value or len(value) > 128 or not ID_RE.match(value):
        raise ValueError(f"invalid {field}")
    return value


def validate_optional_id(value: str | None, field: str = "id") -> str | None:
    if value is None or value == "":
        return None
    return validate_id(str(value), field)


def validate_email(email: str | None) -> str | None:
    if email is None or email == "":
        return None
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise ValueError("invalid email")
    return email


def validate_name(name: str, field: str = "name", max_len: int = 200) -> str:
    name = (name or "").strip()
    if not name or len(name) > max_len:
        raise ValueError(f"invalid {field}")
    if any(ord(c) < 32 for c in name):
        raise ValueError(f"invalid {field}")
    if re.search(r"[;<>`]", name):
        raise ValueError(f"invalid {field}")
    return name


def validate_text(text: str | None, field: str = "text", max_len: int = 4000, *, required: bool = False) -> str | None:
    if text is None:
        if required:
            raise ValueError(f"invalid {field}")
        return None
    text = str(text).strip()
    if not text:
        if required:
            raise ValueError(f"invalid {field}")
        return None
    if len(text) > max_len:
        raise ValueError(f"{field} too long")
    if any(ord(c) < 9 or ord(c) in (11, 12) for c in text if ord(c) < 32):
        raise ValueError(f"{field} contains control characters")
    return text


def validate_phone(phone: str | None) -> str | None:
    if phone is None or phone == "":
        return None
    phone = phone.strip()
    if not PHONE_RE.match(phone):
        raise ValueError("invalid phone")
    return phone


def validate_currency(currency: str | None) -> str:
    currency = (currency or "USD").strip().upper()
    if not CURRENCY_RE.match(currency):
        raise ValueError("invalid currency")
    return currency


def validate_country(country: str | None) -> str:
    country = (country or "US").strip().upper()
    if not COUNTRY_RE.match(country):
        raise ValueError("invalid country")
    return country


def validate_lead_status(status: str | None) -> str | None:
    if status is None or status == "":
        return None
    status = status.strip().lower()
    if status not in LEAD_STATUS_WHITELIST:
        raise ValueError("invalid lead_status")
    return status


def validate_deal_status(status: str | None) -> str | None:
    if status is None or status == "":
        return None
    status = status.strip().lower()
    if status not in DEAL_STATUS_WHITELIST:
        raise ValueError("invalid deal status")
    return status


def validate_activity_type(typ: str | None) -> str:
    typ = (typ or "").strip().lower()
    if typ not in ACTIVITY_TYPE_WHITELIST:
        # allow unknown short alphanumerics for extensibility, still sanitized
        if not typ or len(typ) > 50 or not re.match(r"^[a-z0-9_\-]{1,50}$", typ):
            raise ValueError("invalid activity type")
    return typ


def validate_source(source: str | None) -> str:
    source = (source or "manual").strip().lower()
    if source in SOURCE_WHITELIST:
        return source
    if not re.match(r"^[a-z0-9_\-]{1,64}$", source):
        raise ValueError("invalid source")
    return source


def validate_plan(plan_id: str) -> str:
    plan_id = (plan_id or "").strip().lower()
    if plan_id not in PLAN_WHITELIST:
        raise ValueError("invalid plan_id")
    return plan_id


def validate_operator(op: str) -> str:
    op = (op or "").strip().lower()
    if op not in OPERATOR_WHITELIST:
        raise ValueError("invalid operator")
    return op


def validate_entity_type(et: str | None) -> str | None:
    if et is None or et == "":
        return None
    et = et.strip().lower()
    if et not in ENTITY_TYPE_WHITELIST:
        raise ValueError("invalid entity_type")
    return et


def validate_color(color: str | None) -> str:
    color = (color or "#6366f1").strip()
    if not COLOR_RE.match(color):
        raise ValueError("invalid color")
    return color


def validate_search(q: str | None) -> str | None:
    if q is None or q == "":
        return None
    q = q.strip()
    if len(q) > 200:
        raise ValueError("search query too long")
    if any(c in q for c in ("\x00", "\r", "\n", ";", "--")):
        raise ValueError("invalid search query")
    return q


def validate_amount(value: Any, field: str = "value", *, allow_zero: bool = True) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if v != v or v == float("inf") or v == float("-inf"):
        raise ValueError(f"invalid {field}")
    if allow_zero:
        if v < 0 or v > 1_000_000_000:
            raise ValueError(f"invalid {field}")
    else:
        if v <= 0 or v > 1_000_000_000:
            raise ValueError(f"invalid {field}")
    return round(v, 4)


def validate_score(value: Any) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid score") from exc
    if v < -1000 or v > 1000:
        raise ValueError("invalid score")
    return v


def validate_probability(value: Any) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid probability") from exc
    if v != v or v < 0 or v > 100:
        raise ValueError("invalid probability")
    return round(v, 4)


def validate_position(value: Any) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid position") from exc
    if v < 0 or v > 10_000:
        raise ValueError("invalid position")
    return v


def validate_limit(limit: int, default: int = 50, max_limit: int = 200) -> int:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, max_limit))


def validate_offset(offset: int, max_offset: int = 1_000_000) -> int:
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    return max(0, min(offset, max_offset))


def validate_json_object(
    payload: dict[str, Any] | list[Any] | None,
    *,
    max_keys: int = 64,
    max_depth: int = 4,
    max_list: int = 500,
) -> Any:
    """Validate external JSON for size/shape; reject deep or huge payloads."""
    if payload is None:
        return None

    def _walk(obj: Any, depth: int) -> None:
        if depth > max_depth:
            raise ValueError("payload too deeply nested")
        if isinstance(obj, dict):
            if len(obj) > max_keys:
                raise ValueError("payload object too large")
            for k, v in obj.items():
                if not isinstance(k, str) or len(k) > 128:
                    raise ValueError("invalid payload key")
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            if len(obj) > max_list:
                raise ValueError("payload array too large")
            for item in obj:
                _walk(item, depth + 1)
        elif isinstance(obj, str):
            if len(obj) > 8000:
                raise ValueError("payload string too long")
        elif isinstance(obj, (int, float, bool)) or obj is None:
            return
        else:
            raise ValueError("payload contains unsupported type")

    _walk(payload, 0)
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("payload is not JSON-serializable") from exc
    return payload


def sanitize_like_pattern(value: str) -> str:
    """Escape SQL LIKE wildcards in user-provided search fragments."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def escape_html(value: str | None) -> str:
    """Escape untrusted text for HTML response bodies."""
    return html.escape(value or "", quote=True)


def sanitize(val: Any, max_len: int = 2000) -> str:
    """Coerce a value to a safe string and strip control characters."""
    if val is None:
        return ""
    s = str(val)[:max_len]
    return "".join(ch for ch in s if ch >= " " or ch in "\n\r\t")


def all_endpoint_keys() -> frozenset[str]:
    return frozenset(ENDPOINT_AUTH.keys())


def scan_for_hardcoded_secrets(source: str) -> list[str]:
    """Static scan helper for tests — detect obvious secret literals in source."""
    findings: list[str] = []
    patterns = [
        (r'password\s*=\s*["\']echo["\']', "hardcoded PG password"),
        (r'password\s*:\s*["\']echo["\']', "hardcoded PG password"),
        (r'get\(["\']PGPASSWORD["\']\s*,\s*["\']echo["\']\)', "hardcoded PG password default"),
        (r"(?m)^(?!\s*#).*PGPASSWORD=echo\b", "hardcoded PG password in service file"),
        (r"sk_live_[a-zA-Z0-9]{20,}", "stripe live key"),
        (r"whsec_[a-zA-Z0-9]{20,}", "stripe webhook secret"),
        (r'api_key\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "hardcoded api key literal"),
    ]
    cleaned_lines: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        if "r\"" in line or "r'" in line or "re.compile" in line or "re.search" in line:
            continue
        if "scan_for_hardcoded" in line:
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    for pattern, label in patterns:
        if re.search(pattern, cleaned):
            findings.append(label)
    return findings


def scan_for_unsafe_sql(source: str) -> list[str]:
    """Detect non-parameterized SQL construction patterns in app source."""
    findings: list[str] = []
    patterns = [
        (r'execute\s*\(\s*f["\']', "f-string SQL execute"),
        (r"execute\s*\(\s*f['\"]", "f-string SQL execute"),
        (r"\.execute\s*\([^)]*\.format\s*\(", "str.format execute"),
        (r"\.execute\s*\([^,]+%\s*\(", "percent-format execute"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, source):
            findings.append(label)
    return findings
