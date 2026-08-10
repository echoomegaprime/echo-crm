# Security policy

Echo CRM holds customer/prospect PII (contacts, companies), sales data (deals, pipelines,
revenue analytics), and a bulk `/export/contacts` dump endpoint. The authoritative production
runtime is the FastAPI service (`app.py`, FORGE `echo-crm.service`, port 8142); `src/index.ts`
is the legacy Cloudflare Worker reference. **Their authentication boundaries are not identical**
-- see README.md's two endpoint tables before assuming a route's access level carries over
between runtimes.

## Python (production) security model

Version tag: `2.2.0-resilience` (evolved from an earlier `2.1.0-security` hardening pass;
`test_version_security_tag` in `test_security.py` still asserts the older `-security` suffix and
currently fails -- a cosmetic test-drift issue, not a security regression, tracked for cleanup).

1. **Parameterized SQL only** -- no f-string/`.format`/percent-format `execute` with user input;
   `security.scan_for_unsafe_sql` scans for violations.
2. **Vault-backed secrets, never hardcoded** -- resolution order: `vault.read_secret` /
   `echo.vault.get` -> env (`ECHO_CRM_*`, then shared) -> `~/.echo_sovereign_key`.
3. **Input validation** on IDs, email, search terms, enums, amounts, and JSON payload size.
4. **Five-tier authorization** (`security.ENDPOINT_AUTH` / `resolve_endpoint()`): public, read,
   write, admin, webhook -- resolved per exact method+path via a FastAPI dependency, not a
   blanket method-based exemption.
5. **Constant-time credential comparison** (`secure_compare`), multiple accepted keys so the SDK
   gate's sovereign key and the service's own process key both work.
6. **Security headers** on every response: `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
7. OpenAPI/docs endpoints are exposed only when `ECHO_CRM_DEV_MODE=1` (never in production).

| Secret | Env | Notes |
|---|---|---|
| Postgres password | `ECHO_CRM_PG_PASSWORD`, `PGPASSWORD` | Required; the unit does not hardcode a default |
| API key | `ECHO_CRM_API_KEY`, `ECHO_API_KEY`, `SOVEREIGN_KEY`, `ECHO_FLEET_API_KEY`, `ECHO_ACCEPTED_API_KEYS` | Constant-time compare via `secure_compare` |
| Stripe secret | `ECHO_CRM_STRIPE_SECRET_KEY`, `STRIPE_SECRET_KEY` | Plan upgrade |
| Stripe webhook | `ECHO_CRM_STRIPE_WEBHOOK_SECRET`, `STRIPE_WEBHOOK_SECRET` | HMAC v1, 5-minute skew |

`ECHO_CRM_DEV_MODE=1` is dev/test-only (used by the pytest suite) -- never set it in production
systemd.

Verify:

```bash
python3 verify_security.py
curl -s http://127.0.0.1:8142/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8142/plans   # 401 without a key
curl -s -H "X-Echo-API-Key: $ECHO_CRM_API_KEY" http://127.0.0.1:8142/plans
```

## Worker (legacy reference) security model

Every route requires `X-Echo-API-Key` or a Bearer token, compared in constant time, **except**
the small, explicit `PUBLIC_PATHS` allowlist (`/`, `/health`, `/status`, `/plans`,
`/webhooks/stripe`) -- broader than the Python service's public surface (which requires a key
for `/status` and `/plans`).

**This Worker previously had a real, serious defect**: the auth middleware exempted every
`GET`/`HEAD`/`OPTIONS` request from authentication regardless of path, leaving the entire CRM
read surface -- contacts, companies, deals, activity, notes, tags, lead-scoring rules, every
analytics endpoint, and the bulk contacts export -- publicly readable with no credentials. This
was fixed by replacing the method-based exemption with an explicit path allowlist; see
`tests/auth.test.mjs` for the regression tests and CHANGELOG.md for details.

## Supported version

Security fixes target the current `main` branch and the currently deployed release of both
runtimes. Historical commits are retained for evidence and are not patched in place.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report to
`security@echo-op.com` with:

- affected endpoint, exact revision, and which runtime (Python or Worker);
- reproduction steps and expected impact;
- whether an authentication boundary, a public-path/tier allowlist, or customer/deal data
  exposure may be involved;
- safe contact details for follow-up.

Never include a live `ECHO_CRM_API_KEY`, `ECHO_API_KEY`, `STRIPE_SECRET_KEY`, or real
customer/contact data in a report.
