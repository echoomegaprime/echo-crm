# Echo CRM

Contacts, companies, deals, pipelines, lead scoring, revenue analytics, import/export, activity
logging, and Stripe-backed plan upgrades for the ECHO / LGE fleet.

## Runtime

The authoritative production runtime is the FastAPI service `app.py`, deployed as
`echo-crm.service` on FORGE (port 8142, Postgres schema `echo_crm`). `src/index.ts` (with
`wrangler.toml`) is the original Cloudflare Worker implementation, kept in this repository as a
reference/legacy edge surface -- it is not the production deployment target. See
[PYTHON_RUNTIME.md](PYTHON_RUNTIME.md) for Python installation, required credentials, and the
staging-first deployment gate.

Both runtimes implement the same route surface (pipelines, contacts, companies, deals, activity,
notes, tags, lead scoring, analytics, import/export, Stripe plans and webhooks), but **their
public/authenticated boundaries are not identical** -- see the two tables below rather than
assuming parity.

## Endpoints -- Python (production)

Authorization tiers come from `security.ENDPOINT_AUTH`/`resolve_endpoint()`.

| Access | Method | Path | Description |
|---|---|---|---|
| Public (`AUTH_PUBLIC`) | GET | `/`, `/health`, `/ready`, `/resilience` | Service info / health / readiness |
| Read (`AUTH_READ`, requires a valid key) | GET | `/status`, `/metrics`, `/plans`, and every list/get/analytics/export endpoint | Aggregate status, Prometheus metrics, pricing, and all CRM reads |
| Write (`AUTH_WRITE`) | POST/PUT/DELETE | create/update/delete on any CRM entity, `/import/contacts`, `/lead-scoring/*` | Mutations |
| Admin (`AUTH_ADMIN`) | POST | `/plans/upgrade`, `/admin/migrate-stripe`, `/internal/cron/weekly-digest`, `/resilience/flush` | Privileged operations |
| Webhook (`AUTH_WEBHOOK`) | POST | `/webhooks/stripe` | Signature-verified, not API-key |

## Endpoints -- Worker (legacy reference)

| Access | Method | Path | Description |
|---|---|---|---|
| Public | GET | `/`, `/health`, `/status` | Service info / health / aggregate counts (no PII) |
| Public | GET | `/plans` | Pricing tiers |
| Public | POST | `/webhooks/stripe` | Stripe webhook (signature-verified, not API-key) |
| Authenticated | ALL | everything else | Contacts, companies, deals, pipelines, activities, notes, tags, lead scoring, analytics, import/export, admin |

The Worker treats `/status` and `/plans` as fully public (no credentials at all), while the
production Python service requires a valid key for both (`AUTH_READ`). Since the Worker is a
legacy reference and not the deployment target, this divergence is documented rather than
reconciled here -- do not assume the two runtimes are interchangeable for anything beyond the
routes both treat identically (`/`, `/health`, `/webhooks/stripe`, and every entity CRUD route).

## Authentication

**Python:** `X-Echo-API-Key` or `Authorization: Bearer`, resolved per-endpoint tier via
`security.require_auth`/`auth_dependency`, using `secure_compare` (constant-time). Accepts
multiple valid keys (`accepted_api_keys()`) so the SDK gate's sovereign key works alongside the
service's own process key. See [SECURITY.md](SECURITY.md) for the full tier table and secret
resolution order.

**Worker:** every route requires `X-Echo-API-Key` or an `Authorization: Bearer` token, compared
in constant time, except the small explicit public-path allowlist above. This repository's
Worker previously had a real vulnerability where every `GET` request was exempt from auth
regardless of path, exposing the entire customer/deal database publicly; see
`tests/auth.test.mjs`'s end-to-end regression tests.

## Verify

```powershell
# Python (production runtime) -- requires a reachable Postgres
python -m pip install -r requirements-dev.txt
python -m pytest tests/ test_security.py test_observability.py -q

# Worker (legacy reference)
npm install
npm test
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability -- never as a public issue. This
service holds customer PII (contacts, companies) and financial data (deals, revenue).

## License

See [LICENSE](LICENSE). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
