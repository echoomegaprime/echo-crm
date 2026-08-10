# Security policy

Echo CRM is a Cloudflare Worker (Hono + D1 + KV + Stripe) holding customer/prospect PII
(contacts, companies), sales data (deals, pipelines, revenue analytics), and a bulk
`/export/contacts` dump endpoint. Every route requires `X-Echo-API-Key` or a Bearer token,
compared in constant time, **except** the small, explicit `PUBLIC_PATHS` allowlist
(`/`, `/health`, `/status`, `/plans`, `/webhooks/stripe`).

**This repository previously had a real, serious defect**: the auth middleware exempted every
`GET`/`HEAD`/`OPTIONS` request from authentication regardless of path, leaving the entire CRM
read surface -- contacts, companies, deals, activity, notes, tags, lead-scoring rules, every
analytics endpoint, and the bulk contacts export -- publicly readable with no credentials. This
was fixed by replacing the method-based exemption with an explicit path allowlist; see
`tests/auth.test.mjs` for the regression tests and CHANGELOG.md for details.

## Supported version

Security fixes target the current `main` branch and the currently deployed Worker release.
Historical commits are retained for evidence and are not patched in place.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report to
`security@echo-op.com` with:

- affected endpoint and exact revision;
- reproduction steps and expected impact;
- whether the authentication boundary, the `PUBLIC_PATHS` allowlist, or customer/deal data
  exposure may be involved;
- safe contact details for follow-up.

Never include a live `ECHO_API_KEY`, `STRIPE_SECRET_KEY`, or real customer/contact data in a
report.
