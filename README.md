# Echo CRM

Contacts, companies, deals, pipelines, lead scoring, and revenue analytics -- a Cloudflare
Worker (Hono + D1 + KV + Stripe) CRM with import/export, activity logging, and Stripe-backed
plan upgrades.

## Endpoints

| Access | Method | Path | Description |
|---|---|---|---|
| Public | GET | `/`, `/health`, `/status` | Service info / health / aggregate counts (no PII) |
| Public | GET | `/plans` | Pricing tiers |
| Public | POST | `/webhooks/stripe` | Stripe webhook (signature-verified, not API-key) |
| Authenticated | ALL | everything else | Contacts, companies, deals, pipelines, activities, notes, tags, lead scoring, analytics, import/export, admin |

## Authentication

Every route requires `X-Echo-API-Key` or an `Authorization: Bearer` token, compared in constant
time, **except** the small explicit `PUBLIC_PATHS` allowlist above. This repository previously
had a real vulnerability where every `GET` request was exempt from auth regardless of path,
exposing the entire customer/deal database publicly; see [SECURITY.md](SECURITY.md) and
`tests/auth.test.mjs`'s end-to-end regression tests.

## Verify

```powershell
npm install
npm test
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability -- never as a public issue. This
service holds customer PII (contacts, companies) and financial data (deals, revenue).

## License

See [LICENSE](LICENSE). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
