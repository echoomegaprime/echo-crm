# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- **Fixed a serious data-exposure defect**: the auth middleware exempted every
  `GET`/`HEAD`/`OPTIONS` request from authentication regardless of path. This left the entire
  CRM read surface -- `/contacts`, `/contacts/:id`, `/companies`, `/deals`, `/deals/board`,
  `/activities`, `/notes`, `/tags`, `/email-events`, `/lead-scoring/rules`, every `/analytics/*`
  endpoint, `/activity-log`, and a bulk `/export/contacts` CSV-style dump -- publicly readable
  with zero credentials, on the public internet. This is real customer PII (contacts, companies)
  and financial data (deals, revenue analytics), not the kind of thing that should ever be
  publicly readable. Fixed by replacing the method-based exemption with an explicit
  `PUBLIC_PATHS` allowlist (`/`, `/health`, `/status`, `/plans`, `/webhooks/stripe` only).
- Replaced the (now-guarded) `!==` credential comparisons with a constant-time
  `timingSafeEqual`, closing a timing side-channel on top of the exposure fix.
- Bumped `hono` `^4.12.9` -> `^4.13.1` (same known-vuln class found in prior repos this
  campaign); `npm audit` reports 0 vulnerabilities.
- Corrected `package.json`'s stale `"license": "ISC"` to point at the real `LICENSE` file, and
  its placeholder `"test": "echo ... && exit 1"` script (there was no test infrastructure at
  all before this) to the real `tsc --noEmit && node --test` pipeline.

### Added

- `package.json` `devDependencies`/`tsconfig.json` (neither existed).
- `tests/auth.test.mjs`: 13 real tests, including 6 end-to-end middleware tests that call the
  actual exported Hono `app` via `app.request()` against real routes (`/contacts`, `/companies`,
  `/deals`, `/export/contacts`, `/analytics/revenue`) -- these exercise the real routing and
  middleware, not a reimplementation of it. Verified locally to actually fail when the original
  GET-exemption bug is reintroduced, then restored.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- Hosted CI (`.github/workflows/ci.yml`): runs `npm test` on every push and pull request.
- Issue templates (bug report, feature request) and a pull-request template.
- `.echo/{apps.json,certification.json,sdk.json}` for ECHO Certification Forge and GitHub App
  Suite enrollment; `sdk.json` declares the 33 real `echo.crm.*` capabilities matching this
  repo's actual routes (explicitly excludes 7 registered under the same prefix --
  `sync.*`, `leads.triage`, `internal.weekly_digest` -- with no matching route here).
  `scripts/certforge_journey.py` critical journey verified locally to fail if the GET-exemption
  regresses, then restored.
- This CHANGELOG and a README (the repository previously had no README at all).

## [Prior history]

- Add Stripe payment integration v2.0.0.
- Auth hardening + service binding updates.
- Fix CORS headers to ok()/fail() helpers bypassing Hono middleware.
- Harden D1 queries with try-catch error handling.
- Fix: structured logging in error handler + empty catch block.
- Add security headers middleware (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
  Referrer-Policy, Permissions-Policy).
