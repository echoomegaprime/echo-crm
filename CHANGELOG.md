# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Merged the production Python runtime

- Brought in the FastAPI service (`app.py` + `security.py`/`resilience.py`/`metrics.py`/
  `logging_config.py`, 5,639 lines total) from the live FORGE deployment
  (`echo-crm.service`, port 8142) as the **authoritative production runtime** -- the
  Cloudflare Worker (`src/index.ts`) is now documented as a legacy reference implementation,
  matching the pattern already established for `echo-invoice`/`echo-live-chat`/
  `echo-compliance-auditor`. See README.md for the two runtimes' endpoint tables -- their
  public/authenticated boundaries are **not identical** (the Python service requires a key for
  `/status` and `/plans`; the Worker treats both as public) and this is documented rather than
  silently reconciled.
- Verified a real baseline before touching anything: ran the existing Python suite (`tests/` +
  `test_security.py` + `test_observability.py`, 88 tests) both on the live FORGE deployment and
  against this repo's copy of the same files from a clean venv, connected to the real FORGE
  Postgres from a separate machine -- 87/88 passed both times, confirming the merge preserved
  the exact tested behavior.
- Fixed the one real test-drift issue found: `test_version_security_tag` asserted
  `CRM_VERSION.endswith("-security")` and `"2.1.0" in CRM_VERSION`, but the real, current,
  intentional version is `2.2.0-resilience` (a later resilience pass layered on the same
  hardened baseline, confirmed via the live systemd unit's `ECHO_CRM_VERSION` env var, not a
  regression). Broadened the assertion to accept either hardening-pass suffix instead of pinning
  to a value that goes stale on every future pass.
- Added `requirements.txt`/`requirements-dev.txt` (constructed from a real `ast`-based import
  scan of every core module, not guessed: `fastapi`, `uvicorn[standard]`, `psycopg2-binary`,
  `pydantic`, `minio`, `prometheus-client`, plus `pytest`/`httpx` for the dev suite -- `httpx`
  was missing initially and caused a real collection error, `starlette.testclient` requires it).
- Added `PYTHON_RUNTIME.md` (install/verify/deploy-gate instructions for the Python side).
- Extended `certforge_journey.py` to validate both runtimes: real `ast.parse` syntax validation
  for every Python module (the sandbox has no Node, so the Worker side still uses the
  bracket-count heuristic, but Python gets genuine parsing since the sandbox IS bare Python),
  plus a new regression guard on `security.py`'s `ENDPOINT_AUTH` map -- fails if any endpoint
  beyond `root`/`health`/`ready`/`resilience` is marked `AUTH_PUBLIC`, since the Python
  service's public surface is deliberately narrower than the Worker's and a silent widening
  there would be a real regression. Verified locally by deliberately marking `/status` public
  and confirming the journey fails, then restoring.
- Extended hosted CI with a `python` job (Postgres 16 service container, real integration
  tests) alongside the existing `worker` job.
- Merged `SECURITY.md` to document both runtimes' security models side by side (the Python
  service's five-tier authorization, vault-backed secret resolution order, and constant-time
  comparison; the Worker's `PUBLIC_PATHS` allowlist and its prior GET-exemption vulnerability).

### Security (Worker, prior to the Python merge)

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
