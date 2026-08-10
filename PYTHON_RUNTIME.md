# Python runtime

This repository is the authoritative source for the Echo CRM Python runtime. Production
changes originate here, pass review and tests here, and only then synchronize to the FORGE
deployment at `/home/forge/echo-crm`.

## Local verification

~~~powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest tests/ test_security.py test_observability.py -q
~~~

Requires a reachable Postgres instance (schema `echo_crm`) -- these are real integration tests,
not mocked. Set `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE` if not using the local
defaults (`127.0.0.1` / `5432` / `echo` / `echo` / `echo`).

## Required configuration

Credential-bearing variables have no built-in production values. Missing or blank required
values fail closed.

- `PGPASSWORD`
- `ECHO_CRM_API_KEY` (also accepted as `ECHO_API_KEY`)
- `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` (optional -- MinIO usage is best-effort)
- `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` (optional -- required only for Stripe plans/webhooks)

Never place values in source, examples, service files, or command history. Inject them through
the approved runtime secret mechanism.

## Deployment gate

The FORGE unit is `echo-crm.service` (port 8142). Deploy an exact reviewed commit to an isolated
staging port, exercise `/health`, unauthenticated and invalid-auth rejection, and authenticated
access, then promote. If any check fails, leave the current unit untouched or restore its
pre-deploy backup.
