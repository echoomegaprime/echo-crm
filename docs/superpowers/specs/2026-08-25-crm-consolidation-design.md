# Echo CRM Consolidation Design

**Status:** Approved for implementation  
**Canonical repository:** `echoomegaprime/echo-crm`  
**Canonical runtime:** FORGE `echo-crm.service` / FastAPI / PostgreSQL `echo_crm` schema  
**Scope:** P0 consolidation required before Explee hot-lead ingestion.

## Goal

Make `echo-crm` the single canonical CRM domain service, harvest proven CRM logic that currently lives in sibling systems, and provide a stable ingestion contract for Explee hot leads without creating another CRM truth store.

## Non-goals

- Do not merge invoicing, payroll, inventory, purchase orders, or other ERP domains into `echo-crm`.
- Do not replace BillyMC, Zoho, Echo Office, or Business Manager as engagement/business-ops clients; they should integrate with canonical CRM.
- Do not create HubSpot as the primary store.
- Do not hard-code provider credentials or Explee API keys in Git.

## Canonical ownership

`echo-crm` owns:
- contacts
- companies
- deals
- pipelines/stages
- activities/notes
- lead scoring
- lead triage
- external provider identity mappings
- lead assignment/next action
- communication consent/suppression state
- CRM synchronization mappings/history

Sibling systems consume these records through SDK/API contracts.

## P0 requirements

### 1. Repair SDK-to-CRM authentication

Observed state:
- `echo.crm.health` succeeds.
- protected reads such as `echo.crm.status` and `echo.crm.contacts.list` return HTTP 401.

Required behavior:
- SDK-gated calls present a credential accepted by the canonical CRM authentication layer.
- No credential is embedded in source or repository metadata.
- `echo.crm.status` and `echo.crm.contacts.list` pass through the SDK gate.

### 2. Move lead-triage ownership into `echo-crm`

The currently green `echo.crm.leads.triage` capability must be implemented by the canonical CRM service, not by Build Tracker.

Required behavior:
- triage accepts the current request shape used by the SDK/router.
- output contract remains backward compatible.
- Build Tracker may consume the capability but no longer owns CRM triage domain logic.

### 3. External provider identity

Add an idempotent provider mapping layer so external systems do not become identity authorities.

Minimum fields:
- provider (`explee`, `hubspot`, `salesforce`, `zoho`, etc.)
- provider_object_type (`contact`, `company`, `deal`)
- provider_object_id
- local_object_type
- local_object_id
- provider_project_id nullable
- first_seen_at
- last_seen_at
- metadata JSON
- unique constraint on `(provider, provider_object_type, provider_object_id)`

For Explee contacts, email is the preferred deduplication key when present; company domain is the preferred company deduplication key when present.

### 4. Lead ownership and next action

Canonical CRM contacts/deals must support operational follow-through.

Required fields or equivalent normalized records:
- assigned_to
- next_action
- next_action_due_at
- priority
- lead_temperature
- last_contacted_at

These must be queryable without joining an external CRM.

### 5. Communication consent and suppression

Harvest the proven Echo Office pattern into canonical CRM.

Required behavior:
- normalized phone representation
- explicit consent records by channel/purpose
- global suppression records
- STOP-style suppression can block future automated SMS paths
- send-attempt audit log records allowed/blocked decision and reason
- provider ingestion does not imply consent

### 6. Explee-ready ingestion contract

The canonical CRM must be able to accept a hot lead with:
- name
- email
- job_title
- company_name
- company_domain
- linkedin_url
- country
- phone
- why_hot (verbatim)
- became_hot_at
- project_id
- source=`explee`

Required behavior:
1. Upsert company by normalized domain where present.
2. Upsert contact by normalized email where present.
3. Create/update external provider mapping.
4. Preserve `why_hot` verbatim as an activity/note.
5. Create or attach an open deal in the `Explee Hot Leads` pipeline without duplicate creation.
6. Set `lead_temperature=hot`.
7. Set a deterministic next action and due date policy.
8. Preserve `became_hot_at` as source event time.
9. Return canonical local IDs plus whether each object was created or matched.

The poller itself is a follow-on change; this design establishes the CRM-side contract first.

## Data model principles

- Canonical local IDs never depend on provider IDs.
- External IDs live in mapping records, not overloaded contact/company columns.
- Derived metrics such as lifetime value are calculated from canonical won-deal/payment facts where possible.
- Provider payload fragments go into bounded JSON metadata only when not represented by typed fields.
- PII remains protected by existing CRM auth tiers.

## API/SDK shape

Add or normalize capabilities along these lines:

- `echo.crm.leads.triage`
- `echo.crm.providers.upsert`
- `echo.crm.providers.lookup`
- `echo.crm.leads.ingest_hot`
- `echo.crm.communications.consent.record`
- `echo.crm.communications.suppress`
- `echo.crm.communications.status`
- `echo.crm.communications.log`

Exact route names may follow current `echo-crm` conventions, but capability IDs above are the canonical intent.

## Error handling and idempotency

- Every mutating ingestion path accepts an idempotency key.
- Duplicate provider events return the existing canonical object IDs.
- Partial failure must not leave duplicate contacts/deals.
- Database writes for one hot-lead ingestion occur in a transaction where practical.
- External provider outages do not affect CRM reads.
- Missing optional lead fields must not reject an otherwise usable hot lead.
- Invalid email/domain/phone values are stored only when validation policy permits; they must never corrupt dedup keys.

## Tests / acceptance criteria

The consolidation is complete only when all of these pass:

1. `echo.crm.health` returns 200.
2. `echo.crm.status` through SDK returns 200.
3. `echo.crm.contacts.list` through SDK returns 200.
4. Triage implementation is present in `echo-crm`; Build Tracker no longer contains canonical triage logic.
5. External provider mapping unique constraint prevents duplicate mappings.
6. Same Explee contact ingested twice produces one contact.
7. Same Explee company domain ingested twice produces one company.
8. Same Explee hot-lead event ingested twice produces one open deal/activity event according to idempotency policy.
9. `why_hot` is preserved byte-for-byte as user-visible activity text.
10. Provider ingestion does not create SMS consent.
11. Suppressed phone cannot pass automated SMS eligibility.
12. Existing CRM tests remain green.
13. New regression tests cover authentication, provider mapping, hot-lead ingestion, triage, and consent/suppression.
14. Working tree/repository branch is clean after commits.
15. Changes are delivered by an `agent/*` branch and draft PR; no direct default-branch rewrite.

## Follow-on phases

### P1
- behavioral segmentation
- derived lifetime value / recency / frequency
- referrals
- preferred language
- appointment/booking linkage
- appointment reminders
- stale-lead follow-up engine

### P2
- review request/recovery
- NPS
- BillyMC calling/scripts/DNC integration
- Zoho adapter under `echo.crm.sync.*`
- full tenant-isolation expansion where required

## Rollback

All changes land on an isolated `agent/*` branch. Rollback is branch/commit reversion before merge. Database changes must be additive for P0; destructive schema changes are prohibited.
