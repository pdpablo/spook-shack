# Spook Shack Roadmap

## MVP definition

The MVP should prove the full intelligence loop with one source, one analyst workflow, one dashboard, and one Dockerized deployment path.

### MVP must include
- Authentication and RBAC
- Source registry
- Credential encryption
- Scheduled ingestion from at least one approved source
- Raw payload storage
- Normalization into reusable intelligence objects
- Analyst notes and true-positive / false-positive verdicts
- A source dashboard
- A simple universal dashboard
- Docker Compose deployment

## Delivery phases

### Phase 1 — platform foundation
**Goal:** make the system safe and operable.

Deliverables:
- backend API skeleton
- user login
- admin/analyst roles
- secret encryption helper
- source model and schedule model
- audit log model
- Docker Compose with Postgres, Redis, API, worker, and web

Acceptance:
- users can log in
- admins can configure a source
- secrets are stored encrypted
- the stack boots with one command

### Phase 2 — one-source ingestion slice
**Goal:** prove the collection pipeline end to end.

Deliverables:
- one source connector
- rate-limit guardrails
- raw document persistence
- parser -> normalized object pipeline
- source-specific dashboard
- ingestion health metrics

Acceptance:
- a scheduled job ingests sample data from a real source policy-compliant endpoint
- normalized data is visible in the UI
- ingestion failures are visible and retryable

### Phase 3 — analyst workflow
**Goal:** make the platform useful for triage.

Deliverables:
- notes
- verdicts
- confidence scores
- entity linking
- cross-source search
- basic correlation rules

Acceptance:
- analysts can mark true positive / false positive
- notes persist and appear in the dashboard
- a single item can link to multiple sources

### Phase 4 — reporting
**Goal:** generate CTI reports from the data.

Deliverables:
- report builder
- scheduled weekly/monthly/quarterly/annual jobs
- Zeltser-template-aligned sections
- HTML/Markdown export

Acceptance:
- a report can be generated from stored intelligence
- the report includes evidence, confidence, and defensive implications

### Phase 5 — source expansion and discovery
**Goal:** broaden coverage safely.

Deliverables:
- RSS ingestion
- public-source discovery workflow
- source policy review workflow
- more connectors for approved public feeds

Acceptance:
- new sources can be proposed and reviewed without code changes
- source metadata records access policy and rate limits

### Phase 6 — future technology forecasting
**Goal:** identify emerging attack surfaces early.

Deliverables:
- structured Hermes-agent report ingestion
- technology classification model
- related-technology mapping
- threat-surface hypothesis dashboard

Acceptance:
- a research report can be ingested and transformed into forecastable intelligence
- analysts can review and adjust the confidence on predicted vectors

## Recommended build order

1. database schema and auth
2. source registry and encrypted secrets
3. one connector plus scheduler
4. normalization and correlation primitives
5. source dashboard
6. analyst notes and verdicts
7. universal dashboard
8. report generation
9. source discovery and future-tech module

## Defer until after MVP

- Graph database
- Multi-tenant enterprise SSO
- Mobile apps
- Full public source crawler automation
- Advanced ML ranking models
- Large-scale distributed deployment
