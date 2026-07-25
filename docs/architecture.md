# Spook Shack Technical Architecture

## 1. Objective

Spook Shack is a threat intelligence platform that continuously ingests source material, normalizes it into reusable intelligence objects, correlates objects across sources, and supports both operational triage and strategic reporting.

The system should feel alive: new source data arrives on schedule, correlations improve over time, analyst verdicts refine scoring, and report generation turns accumulated intelligence into weekly, monthly, quarterly, and annual outputs.

## 2. Product boundaries

### In scope
- Public and approved-source ingestion
- Analyst access control
- Source configuration and scheduling
- Raw data retention
- Normalization, enrichment, and correlation
- Notes, verdicts, and case management
- Dashboards per source and a universal intelligence dashboard
- Report generation from curated intelligence
- Future-technology forecasting workflow
- Docker-based deployment

### Out of scope for the first release
- Full-scale web crawling of arbitrary sites without review
- Private-channel scraping or policy-bypassing ingestion
- Fully autonomous attribution claims without analyst review
- One-click public SaaS multi-tenancy

## 3. Recommended implementation stack

### Backend
- **FastAPI** for HTTP API and admin surface
- **SQLAlchemy 2.x** + **Alembic** for persistence and migrations
- **Pydantic** for typed request/response schemas
- **Celery** for background work
- **Celery Beat** for schedules
- **Redis** as broker/cache
- **PostgreSQL** as primary database
- **MinIO** or S3-compatible storage for raw artifacts and generated reports
- **OpenSearch** later, or PostgreSQL full-text search for MVP

### Frontend
- **React + Vite**
- Tailwind or component tokens for the dashboard shell
- Charting for trends and timelines
- A dark, angular, neon-accented UI inspired by Zenless Zone Zero's Spook Shack vibe

### Infrastructure
- Dockerfile for each service or a single multi-stage build
- Docker Compose for local and self-hosted deployment
- Environment-based configuration
- Docker secrets or mounted secrets for master encryption keys
- Optional reverse proxy such as Caddy or Traefik

## 4. High-level service topology

### Core services
1. **web**
   - React dashboard
   - Login, dashboards, search, reports, admin UI

2. **api**
   - Auth, RBAC, source management, queries, annotations, report orchestration

3. **worker**
   - Ingestion jobs, parsers, enrichment, correlation, report rendering

4. **scheduler**
   - Triggers periodic source syncs and report generation

5. **postgres**
   - System of record

6. **redis**
   - Queue, cache, rate-limit counters, job state

7. **object-store**
   - Raw payloads, attachments, generated report artifacts

### Optional later services
- **search**: OpenSearch
- **graph**: graph database if relationships become large enough to justify it
- **proxy**: edge proxy / TLS termination
- **auth**: external SSO provider, if you later want enterprise login

## 5. Core data flow

### Ingestion path
1. A source connector wakes on schedule.
2. The connector checks the source policy and rate-limit budget.
3. It fetches only the next permitted increment.
4. Raw payloads are stored with provenance and retrieval metadata.
5. Parsers normalize the payload into a common intelligence schema.
6. Enrichment jobs resolve entities, extract indicators, and infer tags.
7. Correlation jobs link the item to other observations.
8. The item becomes visible in source dashboards and the universal dashboard.
9. Analysts add notes and verdicts.
10. Verdicts feed scoring and future correlation confidence.

### Reporting path
1. A report job gathers intelligence for the requested time window.
2. It assembles findings, confidence, source provenance, and analyst notes.
3. It renders an artifact using the Zeltser report template structure.
4. The report is stored as an immutable artifact and indexed in the database.

### Future-tech path
1. A Hermes agent generates a structured report about an emerging technology.
2. Spook Shack ingests that report as a first-class intelligence object.
3. The system maps the technology to existing categories and attack surfaces.
4. Analysts review the forecast and refine the confidence score.
5. The dashboard surfaces emerging vectors and adjacent risk clusters.

## 6. Source ingestion model

Each source must have a dedicated connector with the following metadata:
- name
- source type
- allowed access method
- legal / policy notes
- rate limit budget
- auth requirements
- polling schedule
- retry/backoff policy
- parser version
- last successful sync
- last policy review

### Source categories you listed
- ransomware.live
- Telegram leak channels
- Tweet/X feed source
- PhishHunt
- Have I Been Pwned
- RSS feeds
- future public / open-source discovery results

### Policy handling rules
- Use only official APIs, public feeds, or documented access methods.
- Do not scrape private channels, restricted data, or content protected by platform rules.
- Keep source-specific rate limits in metadata and enforce them centrally.
- Use cursor-based incremental sync whenever possible.
- Cache result markers such as timestamps, IDs, and ETags.
- Back off aggressively on 429s or policy warnings.

## 7. Persistence design

### Primary entities
- users
- roles
- permissions
- sessions
- audit_events
- sources
- source_accounts
- source_policies
- sync_runs
- raw_documents
- raw_observations
- indicators
- entities
- relationships
- sightings
- analyst_notes
- verdicts
- cases
- reports
- report_runs
- report_templates
- technology_items
- research_sources
- forecast_assessments

### Storage rules
- Store raw source payloads separately from normalized intelligence.
- Preserve provenance on every derived record.
- Use soft deletion for analyst notes and workflow records where auditability matters.
- Store generated reports as immutable artifacts.
- Store credentials and secret material encrypted at rest.

### Encryption strategy
- Encrypt source credentials using envelope encryption.
- Keep the master key outside the database.
- Use Docker secrets or environment-injected secrets for local/self-hosted deployments.
- Re-encrypt credentials on key rotation.
- Record access to secrets in audit logs.

## 8. RBAC and access control

### Roles
- **Admin**
  - manage users
  - manage roles and permissions
  - add/edit sources
  - approve new connectors
  - configure schedules and secrets
  - view all reports and dashboards

- **Analyst**
  - view permitted sources
  - search and correlate data
  - add notes and verdicts
  - generate reports
  - create cases and track investigations

### Access-control rules
- Source-level permissions should exist even if only admin and analyst are used at first.
- Every privilege-changing action must be audited.
- Report generation should honor the caller's source visibility.
- Analyst notes should be editable only by the author or an admin, with audit history preserved.

## 9. Normalization and correlation

### Normalization goals
Convert all source-specific payloads into reusable objects with common fields:
- type
- value
- timestamp
- confidence
- source provenance
- entity links
- tags
- severity
- verdicts

### Common intelligence objects
- domains
- IPs
- URLs
- hashes
- email addresses
- wallet addresses
- actor aliases
- malware families
- campaigns
- infrastructure clusters
- techniques / TTPs
- technology references

### Correlation methods
- exact matching
- normalized string matching
- shared infrastructure
- shared actor aliases
- shared TTPs
- timeline proximity
- semantic similarity
- rule-based confidence boosting

### Learning loop
Analyst verdicts should influence scoring but not overwrite source truth. Over time, the system can:
- suppress recurrent false positives
- prioritize high-value source combinations
- improve entity matching thresholds
- highlight source overlaps that historically produced true positives

## 10. Dashboards

### Per-source dashboard
Each source dashboard should show:
- health and last sync status
- volume over time
- newest raw items
- normalized item counts
- top entities and trends
- analyst verdict breakdown
- parser errors and lag
- source-policy status

### Universal dashboard
The global dashboard should show:
- all-source search
- correlation graph / relationship view
- cross-source entity timelines
- trending campaigns and actors
- top high-confidence clusters
- analyst workload and verdict patterns
- emerging technology watchlist
- report output summary

### Watchlist views
- ransomware families
- infrastructure reuse
- phishing activity spikes
- leaked credentials / identity exposure
- emerging technology risk clusters

## 11. Reporting

Use the structure of Lenny Zeltser's CTI report template as the reporting baseline:
- executive summary
- actor snapshot
- methodology
- activity overview
- representative techniques
- indicators of compromise
- defensive implications
- attribution analysis
- anticipated activity
- optional strategic analysis
- optional competing hypotheses
- report metadata and follow-up notes

### Report cadence
- weekly
- monthly
- quarterly
- annual

### Report rendering
- Markdown for easy review and versioning
- HTML for the app UI
- PDF for distribution
- optional DOCX later if needed

### Report-quality requirements
- Every claim should retain evidence and provenance.
- Confidence levels should be explicit.
- Forward-looking statements should be phrased as likelihoods, not certainties.

## 12. Future-technology prediction module

This is a separate intelligence lane.

### Inputs
- research papers
- pre-release technology announcements
- standards drafts
- conference talks
- public repos
- patents
- technical blog posts
- structured Hermes-agent reports

### Each forecast item should capture
- technology name
- classification / category
- maturity level
- related existing technology
- linked attack surface
- known attack vectors for the related technology
- likely threat-actor abuse patterns
- possible detections / mitigations
- confidence and evidence score

### Output mode
The dashboard should present these as hypotheses:
- what the technology is
- what it resembles
- where it can be abused
- how it might be used by threat actors
- what defenders should monitor next

## 13. Observability and auditability

### Logs
- auth events
- source sync events
- parser failures
- rate-limit pauses
- report runs
- note edits
- verdict changes
- credential access events

### Metrics
- ingestion latency
- backlog depth
- source health
- correlation throughput
- report generation time
- error rates
- verdict distribution

### Tracing
- ingest request to raw storage
- raw storage to normalized object
- normalized object to dashboard visibility
- report generation provenance

## 14. Docker deployment topology

### Local / self-hosted layout
- `api` container
- `worker` container
- `scheduler` container
- `web` container
- `postgres` container
- `redis` container
- `minio` container
- optional `opensearch` container

### Docker principles
- One service per container.
- Use multi-stage builds for frontend and backend images.
- Keep secrets out of the image.
- Use healthchecks so the stack can be orchestrated cleanly.
- Mount only the persistent data directories that need persistence.
- Keep ingestion and report jobs in separate worker containers.

### GitHub-ready repository layout
```text
spook-shack/
  backend/
  frontend/
  infra/
  docs/
  tests/
  docker-compose.yml
  Dockerfile
  .env.example
  README.md
```

## 15. UI / UX direction

### Visual direction
- Dark, tactile, neon-accented, and high-contrast
- Inspired by the Spook Shack energy from Zenless Zone Zero
- Slightly gritty HUD aesthetics, but still clean enough for analyst work
- Avoid copying exact game art, logos, or proprietary assets

### UI patterns
- left-hand navigation with strong iconography
- card-based source dashboards
- layered panels with sharp edges
- signal-quality badges
- timeline strips and trend bars
- report composer with section cards
- analyst note drawer
- case board / queue view

### Typography
- condensed display font for headings
- highly legible sans-serif for body text
- monospace for hashes, indicators, and raw artifacts

### Motion
- short, confident transitions
- subtle glow / scanline effects
- no excessive animation that interferes with analysis

### Palette suggestion
- base: blackened charcoal / midnight blue
- accents: cyan, violet, acid green, and amber
- warnings: orange and crimson
- data emphasis: pale ivory / warm off-white

## 16. MVP implementation sequence

### Phase 1
- auth
- RBAC
- source registry
- encrypted secrets
- raw ingestion storage
- one connector
- one source dashboard

### Phase 2
- normalization
- indicator/entity extraction
- analyst notes and verdicts
- universal dashboard
- search

### Phase 3
- report generation
- scheduled weekly/monthly output
- export formats

### Phase 4
- RSS discovery
- source approval workflow
- additional connectors

### Phase 5
- future-tech forecasting dashboard
- Hermes-agent report ingestion
- advanced correlation heuristics

## 17. Design constraints to keep it shippable

- Build the first vertical slice end-to-end before broadening source coverage.
- Keep source policy metadata explicit and editable.
- Make provenance visible in the UI.
- Do not let the prediction module become a black box.
- Favor auditable heuristics over hidden scoring whenever possible.

## 18. Suggested first slice

The best first slice is:
1. user login
2. source registry with one connector
3. raw ingestion into PostgreSQL
4. normalization into a shared intelligence table
5. a source dashboard showing the newest ingested items
6. analyst note + verdict capture
7. Docker Compose to run the whole stack locally

That slice proves the architecture while staying small enough to build quickly.
