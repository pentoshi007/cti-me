## Cyber Threat Intelligence (CTI) Dashboard — Minimal SRS

### 1. Purpose and Scope
- **Purpose**: Provide a simple, fast dashboard to aggregate threat feeds, display threat levels and trends, allow IOC lookups (IP, domain, URL, hash) against VirusTotal and AbuseIPDB, support basic tagging, and export filtered results to CSV.
- **Scope (keep minimal)**:
  - One open feed (URLHaus) + on-demand enrichment via VirusTotal and AbuseIPDB.
  - REST API only (no WebSockets). Frontend polls on intervals where needed.
  - Glassmorphic UI with responsive layout and accessible contrast.
  - Basic RBAC (Admin, Analyst, Viewer) and JWT auth.

### 2. Technology Stack
- **Backend**: Flask 3.0.3, Flask-RESTX 1.3.0, Flask-JWT-Extended 4.6.0, APScheduler 3.10.4 (periodic jobs), httpx 0.27.2 (HTTP calls), Flask-Limiter 3.8.0 (per-user/IP rate limiting), PyMongo 4.8.0 (MongoDB driver).
- **Database**: MongoDB Atlas Free (M0 shared cluster) via `mongodb+srv` SRV URI. Use TTL indexes for ephemeral data (lookups/exports).
- **Frontend**: React 18.3.1 + TypeScript 5.6.3 + Vite 5.4.10, Tailwind CSS 3.4.14, Headless UI 2.1.10, TanStack React Query 5.59.0, Axios 1.7.7, Recharts 2.12.7.
- **Integrations**: VirusTotal (free tier), AbuseIPDB (free tier), URLHaus feed.
- **Deployment (optional)**: Docker Compose for `api` and `frontend` (Atlas used as managed DB).

### 2a. MongoDB Atlas (Free Tier) Setup
- Create a MongoDB Atlas project and a Free (M0) shared cluster.
- Create a database user with least-privilege (role: `readWrite` on your app database, e.g., `cti`).
- Network access: add your development IP (or temporarily `0.0.0.0/0` for testing; remove it later).
- Get the SRV connection string and set env vars:

```
MONGO_URI="mongodb+srv://<username>:<password>@<cluster-name>.mongodb.net/cti?retryWrites=true&w=majority&appName=<appName>"
MONGO_DB=cti
```

- Driver recommendations: enable TLS (default with SRV), set a reasonable pool size (e.g., `maxPoolSize=50`), and timeouts (`socketTimeoutMS`/`connectTimeoutMS` ~ 20s).
- Do not commit credentials. Use `.env` locally and secret manager in production.

### 3. Functional Requirements
- **FR-1 Ingestion**
  - Fetch URLHaus feed on schedule (default: every 30 minutes).
  - Normalize into unified IOC schema; upsert by `(type, value)`; record `first_seen`/`last_seen` per source.
- **FR-2 Lookup**
  - Allow user to submit IP/domain/URL/hash.
  - Validate input; query internal DB; enrich with VirusTotal and AbuseIPDB (respect rate limits) and cache results.
  - Store a `lookup` record with status and reference to resulting IOC document.
- **FR-3 Threat level**
  - Compute a simple score [0–100] using: source count, recency, VT positives ratio (if available), AbuseIPDB score (if IP).
  - Map to severity: info (0–24), low (25–49), medium (50–69), high (70–84), critical (85–100).
- **FR-4 Dashboard**
  - KPIs: total IOCs, by severity, last 24h ingested.
  - Charts: severity distribution (donut) and simple 7/30-day IOC count time series.
  - Recent IOCs table with basic filters (type, severity, date range, tags) and server-side pagination.
- **FR-5 IOC detail**
  - Unified view: value, type, sources, timestamps, score/severity, VT summary, AbuseIPDB summary, tags.
- **FR-6 Tagging**
  - Admin/Analyst can create tags; apply/remove tags to an IOC (single or multi-select from table).
- **FR-7 Export**
  - CSV export of current table query; if large (e.g., >10k rows), run as background job and provide a download link.
- **FR-8 Auth/RBAC**
  - **Public Access**: Dashboard, IOC browsing, IOC details, and lookups available without authentication.
  - **JWT-based auth for protected features**: roles: Admin (full access), Analyst (tag + export + admin), Viewer (limited admin).
  - **Authentication required for**: Tag management, CSV exports, manual IOC creation, bulk operations, admin functions.

### 4. Non-Functional Requirements
- **Performance**: p95 API under 800ms for cached reads; lookups with enrichment complete ≤ 4s p95.
- **Simplicity**: Minimal dependencies; no WebSockets; one open feed.
- **Security**: Validate inputs; sanitize logs; HTTPS in production; secrets from env; per-user rate limits (e.g., 60/min) on lookup and export.
- **Usability & A11y**: Keyboard access, focus states, aria labels; maintain ≥ 4.5:1 contrast.
- **Reliability**: Idempotent upserts; 3 retries with backoff for feed and enrichment calls.

### 5. Data Model (MongoDB)
- **Collection `indicators`** (unique index `{ type: 1, value: 1 }`)
  - `_id`, `type` ("ip"|"domain"|"url"|"sha256"|"md5"), `value`
  - `first_seen`, `last_seen`
  - `sources`: [{ `name`, `first_seen`, `last_seen`, `ref`? }]
  - `score` (0–100), `severity` ("info"|"low"|"medium"|"high"|"critical")
  - `vt` { `last_fetched_at`, `positives`, `total`, `categories`?, `permalink`? }
  - `abuseipdb` { `last_fetched_at`, `abuseConfidenceScore`?, `reports`? }
  - `tags`: [string]
  - `created_at`, `updated_at`
  - Indexes: `{ last_seen: -1 }`, `{ severity: 1, last_seen: -1 }`, `{ tags: 1, last_seen: -1 }`
- **Collection `lookups`** (TTL index e.g., 30 days)
  - `_id`, `indicator` { `type`, `value` }, `user_id`, `status` ("pending"|"done"|"error"), `started_at`, `finished_at`, `result_indicator_id`?, `error`?
- **Collection `tags`**
  - `_id`, `name` (unique), `color`?, `description`?, `created_by`, `created_at`
- **Collection `exports`** (TTL index e.g., 7–30 days)
  - `_id`, `format` ("csv"), `query` (serialized), `status`, `file_url`?, `row_count`?, `created_by`, `created_at`, `finished_at`?
- **Collection `ingest_runs`** (optional)
  - `_id`, `source`, `status`, `started_at`, `finished_at`, `fetched_count`, `new_count`, `updated_count`, `error`?

- Atlas notes: TTL indexes are supported on Atlas Free; expired documents will be purged automatically by the TTL monitor.

### 6. API Contract (REST, JSON)
- **Public Endpoints (No Auth Required)**
  - GET `/api/health` → { status }
  - GET `/api/iocs` query: `q`, `type`, `severity`, `tags`, `from`, `to`, `sort`, `page`, `pageSize`
  - GET `/api/iocs/{id}`
  - POST `/api/lookup` { `indicator`: string } → immediate merged data or `{ lookup_id }` for async
  - GET `/api/lookup/{id}` → status/result
  - GET `/api/metrics/overview` → KPIs
  - GET `/api/metrics/timeseries` params: `interval` (day/week), `from`, `to`
- **Authentication Required**
  - POST `/api/auth/login` → { access, refresh }
  - POST `/api/auth/refresh` → { access }
  - GET `/api/auth/me` → profile, roles
  - PATCH `/api/iocs/{id}` (apply/remove tags) - **Analyst+**
  - POST `/api/iocs` (manual add) - **Analyst+**
  - GET `/api/tags` - **Public**
  - POST `/api/tags` - **Analyst+**
  - DELETE `/api/tags/{id}` - **Admin**
  - POST `/api/exports` { `format`: "csv", `query` } → `{ export_id }` - **Analyst+**
  - GET `/api/exports/{id}` → status + `file_url` if ready - **Analyst+**
  - POST `/api/ingest/run` { `source`? } → trigger now - **Admin**
  - GET `/api/ingest/runs` - **Admin**

Errors: JSON `{ error_code, message, details? }`; use accurate HTTP status codes.

### 7. Scheduling & Rate Limits
- **Scheduler**: APScheduler in the API process or a lightweight separate worker.
  - URLHaus fetch: every 30 minutes.
  - Enrichment backfill: hourly for the most recent 500 IOCs updated in last 24h.
- **Rate limits** (via Flask-Limiter):
  - Lookup: 60/min per user, 120/min per IP (configurable).
  - External APIs: internal buckets honoring free-tier quotas (queue + backoff).

### 8. Frontend UX (Glassmorphism, minimal)
- **Pages**: Dashboard, IOCs (table), Lookup, IOC Detail, Tags (admin), Settings (API keys).
- **Style tokens**:
  - Background: subtle gradient; panels use `backdrop-filter: blur(24px)` with translucent surfaces (`rgba(255,255,255,0.10)` in dark, `rgba(0,0,0,0.08)` in light).
  - Borders: 1px hairline `rgba(255,255,255,0.18)` and soft shadow.
  - Radius: 16px panels; 10px buttons/chips.
  - Contrast: ensure text ≥ 4.5:1; large text ≥ 3:1.
- **Components**: KPI cards, donut chart (severity), line chart (7/30-day counts), server-driven table with filters and row selection, lookup input with result panel, tag chips and picker.

### 9. Configuration & Secrets
- **Env vars** (examples):
  - `FLASK_ENV`, `FLASK_SECRET_KEY`
  - `MONGO_URI`, `MONGO_DB`
  - `VT_API_KEY`, `ABUSEIPDB_API_KEY`
  - `JWT_ACCESS_TTL`, `JWT_REFRESH_TTL`
  - `SCHEDULER_TIMEZONE`, `EXPORT_DIR`
  - `RATE_LIMIT_LOOKUP_PER_MIN`
- Provide `.env.example` (no secrets) and simple setup instructions.

Example `.env` snippet for Atlas:

```
FLASK_ENV=development
FLASK_SECRET_KEY=change_me
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/cti?retryWrites=true&w=majority&appName=cti
MONGO_DB=cti
VT_API_KEY=
ABUSEIPDB_API_KEY=
JWT_ACCESS_TTL=900
JWT_REFRESH_TTL=2592000
SCHEDULER_TIMEZONE=UTC
EXPORT_DIR=./exports
RATE_LIMIT_LOOKUP_PER_MIN=60
```

### 10. Acceptance Criteria (MVP)
- URLHaus ingestion runs every 30 minutes and new IOCs appear in the dashboard within 1 minute of ingest completion.
- Lookup for an IP/domain returns merged internal + VT/AbuseIPDB data within 4 seconds p95; errors are user-friendly.
- Table filters (type, severity, date, tags) update results in ≤ 1.5 seconds p95.
- CSV export of ≤ 10k rows downloads immediately; larger exports are queued and retrievable within 2 minutes.
- Tag create/apply/remove works and persists; Viewer cannot create or delete tags.
- Application connects to MongoDB Atlas via SRV URI with TLS; required indexes and TTLs are created successfully on first run.

### 11. Bill of Materials (Updated)
- **Backend**: flask==3.0.3, flask-restx==1.3.0, flask-jwt-extended==4.6.0, apscheduler==3.10.4, httpx==0.27.2, flask-limiter==3.8.0, pymongo==4.8.0, python-dotenv==1.0.1, tenacity==9.0.0, pydantic==2.9.2
- **Frontend**: react==18.3.1, react-dom==18.3.1, typescript==5.6.3, vite==5.4.10, tailwindcss==3.4.14, @headlessui/react==2.1.10, @tanstack/react-query==5.59.0, axios==1.7.7, recharts==2.12.7, zustand==5.0.1
- **Testing**: pytest, requests-mock; vitest or jest + testing-library/react

### 12. Initial Implementation Tasks (MVP)
- Backend
  - Scaffold Flask API; auth (JWT); `/health` endpoint.
  - Mongo repositories and indexes; `indicators`, `tags`, `lookups`, `exports`.
  - URLHaus fetcher + normalizer + upsert pipeline; APScheduler wiring.
  - VT and AbuseIPDB clients with backoff and simple caching; lookup endpoint.
  - Threat scoring function; metrics endpoints (overview, timeseries).
  - Table list endpoint with pagination and filters; tag endpoints; CSV export.
- Frontend
  - App shell with glassmorphic panels; dark/light.
  - Login flow; route guards.
  - Dashboard KPIs + charts.
  - IOCs table with filters and pagination; row selection; tag actions.
  - Lookup page and IOC detail view.
  - Tag manager page.

---
This SRS intentionally limits scope to essential features plus a small set of extras (tags and CSV export) to keep the product simple, focused, and fast to deliver.



api:
virustotal=a6fe6ff191183ed733f251326a6d015722737640121f03734fce3265609f9573;
mongodb atlas connection string: mongodb+srv://aniket00736:ak802135@cluster0.h8lwxvz.mongodb.net/opencti?retryWrites=true&w=majority&appName=Cluster0;
abuseipdb api:26868134edb1a27b3fd8315c9de81ab80228a43fffd5f2e5011333437d21c18ea3e238e57332bbc1;
