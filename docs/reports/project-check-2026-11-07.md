# Project check report
> Status: Historical snapshot · Original check: 2026-11-07
>
> [Report index](README.md) · [Current backend reference](../backend-reliability.md)

Counts and access/CSP descriptions below refer to different stages of the original
check and fixes, not the current checkout. Dashboard password login was subsequently
removed; see [audit fixes](audit-fixes.md). Later browser checks and backend
benchmarks are indexed separately; original coverage limits remain historical.

Date: 2026-11-07

## Overall result

**Passing after fixes.** The regression suite now has **46 passing tests**, and
`python -m scratch.check_project` completes with **zero failures**. Python syntax
checks cover 31 files. The findings below record the original investigation;
their current resolution is summarized here:

- Custom CSV diagnosis returns `UNSUPPORTED_DATASET`; connections always close.
- Served HTML IDs are unique; repeated toolbar controls use scoped lookups.
- Cached investigator reports are scoped to the active database.
- Dashboard JavaScript is served externally with listeners; CSP is now **270
  bytes** and contains neither inline-script permissions nor handler hashes.
- README and `.env.example` document dashboard login configuration.

## Passed checks

- `python -m unittest discover -s tests -v`: **42 tests passed**.
- `python -m pip check`: no broken installed requirements.
- Python AST syntax validation: **29 files passed** (root, backend, tests, and
  the new check script).
- Node syntax validation: dashboard inline JavaScript and mock checkout bundle
  passed.
- Static dashboard event-handler function references resolved.
- Isolated FastAPI startup created the database; background streaming flushed
  events; shutdown stopped the worker.
- **20 GET routes** and **14 POST routes** returned HTTP 200 against an isolated
  telemetry database, covering configuration, database inspection, SQL,
  classification, scanners, Sentinel, investigator, copilot, risk evaluation,
  work-order preview, patch export, and stream pause/resume.
- Real multipart SQLite activation and CSV import succeeded, without mocking
  the importers.
- Authenticated dashboard rendering succeeded; every complete script block
  matched an authorized CSP hash.
- `git diff --check`: no whitespace errors; Git printed LF/CRLF normalization
  warnings.

## Original findings (resolved)

### 1. Custom CSV breaks investigator diagnosis — High

Locations: `backend/agents/quant_investigator.py`,
`backend/server.py` investigator diagnosis route.

After a successful CSV import with columns `name,value`, diagnosis returns
HTTP 500. The underlying error is:

```text
sqlite3.OperationalError: no such column: event_id
```

The investigator assumes the active database always has the complete telemetry
schema, although the application explicitly accepts arbitrary CSV schemas.
It should validate schema compatibility and return a structured unsupported-data
result instead of an unhandled exception.

The connection is closed only after the successful query path. An exception
leaves it unclosed until garbage collection; the Windows check encountered a
database-file lock during temporary-directory cleanup. Use `try/finally` or
`contextlib.closing` around the connection.

### 2. Duplicate dashboard element IDs — Medium

Locations: `frontend/index.html`, toolbar around lines 1182–1245 and duplicated
controls around lines 2440–2600.

Each of these **13 IDs appears twice**:

```text
btn-ai-classify
btn-deep-dive
btn-pii-scanner
btn-fintech-risk
btn-openapi-ingest
btn-db-dropdown
db-dropdown-menu
dropdown-active-db-name
dropdown-path-input
btn-dropdown-connect
dropdown-csv-input
dropdown-db-input
btn-delete-active-db
```

Associated handlers use `document.getElementById`, which selects the first
matching element. Controls in the second toolbar can therefore target the
first toolbar's input, menu, or button state. Use unique IDs and scoped control
lookup, or consolidate the duplicated controls.

## Additional concerns

- **CSP header size:** 8,548 bytes before other response headers. This exceeds
  common 4 KiB/8 KiB proxy response-header buffer defaults. A proxy failure was
  not reproduced. Extracting scripts and replacing static inline handlers with
  listeners would reduce the header and avoid `'unsafe-hashes'`.
- **Stale investigator result:** immediately after switching to an incompatible
  CSV database, `/api/v1/investigator/latest` still returns the cached report
  generated for the previous active database. Report caching is not associated
  with database identity.
- `.env.example` does not document `AIGIS_DASHBOARD_PASSWORD`; setup documentation
  was split between the root README and the [audit-fixes record](audit-fixes.md).
- Installed Starlette emits a TestClient deprecation warning recommending
  `httpx2`. This does not fail the current tests.

## Repeatable extended check

```powershell
python -m scratch.check_project
```

The script uses an isolated temporary database and offline heuristic gateway.
It now exits successfully, including custom CSV diagnosis, database-aware cache,
served JavaScript syntax, unique IDs, compact CSP, and real multipart uploads.

## Coverage limits

- No browser automation package is installed, so actual browser layout, clicks,
  and CSP enforcement were not exercised.
- External LLM provider connectivity, remote proxy behavior, and a million-row
  load/performance benchmark were not tested.
- Scenario simulation is covered by existing local regression tests; the full
  multi-agent training pipeline was not run as an HTTP end-to-end workflow.
- Dependency consistency was checked, not advisory-database vulnerability status.
- HTTP integration used FastAPI TestClient rather than a listening TCP server.
