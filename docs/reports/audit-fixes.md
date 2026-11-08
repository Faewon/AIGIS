# Audit fixes
> Status: Historical implementation record · Indexed: 2026-11-08
>
> [Report index](README.md) · [Current architecture](../architecture.md)

## Dashboard access

Start the app with `python run_server.py`. The dashboard opens without login.
The username/password requirement was removed at the user's request.

The dashboard supplies the API token to browser clients automatically. Responses
are marked `Cache-Control: no-store`. Script execution is restricted by a CSP
response header with `script-src 'self'`. `backend/dashboard.py` extracts the
shipped JavaScript and converts static handlers to event listeners, serving the
result at `/assets/dashboard.js`. The source stays in one dashboard template;
the browser receives HTML without inline executable code. Duplicate control IDs
are made unique, and toolbar-specific lookups are scoped to the active controls.

## Backend changes

- Uploads read bounded chunks, close resources, and remove incomplete files on
  size rejection or exceptions. Existing destination files are not overwritten.
- JSON mutations validate known fields and numeric bounds using Pydantic before
  dispatch, returning 422 for malformed JSON, non-object bodies, and bad values.
  Negative transaction amounts remain accepted for the application's intentional
  mock-target tampering scenarios.
- Concurrency analysis respects the requested time window, separates users and
  burst IDs, excludes the first success of each short burst from duplicate loss,
  and measures TPS across the observed interval. An unresolved, zero-duration
  interval reports zero TPS rather than an invented rate. Duplicate counts remain
  telemetry-based estimates rather than proof of database isolation anomalies.
- Incident IDs use UUIDs; duplicate explicit IDs fail instead of replacing data.
- Investigator checks telemetry schema compatibility before querying, closes
  connections on all paths, and associates cached results with database paths.
- PII detection includes nine-digit CMND alongside twelve-digit CCCD. A numeric
  pattern is a candidate detector, not national-ID authenticity validation.
- Backend entry points use package imports. Run from the project root using
  `python run_server.py` or `python -m uvicorn backend.server:app`.

## Verification

Run `python -m unittest discover -s tests -v`.

Regression coverage includes multipart upload routes, size limits, interrupted
uploads, invalid requests, dashboard access and CSP, duplicate accounting and TPS,
incident uniqueness, CMND masking, and FIFO retention below, at, and above the
limit. FIFO tests lower the configurable limit to exercise the same production
branch without generating a million rows.
