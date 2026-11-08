# PostgreSQL telemetry source

> Status: Current implementation reference · Updated: 2026-11-09 · Scope: Read-only snapshots, not live remote analysis
>
> [Documentation index](README.md) · [Architecture](architecture.md#7-postgresql-như-nguồn-dữ-liệu-chỉ-đọc)

AIGIS supports a **read-only PostgreSQL source with a bounded local snapshot**.
It does not migrate the application to PostgreSQL or run arbitrary console/agent
SQL on the remote server. Dashboard, classifier, Model and SQL console operate on
the imported SQLite snapshot, with the existing schema compatibility checks.
Run history, job queue, simulator and live demo stream remain local SQLite.

## Setup

1. Install the optional dependency in the Python environment used to run AIGIS:

   ```powershell
   python -m pip install -r requirements-postgres.txt
   ```

2. Configure a dedicated read-only PostgreSQL role. An administrator should grant
   only CONNECT, schema USAGE and SELECT on the intended source tables. Do not use
   an administrator, table-owner or production write account. AIGIS additionally
   opens repeatable-read, read-only transactions with a 5-second connection
   timeout, 10-second statement timeout and 2-second lock timeout.

3. In the server's environment, configure `AIGIS_POSTGRES_MAIN` with a libpq DSN or
   PostgreSQL URI. Use your OS/secret manager; do not paste the real value into
   chat, a tracked file, logs, command history or screenshots. For remote servers,
   use `sslmode=verify-full` and a trusted CA (`sslrootcert`). Local disposable
   test servers may use `sslmode=disable`. TLS configuration is taken from the
   server-side profile, not a browser-provided connection string.

   Example format only, **not a working credential**:

   ```text
   host=db.example.invalid port=5432 dbname=telemetry user=aigis_reader password=<secret> sslmode=verify-full sslrootcert=<ca-file>
   ```

4. Start AIGIS from an environment containing the profile. Open Telemetry Explorer
   → **PostgreSQL source — read-only snapshot**. Enter the profile name, press
   **Test connection / list tables**, select a schema/table, then load a snapshot.

The browser only receives an opaque source ID and table metadata, not credentials.
Only environment names matching `AIGIS_POSTGRES_<NAME>` are accepted. Profile
registrations are process-local and capped at 20; rediscover after server restart.
All source operations require the existing local API token.

## Behavior and limits

- Lists up to 500 non-system base tables; imports one selected table as local
  `telemetry`. Tables without expected telemetry columns remain browsable, but
  some analyses correctly report unsupported schema.
- Reads at most 100,000 rows and 50 MiB of converted field data. An extra row
  determines truncation. No ordering is promised: the sample is **not necessarily
  the newest rows or reproducible across refreshes**.
- Remote rows are streamed in batches inside a repeatable-read snapshot. Loading
  does not lock source rows for update, create remote tables or mutate records.
- The previous dataset remains active on connection/import failure. Successful
  refresh creates a new local snapshot file; it does not overwrite old snapshots.
- Snapshot files contain real data. They persist under `backend/datasets/uploads`:
  apply workspace access controls and delete obsolete snapshots using the
  existing imported-database controls. Consider data minimization before import.
- Source provenance includes capture time, row limit, truncation and a snapshot
  ID. Metadata is held in memory during the server session; the SQLite data file
  remains after restart, but its PostgreSQL provenance is not currently restored.
- Numeric/decimal fields preserve exact values as text; date/time fields use ISO
  text. Analysis requires compatible field names/types, e.g. numeric `epoch_ms` in
  milliseconds. Nested values are JSON text. There is no automatic field mapping.
- The SQL console uses **SQLite syntax against the snapshot**. It is not a remote
  PostgreSQL console. The synthetic stream does not write to PostgreSQL or refresh
  the snapshot. Click Load / refresh explicitly to capture new data.
- Active dataset selection is global for the local application, as with existing
  SQLite uploads; this is not a multi-tenant connection service.

## API

`POST /api/v1/database/postgres/discover`

```json
{"profile": "AIGIS_POSTGRES_MAIN"}
```

`POST /api/v1/database/postgres/snapshot`

```json
{"source_id": "<returned-id>", "schema_name": "public", "table": "telemetry", "row_limit": 10000}
```

Errors are intentionally generic to avoid exposing driver errors/connection
strings. Check driver installation, environment, TLS and read permissions locally.
Restore the bundled dataset through the existing default database action.

## Verification

```powershell
python -m unittest tests.test_postgres_source -v
python -m unittest discover -s tests
python -m scratch.check_browser
```

Unit tests mock the PostgreSQL driver and exercise discovery, strict API input,
redacted errors, read-only/timeouts, snapshot import/truncation and rollback of
failed activation. They do not prove connectivity to a live server. The optional
[PostgreSQL fixture](wargame-improvements.md#optional-postgresql-fixture) requires
an actual disposable PostgreSQL database.

Latest recorded verification before this documentation-only update: 85 tests
discovered, 83 passed and 2 PostgreSQL integration tests skipped; full Edge browser
suite passed. Real driver/server connectivity is **not yet verified** in this
environment. The browser check covers failure of an unconfigured profile, not a
successful remote import. Optional integration coverage now includes the actual
application discovery/snapshot path as well as transaction invariants, but requires
`AIGIS_TEST_POSTGRES_DSN` and the optional driver to execute.
