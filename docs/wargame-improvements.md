# Wargame verification improvements

> Status: Current implementation reference · Updated: 2026-11-09 · Scope: Local mock benchmarks
>
> [Documentation index](README.md) · [PostgreSQL source](postgresql.md)

Scope: local mock targets and synthetic fixtures only. No external-target execution.

## Execution and evidence

- Training persists RUNNING progress, COMPLETED results, FAILED errors and CANCELLED task outcomes.
- Completed training manifests use simulation version 3 and SHA-256 workload identities. Baseline and retest share saved workloads. Replay validates source compatibility and manifest integrity without regenerating from seed. Wall-clock timing may differ.
- Each scenario has legitimate regression coverage: voucher claims, account ownership, valid checkout and ordered state transitions.
- Business regression and latency SLA are separate measurements. A business pass is not a latency guarantee.
- Red/Blue Elo fields have been removed; demo heuristic scores remain explicitly labeled.
- Browser tabs use independent in-memory step-session IDs. Sessions expire after one hour and are limited to 100. Legacy callers without the header retain serialized shared-state behavior.

## API and UI

- `GET /api/v1/wargame/runs`: bounded recent history.
- `GET /api/v1/wargame/runs/{run_id}`: saved status, configuration and evidence.
- `POST /api/v1/wargame/runs/{run_id}/replay`: completed runs only; incompatible training versions return 409. Existing version-2 history remains readable but cannot be replayed with version-3 code.
- `POST /api/v1/wargame/controls/evaluate`: local-only ablation matrix with absent, relevant, all, broken/no-op and reject-all controls.
- `GET /api/v1/wargame/classifier/evaluation`: per-row stress fixtures and separate temporal sequence fixtures.
- Training/full/recheck/control inputs reject invalid types, ranges, unknown fields and malformed JSON with 422.
- Wargame UI supports history, two-run inspection, replay and control matrix inspection. Cross-run inspection is not a matched verification.

## Classifier limitations

Temporal detection is an additive, separately evaluated prototype, not a silent replacement for the existing row classifier. It groups observable user/endpoint timestamps. Legitimate retry bursts can be false positives; low-rate or distributed abuse can remain invisible. Holdout fixtures report these failures explicitly and are not real-world validation.

## Validation

```sh
python -m unittest discover -s tests -v
python -m scratch.check_browser --wargame-only
```

The browser check uses installed Edge and DevTools, not Playwright. SQLite integration fixtures exercise independent connections, a unique claim constraint, transaction serialization and rollback. They do not certify generated patch templates, production databases or distributed deployments.

## Durable execution and replay

- `POST /api/v1/wargame/jobs` submits a local mock benchmark (202); `GET /api/v1/wargame/jobs/{id}` polls status; `POST /api/v1/wargame/jobs/{id}/cancel` requests cancellation.
- SQLite admission is bounded to 20 queued/running jobs; atomic claims allow one active durable job across workers sharing the file. Legacy synchronous routes remain available and are not governed by that queue.
- The application lifespan runs the worker. It polls every 250ms, acknowledges cancellation during execution, updates heartbeat every approximately 200ms, and imposes a 120-second deadline. A lease older than 10 seconds becomes INTERRUPTED, or TIMED_OUT after its deadline. Recovery occurs on the next claim, including after restart, without automatic replay.
- UI supports queue/progress/cancel and restores polling from sessionStorage after reload. A network error does not cancel a durable job.
- Training replay validates saved manifests and executes them directly, without calling the generator. Schema/scenario/control versions and a normalized source hash gate compatibility; old manifests lacking version metadata return 409.
- Version-3 manifests vary voucher per-request schedules, BOLA/tamper fixture ordering, and synthetic order IDs; serial fixtures also consume an aggregate pre-execution delay. Monetary boundary fixtures and state transitions remain canonical; this does **not** claim exhaustive business-parameter coverage.
- `GET /api/v1/wargame/classifier/shadow` reads at most 2000 events from the selected dataset and reports timing signals, with no enforcement or raw identities returned. This is on-demand sampled shadow analysis, not a continuous production stream.

API key revocation must be performed by the account owner at the provider. No credentials are included in this document.

## Optional PostgreSQL fixture

This fixture verifies a dedicated transactional implementation, not generated templates or a production service. It creates and removes only a uniquely named test schema. Use a disposable database and a restricted test role.

```powershell
docker compose -f compose.integration.yml up -d --wait
python -m pip install "psycopg[binary]==3.2.10"
$env:AIGIS_TEST_POSTGRES_DSN = 'postgresql://aigis_test:local_test_only@127.0.0.1:55432/aigis_test'
python -m unittest tests.test_postgres_integration -v
docker compose -f compose.integration.yml down
```

Without the DSN, PostgreSQL tests are explicitly skipped, not passed. The container uses a loopback-only port, test-only credentials and ephemeral storage. Tests cover cross-connection uniqueness, budget mutation, legitimate inserts and rollback.

The optional integration suite also exercises application PostgreSQL discovery,
bounded snapshot import and read-only transaction configuration. This remains
separate from mock wargame evidence; neither suite certifies generated templates.
Latest recorded full local regression before this documentation-only update:
85 tests discovered, 83 passed and 2 PostgreSQL tests skipped; full Edge browser
suite passed, including Model responsive checks and queued benchmark polling.
