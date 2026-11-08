# Backend reliability improvements
> Status: Current implementation reference · Updated: 2026-11-08 · Scope: Local/offline checks
>
> [Documentation index](README.md) · [Architecture](architecture.md) · [Review history](reports/README.md)

## Implemented scope

The backend implements evidence provenance, simulation isolation, run persistence,
canonical reference patches, telemetry query improvements, stress evaluation,
structured events, and repeatable operational checks.

### Evidence and assessment

- `backend/evidence.py`: typed immutable dataset, analysis, and simulation
  provenance plus validated scenario measurements.
- Dataset identity includes canonical path and a conservative file/WAL revision.
  Same-path replacement or writes invalidate current cached diagnoses. This is a
  cache fingerprint, not a cryptographic dataset-content hash.
- Analysis records the exact endpoint, time bounds, event count, source, and
  coverage. SQLite analysis holds a read transaction; concurrent writes do not
  mix counts and detail rows. A changed revision is explicitly marked stale.
- Telemetry signals are `SIGNAL_DETECTED`, not proof of an isolation failure.
  Empty/unsupported windows are `INSUFFICIENT_DATA`. Only matched mock workloads
  can produce `MITIGATION_VERIFIED_IN_MOCK`.
- Incident signals are recorded as unresolved signals, not automatically resolved
  production exploits. Failed incident persistence is disclosed.

### Four follow-up findings

- Default Sentinel follows the selected database. Explicitly constructed
  Sentinel instances can monitor a fixed path and identify it in their reports.
  Policy/incident reads use the same snapshot as telemetry.
- Copilot returns unavailable measurements for unsupported/empty datasets rather
  than substituting fabricated metrics. Work-order IDs come from real drafts.
- Training stores each matched attack/retest pair and dossier. The compatibility
  `dossier` field refers to the final matched round; `training_summary` holds
  all-round aggregates. Voucher losses exclude the legitimate first claim.
- All Python patch handoffs use one authenticated-state/owner-token template.
  Arbitrary client fingerprint headers are no longer used in the composite guard.

### Simulation isolation and replay

- Full workflows/training use task-local mock stores. Parallel runs do not reset
  the shared target or each other's stores. Scope exit restores state after
  errors/cancellation.
- Legacy step-by-step target mutations remain a serialized single shared session.
  Use full runs for independent concurrent experiments. The API should be run in
  one worker while using the legacy shared session.
- Completed training and HTTP recheck results/configurations are saved to
  `backend/datasets/aigis_runs.db` (override with `AIGIS_RUN_DB`).
- POST `/api/v1/wargame/run_full` or `/api/v1/wargame/train` accepts `seed`.
- GET `/api/v1/wargame/runs/{run_id}` retrieves evidence and configuration.
- POST `/api/v1/wargame/runs/{run_id}/replay` replays stored workload/control
  settings with the same seed and produces a new manifest.
- Replay reproduces scenario configuration and functional outcomes, not exact
  wall-clock latency or generated IDs. Failed operations emit structured events.
- Dataset generation uses a local seeded RNG, records its effective seed and
  generator version, and uses a UTC baseline for cross-timezone reproducibility.

### Canonical reference patches

`backend/patch_registry.py` owns the Python guard and its diff. Blue Team, Arbiter,
multi-round training, and the multi-language exporter all reuse it. Metadata
records dependencies, assumptions, applicability, and limitations. It is a
concurrency mitigation, not a durable idempotency implementation; DB constraints
remain necessary. Redis acquisition failure returns 503. Release uses owner-token
comparison; protocol-double tests check spoofed headers, missing identity,
concurrent claims, and unavailable Redis. Java/Go/edge outputs remain reference
templates and are not compiler/runtime-validated here.

### Telemetry performance

- Investigator streams chronologically ordered rows and retains per-user/burst
  state, not all event records. Memory scales with distinct grouping keys.
- Sentinel uses SQL counts, sums, distinct identities, and window functions.
- Added `(api_endpoint, epoch_ms)` indexing at initialization/import.
- Investigator and deep classification work execute outside the async event loop.
- Classification responses disclose non-representative prefix sampling and
  incomplete coverage instead of implying a full-dataset assessment.

Local disposable **1,000,000-row** benchmark on 2026-11-08:

| Measurement | Result |
|---|---:|
| Investigator | 6.36 s |
| Sentinel | 1.32 s |
| Peak Python allocations | 4.22 MB |

The query plan used `idx_endpoint_epoch`. Python allocation measurement excludes
SQLite native buffers; these are local measurements, not throughput guarantees.

**Reproduction context:** run `python -m scratch.benchmark_telemetry --rows 1000000`
from the repository root. The disposable fixture uses 10,000 repeating user IDs,
one voucher endpoint, $10 events, and one-millisecond event spacing. It uses no
random generator seed; the timestamp baseline is the current time. The timer covers
the analysis functions, not dataset creation or HTTP/UI overhead. The original
record did not capture CPU, RAM, exact Python/SQLite versions, or system load, so
the historical timings cannot be treated as machine-normalized results. Record
those details alongside output when comparing a new run.

### Evaluation and operational checks

- Independent hand-authored classifier stress fixtures cover legitimate automated
  clients/cloud users, browser-like attacks, low-and-slow abuse, unmarked bursts,
  and observable automated abuse. Ground-truth labels are never classifier inputs.
- Current stress fixture result: 100 TP, 0 FP, 200 TN, 300 FN; recall **25%**, F1
  **40%**. This intentionally exposes the limits of per-row observable features.
  It is not a real-world or held-out benchmark; improving these features is a
  separate detector-design task, not a reason to tune to these fixtures.
- Structured request/run events include request/run IDs, status, timing, and seed;
  request bodies, API tokens, and LLM keys are not logged by these events.
- Direct runtime dependencies are pinned to locally tested versions. Transitive
  dependencies are resolved by pip; this is not a full hash-locked environment.
- GitHub Actions checks Linux/Windows on Python 3.12/3.14, offline regressions,
  integration, dependency consistency, stress evaluation, a 100k-row benchmark,
  and a separate online dependency-advisory job.

## Commands

Verification completed locally: full regression suite **60 tests passed**;
the subsequently added recheck HTTP persistence/replay test also passed in the
targeted API suite (**2 tests passed**). Extended integration reported **zero
failures**. Both original-fix confirmations and follow-up negative-control checks
passed **three consecutive runs**. `pip check` reported no broken requirements.
`git diff --check` reported no whitespace errors.

These are historical implementation-time results, not a fresh verification of
every later documentation or code revision. Run the commands below for the current
checkout; earlier report counts describe earlier snapshots.

```powershell
python -m unittest discover -s tests -v
python -m scratch.check_project
python -m scratch.review_confirmations
python -m scratch.check_additional_findings
python -m backend.classifier_evaluation
python -m scratch.benchmark_telemetry --rows 1000000
python -m pip check
```

GitHub-hosted CI and the network-backed advisory job must run on GitHub to confirm
their results. External LLM/provider behavior and real Redis deployment were not
validated by these offline tests.
