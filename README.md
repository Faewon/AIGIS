<div align="center">

# AIGIS: Adversarial Intelligence for Generative Immunity & Security

**Local Multi-Agent Wargaming & Remediation Simulation for FinTech Business Logic**

*Explore telemetry signals, reproduce business-logic flaws on mock targets, and compare baseline vs. patched behavior with saved evidence.*

<br/>

<p align="center">
  <a href="https://github.com/Faewon/AIGIS"><img src="https://img.shields.io/badge/AIGIS-Local%20Proof%20of%20Concept-4f46e5.svg?style=for-the-badge" alt="AIGIS local proof of concept"/></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/Backend-FastAPI%20Async-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Runtime-Python%203.10%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/></a>
  <a href="https://www.sqlite.org/"><img src="https://img.shields.io/badge/Telemetry-1%2C000%2C000%20Events-003B57.svg?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite WAL"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Scope-Simulation%20Demo-6B7280.svg?style=for-the-badge" alt="Simulation Demo"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"/></a>
</p>

</div>

---

> [!IMPORTANT]
> **WHY BUSINESS-LOGIC WARGAMING?**
>
> Financial services, digital wallets, and e-commerce platforms need to preserve business invariants under concurrent requests, retries and invalid state transitions. **Time-of-Check to Time-of-Use (TOCTOU) races**, missing ownership checks and payment-flow bypasses are examples that benefit from explicit scenario testing.
>
> Static application security testing (SAST) and dynamic web vulnerability scanners (DAST) struggle with these temporal, multi-threaded business logic flaws. AIGIS is a **simulation demo**: a multi-agent arena that runs attacks, patches and retests against an **in-process mock target** and synthetic telemetry, to illustrate the workflow.

> [!WARNING]
> **Scope & limitations (read before relying on any number shown in the UI)**
> - All attacks, patches and benchmarks run against `backend/mock_target/store.py`, an in-process Python object. AIGIS cannot be pointed at a real service.
> - "HTTP/2 single-packet bursts" are `asyncio.gather` calls on local coroutines; no HTTP is sent.
> - The "distributed mutex" used in the mock is an in-process dict. Redis is only referenced in the *generated reference templates*, which are never executed.
> - "Applying a patch" flips feature flags on the mock target. Generated code is displayed for review only.
> - Shadow-API discovery is regex-based, not an AST analysis.
> - Scores, mitigation rates and losses are computed from the mock runs and labelled as demo heuristics. Compliance entries are demo mappings, not audit results.
> - The bundled telemetry generator is synthetic. The DB and CSV are not committed (they exceed GitHub limits); generate them from the UI (`/api/v1/dataset/generate`, then `/api/v1/database/sync`). Optional PostgreSQL sources import authorized data into bounded, read-only snapshots; this does not enable attacks or patch deployment against remote services.

---

## Feature Overview (demo scope)

### Dashboard access and checks

Start with `python run_server.py` (or `start.bat` on Windows). The dashboard opens
without username or password. It automatically sends the per-process API token
for API requests. `.env` files are not loaded automatically.

Run regression tests with `python -m unittest discover -s tests -v` and extended
offline integration checks with `python -m scratch.check_project`.

See [Backend reliability](docs/backend-reliability.md) for typed evidence contexts,
isolated seeded simulations, persisted run retrieval/replay, classifier stress
evaluation, and million-row benchmark results. Complete simulations accept an
optional `seed`; saved runs are available at `/api/v1/wargame/runs/{run_id}`.

Custom CSVs remain browsable, but concurrency diagnosis requires telemetry
columns. Incompatible datasets return `UNSUPPORTED_DATASET`; cached diagnoses
are scoped to the active database.

| Capability | What the code actually does |
| :--- | :--- |
| **TOCTOU race detection** | Fires N concurrent coroutines at the mock voucher store and counts duplicate successes. |
| **Concurrency gap measurement** | Computes per-user inter-arrival gaps from telemetry with parameterized, read-only SQL. Reports "no collisions" when none are found. |
| **Root cause analysis** | In-process SQL analysis. The displayed Python script is a read-only audit preview and is not executed. |
| **Patch synthesis** | Emits reference templates (SQL atomic claim, FastAPI, Spring, Gin, Cloudflare, NGINX, AWS WAF). Not executed. |
| **Canary rollout** | Preview only; stages are marked `SIMULATED_PENDING_APPROVAL`. |
| **Contextual stand-down** | Distinct-user ratio + proxy ratio heuristic, gated by the flash-sale policy's `active_from`/`active_to` window. |
| **Incident memory** | SQLite table; new incidents are only recorded when collisions are actually measured. |
| **PostgreSQL source** | Read-only discovery and bounded snapshot import; analysis uses local SQLite, not live remote SQL. |
| **Durable mock benchmarks** | SQLite queue with progress, Cancel, heartbeat/lease and timeout; versioned manifest replay. |
| **Temporal shadow signals** | On-demand timing analysis of up to 2,000 selected-dataset events; no automatic blocking. |

---

## Core Capabilities Grid

| Time-Series Sentinel & Drift | In-Process RCA | Reference Patches | Demo Work Order |
| :--- | :--- | :--- | :--- |
| • Sliding window dTPS/dt<br/>• Linear tail forecast at t+15s, t+30s, t+60s<br/>• Contextual Stand-Down Filter<br/>• Sub-50ms collision clustering | • Parameterized read-only SQL<br/>• Inter-arrival gap calculation<br/>• "Insufficient data" instead of defaults<br/>• No code execution | • DB unique constraint + conditional UPDATE<br/>• Owner-token lock release templates<br/>• Identity from auth context, not headers<br/>• Not executed by AIGIS | • Demo mappings only (not assessed)<br/>• Measured mock-target regression check<br/>• 3-stage canary plan preview<br/>• Simulated PR text |

---

## System Architecture

```mermaid
flowchart TD
    subgraph Data_Layer["TELEMETRY & KNOWLEDGE LAYER"]
        StreamEngine["Continuous Telemetry Stream Engine<br/>(10-100 TPS Ingestion Buffer)"]
        IncidentKB[("Incident Memory & Threat KB<br/>(Historical Vulnerabilities & Patches)")]
        PolicyStore["Contextual Policies & SLAs<br/>(Flash Sale Schedules & Thresholds)"]
    end

    subgraph Agent_Swarm["5-ROLE LOCAL SIMULATION WORKFLOW"]
        Sentinel["Agent 1: FinTech Sentinel<br/>(Time-Series Drift & Velocity Derivative)"]
        Investigator["Agent 2: Deep Quant Investigator<br/>(In-Process Read-Only SQL RCA)"]
        RedTeam["Agent 3: Red Adversary & Exploit Fuzzer<br/>(Regex Shadow API Scan & Coroutine Bursts)"]
        BlueTeam["Agent 4: Auto-Remediator (Blue Aegis)<br/>(Reference Patch Templates)"]
        Arbiter["Agent 5: Compliance Arbiter & Copilot<br/>(Mock Regression Checks & Draft Work Orders)"]
    end

    subgraph Interface_Layer["TECHNICAL OPERATIONS CONSOLE"]
        TelemetryGrid["Browser Telemetry Explorer & Dashboard"]
        CopilotChat["SecOps Copilot Q&A & Handoff"]
        WorkOrderView["Canary Plan Preview (5% -> 25% -> 100%)"]
    end

    StreamEngine --> Sentinel
    PolicyStore --> Sentinel
    Sentinel -- "Critical Drift Detected" --> Investigator
    Sentinel -- "Contextual Stand-Down" --> TelemetryGrid

    RedTeam -- "Discovered Shadow API" --> Investigator
    Investigator <--> IncidentKB
    Investigator -- "Quantitative RCA Dossier" --> BlueTeam
    BlueTeam -- "Reference Patch" --> Arbiter
    Arbiter -- "Mock Evidence & Simulated PR Text" --> WorkOrderView

    CopilotChat -- "Operator Diagnostic Request" --> Investigator
    Investigator -- "Analysis Telemetry" --> CopilotChat
```

---

## The 5-Agent Swarm Deep Dive

### 1. FinTech Sentinel: Time-Series Drift & Signal Tail Forecasting
FinTech Sentinel tracks live operational telemetry streams (10 to 100 TPS) across multiple sliding time windows (5s, 15s, 60s). Unlike basic threshold monitors, it computes the **velocity derivative**:

$$\frac{d\text{TPS}}{dt} = \frac{\text{TPS}_{t} - \text{TPS}_{t-\Delta t}}{\Delta t}$$

- **Signal Tail Forecasting**: Projects traffic volume at $t+15\text{s}$, $t+30\text{s}$, and $t+60\text{s}$ by linear extrapolation of the velocity derivative (TPS + t * dTPS/dt). Time to exhaustion:
  $$T_{\text{exhaust}} = \frac{\text{Remaining Budget}}{\text{Current Drain Velocity}}$$
- **Contextual Stand-Down Filter**: When transactions surge during an active promotion window (`active_from` <= now <= `active_to`), Sentinel computes the **distinct-user ratio** (unique users / events; not Shannon entropy). If it is >= 0.70, the datacenter-proxy ratio is <= 0.25 and no sub-50ms clusters are present, Sentinel triggers a **Stand-Down**.

### 2. Deep Quant Investigator: In-Process RCA
When an anomaly is flagged, the Investigator validates the endpoint against an allow-list pattern and computes metrics in-process with parameterized SQL over a `mode=ro` connection. No request data is turned into code, and nothing is executed in a subprocess. The UI shows an equivalent audit script for transparency:

```python
# Audit preview (displayed, not executed)
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
cur.execute("SELECT epoch_ms, user_id, status_code_unpatched FROM telemetry "
            "WHERE api_endpoint = ? ORDER BY epoch_ms ASC LIMIT 500", (endpoint,))
# ...per-user inter-arrival gaps; gap <= 50ms counts as a collision
```

- If no collisions are measured, the report says so and no incident is recorded. There are no hard-coded fallback numbers.

### 3. Red Adversary: Shadow API Discovery & Burst Simulation
- **Shadow API Discovery**: Regex scan of the bundled `checkout_bundle.js` for endpoint strings.
- **Concurrency burst**: `asyncio.gather` of N coroutine calls against the in-process mock store (no network I/O).

### 4. Auto-Remediator (Blue Aegis): Reference Patch Templates
The root-cause fix is database-level atomicity. A mutex only narrows the window:

```sql
ALTER TABLE voucher_claims ADD CONSTRAINT uq_voucher_claim_user UNIQUE (user_id, voucher_code);
BEGIN;
UPDATE voucher_campaigns SET budget_remaining = budget_remaining - $3
 WHERE voucher_code = $2 AND budget_remaining >= $3;      -- 0 rows -> ROLLBACK (budget exhausted)
INSERT INTO voucher_claims (user_id, voucher_code, amount, claimed_at)
VALUES ($1, $2, $3, now()) ON CONFLICT (user_id, voucher_code) DO NOTHING;  -- 0 rows -> ROLLBACK
COMMIT;
```

Optional edge lock templates take the user ID from the authenticated request context (never a client header), release the lock only with the owner token, and fail closed if Redis is unavailable. On the mock target, enabling the patch flips a flag; the retest resets state and passes only when **exactly one** claim succeeds.

### 5. Compliance Arbiter & SecOps Copilot: Regression Check & Work Orders
- **Regression check**: Runs the same legitimate-user workload with the patch off and on against the mock store and reports the measured false-positive rate and latency delta.
- **SecOps Work Order Generator**: Emits a draft change order with a 3-stage canary plan. The rollout endpoint is a preview and does not deploy anything.
- **Interactive SecOps Copilot**: Whole-word intent matching. Diagnostic intents hand off to the Investigator.

---

## 4-Vector Autonomous Traffic Classifier

AIGIS evaluates requests across four observable vectors. Neither the ground-truth `is_attack` label nor `user_id` is used as a feature (the simulator names attackers `usr_botnet_*`, so using it would leak the label):

```
[Raw Telemetry Ingestion]
           |
           +---> Vector 1: Concurrency Velocity (burst stream id & rank)
           +---> Vector 2: Infrastructure ASN (Datacenter proxy AWS/Hetzner)
           +---> Vector 3: Bot Client Fingerprint (httpx, curl, go user agents)
           +---> Vector 4: State Mutation Idempotency (Unkeyed /claim requests)
           |
   [Anomaly Scoring: S = SUM(w_i * v_i)]
           |
           +---> S >= 0.45: ATTACK-LIKE
           +---> S <  0.45: BENIGN
```

### Classifier Evaluation

When the sampled rows carry an `is_attack` column, `/api/v1/database/classify` returns an `evaluation` block with the confusion matrix, precision, recall, false-positive rate, false-negative rate, F1, and per-burst **time-to-detect** (first flagged event minus first event of each attack burst, median and p95). Without labels it reports `NOT_EVALUATED`. Because the data is synthetic and generated by the same project, treat these numbers as a sanity check, not a held-out evaluation.

**Separate evaluation tracks:** the hand-authored classifier stress fixtures recorded **25% recall / 40% F1**, exposing limits of the observable features. A separate local **1,000,000-row performance benchmark** recorded 6.36 s for Investigator and 1.32 s for Sentinel analysis. These are different measurements, not real-world detection or throughput guarantees. See [evaluation, benchmark context, and reproduction commands](docs/backend-reliability.md). No independent real-world evaluation is published.

---

## Telemetry Database & Operational Scale

AIGIS can generate a synthetic telemetry dataset of **1,000,000 transaction records**. The CSV and `aigis_telemetry.db` are gitignored and are not included in a fresh clone. At startup, the server initializes local storage and automatically starts the synthetic stream at 10 TPS; you do not need the million-row dataset for a first demo. To create the larger fixture, use the UI or `POST /api/v1/dataset/generate` then `POST /api/v1/database/sync`. The `attack_ratio` parameter is the per-*batch* probability of an attack burst; each burst writes several rows, so the committed metadata shows about 31% attack rows at `attack_ratio=0.035`.

| Column Name | Type | Description |
| :--- | :--- | :--- |
| `event_id` | TEXT | Unique UUID primary key per transaction event |
| `timestamp` / `epoch_ms` | TEXT / INT | Millisecond-precision event timestamp |
| `user_id` / `session_id` | TEXT | Synthetic user and session tracking identifiers |
| `account_age_days` / `kyc_level` | INT / TEXT | Account maturity and KYC tier |
| `client_ip` / `is_datacenter_proxy` | TEXT / INT | Client IP address and ASN datacenter flag |
| `tls_ja3_hash` / `http_protocol` | TEXT | Client TLS fingerprint and protocol (`HTTP/1.1`, `HTTP/2`) |
| `api_endpoint` | TEXT | Target endpoint (e.g., `/api/v1/voucher/claim`) |
| `burst_stream_id` / `burst_rank` | TEXT / INT | Group ID and rank within concurrent burst waves |
| `transaction_amount_usd` | REAL | Monetary transaction volume |
| `status_code_unpatched` | INT | Vulnerable response code (`200 OK` on duplicate claims) |
| `status_code_patched` | INT | Hardened response code (`409 Conflict` on race attempt) |
| `is_attack` / `attack_type` | INT / TEXT | Ground-truth tag (`TOCTOU_RACE_CONDITION`, `BENIGN`) |

---

## Quick Start Guide

### Prerequisites
- Python 3.10 or higher; CI is configured for Python 3.12 and 3.14 on Windows and Ubuntu
- Git
- Node.js for extended offline JavaScript checks only (CI uses Node 22); not required to launch the dashboard

### Installation

```powershell
git clone https://github.com/Faewon/AIGIS.git
cd AIGIS
```

**Windows PowerShell** (activation is not required):

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_server.py
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run_server.py
```

### Launching the Platform

With the virtual environment active (or using its explicit Python path), launch:
```bash
python run_server.py
```
Or execute the Windows launcher:
```bat
start.bat
```

Open the console in your browser:
```
http://127.0.0.1:8000
```

The server binds to `127.0.0.1` only. Every `/api/*` route requires an `X-AIGIS-Token` header. The token is generated per process (or taken from `AIGIS_API_TOKEN`) and injected into the dashboard page, so the bundled UI works without extra setup. CORS is disabled. See [.env.example](.env.example) for supported settings; copying it to `.env` does **not** load it into the process.

### First demo

1. Open the dashboard and inspect the automatically generated synthetic stream.
2. Run a Wargame scenario: voucher race, account ownership (BOLA/IDOR), negative payment amount, or skipped order-state transition.
3. Compare baseline and mock-patched results, including legitimate-user regression evidence. A business pass does not imply a latency SLA pass.
4. Use **Queue benchmark** for a durable run and inspect history/replay. Generated patch and PR text are review artifacts, not deployed changes.

See the [3-minute demo guide](docs/demo.md) for the presentation workflow.

### Configuration and data safety

- **Offline by default:** `AIGIS_LLM_PROVIDER=heuristic` needs no API key. External LLMs are optional and do not turn the mock into a production scanner.
- **Provider-specific credentials:** startup reads only the selected provider's key (`GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `CEREBRAS_API_KEY`, `SAMBANOVA_API_KEY`, or `GITHUB_TOKEN`). Switching provider in the UI without entering a replacement key clears the previous key. Ollama uses a loopback endpoint.
- **Outbound data:** choosing an external LLM can send prompt/context data to that provider. Review its policies and avoid sensitive uploads or prompts; the PII scanner is not a guarantee of complete anonymization.
- **Local trust boundary:** the dashboard has no user login and supplies the API token to its browser client. This is not multi-user authentication. Do not expose the server through a public proxy or change its bind address for production use.
- **Persistence:** uploaded datasets, snapshots, incidents and run history may remain on disk. Use authorized, sanitized data and manage local retention; do not commit keys, DSNs or private datasets.

### Running the tests
```bash
python -m unittest discover -s tests -v
python -m scratch.check_project
python -m scratch.check_docs
python -m pip check
```

On Windows without activation, replace `python` with `.\.venv\Scripts\python.exe`.

### Optional PostgreSQL telemetry

Install the optional driver in the server's Python environment:

```bash
python -m pip install -r requirements-postgres.txt
```

Configure `AIGIS_POSTGRES_MAIN` in the server environment with a PostgreSQL URI or
libpq DSN for a dedicated read-only role. Do not put real credentials in Git,
chat, logs or command history. `.env` files are not loaded automatically. Use
verified TLS for remote servers. In **Telemetry Explorer → PostgreSQL source —
read-only snapshot**, test the profile, choose schema/table and load or refresh.

The import is capped at 100,000 rows / 50 MiB of converted field data. The UI
discloses capture time and truncation. The SQL console and agents analyze a local
SQLite snapshot, not live PostgreSQL; schema compatibility is still required.
The demo stream, job queue and run history remain SQLite. See the
[PostgreSQL setup and limitations](docs/postgresql.md).

### Durable wargame benchmarks

Use **Queue benchmark** on Wargame for durable submission/progress and **Cancel
job** to request cancellation. Reloading the tab restores polling. Queue admission
is limited to 20 pending/active jobs and one active queued benchmark; legacy
synchronous routes are separate. Expired leases become `INTERRUPTED` or
`TIMED_OUT`, not automatically retried. Training replay executes saved version-3
manifests and rejects incompatible source versions. See
[wargame execution and evidence](docs/wargame-improvements.md).

Local verification on **2026-11-10**: **88 tests discovered, 86 passed,
2 PostgreSQL integration tests skipped**; extended offline project checks and
local documentation-link checks passed. Browser checks were **not rerun** in this
review; an earlier Edge suite pass is historical evidence only. Skips do not verify real PostgreSQL
connectivity. Re-run tests for your checkout; see
[verification commands](docs/postgresql.md#verification).

### Remaining validation and development priorities

- Run the optional integration tests against a disposable PostgreSQL instance; the default offline suite does not verify real database connectivity or TLS.
- Rerun browser workflows after UI changes; backend tests do not establish browser correctness.
- Validate detection on independently labeled, authorized data. Synthetic fixtures and the current low-recall stress results do not establish production detection quality.
- Production adoption would require separately designed authentication/authorization, deployment controls, retention/privacy review and independently reviewed business invariants. These are not delivered by this local proof of concept.
- The current test environment emits a Starlette/httpx deprecation warning. Tests pass, but dependency compatibility should be reviewed before a future upgrade.

---

## REST API Specification

| Route | HTTP | Description |
| :--- | :---: | :--- |
| `/api/v1/stream/status` | `GET` | Telemetry stream velocity, active batch queue, and TPS metrics |
| `/api/v1/stream/start` | `POST` | Launch continuous background telemetry streaming engine |
| `/api/v1/stream/stop` | `POST` | Terminate continuous telemetry stream safely |
| `/api/v1/sentinel/status` | `GET` | Real-time Sentinel drift verdict, velocity derivatives, and tail forecasts |
| `/api/v1/sentinel/evaluate` | `POST` | Trigger ad-hoc Sentinel evaluation across sliding temporal windows |
| `/api/v1/sentinel/simulate` | `POST` | Inject simulated promotional Flash Sale traffic spikes |
| `/api/v1/investigator/diagnose` | `POST` | Run in-process, read-only RCA over telemetry for an allow-listed endpoint |
| `/api/v1/investigator/latest` | `GET` | Retrieve latest quantitative RCA dossier, vulnerability gap, and loss figures |
| `/api/v1/copilot/chat` | `POST` | Query SecOps Copilot with autonomous RCA handoff support |
| `/api/v1/workorder/generate` | `GET` | Generate standardized 3-stage Canary Rollout SecOps Work Order ticket |
| `/api/v1/workorder/deploy` | `POST` | Execute simulated canary stage progression (5% -> 25% -> 100%) |
| `/api/v1/sentinel/incidents` | `GET` | Query recorded incident signals and historical findings |
| `/api/v1/sentinel/policies` | `GET` | List contextual stand-down policies and promotional windows |
| `/api/v1/sentinel/policies/toggle` | `POST` | Toggle active state of a specific contextual policy rule |
| `/api/v1/database/table_data` | `GET` | Browse a selected database table with pagination |
| `/api/v1/database/postgres/discover` | `POST` | Test a server-side PostgreSQL profile and list base tables, read-only |
| `/api/v1/database/postgres/snapshot` | `POST` | Import a selected table into a bounded local snapshot |
| `/api/v1/database/classify` | `POST` | Execute the 4-vector heuristic traffic classifier over telemetry |
| `/api/v1/wargame/run_full` | `POST` | Run an isolated full mock workflow with optional seed |
| `/api/v1/wargame/train` | `POST` | Run seeded multi-round mock training with paired evidence |
| `/api/v1/wargame/recheck_multicycle` | `POST` | Run repeated mock verification cycles and persist the result |
| `/api/v1/wargame/runs/{run_id}` | `GET` | Retrieve saved configuration and simulation evidence |
| `/api/v1/wargame/runs/{run_id}/replay` | `POST` | Replay compatible saved training manifests or recheck settings |
| `/api/v1/wargame/runs` | `GET` | Bounded saved-run history |
| `/api/v1/wargame/jobs` | `POST` | Submit a durable local benchmark (202) |
| `/api/v1/wargame/jobs/{run_id}` | `GET` | Job status, heartbeat and saved run |
| `/api/v1/wargame/jobs/{run_id}/cancel` | `POST` | Request queued/running job cancellation |
| `/api/v1/wargame/controls/evaluate` | `POST` | Local mock control-ablation matrix |
| `/api/v1/wargame/classifier/shadow` | `GET` | Read-only sampled temporal signals; no enforcement |
| `/api/v1/wargame/classifier/evaluation` | `GET` | Separate synthetic row/temporal evaluation fixtures |

This table highlights the main routes. Set `AIGIS_ENABLE_DOCS=1` before starting the server to expose request schemas and the complete route list at `http://127.0.0.1:8000/docs`; documentation endpoints are disabled by default. API calls require `X-AIGIS-Token`; the bundled dashboard supplies it automatically.

---

## Regulatory & Compliance Mapping

> [!CAUTION]
> AIGIS has **not** been assessed against any standard. The table below lists topics the demo touches on, not claims of compliance. The app never emits "COMPLIANT"; its dossier marks every framework as `NOT_ASSESSED` or `VERIFIED_IN_MOCK_TARGET`. Have a QSA or auditor confirm any clause mapping before you rely on it.

| Regulatory Standard | Related topic (unverified mapping) | What the demo shows |
| :--- | :--- | :--- |
| **PCI-DSS 4.0** | Req 6.4 (Public-facing app defense) | Detection of a race condition in a mock target. |
| **PCI-DSS 4.0** | Req 10.4.1 (Audit log review) | Sliding-window review of synthetic telemetry. |
| **SBV Circular 09/2020/TT-NHNN** | System safety in banking | Illustrative only. |
| **OWASP API Security Top 10** | API1:2023 (BOLA), API6:2023 (Sensitive business flows) | Mock BOLA and voucher-abuse scenarios. |
| **NIST CSF 2.0** | DE.AE, RS.AN | Detection and analysis workflow on synthetic data. |

---

## Repository Structure

```
AIGIS/
|-- backend/
|   |-- agents/
|   |   |-- adversarial_trainer.py   # Wargame orchestration engine
|   |   |-- arbiter.py               # Demo compliance mappings & simulated PR text
|   |   |-- blue_aegis.py            # Reference patch template generator
|   |   |-- fintech_sentinel.py      # Time-series drift & velocity derivatives
|   |   |-- quant_investigator.py    # In-process read-only SQL RCA engine
|   |   |-- rea_dissector.py         # Regex-based Shadow API extraction from bundle
|   |   |-- red_cerebrus.py          # Concurrent-coroutine burst simulator (no HTTP)
|   |   |-- sandbox_runner.py        # Runs attack scenarios against the mock store
|   |   |-- secops_copilot.py        # Natural-language Q&A and handoff agent
|   |   |-- work_order_generator.py  # 3-Stage Canary Rollout ticket generator
|   |-- datasets/
|   |   |-- aigis_simulated_traffic_1m_meta.json  # 1M dataset metadata & schema
|   |-- mock_target/
|   |   |-- checkout_bundle.js       # Client bundle with exposed Shadow APIs
|   |   |-- store.py                 # Target mock e-commerce & voucher microservice
|   |-- database.py                  # SQLite WAL connection & Incident KB store
|   |-- data_simulator.py            # 1M telemetry simulation pipeline
|   |-- llm_engine.py                # Optional multi-provider LLM gateway & heuristic fallback
|   |-- patch_exporter.py            # Multi-target reference patch templates
|   |-- pii_scanner.py               # Pattern-based PII detection/masking (not exhaustive)
|   |-- server.py                    # High-throughput FastAPI asynchronous application
|   |-- stream_engine.py             # Continuous telemetry streaming engine
|   |-- text_to_sql.py               # Natural language to SQLite query engine
|   |-- traffic_classifier.py        # 4-vector heuristic classifier
|   |-- evidence.py                  # Typed analysis & simulation provenance
|   |-- postgres_source.py           # Optional read-only PostgreSQL snapshots
|-- tests/
|   |-- test_security_regressions.py # Regression tests for the security review
|-- frontend/
|   |-- index.html                   # Technical Operations Single-Page Application
|   |-- standalone.css               # Complete technical styling definitions
|   |-- wargame-verification.js       # Wargame evidence presentation helpers
|   |-- vendor/                      # Bundled browser dependencies
|-- docs/
|   |-- README.md                    # Documentation navigation & reading paths
|   |-- overview.md                  # Vietnamese executive summary
|   |-- architecture.md              # Architecture, evidence, isolation & replay
|   |-- demo.md                      # Demo preparation & presentation workflow
|   |-- design-system.md             # Brand & dashboard design reference
|   |-- backend-reliability.md        # Backend implementation & evaluation context
|   |-- postgresql.md                # Read-only source setup & integration checks
|   |-- wargame-improvements.md       # Queue, replay & mock benchmark limitations
|   `-- reports/                     # Indexed historical checks & resolved findings
|-- LICENSE                          # MIT License
|-- README.md                        # Master technical documentation
|-- requirements.txt                 # Python dependencies
|-- run_server.py                    # Application launch entrypoint
`-- start.bat                        # Windows execution script
```

---

## Documentation Hub

| Document | Read it for |
| :--- | :--- |
| [Documentation index](docs/README.md) | Reading paths and document status conventions |
| [Project overview](docs/overview.md) | Vietnamese summary, value proposition, and current scope |
| [System architecture](docs/architecture.md) | Components, evidence states, simulation isolation, and run replay |
| [3-minute demo](docs/demo.md) | Preparation, presentation steps, and measured-result narration |
| [Design system](docs/design-system.md) | Brand identity and dashboard visual guidance |
| [Backend reliability](docs/backend-reliability.md) | Implementation details, classifier stress results, and local benchmarks |
| [PostgreSQL sources](docs/postgresql.md) | Optional read-only profiles, bounded snapshots, and integration tests |
| [Wargame verification](docs/wargame-improvements.md) | Durable jobs, manifest replay, control ablations, and evidence limits |
| [Review & check history](docs/reports/README.md) | Historical checks, resolved findings, and reproduction commands |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
