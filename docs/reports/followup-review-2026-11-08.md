# Additional confirmed findings — 2026-11-08
> Status: Resolved historical findings · Original review: 2026-11-08
>
> [Report index](README.md) · [Current backend reference](../backend-reliability.md)

Original code locations and reproduction results describe the pre-fix snapshot.

**Resolution:** All four findings have now been addressed. See
[Backend reliability](../backend-reliability.md) and the behavioral regression tests in
`tests/test_backend_improvements.py`. The three-pass follow-up script now asserts
the corrected behavior; the original findings below are historical.

These findings are separate from the five previously fixed defects. Each was
traced through its caller and reproduced three times with isolated fixtures using
`python -m scratch.check_additional_findings`. No application source was changed
in this follow-up review.

## 1. Medium — Sentinel analyzes a different database from the selected dataset

**Locations:** `backend/agents/fintech_sentinel.py:21–22,81`,
`backend/database.py:set_active_db`, `backend/server.py:964–975`.

The global Sentinel retains the default `DB_PATH` captured at construction and
passes it explicitly to `get_connection`. Switching databases changes
`ACTIVE_DB_PATH` but never updates Sentinel. The evaluation reports its source as
`ACTIVE_DB` even though it still queries the original file. Policy and incident
lookups, however, use the active database, mixing data sources within one verdict.

**Confirmed:** Select a custom database with only `name,value` telemetry while the
default database contains an attack burst. Sentinel reports `CRITICAL_ANOMALY`
and that default database's burst ID under `ACTIVE_DB`. The investigator correctly
reports the selected custom database as unsupported.

**Impact:** Operators receive attack verdicts and metrics for the wrong dataset;
an attack present only in the selected database could likewise be missed.

**Fix:** Bind all components of an evaluation to a single captured database
identity. Include that identity in the response and invalidate or partition
cached Sentinel state/history when switching datasets. If Sentinel intentionally
monitors only the default live stream, label that source accurately rather than
presenting it as the selected dataset.

## 2. Medium — Copilot fabricates measurements for unsupported datasets

**Locations:** `backend/agents/secops_copilot.py:58–71`,
`backend/agents/quant_investigator.py:248–260`.

The investigator returns `UNSUPPORTED_DATASET` with no quantitative RCA fields.
Copilot ignores this status and supplies hard-coded fallback values: 1.45 ms,
93.3%, and $7,500. It also describes a verified patch and offers remediation
actions despite having no supporting analysis.

**Confirmed:** Ask `diagnose` with a custom `name,value` CSV active. The structured
investigator result says unsupported, while the human-facing reply asserts
`1.45ms`, `93.3%`, and `$7,500.00` exposure.

**Impact:** An ordinary supported user workflow produces invented security and
financial findings, contradicting both the structured result and demo guarantees.

**Fix:** Handle unsupported/error/no-data outcomes before rendering numerical
findings. Display missing measurements as unavailable and only present measured
values. Gate any verification language on actual evidence.

## 3. Medium — Multi-round dossier compares different attack scenarios

**Locations:** `backend/agents/adversarial_trainer.py:76–78,149–154`,
`backend/agents/arbiter.py:134–136,247–258`.

The trainer passes the first round's attack and last round's retest to the
Arbiter. For heterogeneous rounds these artifacts describe different scenarios,
request counts, and loss definitions. The resulting single-cycle dossier is not
a valid before/after comparison.

**Confirmed:** Run two rounds with three burst streams. The first attack is three
voucher claims and the final retest is two unauthorized-account withdrawal
denials. The dossier reports `blocked 2/1 retest streams`, calls the retest a
voucher-claim pipeline, and reports $1,500 preserved. The trainer's correctly
aggregated illegal-loss reduction across those rounds is $16,000.

**Impact:** Final security scores, financial summaries, and remediation handoff
artifacts can describe a comparison that never took place.

**Fix:** Generate paired per-round dossiers and an explicitly aggregated training
summary, or pass a matched attack/retest pair to a clearly scoped final dossier.
Use `illegal_stolen_amount` for voucher loss rather than counting its legitimate
first claim as theft.

## 4. Medium — Composite generated security guard is bypassable by headers

**Location:** `backend/agents/adversarial_trainer.py:277–335`, particularly
`309–315` and `324–325`.

The separate multi-round composite patch uses client-supplied `X-User-ID` as its
lock identity and `X-TLS-JA3` as its rate-limit identity. These are untrusted request
headers; changing them changes both defense keys. This is different from the
ordinary patch exporter, which correctly requires authenticated server state.

**Confirmed:** Execute the generated middleware class against an in-memory Redis
protocol double. Two concurrent requests with the same authenticated
`scope.state.user_id` but different `X-User-ID` headers both enter the protected
application. The lock keys do not collide because the authenticated ID is ignored.

**Impact:** A user who adopts this generated reference guard can bypass its
per-user serialization and reset its fingerprint throttling by rotating headers.
The template is displayed/generated, not executed by the AIGIS mock server.

**Fix:** Use authenticated identity from ASGI state and fingerprints from a
trusted ingress integration. Reuse the hardened exporter rather than maintaining
a divergent weaker generator, with negative controls that rotate client headers.

## Verification and scope

- Each finding reproduced in **three consecutive runs**.
- Generated middleware was exercised with a deterministic Redis protocol double;
  this confirms its key-selection logic, not Redis deployment behavior.
- Dataset fixtures were disposable SQLite files; training used only the in-process
  mock target and offline heuristic provider.
- The four findings were initially unfixed in the review-only pass and have since
  been resolved by the backend improvements implementation.
- Browser interaction, external providers, and large-load performance were not
  exercised. This is not an exhaustive guarantee of project correctness.
