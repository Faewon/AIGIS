# Frontend interaction improvements — 2026-11-08

> Status: Verified locally · Scope: Dashboard interactions on headless Microsoft Edge

[Report index](README.md) · [Design reference](../design-system.md)

## Implemented

- Work orders clear previous evidence while loading, show unavailable measurements
  as `N/A`, render stage statuses from the backend, and expose retry on load failure.
  Canary action is a simulation preview, not a production deployment.
- PR action describes a simulated draft; a clean PII pattern scan does not claim
  compliance. Investigator labels describe read-only analysis and audit preview.
- Stream counters use actual session events and observed attack ratios, without
  adding a fictional million-row baseline.
- Same-origin authenticated requests reject HTTP failures and have timeouts.
  Table requests abort superseded work and ignore stale responses even if abort
  is not honored by the transport. Failed table loads expose a retry button.
- Main upload/connect/configuration/copy flows use non-blocking notifications.
  Some legacy tools still retain their existing alert dialogs.
- Polling waits for completion, pauses while the document is hidden, backs off on
  errors, and marks a stale connection. Polling starts on initial dashboard load.
- Shared modal handling supplies dialog semantics, focus entry, Tab containment,
  Escape dismissal, and focus restoration. Added visible keyboard focus, input
  accessible names, keyboard support for workflow steps, reduced-motion CSS, and
  wrapping modal controls on compact screens.

## Verification

- `python -m scratch.check_project`: zero failures, including served JavaScript
  syntax, unique served IDs, strict CSP, and isolated HTTP integrations.
- `python -m scratch.check_browser`: passed on headless Edge with disposable
  datasets and offline provider. Exercised navigation, dropdown visibility,
  real CSV upload, unsupported diagnosis, risk slider, SQL, and PII scan.
- Added browser assertions for unavailable work-order evidence, backend-derived
  preview stages, modal focus/Tab/Escape/return, HTTP error rejection, and forced
  out-of-order table responses.
- Mobile emulation: viewport/content width both 390 px. No JavaScript exceptions.
  An intentional 404 request checks error handling; its network error is expected.
  Edge also prints a non-blocking password-field-outside-form recommendation.

## Model View follow-up

Model View now supports moving table cards by dragging their headers, scrolling
all columns, and connecting columns by drag/drop or by selecting a column in each
of two tables. **New relationship** opens the same editor without dragging.
Click a connector or an existing relationship to edit its endpoints, cardinality
(`1:*`, `*:1`, `1:1`, `*:*`), and active/inactive state. Inactive links are dashed.
The editor also supports deletion and rejects duplicate column pairs.

Positions and model relationships are stored in browser local storage per
database-path identity returned by the backend. Schema reloads retain valid
endpoints and ignore relationships whose columns no longer exist. This is visual
model metadata: it does not validate uniqueness/cardinality, enforce foreign keys,
or propagate filters into SQL queries. Storage is specific to the browser/origin.

Headless Edge checks passed for actual mouse dragging of a table header, two-column
connection, interactive connector rendering, editing inactive state, metadata
reload persistence, and deletion. Native column drag/drop has the equivalent
handler but was not separately automated. `python -X utf8 -m scratch.check_project`
passed with zero failures; UTF-8 mode avoids the Windows subprocess stdin encoding
issue with Unicode text in the dashboard script.

## Remaining scope

### Crossing-aware Auto arrange

Auto arrange now runs locally vendored `elkjs@0.11.0` in a dedicated Worker.
Four deterministic candidates (left/right direction, seeds 1/7) use layered
crossing minimization, greedy switching, fixed field ports, and orthogonal routing.
Candidates are ranked lexicographically by card overlap, edge/card intersections,
strict segment crossings, shared segment length, length, bends, and area.
Shared endpoints are not counted as strict crossings; shared lengths are measured
separately. Multiple segments at a single visual junction can count separately.

The action has a 20-second timeout, ignores results if model identity/layout,
positions, relationships or measured ports changed, and retains existing positions
on failure. Undo arrange restores the previous positions/routes for the same
in-memory dataset. Routes use widened invisible hit targets. Field order remains
unchanged; clipped fields fan out near the visible boundary. Dragging cards or
scrolling fields invalidates optimized routes and uses simple orthogonal fallback
until Auto arrange is run again. Optimized routes are session-only; positions and
relationships retain their existing local-storage persistence.

`node scratch/check_model_layout.cjs` covers stars, shared dimensions, cycles,
parallel edges/disconnected nodes, and a 24-table/40-edge model, with varied card
heights. Across these synthetic fixtures, strict crossing counts went from 192
to 3 compared with a fixed-grid/straight-line baseline (not the previous BFS).
All optimized fixtures had zero card overlaps and zero unrelated-card
intersections; repeated runs were deterministic. Shared segments can remain,
particularly edges using the same column port. This is not a global-optimum claim.
Headless Edge verified the local Worker and scripts under CSP, returned column
routes, Undo availability, and card containment at 1440/1024/768/390 px.

### Model overlap correction

Browser geometry inspection confirmed that the model canvas computed to
`overflow: visible`: its utility class had no matching CSS definition. The zoom
origin utility was also undefined, so scaling used the center of the large canvas.
Cards could paint over the Properties pane and bottom controls, and zoom/scroll
coordinates did not match the model's top-left coordinate system.

The canvas now explicitly clips and scrolls, has an isolated stacking context,
and scales from `0 0`. A dedicated surface tracks scaled canvas dimensions for
scrollbars. Properties and toolbar controls have separate layers. Table headers
truncate long names, and initial rendering repairs colliding card positions from
older layouts. Browser assertions verify canvas clipping, zoom origin and pane
hit testing. At widths 1440, 1024, 768 and 390 px, Auto arrange + Fit to view kept
all three fixture cards inside the canvas without card-to-card or pane overlap.
The broader interaction checks also passed without JavaScript exceptions.

### Model workspace cleanup

The model workspace now uses neutral table cards without page-number/category
badges or repeated row-count footers. A compact toolbar and bottom zoom/layout bar
leave the canvas as the main work area. A collapsible Properties pane shows table
metadata or selected relationship details. Single-click selects a relationship;
double-click opens the editor. Selected endpoints are highlighted, inactive links
remain dashed, and direction arrows were removed because no filter propagation
is implemented.

Added Fit to view, Auto arrange, Show related, and named layout tabs. Custom layouts
can include/exclude tables using the pane checkboxes without deleting data. Layout
membership is stored alongside existing model settings; table positions are shared
across layouts. Manage relationships shows the list separately from the editor.
Edge assertions cover single-click inspection without a modal, related-table
visibility, Fit to view, and returning to All tables, in addition to the earlier
model interaction checks.

This iteration preserves the existing dashboard structure and embedded source.
Module extraction, toolbar redesign, full visual/accessibility audits, and other
browser engines were not part of this verification. No production deployment or
external-provider behavior was tested.
