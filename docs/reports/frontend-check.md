# Frontend functionality check
> Status: Historical browser-check snapshot · Indexed: 2026-11-08
>
> [Report index](README.md) · [Design reference](../design-system.md)

The original run date and browser version were not recorded. The index date above
is documentation maintenance metadata, not a claim that the browser check was rerun.

Verified in real headless Microsoft Edge against a running localhost server,
using an isolated database and offline heuristic provider.

## Confirmed working

- Authenticated dashboard load; Data, Model, SQL, FYI, and Wargame navigation.
- Main scanner, risk, investigator, and Sentinel modals open; backdrop closes.
- Navigation clicks, input events, table filtering, database dropdown.
- CSV selection via browser File/change event, successful ingestion, and imported
  rows displayed in the refreshed data view.
- Restore-default action reconnects the actual configured database.
- SQL console executes a count query and renders the result.
- PII scan renders a national-ID finding and masked payload.
- OpenAPI parsing renders endpoint results and visible invalid-input errors.
- Investigator shows unsupported-data and no-anomaly states without inventing
  an incident or claiming a threat was detected.
- Risk velocity input changes the computed score without accumulating phantom
  requests from moving the slider.
- Desktop has no horizontal document overflow; mobile emulation is 390 px wide
  with 390 px content width.
- No JavaScript exceptions, CSP errors, or failed resources in the final run.
  Edge prints a non-blocking password-field-outside-form recommendation.

## Fixes made

- Default to telemetry and select an available table for custom databases.
- Add ribbon upload status and refresh schema/table metadata after uploads.
- Correct scoped dropdown closing and delegated handler bubbling; preserve
  existing data attributes when making element IDs unique.
- Correct API token origin checking and preserve Request headers.
- Show honest investigator labels and use the actual execution-result fields.
- Escape schema/spec names in generated markup; show parser errors to users.
- Remove hard-coded machine path and fake million-row counts from restore action.
- Wire the risk velocity slider to a non-mutating simulation input.
- Fix header search, live table counts, mobile sizing, and missing favicon.

## Reproduce

`python -m scratch.check_browser` requires Microsoft Edge at the installed Windows
path, Python `websocket-client`, and uvicorn. It prints observed browser results.
`python -m scratch.check_project` checks syntax and isolated HTTP integrations.

## Limits

This is a targeted usability smoke check, not exhaustive acceptance testing.
External provider keys, all long-running wargame/training flows, download dialogs,
keyboard-only accessibility, and other browsers were not fully exercised.
