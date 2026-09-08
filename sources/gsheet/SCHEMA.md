# Sheet schemas — FROZEN 2026-09-07 (Sheet I inserted + I–M re-lettered J–N 2026-09-08)

Every sheet is mirrored to a JSON array by `build/ingest/fetch_sheets.php`. Ingest parses
exactly these layouts.

## Mirror format — flat string arrays
Every **domain** sheet (A, C–I, J–N) mirrors as a flat, sorted, deduped JSON array of
domain strings: `["adblockghost.com", "ninja-block.com", …]`. The `added`/`reason` columns
are sheet-side audit trail only — they never enter the mirror. Only Sheet B mirrors as
objects (it's data, not a domain list). Rows are preserved exactly as entered — `www.x.com`
and `x.com` are distinct entries and both are kept; dedupe only removes identical rows.

## A · popup — KEPT in its current pivot format
| Block List v3 | COUNTA of Block List v3 |
|---|---|
Quoted cells (`"domain",`), a blank-label pivot row, a `Grand Total` footer — the fetcher
strips all of it. Mirror: flat domain array; the popup role treats all of them as
redirect targets (block-type handling is a compile-level decision).

## B · traffic-quality-trackers
| market | hostname | nb_click |
|---|---|---|
Mirrored as a per-market split, directly at ingest, into **`sources/traffic_quality/`**:
one flat sorted hostname array per market (`fr.json`, `de.json`, …); rows with an empty
market land in `global.json`. `nb_click` stays sheet-side only. A market file whose market
disappears from the sheet is deleted. `dist/traffic_quality/` publishes these files as-is.
Three **regional rollups** are also written (restored 2026-09-08 — v3 shipped them and the
backends request them by region key): `latam.json`, `apac.json`, `nordics.json`, each the
UNION of its member markets (member lists in `fetch_sheets.php`, copied from v3's
generator). A literal sheet market sharing a rollup name merges into the union.

## C–I · pipeline domain sheets · J–N · standalone domain sheets
| domain | added | reason |
|---|---|---|
Only the `domain` column is required (header cell must be `domain`); `added`/`reason` are
optional audit columns. Mirror: flat string array. A listed domain covers itself and all
subdomains.

| Sheet | Name | Contract |
|---|---|---|
| C | default-whitelist | product-only (2026-09-08): published as `dist/whitelist/default.json` (−G) — takes part in NO curation or scrub |
| D | default-blocklist | org default blocks, appended as block rules (bootstrap: the 23 default_blockdom) |
| E | manual-whitelist | mirrored; part of NO recipe for now (user decision 2026-09-08: role to be decided) |
| F | manual-blocklist | appended block rules, like D |
| G | omit-from-whitelist | step-2 veto on the user whitelist, EXACT host (holds the protected search hosts + gamed-vote vetoes) |
| H | omit-from-blocklist | never-block floor — curation-set member + append floor at compile |
| I | download-sites | NEW 2026-09-08 (live, 50 rows), dual role: ① curation-set member — subtracted from every blocking source by curate.php; ② source — normalized (invalid rows warn) − G → `sanitized/download-sites.txt` (ABP allow list, exact 7-option template) → DNR allow lane at priority 2 (guards: $document/$~third-party/non-@@ = fail) |
| J | whitelisted-domains-injection-enabled | standalone · on-demand JSON, never merged |
| K | tracking-whitelist | standalone · on-demand (was rule 5005) |
| L | allow-request-domains | standalone · on-demand (was rule 5006) |
| M | initiator-allowed-domains | standalone · on-demand (was rule 5006) |
| N | rule101xtra | standalone · on-demand (was CSP-strip rule 33) |

## Ingest gates (per sheet, fail-closed — keep previous mirror on violation)
- fetch error / HTML login page / empty body
- header mismatch vs the layouts above
- row-level: invalid domains rejected + reported (IPs, localhost, no-dot, bad syntax)
- shrink guard on C / E / H / I (any shrink → hold; `force` dispatch input = the confirming re-run)
- ±30% size-delta guard on A / B (when previous mirror ≥ 20 rows)
- `TBD` export_url → sheet skipped without failing the run
- every run posts a per-sheet diff summary (added/removed, rejects with line numbers)

Bootstraps: C (174) · G (2 protected hosts) · H (13, whitelistes3) done and live.
All sheets bootstrapped and live; the one-time `bootstrap/` TSV folder was removed 2026-09-08.
