# Sheet schemas — FROZEN 2026-09-07 (lettering updated same day)

Every sheet is mirrored to a JSON array by `build/ingest/fetch_sheets.php`. Ingest parses
exactly these layouts.

## Mirror format — flat string arrays
Every **domain** sheet (A, C–H, I–M) mirrors as a flat, sorted, deduped JSON array of
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

## C–H · pipeline domain sheets · I–M · standalone domain sheets
| domain | added | reason |
|---|---|---|
Only the `domain` column is required (header cell must be `domain`); `added`/`reason` are
optional audit columns. Mirror: flat string array. A listed domain covers itself and all
subdomains.

| Sheet | Name | Contract |
|---|---|---|
| C | default-whitelist | exclusion set member (excluded conditions + easylist/hosts scrub) |
| D | default-blocklist | org default blocks, appended as block rules (bootstrap: the 23 default_blockdom) |
| E | manual-whitelist | exclusion set member, like C |
| F | manual-blocklist | appended block rules, like D |
| G | omit-from-whitelist | subtracted from the exclusion set (holds the protected search hosts) |
| H | omit-from-blocklist | never-block floor — drops block rules from every source |
| I | whitelisted-domains-injection-enabled | standalone · on-demand JSON, never merged |
| J | tracking-whitelist | standalone · on-demand (was rule 5005) |
| K | allow-request-domains | standalone · on-demand (was rule 5006) |
| L | initiator-allowed-domains | standalone · on-demand (was rule 5006) |
| M | rule101xtra | standalone · on-demand (was CSP-strip rule 33) |

## Ingest gates (per sheet, fail-closed — keep previous mirror on violation)
- fetch error / HTML login page / empty body
- header mismatch vs the layouts above
- row-level: invalid domains rejected + reported (IPs, localhost, no-dot, bad syntax)
- shrink guard on C / E / H (any shrink → hold; `force` dispatch input = the confirming re-run)
- ±30% size-delta guard on A / B (when previous mirror ≥ 20 rows)
- `TBD` export_url → sheet skipped without failing the run
- every run posts a per-sheet diff summary (added/removed, rejects with line numbers)

Bootstraps: C (174) · G (2 protected hosts) · H (13, whitelistes3) done and live.
TSVs for D · I · J · K · L · M are in `bootstrap/` — paste, fill the export_urls, delete the folder.
