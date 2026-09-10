# Sheet schemas — 15 sheets, A–O
(Sheet I inserted + I–M re-lettered J–N on 2026-09-08; Sheet E
`default-blocklist-not-to-add` inserted + E–N re-lettered F–O on 2026-09-10)

Every sheet is mirrored to a JSON array by `build/ingest/fetch_sheets.php`. Ingest parses
exactly these layouts.

## Mirror format — flat string arrays
Every **domain** sheet (A, C–J, K–O) mirrors as a flat, sorted, deduped JSON array of
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
market land in `global.json`, which ALSO receives a cross-market promotion (a hostname seen
in >= 3 literal markets is promoted into global — `$PROMOTE_MIN_MARKETS` in fetch_sheets.php). `nb_click` stays sheet-side only. A market file whose market
disappears from the sheet is deleted. `dist/traffic_quality/` publishes these files as-is.
Three **regional rollups** are also written (restored 2026-09-08 — v3 shipped them and the
backends request them by region key): `latam.json`, `apac.json`, `nordics.json`, each the
UNION of its member markets (member lists in `fetch_sheets.php`, copied from v3's
generator). A literal sheet market sharing a rollup name merges into the union.

## C–J · pipeline domain sheets · K–O · standalone domain sheets
| domain | added | reason |
|---|---|---|
Only the `domain` column is required (header cell must be `domain`); `added`/`reason` are
optional audit columns. Mirror: flat string array. A listed domain covers itself and all
subdomains.

| Sheet | Name | Contract |
|---|---|---|
| C | default-whitelist | product-only (2026-09-08): published as `dist/whitelist/default.json` (− omit-from-whitelist − omit-from-blocklist) — takes part in NO curation or scrub |
| D | default-blocklist | org default blocks, appended as block rules (bootstrap: the 23 `$blockdom` entries carried over from the legacy server `stopads.php`) |
| E | default-blocklist-not-to-add | **NEW 2026-09-10** — the veto on the default blocklist: a listed domain produces NO rule at all. Same contract as omit-from-blocklist (curation-set member + never-block floor, so it also stops the appends, which sit above curation), domain + all subdomains. Kept separate because omit-from-blocklist has the tightest edit access of all sheets (own-brand only); this one is meant to be edited freely. LIVE since 2026-09-10 (gid 866107718, tab `blocklist_but_do_not_add`, 21 rows); the absent-mirror path stays as a fail-soft fallback |
| F | manual-whitelist | mirrored; part of NO recipe for now (user decision 2026-09-08: role to be decided) |
| G | manual-blocklist | appended block rules, like D |
| H | omit-from-whitelist | EXACT host, four consumers (holds the protected search hosts + gamed-vote vetoes): ① step-2 veto on the user whitelist · ② veto on download-sites · ④ compile's `$minusG` before publishing `dist/whitelist/default.json` · ③ since 2026-09-09, the veto on BLANKET upstream allows (`scrubGVetoAllows`, guarded) — path/type-scoped exceptions stay |
| I | omit-from-blocklist | never-block floor, domain+subdomains — curation-set member + append floor at compile + (2026-09-09) vetoed from every whitelist derivation, exactly where omit-from-whitelist is: user whitelist step 2b · download-sites · compile's `$minusG`. Tightest edit access of all sheets |
| J | download-sites | added 2026-09-08 (live, 50 rows), dual role: ① curation-set member — subtracted from every blocking source by curate.php; ② source — normalized (invalid rows warn) − omit-from-whitelist − omit-from-blocklist → `sanitized/download-sites.txt` (ABP allow list, exact 7-option template) → DNR allow lane at priority 2 (guards: $document/$~third-party/non-@@ = fail) |
| K | whitelisted-domains-injection-enabled | standalone · on-demand JSON, never merged |
| L | tracking-whitelist | standalone · on-demand (was rule 5005) |
| M | allow-request-domains | standalone · on-demand (was rule 5006) |
| N | initiator-allowed-domains | standalone · on-demand (was rule 5006) |
| O | rule101xtra | standalone · on-demand (was CSP-strip rule 33) |

## Ingest gates (per sheet, fail-closed — keep previous mirror on violation)
- fetch error / HTML login page / empty body
- header mismatch vs the layouts above
- row-level: invalid domains rejected + reported (IPs, localhost, no-dot, bad syntax)
- shrink guard on C / E / F / I / J (any shrink → hold; `force` dispatch input = the confirming re-run)
- ±30% size-delta guard on A / B (when previous mirror ≥ 20 rows)
- `TBD` export_url → sheet skipped without failing the run
- every run posts a per-sheet diff summary (added/removed, rejects with line numbers)

Bootstraps: C (174) · H omit-from-whitelist · I omit-from-blocklist (13, whitelistes3) done and live.
Sheet E went live 2026-09-10 (21 rows). All 15 export_urls are configured — no TBD left.
All sheets bootstrapped and live; the one-time `bootstrap/` TSV folder was removed 2026-09-08.
