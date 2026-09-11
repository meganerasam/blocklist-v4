# Automated All-In-One List V2

The single factory repo for every blocklist and whitelist consumed by the ad-block extension
family (Ninja Block, Stop Ads Now, Ad Block Wonder, Ad Block Ghost). It replaces the four
previous repos (`blocklist`, `blocklist-v2`, `blocklist-v3`, `whitelist-domains`) and the two
server-side generators (`generate_compiled_rules.php`, `generate_cosmetic_rules.php`).

Full design, diagrams and rationale: **Ninja List Atlas** (sections 08–09)
https://claude.ai/code/artifact/6291c622-79d0-4fd5-b269-0ad6174ab0d1

## The one principle

**Inputs are filed by origin, mirrored verbatim. Curation is its own layer, per source,
inspectable. Outputs are filed by role. Feeds before merges.**

```
sources/    ALL upstream inputs, filed by origin, VERBATIM: gsheet/ (Sheets A–O) ·
            easylist/ · hosts/ · traffic_quality/ (Sheet B pre-split per market) ·
            extension/ (fleet reports, whitelists live + blocklists reserved)
sanitized/  the CURATED sources (2026-09-08) — machine-owned, written only by
            build/curate/curate.php, committed so every curation decision is a git diff:
            extension/user-whitelist{-raw,}.json (fleet ≥50 → − omit-from-whitelist − omit-from-blocklist) · curation-set.json · download-sites.txt + download-sites/allow.json
            (omit-from-blocklist ∪ not-to-add ∪ download-sites ∪ userWL, the single derivation) · gsheet/popup.json · hosts/ ·
            easylist/ (curated DNR lanes + pass-through cosmetic)
curated/    break-glass hand-edited files only (vetoes.txt) — all normal human input = Sheets
state/      pipeline memory (domain-ledger.json) — machine-owned, never hand-edited
build/      ALL code (ingest / curate / verify / compile) — no code anywhere else
dist/       the public API — ONLY artifacts a consumer actually calls, plus derived/
            (compile helpers committed for inspection) and catalog/ (the à-la-carte layer,
            user decision 2026-09-10: per-source domains + per-type DNR rules at three
            stages raw/curated/merged, indexed by catalog.json) · one manifest.json
```

## The fifteen sheets

| Sheet | Mirror | Compiler contract |
|---|---|---|
| A · popup | `sources/gsheet/popup.json` | redirect rules (kept in its current pivot format); curated − (omit-from-blocklist ∪ not-to-add ∪ download-sites ∪ user whitelist) → `sanitized/gsheet/popup.json` |
| B · trackers | `sources/traffic_quality/` (split per market at ingest) | published untouched to `dist/traffic_quality/` — never merged into rules |
| C · default whitelist | `sources/gsheet/default-whitelist.json` | product-only: published as `dist/whitelist/default.json` (− omit-from-whitelist − omit-from-blocklist) — takes part in NO curation or scrub |
| D · default blocklist | `sources/gsheet/default-blocklist.json` | org default blocks, appended as block rules — ABOVE curation; floored only by omit-from-blocklist and default-blocklist-not-to-add |
| E · default blocklist not to add | `sources/gsheet/default-blocklist-not-to-add.json` | **NEW 2026-09-10** — the veto on the default blocklist: a listed domain produces NO rule at all. Curation-set member AND never-block floor (so it stops the appends too). Separate from omit-from-blocklist, which stays locked to own-brand domains. **Live since 2026-09-10** (gid 866107718, tab `blocklist_but_do_not_add`, 21 rows) |
| F · manual whitelist | `sources/gsheet/manual-whitelist.json` | mirrored; part of NO recipe for now (user decision 2026-09-08: role to be decided) |
| G · manual blocklist | `sources/gsheet/manual-blocklist.json` | block rules appended, like D |
| H · omit from whitelist | `sources/gsheet/omit-from-whitelist.json` | EXACT host, four consumers: user-whitelist step 2 · download-sites veto · blanket upstream allows (`scrubGVetoAllows`) · compile's `$minusG` for whitelist/default.json |
| I · omit from blocklist | `sources/gsheet/omit-from-blocklist.json` | never-block floor — curation-set member (subtracted from every blocking source at curate) + append floor at compile (no dist artifact: own-brand domains are covered by the static self-vendor 99999 allows; the rest is server-to-server traffic DNR never sees) |
| J · download sites | `sources/gsheet/download-sites.json` | NEW 2026-09-08, dual role. ① curation-set member — subtracted from every blocking source at curate. ② a SOURCE: normalized (lowercase, strip protocol/path/port/www./trailing dot; invalid rows warn, never fail) − omit-from-whitelist − omit-from-blocklist → `sanitized/download-sites.txt` (ABP, overwritten each run, `@@||domain^$subdocument,stylesheet,font,xmlhttprequest,media,websocket,other`) → DNR allow lane (priority 50 since 2026-09-11, was 2 — above blocks AND redirects AND the extension's bundled static rulesets (10/11/40/41), which the old 2 could not reach; below the client user tier; subdocument→sub_frame, websocket/other never dropped). Guards: `$document` / `$~third-party` / non-`@@` line = build failure; compile re-validates the lane, PINS its priority to `DL_ALLOW_PRIORITY` (`build/compile/lib/util.php`, exact equality — a drift back to 2 fails the build) and asserts min-allow-prio > max-block-prio over the whole merge |
| K–O · standalone | `whitelisted-domains-injection-enabled` · `tracking-whitelist` · `allow-request-domains` · `initiator-allowed-domains` · `rule101xtra` | mirrored + published as on-demand JSON — never merged into any generated ruleset |

## Order of operations (the four-stage pipeline, 2026-09-08)

0. **Ingest (upstream)** — verbatim mirrors current (fail-closed: bad fetch ⇒ keep previous)
1. **Curate** — `build/curate/curate.php` → `sanitized/`, per-source recipes (there is no
   monolithic whitelist anymore — different curation per source):
   - user whitelist = fleet votes ≥ 50 *(step 1)* − omit-from-whitelist *(step 2)* − omit-from-blocklist *(step 2b)*
   - **curation set = omit-from-blocklist ∪ default-blocklist-not-to-add ∪ download-sites ∪ user whitelist** (domain + subdomains)
   - Sheet A − set · hosts lanes − set · easylist DNR lanes scrubbed on every block axis;
     allows follow the SELF-PROTECTION policy (allows on curated destinations/initiators
     kept — they only ever protect those sites; mixed batches strip curated members);
     cosmetic passes through uncurated
   - download-sites (Sheet J) is ALSO a source: normalized − omit-from-whitelist − omit-from-blocklist → `sanitized/download-sites.txt` (ABP) →
     its DNR allow lane (sub-resource unbreakage on the download sites, priority 50)
   - Sheet C takes no part (product-only) · Sheets D/G + fleet blocklist stay ABOVE curation
     (vetoed only by omit-from-blocklist and by Sheet E `default-blocklist-not-to-add`)
2. **Verify** — tiered DNS over the sanitized candidates (no skip rules left: the ledger
   tests exactly what can ship)
3. **Compile = assembly** — sanitized lanes → veto (`curated/vetoes.txt`) · never-block floor +
   curation guards · appends D + manual-blocklist + fleet-BL (floored only by omit-from-blocklist + not-to-add, conflicts flagged) ·
   band re-ID · DNR budgets · staged writes → `dist/` + `manifest.json`
4. **Catalog** — `build/catalog/catalog.php` (compile.yml step, after a green compile) →
   `dist/catalog/`: every source in two representations (domains.json + DNR rules split
   per action type, per-file IDs 1..N) at three stages — `raw/` (pre-curation, inspection
   only, NEVER shippable as-is) · `curated/` (the sanitized recipes, safe standalone) ·
   `merged/` (per-action subsets of rules.json keeping the canonical band IDs + domain
   rollups; the canonical merge stays `network/rules.json`, never duplicated) — indexed,
   with counts and per-cell notes, by `dist/catalog/catalog.json`

## Cold start — regenerating everything from a data-free clone

The initial commit ships **no data**: no mirrors, no snapshots, no ledger, no dist. Every
stage is fail-closed, so the order matters — a stage run before its inputs exist turns red
and touches nothing (that's the design, not a bug):

1. `ingest.yml` (or `php build/ingest/fetch_sheets.php` + `fetch_upstreams.php`) — mirrors
   the 15 sheets, 24 market files, 4 hosts + 59 EasyList snapshots. First run: the
   shrink/delta guards auto-skip (no previous mirror to compare against).
2. `extension.yml` (or `fetch_extension_whitelists.php`) — pulls the 4 backend whitelist
   exports. Needs the `USER_WHITELIST_DOMAINS` secret (locally: the env var).
2b. `curate.yml` (or `php build/curate/curate.php`) — needs the mirrors + fleet CSV;
   builds `sanitized/` (user whitelist, curation set, curated lanes). Verify and compile
   read ONLY sanitized data, so this must be green before either of them can run.
3. `verify.yml` (or `php build/verify/ledger.php`) — no ledger file ⇒ self-seeding run:
   every candidate starts `n`(ever-tested) and the backlog drains across daily runs under
   `MAX_TESTS`. Until it drains, compile ships not-yet-tested domains (innocent until
   proven dead) — expect the shipped set to shrink over the first few days.
4. `compile.yml` (or `php build/compile/compile.php`) — requires ALL of the above; the
   change-budget gate auto-skips (no previous manifest).
5. `php build/review/shadow_diff.php <path to production compiled_rules_cache.json>` —
   the cutover gate.

## Status

Phase 2 (compile + shadow diff) — source layer, curation stage, ledger and compile are all
written and live-tested locally; see `STATUS.md` for the per-file map. One
`php build/curate/curate.php && php build/compile/compile.php`
publishes the whole `dist/` tree (10,287 rules at 2026-09-10, byte-deterministic, budgets asserted) and
`php build/review/shadow_diff.php <production cache>` is the cutover gate — currently
**clear: 0 unexplained divergences** vs the Aug 2 production cache.

dist/ as-built (2026-09-10, only called artifacts): `network/rules.json` (extension) ·
`network/rules-{hosts,easylist}.json` (by-origin subsets, canonical IDs — hosts 60 · easylist 10,175) ·
`whitelist/` — default.json (backend sync) · community.json · download-sites.json ·
`blocklist/` — popup-curated.json (the redirect lane as a flat list) · popup.json (Sheet A's
shipped share) · `cosmetic/` (4 files) · `traffic_quality/` (per-market) · `standalone/`
(Sheets K–O) · `derived/` (community + to-filter-out-domains-set — inspection helpers) · `catalog/`
(the à-la-carte layer, 2026-09-10: 117 files + catalog.json, ~71 MB) · `manifest.json`.

Decisions locked 2026-09-07: `dist/` is published **as commits**; the fleet fetches it
**via the backend mirrors** (raw GitHub only as fallback). Workflows activate on push:
ingest (0 */12) → curate (after every green ingest/extension) → verify (00:30) →
extension (06:00) → compile (07:00 + after every green curate). (The previous generation's
reference YAMLs were removed 2026-09-08 — they live in the legacy repo clones.)
