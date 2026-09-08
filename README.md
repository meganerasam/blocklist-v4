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
sources/    ALL upstream inputs, filed by origin, VERBATIM: gsheet/ (Sheets A–N) ·
            easylist/ · hosts/ · traffic_quality/ (Sheet B pre-split per market) ·
            extension/ (fleet reports, whitelists live + blocklists reserved)
sanitized/  the CURATED sources (2026-09-08) — machine-owned, written only by
            build/curate/curate.php, committed so every curation decision is a git diff:
            extension/user-whitelist{-raw,}.json (fleet ≥50 → −G) · curation-set.json
            (H ∪ I ∪ userWL, the single derivation) · gsheet/popup.json · hosts/ ·
            easylist/ (curated DNR lanes + pass-through cosmetic)
curated/    break-glass hand-edited files only (vetoes.txt) — all normal human input = Sheets
state/      pipeline memory (domain-ledger.json) — machine-owned, never hand-edited
build/      ALL code (ingest / curate / verify / compile) — no code anywhere else
dist/       the public API — ONLY artifacts a consumer actually calls, plus derived/
            (compile helpers committed for inspection) · one manifest.json
```

## The fourteen sheets

| Sheet | Mirror | Compiler contract |
|---|---|---|
| A · popup | `sources/gsheet/popup.json` | redirect rules (kept in its current pivot format); curated − (H ∪ I ∪ user whitelist) → `sanitized/gsheet/popup.json` |
| B · trackers | `sources/gsheet/traffic-quality-trackers.json` | published untouched to `dist/traffic_quality/` — never merged into rules |
| C · default whitelist | `sources/gsheet/default-whitelist.json` | product-only: published as `dist/whitelist/default.json` (−G) — takes part in NO curation or scrub (2026-09-08) |
| D · default blocklist | `sources/gsheet/default-blocklist.json` | org default blocks, appended as block rules — ABOVE curation, only H floors them |
| E · manual whitelist | `sources/gsheet/manual-whitelist.json` | mirrored; part of NO recipe for now (user decision 2026-09-08: role to be decided) |
| F · manual blocklist | `sources/gsheet/manual-blocklist.json` | block rules appended, like D |
| G · omit from whitelist | `sources/gsheet/omit-from-whitelist.json` | step-2 veto on the user whitelist (EXACT host) — gamed fleet votes die here |
| H · omit from blocklist | `sources/gsheet/omit-from-blocklist.json` | never-block floor — curation-set member (subtracted from every blocking source at curate) + append floor at compile (no dist artifact: own-brand domains are covered by the static self-vendor 99999 allows; the rest is server-to-server traffic DNR never sees) |
| I · download sites | `sources/gsheet/download-sites.json` | NEW 2026-09-08, dual role. ① curation-set member — subtracted from every blocking source at curate. ② a SOURCE: normalized (lowercase, strip protocol/path/port/www./trailing dot; invalid rows warn, never fail) − G → `sanitized/download-sites.txt` (ABP, overwritten each run, `@@||domain^$subdocument,stylesheet,font,xmlhttprequest,media,websocket,other`) → DNR allow lane (priority 2, subdocument→sub_frame, websocket/other never dropped). Guards: `$document` / `$~third-party` / non-`@@` line = build failure; compile re-validates the lane and asserts allow priority strictly above every block |
| J–N · standalone | `whitelisted-domains-injection-enabled` · `tracking-whitelist` · `allow-request-domains` · `initiator-allowed-domains` · `rule101xtra` | mirrored + published as on-demand JSON — never merged into any generated ruleset |

## Order of operations (the four-stage pipeline, 2026-09-08)

0. **Ingest (upstream)** — verbatim mirrors current (fail-closed: bad fetch ⇒ keep previous)
1. **Curate** — `build/curate/curate.php` → `sanitized/`, per-source recipes (there is no
   monolithic whitelist anymore — different curation per source):
   - user whitelist = fleet votes ≥ 50 *(step 1)* − Sheet G *(step 2)*
   - **curation set = H ∪ I (download sites) ∪ user whitelist** (domain + subdomains)
   - Sheet A − set · hosts lanes − set · easylist DNR lanes scrubbed on every block axis;
     allows follow the SELF-PROTECTION policy (allows on curated destinations/initiators
     kept — they only ever protect those sites; mixed batches strip curated members);
     cosmetic passes through uncurated
   - Sheet I is ALSO a source: normalized − G → `sanitized/download-sites.txt` (ABP) →
     its DNR allow lane (sub-resource unbreakage on the download sites, priority 2)
   - Sheet C takes no part (product-only) · Sheets D/F + fleet blocklist stay ABOVE curation
2. **Verify** — tiered DNS over the sanitized candidates (no skip rules left: the ledger
   tests exactly what can ship)
3. **Compile = assembly** — sanitized lanes → veto (`curated/vetoes.txt`) · H floor +
   curation guards · appends D + F + fleet-BL (only H floors them, conflicts flagged) ·
   band re-ID · DNR budgets · staged writes → `dist/` + `manifest.json`

## Cold start — regenerating everything from a data-free clone

The initial commit ships **no data**: no mirrors, no snapshots, no ledger, no dist. Every
stage is fail-closed, so the order matters — a stage run before its inputs exist turns red
and touches nothing (that's the design, not a bug):

1. `ingest.yml` (or `php build/ingest/fetch_sheets.php` + `fetch_upstreams.php`) — mirrors
   the 14 sheets, 24 market files, 4 hosts + 59 EasyList snapshots. First run: the
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
publishes the whole `dist/` tree (10,216 rules, byte-deterministic, budgets asserted) and
`php build/review/shadow_diff.php <production cache>` is the cutover gate — currently
**clear: 0 unexplained divergences** vs the Aug 2 production cache.

dist/ as-built (2026-09-08, only called artifacts): `network/rules.json` (extension) ·
`whitelist/default.json` (backend sync) · `cosmetic/` (4 files) · `traffic_quality/`
(per-market) · `standalone/` (Sheets J–N) · `derived/` (community: the sanitized user
whitelist ≥50 −G + curation-set — compile helpers, called by nothing) · `manifest.json`.

Decisions locked 2026-09-07: `dist/` is published **as commits**; the fleet fetches it
**via the backend mirrors** (raw GitHub only as fallback). Workflows activate on push:
ingest (0 */12) → curate (after every green ingest/extension) → verify (00:30) →
extension (06:00) → compile (07:00 + after every green curate). (The previous generation's
reference YAMLs were removed 2026-09-08 — they live in the legacy repo clones.)
