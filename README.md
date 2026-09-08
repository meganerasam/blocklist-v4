# Automated All-In-One List V2

The single factory repo for every blocklist and whitelist consumed by the ad-block extension
family (Ninja Block, Stop Ads Now, Ad Block Wonder, Ad Block Ghost). It replaces the four
previous repos (`blocklist`, `blocklist-v2`, `blocklist-v3`, `whitelist-domains`) and the two
server-side generators (`generate_compiled_rules.php`, `generate_cosmetic_rules.php`).

Full design, diagrams and rationale: **Ninja List Atlas** (sections 08–09)
https://claude.ai/code/artifact/6291c622-79d0-4fd5-b269-0ad6174ab0d1

## The one principle

**Inputs are filed by origin. Outputs are filed by role. Feeds before merges.**

```
sources/    ALL inputs, filed by origin: gsheet/ (Sheets A–M) · easylist/ · hosts/ ·
            traffic_quality/ (Sheet B pre-split per market) · extension/ (fleet reports,
            whitelists live + blocklists reserved)
curated/    break-glass hand-edited files only (vetoes.txt) — all normal human input = Sheets
state/      pipeline memory (domain-ledger.json) — machine-owned, never hand-edited
build/      ALL code (ingest / verify / compile) — no code anywhere else
dist/       the public API — ONLY artifacts a consumer actually calls, plus derived/
            (compile helpers committed for inspection) · one manifest.json
```

## The thirteen sheets

| Sheet | Mirror | Compiler contract |
|---|---|---|
| A · popup | `sources/gsheet/popup.json` | redirect rules (kept in its current pivot format) |
| B · trackers | `sources/gsheet/traffic-quality-trackers.json` | published untouched to `dist/traffic_quality/` — never merged into rules |
| C · default whitelist | `sources/gsheet/default-whitelist.json` | excluded conditions on every block rule + easylist/hosts scrub |
| D · default blocklist | `sources/gsheet/default-blocklist.json` | org default blocks, appended as block rules |
| E · manual whitelist | `sources/gsheet/manual-whitelist.json` | same dual treatment as C |
| F · manual blocklist | `sources/gsheet/manual-blocklist.json` | block rules appended, like D |
| G · omit from whitelist | `sources/gsheet/omit-from-whitelist.json` | subtracted from the exclusion set at assembly |
| H · omit from blocklist | `sources/gsheet/omit-from-blocklist.json` | never-block floor — drops block rules from every source at compile time (no dist artifact: own-brand domains are covered by the static self-vendor 99999 allows; the rest is server-to-server traffic DNR never sees) |
| I–M · standalone | `whitelisted-domains-injection-enabled` · `tracking-whitelist` · `allow-request-domains` · `initiator-allowed-domains` · `rule101xtra` | mirrored + published as on-demand JSON — never merged into any generated ruleset |

## Order of operations (one compile)

0. Ingest — all mirrors current (fail-closed: bad fetch ⇒ keep previous dist)
1. **Exclusion set = (C ∪ E ∪ fleet community[votes ≥ 200]) − G** — built before anything else
2. Verify (tiered DNS via `state/domain-ledger.json`, exclusion set subtracted first)
3. Generate raw rules per source (internal lanes — nothing per-source is published)
4. Whitelist enforcement pass (scrub easylist/hosts rules + excluded conditions)
5. Append explicit blocks (Sheets D + F + fleet blocklists) — after the pass, never scrubbed
6. Omit pass (H) · veto (`curated/vetoes.txt`) · re-ID · merge → `dist/` + `manifest.json`

## Cold start — regenerating everything from a data-free clone

The initial commit ships **no data**: no mirrors, no snapshots, no ledger, no dist. Every
stage is fail-closed, so the order matters — a stage run before its inputs exist turns red
and touches nothing (that's the design, not a bug):

1. `ingest.yml` (or `php build/ingest/fetch_sheets.php` + `fetch_upstreams.php`) — mirrors
   the 13 sheets, 21 market files, 4 hosts + 59 EasyList snapshots. First run: the
   shrink/delta guards auto-skip (no previous mirror to compare against).
2. `extension.yml` (or `fetch_extension_whitelists.php`) — pulls the 4 backend whitelist
   exports. Needs the `USER_WHITELIST_DOMAINS` secret (locally: the env var).
3. `verify.yml` (or `php build/verify/ledger.php`) — no ledger file ⇒ self-seeding run:
   every candidate starts `n`(ever-tested) and the backlog drains across daily runs under
   `MAX_TESTS`. Until it drains, compile ships not-yet-tested domains (innocent until
   proven dead) — expect the shipped set to shrink over the first few days.
4. `compile.yml` (or `php build/compile/compile.php`) — requires ALL of the above; the
   change-budget gate auto-skips (no previous manifest).
5. `php build/review/shadow_diff.php <path to production compiled_rules_cache.json>` —
   the cutover gate.

## Status

Phase 2 (compile + shadow diff) — source layer, ledger and compile are all written and
live-tested locally; see `STATUS.md` for the per-file map. One `php build/compile/compile.php`
publishes the whole `dist/` tree (10,147 rules, byte-deterministic, budgets asserted) and
`php build/review/shadow_diff.php <production cache>` is the cutover gate — currently
**clear: 0 unexplained divergences** vs the Aug 2 production cache.

dist/ as-built (2026-09-08, only called artifacts): `network/rules.json` (extension) ·
`whitelist/default.json` (backend sync) · `cosmetic/` (4 files) · `traffic_quality/`
(per-market) · `standalone/` (Sheets I–M) · `derived/` (community ≥200 vote set +
exclusion-set — compile helpers, called by nothing) · `manifest.json`.

Decisions locked 2026-09-07: `dist/` is published **as commits**; the fleet fetches it
**via the backend mirrors** (raw GitHub only as fallback). Workflows activate on push:
ingest (0 */12) → verify (00:30) → extension (06:00) → compile (07:00 + after every green
ingest). (The previous generation's reference YAMLs were removed 2026-09-08 — they live in the
legacy repo clones.)
