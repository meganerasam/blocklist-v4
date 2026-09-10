<?php
// build/compile/compile.php — one compile: ASSEMBLY of the sanitized sources.
//
// Since the curation re-conception (2026-09-08 evening) all per-source subtraction
// happens in build/curate/curate.php, which publishes the sanitized/ tree. Compile
// consumes sanitized/ and never re-derives a whitelist:
//
//   ① curation set — READ from sanitized/curation-set.json (omit-from-blocklist ∪ not-to-add
//      the single derivation; used here only for carve-outs, twin-initiator stripping,
//      retention-leak guards and the final asserts). Sheet C stays PRODUCT-ONLY: it
//      ∪ download-sites ∪ user whitelist). Sheet C ships as whitelist/default.json
//      (− both omit sheets) and takes no part in any subtraction.
//   ② ledger read — dead domains (st = 'd') never ship; sheets are never modified
//   ③ lanes from sanitized/: gsheet/popup.json · hosts/<tag>.txt · easylist/<cat>/
//      DNR lanes (already curated; cosmetic passed through uncurated)
//   ④ policy pass: veto (curated/vetoes.txt) · H floor guards — H is a compile-time
//      floor ONLY: own-brand domains are protected client-side by the static
//      self-vendor allow rules at priority 99999, and the rest of Sheet H is
//      server-to-server traffic DNR never sees — verified 2026-09-08, so no
//      never-block artifact ships
//   ⑤ append explicit blocks (Sheets D + manual-blocklist + fleet blocklists) — ABOVE curation, never
//      scrubbed (only the never-block floor = omit-from-blocklist ∪ Sheet E); conflicts are FLAGGED, not
//      silently resolved
//   ⑥ merge → dist/network/rules.json — re-ID into the production bands, assert DNR
//      budgets, keep __EXT_ID__ placeholders — then cosmetic, whitelist, traffic_quality,
//      standalone, derived/ helpers, manifest.json
//
// dist/ contract (2026-09-08): ONLY what a consumer actually calls is published —
//   network/rules.json (extension) · whitelist/default.json (backend sync) · cosmetic/ ·
//   traffic_quality/ · standalone/ (Sheets K–O) — plus derived/ (community.json,
//   curation-set.json): compile helpers committed for inspection, called by nothing.
//
// Fail-closed doctrine: every artifact is computed and every assertion passes BEFORE the
// first byte lands in dist/ (staged writes, tmp+rename). A failed run leaves the previous
// dist/ untouched and exits non-zero.
//
// Env: COMPILE_FORCE=1  — override the change-budget gate (the confirming re-run)
//      GITHUB_STEP_SUMMARY — markdown report appended when set; always echoed

declare(strict_types=1);
ini_set('memory_limit', '3072M');

$ROOT = dirname(__DIR__, 2);
require __DIR__ . '/lib/util.php';
require __DIR__ . '/lib/scrub.php';

const CHUNK = 5000;                       // domains per batched DNR rule (production value)
const SUB_RESOURCE_TYPES = ['script', 'xmlhttprequest', 'sub_frame', 'image', 'media'];
const REDIRECT_SUBSTITUTION = 'chrome-extension://__EXT_ID__/pages/popup-tracker.html?url=\0';
// Unified ID bands (production generate_compiled_rules.php; IDs < 11000 stay reserved
// for the server's inline sync rules).
const ID_BANDS = [
    'redirect'         => [11000, 21000],
    'block'            => [21000, 31000],
    'modifyHeaders'    => [31000, 41000],
    'allow'            => [41000, 51000],
    'allowAllRequests' => [51000, 91000],
    '_unknown'         => [91000, 100000],
];
const BUDGET_TOTAL_RULES  = 30000;        // Chrome dynamic-rule cap (121+)
const BUDGET_UNSAFE_RULES = 5000;         // redirect + modifyHeaders cap
const BUDGET_REGEX_RULES  = 1000;         // regexFilter rule cap
const GATE_RULES_DELTA_PCT   = 30;        // change-budget gate vs previous manifest
const GATE_DOMAIN_DROP_PCT   = 20;
// The fleet trust bar (COMMUNITY_MIN_VOTES) lives in build/curate/curate.php — the only
// place the user whitelist and curation set are derived; compile just reads sanitized/.

$FORCE = getenv('COMPILE_FORCE') === '1';
$t0 = microtime(true);
$report = [];        // markdown lines for the step summary
$review = [];        // state/review/compile-drops.json payload

function fail(string $msg): void
{
    fwrite(STDERR, "FATAL: $msg\n");
    $md = "# Compile — FAILED\n\n**$msg**\n\nPrevious dist/ kept (fail-closed).\n";
    echo $md;
    if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
        file_put_contents($sum, $md, FILE_APPEND);
    }
    exit(1);
}

/** Mirror loader: file must exist and be a JSON array of strings. */
function load_mirror(string $path, string $label, bool $mustBeNonEmpty): array
{
    if (!is_file($path)) fail("$label mirror missing: $path");
    $arr = json_decode((string) file_get_contents($path), true);
    if (!is_array($arr)) fail("$label mirror is not a JSON array: $path");
    $out = [];
    foreach ($arr as $row) {
        if (!is_string($row)) fail("$label mirror has a non-string row: $path");
        $row = rtrim(strtolower(trim($row)), '.');   // trailing dot would dodge every set match
        if ($row !== '') $out[] = $row;
    }
    if ($mustBeNonEmpty && !$out) fail("$label mirror is empty: $path");
    return $out;
}

// ============================================================================
// ① INPUTS — compile-side mirrors + the sanitized curation products
// ============================================================================
$omitWhitelist  = load_mirror("$ROOT/sources/gsheet/omit-from-whitelist.json",  'Sheet H (omit-from-whitelist)', false);
$defaultWhitelist  = load_mirror("$ROOT/sources/gsheet/default-whitelist.json",    'Sheet C', true);
$omitBlocklist  = load_mirror("$ROOT/sources/gsheet/omit-from-blocklist.json",  'Sheet I (omit-from-blocklist)', true);
$defaultBlocklist  = load_mirror("$ROOT/sources/gsheet/default-blocklist.json",    'Sheet D', true);
$manualBlocklist  = load_mirror("$ROOT/sources/gsheet/manual-blocklist.json",     'Sheet G (manual-blocklist)', false);
$fleetBLPath = "$ROOT/sources/extension/blocklist/user-extension-blocklist.json";
$fleetBL = is_file($fleetBLPath) ? load_mirror($fleetBLPath, 'Fleet blocklist', false) : [];

// The sanitized layer — build/curate/curate.php is the ONLY writer. The curation set is
// read, never re-derived; compile uses it for carve-outs, twin-initiator stripping,
// retention-leak guards and the final asserts.
$SAN = "$ROOT/sanitized";
if (!is_dir($SAN)) fail('sanitized/ missing — run build/curate/curate.php first');
// Provenance gate (2026-09-08, adversarial review): sanitized/ must have been built from
// the CURRENT mirrors. Mirrors that moved since the last green curate (a red ingest still
// commits per-sheet successes but skips curate) = a mixed generation — never publish it.
$prov = json_decode((string) @file_get_contents("$SAN/provenance.json"), true);
if (!is_array($prov) || !$prov) fail('sanitized/provenance.json missing/invalid — run build/curate/curate.php');
foreach ($prov as $rel => $sha) {
    $cur = is_file("$ROOT/$rel") ? hash_file('sha256', "$ROOT/$rel") : 'MISSING';
    if ($cur !== $sha) {
        fail("sanitized/ is STALE vs $rel — the mirror moved since the last curate; run build/curate/curate.php first");
    }
}
$curationList = load_mirror("$SAN/curation-set.json", 'curation set (sanitized)', true);
$curation = [];
foreach ($curationList as $d) $curation[$d] = true;
$userWL = load_mirror("$SAN/extension/user-whitelist.json", 'user whitelist (sanitized)', true);
$popupSheetRows = load_mirror("$SAN/gsheet/popup.json", 'Sheet A (sanitized)', true);
// Sheet E — default-blocklist-not-to-add (2026-09-10, user decision). Same contract as
// omit-from-blocklist: curation-set member (handled in curate) AND part of the never-block
// floor here, which is what actually vetoes the Sheet D / manual-blocklist / fleet appends —
// those sit ABOVE curation, so curation-set membership alone would not stop them.
// Live since 2026-09-10; the absent-mirror path stays as a fail-soft fallback.
$noAddPath = "$ROOT/sources/gsheet/default-blocklist-not-to-add.json";
$noAdd = is_file($noAddPath) ? load_mirror($noAddPath, 'Sheet E (default-blocklist-not-to-add)', false) : [];
$never = [];
foreach ($omitBlocklist as $d) $never[$d] = true;      // Sheet I: never-block floor, domain + subdomains
foreach ($noAdd as $d)         $never[$d] = true;      // Sheet E: same floor, freely editable list

// Download-sites allow lane (Sheet I as a SOURCE, user spec 2026-09-08): the compiler
// VERIFIES the contract the curate stage promises before merging a single rule —
//   · action is allow, priority strictly above every block (blocks are priority 1)
//   · resourceTypes contain ONLY the mapped sub-resource set (subdocument→sub_frame,
//     websocket/other included — a lane that lost them fails, never ships narrowed)
//   · ||domain^ anchor form; no main_frame ($document-class) coverage can ever appear
$DL_LANE_TYPES = ['font', 'media', 'other', 'stylesheet', 'sub_frame', 'websocket', 'xmlhttprequest'];
$dlLanePath = "$SAN/download-sites/allow.json";
if (!is_file($dlLanePath)) fail('sanitized download-sites lane missing (run build/curate/curate.php): ' . $dlLanePath);
$dlAllow = json_decode((string) file_get_contents($dlLanePath), true);
if (!is_array($dlAllow)) fail('download-sites lane is not valid JSON: ' . $dlLanePath);
// The domain list is harvested from this same validation pass — never re-derived from the
// sheet — so dist/whitelist/download-sites.json can only ever contain domains that
// actually cleared every guard below (normalized, G-vetoed, ||domain^ anchored).
$dlSiteDomains = [];
foreach ($dlAllow as $i => $r) {
    if (($r['action']['type'] ?? '') !== 'allow') fail("download-sites lane rule #$i: action is not allow");
    if ((int) ($r['priority'] ?? 0) <= 1) fail("download-sites lane rule #$i: priority must be strictly above blocks (>1)");
    $types = $r['condition']['resourceTypes'] ?? [];
    if (!is_array($types) || !$types) fail("download-sites lane rule #$i: resourceTypes missing");
    if (array_diff($types, $DL_LANE_TYPES)) {
        fail("download-sites lane rule #$i: unexpected resourceTypes " . implode(',', array_diff($types, $DL_LANE_TYPES)));
    }
    if (count(array_unique($types)) !== count($DL_LANE_TYPES)) {
        fail("download-sites lane rule #$i: resourceTypes narrowed to " . implode(',', $types) . ' — websocket/other-class types must never be dropped');
    }
    $uf = (string) ($r['condition']['urlFilter'] ?? '');
    if (!preg_match('/^\|\|[a-z0-9.-]+\^$/', $uf)) fail("download-sites lane rule #$i: urlFilter is not a ||domain^ anchor: $uf");
    $dlSiteDomains[substr($uf, 2, -1)] = true;      // ||domain^ -> domain
}
$dlSiteDomains = array_keys($dlSiteDomains);
sort($dlSiteDomains, SORT_STRING);
if (!$dlSiteDomains) fail('download-sites lane yielded no domains — lane corrupted?');

$vetoes = [];
foreach (file("$ROOT/curated/vetoes.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    $line = trim($line);
    if ($line !== '' && $line[0] !== '#') $vetoes[] = strtolower($line);
}
if (!$vetoes) fail('curated/vetoes.txt yielded no patterns — file corrupted?');

// ============================================================================
// ② LEDGER — the dead never ship (and only what ships is filtered; sheets stay)
// ============================================================================
$ledgerRaw = json_decode((string) @file_get_contents("$ROOT/state/domain-ledger.json"), true);
if (!is_array($ledgerRaw) || !$ledgerRaw) fail('state/domain-ledger.json missing or invalid');
$dead = [];
$ledgerAlive = ['anudeep' => [], 'peterlowe' => [], 'adguarddns' => [], 'kadhosts' => []];
foreach ($ledgerRaw as $d => $r) {
    if (($r['st'] ?? '') === 'd') { $dead[$d] = true; continue; }
    // policy retention (replaces v2's last-50k slice): a hosts-lane domain keeps shipping
    // while it still resolves and the ledger still remembers its listing — the ledger's
    // purge rules (dead+delisted 180 d · delisted 365 d) put the 12-month bound on this.
    foreach ($r['s'] ?? [] as $tag) {
        if (isset($ledgerAlive[$tag])) $ledgerAlive[$tag][$d] = true;
    }
}
unset($ledgerRaw);

// ============================================================================
// ③ LANES — everything already generated + curated by build/curate/curate.php
// ============================================================================
$CATS = ['adult', 'easylist', 'easyprivacy', 'fanboy'];
// The generators (build/compile/<cat>/...) now run inside the CURATE stage; their
// curated DNR lanes and pass-through cosmetic outputs live under sanitized/easylist/.
$WORK = "$SAN/easylist";
function work_json(string $path): array
{
    if (!is_file($path)) fail('expected sanitized lane missing (run build/curate/curate.php): ' . $path);
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) fail('sanitized lane is not valid JSON: ' . $path);
    return $data;
}

/** The v3 merge order: allow/network · allow/popup · block/domains · block/popup ·
 *  block/urlfilter — each kind concatenated across the four categories. */
function merge_category_dnr(string $work, array $cats): array
{
    $kinds = [
        ['allow', 'network.json'], ['allow', 'popup.json'],
        ['block', 'domains.json'], ['block', 'popup.json'], ['block', 'urlfilter.json'],
    ];
    $merged = [];
    foreach ($kinds as [$folder, $file]) {
        foreach ($cats as $cat) {
            foreach (work_json("$work/$cat/$folder/$file") as $rule) {
                $merged[] = $rule;
            }
        }
    }
    return $merged;
}

function reid_sequential(array $rules): array
{
    $id = 1;
    foreach ($rules as &$rule) $rule['id'] = $id++;
    unset($rule);
    return $rules;
}

// ---- Sheet A (popup role): normalize like production short.php, dead-filter ----
$sheetADead = [];
$popupSheet = [];
foreach ($popupSheetRows as $row) {
    $rawClean = clean_domain($row);                    // ledger keyed on this form
    if ($rawClean !== null && isset($dead[$rawClean])) { $sheetADead[] = $row; continue; }
    $norm = normalize_domain($row);
    if ($norm === '' || $norm === 'grand total') continue;
    $popupSheet[$norm] = true;
}
ksort($popupSheet, SORT_STRING);

// ---- hosts lanes: sanitized (already curated), dead-filter here ----
$HOSTS = [
    'anudeep'    => "$SAN/hosts/anudeep.txt",
    'peterlowe'  => "$SAN/hosts/peterlowe.txt",
    'adguarddns' => "$SAN/hosts/adguarddns.txt",
    'kadhosts'   => "$SAN/hosts/kadhosts.txt",
];
$hostsFeeds = [];
$hostsDeadDropped = [];
$hostsRetained = [];
$hostsRetainedCurated = 0;
foreach ($HOSTS as $tag => $path) {
    $all = load_hosts_file($path);
    if (!$all) fail("sanitized hosts lane empty/missing (run build/curate/curate.php): $path");
    $kept = [];
    $droppedDead = 0;
    foreach ($all as $d => $_) {
        if (isset($dead[$d])) { $droppedDead++; continue; }
        $kept[$d] = true;
    }
    // retention: delisted-but-alive ledger domains for this lane keep shipping.
    // These re-adds BYPASS the curate stage (they come from the ledger, not a snapshot),
    // so the curation set must hold right here.
    $retained = 0;
    foreach ($ledgerAlive[$tag] as $d => $_) {
        if (isset($kept[$d])) continue;
        if (isWhitelistCovered($d, $curation)) { $hostsRetainedCurated++; continue; }
        $kept[$d] = true;
        $retained++;
    }
    ksort($kept, SORT_STRING);
    $hostsFeeds[$tag] = $kept;
    $hostsDeadDropped[$tag] = $droppedDead;
    $hostsRetained[$tag] = $retained;
}

// ============================================================================
// ④ POLICY PASS — veto → dist/network/ (curation already happened upstream)
// ============================================================================
// filters.json — the surgical EasyList DNR, pre-curated by curate.php; only the
// break-glass veto applies here. The download-sites allow lane (validated above) joins
// the surgical population — the veto only ever drops blocks, so it passes through.
$filters = merge_category_dnr($WORK, $CATS);
foreach ($dlAllow as $r) $filters[] = $r;
$vetoed = 0;
$filters = array_values(array_filter($filters, function ($rule) use ($vetoes, &$vetoed) {
    if (($rule['action']['type'] ?? 'block') !== 'block') return true;
    $hay = strtolower((string)($rule['condition']['urlFilter'] ?? '')
         . ' ' . (string)($rule['condition']['regexFilter'] ?? ''));
    foreach ($vetoes as $needle) {
        if ($needle !== '' && strpos($hay, $needle) !== false) { $vetoed++; return false; }
    }
    return true;
}));
$filters = reid_sequential($filters);

// popup.json — Sheet A + KADhosts as redirect rules (the popup/scam role)
$popupExcluded = [];
$popupDomains = [];
$popupNeverDropped = 0;
// Lanes arrive pre-curated; these checks are GUARDS against what bypasses curate
// (ledger retention re-adds, normalization edge cases) — expect counts near zero.
foreach ([array_keys($popupSheet), array_keys($hostsFeeds['kadhosts'])] as $lane) {
    foreach ($lane as $d) {
        if (isWhitelistCovered($d, $never)) { $popupNeverDropped++; continue; }   // H floor
        if (isWhitelistCovered($d, $curation)) { $popupExcluded[$d] = true; continue; }
        $popupDomains[$d] = true;
    }
}
// Sheet A's own contribution to the shipped lane — derived by intersecting with the very
// map the redirect rules are built from, so blocklist/popup.json is a guaranteed subset of
// blocklist/popup-curated.json (and of rules.json) rather than a parallel re-derivation.
$popupSheetShipped = [];
foreach (array_keys($popupSheet) as $d) if (isset($popupDomains[$d])) $popupSheetShipped[] = $d;
sort($popupSheetShipped, SORT_STRING);

$popupDomains = array_keys($popupDomains);
sort($popupDomains, SORT_STRING);
$popupExcluded = array_keys($popupExcluded);
sort($popupExcluded, SORT_STRING);

$carveSet = $curation + $never;   // carve-outs protect curated + never-block subdomains
$popupRules = [];
foreach (array_chunk($popupDomains, CHUNK) as $domains) {
    $cond = [
        'regexFilter'    => '^http.+',
        'requestDomains' => $domains,
        'resourceTypes'  => ['main_frame'],
    ];
    $carve = carve_for_chunk($domains, $carveSet);
    if ($carve) $cond['excludedRequestDomains'] = $carve;
    $popupRules[] = [
        'id'       => 0,
        'priority' => 3,
        'action'   => ['type' => 'redirect', 'redirect' => ['regexSubstitution' => REDIRECT_SUBSTITUTION]],
        'condition' => $cond,
    ];
}
$popupRules = reid_sequential($popupRules);

// domains.json — the tracker/ad hosts lanes, minus what EasyList already blocks broadly
$easylistCovered = [];
foreach ($filters as $rule) {
    if (($rule['action']['type'] ?? '') !== 'block') continue;
    $cond = $rule['condition'] ?? [];
    $extra = array_diff(array_keys($cond), ['requestDomains', 'excludedRequestDomains']);
    if ($extra) continue;                       // only broad, unconditional domain blocks count
    foreach ($cond['requestDomains'] ?? [] as $d) $easylistCovered[strtolower($d)] = true;
}
$trackerStats = ['excl' => 0, 'never' => 0, 'covered' => 0];
$trackerDomains = [];
foreach (['adguarddns', 'anudeep', 'peterlowe'] as $tag) {
    foreach ($hostsFeeds[$tag] as $d => $_) {
        if (isWhitelistCovered($d, $never))          { $trackerStats['never']++;   continue; }
        if (isWhitelistCovered($d, $curation))       { $trackerStats['excl']++;    continue; }
        if (covered_subdomain($d, $easylistCovered)) { $trackerStats['covered']++; continue; }
        $trackerDomains[$d] = true;
    }
}
$trackerDomains = array_keys($trackerDomains);
sort($trackerDomains, SORT_STRING);

$domainRules = [];
foreach (array_chunk($trackerDomains, CHUNK) as $domains) {
    $carve = carve_for_chunk($domains, $carveSet);
    $blockCond = ['resourceTypes' => SUB_RESOURCE_TYPES, 'requestDomains' => $domains];
    if ($carve) $blockCond['excludedRequestDomains'] = $carve;
    $domainRules[] = [
        'id' => 0, 'priority' => 1,
        'action' => ['type' => 'block'],
        'condition' => $blockCond,
    ];
    $redirCond = ['regexFilter' => '^http.+', 'requestDomains' => $domains, 'resourceTypes' => ['main_frame']];
    if ($carve) $redirCond['excludedRequestDomains'] = $carve;
    $domainRules[] = [
        'id' => 0, 'priority' => 3,
        'action' => ['type' => 'redirect', 'redirect' => ['regexSubstitution' => REDIRECT_SUBSTITUTION]],
        'condition' => $redirCond,
    ];
}
$domainRules = reid_sequential($domainRules);

// ============================================================================
// ⑤ APPENDS — Sheets D + manual-blocklist + fleet blocklists, AFTER the pass, never scrubbed
// ============================================================================
$appendAll = [];
foreach ([$defaultBlocklist, $manualBlocklist, $fleetBL] as $src) foreach ($src as $d) $appendAll[$d] = true;
$appendConflicts = [];       // deliberate block vs whitelist — flagged, never silent
$appendShipped = [];
$appendNeverDropped = 0;
foreach ($appendAll as $d => $_) {
    if (isWhitelistCovered($d, $never)) { $appendNeverDropped++; continue; }  // H outranks all
    if (isWhitelistCovered($d, $curation)) $appendConflicts[] = $d;
    $appendShipped[$d] = true;
}
$appendShipped = array_keys($appendShipped);
sort($appendShipped, SORT_STRING);
sort($appendConflicts, SORT_STRING);
// The other conflict direction: a curated domain living UNDER an append domain —
// requestDomains matches subdomains, appends carve only against H, so the block wins.
// Deliberate-block-outranks-whitelist is the design; silence is not. Flag it.
$appendParentOverrides = carve_for_chunk($appendShipped, $curation);

$appendRules = [];
foreach (array_chunk($appendShipped, CHUNK) as $domains) {
    $carve = carve_for_chunk($domains, $never);     // only H carves appends — excl never does
    $cond = ['resourceTypes' => SUB_RESOURCE_TYPES, 'requestDomains' => $domains];
    if ($carve) $cond['excludedRequestDomains'] = $carve;
    $appendRules[] = ['id' => 0, 'priority' => 1, 'action' => ['type' => 'block'], 'condition' => $cond];
}
$appendRules = reid_sequential($appendRules);

// ============================================================================
// ⑥ MERGE + RE-ID + BUDGETS → rules.json
// ============================================================================
$idCounters = [];
foreach (ID_BANDS as $type => [$startId, $limit]) $idCounters[$type] = $startId;
$assignId = function (string $type) use (&$idCounters) {
    if (!isset($idCounters[$type])) $type = '_unknown';
    $id = $idCounters[$type]++;
    if ($id >= ID_BANDS[$type][1]) {
        fail("ID band overflow: '$type' crossed " . ID_BANDS[$type][1]
           . ' — the band scheme needs widening before this can ship');
    }
    return $id;
};

$rules = [];
foreach ($popupRules as $rule) {
    $rule['id'] = $assignId('redirect');
    $rules[] = $rule;
}
foreach ($domainRules as $rule) {
    $rule['id'] = $assignId($rule['action']['type']);
    $rules[] = $rule;
}
$dupAsRedirect = 0;
$dupInitStripped = 0;
$dupSkippedWhitelisted = 0;
foreach ($filters as $rule) {
    $type = $rule['action']['type'] ?? 'block';
    $rule['id'] = $assignId($type);
    if ($type === 'block') {
        $rule['priority'] = 1;
        if (!isset($rule['condition'])) $rule['condition'] = [];
        // Domain-level main_frame-only blocks are duplicated as redirect rules —
        // production behavior: the navigation lands on the extension's blocked page.
        // 2026-09-08: the twin CANNOT carry the source rule's urlFilter (regexSubstitution
        // needs a regexFilter), so an initiator-scoped twin redirects EVERY navigation
        // from those pages — a whitelisted/never-block site must never be widened into
        // that (the live pornhub breakage this fixes; production rule 11018 still has it).
        // Whitelist-covered initiators are stripped; a twin left with no scope is skipped.
        $hasReq  = isset($rule['condition']['requestDomains'])   && is_array($rule['condition']['requestDomains']);
        $hasInit = isset($rule['condition']['initiatorDomains']) && is_array($rule['condition']['initiatorDomains']);
        if (($hasReq || $hasInit) && ($rule['condition']['resourceTypes'] ?? null) === ['main_frame']) {
            $keptInit = [];
            if ($hasInit) {
                foreach ($rule['condition']['initiatorDomains'] as $d) {
                    if (isWhitelistCovered(strtolower((string) $d), $carveSet)) { $dupInitStripped++; continue; }
                    $keptInit[] = $d;
                }
            }
            // 2026-09-08 (adversarial review): if the source rule was initiator-scoped and
            // EVERY initiator is curation-covered, the twin must be SKIPPED — building it
            // from requestDomains alone would silently WIDEN it to navigations from every
            // site (and still hijack the curated initiator's own navigations).
            if ($hasInit && !$keptInit) {
                $dupSkippedWhitelisted++;
            } elseif ($hasReq || $keptInit) {
                $redirCond = ['regexFilter' => '^http.+', 'resourceTypes' => ['main_frame']];
                if ($hasReq)   $redirCond['requestDomains']   = $rule['condition']['requestDomains'];
                if ($keptInit) $redirCond['initiatorDomains'] = $keptInit;
                if (isset($rule['condition']['excludedRequestDomains'])) {
                    $redirCond['excludedRequestDomains'] = $rule['condition']['excludedRequestDomains'];
                }
                $rules[] = [
                    'id' => $assignId('redirect'), 'priority' => 3,
                    'action' => ['type' => 'redirect', 'redirect' => ['regexSubstitution' => REDIRECT_SUBSTITUTION]],
                    'condition' => $redirCond,
                ];
                $dupAsRedirect++;
            }
        }
    }
    $rules[] = $rule;
}
foreach ($appendRules as $rule) {
    $rule['id'] = $assignId('block');
    $rules[] = $rule;
}

// Final-pass safety asserts: H floor, veto, and the redirect-initiator guarantee
// must hold over the WHOLE merge, whatever produced the rule.
foreach ($rules as $rule) {
    $type = $rule['action']['type'] ?? '';
    if ($type !== 'block' && $type !== 'redirect') continue;
    foreach ($rule['condition']['requestDomains'] ?? [] as $d) {
        if (isWhitelistCovered(strtolower($d), $never)) {
            fail("never-block violation survived the merge: $d (rule {$rule['id']})");
        }
    }
    if ($type === 'redirect') {
        // a curated site's navigation may never be hijacked — the twin builder
        // strips these, this assert makes sure nothing else can ever emit one
        foreach ($rule['condition']['initiatorDomains'] ?? [] as $d) {
            $ld = strtolower((string) $d);
            if (isWhitelistCovered($ld, $curation) || isWhitelistCovered($ld, $never)) {
                fail("curation-covered initiator survived on redirect rule {$rule['id']}: $d");
            }
        }
    }
    // same guarantee for generic-pattern main_frame BLOCKS: with no destination scope
    // they can match the whitelisted site's own navigation (ABP $popup over-breadth)
    if ($type === 'block'
        && !isset($rule['condition']['requestDomains'])
        && in_array('main_frame', $rule['condition']['resourceTypes'] ?? [], true)
        && !(isset($rule['condition']['urlFilter']) && strpos($rule['condition']['urlFilter'], '||') === 0)) {
        foreach ($rule['condition']['initiatorDomains'] ?? [] as $d) {
            $ld = strtolower((string) $d);
            if (isWhitelistCovered($ld, $curation) || isWhitelistCovered($ld, $never)) {
                fail("curation-covered initiator survived on generic main_frame block {$rule['id']}: $d");
            }
        }
    }
    if ($type === 'block') {
        $hay = strtolower((string)($rule['condition']['urlFilter'] ?? '')
             . ' ' . (string)($rule['condition']['regexFilter'] ?? ''));
        foreach ($vetoes as $needle) {
            if ($needle !== '' && strpos($hay, $needle) !== false) {
                fail("vetoed pattern survived the merge: $needle (rule {$rule['id']})");
            }
        }
    }
    // The urlFilter-ANCHOR axis (2026-09-08, adversarial review): a || anchor matches at
    // every subdomain boundary, so a block anchored on (or wildcard-covering) a curated
    // domain reaches it even with no requestDomains. Every curated domain reachable
    // through an anchor must be carved via excludedRequestDomains — mirror of the scrub.
    if ($type === 'block'
        && isset($rule['condition']['urlFilter'])
        && strpos($rule['condition']['urlFilter'], '||') === 0
        && preg_match('/^\|\|([a-z0-9.-]+)/i', $rule['condition']['urlFilter'], $mA)) {
        $anchorRaw = strtolower($mA[1]);
        $anchor    = trim($anchorRaw, '.');
        $exSet = [];
        foreach ($rule['condition']['excludedRequestDomains'] ?? [] as $x) $exSet[strtolower($x)] = true;
        $isWild = substr($rule['condition']['urlFilter'], 2 + strlen($mA[1]), 1) === '*'
               && str_ends_with($anchorRaw, '.');
        if ($isWild) {
            foreach ($curation as $w => $_) {
                $hit = str_starts_with($w, $anchorRaw);
                if (!$hit) {
                    foreach (domainAncestors($w) as $anc) {
                        if (str_starts_with($anc, $anchorRaw)) { $hit = true; break; }
                    }
                }
                if ($hit && !isWhitelistCovered($w, $exSet)) {
                    fail("curation-covered domain reachable via wildcard block anchor (rule {$rule['id']}, {$rule['condition']['urlFilter']}): $w");
                }
            }
        } else {
            if (isWhitelistCovered($anchor, $curation)) {
                fail("block anchor is curation-covered (rule {$rule['id']}): {$rule['condition']['urlFilter']}");
            }
            foreach ($curation as $w => $_) {
                if (in_array($anchor, domainAncestors($w), true) && !isWhitelistCovered($w, $exSet)) {
                    fail("curation-covered domain under block anchor without carve (rule {$rule['id']}, anchor $anchor): $w");
                }
            }
        }
    }
}

// Sheet C is product-only: it never scrubs, but a served-whitelist domain that still
// ships as a block/redirect target is a CONTRADICTION between two dist artifacts
// (rules.json vs whitelist/default.json) — flagged, never silently resolved. The
// redirect-INITIATOR axis is called out separately: a redirect scoped to a C-covered
// initiator would hijack EVERY navigation from a default-whitelisted site, the one
// axis a request-level client whitelist cannot counter (pornhub-class breakage).
$cSet = [];
foreach ($defaultWhitelist as $d) $cSet[$d] = true;
$cShippedBlock = $cShippedRedirect = $cHijackInitiators = [];
foreach ($rules as $rule) {
    $type = $rule['action']['type'] ?? '';
    if ($type !== 'block' && $type !== 'redirect') continue;
    foreach ($rule['condition']['requestDomains'] ?? [] as $d) {
        $ld = strtolower($d);
        if (isWhitelistCovered($ld, $cSet)) {
            if ($type === 'block') $cShippedBlock[$ld] = true;
            else                   $cShippedRedirect[$ld] = true;
        }
    }
    if ($type === 'redirect') {
        foreach ($rule['condition']['initiatorDomains'] ?? [] as $d) {
            $ld = strtolower((string) $d);
            if (isWhitelistCovered($ld, $cSet)) $cHijackInitiators[$rule['id'] . ' ' . $ld] = true;
        }
    }
}
$cShippedBlock = array_keys($cShippedBlock);
sort($cShippedBlock, SORT_STRING);
$cShippedRedirect = array_keys($cShippedRedirect);
sort($cShippedRedirect, SORT_STRING);
$cHijackInitiators = array_keys($cHijackInitiators);
sort($cHijackInitiators, SORT_STRING);

// Allow must outrank block EVERYWHERE (user guarantee 2026-09-08): a block that ties or
// beats an allow on priority would re-block the traffic the allows exist to protect
// (DNR resolves equal priority in the allow's favor, but "strictly above" is the contract).
$maxBlockPrio = 0;
$minAllowPrio = PHP_INT_MAX;
foreach ($rules as $rule) {
    $p = (int) ($rule['priority'] ?? 1);
    $t = $rule['action']['type'] ?? '';
    if ($t === 'block') $maxBlockPrio = max($maxBlockPrio, $p);
    elseif ($t === 'allow') $minAllowPrio = min($minAllowPrio, $p);
}
if ($minAllowPrio !== PHP_INT_MAX && $minAllowPrio <= $maxBlockPrio) {
    fail("allow/block priority inversion: min allow priority $minAllowPrio ≤ max block priority $maxBlockPrio");
}

// DNR budgets — growth may never brick clients silently.
$byAction = [];
$regexRules = 0;
foreach ($rules as $rule) {
    $type = $rule['action']['type'] ?? '?';
    $byAction[$type] = ($byAction[$type] ?? 0) + 1;
    if (isset($rule['condition']['regexFilter'])) $regexRules++;
}
$totalRules  = count($rules);
$unsafeRules = ($byAction['redirect'] ?? 0) + ($byAction['modifyHeaders'] ?? 0);
if ($totalRules > BUDGET_TOTAL_RULES)   fail("DNR budget: $totalRules rules > " . BUDGET_TOTAL_RULES);
if ($unsafeRules > BUDGET_UNSAFE_RULES) fail("DNR budget: $unsafeRules redirect/modifyHeaders > " . BUDGET_UNSAFE_RULES);
if ($regexRules > BUDGET_REGEX_RULES)   fail("DNR budget: $regexRules regexFilter rules > " . BUDGET_REGEX_RULES);

// ============================================================================
// COSMETIC — generic.css union + specific/extended/unhide maps
// ============================================================================
$allSelectors = [];
foreach ($CATS as $cat) {
    $path = "$WORK/$cat/css/generic.css";
    if (!is_file($path)) continue;                    // only easylist + fanboy ship cosmetics
    $content = preg_replace('!/\*.*?\*/!s', '', (string) file_get_contents($path));
    if (strpos($content, '{') === false) continue;
    // generators join selectors with ",\n" — splitting on that (not bare ',') keeps
    // selectors that legitimately contain commas (:is(a, b), [title="a,b"]) intact
    foreach (explode(",\n", substr($content, 0, strpos($content, '{'))) as $sel) {
        $sel = trim($sel);
        if ($sel !== '') $allSelectors[$sel] = true;
    }
}
if (!$allSelectors) fail('cosmetic merge produced zero generic selectors');
$selectorsList = array_keys($allSelectors);
sort($selectorsList);
$genericCss = "/*\n * generic.css — EasyList-family generic element hiding\n"
    . " * Generated by build/compile/compile.php — do not edit\n */\n\n"
    . implode(",\n", $selectorsList) . " {\n  display: none !important;\n}\n";

function merge_css_maps(string $work, array $cats, string $folder, string $file): array
{
    $merged = [];
    foreach ($cats as $cat) {
        $path = "$work/$cat/$folder/$file";
        if (!is_file($path)) continue;
        $data = json_decode((string) file_get_contents($path), true);
        if (!is_array($data)) fail("cosmetic input is not valid JSON: $path");
        foreach ($data as $domain => $items) {
            $merged[$domain] = array_merge($merged[$domain] ?? [], $items);
        }
    }
    foreach ($merged as &$items) {
        $seen = [];
        $unique = [];
        foreach ($items as $item) {
            $key = is_string($item) ? $item : json_encode($item);
            if (!isset($seen[$key])) { $seen[$key] = true; $unique[] = $item; }
        }
        $items = $unique;
    }
    unset($items);
    ksort($merged);
    return $merged;
}
$cssSpecific = merge_css_maps($WORK, $CATS, 'css', 'specific.json');
$cssExtended = merge_css_maps($WORK, $CATS, 'css', 'extended.json');
$cssUnhide   = merge_css_maps($WORK, $CATS, 'allow', 'unhide.json');

// ============================================================================
// WHITELIST + TRAFFIC_QUALITY + NEVER-BLOCK ARTIFACTS
// ============================================================================
// − G − H (H added 2026-09-09: vetoed everywhere G is). G is exact-host, H is domain +
// all subdomains — each keeps the semantics it has everywhere else in the pipeline.
$neverSet = [];
foreach ($omitBlocklist as $h) $neverSet[$h] = true;
$minusG = function (array $list) use ($omitWhitelist, $neverSet): array {
    $set = [];
    foreach ($list as $d) $set[$d] = true;
    foreach ($omitWhitelist as $g) unset($set[$g]);          // same exact-host veto as user-WL step 2
    foreach (array_keys($set) as $d) {
        if (isWhitelistCovered($d, $neverSet)) unset($set[$d]);
    }
    $out = array_keys($set);
    sort($out, SORT_STRING);
    return $out;
};
$wlDefault   = $minusG($defaultWhitelist);                      // Sheet C as a product — the only SERVED
                                                 // whitelist (backend sync); C∩G is empty
                                                 // today, so the vetoes are standing hooks
$wlCommunity = $userWL;                          // = sanitized user whitelist (≥50, − both omits),
sort($wlCommunity, SORT_STRING);                 //   derived once, in curate.php
$curationOut = $curationList;
sort($curationOut, SORT_STRING);

$tqDir = "$ROOT/sources/traffic_quality";
$tqFiles = [];
foreach (glob("$tqDir/*.json") ?: [] as $path) {
    $tqFiles[basename($path)] = (string) file_get_contents($path);
}
if (!$tqFiles) fail('sources/traffic_quality/ has no market files');

// Sheets J–N: standalone, published as on-demand JSON, never merged (mirror bytes verbatim)
$STANDALONE = ['whitelisted-domains-injection-enabled', 'tracking-whitelist',
               'allow-request-domains', 'initiator-allowed-domains', 'rule101xtra'];
$standaloneFiles = [];
foreach ($STANDALONE as $name) {
    $path = "$ROOT/sources/gsheet/$name.json";
    $content = (string) @file_get_contents($path);
    if ($content === '' || !is_array(json_decode($content, true))) fail("standalone mirror invalid: $path");
    $standaloneFiles[$name] = $content;
}

// ============================================================================
// CHANGE-BUDGET GATE — an upstream poisoning can never ship on autopilot
// ============================================================================
$shippedBlockDomains = count(array_unique(array_merge($popupDomains, $trackerDomains, $appendShipped)));
$prevManifest = is_file("$ROOT/dist/manifest.json")
    ? json_decode((string) file_get_contents("$ROOT/dist/manifest.json"), true)
    : null;
$gateNotes = [];
if (is_array($prevManifest) && isset($prevManifest['counts']['network_rules_total'], $prevManifest['counts']['shipped_block_domains'])) {
    $prevRules   = (int) $prevManifest['counts']['network_rules_total'];
    $prevDomains = (int) $prevManifest['counts']['shipped_block_domains'];
    if ($prevRules > 0) {
        $deltaPct = abs($totalRules - $prevRules) / $prevRules * 100;
        if ($deltaPct > GATE_RULES_DELTA_PCT) {
            $msg = sprintf('change gate: rule count moved %.1f%% (%d → %d), limit %d%%',
                $deltaPct, $prevRules, $totalRules, GATE_RULES_DELTA_PCT);
            if (!$FORCE) fail($msg . ' — re-run with COMPILE_FORCE=1 to confirm');
            $gateNotes[] = "FORCED past: $msg";
        }
    }
    if ($prevDomains > 0 && $shippedBlockDomains < $prevDomains) {
        $dropPct = ($prevDomains - $shippedBlockDomains) / $prevDomains * 100;
        if ($dropPct > GATE_DOMAIN_DROP_PCT) {
            $msg = sprintf('change gate: shipped domains dropped %.1f%% (%d → %d), limit %d%%',
                $dropPct, $prevDomains, $shippedBlockDomains, GATE_DOMAIN_DROP_PCT);
            if (!$FORCE) fail($msg . ' — re-run with COMPILE_FORCE=1 to confirm');
            $gateNotes[] = "FORCED past: $msg";
        }
    }
}

// ============================================================================
// STAGED WRITE-OUT — everything passed; now (and only now) touch dist/
// ============================================================================
$artifacts = [];   // rel path => ['content' => string, 'count' => ?int]
$stage = function (string $rel, string $content, ?int $count) use (&$artifacts) {
    $artifacts[$rel] = ['content' => $content, 'count' => $count];
};

$stage('network/rules.json',        json_out($rules, false), $totalRules);
$stage('whitelist/default.json',    json_out($wlDefault, true), count($wlDefault));
// whitelist/ now carries the three whitelist flavours side by side (2026-09-09), so a
// consumer reads one folder instead of three: the org default (Sheet C − both omits), the fleet
// list (votes ≥ bar, − both omits) and the download sites (normalized + vetoed — NOT the raw sheet,
// whose www. rows would never match). community.json is byte-identical to
// derived/community.json — same variable, staged twice on purpose; derived/ stays the
// inspection surface, whitelist/ is the product surface.
// The popup/redirect lane as a flat domain array (2026-09-09, user request). Same
// $popupDomains the redirect rules are chunked from a few lines below, so the file and
// rules.json can never disagree: Sheet A ∪ kadhosts, − ledger dead, − H, − curation set.
// This is the POST-ledger list — what actually ships. The pre-ledger curated halves stay
// in sanitized/gsheet/popup.json and sanitized/hosts/kadhosts.json.
$stage('blocklist/popup-curated.json',  json_out($popupDomains, true), count($popupDomains));
// Sheet A alone, as SHIPPED (2026-09-09, user decision): same ledger + H + curation
// filtering as the merged lane, so it is a strict subset of popup-curated.json. The
// pre-ledger forms stay upstream — sources/gsheet/popup.json (raw sheet) and
// sanitized/gsheet/popup.json (− curation set).
$stage('blocklist/popup.json',          json_out($popupSheetShipped, true), count($popupSheetShipped));
$stage('whitelist/community.json',      json_out($wlCommunity, true), count($wlCommunity));
$stage('whitelist/download-sites.json', json_out($dlSiteDomains, true), count($dlSiteDomains));
$stage('derived/community.json',    json_out($wlCommunity, true), count($wlCommunity));
$stage('derived/curation-set.json', json_out($curationOut, true), count($curationOut));

$stage('cosmetic/generic.css',     $genericCss, count($selectorsList));
$stage('cosmetic/specific.json',   json_out($cssSpecific, true), count($cssSpecific));
$stage('cosmetic/extended.json',   json_out($cssExtended, true), count($cssExtended));
$stage('cosmetic/unhide.json',     json_out($cssUnhide, true), count($cssUnhide));

foreach ($tqFiles as $name => $content) {
    $stage("traffic_quality/$name", $content, null);
}
foreach ($standaloneFiles as $name => $content) {
    $stage("standalone/$name.json", $content, null);
}

// manifest: content-derived version — identical inputs produce an identical manifest
$manifestArtifacts = [];
foreach ($artifacts as $rel => $a) {
    $manifestArtifacts[$rel] = [
        'sha256' => hash('sha256', $a['content']),
        'bytes'  => strlen($a['content']),
    ];
    if ($a['count'] !== null) $manifestArtifacts[$rel]['count'] = $a['count'];
}
ksort($manifestArtifacts);
$version = hash('sha256', json_out(array_map(fn ($a) => $a['sha256'], $manifestArtifacts), false));
$generatedAt = (is_array($prevManifest) && ($prevManifest['version'] ?? '') === $version)
    ? ($prevManifest['generated_at'] ?? gmdate('c'))   // unchanged content -> unchanged file
    : gmdate('c');
$manifest = [
    'schema'       => 1,
    'version'      => $version,
    'generated_at' => $generatedAt,
    'counts'       => [
        'network_rules_total'   => $totalRules,
        'network_rules_by_action' => $byAction,
        'unsafe_rules'          => $unsafeRules,
        'regex_rules'           => $regexRules,
        'shipped_block_domains' => $shippedBlockDomains,
        'curation_set'          => count($curation),
    ],
    'budgets'      => [
        'total_rules'  => BUDGET_TOTAL_RULES,
        'unsafe_rules' => BUDGET_UNSAFE_RULES,
        'regex_rules'  => BUDGET_REGEX_RULES,
    ],
    'artifacts'    => $manifestArtifacts,
];

foreach ($artifacts as $rel => $a) {
    atomic_write("$ROOT/dist/$rel", $a['content']);
}
// Prune managed dist dirs: anything not staged this run is stale (a delisted market,
// a retired artifact) and must not keep shipping. static-rulesets/ is not managed —
// it is a reserved slot pending its own decision.
$managedDirs = ['network', 'whitelist', 'blocklist', 'cosmetic', 'traffic_quality', 'standalone', 'derived', 'feeds', 'popup'];
foreach ($managedDirs as $dir) {
    $base = "$ROOT/dist/$dir";
    if (!is_dir($base)) continue;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $p = $f->getPathname();
        if ($f->isDir()) { @rmdir($p); continue; }        // removes dirs emptied below
        $rel = substr($p, strlen("$ROOT/dist/"));
        if (!isset($artifacts[$rel])) unlink($p);
    }
    @rmdir($base);                                        // fully-retired dir disappears
}
atomic_write("$ROOT/dist/manifest.json", json_out($manifest, true) . "\n");

// review artifact — decisions belong in the Sheets, never in this file.
// No timestamp on purpose: unchanged content must not churn a commit every run.
$review = [
    'sheet_a_dead_dropped'    => $sheetADead,
    'popup_excluded_by_whitelist' => $popupExcluded,
    'append_vs_whitelist_conflicts' => $appendConflicts,
    'append_parent_overrides' => $appendParentOverrides,
    'default_whitelist_vs_shipped' => [
        'note' => 'Sheet C is product-only (2026-09-08): these whitelist/default.json-covered'
            . ' domains ship as rule targets anyway; only client-side enforcement protects them.'
            . ' redirect_initiators would hijack every navigation FROM a default-whitelisted'
            . ' site — the axis a request-level client whitelist cannot counter. Resolutions'
            . ' belong in the Sheets (or in the client), never here.',
        'block_targets'       => $cShippedBlock,
        'redirect_targets'    => $cShippedRedirect,
        'redirect_initiators' => $cHijackInitiators,
    ],
];
atomic_write("$ROOT/state/review/compile-drops.json", json_out($review, true) . "\n");

// ============================================================================
// REPORT
// ============================================================================
$elapsed = round(microtime(true) - $t0, 1);
$rep = [];
$rep[] = '# Compile — ' . gmdate('Y-m-d H:i') . " UTC · {$elapsed}s" . ($FORCE ? ' · **FORCED**' : '');
$rep[] = '';
$rep[] = '| stage | result |';
$rep[] = '|---|---|';
$rep[] = '| ① curation set (sanitized/) | ' . count($curation) . ' domains (omit-from-blocklist ∪ not-to-add ∪ download-sites ∪ userWL — derived by curate.php) · user whitelist ' . count($wlCommunity) . ' · C product-only: ' . count($wlDefault) . ' → whitelist/default.json |';
$rep[] = '| ② ledger dead set | ' . count($dead) . ' domains never ship |';
$feedCell = 'sheet-A ' . count($popupSheet) . ' (dead −' . count($sheetADead) . ')';
foreach (['kadhosts', 'adguarddns', 'anudeep', 'peterlowe'] as $tag) {
    $feedCell .= " · $tag " . count($hostsFeeds[$tag])
        . ' (dead −' . $hostsDeadDropped[$tag] . ' · retained +' . $hostsRetained[$tag] . ')';
}
$rep[] = '| ③ lanes (internal) | ' . $feedCell . ' |';
$rep[] = '| ④ guards (post-curation leaks: retention re-adds, edge cases) | popup lane: curation ' . count($popupExcluded) . ' · H ' . $popupNeverDropped . ' · domains lane: curation ' . $trackerStats['excl'] . ' · H ' . $trackerStats['never'] . ' · retention blocked by curation: ' . $hostsRetainedCurated . ' · appends H −' . $appendNeverDropped . ' |';
$rep[] = '| ④ veto (curated/vetoes.txt) | ' . $vetoed . ' block rules dropped |';
$rep[] = '| ④ popup lane | ' . count($popupDomains) . ' domains → ' . count($popupRules) . ' redirect rules |';
$rep[] = '| ④ domains lane | ' . count($trackerDomains) . ' domains → ' . count($domainRules) . ' rules (easylist-covered −' . $trackerStats['covered'] . ') |';
$rep[] = '| ⑤ appends (D + G + fleet-BL) | ' . count($appendShipped) . ' domains → ' . count($appendRules) . ' rules · H −' . $appendNeverDropped . ' · **conflicts vs whitelist: ' . count($appendConflicts) . '** · **whitelisted subdomains overridden by an append parent: ' . count($appendParentOverrides) . '** |';
$rep[] = '| ⑥ rules.json | **' . $totalRules . ' rules** (' . implode(' · ', array_map(fn ($k, $v) => "$k $v", array_keys($byAction), $byAction)) . ') · main-frame dup→redirect ' . $dupAsRedirect . ' (whitelisted initiators stripped ' . $dupInitStripped . ' · twins skipped ' . $dupSkippedWhitelisted . ') |';
$rep[] = '| ⑥ download-sites allow lane | ' . count($dlAllow) . ' rules merged (validated: allow · priority>blocks · full 7-type map incl. websocket/other) · global assert: min allow prio ' . ($minAllowPrio === PHP_INT_MAX ? '—' : $minAllowPrio) . ' > max block prio ' . $maxBlockPrio . ' |';
$rep[] = '| ⑥ C (product-only) vs shipped | block targets ' . count($cShippedBlock) . ' · redirect targets ' . count($cShippedRedirect) . ' · **redirect initiators (navigation hijack): ' . count($cHijackInitiators) . '** |';
$rep[] = '| budgets | total ' . $totalRules . '/' . BUDGET_TOTAL_RULES . ' · unsafe ' . $unsafeRules . '/' . BUDGET_UNSAFE_RULES . ' · regex ' . $regexRules . '/' . BUDGET_REGEX_RULES . ' |';
$rep[] = '| shipped block domains | ' . $shippedBlockDomains . ' |';
$rep[] = '| manifest version | `' . substr($version, 0, 12) . '…` |';
foreach ($gateNotes as $note) $rep[] = '| ⚠ change gate | ' . $note . ' |';
if ($appendConflicts) {
    $rep[] = '';
    $rep[] = '**Append ∩ curation set** (deliberate block kept — review): '
        . implode(', ', array_slice($appendConflicts, 0, 30))
        . (count($appendConflicts) > 30 ? ' … +' . (count($appendConflicts) - 30) : '');
}
if ($appendParentOverrides) {
    $rep[] = '';
    $rep[] = '**Whitelisted domains blocked via an append PARENT** (deliberate block wins — review): '
        . implode(', ', array_slice($appendParentOverrides, 0, 30))
        . (count($appendParentOverrides) > 30 ? ' … +' . (count($appendParentOverrides) - 30) : '');
}
if ($cHijackInitiators) {
    $rep[] = '';
    $rep[] = '**Sheet C domains as redirect INITIATORS — every navigation from these default-whitelisted sites is hijacked, client whitelist cannot counter this axis** ('
        . count($cHijackInitiators) . '): '
        . implode(', ', array_slice($cHijackInitiators, 0, 30))
        . (count($cHijackInitiators) > 30 ? ' … +' . (count($cHijackInitiators) - 30) : '');
}
if ($sheetADead) {
    $rep[] = '';
    $rep[] = '**Sheet A dead (ledger) — not shipped** (' . count($sheetADead) . '): '
        . implode(', ', array_slice($sheetADead, 0, 30))
        . (count($sheetADead) > 30 ? ' … +' . (count($sheetADead) - 30) : '');
}
$rep[] = '';
$rep[] = 'Full drop lists: `state/review/compile-drops.json`';
$md = implode("\n", $rep) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit(0);
