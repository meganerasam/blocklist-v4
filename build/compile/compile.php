<?php
// build/compile/compile.php — one compile, in the Atlas §08 order of operations.
//
//   ① exclusion set = (C ∪ E ∪ fleet community) − G   — built before ANY rule generation
//      (G matches EXACT host only; H, the never-block floor, matches domain + subdomains;
//       fleet community = all-extension.csv merged votes ≥ 200 — the ≥20-users/6-month
//       floor is only the backends' EXPORT contract, not the factory's trust bar)
//   ② ledger read — dead domains (st = 'd') never ship; sheets are never modified
//   ③ per-source generation → internal lanes (nothing per-source is published)
//   ④ whitelist enforcement pass over the lanes
//      (exclusion scrub + carve-outs · H omit · veto — H is a compile-time floor ONLY:
//       own-brand domains are protected client-side by the static self-vendor allow rules
//       at priority 99999, and the rest of Sheet H is server-to-server traffic DNR never
//       sees — verified 2026-09-08, so no never-block artifact ships)
//   ⑤ append explicit blocks (Sheets D + F + fleet blocklists) — after the pass, never
//      scrubbed; conflicts vs the exclusion set are FLAGGED, not silently resolved
//   ⑥ merge → dist/network/rules.json — re-ID into the production bands, assert DNR
//      budgets, keep __EXT_ID__ placeholders — then cosmetic, whitelist, traffic_quality,
//      standalone, derived/ helpers, manifest.json
//
// dist/ contract (2026-09-08): ONLY what a consumer actually calls is published —
//   network/rules.json (extension) · whitelist/default.json (backend sync) · cosmetic/ ·
//   traffic_quality/ · standalone/ (Sheets I–M) — plus derived/ (community.json,
//   exclusion-set.json): compile helpers committed for inspection, called by nothing.
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
const COMMUNITY_MIN_VOTES    = 200;       // fleet trust bar — keep in sync with ledger.php

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
// ① INPUTS + EXCLUSION SET — before any rule is generated
// ============================================================================
$G  = load_mirror("$ROOT/sources/gsheet/omit-from-whitelist.json",  'Sheet G', false);
$C  = load_mirror("$ROOT/sources/gsheet/default-whitelist.json",    'Sheet C', true);
$E  = load_mirror("$ROOT/sources/gsheet/manual-whitelist.json",     'Sheet E', false);
$H  = load_mirror("$ROOT/sources/gsheet/omit-from-blocklist.json",  'Sheet H', true);
$D  = load_mirror("$ROOT/sources/gsheet/default-blocklist.json",    'Sheet D', true);
$F  = load_mirror("$ROOT/sources/gsheet/manual-blocklist.json",     'Sheet F', false);
$A  = load_mirror("$ROOT/sources/gsheet/popup.json",                'Sheet A', true);
$fleetBLPath = "$ROOT/sources/extension/blocklist/user-extension-blocklist.json";
$fleetBL = is_file($fleetBLPath) ? load_mirror($fleetBLPath, 'Fleet blocklist', false) : [];

// Fleet community = merged fleet votes ≥ COMMUNITY_MIN_VOTES. The flat ≥20 export
// (user-extension-whitelist.json) stays an ingest product; the factory trusts counts.
$fleetCsv = "$ROOT/sources/extension/whitelist/raw/all-extension.csv";
if (!is_file($fleetCsv)) fail("fleet votes CSV missing: $fleetCsv");
$fleetWL = [];
foreach (array_slice(file($fleetCsv, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [], 1) as $line) {
    [$d, $c] = array_pad(explode(',', $line, 2), 2, '0');
    $d = rtrim(strtolower(trim($d)), '.');
    if ($d !== '' && (int) $c >= COMMUNITY_MIN_VOTES) $fleetWL[] = $d;
}
if (!$fleetWL) fail("fleet community empty — no domain reaches " . COMMUNITY_MIN_VOTES . " votes in $fleetCsv?");

$excl = [];
foreach ([$C, $E, $fleetWL] as $src) foreach ($src as $d) $excl[$d] = true;
foreach ($G as $g) unset($excl[$g]);       // G: EXACT host only — the editorial veto
if (!$excl) fail('exclusion set is empty — C/E/fleet mirrors broken?');
$never = [];
foreach ($H as $d) $never[$d] = true;      // H: never-block floor, domain + subdomains

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
// ③ PER-SOURCE GENERATION
// ============================================================================
$CATS = ['adult', 'easylist', 'easyprivacy', 'fanboy'];
$WORK = __DIR__ . '/.work';
// Stale outputs must never survive into a merge: a generator that dies after this point
// leaves a HOLE (which work_json turns into a hard fail), never last run's data.
if (is_dir($WORK)) {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($WORK, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) { $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname()); }
}
$GENERATORS = [];
foreach ($CATS as $cat) {
    $GENERATORS[] = "$cat/allow/generate_allow.php";
    $GENERATORS[] = "$cat/block/generate_dnr.php";
    if (is_file(__DIR__ . "/$cat/css/generate_css.php")) $GENERATORS[] = "$cat/css/generate_css.php";
}
foreach ($GENERATORS as $gen) {
    $out = [];
    $code = 1;
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . "/$gen") . ' 2>&1', $out, $code);
    if ($code !== 0) {
        fail("generator $gen exited $code:\n" . implode("\n", array_slice($out, -15)));
    }
}
function work_json(string $path): array
{
    if (!is_file($path)) fail('expected generator output missing: ' . $path);
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) fail('generator output is not valid JSON: ' . $path);
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
foreach ($A as $row) {
    $rawClean = clean_domain($row);                    // ledger keyed on this form
    if ($rawClean !== null && isset($dead[$rawClean])) { $sheetADead[] = $row; continue; }
    $norm = normalize_domain($row);
    if ($norm === '' || $norm === 'grand total') continue;
    $popupSheet[$norm] = true;
}
ksort($popupSheet, SORT_STRING);

// ---- hosts snapshots: parse, dead-filter ----
$HOSTS = [
    'anudeep'    => "$ROOT/sources/hosts/anudeep.txt",
    'peterlowe'  => "$ROOT/sources/hosts/peterlowe.txt",
    'adguarddns' => "$ROOT/sources/hosts/adguarddns.txt",
    'kadhosts'   => "$ROOT/sources/hosts/kadhosts.txt",
];
$hostsFeeds = [];
$hostsDeadDropped = [];
$hostsRetained = [];
foreach ($HOSTS as $tag => $path) {
    $all = load_hosts_file($path);
    if (!$all) fail("hosts snapshot empty/missing: $path");
    $kept = [];
    $droppedDead = 0;
    foreach ($all as $d => $_) {
        if (isset($dead[$d])) { $droppedDead++; continue; }
        $kept[$d] = true;
    }
    // retention: delisted-but-alive ledger domains for this lane keep shipping
    $retained = 0;
    foreach ($ledgerAlive[$tag] as $d => $_) {
        if (!isset($kept[$d])) { $kept[$d] = true; $retained++; }
    }
    ksort($kept, SORT_STRING);
    $hostsFeeds[$tag] = $kept;
    $hostsDeadDropped[$tag] = $droppedDead;
    $hostsRetained[$tag] = $retained;
}

// ============================================================================
// ④ POLICY PASS — exclusion scrub · H omit · veto → dist/network/
// ============================================================================
// filters.json — the surgical EasyList DNR, scrubbed
$scrubStats = ['domainsRemoved' => 0, 'rulesDropped' => 0, 'exclusionsAdded' => 0];
$hStats     = ['domainsRemoved' => 0, 'rulesDropped' => 0, 'exclusionsAdded' => 0];
$filters = scrubBlockRules(merge_category_dnr($WORK, $CATS), $excl, $scrubStats);
$filters = scrubBlockRules($filters, $never, $hStats);
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
foreach ([array_keys($popupSheet), array_keys($hostsFeeds['kadhosts'])] as $lane) {
    foreach ($lane as $d) {
        if (isWhitelistCovered($d, $never)) { $popupNeverDropped++; continue; }   // H floor
        if (isWhitelistCovered($d, $excl)) { $popupExcluded[$d] = true; continue; }
        $popupDomains[$d] = true;
    }
}
$popupDomains = array_keys($popupDomains);
sort($popupDomains, SORT_STRING);
$popupExcluded = array_keys($popupExcluded);
sort($popupExcluded, SORT_STRING);

$carveSet = $excl + $never;   // carve-outs protect both whitelisted + never-block subdomains
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
        if (isWhitelistCovered($d, $excl))           { $trackerStats['excl']++;    continue; }
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
// ⑤ APPENDS — Sheets D + F + fleet blocklists, AFTER the pass, never scrubbed
// ============================================================================
$appendAll = [];
foreach ([$D, $F, $fleetBL] as $src) foreach ($src as $d) $appendAll[$d] = true;
$appendConflicts = [];       // deliberate block vs whitelist — flagged, never silent
$appendShipped = [];
$appendNeverDropped = 0;
foreach ($appendAll as $d => $_) {
    if (isWhitelistCovered($d, $never)) { $appendNeverDropped++; continue; }  // H outranks all
    if (isWhitelistCovered($d, $excl)) $appendConflicts[] = $d;
    $appendShipped[$d] = true;
}
$appendShipped = array_keys($appendShipped);
sort($appendShipped, SORT_STRING);
sort($appendConflicts, SORT_STRING);
// The other conflict direction: a whitelisted domain living UNDER an append domain —
// requestDomains matches subdomains, appends carve only against H, so the block wins.
// Deliberate-block-outranks-whitelist is the design; silence is not. Flag it.
$appendParentOverrides = carve_for_chunk($appendShipped, $excl);

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
foreach ($filters as $rule) {
    $type = $rule['action']['type'] ?? 'block';
    $rule['id'] = $assignId($type);
    if ($type === 'block') {
        $rule['priority'] = 1;
        if (!isset($rule['condition'])) $rule['condition'] = [];
        // Domain-level main_frame-only blocks are duplicated as redirect rules —
        // production behavior: the navigation lands on the extension's blocked page.
        $hasReq  = isset($rule['condition']['requestDomains'])   && is_array($rule['condition']['requestDomains']);
        $hasInit = isset($rule['condition']['initiatorDomains']) && is_array($rule['condition']['initiatorDomains']);
        if (($hasReq || $hasInit) && ($rule['condition']['resourceTypes'] ?? null) === ['main_frame']) {
            $redirCond = ['regexFilter' => '^http.+', 'resourceTypes' => ['main_frame']];
            if ($hasReq)  $redirCond['requestDomains']   = $rule['condition']['requestDomains'];
            if ($hasInit) $redirCond['initiatorDomains'] = $rule['condition']['initiatorDomains'];
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
    $rules[] = $rule;
}
foreach ($appendRules as $rule) {
    $rule['id'] = $assignId('block');
    $rules[] = $rule;
}

// Final-pass safety asserts: H floor and veto must hold over the WHOLE merge.
foreach ($rules as $rule) {
    $type = $rule['action']['type'] ?? '';
    if ($type !== 'block' && $type !== 'redirect') continue;
    foreach ($rule['condition']['requestDomains'] ?? [] as $d) {
        if (isWhitelistCovered(strtolower($d), $never)) {
            fail("never-block violation survived the merge: $d (rule {$rule['id']})");
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
$minusG = function (array $list) use ($G): array {
    $set = [];
    foreach ($list as $d) $set[$d] = true;
    foreach ($G as $g) unset($set[$g]);          // same exact-host veto as the exclusion set
    $out = array_keys($set);
    sort($out, SORT_STRING);
    return $out;
};
$wlDefault   = $minusG($C);                      // the only SERVED whitelist (backend sync)
$wlCommunity = $minusG($fleetWL);                // derived/ helper — called by nothing
$exclusionOut = array_keys($excl);
sort($exclusionOut, SORT_STRING);

$tqDir = "$ROOT/sources/traffic_quality";
$tqFiles = [];
foreach (glob("$tqDir/*.json") ?: [] as $path) {
    $tqFiles[basename($path)] = (string) file_get_contents($path);
}
if (!$tqFiles) fail('sources/traffic_quality/ has no market files');

// Sheets I–M: standalone, published as on-demand JSON, never merged (mirror bytes verbatim)
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
$stage('derived/community.json',    json_out($wlCommunity, true), count($wlCommunity));
$stage('derived/exclusion-set.json', json_out($exclusionOut, true), count($exclusionOut));

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
        'exclusion_set'         => count($excl),
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
$managedDirs = ['network', 'whitelist', 'cosmetic', 'traffic_quality', 'standalone', 'derived', 'feeds', 'popup'];
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
$rep[] = '| ① exclusion set (C ∪ E ∪ fleet≥' . COMMUNITY_MIN_VOTES . ') − G | ' . count($excl) . ' domains (C ' . count($C) . ' · E ' . count($E) . ' · fleet≥' . COMMUNITY_MIN_VOTES . ' ' . count($fleetWL) . ' · G −' . count($G) . ') |';
$rep[] = '| ② ledger dead set | ' . count($dead) . ' domains never ship |';
$feedCell = 'sheet-A ' . count($popupSheet) . ' (dead −' . count($sheetADead) . ')';
foreach (['kadhosts', 'adguarddns', 'anudeep', 'peterlowe'] as $tag) {
    $feedCell .= " · $tag " . count($hostsFeeds[$tag])
        . ' (dead −' . $hostsDeadDropped[$tag] . ' · retained +' . $hostsRetained[$tag] . ')';
}
$rep[] = '| ③ lanes (internal) | ' . $feedCell . ' |';
$rep[] = '| ④ scrub (exclusion) | ' . $scrubStats['domainsRemoved'] . ' domains removed · ' . $scrubStats['rulesDropped'] . ' rules dropped · ' . $scrubStats['exclusionsAdded'] . ' carve-outs |';
$rep[] = '| ④ omit H (never-block floor) | filters: ' . $hStats['domainsRemoved'] . ' removed / ' . $hStats['rulesDropped'] . ' dropped · popup lane: ' . $popupNeverDropped . ' · domains lane: ' . $trackerStats['never'] . ' · appends: ' . $appendNeverDropped . ' |';
$rep[] = '| ④ veto (curated/vetoes.txt) | ' . $vetoed . ' block rules dropped |';
$rep[] = '| ④ popup lane | ' . count($popupDomains) . ' domains → ' . count($popupRules) . ' redirect rules · excluded by whitelist: ' . count($popupExcluded) . ' |';
$rep[] = '| ④ domains lane | ' . count($trackerDomains) . ' domains → ' . count($domainRules) . ' rules (excl −' . $trackerStats['excl'] . ' · H −' . $trackerStats['never'] . ' · easylist-covered −' . $trackerStats['covered'] . ') |';
$rep[] = '| ⑤ appends (D + F + fleet-BL) | ' . count($appendShipped) . ' domains → ' . count($appendRules) . ' rules · H −' . $appendNeverDropped . ' · **conflicts vs whitelist: ' . count($appendConflicts) . '** · **whitelisted subdomains overridden by an append parent: ' . count($appendParentOverrides) . '** |';
$rep[] = '| ⑥ rules.json | **' . $totalRules . ' rules** (' . implode(' · ', array_map(fn ($k, $v) => "$k $v", array_keys($byAction), $byAction)) . ') · main-frame dup→redirect ' . $dupAsRedirect . ' |';
$rep[] = '| budgets | total ' . $totalRules . '/' . BUDGET_TOTAL_RULES . ' · unsafe ' . $unsafeRules . '/' . BUDGET_UNSAFE_RULES . ' · regex ' . $regexRules . '/' . BUDGET_REGEX_RULES . ' |';
$rep[] = '| shipped block domains | ' . $shippedBlockDomains . ' |';
$rep[] = '| manifest version | `' . substr($version, 0, 12) . '…` |';
foreach ($gateNotes as $note) $rep[] = '| ⚠ change gate | ' . $note . ' |';
if ($appendConflicts) {
    $rep[] = '';
    $rep[] = '**Append ∩ exclusion set** (deliberate block kept — review): '
        . implode(', ', array_slice($appendConflicts, 0, 30))
        . (count($appendConflicts) > 30 ? ' … +' . (count($appendConflicts) - 30) : '');
}
if ($appendParentOverrides) {
    $rep[] = '';
    $rep[] = '**Whitelisted domains blocked via an append PARENT** (deliberate block wins — review): '
        . implode(', ', array_slice($appendParentOverrides, 0, 30))
        . (count($appendParentOverrides) > 30 ? ' … +' . (count($appendParentOverrides) - 30) : '');
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
