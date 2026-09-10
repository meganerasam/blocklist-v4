<?php
// build/review/shadow_diff.php — phase-2 gate: staging dist/network/rules.json vs the
// production compiled_rules_cache.json. Cutover is allowed only when every divergence
// falls into an EXPLAINED bucket AND the population floors hold; anything else exits 1.
//
// Usage:  php build/review/shadow_diff.php /path/to/compiled_rules_cache.json
//
// Explained-divergence vocabulary (staging no longer blocks a production domain):
//   ledger-dead        — DNS-dead per state/domain-ledger.json (v2 kept testing daily; the
//                        ledger's backoff keeps it out of the shipped set)
//   whitelist-excluded — covered by the CURATION SET (sanitized/curation-set.json =
//                        omit-from-blocklist ∪ not-to-add ∪ download-sites ∪ user whitelist, derived once by
//                        build/curate/curate.php); production's long lane never
//                        subtracted the fleet whitelist. Sheet C is product-only
//                        (2026-09-08) and takes no part in this bucket.
//   never-block-floor  — Sheet H (domain + subdomains)
//   still-covered      — still blocked by a BROAD staging batch on a parent domain
//   role-change        — bounded: redirect-instead-of-block only for the designed popup
//                        population (Sheet A + KADhosts); block-instead-of-redirect only
//                        when a broad staging block genuinely covers the domain
//   source-delisted    — no current snapshot/sheet lists it (production compiled from
//                        older upstream fetches; the no-graveyard seed decision)
//   narrowed-conditions / UNEXPLAINED* — gated: investigate before cutover
//
// Hardened 2026-09-07 after adversarial review: the gate now also fails on
//   · any Sheet D/F/fleet-BL append domain missing from staging (deliberate blocks may
//     never be explained away)
//   · broad→narrow condition drift (production blocks all/sub-resources, staging only a
//     main_frame or conditional batch)
//   · population floors: staging total ≥75% of production, allow rules ≥90%,
//     production-only surgical rules ≤10% of production's surgical population
//
// Output: markdown to stdout (+ GITHUB_STEP_SUMMARY) · state/review/shadow-diff.json

declare(strict_types=1);
ini_set('memory_limit', '4096M');

$ROOT = dirname(__DIR__, 2);
require $ROOT . '/build/compile/lib/util.php';
require $ROOT . '/build/compile/lib/scrub.php';

const FLOOR_TOTAL_PCT    = 75;   // staging total rules ≥ 75% of production
const FLOOR_ALLOW_PCT    = 90;   // staging allow rules ≥ 90% of production
const CEIL_PROD_ONLY_SURGICAL_PCT = 10; // production-only surgical ≤ 10% of prod surgical

$prodPath = $argv[1] ?? '';
if ($prodPath === '' || !is_file($prodPath)) {
    fwrite(STDERR, "usage: php build/review/shadow_diff.php /path/to/compiled_rules_cache.json\n");
    exit(2);
}
$stagPath = "$ROOT/dist/network/rules.json";
if (!is_file($stagPath)) {
    fwrite(STDERR, "staging dist/network/rules.json missing — run build/compile/compile.php first\n");
    exit(2);
}

$prod = json_decode((string) file_get_contents($prodPath), true);
$stag = json_decode((string) file_get_contents($stagPath), true);
if (!is_array($prod) || !is_array($stag)) { fwrite(STDERR, "invalid JSON input\n"); exit(2); }

// ---- context sets for classification --------------------------------------
$loadList = function (string $rel) use ($ROOT): array {
    $arr = json_decode((string) @file_get_contents("$ROOT/$rel"), true);
    $set = [];
    foreach (is_array($arr) ? $arr : [] as $d) if (is_string($d)) $set[rtrim(strtolower(trim($d)), '.')] = true;
    return $set;
};
// the curation set — read from sanitized/, never re-derived (single source of truth;
// build/curate/curate.php is the only writer). Sheet C is product-only and must not
// explain anything away here.
$excl = $loadList('sanitized/curation-set.json');
if (!$excl) {
    fwrite(STDERR, "sanitized/curation-set.json missing/empty — run build/curate/curate.php first\n");
    exit(2);
}
$never = $loadList('sources/gsheet/omit-from-blocklist.json');

$dead = [];
$ledger = json_decode((string) @file_get_contents("$ROOT/state/domain-ledger.json"), true) ?: [];
foreach ($ledger as $d => $r) if (($r['st'] ?? '') === 'd') $dead[$d] = true;
unset($ledger);

// the deliberately-appended population: these may NEVER be explained away
$appendSet = $loadList('sources/gsheet/default-blocklist.json')
           + $loadList('sources/gsheet/manual-blocklist.json')
           + $loadList('sources/extension/blocklist/user-extension-blocklist.json');

// the designed redirect-only population (popup role): Sheet A (normalized) + KADhosts
$designedPopup = [];
foreach (array_keys($loadList('sources/gsheet/popup.json')) as $d) {
    $designedPopup[$d] = true;
    $n = normalize_domain($d);
    if ($n !== '') $designedPopup[$n] = true;
}
foreach (load_hosts_file("$ROOT/sources/hosts/kadhosts.txt") as $d => $_) $designedPopup[$d] = true;

$listed = $designedPopup;   // everything the current sources still list
foreach (['anudeep', 'peterlowe', 'adguarddns'] as $tag) {
    foreach (load_hosts_file("$ROOT/sources/hosts/$tag.txt") as $d => $_) $listed[$d] = true;
}
foreach (array_keys($appendSet) as $d) $listed[$d] = true;

// ---- pull the two rule populations apart ----------------------------------
/**
 * A batched block rule is BROAD when it restricts nothing but the domain list and
 * (at most) the sub-resource type set — i.e. it really blocks the domain's traffic.
 * main_frame-only batches, domainType/initiator-conditioned batches are NARROW.
 */
function is_broad_block(array $cond): bool
{
    foreach (array_keys($cond) as $k) {
        if (!in_array($k, ['requestDomains', 'excludedRequestDomains', 'resourceTypes'], true)) return false;
    }
    if (!isset($cond['resourceTypes'])) return true;
    $rt = $cond['resourceTypes'];
    return is_array($rt) && in_array('script', $rt, true) && in_array('xmlhttprequest', $rt, true);
}

function split_rules(array $rules): array
{
    $out = [
        'byAction'    => [],
        'blockBroad'  => [],   // requestDomains of broad block batches
        'blockAll'    => [],   // requestDomains of ANY block rule
        'redirDoms'   => [],   // requestDomains of redirect rules
        'surgical'    => [],   // canonicalized non-domain-batch rules
        'idBands'     => [],
        'total'       => count($rules),
    ];
    foreach ($rules as $rule) {
        $type = $rule['action']['type'] ?? '?';
        $out['byAction'][$type] = ($out['byAction'][$type] ?? 0) + 1;
        $band = intdiv((int) ($rule['id'] ?? 0), 10000) * 10000;
        $out['idBands'][$band] = ($out['idBands'][$band] ?? 0) + 1;

        $cond = $rule['condition'] ?? [];
        $reqDoms = $cond['requestDomains'] ?? null;
        $isDomainBatch = is_array($reqDoms)
            && !isset($cond['urlFilter'])
            && (!isset($cond['regexFilter']) || $cond['regexFilter'] === '^http.+');

        if ($isDomainBatch && ($type === 'block' || $type === 'redirect')) {
            if ($type === 'redirect') {
                foreach ($reqDoms as $d) $out['redirDoms'][strtolower((string) $d)] = true;
            } else {
                $broad = is_broad_block($cond);
                foreach ($reqDoms as $d) {
                    $ld = strtolower((string) $d);
                    $out['blockAll'][$ld] = true;
                    if ($broad) $out['blockBroad'][$ld] = true;
                }
            }
            continue;
        }
        // canonical form: drop id, sort keys recursively — same logic ⇒ same string
        $canon = $rule;
        unset($canon['id']);
        $sortRec = function (&$v) use (&$sortRec) {
            if (!is_array($v)) return;
            if (array_is_list($v)) { foreach ($v as &$x) $sortRec($x); unset($x); }
            else { ksort($v); foreach ($v as &$x) $sortRec($x); unset($x); }
        };
        $sortRec($canon);
        $out['surgical'][json_encode($canon, JSON_UNESCAPED_SLASHES)][] = $rule['id'] ?? 0;
    }
    ksort($out['idBands']);
    return $out;
}
$P = split_rules($prod);
$S = split_rules($stag);

// ---- headline table --------------------------------------------------------
$result = ['production' => $prodPath];
$md = [];
$md[] = '# Shadow diff — staging dist/network/rules.json vs production';
$md[] = '';
$md[] = '| | production | staging |';
$md[] = '|---|---|---|';
$md[] = '| total rules | ' . $P['total'] . ' | ' . $S['total'] . ' |';
foreach (array_unique(array_merge(array_keys($P['byAction']), array_keys($S['byAction']))) as $t) {
    $md[] = "| $t | " . ($P['byAction'][$t] ?? 0) . ' | ' . ($S['byAction'][$t] ?? 0) . ' |';
}
$md[] = '| block domains — broad batches | ' . count($P['blockBroad']) . ' | ' . count($S['blockBroad']) . ' |';
$md[] = '| block domains — any batch | ' . count($P['blockAll']) . ' | ' . count($S['blockAll']) . ' |';
$md[] = '| redirect domains (batched) | ' . count($P['redirDoms']) . ' | ' . count($S['redirDoms']) . ' |';
$md[] = '| surgical rules (canonical) | ' . count($P['surgical']) . ' | ' . count($S['surgical']) . ' |';
$result['counts'] = [
    'production' => ['total' => $P['total'], 'byAction' => $P['byAction'], 'idBands' => $P['idBands']],
    'staging'    => ['total' => $S['total'], 'byAction' => $S['byAction'], 'idBands' => $S['idBands']],
];

$gatedCount = 0;   // everything that must be zero for the gate to clear

// ---- block-domain diff (shape-aware) ---------------------------------------
$missing = [];
foreach ($P['blockAll'] as $d => $_) {
    $prodBroad = isset($P['blockBroad'][$d]);
    if (isset($S['blockBroad'][$d])) continue;                       // fully present
    if (!$prodBroad && isset($S['blockAll'][$d])) continue;          // narrow on both sides — parity
    $stagNarrowOnly = $prodBroad && isset($S['blockAll'][$d]);       // broad → narrow drift…
    // …but only a regression when compile SHOULD ship it broadly — check causes first
    // (a dead/delisted domain losing its broad batch while easylist keeps a narrow rule
    // is expected: production carried BOTH shapes, the long lane supplied the broad one)
    if (isset($appendSet[$d]) || covered_subdomain($d, $appendSet)) {
        $missing['UNEXPLAINED: deliberate-append-lost'][] = $d;      // D/F/fleet-BL must always ship
    } elseif (isset($dead[$d])) {
        $missing['ledger-dead'][] = $d;
    } elseif (isWhitelistCovered($d, $never)) {
        $missing['never-block-floor'][] = $d;
    } elseif (isWhitelistCovered($d, $excl)) {
        $missing['whitelist-excluded'][] = $d;
    } elseif (covered_subdomain($d, $S['blockBroad'])) {
        $missing['still-covered'][] = $d;
    } elseif (isset($designedPopup[$d]) && isset($S['redirDoms'][$d])) {
        $missing['role-change: redirected-not-blocked (popup role)'][] = $d;
    } elseif (!isset($listed[$d])) {
        $missing['source-delisted'][] = $d;
    } elseif ($stagNarrowOnly) {
        $missing['narrowed-conditions'][] = $d;                      // gated: listed + alive + broad in prod
    } else {
        $missing['UNEXPLAINED'][] = $d;
    }
}
$addedBlock = array_diff_key($S['blockAll'], $P['blockAll']);

$md[] = '';
$md[] = '## block domains — production→staging';
$md[] = '';
$md[] = '| bucket | count | sample |';
$md[] = '|---|---|---|';
ksort($missing);
foreach ($missing as $bucket => $doms) {
    sort($doms);
    if (str_starts_with($bucket, 'UNEXPLAINED') || $bucket === 'narrowed-conditions') $gatedCount += count($doms);
    $md[] = "| dropped: $bucket | " . count($doms) . ' | ' . implode(', ', array_slice($doms, 0, 8)) . ' |';
    $result['block']['dropped'][$bucket] = ['count' => count($doms), 'domains' => array_slice($doms, 0, 2000)];
}
$md[] = '| added (staging only) | ' . count($addedBlock) . ' | ' . implode(', ', array_slice(array_keys($addedBlock), 0, 8)) . ' |';
$result['block']['added'] = ['count' => count($addedBlock), 'domains' => array_slice(array_keys($addedBlock), 0, 2000)];

// ---- redirect-domain diff ---------------------------------------------------
$missing = [];
foreach ($P['redirDoms'] as $d => $_) {
    if (isset($S['redirDoms'][$d])) continue;
    if (isset($dead[$d])) {
        $missing['ledger-dead'][] = $d;
    } elseif (isWhitelistCovered($d, $never)) {
        $missing['never-block-floor'][] = $d;
    } elseif (isWhitelistCovered($d, $excl)) {
        $missing['whitelist-excluded'][] = $d;
    } elseif (covered_subdomain($d, $S['redirDoms'])) {
        $missing['still-covered'][] = $d;
    } elseif (isset($S['blockBroad'][$d]) || covered_subdomain($d, $S['blockBroad'])) {
        // still blocked outright (EasyList broad batch blocks main_frame too) —
        // only the popup-tracker landing page is lost, not the protection
        $missing['role-change: blocked-not-redirected (easylist-covered)'][] = $d;
    } elseif (!isset($listed[$d])) {
        $missing['source-delisted'][] = $d;
    } else {
        $missing['UNEXPLAINED'][] = $d;
    }
}
$addedRedir = array_diff_key($S['redirDoms'], $P['redirDoms']);

$md[] = '';
$md[] = '## redirect domains — production→staging';
$md[] = '';
$md[] = '| bucket | count | sample |';
$md[] = '|---|---|---|';
ksort($missing);
foreach ($missing as $bucket => $doms) {
    sort($doms);
    if (str_starts_with($bucket, 'UNEXPLAINED')) $gatedCount += count($doms);
    $md[] = "| dropped: $bucket | " . count($doms) . ' | ' . implode(', ', array_slice($doms, 0, 8)) . ' |';
    $result['redirect']['dropped'][$bucket] = ['count' => count($doms), 'domains' => array_slice($doms, 0, 2000)];
}
$md[] = '| added (staging only) | ' . count($addedRedir) . ' | ' . implode(', ', array_slice(array_keys($addedRedir), 0, 8)) . ' |';
$result['redirect']['added'] = ['count' => count($addedRedir), 'domains' => array_slice(array_keys($addedRedir), 0, 2000)];

// ---- surgical rule diff ------------------------------------------------------
$prodOnly = array_diff_key($P['surgical'], $S['surgical']);
$stagOnly = array_diff_key($S['surgical'], $P['surgical']);
$shared   = count($P['surgical']) - count($prodOnly);

$surgBuckets = [];
foreach ($prodOnly as $canon => $ids) {
    $rule = json_decode($canon, true);
    $bucket = 'upstream-drift';                    // default: EasyList moved since the prod build
    $anchor = null;
    if (preg_match('/^\|\|([a-z0-9.-]+)/i', (string) ($rule['condition']['urlFilter'] ?? ''), $m)) {
        $anchor = strtolower(trim($m[1], '.'));
    }
    if (($rule['action']['type'] ?? '') === 'block' && $anchor !== null) {
        if (isWhitelistCovered($anchor, $never))      $bucket = 'never-block-floor';
        elseif (isWhitelistCovered($anchor, $excl))   $bucket = 'whitelist-excluded';
    }
    $surgBuckets[$bucket][] = substr((string) ($rule['condition']['urlFilter']
        ?? $rule['condition']['regexFilter'] ?? $canon), 0, 90);
}
$md[] = '';
$md[] = '## surgical rules (id-less canonical compare)';
$md[] = '';
$md[] = '| bucket | count | sample |';
$md[] = '|---|---|---|';
$md[] = '| identical both sides | ' . $shared . ' | |';
ksort($surgBuckets);
foreach ($surgBuckets as $bucket => $rules) {
    $md[] = "| production-only: $bucket | " . count($rules) . ' | `' . implode('` · `', array_slice($rules, 0, 3)) . '` |';
    $result['surgical']['production_only'][$bucket] = ['count' => count($rules), 'sample' => array_slice($rules, 0, 200)];
}
$md[] = '| staging-only (new snapshots + carve-outs) | ' . count($stagOnly) . ' | |';
$result['surgical']['identical'] = $shared;
$result['surgical']['staging_only'] = count($stagOnly);

// ---- gates -------------------------------------------------------------------
$stagRaw = (string) file_get_contents($stagPath);
$extIdOk = strpos($stagRaw, '__EXT_ID__') !== false;

$floors = [];
$pct = fn (int $a, int $b): float => $b > 0 ? round($a / $b * 100, 1) : 100.0;
$floors[] = ['staging total ≥ ' . FLOOR_TOTAL_PCT . '% of production',
    $pct($S['total'], $P['total']), $pct($S['total'], $P['total']) >= FLOOR_TOTAL_PCT];
$floors[] = ['staging allow rules ≥ ' . FLOOR_ALLOW_PCT . '% of production',
    $pct($S['byAction']['allow'] ?? 0, $P['byAction']['allow'] ?? 0),
    $pct($S['byAction']['allow'] ?? 0, $P['byAction']['allow'] ?? 0) >= FLOOR_ALLOW_PCT];
$floors[] = ['production-only surgical ≤ ' . CEIL_PROD_ONLY_SURGICAL_PCT . '% of production surgical',
    $pct(count($prodOnly), count($P['surgical'])),
    $pct(count($prodOnly), count($P['surgical'])) <= CEIL_PROD_ONLY_SURGICAL_PCT];

$floorsOk = true;
$md[] = '';
$md[] = '| gate | value | status |';
$md[] = '|---|---|---|';
$md[] = '| __EXT_ID__ placeholder preserved | | ' . ($extIdOk ? '✓' : '✗ MISSING') . ' |';
$md[] = '| unexplained + narrowed dropped domains | ' . $gatedCount . ' | '
    . ($gatedCount === 0 ? '✓' : '✗ investigate before cutover') . ' |';
foreach ($floors as [$label, $value, $ok]) {
    if (!$ok) $floorsOk = false;
    $md[] = "| $label | {$value}% | " . ($ok ? '✓' : '✗') . ' |';
}
$gateOk = $extIdOk && $gatedCount === 0 && $floorsOk;
$md[] = '| **verdict** | | ' . ($gateOk ? '**GATE CLEAR**' : '**GATE BLOCKED**') . ' |';
$result['gate'] = [
    'ext_id_placeholder' => $extIdOk,
    'gated_domain_count' => $gatedCount,
    'floors' => array_map(fn ($f) => ['check' => $f[0], 'value_pct' => $f[1], 'ok' => $f[2]], $floors),
    'clear' => $gateOk,
];

if (!is_dir("$ROOT/state/review")) mkdir("$ROOT/state/review", 0755, true);
file_put_contents("$ROOT/state/review/shadow-diff.json",
    json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

$out = implode("\n", $md) . "\n";
echo $out;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $out, FILE_APPEND);
}
exit($gateOk ? 0 : 1);
