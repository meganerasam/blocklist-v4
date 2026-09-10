<?php
// build/catalog/catalog.php — the à-la-carte catalog: dist/catalog/{raw,curated,merged}.
//
// User decision 2026-09-10: every source (each Google Sheet, each public list, the fleet
// whitelist) is published in TWO representations (domains.json + DNR rules per action
// type) at THREE stages that mirror the pipeline itself:
//
//   raw/      — each source verbatim, BEFORE any subtraction (from sources/ mirrors and
//               the generators' .work output). Inspection/composition surface only —
//               NEVER shippable as-is: it predates the never-block floor, the vetoes and
//               the curation set.
//   curated/  — each source AFTER its own +/- recipe (from sanitized/, the single place
//               subtraction is derived — rule 5 stands: nothing is re-derived here, files
//               are copied or re-shaped from sanitized/ and dist/).
//   merged/   — the cross-source cumulés: per-action subsets of the canonical
//               dist/network/rules.json (IDs preserved) and the domain rollups. The
//               canonical merge itself is NOT duplicated — network/rules.json stays the
//               single merged truth (user decision: alias, never a second compile).
//
// Rule IDs (user decision 2026-09-10): per-file sequential 1..N. Files load fine as
// SEPARATE DNR rulesets (Chrome scopes ID uniqueness per ruleset); concatenating two
// catalog files into ONE ruleset requires re-IDing — which is exactly what the canonical
// merge already does (compile's band re-ID). merged/rules/* subsets keep the canonical
// band IDs so every rule can be cross-referenced back to network/rules.json.
//
// Runs AFTER build/compile/compile.php (compile.yml step). Reads sources/ + sanitized/ +
// dist/; writes ONLY dist/catalog/. Same doctrine as every other emitter: fail-closed
// (compute everything, then staged atomic writes + prune), byte-deterministic
// (sorted output, no timestamps, generic.css 'Generated:' line stripped like curate).

declare(strict_types=1);
ini_set('memory_limit', '3072M');

$ROOT = dirname(__DIR__, 2);
require dirname(__DIR__) . '/compile/lib/util.php';
require dirname(__DIR__) . '/compile/lib/scrub.php';

const CHUNK = 5000;                       // domains per batched DNR rule (compile's value)
const SUB_RESOURCE_TYPES = ['script', 'xmlhttprequest', 'sub_frame', 'image', 'media'];
const REDIRECT_SUBSTITUTION = 'chrome-extension://__EXT_ID__/pages/popup-tracker.html?url=\0';

$t0 = microtime(true);

function fail(string $msg): void
{
    fwrite(STDERR, "FATAL: $msg\n");
    $md = "# Catalog — FAILED\n\n**$msg**\n\nPrevious dist/catalog/ kept (fail-closed).\n";
    echo $md;
    if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
        file_put_contents($sum, $md, FILE_APPEND);
    }
    exit(1);
}

/** Mirror loader (same semantics as compile's): JSON array of strings, lowercased,
 *  trimmed, trailing dot stripped. */
function cat_load_mirror(string $path, string $label, bool $mustExist = true): array
{
    if (!is_file($path)) {
        if ($mustExist) fail("$label mirror missing: $path");
        return [];
    }
    $arr = json_decode((string) file_get_contents($path), true);
    if (!is_array($arr)) fail("$label mirror is not a JSON array: $path");
    $out = [];
    foreach ($arr as $row) {
        if (!is_string($row)) fail("$label mirror has a non-string row: $path");
        $row = rtrim(strtolower(trim($row)), '.');
        if ($row !== '') $out[] = $row;
    }
    return $out;
}

function cat_json(string $path, string $label): array
{
    if (!is_file($path)) fail("$label missing: $path");
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) fail("$label is not valid JSON: $path");
    return $data;
}

function reid(array $rules): array
{
    $id = 1;
    foreach ($rules as &$rule) $rule['id'] = $id++;
    unset($rule);
    return $rules;
}

function chunk_block_rules(array $domains, array $carveSet = []): array
{
    $rules = [];
    foreach (array_chunk($domains, CHUNK) as $chunk) {
        $cond = ['resourceTypes' => SUB_RESOURCE_TYPES, 'requestDomains' => $chunk];
        if ($carveSet) {
            $carve = carve_for_chunk($chunk, $carveSet);
            if ($carve) $cond['excludedRequestDomains'] = $carve;
        }
        $rules[] = ['id' => 0, 'priority' => 1, 'action' => ['type' => 'block'], 'condition' => $cond];
    }
    return reid($rules);
}

function chunk_redirect_rules(array $domains, array $carveSet = []): array
{
    $rules = [];
    foreach (array_chunk($domains, CHUNK) as $chunk) {
        $cond = ['regexFilter' => '^http.+', 'requestDomains' => $chunk, 'resourceTypes' => ['main_frame']];
        if ($carveSet) {
            $carve = carve_for_chunk($chunk, $carveSet);
            if ($carve) $cond['excludedRequestDomains'] = $carve;
        }
        $rules[] = [
            'id' => 0, 'priority' => 3,
            'action' => ['type' => 'redirect', 'redirect' => ['regexSubstitution' => REDIRECT_SUBSTITUTION]],
            'condition' => $cond,
        ];
    }
    return reid($rules);
}

function chunk_allow_rules(array $domains): array
{
    $rules = [];
    foreach (array_chunk($domains, CHUNK) as $chunk) {
        $rules[] = [
            'id' => 0, 'priority' => 2,
            'action' => ['type' => 'allow'],
            'condition' => ['requestDomains' => $chunk],
        ];
    }
    return reid($rules);
}

// Partial block-target extraction: requestDomains of block rules + PURE ||domain^
// urlFilter anchors (end-anchored — adversarial review 2026-09-10: a path-scoped anchor
// such as "||googleapis.com^" followed by a path pattern must NOT list its domain as a
// block target; the catalog's honest failure mode is under-coverage, never over-coverage).
function extract_block_domains(array $rules): array
{
    $set = [];
    foreach ($rules as $r) {
        if (($r['action']['type'] ?? '') !== 'block') continue;
        foreach ($r['condition']['requestDomains'] ?? [] as $d) $set[strtolower((string) $d)] = true;
        $uf = $r['condition']['urlFilter'] ?? '';
        if (is_string($uf) && preg_match('/^\|\|([a-z0-9-]+(?:\.[a-z0-9-]+)+)\^$/i', $uf, $m)) {
            $set[strtolower($m[1])] = true;
        }
    }
    $out = array_keys($set);
    sort($out, SORT_STRING);
    return $out;
}

/** The curated stage may never list a never-block-floor domain — sanitized/ already
 *  subtracts the curation set (⊇ the floor), this assert keeps that guarantee explicit. */
function assert_never_clean(array $domains, array $never, string $label): void
{
    foreach ($domains as $d) {
        if (isWhitelistCovered($d, $never)) {
            fail("never-block violation in curated catalog lane $label: $d");
        }
    }
}

// ============================================================================
// ① GATES — same freshness doctrine as compile: no mixed-generation catalog
// ============================================================================
$SAN = "$ROOT/sanitized";
if (!is_dir($SAN)) fail('sanitized/ missing — run build/curate/curate.php first');
$prov = json_decode((string) @file_get_contents("$SAN/provenance.json"), true);
if (!is_array($prov) || !$prov) fail('sanitized/provenance.json missing/invalid — run build/curate/curate.php');
foreach ($prov as $rel => $sha) {
    $cur = is_file("$ROOT/$rel") ? hash_file('sha256', "$ROOT/$rel") : 'MISSING';
    if ($cur !== $sha) {
        fail("sanitized/ is STALE vs $rel — run build/curate/curate.php (then compile) before the catalog");
    }
}
$manifest = cat_json("$ROOT/dist/manifest.json", 'dist/manifest.json (run compile first)');
$rulesJsonRaw = (string) @file_get_contents("$ROOT/dist/network/rules.json");
if ($rulesJsonRaw === '') fail('dist/network/rules.json missing — run build/compile/compile.php first');
$manifestSha = $manifest['artifacts']['network/rules.json']['sha256'] ?? '';
if ($manifestSha !== hash('sha256', $rulesJsonRaw)) {
    fail('dist/network/rules.json does not match dist/manifest.json — dist/ is torn; re-run compile');
}
// Cross-stage generation lock (adversarial review 2026-09-10, reproduced hole: green
// curate + gated/skipped compile leaves dist/ one generation BEHIND sanitized/, and both
// checks above still pass — the catalog would then mix curated/ from the new generation
// with merged/ from the old one). compile.php stamps the sanitized provenance hash into
// manifest.json; equality here proves dist/ was assembled from the CURRENT sanitized/.
$provSha = hash('sha256', (string) file_get_contents("$SAN/provenance.json"));
if (($manifest['sanitized_provenance'] ?? '') !== $provSha) {
    fail('dist/ was not compiled from the CURRENT sanitized/ generation (manifest.sanitized_provenance mismatch) — run build/compile/compile.php first');
}

// ============================================================================
// ② SHARED SETS — read, never re-derived (curate.php owns every derivation)
// ============================================================================
// Sheet H (omit-from-whitelist) is deliberately NOT loaded: its exact-host veto is
// already baked into every artifact the catalog copies (sanitized user-whitelist,
// download-sites lane, whitelist/default.json) — the catalog never re-applies it.
$omitBlocklist = cat_load_mirror("$ROOT/sources/gsheet/omit-from-blocklist.json", 'Sheet I');
$noAdd = cat_load_mirror("$ROOT/sources/gsheet/default-blocklist-not-to-add.json", 'Sheet E', false);
$never = [];
foreach ($omitBlocklist as $d) $never[$d] = true;
foreach ($noAdd as $d)         $never[$d] = true;
$curation = [];
foreach (cat_load_mirror("$SAN/curation-set.json", 'curation set (sanitized)') as $d) $curation[$d] = true;
$carveSet = $curation + $never;

// ============================================================================
// ③ RAW EASYLIST LANES — regenerate .work exactly the way curate.php does
//    (.work is transient and gitignored; the generators read RAW snapshots and
//    contain zero curation, so their output IS the raw DNR form)
// ============================================================================
$CATS = ['adult', 'easylist', 'easyprivacy', 'fanboy'];
$COMPILE = "$ROOT/build/compile";
$WORK = "$COMPILE/.work";
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
    if (is_file("$COMPILE/$cat/css/generate_css.php")) $GENERATORS[] = "$cat/css/generate_css.php";
}
foreach ($GENERATORS as $gen) {
    $out = [];
    $code = 1;
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$COMPILE/$gen") . ' 2>&1', $out, $code);
    if ($code !== 0) fail("generator $gen exited $code:\n" . implode("\n", array_slice($out, -15)));
}

// ============================================================================
// ④ STAGING — compute every artifact, then (and only then) touch dist/catalog/
// ============================================================================
$artifacts = [];   // rel path under dist/catalog/ => ['content' => string, 'count' => ?int]
$stage = function (string $rel, string $content, ?int $count) use (&$artifacts) {
    $artifacts[$rel] = ['content' => $content, 'count' => $count];
};
$stageJson = function (string $rel, array $data, ?int $count = null) use ($stage) {
    $stage($rel, json_out($data, false) . "\n", $count ?? count($data));
};
$copyFile = function (string $rel, string $absSrc, string $label, ?int $count) use ($stage) {
    if (!is_file($absSrc)) fail("$label missing: $absSrc");
    $stage($rel, (string) file_get_contents($absSrc), $count);
};

$catalogSources = [];   // catalog.json "sources" section, built alongside the files
$srcEntry = function (string $id, array $meta) use (&$catalogSources) {
    ksort($meta);
    $catalogSources[$id] = $meta;
};
$fileRef = function (string $rel) use (&$artifacts): array {
    return ['path' => "catalog/$rel", 'count' => $artifacts[$rel]['count']];
};

// ---------------------------------------------------------------- Google Sheets
// Every domain-sheet mirror ships verbatim at raw/<id>/domains.json (byte copy of the
// committed mirror). Rule cells exist only where the factory has a defined recipe.
$SHEETS = [
    // id suffix                    letter  mirror file                          role
    ['popup',                        'A', 'popup.json',                          'block'],
    ['default-whitelist',            'C', 'default-whitelist.json',              'allow'],
    ['default-blocklist',            'D', 'default-blocklist.json',              'append'],
    ['default-blocklist-not-to-add', 'E', 'default-blocklist-not-to-add.json',   'veto'],
    ['manual-whitelist',             'F', 'manual-whitelist.json',               'unassigned'],
    ['manual-blocklist',             'G', 'manual-blocklist.json',               'append'],
    ['omit-from-whitelist',          'H', 'omit-from-whitelist.json',            'veto'],
    ['omit-from-blocklist',          'I', 'omit-from-blocklist.json',            'veto'],
    ['download-sites',               'J', 'download-sites.json',                 'allow'],
    ['whitelisted-domains-injection-enabled', 'K', 'whitelisted-domains-injection-enabled.json', 'standalone'],
    ['tracking-whitelist',           'L', 'tracking-whitelist.json',             'standalone'],
    ['allow-request-domains',        'M', 'allow-request-domains.json',          'standalone'],
    ['initiator-allowed-domains',    'N', 'initiator-allowed-domains.json',      'standalone'],
    ['rule101xtra',                  'O', 'rule101xtra.json',                    'standalone'],
];
$sheetRows = [];
$sheetMissing = [];
// default-blocklist-not-to-add and download-sites keep their documented absent-mirror
// fail-soft (curate degrades to empty+warn, compile falls back) — the catalog mirrors
// that tolerance instead of being the one stage that turns the chain red (review 2026-09-10).
$FAIL_SOFT = ['default-blocklist-not-to-add' => true, 'download-sites' => true];
foreach ($SHEETS as [$suffix, $letter, $file, $role]) {
    $id = "gsheet-$suffix";
    $mirror = "$ROOT/sources/gsheet/$file";
    if (!is_file($mirror) && isset($FAIL_SOFT[$suffix])) {
        $sheetRows[$suffix] = [];
        $sheetMissing[$suffix] = true;
        $stage("raw/$id/domains.json", "[]\n", 0);
        continue;
    }
    $rows = cat_json($mirror, "Sheet $letter mirror");
    $sheetRows[$suffix] = $rows;
    $copyFile("raw/$id/domains.json", $mirror, "Sheet $letter mirror", count($rows));
}

// Sheet A — the popup/redirect source. Raw rules: the lane recipe on the raw mirror
// (normalize like production short.php), no floors. Curated rules: the sanitized rows
// through the same normalization + the standing guards + carve-outs.
$rawPopup = [];
foreach ($sheetRows['popup'] as $row) {
    // mirror-loader normalization FIRST (lowercase · trim · trailing dot), like every
    // other lane — an uppercase sheet row must never reach requestDomains (Chrome
    // matches lowercase only) nor dodge the grand-total guard (review 2026-09-10)
    $norm = normalize_domain(rtrim(strtolower(trim((string) $row)), '.'));
    if ($norm === '' || $norm === 'grand total') continue;
    $rawPopup[$norm] = true;
}
ksort($rawPopup, SORT_STRING);
$stageJson('raw/gsheet-popup/rules/redirect.json', chunk_redirect_rules(array_keys($rawPopup)));

$curPopupRows = cat_load_mirror("$SAN/gsheet/popup.json", 'Sheet A (sanitized)');
$copyFile('curated/gsheet-popup/domains.json', "$SAN/gsheet/popup.json", 'Sheet A (sanitized)', count($curPopupRows));
$curPopup = [];
foreach ($curPopupRows as $row) {
    $norm = normalize_domain($row);
    if ($norm === '' || $norm === 'grand total') continue;
    if (isWhitelistCovered($norm, $never) || isWhitelistCovered($norm, $curation)) continue;
    $curPopup[$norm] = true;
}
ksort($curPopup, SORT_STRING);
assert_never_clean(array_keys($curPopup), $never, 'gsheet-popup');
$stageJson('curated/gsheet-popup/rules/redirect.json', chunk_redirect_rules(array_keys($curPopup), $carveSet));

$srcEntry('gsheet-popup', [
    'kind' => 'gsheet', 'sheet' => 'A', 'role' => 'block',
    'matching' => 'domain+subdomains',
    'raw' => ['domains' => $fileRef('raw/gsheet-popup/domains.json'),
              'rules' => ['redirect' => $fileRef('raw/gsheet-popup/rules/redirect.json')]],
    'curated' => ['domains' => $fileRef('curated/gsheet-popup/domains.json'),
                  'rules' => ['redirect' => $fileRef('curated/gsheet-popup/rules/redirect.json')]],
    'notes' => ['curated domains keep the sheet rows verbatim; curated rules normalize them (www./scheme strip) before chunking',
                'ledger dead-filtering happens only at the canonical merge — curated here = post-curation, pre-ledger'],
]);

// Sheet C — product-only whitelist. Curated form IS dist/whitelist/default.json
// (C − H − I, derived once at compile) — copied, never re-derived.
$stageJson('raw/gsheet-default-whitelist/rules/allow.json',
    chunk_allow_rules(cat_load_mirror("$ROOT/sources/gsheet/default-whitelist.json", 'Sheet C')));
$wlDefault = cat_json("$ROOT/dist/whitelist/default.json", 'dist/whitelist/default.json');
$copyFile('curated/gsheet-default-whitelist/domains.json', "$ROOT/dist/whitelist/default.json",
    'dist/whitelist/default.json', count($wlDefault));
$stageJson('curated/gsheet-default-whitelist/rules/allow.json', chunk_allow_rules($wlDefault));
$srcEntry('gsheet-default-whitelist', [
    'kind' => 'gsheet', 'sheet' => 'C', 'role' => 'allow',
    'matching' => 'domain+subdomains',
    'raw' => ['domains' => $fileRef('raw/gsheet-default-whitelist/domains.json'),
              'rules' => ['allow' => $fileRef('raw/gsheet-default-whitelist/rules/allow.json')]],
    'curated' => ['domains' => $fileRef('curated/gsheet-default-whitelist/domains.json'),
                  'rules' => ['allow' => $fileRef('curated/gsheet-default-whitelist/rules/allow.json')]],
    'notes' => ['product-only sheet: takes part in no curation; curated form = dist/whitelist/default.json (C − omit-from-whitelist − omit-from-blocklist, derived at compile, copied here)'],
]);

// Sheets D + G — the append blocklists. Raw = mirror rows as block rules; curated =
// rows minus the never-block floor (the append recipe: floored only by I ∪ E,
// carved only against the floor — appends outrank the curation set by design).
foreach ([['default-blocklist', 'D'], ['manual-blocklist', 'G']] as [$suffix, $letter]) {
    $id = "gsheet-$suffix";
    $rows = cat_load_mirror("$ROOT/sources/gsheet/$suffix.json", "Sheet $letter");
    $rows = array_values(array_unique($rows));
    sort($rows, SORT_STRING);
    $stageJson("raw/$id/rules/block.json", chunk_block_rules($rows));
    $kept = [];
    foreach ($rows as $d) if (!isWhitelistCovered($d, $never)) $kept[] = $d;
    $stageJson("curated/$id/domains.json", $kept);
    $stageJson("curated/$id/rules/block.json", chunk_block_rules($kept, $never));
    $srcEntry($id, [
        'kind' => 'gsheet', 'sheet' => $letter, 'role' => 'append',
        'matching' => 'domain+subdomains',
        'raw' => ['domains' => $fileRef("raw/$id/domains.json"),
                  'rules' => ['block' => $fileRef("raw/$id/rules/block.json")]],
        'curated' => ['domains' => $fileRef("curated/$id/domains.json"),
                      'rules' => ['block' => $fileRef("curated/$id/rules/block.json")]],
        'notes' => ['append lane: sits ABOVE the curation set, floored only by omit-from-blocklist ∪ not-to-add (the never-block floor)'],
    ]);
}

// Sheet J — download-sites. Raw = verbatim mirror only (the normalization that makes
// rows usable is itself the curate recipe). Curated = the validated sanitized allow
// lane, re-ID'd, plus the domains harvested from its ||domain^ anchors.
$dlLane = cat_json("$SAN/download-sites/allow.json", 'sanitized download-sites lane');
$dlDomains = [];
foreach ($dlLane as $i => $r) {
    $uf = (string) ($r['condition']['urlFilter'] ?? '');
    if (!preg_match('/^\|\|([a-z0-9.-]+)\^$/', $uf, $m)) {
        // compile hard-fails this same deviation — a silently skipped rule would ship in
        // rules/allow.json yet vanish from the paired domains.json (review 2026-09-10)
        fail("download-sites lane rule #$i is off-template ($uf) — refusing a domains/rules pair that disagrees");
    }
    $dlDomains[$m[1]] = true;
}
$dlDomains = array_keys($dlDomains);
sort($dlDomains, SORT_STRING);
$stageJson('curated/gsheet-download-sites/domains.json', $dlDomains);
$stageJson('curated/gsheet-download-sites/rules/allow.json', reid($dlLane));
$srcEntry('gsheet-download-sites', [
    'kind' => 'gsheet', 'sheet' => 'J', 'role' => 'allow',
    'matching' => 'domain+subdomains',
    'raw' => ['domains' => $fileRef('raw/gsheet-download-sites/domains.json'), 'rules' => null],
    'curated' => ['domains' => $fileRef('curated/gsheet-download-sites/domains.json'),
                  'rules' => ['allow' => $fileRef('curated/gsheet-download-sites/rules/allow.json')]],
    'notes' => array_merge(
        ['no raw rules on purpose: row normalization (protocol/path/www. strip) IS the curate recipe — raw rows are not rule material',
         'dual role: allow source (this lane) AND curation-set member subtracted from every blocking source'],
        isset($sheetMissing['download-sites']) ? ['mirror ABSENT this run (documented fail-soft) — raw cell published empty'] : []
    ),
]);

// Veto sheets (E, H, I), Sheet F (no recipe yet) and the standalone Sheets K–O:
// raw domains only — a veto produces no rules by definition, F's role is undecided,
// K–O ship verbatim at dist/standalone/ and are consumed as plain JSON.
$SIMPLE = [
    ['default-blocklist-not-to-add', 'E', 'veto', 'domain+subdomains',
        ['never-block floor + curation-set member; a listed domain produces NO rule anywhere']],
    ['manual-whitelist', 'F', 'unassigned', 'domain+subdomains',
        ['mirrored, part of NO recipe (role to be decided)']],
    ['omit-from-whitelist', 'H', 'veto', 'exact-host',
        ['whitelist veto: exact host only — subdomain matching would let google.com strip accounts.google.com']],
    ['omit-from-blocklist', 'I', 'veto', 'domain+subdomains',
        ['never-block floor, own-brand only; overrides every block source including fleet blocklists']],
    ['whitelisted-domains-injection-enabled', 'K', 'standalone', null,
        ['ships verbatim at dist/standalone/whitelisted-domains-injection-enabled.json']],
    ['tracking-whitelist', 'L', 'standalone', null,
        ['ships verbatim at dist/standalone/tracking-whitelist.json']],
    ['allow-request-domains', 'M', 'standalone', null,
        ['ships verbatim at dist/standalone/allow-request-domains.json']],
    ['initiator-allowed-domains', 'N', 'standalone', null,
        ['ships verbatim at dist/standalone/initiator-allowed-domains.json']],
    ['rule101xtra', 'O', 'standalone', null,
        ['ships verbatim at dist/standalone/rule101xtra.json']],
];
foreach ($SIMPLE as [$suffix, $letter, $role, $matching, $notes]) {
    $id = "gsheet-$suffix";
    if (isset($sheetMissing[$suffix])) $notes[] = 'mirror ABSENT this run (documented fail-soft) — raw cell published empty';
    $srcEntry($id, [
        'kind' => 'gsheet', 'sheet' => $letter, 'role' => $role,
        'matching' => $matching,
        'raw' => ['domains' => $fileRef("raw/$id/domains.json"), 'rules' => null],
        'curated' => null,
        'notes' => $notes,
    ]);
}

// Sheet B — traffic_quality: object-shaped, split per market at ingest, published
// as-is. Index entry only; the 24 market files live at dist/traffic_quality/.
$srcEntry('gsheet-traffic-quality', [
    'kind' => 'gsheet', 'sheet' => 'B', 'role' => 'data',
    'matching' => null,
    'raw' => null, 'curated' => null,
    'notes' => ['per-market split published verbatim at dist/traffic_quality/<market>.json (24 files incl. global + latam/apac/nordics rollups) — never merged into rules'],
]);

// ---------------------------------------------------------------- hosts lists
// kadhosts feeds the popup/redirect lane; the other three feed the block+redirect
// domains lane — each catalog source mirrors its own lane's rule shapes.
$HOSTS = ['anudeep', 'peterlowe', 'adguarddns', 'kadhosts'];
foreach ($HOSTS as $tag) {
    $id = "hosts-$tag";
    $raw = array_keys(load_hosts_file("$ROOT/sources/hosts/$tag.txt"));
    if (!$raw) fail("raw hosts snapshot empty/missing: sources/hosts/$tag.txt");
    sort($raw, SORT_STRING);
    $cur = array_keys(load_hosts_file("$SAN/hosts/$tag.txt"));
    if (!$cur) fail("sanitized hosts lane empty/missing: sanitized/hosts/$tag.txt");
    sort($cur, SORT_STRING);
    assert_never_clean($cur, $never, $id);
    $stageJson("raw/$id/domains.json", $raw);
    $stageJson("curated/$id/domains.json", $cur);
    $rawRules = $curRules = [];
    if ($tag === 'kadhosts') {
        $stageJson("raw/$id/rules/redirect.json", chunk_redirect_rules($raw));
        $stageJson("curated/$id/rules/redirect.json", chunk_redirect_rules($cur, $carveSet));
        $rawRules = ['redirect' => $fileRef("raw/$id/rules/redirect.json")];
        $curRules = ['redirect' => $fileRef("curated/$id/rules/redirect.json")];
    } else {
        $stageJson("raw/$id/rules/block.json", chunk_block_rules($raw));
        $stageJson("raw/$id/rules/redirect.json", chunk_redirect_rules($raw));
        $stageJson("curated/$id/rules/block.json", chunk_block_rules($cur, $carveSet));
        $stageJson("curated/$id/rules/redirect.json", chunk_redirect_rules($cur, $carveSet));
        $rawRules = ['block' => $fileRef("raw/$id/rules/block.json"),
                     'redirect' => $fileRef("raw/$id/rules/redirect.json")];
        $curRules = ['block' => $fileRef("curated/$id/rules/block.json"),
                     'redirect' => $fileRef("curated/$id/rules/redirect.json")];
    }
    $srcEntry($id, [
        'kind' => 'hosts', 'sheet' => null, 'role' => 'block',
        'matching' => 'domain+subdomains',
        'raw' => ['domains' => $fileRef("raw/$id/domains.json"), 'rules' => $rawRules],
        'curated' => ['domains' => $fileRef("curated/$id/domains.json"), 'rules' => $curRules],
        'notes' => $tag === 'kadhosts'
            ? ['feeds the popup/redirect lane (with Sheet A); ledger dead-filtering + easylist-coverage dedup happen only at the canonical merge']
            : ['feeds the tracker domains lane (block + main_frame redirect); ledger dead-filtering + retention + easylist-coverage dedup happen only at the canonical merge'],
    ]);
}

// ---------------------------------------------------------------- easylist family
// Raw = the generators' .work output (regenerated above — the DNR form of the raw
// snapshots, zero curation). Curated = the committed sanitized/easylist lanes.
// Per-type concat keeps compile's kind order; every emitted file re-IDs 1..N.
$stripCssTimestamp = fn (string $css): string =>
    (string) preg_replace('/^\s*\*\s*Generated:.*\R/m', '', $css);
foreach ($CATS as $cat) {
    $id = "easylist-$cat";
    foreach ([['raw', $WORK], ['curated', "$SAN/easylist"]] as [$stageName, $base]) {
        $allowRules = array_merge(
            cat_json("$base/$cat/allow/network.json", "$id $stageName allow/network"),
            cat_json("$base/$cat/allow/popup.json", "$id $stageName allow/popup"),
        );
        $blockRules = array_merge(
            cat_json("$base/$cat/block/domains.json", "$id $stageName block/domains"),
            cat_json("$base/$cat/block/popup.json", "$id $stageName block/popup"),
            cat_json("$base/$cat/block/urlfilter.json", "$id $stageName block/urlfilter"),
        );
        $stageJson("$stageName/$id/rules/all.json", reid(array_merge($allowRules, $blockRules)));
        $stageJson("$stageName/$id/rules/block.json", reid($blockRules));
        $stageJson("$stageName/$id/rules/allow.json", reid($allowRules));
        $stageJson("$stageName/$id/domains.json", extract_block_domains($blockRules));
        $unhide = cat_json("$base/$cat/allow/unhide.json", "$id $stageName unhide");
        $stage("$stageName/$id/cosmetic/unhide.json", json_out($unhide, true) . "\n", count($unhide));
        if (is_file("$base/$cat/css/specific.json")) {
            $specific = cat_json("$base/$cat/css/specific.json", "$id $stageName css/specific");
            $extended = cat_json("$base/$cat/css/extended.json", "$id $stageName css/extended");
            $stage("$stageName/$id/cosmetic/specific.json", json_out($specific, true) . "\n", count($specific));
            $stage("$stageName/$id/cosmetic/extended.json", json_out($extended, true) . "\n", count($extended));
            $css = (string) file_get_contents("$base/$cat/css/generic.css");
            $stage("$stageName/$id/cosmetic/generic.css", $stripCssTimestamp($css), null);
        }
    }
    $hasCss = is_file("$SAN/easylist/$cat/css/specific.json");
    if ($hasCss !== is_file("$WORK/$cat/css/specific.json")) {
        fail("cosmetic presence mismatch for $cat: .work and sanitized/ disagree — mixed generator generation");
    }
    $cosmetic = function (string $stageName) use ($id, $hasCss, $fileRef): array {
        $c = ['unhide' => $fileRef("$stageName/$id/cosmetic/unhide.json")];
        if ($hasCss) {
            $c['specific'] = $fileRef("$stageName/$id/cosmetic/specific.json");
            $c['extended'] = $fileRef("$stageName/$id/cosmetic/extended.json");
            $c['generic_css'] = $fileRef("$stageName/$id/cosmetic/generic.css");
        }
        return $c;
    };
    $rulesRefs = fn (string $s): array => [
        'all' => $fileRef("$s/$id/rules/all.json"),
        'block' => $fileRef("$s/$id/rules/block.json"),
        'allow' => $fileRef("$s/$id/rules/allow.json"),
    ];
    $srcEntry($id, [
        'kind' => 'easylist', 'sheet' => null, 'role' => 'block+allow',
        'matching' => null,
        'raw' => ['domains' => $fileRef("raw/$id/domains.json"), 'rules' => $rulesRefs('raw'),
                  'cosmetic' => $cosmetic('raw')],
        'curated' => ['domains' => $fileRef("curated/$id/domains.json"), 'rules' => $rulesRefs('curated'),
                      'cosmetic' => $cosmetic('curated')],
        'notes' => ['domains.json is PARTIAL: block-rule requestDomains + pure ||domain^ anchors — path/pattern rules carry no domain',
                    'cosmetic is never curated (policy): raw and curated cosmetic differ only by regeneration',
                    'allow-lane requestDomains may contain wildcard-TLD entries (literal *) inherited from @@||name.*^ patterns'],
    ]);
}

// ---------------------------------------------------------------- fleet (extension)
$fleetWLPath = "$ROOT/sources/extension/whitelist/user-extension-whitelist.json";
$fleetWL = cat_load_mirror($fleetWLPath, 'fleet whitelist');
if (!$fleetWL) fail('fleet whitelist mirror is empty — refusing to publish an empty raw lane (fail-closed)');
$copyFile('raw/extension-whitelist/domains.json', $fleetWLPath, 'fleet whitelist', count($fleetWL));
$stageJson('raw/extension-whitelist/rules/allow.json', chunk_allow_rules($fleetWL));
$userWL = cat_load_mirror("$SAN/extension/user-whitelist.json", 'user whitelist (sanitized)');
$copyFile('curated/extension-whitelist/domains.json', "$SAN/extension/user-whitelist.json",
    'user whitelist (sanitized)', count($userWL));
$stageJson('curated/extension-whitelist/rules/allow.json', chunk_allow_rules($userWL));
$srcEntry('extension-whitelist', [
    'kind' => 'extension', 'sheet' => null, 'role' => 'allow',
    'matching' => 'domain+subdomains',
    'raw' => ['domains' => $fileRef('raw/extension-whitelist/domains.json'),
              'rules' => ['allow' => $fileRef('raw/extension-whitelist/rules/allow.json')]],
    'curated' => ['domains' => $fileRef('curated/extension-whitelist/domains.json'),
                  'rules' => ['allow' => $fileRef('curated/extension-whitelist/rules/allow.json')]],
    'notes' => ['raw = the 4 backends merged, pre-vote-bar — includes gamed "click Allow to continue" votes; curated = votes ≥ the trust bar − omit-from-whitelist − omit-from-blocklist (derived in curate.php)'],
]);

$fleetBLPath = "$ROOT/sources/extension/blocklist/user-extension-blocklist.json";
$fleetBL = is_file($fleetBLPath) ? cat_load_mirror($fleetBLPath, 'fleet blocklist') : [];
$fleetBL = array_values(array_unique($fleetBL));
sort($fleetBL, SORT_STRING);
$stageJson('raw/extension-blocklist/domains.json', $fleetBL);
$stageJson('raw/extension-blocklist/rules/block.json', chunk_block_rules($fleetBL));
$fleetBLKept = [];
foreach ($fleetBL as $d) if (!isWhitelistCovered($d, $never)) $fleetBLKept[] = $d;
$stageJson('curated/extension-blocklist/domains.json', $fleetBLKept);
$stageJson('curated/extension-blocklist/rules/block.json', chunk_block_rules($fleetBLKept, $never));
$srcEntry('extension-blocklist', [
    'kind' => 'extension', 'sheet' => null, 'role' => 'append',
    'matching' => 'domain+subdomains',
    'raw' => ['domains' => $fileRef('raw/extension-blocklist/domains.json'),
              'rules' => ['block' => $fileRef('raw/extension-blocklist/rules/block.json')]],
    'curated' => ['domains' => $fileRef('curated/extension-blocklist/domains.json'),
                  'rules' => ['block' => $fileRef('curated/extension-blocklist/rules/block.json')]],
    'notes' => ['mirror absent today (compile fail-softs it to empty) — cells stay declared so the shape is stable when it appears',
                'append lane like Sheets D/G: above curation, floored only by the never-block floor'],
]);

// ---------------------------------------------------------------- merged
// The canonical merge is dist/network/rules.json (alias, user decision — never a second
// compile). Materialized here: per-action subsets (canonical band IDs KEPT so every rule
// cross-references back) and the domain rollups.
$mergedRules = json_decode($rulesJsonRaw, true);
if (!is_array($mergedRules) || !$mergedRules) fail('dist/network/rules.json is not a rule array');
// dynamic per-action split: a future modifyHeaders/allowAllRequests band ships as its
// own merged/rules/<type>.json instead of turning the publish chain red (review 2026-09-10)
$byType = [];
foreach ($mergedRules as $rule) {
    $type = (string) ($rule['action']['type'] ?? '');
    if ($type === '' || !preg_match('/^[a-zA-Z]+$/', $type)) {
        fail("invalid action type '$type' in dist/network/rules.json");
    }
    $byType[$type][] = $rule;
}
if (array_sum(array_map('count', $byType)) !== count($mergedRules)) fail('merged split lost rules');
ksort($byType);
$mergedRuleRefs = [];
foreach ($byType as $type => $typedRules) {
    $stageJson("merged/rules/$type.json", $typedRules);
    $mergedRuleRefs[$type] = $fileRef("merged/rules/$type.json");
}

// Domain rollups PER TYPE (user's sketch 2026-09-10: one merged domains file per rule
// type — block, redirect, allow, cosmetic — never fused together).
$domainsOfRules = function (array $rules): array {
    $set = [];
    foreach ($rules as $rule) {
        foreach ($rule['condition']['requestDomains'] ?? [] as $d) $set[strtolower((string) $d)] = true;
        $uf = $rule['condition']['urlFilter'] ?? '';
        // end-anchored: only a PURE ||domain^ anchor names its domain as a target
        if (is_string($uf) && preg_match('/^\|\|([a-z0-9-]+(?:\.[a-z0-9-]+)+)\^$/i', $uf, $m)) {
            $set[strtolower($m[1])] = true;
        }
    }
    $out = array_keys($set);
    sort($out, SORT_STRING);
    return $out;
};
$stageJson('merged/domains/block.json', $domainsOfRules($byType['block'] ?? []));
$stageJson('merged/domains/redirect.json', $domainsOfRules($byType['redirect'] ?? []));

$mergedCosmeticDomains = [];
foreach (['specific', 'extended', 'unhide'] as $map) {
    foreach (array_keys(cat_json("$ROOT/dist/cosmetic/$map.json", "dist/cosmetic/$map.json")) as $host) {
        if ($host !== '*') $mergedCosmeticDomains[strtolower((string) $host)] = true;
    }
}
$mergedCosmeticDomains = array_keys($mergedCosmeticDomains);
sort($mergedCosmeticDomains, SORT_STRING);
$stageJson('merged/domains/cosmetic.json', $mergedCosmeticDomains);

$mergedAllowDomains = [];
foreach (['default', 'community', 'download-sites'] as $flavour) {
    foreach (cat_json("$ROOT/dist/whitelist/$flavour.json", "dist/whitelist/$flavour.json") as $d) {
        $mergedAllowDomains[strtolower((string) $d)] = true;
    }
}
$mergedAllowDomains = array_keys($mergedAllowDomains);
sort($mergedAllowDomains, SORT_STRING);
$stageJson('merged/domains/allow.json', $mergedAllowDomains);

$mergedSection = [
    'canonical' => [
        'rules_all' => ['path' => 'network/rules.json', 'count' => count($mergedRules),
                        'note' => 'THE merged artifact — band re-ID, budgets, shadow-diff gate; the catalog never duplicates it'],
        'cosmetic' => ['path' => 'cosmetic/', 'note' => 'merged cosmetic (generic.css + specific/extended/unhide maps)'],
        'whitelists' => ['path' => 'whitelist/', 'note' => 'the three product whitelist flavours (default · community · download-sites)'],
        'popup_domains' => ['path' => 'blocklist/popup-curated.json', 'note' => 'the redirect lane as a flat array (post-ledger, = rules.json)'],
    ],
    'rules' => $mergedRuleRefs,
    'domains' => [
        'block' => $fileRef('merged/domains/block.json'),
        'redirect' => $fileRef('merged/domains/redirect.json'),
        'allow' => $fileRef('merged/domains/allow.json'),
        'cosmetic' => $fileRef('merged/domains/cosmetic.json'),
    ],
    'notes' => ['merged/rules/* keep the CANONICAL band IDs (redirect 11000+ · block 21000+ · allow 41000+) — subsets of one coherent ID space, cross-referenceable to network/rules.json',
                'merged domains are split PER TYPE (user sketch 2026-09-10): block.json = block-rule targets · redirect.json = redirect-rule targets (the popup lane) · a domain blocked via redirect only is NOT in block.json — union them for "everything blocked"',
                'merged/domains/{block,redirect}.json are PARTIAL like every extraction: listed requestDomains + pure ||domain^ anchors; pattern rules carry no domain',
                'merged/domains/allow.json = union of the three whitelist flavours (different consumers — read whitelist/ for the split); cosmetic.json = every hostname carrying a specific/extended/unhide cosmetic entry (generic.css is site-wide, no domain)'],
];

// ============================================================================
// ⑤ INDEX + WRITE-OUT — catalog.json is the manifest of this layer
// ============================================================================
$indexArtifacts = [];
foreach ($artifacts as $rel => $a) {
    $indexArtifacts["catalog/$rel"] = [
        'sha256' => hash('sha256', $a['content']),
        'bytes'  => strlen($a['content']),
    ];
    if ($a['count'] !== null) $indexArtifacts["catalog/$rel"]['count'] = $a['count'];
}
ksort($indexArtifacts);
ksort($catalogSources);
$version = hash('sha256', json_out(array_map(fn ($a) => $a['sha256'], $indexArtifacts), false));
$catalogIndex = [
    'schema'  => 1,
    'version' => $version,
    'built_from' => ['dist_manifest_version' => $manifest['version'] ?? null],
    'contract' => [
        'stages' => [
            'raw'     => 'each source verbatim, BEFORE any subtraction — inspection/composition only, NEVER shippable as-is (predates the never-block floor, the vetoes and the curation set)',
            'curated' => 'each source after its own curation recipe (from sanitized/ — curate.php is the only place subtraction is derived); safe standalone, but pre-ledger and pre-merge-dedup',
            'merged'  => 'the cross-source cumulés; the canonical merge stays network/rules.json',
        ],
        'ids' => 'per-file sequential 1..N — files are loadable as SEPARATE DNR rulesets (Chrome scopes rule-ID uniqueness per ruleset); concatenating catalog files into ONE ruleset requires re-IDing, which the canonical merge already does. merged/rules/* keep the canonical band IDs instead.',
        'budgets' => 'Chrome DNR budgets apply to what a consumer LOADS, not per file — combine lanes under your own budget using the counts below (canonical caps: 30,000 rules · 5,000 redirect/modifyHeaders · 1,000 regex)',
        'absent_cells' => 'a missing cell is information, not an omission: veto sheets produce no rules by definition, cosmetic exists only for easylist/fanboy, download-sites has no raw rules (normalization is the curate recipe)',
    ],
    'sources' => $catalogSources,
    'merged'  => $mergedSection,
    'artifacts' => $indexArtifacts,
];

$CATDIR = "$ROOT/dist/catalog";
foreach ($artifacts as $rel => $a) {
    atomic_write("$CATDIR/$rel", $a['content']);
}
atomic_write("$CATDIR/catalog.json", json_out($catalogIndex, true) . "\n");
// prune: anything under dist/catalog/ not staged this run is stale
if (is_dir($CATDIR)) {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($CATDIR, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $p = $f->getPathname();
        if ($f->isDir()) { @rmdir($p); continue; }
        $rel = substr($p, strlen("$CATDIR/"));
        if ($rel !== 'catalog.json' && !isset($artifacts[$rel])) unlink($p);
    }
}

// ============================================================================
// REPORT
// ============================================================================
$elapsed = round(microtime(true) - $t0, 1);
$totBytes = array_sum(array_map(fn ($a) => strlen($a['content']), $artifacts));
$nRaw = count(array_filter(array_keys($artifacts), fn ($r) => str_starts_with($r, 'raw/')));
$nCur = count(array_filter(array_keys($artifacts), fn ($r) => str_starts_with($r, 'curated/')));
$nMer = count(array_filter(array_keys($artifacts), fn ($r) => str_starts_with($r, 'merged/')));
$rep = [];
$rep[] = '# Catalog — ' . gmdate('Y-m-d H:i') . " UTC · {$elapsed}s";
$rep[] = '';
$rep[] = '| section | files |';
$rep[] = '|---|---|';
$rep[] = "| raw/ | $nRaw |";
$rep[] = "| curated/ | $nCur |";
$rep[] = "| merged/ | $nMer |";
$rep[] = '| total | ' . count($artifacts) . ' + catalog.json · ' . round($totBytes / 1048576, 1) . ' MB |';
$rep[] = '| sources indexed | ' . count($catalogSources) . ' |';
$rep[] = '| merged split | ' . implode(' · ', array_map(fn ($k, $v) => "$k " . count($v), array_keys($byType), $byType)) . ' (= ' . count($mergedRules) . ') |';
$rep[] = '| version | `' . substr($version, 0, 12) . '…` |';
$md = implode("\n", $rep) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit(0);
