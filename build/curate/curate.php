<?php
// build/curate/curate.php — the curation stage (user re-conception, 2026-09-08 evening).
//
// Sits BETWEEN the verbatim mirrors (sources/, machine-fetched but human-auditable) and
// the consumers (verify + compile). Mirrors stay exactly as fetched; every subtraction
// happens here, per source, and lands in sanitized/ — machine-owned, committed, so each
// curation decision is a reviewable git diff.
//
//   step 1 · user whitelist raw  = all-extension.csv merged votes ≥ COMMUNITY_MIN_VOTES
//   step 2 · user whitelist      = step 1 − Sheet G (exact-host veto)
//   curation set                 = Sheet H ∪ Sheet I (download sites) ∪ user whitelist
//                                  (all matched domain + subdomains)
//   per-source recipes (user decisions 2026-09-08):
//     Sheet A (popup)     − curation set                → sanitized/gsheet/popup.json
//     hosts lanes (4)     − curation set                → sanitized/hosts/<tag>.txt
//     easylist family     — generators run here; DNR block lanes scrubbed with the full
//                           engine (batch strip + carve · ||-anchor · wildcard-TLD incl.
//                           deeper family members · generic-main_frame initiators) and
//                           DNR allow lanes under the SELF-PROTECTION policy (allows on
//                           curated destinations/initiators kept — they only ever protect
//                           those sites; mixed batches strip curated members — see
//                           scrubAllowRules); cosmetic outputs
//                           (css/*, allow/unhide.json) pass through UNCURATED
//                                                       → sanitized/easylist/<cat>/...
//     Sheets C · B · J–N  — no curation (C is product-only; B and J–N verbatim)
//     Sheets D · F + fleet blocklist — ABOVE curation: deliberate blocks are never
//                           scrubbed (only the H floor at compile); overlaps are flagged
//     Sheet E             — mirrored but takes part in NO recipe (user: decide later)
//
// Consumers: sanitized/curation-set.json is THE single derivation of the curation set —
// compile (carve-outs, twin-initiator stripping, final asserts), ledger (nothing to
// skip: it just tests sanitized candidates) and shadow_diff (divergence classification)
// all read it instead of re-deriving. The old keep-three-in-sync problem is gone.
//
// Fail-closed doctrine: every output is computed and validated BEFORE the first byte
// lands in sanitized/ (staged writes, tmp+rename). A failed run leaves the previous
// sanitized/ tree untouched and exits non-zero.
//
// Sheet I bootstrap: its export URL is TBD, so the mirror may not exist yet. A MISSING
// download-sites mirror degrades to an empty set with a loud report note (the sheet is
// declared but not yet fed); once the mirror exists it must be valid or the run fails.

declare(strict_types=1);
ini_set('memory_limit', '3072M');

$ROOT = dirname(__DIR__, 2);
require $ROOT . '/build/compile/lib/util.php';
require $ROOT . '/build/compile/lib/scrub.php';

const COMMUNITY_MIN_VOTES = 50;   // the fleet trust bar (2026-09-08, was 200) — lives ONLY here

// Sheet I as a SOURCE (2026-09-08 evening): every download site gets an ABP allow rule
// with EXACTLY these type options — sub-resource unbreakage only. $document and
// $~third-party are banned by the guard below; main_frame coverage must never appear.
const DL_ALLOW_OPTIONS = 'subdocument,stylesheet,font,xmlhttprequest,media,websocket,other';
// ABP option -> DNR resourceType (same semantics as the category generators' map;
// subdocument maps to sub_frame, every other option maps to itself — and websocket/other
// are REAL entries here precisely so they can never be silently dropped)
const DL_TYPE_MAP = [
    'subdocument'    => 'sub_frame',
    'stylesheet'     => 'stylesheet',
    'font'           => 'font',
    'xmlhttprequest' => 'xmlhttprequest',
    'media'          => 'media',
    'websocket'      => 'websocket',
    'other'          => 'other',
];

$t0 = microtime(true);

function fail(string $msg): void
{
    fwrite(STDERR, "FATAL: $msg\n");
    $md = "# Curate — FAILED\n\n**$msg**\n\nPrevious sanitized/ kept (fail-closed).\n";
    echo $md;
    if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
        file_put_contents($sum, $md, FILE_APPEND);
    }
    exit(1);
}

/** Mirror loader: file must exist and be a JSON array of strings (rows kept as entered). */
function load_mirror(string $path, string $label, bool $mustBeNonEmpty): array
{
    if (!is_file($path)) fail("$label mirror missing: $path");
    $arr = json_decode((string) file_get_contents($path), true);
    if (!is_array($arr)) fail("$label mirror is not a JSON array: $path");
    $out = [];
    foreach ($arr as $row) {
        if (!is_string($row)) fail("$label mirror has a non-string row: $path");
        $row = rtrim(strtolower(trim($row)), '.');
        if ($row !== '') $out[] = $row;
    }
    if ($mustBeNonEmpty && !$out) fail("$label mirror is empty: $path");
    return $out;
}

// ============================================================================
// ① CURATION INPUTS
// ============================================================================
$G = load_mirror("$ROOT/sources/gsheet/omit-from-whitelist.json", 'Sheet G', false);
$H = load_mirror("$ROOT/sources/gsheet/omit-from-blocklist.json", 'Sheet H', true);
$downloadPath = "$ROOT/sources/gsheet/download-sites.json";
$downloadMissing = !is_file($downloadPath);
$I = $downloadMissing ? [] : load_mirror($downloadPath, 'Sheet I (download-sites)', false);

// ---- Sheet I normalization + its own curation (user spec 2026-09-08 evening) ----
// step 1: normalize each row — lowercase/trim (load_mirror), strip protocol, path/query/
//         fragment, port, "www." prefix and trailing dot; dedupe. Empty rows are ignored;
//         non-hostname rows WARN and are skipped — never a failure (sheets are human
//         territory, one bad row must not hold the whole pipeline red).
// step 2: − Sheet G (exact host) — the same editorial veto the user whitelist gets.
//         The curated+normalized list feeds BOTH roles of Sheet I: the curation set
//         (a G-vetoed download site is fully retracted) and the allow-list source below.
$dlWarnings = [];
$dlSet = [];
foreach ($I as $row) {
    $s = (string) preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $row);   // protocol
    $s = (string) preg_replace('#[/?\#].*$#', '', $s);                 // path / query / fragment
    $s = (string) preg_replace('#:\d+$#', '', $s);                     // port
    $s = rtrim($s, '.');
    if (str_starts_with($s, 'www.')) $s = substr($s, 4);
    if ($s === '') continue;
    if (filter_var($s, FILTER_VALIDATE_IP) !== false
        || !preg_match('/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/', $s)) {
        $dlWarnings[] = $row;
        continue;
    }
    $dlSet[$s] = true;
}
$dlVetoed = [];
foreach ($G as $g) {
    if (isset($dlSet[$g])) { $dlVetoed[] = $g; unset($dlSet[$g]); }
}
$dlSites = array_keys($dlSet);
sort($dlSites, SORT_STRING);
sort($dlVetoed, SORT_STRING);

// user whitelist — step 1: merged fleet votes ≥ the trust bar
$fleetCsv = "$ROOT/sources/extension/whitelist/raw/all-extension.csv";
if (!is_file($fleetCsv)) fail("fleet votes CSV missing: $fleetCsv");
$userRaw = [];
foreach (array_slice(file($fleetCsv, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [], 1) as $line) {
    [$d, $c] = array_pad(explode(',', $line, 2), 2, '0');
    $d = rtrim(strtolower(trim($d)), '.');
    if ($d !== '' && (int) $c >= COMMUNITY_MIN_VOTES) $userRaw[$d] = true;
}
if (!$userRaw) fail('user whitelist step 1 empty — no domain reaches ' . COMMUNITY_MIN_VOTES . " votes in $fleetCsv?");
// step 2: − G (exact host — the editorial veto for gamed votes)
$userWL = $userRaw;
$userVetoed = [];
foreach ($G as $g) {
    if (isset($userWL[$g])) { $userVetoed[] = $g; unset($userWL[$g]); }
}
if (!$userWL) fail('user whitelist step 2 empty — G vetoed everything?');

// the curation set — every recipe below subtracts THIS (domain + subdomains).
// Sheet I contributes its NORMALIZED, G-vetoed form ($dlSites), never the raw rows.
$curation = [];
foreach ([$H, $dlSites, array_keys($userWL)] as $src) foreach ($src as $d) $curation[$d] = true;

// ============================================================================
// ② SHEET A (popup) − curation set
// ============================================================================
$A = load_mirror("$ROOT/sources/gsheet/popup.json", 'Sheet A', true);
$popupKept = [];
$popupDropped = [];
foreach ($A as $row) {
    $norm = normalize_domain($row);
    $raw  = clean_domain($row);
    $covered = ($norm !== '' && isWhitelistCovered($norm, $curation))
            || ($raw !== null && isWhitelistCovered($raw, $curation));
    if ($covered) { $popupDropped[] = $row; continue; }
    $popupKept[] = $row;   // rows kept exactly as entered — sanitized A is still a row list
}
if (!$popupKept) fail('sanitized Sheet A is empty — curation set swallowed the whole sheet?');

// ============================================================================
// ③ HOSTS LANES − curation set
// ============================================================================
$HOSTS = [
    'anudeep'    => "$ROOT/sources/hosts/anudeep.txt",
    'peterlowe'  => "$ROOT/sources/hosts/peterlowe.txt",
    'adguarddns' => "$ROOT/sources/hosts/adguarddns.txt",
    'kadhosts'   => "$ROOT/sources/hosts/kadhosts.txt",
];
$hostsKept = [];
$hostsDropped = [];
foreach ($HOSTS as $tag => $path) {
    $all = load_hosts_file($path);
    if (!$all) fail("hosts snapshot empty/missing: $path");
    $kept = [];
    $dropped = [];
    foreach ($all as $d => $_) {
        if (isWhitelistCovered($d, $curation)) { $dropped[] = $d; continue; }
        $kept[] = $d;
    }
    if (!$kept) fail("sanitized $tag is empty — curation set swallowed the whole snapshot?");
    sort($kept, SORT_STRING);
    sort($dropped, SORT_STRING);
    $hostsKept[$tag] = $kept;
    $hostsDropped[$tag] = $dropped;
}

// ============================================================================
// ④ EASYLIST FAMILY — generate raw DNR lanes, then curate them
// ============================================================================
$CATS = ['adult', 'easylist', 'easyprivacy', 'fanboy'];
$COMPILE = $ROOT . '/build/compile';
$WORK = $COMPILE . '/.work';
// stale intermediates must never survive into a curation pass
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
function work_json(string $path): array
{
    if (!is_file($path)) fail('expected generator output missing: ' . $path);
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) fail('generator output is not valid JSON: ' . $path);
    return $data;
}

// initiatorsStripped pre-seeded so the committed report's schema never flip-flops
// between runs that do and don't strip one
$blockStats = ['domainsRemoved' => 0, 'rulesDropped' => 0, 'exclusionsAdded' => 0, 'initiatorsStripped' => 0];
$allowStats = ['domainsRemoved' => 0, 'rulesDropped' => 0, 'exclusionsAdded' => 0];
$easylistOut = [];          // rel path under sanitized/easylist/ => JSON string
$cosmeticOut = [];          // rel path => verbatim bytes (cosmetic is NEVER curated)
foreach ($CATS as $cat) {
    foreach ([['block', 'domains.json'], ['block', 'popup.json'], ['block', 'urlfilter.json']] as [$folder, $file]) {
        $rules = scrubBlockRules(work_json("$WORK/$cat/$folder/$file"), $curation, $blockStats);
        $easylistOut["$cat/$folder/$file"] = json_out(array_values($rules), false);
    }
    foreach ([['allow', 'network.json'], ['allow', 'popup.json']] as [$folder, $file]) {
        $rules = scrubAllowRules(work_json("$WORK/$cat/$folder/$file"), $curation, $allowStats);
        $easylistOut["$cat/$folder/$file"] = json_out(array_values($rules), false);
    }
    // cosmetic pass-through (user decision: keep cosmetic): unhide map + css outputs.
    // Expectations are EXPLICIT (adversarial review): every category emits unhide.json;
    // only easylist + fanboy ship css files (adult/easyprivacy have no upstream cosmetic
    // sources — their generators were deleted). A missing EXPECTED file is a hard fail:
    // silently skipping would ship a cosmetic-less tree and prune the last good copy.
    // The generators stamp "* Generated: <time> UTC" into generic.css — sanitized/ is
    // COMMITTED, so that timestamp is stripped here or every run churns a commit
    // (byte-determinism doctrine: unchanged content never churns).
    $unhide = "$WORK/$cat/allow/unhide.json";
    if (!is_file($unhide)) fail("expected cosmetic output missing: $unhide");
    $cosmeticOut["$cat/allow/unhide.json"] = (string) file_get_contents($unhide);
    $catShipsCss = in_array($cat, ['easylist', 'fanboy'], true);
    foreach (['generic.css', 'specific.json', 'extended.json'] as $cssFile) {
        $p = "$WORK/$cat/css/$cssFile";
        if (!is_file($p)) {
            if ($catShipsCss) fail("expected cosmetic output missing: $p");
            continue;
        }
        $content = (string) file_get_contents($p);
        if ($cssFile === 'generic.css') {
            $content = (string) preg_replace('/^\s*\*\s*Generated:.*\R/m', '', $content);
        }
        $cosmeticOut["$cat/css/$cssFile"] = $content;
    }
}

// ============================================================================
// ⑤ DOWNLOAD-SITES SOURCE — Sheet I → download_sites.txt (ABP) → DNR allow lane
// ============================================================================
// The .txt is regenerated (overwritten) every run, then PARSED back — the DNR lane is
// derived from the artifact, not from the in-memory list, so the guard and the
// option-mapping verification exercise the real file. This lane deliberately BYPASSES
// scrubAllowRules: its destinations ARE curated domains — these allows exist because of
// that, to neutralize the generic path-pattern blocks curation cannot reach.
$dlTxt = "[All-in-one 2.0]\n"
       . "! Title: protect\n"
       . "! Generated from Google Sheet — do not edit by hand\n";
foreach ($dlSites as $d) {
    $dlTxt .= '@@||' . $d . '^$' . DL_ALLOW_OPTIONS . "\n";
}

// GUARD (user 2026-09-08): the build FAILS if the generated list ever carries $document
// (whole-page whitelisting) or $~third-party (party-scope flip), or any non-@@ rule line.
if (strpos($dlTxt, '$document') !== false)     fail('download_sites.txt guard: $document present');
if (strpos($dlTxt, '$~third-party') !== false) fail('download_sites.txt guard: $~third-party present');
$dlRules = [];
foreach (explode("\n", rtrim($dlTxt, "\n")) as $ln => $line) {
    if ($line === '' || $line[0] === '!' || $line[0] === '[') continue;   // header + comments
    if (strpos($line, '@@') !== 0) {
        fail('download_sites.txt guard: rule line ' . ($ln + 1) . " does not start with @@: $line");
    }
    if (!preg_match('/^@@\|\|([a-z0-9.-]+)\^\$([a-z,]+)$/', $line, $m)) {
        fail('download_sites.txt guard: line ' . ($ln + 1) . " does not match the allow template: $line");
    }
    $types = [];
    foreach (explode(',', $m[2]) as $opt) {
        // every option MUST map — an unmapped option silently dropped (the websocket/other
        // failure mode) would narrow the allow behind our back; fail instead
        if (!isset(DL_TYPE_MAP[$opt])) {
            fail('download_sites.txt guard: unmapped ABP option \'' . $opt . '\' on line ' . ($ln + 1));
        }
        $types[] = DL_TYPE_MAP[$opt];
    }
    sort($types, SORT_STRING);
    $dlRules[] = [
        'id'        => 0,
        'priority'  => 2,   // strictly above every block (priority 1) — compile asserts this globally
        'action'    => ['type' => 'allow'],
        'condition' => ['urlFilter' => '||' . $m[1] . '^', 'resourceTypes' => $types],
    ];
}
if (count($dlRules) !== count($dlSites)) {
    fail('download_sites.txt guard: parsed rule count (' . count($dlRules) . ') != site count (' . count($dlSites) . ')');
}

// ============================================================================
// ⑥ STAGED WRITE-OUT — everything computed; now (and only now) touch sanitized/
// ============================================================================
$userOut = array_keys($userWL);
sort($userOut, SORT_STRING);
$userRawOut = array_keys($userRaw);
sort($userRawOut, SORT_STRING);
$curationOut = array_keys($curation);
sort($curationOut, SORT_STRING);
sort($userVetoed, SORT_STRING);
sort($popupDropped, SORT_STRING);

// Provenance: hash every INPUT this run consumed. compile.php refuses to assemble when
// any of these has moved since — closing the mixed-generation hole (fresh mirrors +
// stale sanitized/ must never publish; a red ingest commits per-sheet successes but
// skips curate, and the 07:00 cron compile would otherwise publish the mix).
$provInputs = [
    'sources/gsheet/omit-from-whitelist.json',
    'sources/gsheet/omit-from-blocklist.json',
    'sources/gsheet/download-sites.json',        // hashes as 'MISSING' while the sheet bootstraps
    'sources/gsheet/popup.json',
    'sources/extension/whitelist/raw/all-extension.csv',
    'sources/hosts/anudeep.txt',
    'sources/hosts/peterlowe.txt',
    'sources/hosts/adguarddns.txt',
    'sources/hosts/kadhosts.txt',
];
$itProv = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator("$ROOT/sources/easylist", FilesystemIterator::SKIP_DOTS)
);
foreach ($itProv as $f) {
    if ($f->isFile()) $provInputs[] = substr($f->getPathname(), strlen("$ROOT/"));
}
$prov = [];
foreach ($provInputs as $rel) {
    $prov[$rel] = is_file("$ROOT/$rel") ? hash_file('sha256', "$ROOT/$rel") : 'MISSING';
}
ksort($prov);

$artifacts = [];   // rel path under sanitized/ => content
$artifacts['provenance.json'] = json_out($prov, true);
$artifacts['extension/user-whitelist-raw.json'] = json_out($userRawOut, true);   // step 1
$artifacts['extension/user-whitelist.json']     = json_out($userOut, true);      // step 2
$artifacts['curation-set.json']                 = json_out($curationOut, true);  // H ∪ I ∪ userWL
$artifacts['gsheet/popup.json']                 = json_out($popupKept, true);
$artifacts['download-sites.txt']                = $dlTxt;                        // ABP list, overwritten every run
$artifacts['download-sites/allow.json']         = json_out($dlRules, false);     // its DNR allow lane
foreach ($hostsKept as $tag => $kept) {
    $artifacts["hosts/$tag.txt"] = implode("\n", $kept) . "\n";
}
foreach ($easylistOut as $rel => $content) $artifacts["easylist/$rel"] = $content;
foreach ($cosmeticOut as $rel => $content) $artifacts["easylist/$rel"] = $content;

foreach ($artifacts as $rel => $content) {
    atomic_write("$ROOT/sanitized/$rel", $content);
}
// prune: anything in sanitized/ not staged this run is stale and must not survive
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator("$ROOT/sanitized", FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($it as $f) {
    $p = $f->getPathname();
    if ($f->isDir()) { @rmdir($p); continue; }
    $rel = substr($p, strlen("$ROOT/sanitized/"));
    if (!isset($artifacts[$rel])) unlink($p);
}

// review artifact — decisions belong in the Sheets, never here. Timestamp-free.
$review = [
    'note' => 'Regenerated by build/curate/curate.php. Per-source curation drops — resolutions go '
        . 'into the Sheets (H / I / G), never into this file.',
    'user_whitelist_vetoed_by_G'   => $userVetoed,
    'sheet_a_dropped'              => $popupDropped,
    'hosts_dropped'                => $hostsDropped,
    'easylist_block'               => $blockStats,
    'easylist_allow'               => $allowStats,
    'download_sites_mirror_missing' => $downloadMissing,
    'download_sites_invalid_rows'  => $dlWarnings,   // warned + skipped, never a failure
    'download_sites_vetoed_by_G'   => $dlVetoed,
];
atomic_write("$ROOT/state/review/curation-drops.json", json_out($review, true) . "\n");

// ============================================================================
// REPORT
// ============================================================================
$elapsed = round(microtime(true) - $t0, 1);
$rep = [];
$rep[] = '# Curate — ' . gmdate('Y-m-d H:i') . " UTC · {$elapsed}s";
$rep[] = '';
$rep[] = '| stage | result |';
$rep[] = '|---|---|';
$rep[] = '| ① user whitelist | step 1 (votes ≥' . COMMUNITY_MIN_VOTES . ') ' . count($userRawOut) . ' → step 2 (−G) ' . count($userOut) . ' (vetoed ' . count($userVetoed) . ') |';
$rep[] = '| ① download sites (Sheet I) | ' . count($I) . ' rows → ' . count($dlSites) . ' normalized (invalid ' . count($dlWarnings) . ' **warned** · vetoed by G ' . count($dlVetoed) . ')' . ($downloadMissing ? ' **[mirror missing — sheet URL TBD]**' : '') . ' |';
$rep[] = '| ① curation set (H ∪ I ∪ userWL) | ' . count($curationOut) . ' domains (H ' . count($H) . ' · I ' . count($dlSites) . ' · userWL ' . count($userOut) . ') |';
$rep[] = '| ② Sheet A | ' . count($popupKept) . ' kept · ' . count($popupDropped) . ' curated out |';
$hostsCell = [];
foreach ($hostsKept as $tag => $kept) $hostsCell[] = "$tag " . count($kept) . ' (−' . count($hostsDropped[$tag]) . ')';
$rep[] = '| ③ hosts lanes | ' . implode(' · ', $hostsCell) . ' |';
$rep[] = '| ④ easylist block lanes | ' . $blockStats['domainsRemoved'] . ' domains removed · ' . $blockStats['rulesDropped'] . ' rules dropped · ' . $blockStats['exclusionsAdded'] . ' carve-outs · ' . ($blockStats['initiatorsStripped'] ?? 0) . ' generic main_frame initiators stripped |';
$rep[] = '| ④ easylist allow lanes (self-protection kept · mixed batches stripped) | ' . $allowStats['domainsRemoved'] . ' curated members stripped from mixed batches · ' . $allowStats['rulesDropped'] . ' rules dropped (policy: always 0) |';
$rep[] = '| ④ cosmetic | pass-through, never curated |';
$rep[] = '| ⑤ download_sites.txt (ABP allow source) | ' . count($dlRules) . ' rules (@@||domain^$' . DL_ALLOW_OPTIONS . ') · guards OK ($document/$~third-party/non-@@ = fail) |';
if ($dlWarnings) {
    $rep[] = '';
    $rep[] = '**Sheet I rows skipped (not a valid hostname — warned, never failed)** ('
        . count($dlWarnings) . '): ' . implode(', ', array_slice($dlWarnings, 0, 20))
        . (count($dlWarnings) > 20 ? ' … +' . (count($dlWarnings) - 20) : '');
}
$rep[] = '';
$rep[] = 'Full drop lists: `state/review/curation-drops.json`';
$md = implode("\n", $rep) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit(0);
