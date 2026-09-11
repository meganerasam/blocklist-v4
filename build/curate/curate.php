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
//   curation set                 = omit-from-blocklist ∪ default-blocklist-not-to-add ∪ download-sites ∪ user whitelist
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
//                           scrubAllowRules), then the Sheet G VETO pass removes exact G
//                           hosts from BLANKET allows only (no urlFilter, no
//                           resourceTypes) — see scrubGVetoAllows, guarded; cosmetic
//                           outputs (css/*, allow/unhide.json) pass through UNCURATED
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
$omitWhitelist = load_mirror("$ROOT/sources/gsheet/omit-from-whitelist.json", 'Sheet H (omit-from-whitelist)', false);
$omitBlocklist = load_mirror("$ROOT/sources/gsheet/omit-from-blocklist.json", 'Sheet I (omit-from-blocklist)', true);
$omitBlocklistSet = [];
foreach ($omitBlocklist as $h) $omitBlocklistSet[$h] = true;   // lookup form for isWhitelistCovered (domain + subs)
// Sheet E — default-blocklist-not-to-add (2026-09-10, user decision): the veto on the
// default blocklist. Same contract as omit-from-blocklist — curation-set member here AND
// part of compile's never-block floor (which is what actually stops the Sheet D appends,
// since appends sit above curation). Kept as a SEPARATE sheet because omit-from-blocklist
// has the tightest edit access of all sheets (our own brand domains); this one is meant to
// be edited freely. Matched domain + all subdomains, like omit-from-blocklist.
// Live since 2026-09-10; the absent-mirror path stays as a fail-soft fallback.
$noAddPath = "$ROOT/sources/gsheet/default-blocklist-not-to-add.json";
$noAddMissing = !is_file($noAddPath);
$noAdd = $noAddMissing ? [] : load_mirror($noAddPath, 'Sheet E (default-blocklist-not-to-add)', false);

$downloadPath = "$ROOT/sources/gsheet/download-sites.json";
$downloadMissing = !is_file($downloadPath);
$downloadSites = $downloadMissing ? [] : load_mirror($downloadPath, 'Sheet J (download-sites)', false);

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
foreach ($downloadSites as $row) {
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
foreach ($omitWhitelist as $g) {
    if (isset($dlSet[$g])) { $dlVetoed[] = $g; unset($dlSet[$g]); }
}
// ...and − H (2026-09-09, user decision: H is vetoed everywhere G is). H keeps its OWN
// semantics here — domain + all subdomains — because that is what H means everywhere
// else; G stays exact-host. An own-brand domain must never be handed to a client-side
// whitelist: the extension has to stay active on our own pages.
$dlVetoedH = [];
foreach (array_keys($dlSet) as $d) {
    if (isWhitelistCovered($d, $omitBlocklistSet)) { $dlVetoedH[] = $d; unset($dlSet[$d]); }
}
sort($dlVetoedH, SORT_STRING);
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
foreach ($omitWhitelist as $g) {
    if (isset($userWL[$g])) { $userVetoed[] = $g; unset($userWL[$g]); }
}
// step 2b: − H (2026-09-09) — no vote count can whitelist an own-brand domain and
// switch the extension off on our own pages. Domain + subdomains, H's own semantics.
$userVetoedH = [];
foreach (array_keys($userWL) as $d) {
    if (isWhitelistCovered($d, $omitBlocklistSet)) { $userVetoedH[] = $d; unset($userWL[$d]); }
}
sort($userVetoedH, SORT_STRING);
if (!$userWL) fail('user whitelist step 2 empty — G/H vetoed everything?');

// the curation set — every recipe below subtracts THIS (domain + subdomains).
// Sheet I contributes its NORMALIZED, G-vetoed form ($dlSites), never the raw rows.
$curation = [];
foreach ([$omitBlocklist, $noAdd, $dlSites, array_keys($userWL)] as $src) foreach ($src as $d) $curation[$d] = true;

// ============================================================================
// ② SHEET A (popup) − curation set
// ============================================================================
$popupSheetRows = load_mirror("$ROOT/sources/gsheet/popup.json", 'Sheet A (popup)', true);
$popupKept = [];
$popupDropped = [];
foreach ($popupSheetRows as $row) {
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
// Sheet G's "public host" half (ruled 2026-09-09) — a separate pass from the curation
// scrub above, with the opposite polarity: see scrubGVetoAllows() in lib/scrub.php.
$gVetoStats = ['domainsRemoved' => 0, 'rulesDropped' => 0];
$easylistOut = [];          // rel path under sanitized/easylist/ => JSON string
$cosmeticOut = [];          // rel path => verbatim bytes (cosmetic is NEVER curated)
foreach ($CATS as $cat) {
    foreach ([['block', 'domains.json'], ['block', 'popup.json'], ['block', 'urlfilter.json']] as [$folder, $file]) {
        $rules = scrubBlockRules(work_json("$WORK/$cat/$folder/$file"), $curation, $blockStats);
        $easylistOut["$cat/$folder/$file"] = json_out(array_values($rules), false);
    }
    foreach ([['allow', 'network.json'], ['allow', 'popup.json']] as [$folder, $file]) {
        $rules = scrubAllowRules(work_json("$WORK/$cat/$folder/$file"), $curation, $allowStats);
        $rules = scrubGVetoAllows($rules, $omitWhitelist, $gVetoStats);
        $leaks = gVetoAllowLeaks($rules, $omitWhitelist);
        if ($leaks) {
            fail("Sheet G veto guard: a blanket allow still names a G host in $cat/$folder/$file — "
                . implode(', ', array_slice($leaks, 0, 10)));
        }
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
        'priority'  => DL_ALLOW_PRIORITY,  // lib/util.php owns the value (50 since 2026-09-11,
                            // was 2) — strictly above every block (1), every redirect (3) AND the
                            // extension's bundled static rulesets (10/11/40/41), which the old 2
                            // could not reach. No behavioral overlap with the redirects: this lane
                            // carries NO main_frame type, and it stays under the client's
                            // user-block tier (100), so a user's own block still wins.
                            // compile PINS the value and asserts min-allow > max-block globally.
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
    'sources/gsheet/default-blocklist-not-to-add.json',  // Sheet E — live since 2026-09-10
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
$artifacts['curation-set.json']                 = json_out($curationOut, true);  // omit-from-blocklist ∪ not-to-add ∪ download-sites ∪ userWL
$artifacts['gsheet/popup.json']                 = json_out($popupKept, true);
$artifacts['download-sites.txt']                = $dlTxt;                        // ABP list, overwritten every run
$artifacts['download-sites/allow.json']         = json_out($dlRules, false);     // its DNR allow lane
foreach ($hostsKept as $tag => $kept) {
    $artifacts["hosts/$tag.txt"] = implode("\n", $kept) . "\n";
}
// kadhosts also as JSON (2026-09-09) — it is the popup/redirect feed, so consumers want
// it in the same shape as sanitized/gsheet/popup.json: the curated domain array. Same
// content as hosts/kadhosts.txt above, different encoding; the .txt stays for the hosts
// lane readers. The other three feeds are the domains lane and keep .txt only.
$artifacts['hosts/kadhosts.json'] = json_out($hostsKept['kadhosts'], true);
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
    'user_whitelist_vetoed_by_H'   => $userVetoedH,
    'sheet_a_dropped'              => $popupDropped,
    'hosts_dropped'                => $hostsDropped,
    'easylist_block'               => $blockStats,
    'easylist_allow'               => $allowStats,
    'easylist_allow_g_veto'        => $gVetoStats,
    'download_sites_mirror_missing' => $downloadMissing,
    'download_sites_invalid_rows'  => $dlWarnings,   // warned + skipped, never a failure
    'download_sites_vetoed_by_G'   => $dlVetoed,
    'download_sites_vetoed_by_H'   => $dlVetoedH,
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
$rep[] = '| ① user whitelist | step 1 (votes ≥' . COMMUNITY_MIN_VOTES . ') ' . count($userRawOut) . ' → step 2 (−omit-whitelist −omit-blocklist) ' . count($userOut) . ' (vetoed by omit-whitelist ' . count($userVetoed) . ' · by omit-blocklist ' . count($userVetoedH) . ') |';
$rep[] = '| ① download sites (Sheet J) | ' . count($downloadSites) . ' rows → ' . count($dlSites) . ' normalized (invalid ' . count($dlWarnings) . ' **warned** · vetoed by omit-whitelist ' . count($dlVetoed) . ' · by omit-blocklist ' . count($dlVetoedH) . ')' . ($downloadMissing ? ' **[mirror missing — sheet URL TBD]**' : '') . ' |';
$rep[] = '| ① curation set (I ∪ E ∪ J ∪ userWL) | ' . count($curationOut) . ' domains (omit-from-blocklist ' . count($omitBlocklist) . ' · not-to-add ' . count($noAdd) . ($noAddMissing ? ' **[sheet TBD]**' : '') . ' · download-sites ' . count($dlSites) . ' · userWL ' . count($userOut) . ') |';
$rep[] = '| ② Sheet A | ' . count($popupKept) . ' kept · ' . count($popupDropped) . ' curated out |';
$hostsCell = [];
foreach ($hostsKept as $tag => $kept) $hostsCell[] = "$tag " . count($kept) . ' (−' . count($hostsDropped[$tag]) . ')';
$rep[] = '| ③ hosts lanes | ' . implode(' · ', $hostsCell) . ' |';
$rep[] = '| ④ easylist block lanes | ' . $blockStats['domainsRemoved'] . ' domains removed · ' . $blockStats['rulesDropped'] . ' rules dropped · ' . $blockStats['exclusionsAdded'] . ' carve-outs · ' . ($blockStats['initiatorsStripped'] ?? 0) . ' generic main_frame initiators stripped |';
$rep[] = '| ④ easylist allow lanes (self-protection kept · mixed batches stripped) | ' . $allowStats['domainsRemoved'] . ' curated members stripped from mixed batches · ' . $allowStats['rulesDropped'] . ' rules dropped (policy: always 0) |';
$rep[] = '| ④ easylist allow lanes (omit-from-whitelist veto: blanket allows only) | ' . $gVetoStats['domainsRemoved'] . ' omit-from-whitelist hosts stripped · ' . $gVetoStats['rulesDropped'] . ' rules dropped (axis would have emptied) · guard OK |';
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
