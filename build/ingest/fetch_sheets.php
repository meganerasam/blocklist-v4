<?php
// build/ingest/fetch_sheets.php
// Mirrors Google Sheets A–O (15) into sources/gsheet/*.json. Domain sheets mirror as FLAT
// sorted arrays of domain strings; only Sheet B (trackers) mirrors as objects.
// Fail-closed PER SHEET on a BROKEN sheet (fetch error, HTML login page, header mismatch,
// nothing parsed): the previous mirror is kept and the run turns red; sheets that pass are
// still written. A sheet that merely CHANGED SIZE is not broken — it was edited — so it is
// mirrored and reported as a warning, never held. Gates per sources/gsheet/SCHEMA.md.
//
// Env:
//   INGEST_FORCE=1   confirm a WIPE: let a sheet that parses to zero rows replace a
//                    non-empty mirror. Size deltas are never gated (see the loop).
//   GITHUB_STEP_SUMMARY  markdown report is appended there when set (always echoed too)

declare(strict_types=1);

$ROOT = dirname(__DIR__, 2);
$MIRROR_DIR = $ROOT . '/sources/gsheet';
$FORCE = getenv('INGEST_FORCE') === '1';

// ---------------------------------------------------------------- config ----
// Minimal parser for the `sheets:` block of sources/upstream.yml (2-space sheet
// keys, 4-space props, values quoted or bare-with-trailing-comment).
function load_sheet_specs(string $yml): array
{
    $out = [];
    $in = false;
    $cur = null;
    foreach (file($yml, FILE_IGNORE_NEW_LINES) as $ln) {
        if (preg_match('/^(\S[^:]*):\s*(#.*)?$/', $ln, $m)) { $in = ($m[1] === 'sheets'); $cur = null; continue; }
        if (!$in) continue;
        if (preg_match('/^  ([A-Za-z0-9_]+):\s*$/', $ln, $m)) { $cur = $m[1]; $out[$cur] = []; continue; }
        if ($cur && preg_match('/^    (name|mirror|export_url|note):\s*(.*)$/', $ln, $m)) {
            $v = trim($m[2]);
            if ($v !== '' && $v[0] === '"') {
                $v = substr($v, 1);
                $v = substr($v, 0, (int) strpos($v, '"'));
            } else {
                $v = trim((string) preg_replace('/\s+#.*$/', '', $v));
            }
            $out[$cur][$m[1]] = $v;
        }
    }
    return $out;
}

// Expected header + per-sheet profile for `name`.
// `warn_on_change` / `delta_pct` select the WARNING threshold for a size change — neither
// gates the run (2026-09-14). Small hand-curated sheets warn on any delta; the big
// self-moving ones only past their percentage.
// 'popup-pivot' = Sheet A's kept-as-is pivot ("Block List v3" column, quoted cells,
// Grand Total footer). Domain sheets: only the first column ('domain') is required —
// added/reason columns are sheet-side audit trail and never enter the mirror.
const SPECS = [
    'popup'                    => ['header' => ['block list v3'],                   'kind' => 'popup-pivot', 'warn_on_change' => false, 'delta_pct' => 30],
    'traffic-quality-trackers' => ['header' => ['market', 'hostname', 'nb_click'],  'kind' => 'tracker', 'warn_on_change' => false, 'delta_pct' => 30],
    'default-whitelist'        => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => true,  'delta_pct' => null],
    'default-blocklist'        => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    // Sheet E (2026-09-10): the veto on the default blocklist — a listed domain must
    // produce NO rule at all. Warns on any change, like omit-from-blocklist: a shrink
    // re-admits blocks the operator deliberately vetoed, so it should never pass unnoticed.
    'default-blocklist-not-to-add' => ['header' => ['domain'],   'kind' => 'domains', 'warn_on_change' => true,  'delta_pct' => null],
    'manual-whitelist'         => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => true,  'delta_pct' => null],
    'manual-blocklist'         => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'omit-from-whitelist'      => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'omit-from-blocklist'      => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => true,  'delta_pct' => null],
    // Sheet J (2026-09-08, re-lettered 2026-09-10): download sites — omit-style curation input; a shrink
    // strips protection from download sites, so it warns on any change like H
    'download-sites'           => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => true,  'delta_pct' => null],
    // standalone (K–O): mirrored + published on demand, never merged into rules
    'whitelisted-domains-injection-enabled' => ['header' => ['domain'], 'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'tracking-whitelist'       => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'allow-request-domains'    => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'initiator-allowed-domains'=> ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
    'rule101xtra'              => ['header' => ['domain'],       'kind' => 'domains', 'warn_on_change' => false, 'delta_pct' => null],
];

// ----------------------------------------------------------------- fetch ----
function fetch_csv(string $url): array // [ok(bool), body-or-error(string)]
{
    $ctx = stream_context_create(['http' => [
        'timeout' => 30,
        'follow_location' => 1,
        'user_agent' => 'list-factory-ingest/1.0',
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) return [false, 'fetch failed (network/HTTP error)'];
    if (strlen($body) === 0) return [false, 'empty response'];
    $head = substr($body, 0, 200);
    if (stripos($head, '<html') !== false || stripos($head, '<!doctype') !== false) {
        return [false, 'HTML page returned (sheet not link-viewable? wrong gid?)'];
    }
    return [true, $body];
}

function parse_csv(string $body): array
{
    if (str_starts_with($body, "\xEF\xBB\xBF")) $body = substr($body, 3); // BOM
    $fh = fopen('php://temp', 'r+');
    fwrite($fh, $body);
    rewind($fh);
    $rows = [];
    while (($r = fgetcsv($fh, null, ',', '"', '')) !== false) {
        if ($r === [null]) continue; // fully blank line
        $rows[] = array_map(fn($c) => trim((string) $c), $r);
    }
    fclose($fh);
    return $rows;
}

// ------------------------------------------------------------- normalize ----
function normalize_domain(string $d): ?string
{
    $d = strtolower(trim($d));
    $d = (string) preg_replace('~^https?://~', '', $d);
    $d = rtrim(explode('/', $d, 2)[0], '.');
    // rows are kept EXACTLY as entered — www and bare domains are distinct entries
    if ($d === '' || $d === 'localhost') return null;
    if (!str_contains($d, '.')) return null;
    if (preg_match('/\s/', $d)) return null;
    if (filter_var($d, FILTER_VALIDATE_IP) !== false) return null;
    if (!preg_match('/[a-z]/', str_replace(['.', '-'], '', $d)) && preg_match('/^[0-9.]+$/', $d)) return null;
    if (str_contains($d, 'xn--') === false && preg_match('/[^\x20-\x7E]/', $d)) {
        if (function_exists('idn_to_ascii')) {
            $p = idn_to_ascii($d, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($p === false) return null;
            $d = $p;
        } else {
            return null;
        }
    }
    if (filter_var($d, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) return null;
    return $d;
}

// ----------------------------------------------------------------- rows -----
function build_rows(string $kind, array $rows, array &$rejects, array &$dupes): array
{
    $out = [];
    $seen = [];
    foreach ($rows as $i => $r) {
        $line = $i + 2; // 1-based + header row
        if ($kind === 'tracker') {
            [$market, $hostname] = array_pad($r, 2, '');
            if ($market === '' && $hostname === '') continue;
            $h = normalize_domain($hostname);
            if ($h === null) { $rejects[] = [$line, $hostname, 'invalid hostname']; continue; }
            $key = strtolower($market) . '|' . $h;
            if (isset($seen[$key])) { $dupes[] = $key; continue; }
            $seen[$key] = true;
            $out[] = ['market' => strtolower($market), 'hostname' => $h];
            continue;
        }
        $domRaw = $r[0] ?? '';
        if ($kind === 'popup-pivot') {
            // pivot cells look like: "domain",  — strip quotes + trailing commas, skip footer
            $domRaw = rtrim(str_replace('"', '', $domRaw), ", \t");
            if ($domRaw === '' || strcasecmp($domRaw, 'grand total') === 0) continue;
        }
        if ($domRaw === '') continue;
        $d = normalize_domain($domRaw);
        if ($d === null) { $rejects[] = [$line, $domRaw, 'invalid domain']; continue; }
        if (isset($seen[$d])) { $dupes[] = $d; continue; }
        $seen[$d] = true;
        $out[] = $d; // flat domain string — domain mirrors are plain string arrays
    }
    if ($kind === 'tracker') {
        usort($out, fn($a, $b) => [$a['market'], $a['hostname']] <=> [$b['market'], $b['hostname']]);
    } else {
        sort($out, SORT_STRING);
    }
    return $out;
}

function key_set(string $kind, array $rows): array
{
    return array_map(function ($r) use ($kind) {
        if (is_array($r)) { // legacy object-mirror compatibility (pre-flat format)
            return $kind === 'tracker'
                ? ($r['market'] ?? '') . '|' . ($r['hostname'] ?? '')
                : (string) ($r['domain'] ?? '');
        }
        return (string) $r;
    }, $rows);
}

// ------------------------------------------------------------------ main ----
$specs = load_sheet_specs($ROOT . '/sources/upstream.yml');
if (!$specs) { fwrite(STDERR, "FATAL: no sheets found in sources/upstream.yml\n"); exit(1); }

$report = ["# Sheet ingest — " . gmdate('Y-m-d H:i') . " UTC" . ($FORCE ? " · **FORCE**" : ""), ""];
$report[] = "| sheet | status | rows | Δ | notes |";
$report[] = "|---|---|---|---|---|";
$anyFailed = false;
$warnings  = [];   // size deltas worth a line in the summary — never fatal

foreach ($specs as $key => $s) {
    $name = $s['name'] ?? $key;
    $spec = SPECS[$name] ?? null;
    $label = "**{$name}**";
    if (!$spec) { $report[] = "| {$label} | ⚠ skipped | — | — | no SPEC for '{$name}' |"; $anyFailed = true; continue; }
    $url = $s['export_url'] ?? '';
    $mirrorPath = $ROOT . '/' . ($s['mirror'] ?? "sources/gsheet/{$name}.json");
    $prev = is_file($mirrorPath) ? json_decode((string) file_get_contents($mirrorPath), true) : null;
    $prevRows = is_array($prev) ? $prev : null;
    $prevCount = $prevRows !== null ? count($prevRows) : null;

    $fail = function (string $why) use (&$report, &$anyFailed, $label, $prevCount) {
        $report[] = "| {$label} | ❌ FAILED — kept previous | " . ($prevCount ?? '—') . " | — | {$why} |";
        $anyFailed = true;
    };

    if ($url === '' || $url === 'TBD') {
        $report[] = "| {$label} | ⏭ not configured | " . ($prevCount ?? '—') . " | — | export_url is TBD — sheet skipped |";
        continue;
    }

    [$ok, $body] = fetch_csv($url);
    if (!$ok) { $fail($body); continue; }

    $rows = parse_csv($body);
    if (count($rows) < 1) { $fail('no rows parsed'); continue; }

    $header = array_map(fn($c) => strtolower(trim($c)), $rows[0]);
    $header = array_slice($header, 0, count($spec['header']));
    if ($header !== $spec['header']) {
        $fail('header mismatch — expected `' . implode(',', $spec['header']) . '` got `' . implode(',', array_slice($rows[0], 0, 4)) . '`');
        continue;
    }

    $rejects = [];
    $dupes = [];
    $data = build_rows($spec['kind'], array_slice($rows, 1), $rejects, $dupes);
    $n = count($data);

    // SIZE CHANGES ARE REPORTED, NOT BLOCKED (2026-09-14, user decision). The sheets ARE
    // the source of truth: a shrink is a curation decision, and the old fail-closed guards
    // turned every intentional row removal into a red run plus a manual force dispatch —
    // which also froze Curate and Compile behind the workflow_run chain. Seven rows removed
    // from Sheet C on 2026-09-11 stalled the pipeline for three days AND never reached
    // dist/, so the guard did not protect the fleet, it just stopped shipping the decision.
    // The per-sheet thresholds survive as WARNING levels, not gates: `warn_on_change` sheets
    // are small and hand-curated, so any delta deserves a line; `delta_pct` sheets move on
    // their own, so only a jump past the percentage does.
    // ONE HARD GATE REMAINS, because it is the one case that is NOT an edit: a sheet that
    // parses to ZERO rows while the mirror holds some is a fetch/permission accident (an
    // expired share link answers 200 with an empty export), and wiping the mirror on it
    // would ship an empty list fleet-wide. INGEST_FORCE=1 confirms a deliberate emptying.
    if ($prevCount !== null && $prevCount > 0) {
        if ($n === 0 && !$FORCE) {
            $fail("zero rows parsed while the mirror holds {$prevCount} — refusing to wipe it (dispatch with force to confirm an intentional emptying)");
            continue;
        }
        $diff = $n - $prevCount;
        $notable = $spec['warn_on_change']
            ? $diff !== 0
            : ($spec['delta_pct'] !== null && $prevCount >= 20
               && abs($diff) / $prevCount * 100 > $spec['delta_pct']);
        if ($notable) {
            $warnings[] = sprintf(
                '**%s** %s %d domain%s: %d → %d (%s%.0f%%)',
                $name,
                $diff < 0 ? 'LOST' : 'GAINED',
                abs($diff),
                abs($diff) === 1 ? '' : 's',
                $prevCount,
                $n,
                $diff < 0 ? '−' : '+',
                abs($diff) / $prevCount * 100
            );
        }
    }

    if ($spec['kind'] === 'tracker') {
        // Sheet B: split per market into <dir>/<market>.json (empty market -> global.json),
        // each a flat sorted array of hostname strings. mirrorPath is a DIRECTORY here.
        $dir = rtrim($mirrorPath, '/');
        $groups = [];
        foreach ($data as $row) {
            $mk = preg_replace('/[^a-z0-9_-]/', '', $row['market']);
            if ($mk === '') $mk = 'global';
            $groups[$mk][$row['hostname']] = true;
        }
        // CROSS-MARKET PROMOTION (restored 2026-09-08, user decision): v3's whitelist-json
        // built general_global.json with a click-spread classifier that PROMOTED domains
        // seen across several markets into the global list; V2's verbatim split published
        // only the empty-market rows (789 vs v3's 1,173), so every backend serves
        // global + <market> and the SMALL markets silently lost ~370 exemptions each
        // (hk/tw/no/in kept ~62% of their v3 coverage; the domains were never lost, they
        // just stayed in their own market files). A domain listed in >= this many distinct
        // LITERAL markets is treated as market-agnostic and joins global. Count is taken
        // BEFORE the rollups below — a rollup is a union of its members, so counting after
        // would inflate every latam/apac/nordics member by one and promote on noise.
        // Measured at the restore: 789 -> ~1,442 domains, recovering 424 of v3's 474.
        $PROMOTE_MIN_MARKETS = 3;
        $marketCount = [];
        foreach ($groups as $mk => $set) {
            if ($mk === 'global') continue;
            foreach ($set as $h => $_) $marketCount[$h] = ($marketCount[$h] ?? 0) + 1;
        }
        $promoted = 0;
        foreach ($marketCount as $h => $c) {
            if ($c >= $PROMOTE_MIN_MARKETS && !isset($groups['global'][$h])) {
                $groups['global'][$h] = true;
                $promoted++;
            }
        }

        // Regional rollups (restored 2026-09-08): v3's whitelist-json shipped latam/apac/
        // nordics and the backends request them by region key — the verbatim per-market
        // split had silently dropped them. Each rollup = the UNION of its member markets
        // (member lists copied from v3's generate_whitelist_files.php); a literal sheet
        // market sharing a rollup name simply merges into the union. Rollups with no
        // member present are not written, and a stale one is deleted like any market.
        $ROLLUPS = [
            'latam'   => ['br', 'mx', 'ar', 'co', 'cl', 'pe', 've', 'ec', 'gt', 'cu', 'bo', 'do', 'hn', 'py', 'sv', 'ni', 'cr', 'pa', 'uy', 'pr'],
            'apac'    => ['sg', 'my', 'id', 'th', 'vn', 'ph', 'in', 'jp', 'kr', 'cn', 'tw', 'hk', 'nz'],
            'nordics' => ['se', 'dk', 'fi', 'no'],
        ];
        foreach ($ROLLUPS as $region => $members) {
            foreach ($members as $m) {
                foreach ($groups[$m] ?? [] as $h => $_) $groups[$region][$h] = true;
            }
        }
        ksort($groups);
        // $n counts the RAW sheet pairs; the files we are about to write hold something else
        // — promotion adds a row to global, and every rollup re-lists its members' domains.
        // $prevTotal is a sum over the published files, so comparing it to $n subtracted two
        // different units and printed a permanent phantom delta (−2,716 on a run where not a
        // single file changed). $newTotal is the same unit as $prevTotal: what will be on disk.
        $newTotal = 0;
        foreach ($groups as $set) $newTotal += count($set);
        $prevTotal = 0; $prevFiles = [];
        foreach (glob($dir . '/*.json') ?: [] as $f) {
            $arr = json_decode((string) file_get_contents($f), true);
            if (is_array($arr)) { $prevFiles[basename($f, '.json')] = $arr; $prevTotal += count($arr); }
        }
        $legacy = dirname($dir) . '/gsheet/traffic-quality-trackers.json';
        if ($prevTotal === 0 && is_file($legacy)) {
            $l = json_decode((string) file_get_contents($legacy), true);
            if (is_array($l)) $prevTotal = count($l);
        }
        // Same doctrine as the domain sheets above: the size moves with the market data,
        // so it is reported, not gated. $prevCount is null here (mirrorPath is a DIRECTORY
        // for Sheet B), which is why this branch keeps its own copy against $prevTotal.
        if ($prevTotal > 0) {
            if ($newTotal === 0 && !$FORCE) {
                $fail("zero rows parsed while the market files hold {$prevTotal} — refusing to wipe them (dispatch with force to confirm)");
                continue;
            }
            $diff = $newTotal - $prevTotal;
            if ($prevTotal >= 20 && $spec['delta_pct'] !== null
                && abs($diff) / $prevTotal * 100 > $spec['delta_pct']) {
                $warnings[] = sprintf(
                    '**%s** %s %d row%s: %d → %d (%s%.0f%%)',
                    $name,
                    $diff < 0 ? 'LOST' : 'GAINED',
                    abs($diff),
                    abs($diff) === 1 ? '' : 's',
                    $prevTotal,
                    $newTotal,
                    $diff < 0 ? '−' : '+',
                    abs($diff) / $prevTotal * 100
                );
            }
        }
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        $changedMk = [];
        foreach ($groups as $mk => $set) {
            $doms = array_keys($set); sort($doms, SORT_STRING);
            $j = json_encode($doms, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            $fp = "$dir/$mk.json";
            if (!is_file($fp) || (string) file_get_contents($fp) !== $j) {
                file_put_contents($fp . '.tmp', $j); rename($fp . '.tmp', $fp);
                $changedMk[] = $mk;
            }
        }
        foreach (array_diff(array_keys($prevFiles), array_keys($groups)) as $gone) {
            @unlink("$dir/$gone.json"); $changedMk[] = "-$gone";
        }
        if (is_file($legacy)) @unlink($legacy);
        $mkSummary = implode(' · ', array_map(fn($mk) => $mk . ' ' . count($groups[$mk]), array_slice(array_keys($groups), 0, 12)));
        $st = $changedMk ? '✅ updated' : '⏸ unchanged';
        $deltaTot = $newTotal - $prevTotal;
        $deltaTxt = $prevTotal === 0 ? 'new' : (($deltaTot > 0 ? '+' : '') . $deltaTot);
        $notes = [];
        if ($rejects) $notes[] = count($rejects) . ' rejected';
        if ($dupes)   $notes[] = count($dupes) . ' dupes';
        $notes[] = $n . ' sheet rows → ' . $newTotal . ' across ' . count($groups) . ' market files (promotion + rollups re-list domains): ' . $mkSummary;
        $notes[] = "global promoted +{$promoted} (listed in >= {$PROMOTE_MIN_MARKETS} markets)";
        $report[] = "| {$label} | {$st} | {$newTotal} | {$deltaTxt} | " . str_replace('|', '\\|', implode(' · ', $notes)) . " |";
        foreach (array_slice($rejects, 0, 5) as [$ln, $val, $why]) {
            $report[] = "|  | | | | line {$ln}: `" . str_replace('|', '\\|', substr($val, 0, 60)) . "` — {$why} |";
        }
        continue;
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    $changed = !is_file($mirrorPath) || (string) file_get_contents($mirrorPath) !== $json;
    $deltaTxt = $prevCount === null ? 'new' : ($n - $prevCount >= 0 ? '+' : '') . ($n - $prevCount);

    $notes = [];
    if ($rejects) $notes[] = count($rejects) . ' rejected';
    if ($dupes)   $notes[] = count($dupes) . ' dupes';
    if ($changed) {
        if (!is_dir(dirname($mirrorPath))) mkdir(dirname($mirrorPath), 0755, true);
        $tmp = $mirrorPath . '.tmp';
        file_put_contents($tmp, $json);
        rename($tmp, $mirrorPath);
        // added/removed detail
        if ($prevRows !== null) {
            $old = key_set($spec['kind'], $prevRows);
            $new = key_set($spec['kind'], $data);
            $added = array_slice(array_diff($new, $old), 0, 20);
            $removed = array_slice(array_diff($old, $new), 0, 20);
            if ($added)   $notes[] = '+ ' . implode(', ', $added);
            if ($removed) $notes[] = '− ' . implode(', ', $removed);
        }
        $report[] = "| {$label} | ✅ updated | {$n} | {$deltaTxt} | " . str_replace('|', '\\|', implode(' · ', $notes) ?: '—') . " |";
    } else {
        $report[] = "| {$label} | ⏸ unchanged | {$n} | 0 | " . (implode(' · ', $notes) ?: '—') . " |";
    }
    foreach (array_slice($rejects, 0, 10) as [$ln, $val, $why]) {
        $report[] = "|  | | | | line {$ln}: `" . str_replace('|', '\\|', substr($val, 0, 60)) . "` — {$why} |";
    }
}

// Size warnings go FIRST — the table is long and a delta is the thing a human wants to
// see without scrolling. They are also emitted as ::warning:: so GitHub surfaces them on
// the run page itself, where a green run would otherwise say nothing at all.
if ($warnings) {
    $block = ['> [!WARNING]', '> Size changes accepted from the sheets (no gate — verify they were intended):'];
    foreach ($warnings as $w) $block[] = '> - ' . $w;
    $block[] = '';
    array_splice($report, 1, 0, $block);
    foreach ($warnings as $w) {
        echo '::warning title=Sheet size change::' . str_replace('**', '', $w) . "\n";
    }
}

$md = implode("\n", $report) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit($anyFailed ? 1 : 0);
