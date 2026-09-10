<?php
// build/ingest/fetch_sheets.php
// Mirrors Google Sheets A–N into sources/gsheet/*.json. Domain sheets mirror as FLAT
// sorted arrays of domain strings; only Sheet B (trackers) mirrors as objects.
// Fail-closed PER SHEET: any gate violation keeps the previous mirror untouched and marks
// the run red; sheets that pass are still written. Guards per sources/gsheet/SCHEMA.md.
//
// Env:
//   INGEST_FORCE=1   override the shrink/size-delta guards (the "confirming re-run")
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

// Expected header + guard profile per sheet `name`.
// 'popup-pivot' = Sheet A's kept-as-is pivot ("Block List v3" column, quoted cells,
// Grand Total footer). Domain sheets: only the first column ('domain') is required —
// added/reason columns are sheet-side audit trail and never enter the mirror.
const SPECS = [
    'popup'                    => ['header' => ['block list v3'],                   'kind' => 'popup-pivot', 'shrink_guard' => false, 'delta_pct' => 30],
    'traffic-quality-trackers' => ['header' => ['market', 'hostname', 'nb_click'],  'kind' => 'tracker', 'shrink_guard' => false, 'delta_pct' => 30],
    'default-whitelist'        => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => true,  'delta_pct' => null],
    'default-blocklist'        => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    // Sheet E (2026-09-10): the veto on the default blocklist — a listed domain must
    // produce NO rule at all. Shrink-guarded like omit-from-blocklist: a silent shrink
    // would silently re-admit blocks the operator deliberately vetoed.
    'default-blocklist-not-to-add' => ['header' => ['domain'],   'kind' => 'domains', 'shrink_guard' => true,  'delta_pct' => null],
    'manual-whitelist'         => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => true,  'delta_pct' => null],
    'manual-blocklist'         => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'omit-from-whitelist'      => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'omit-from-blocklist'      => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => true,  'delta_pct' => null],
    // Sheet I (2026-09-08): download sites — omit-style curation input; a silent shrink
    // would strip protection from download sites, so it gets the shrink guard like H
    'download-sites'           => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => true,  'delta_pct' => null],
    // standalone (K–O): mirrored + published on demand, never merged into rules
    'whitelisted-domains-injection-enabled' => ['header' => ['domain'], 'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'tracking-whitelist'       => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'allow-request-domains'    => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'initiator-allowed-domains'=> ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
    'rule101xtra'              => ['header' => ['domain'],       'kind' => 'domains', 'shrink_guard' => false, 'delta_pct' => null],
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

    // delta guards vs previous mirror
    if ($prevCount !== null && !$FORCE) {
        if ($spec['shrink_guard'] && $n < $prevCount) {
            $fail("shrink guard: {$prevCount} → {$n} (re-run with force to confirm)");
            continue;
        }
        if ($spec['delta_pct'] !== null && $prevCount >= 20) {
            $delta = abs($n - $prevCount) / $prevCount * 100;
            if ($delta > $spec['delta_pct']) {
                $fail(sprintf('size delta %.0f%% > %d%% (%d → %d; force to confirm)', $delta, $spec['delta_pct'], $prevCount, $n));
                continue;
            }
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
        if ($prevTotal >= 20 && !$FORCE && $spec['delta_pct'] !== null) {
            $delta = abs($n - $prevTotal) / $prevTotal * 100;
            if ($delta > $spec['delta_pct']) {
                $fail(sprintf('size delta %.0f%% > %d%% (%d -> %d; force to confirm)', $delta, $spec['delta_pct'], $prevTotal, $n));
                continue;
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
        $deltaTxt = $prevTotal === 0 ? 'new' : (($n - $prevTotal >= 0 ? '+' : '') . ($n - $prevTotal));
        $notes = [];
        if ($rejects) $notes[] = count($rejects) . ' rejected';
        if ($dupes)   $notes[] = count($dupes) . ' dupes';
        $notes[] = count($groups) . ' market files: ' . $mkSummary;
        $notes[] = "global promoted +{$promoted} (listed in >= {$PROMOTE_MIN_MARKETS} markets)";
        $report[] = "| {$label} | {$st} | {$n} | {$deltaTxt} | " . str_replace('|', '\\|', implode(' · ', $notes)) . " |";
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

$md = implode("\n", $report) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit($anyFailed ? 1 : 0);
