<?php
// build/ingest/fetch_upstreams.php
// Mirrors the non-sheet upstreams into committed snapshots, verbatim:
//   hosts:              sources/hosts/<name>.txt        (4 lists, per upstream.yml)
//   easylist_snapshots: sources/easylist/<path>         (the 59 filter files)
// Fail-closed PER FILE: a failed/suspicious fetch keeps the previous snapshot and
// turns the run red; successes are still written. Downstream (verify, compile)
// reads ONLY these snapshots — never live URLs — so last-good fallback and a
// daily diff history come for free.
//
// Env: GITHUB_STEP_SUMMARY — markdown report appended when set (always echoed).

declare(strict_types=1);

$ROOT = dirname(__DIR__, 2);

// ---- config: parse hosts + easylist_snapshots from sources/upstream.yml ----
function load_upstreams(string $yml): array
{
    $hosts = [];
    $el = ['base_url' => '', 'dir' => '', 'files' => []];
    $section = '';
    $cur = null;
    foreach (file($yml, FILE_IGNORE_NEW_LINES) as $ln) {
        if (preg_match('/^(\S[^:]*):\s*(#.*)?$/', $ln, $m)) { $section = $m[1]; $cur = null; continue; }
        if ($section === 'hosts') {
            if (preg_match('/^  (\w+):\s*$/', $ln, $m)) { $cur = $m[1]; $hosts[$cur] = []; continue; }
            if ($cur && preg_match('/^    (url|snapshot|role):\s*(.*)$/', $ln, $m)) {
                $v = trim($m[2]);
                if ($v !== '' && $v[0] === '"') { $v = substr($v, 1); $v = substr($v, 0, (int) strpos($v, '"')); }
                else { $v = trim((string) preg_replace('/\s+#.*$/', '', $v)); }
                $hosts[$cur][$m[1]] = $v;
            }
        } elseif ($section === 'easylist_snapshots') {
            if (preg_match('/^  (base_url|dir):\s*(.*)$/', $ln, $m)) {
                $v = trim($m[2]);
                if ($v !== '' && $v[0] === '"') { $v = substr($v, 1); $v = substr($v, 0, (int) strpos($v, '"')); }
                else { $v = trim((string) preg_replace('/\s+#.*$/', '', $v)); }
                $el[$m[1]] = $v;
            } elseif (preg_match('/^    - (.+?)\s*$/', $ln, $m)) {
                $el['files'][] = $m[1];
            }
        }
    }
    return [$hosts, $el];
}

function fetch_raw(string $url): array // [ok, body-or-error]
{
    $ctx = stream_context_create(['http' => [
        'timeout' => 60,
        'follow_location' => 1,
        'user_agent' => 'list-factory-ingest/1.0',
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) return [false, 'fetch failed'];
    if (strlen($body) === 0) return [false, 'empty response'];
    if (stripos(substr($body, 0, 200), '<html') !== false || stripos(substr($body, 0, 200), '<!doctype') !== false) {
        return [false, 'HTML page returned'];
    }
    return [true, $body];
}

/**
 * Store $body at $path (atomic) unless a guard trips.
 * Guards: min size; ±40% size delta vs the existing snapshot (only when the
 * previous snapshot is > 10 KB — tiny files legitimately swing hard).
 * Returns [status, detail] where status ∈ updated | unchanged | FAILED.
 */
function store_snapshot(string $path, string $body, int $minBytes): array
{
    if (strlen($body) < $minBytes) {
        return ['FAILED', 'body ' . strlen($body) . ' B < min ' . $minBytes . ' B — kept previous'];
    }
    if (is_file($path)) {
        $prev = (string) file_get_contents($path);
        if ($prev === $body) return ['unchanged', strlen($body) . ' B'];
        if (strlen($prev) > 10_240) {
            $delta = abs(strlen($body) - strlen($prev)) / strlen($prev) * 100;
            if ($delta > 40) {
                return ['FAILED', sprintf('size delta %.0f%% > 40%% (%d → %d B) — kept previous', $delta, strlen($prev), strlen($body))];
            }
        }
    }
    if (!is_dir(dirname($path))) mkdir(dirname($path), 0755, true);
    file_put_contents($path . '.tmp', $body);
    rename($path . '.tmp', $path);
    return ['updated', strlen($body) . ' B'];
}

[$hosts, $el] = load_upstreams($ROOT . '/sources/upstream.yml');
if (!$hosts || !$el['files']) { fwrite(STDERR, "FATAL: hosts/easylist_snapshots missing from upstream.yml\n"); exit(1); }

$report = ["# Upstream snapshots — " . gmdate('Y-m-d H:i') . " UTC", "", "| file | status | detail |", "|---|---|---|"];
$failed = 0; $updated = 0;

foreach ($hosts as $name => $h) {
    if (empty($h['url']) || empty($h['snapshot'])) { $report[] = "| hosts/{$name} | ⚠ | missing url/snapshot in upstream.yml |"; $failed++; continue; }
    [$ok, $body] = fetch_raw($h['url']);
    [$st, $detail] = $ok ? store_snapshot($ROOT . '/' . $h['snapshot'], $body, 20_000) : ['FAILED', $body . ' — kept previous'];
    if ($st === 'FAILED') $failed++; elseif ($st === 'updated') $updated++;
    $icon = $st === 'FAILED' ? '❌' : ($st === 'updated' ? '✅' : '⏸');
    $report[] = "| hosts/{$name} | {$icon} {$st} | {$detail} |";
}

foreach ($el['files'] as $rel) {
    [$ok, $body] = fetch_raw($el['base_url'] . $rel);
    [$st, $detail] = $ok ? store_snapshot($ROOT . '/' . rtrim($el['dir'], '/') . '/' . $rel, $body, 50) : ['FAILED', $body . ' — kept previous'];
    if ($st === 'FAILED') $failed++; elseif ($st === 'updated') $updated++;
    if ($st !== 'unchanged') { // keep the 59-row table readable: list changes + failures only
        $icon = $st === 'FAILED' ? '❌' : '✅';
        $report[] = "| easylist/{$rel} | {$icon} {$st} | {$detail} |";
    }
}
$report[] = "";
$report[] = sprintf("**%d updated · %d failed · %d total**", $updated, $failed, count($hosts) + count($el['files']));

$md = implode("\n", $report) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit($failed > 0 ? 1 : 0);
