<?php
declare(strict_types=1);

/**
 * fetch_extension_whitelists.php
 *
 * Pulls the user-whitelisted-domains CSV from each extension backend into
 * sources/extension/whitelist/raw/extension-<id>.csv (the endpoint's exact
 * response, kept as CSV so the four production backends need no change), then
 * merges them into raw/all-extension.csv (summed user counts, audit view) and
 * the flat mirror sources/extension/whitelist/user-extension-whitelist.json.
 * Run by .github/workflows/extension.yml (daily 06:00 + manual), which commits
 * whatever changed — git history is the archive; the endpoints themselves are
 * stateless and store nothing.
 *
 * Producer contract (see ENDPOINT.md in each extension's backend): GET with an
 * X-Whitelist-Token header; a 200 is always a complete, trustworthy CSV
 * ("domain,count" header line, then "<domain>,<users>" lines); every failure is
 * a non-200 with an empty body.
 *
 * Consumer rules implemented here (fail closed, mirror of the producer):
 *   - Only a 200 with a body that validates against the contract may replace
 *     extension-<id>.csv. On any error the existing file is KEPT untouched, so
 *     a dead or misbehaving server can never wipe a published list.
 *   - One endpoint failing never blocks the others; the run exits non-zero
 *     only when EVERY endpoint failed.
 *   - The token is never committed: this public file only names the environment
 *     variable that carries it (GitHub Actions secret / local export). All
 *     extension backends share one token value — see WLF_TOKEN_ENV below.
 */

// ============================================================================
// CONFIGURATION — read from sources/upstream.yml, never hardcoded here.
// Rule 1 of CLAUDE.md: no source URL lives anywhere except upstream.yml. The
// endpoints used to be duplicated in this file while the yml block sat unread,
// so the two could drift apart silently; the yml is now the only registry.
// To add an extension, see the TO ADD AN EXTENSION note in that block.
// ============================================================================

/**
 * Parse the `extension_endpoints:` list out of sources/upstream.yml.
 *
 * Deliberately a tiny hand-rolled reader (php-yaml is not guaranteed on the
 * runner, and the repo already parses this file the same way in
 * fetch_upstreams.php / fetch_sheets.php): it accepts exactly the block style
 * the file uses — "  - id: N" followed by indented "key: value" lines — and
 * stops at the first line that is neither a comment nor indented under the key.
 *
 * Fail-closed: a missing file, a missing block, a malformed entry or an empty
 * result aborts the run. Silently fetching zero endpoints would look like "all
 * backends returned nothing" and could publish a shrunken whitelist.
 */
function wlf_load_endpoints(string $ymlPath): array
{
    if (!is_file($ymlPath)) {
        fwrite(STDERR, "FATAL: upstream.yml not found: $ymlPath\n");
        exit(1);
    }
    $lines = file($ymlPath, FILE_IGNORE_NEW_LINES);
    $out = [];
    $cur = null;
    $inBlock = false;
    foreach ($lines as $n => $raw) {
        if (!$inBlock) {
            if (preg_match('/^extension_endpoints:\s*$/', $raw)) $inBlock = true;
            continue;
        }
        if (preg_match('/^\s*(#.*)?$/', $raw)) continue;          // blank / comment
        if (preg_match('/^\S/', $raw)) break;                     // next top-level key
        if (preg_match('/^\s*-\s*(\w+):\s*(.*)$/', $raw, $m)) { // "- id: 23"
            if ($cur !== null) $out[] = $cur;
            $cur = [];
            $cur[$m[1]] = trim($m[2], " \"'");
            continue;
        }
        if (preg_match('/^\s+(\w+):\s*(.*)$/', $raw, $m)) {      // "  brand: ..."
            if ($cur === null) {
                fwrite(STDERR, "FATAL: upstream.yml:" . ($n + 1) . " — key outside a list entry\n");
                exit(1);
            }
            $cur[$m[1]] = trim($m[2], " \"'");
            continue;
        }
        fwrite(STDERR, "FATAL: upstream.yml:" . ($n + 1) . " — unparseable line in extension_endpoints: $raw\n");
        exit(1);
    }
    if ($cur !== null) $out[] = $cur;

    if (!$inBlock) {
        fwrite(STDERR, "FATAL: no extension_endpoints: block in $ymlPath\n");
        exit(1);
    }
    $endpoints = [];
    foreach ($out as $k => $e) {
        foreach (['id', 'brand', 'url'] as $req) {
            if (($e[$req] ?? '') === '') {
                fwrite(STDERR, "FATAL: extension_endpoints entry #$k is missing '$req'\n");
                exit(1);
            }
        }
        if (!preg_match('#^https://#', $e['url'])) {
            fwrite(STDERR, "FATAL: extension_endpoints entry {$e['id']}: url must be https — {$e['url']}\n");
            exit(1);
        }
        // 'name' is what the rest of this file calls the label; the yml says 'brand'
        $endpoints[] = ['id' => (string) $e['id'], 'name' => $e['brand'], 'url' => $e['url']];
    }
    if (!$endpoints) {
        fwrite(STDERR, "FATAL: extension_endpoints: is empty — refusing to run with zero backends\n");
        exit(1);
    }
    return $endpoints;
}

$EXTENSIONS = wlf_load_endpoints(dirname(__DIR__, 2) . '/sources/upstream.yml');

// One shared token for ALL extension backends: every server's config.php holds
// the same $whitelist_export_token value, and this env var (GitHub Actions
// secret of the same name; underscores — hyphens are not allowed in secret or
// env names) carries it to the fetcher.
const WLF_TOKEN_ENV = 'USER_WHITELIST_DOMAINS';

// Refuse to store anything absurdly large (contract bodies are a few KB).
const WLF_MAX_BODY_BYTES = 10_000_000;

/**
 * GET $url with the token header. Returns [httpStatus, body, headers] where
 * headers is a lowercase-name => value map. Never follows redirects (a
 * redirect would be off-contract and could leak the token to another host).
 */
function wlf_fetch(string $url, string $token): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HTTPGET        => true,
        CURLOPT_HTTPHEADER     => ['X-Whitelist-Token: ' . $token],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_TIMEOUT        => 120,
        CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$headers): int {
            if (str_contains($line, ':')) {
                [$n, $v] = explode(':', $line, 2);
                $headers[strtolower(trim($n))] = trim($v);
            }
            return strlen($line);
        },
    ]);
    $headers = [];
    $body = curl_exec($ch);
    if ($body === false) {
        return [0, '', ['curl_error' => curl_error($ch)]];
    }
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    return [$status, (string) $body, $headers];
}

/**
 * Defense in depth: even a 200 body must match the contract exactly before it
 * can replace a committed file. Header line "domain,count", then lines of
 * "<lowercase hostname>,<positive int>", \n endings, trailing newline, no BOM.
 * A body of just the header line is valid ("nothing clears the privacy floor").
 */
function wlf_validate_csv(string $body): bool
{
    if ($body === '' || strlen($body) > WLF_MAX_BODY_BYTES) {
        return false;
    }
    if (!str_starts_with($body, "domain,count\n") || !str_ends_with($body, "\n")) {
        return false;
    }
    $lines = explode("\n", substr($body, 0, -1)); // drop the final \n, no empty tail
    foreach (array_slice($lines, 1) as $line) {
        if (!preg_match('/^[a-z0-9][a-z0-9.-]*,[1-9][0-9]*$/', $line)) {
            return false;
        }
    }
    return true;
}

/** Atomically write $body to $path. Returns 'updated' or 'unchanged'. */
function wlf_store(string $path, string $body): string
{
    if (is_file($path) && file_get_contents($path) === $body) {
        return 'unchanged';
    }
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $body) !== strlen($body) || !rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('could not write ' . basename($path));
    }
    return 'updated';
}

/** Emit a GitHub Actions annotation when running in CI, plain line otherwise. */
function wlf_warn(string $msg): void
{
    echo (getenv('GITHUB_ACTIONS') !== false ? '::warning::' : 'WARNING: ') . $msg . "\n";
}

/**
 * Fetch every configured extension into $outDir. Returns the number of
 * failures. A failure NEVER deletes or overwrites the existing CSV.
 */
function wlf_run(array $extensions, string $outDir): int
{
    $failures = 0;
    $summary = [];
    foreach ($extensions as $ext) {
        $label = "extension {$ext['id']} ({$ext['name']})";
        $path = $outDir . '/extension-' . $ext['id'] . '.csv';
        $token = getenv(WLF_TOKEN_ENV);
        if ($token === false || $token === '') {
            wlf_warn("{$label}: env " . WLF_TOKEN_ENV . ' not set — kept existing file');
            $summary[] = "| {$ext['id']} | {$ext['name']} | ❌ token env missing | kept |";
            $failures++;
            continue;
        }

        [$status, $body, $headers] = wlf_fetch($ext['url'], $token);
        if ($status !== 200) {
            $detail = $status === 0 ? ('network: ' . ($headers['curl_error'] ?? '?')) : "HTTP {$status}";
            wlf_warn("{$label}: {$detail} — kept existing file");
            $summary[] = "| {$ext['id']} | {$ext['name']} | ❌ {$detail} | kept |";
            $failures++;
            continue;
        }
        if (!wlf_validate_csv($body)) {
            wlf_warn("{$label}: 200 but body violates the CSV contract — kept existing file");
            $summary[] = "| {$ext['id']} | {$ext['name']} | ❌ invalid body | kept |";
            $failures++;
            continue;
        }

        $action = wlf_store($path, $body);
        $scanned = $headers['x-users-scanned'] ?? '?';
        $domains = $headers['x-domains-returned'] ?? '?';
        echo "{$label}: ok — users-scanned={$scanned} domains={$domains} ({$action})\n";
        $summary[] = "| {$ext['id']} | {$ext['name']} | ✅ {$domains} domains ({$scanned} users) | {$action} |";
    }

    $stepSummary = getenv('GITHUB_STEP_SUMMARY');
    if ($stepSummary !== false && $stepSummary !== '') {
        file_put_contents(
            $stepSummary,
            "### Extension whitelists\n\n| id | extension | result | file |\n|---|---|---|---|\n"
            . implode("\n", $summary) . "\n",
            FILE_APPEND
        );
    }
    return $failures;
}

/**
 * Merge every raw/extension-*.csv into all-extension.csv (union of domains,
 * user counts summed across brands, sorted count desc then domain asc) and
 * the flat mirror user-extension-whitelist.json (sorted domain array).
 * Runs on whatever raw files exist — a failed endpoint's KEPT previous file
 * still contributes, so the merged view degrades gracefully, never abruptly.
 */
function wlf_merge(string $rawDir, string $outDir): void
{
    $counts = [];
    foreach (glob($rawDir . '/extension-*.csv') ?: [] as $f) {
        $lines = file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach (array_slice($lines, 1) as $line) {
            [$d, $c] = array_pad(explode(',', $line, 2), 2, '0');
            if ($d === '') continue;
            $counts[$d] = ($counts[$d] ?? 0) + (int) $c;
        }
    }
    $rows = [];
    foreach ($counts as $d => $c) $rows[] = [$d, $c];
    usort($rows, fn($x, $y) => [$y[1], $x[0]] <=> [$x[1], $y[0]]);
    $csv = "domain,count\n";
    foreach ($rows as [$d, $c]) $csv .= "{$d},{$c}\n";
    wlf_store($rawDir . '/all-extension.csv', $csv);

    $doms = array_keys($counts);
    sort($doms, SORT_STRING);
    $json = json_encode($doms, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    wlf_store($outDir . '/user-extension-whitelist.json', $json);
    echo 'merged: ' . count($doms) . " unique domains -> all-extension.csv + user-extension-whitelist.json\n";
}

if (!defined('WLF_SKIP_MAIN')) {
    if (!function_exists('curl_init')) {
        fwrite(STDERR, "ext-curl is required\n");
        exit(1);
    }
    $root = dirname(__DIR__, 2);
    $rawDir = $root . '/sources/extension/whitelist/raw';
    if (!is_dir($rawDir)) mkdir($rawDir, 0755, true);
    $failures = wlf_run($EXTENSIONS, $rawDir);
    wlf_merge($rawDir, dirname($rawDir));
    // Non-zero only when nothing succeeded: partial failures must not block the
    // commit step from publishing the extensions that did update.
    exit($failures > 0 && $failures === count($EXTENSIONS) ? 1 : 0);
}
