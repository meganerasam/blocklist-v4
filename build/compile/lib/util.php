<?php
// build/compile/lib/util.php — shared helpers for the compile step.
//
// clean_domain / load_hosts_file / load_json_domains / covered_subdomain mirror
// build/verify/ledger.php — keep the two in sync (ledger decides what gets DNS-tested,
// compile decides what ships; both must see the same domain).
// normalize_domain mirrors the production short.php normalizeDomain() — the www-strip
// semantics must survive the migration or the shadow diff drifts.

declare(strict_types=1);

function clean_domain(string $d): ?string
{
    $d = strtolower(trim($d));
    $d = rtrim($d, '.');
    if ($d === '' || !str_contains($d, '.') || preg_match('/[\s\/:]/', $d)) return null;
    if (filter_var($d, FILTER_VALIDATE_IP) !== false) return null;
    return $d;
}

function load_hosts_file(string $path): array
{
    $out = [];
    if (!is_file($path)) return $out;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim(explode('#', $line, 2)[0]);
        if ($line === '') continue;
        if (preg_match('/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$/', $line, $m)) $line = $m[1];
        $d = clean_domain($line);
        if ($d !== null && $d !== 'localhost' && $d !== 'localhost.localdomain' && $d !== 'broadcasthost') $out[$d] = true;
    }
    return $out;
}

function load_json_domains(string $path): array
{
    if (!is_file($path)) return [];
    $arr = json_decode((string) file_get_contents($path), true);
    if (!is_array($arr)) return [];
    $out = [];
    foreach ($arr as $d) if (is_string($d) && ($c = clean_domain($d)) !== null) $out[$c] = true;
    return $out;
}

/** True when $d equals a set member or is a subdomain of one. */
function covered_subdomain(string $d, array $set): bool
{
    $parts = explode('.', $d);
    for ($i = 0, $n = count($parts) - 1; $i < $n; $i++) {
        if (isset($set[implode('.', array_slice($parts, $i))])) return true;
    }
    return false;
}

/** Production short.php normalizeDomain(): quotes/scheme/www/trailing-slash strip. */
function normalize_domain(string $domain): string
{
    $domain = trim($domain);
    $domain = str_replace('"', '', $domain);
    $domain = rtrim($domain, ',');
    $domain = preg_replace('/^https?:\/\//i', '', $domain);
    if (strpos($domain, 'www.') === 0) {
        $domain = substr($domain, 4);
    }
    $domain = rtrim($domain, '/');
    return $domain;
}

/**
 * Carve-out list for a batched domain rule: members of $set that are STRICT
 * subdomains of a domain in $chunk must be excluded from matching the rule
 * (requestDomains matches subdomains too). $chunk is a flat domain list.
 */
function carve_for_chunk(array $chunk, array $set): array
{
    $chunkSet = array_flip($chunk);
    $carve = [];
    foreach ($set as $w => $_) {
        foreach (domainAncestors($w) as $parent) {
            if (isset($chunkSet[$parent])) { $carve[$w] = true; break; }
        }
    }
    $out = array_keys($carve);
    sort($out);
    return $out;
}

/** json_encode that aborts the compile on failure (never publish a broken artifact). */
function json_out($data, bool $pretty): string
{
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | ($pretty ? JSON_PRETTY_PRINT : 0);
    $json = json_encode($data, $flags);
    if ($json === false) {
        fwrite(STDERR, 'FATAL: json_encode failed: ' . json_last_error_msg() . "\n");
        exit(1);
    }
    return $json;
}

/** tmp + rename write — a killed run can never leave a half-written artifact.
 *  Hardened 2026-09-08 (adversarial review): a FAILED rename used to be silently
 *  ignored, leaving the OLD file in place on a green run — the one fail-open path in
 *  the staged-write design. The tmp name carries the pid so two local runs can't
 *  clobber each other's staging file. */
function atomic_write(string $path, string $content): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) mkdir($dir, 0777, true);
    $tmp = $path . '.tmp.' . getmypid();
    if (file_put_contents($tmp, $content) === false) {
        fwrite(STDERR, "FATAL: cannot write $tmp\n");
        exit(1);
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        fwrite(STDERR, "FATAL: rename failed — $path would have stayed STALE on a green run\n");
        exit(1);
    }
}
