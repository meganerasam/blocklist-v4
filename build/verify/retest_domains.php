<?php
/**
 * retest_domains.php
 *
 * Usage: php retest_domains.php <chunk_num> <total_chunks>
 * Processes only working_domains_chunk_<chunk_num>.txt
 * Outputs: working_domains_chunk_<chunk_num>_result.txt, inactive_domains_chunk_<chunk_num>_result.txt
 *
 * Notes:
 * - FIX: Do NOT preload previous inactive domains into this chunk's results.
 *        Each chunk now reports ONLY what it observed. The final merger carries
 *        forward prior inactives and enforces "inactive wins".
 * - Enhancements: domain normalization + A/AAAA DNS checks + stable, deterministic files.
 */

// ---------- Error reporting ----------
error_reporting(E_ALL);
ini_set('display_errors', '1');

// ---------- Args ----------
$chunkNum    = isset($argv[1]) ? (int)$argv[1] : 1;
$totalChunks = isset($argv[2]) ? (int)$argv[2] : 1;
if ($chunkNum < 1 || $totalChunks < 1) {
    fwrite(STDERR, "Usage: php retest_domains.php <chunk_num> <total_chunks>\n");
    exit(2);
}

// ---------- File paths ----------
$chunkFile    = __DIR__ . "/working_domains_chunk_{$chunkNum}.txt";
// kept for compatibility, but we DO NOT preload it anymore (see fix)
$inactiveFile = __DIR__ . '/inactive_domains.txt';
$workingOut   = __DIR__ . "/working_domains_chunk_{$chunkNum}_result.txt";
$inactiveOut  = __DIR__ . "/inactive_domains_chunk_{$chunkNum}_result.txt";

// ---------- Utilities ----------
function norm_domain(string $d): string {
    $d = trim($d);
    // strip protocol if present
    $d = preg_replace('~^\s*https?://~i', '', $d);
    // drop path/query/fragment
    $d = preg_replace('~/.*$~', '', $d);
    $d = strtolower($d);
    return $d;
}

/**
 * Resolves if domain has A or AAAA records.
 * Uses checkdnsrr for A, and dns_get_record for AAAA when available.
 */
function dns_resolves(string $domain): bool {
    // Quick A record check
    if (@checkdnsrr($domain, 'A')) {
        return true;
    }

    // Try AAAA via dns_get_record (if available)
    if (function_exists('dns_get_record')) {
        $aaaa = @dns_get_record($domain, DNS_AAAA);
        if (!empty($aaaa)) {
            return true;
        }
    }

    // Optional: try CNAME chain to A/AAAA (lightweight)
    if (function_exists('dns_get_record')) {
        $cname = @dns_get_record($domain, DNS_CNAME);
        if (!empty($cname)) {
            foreach ($cname as $rec) {
                if (!empty($rec['target'])) {
                    $t = rtrim(strtolower($rec['target']), '.');
                    if (@checkdnsrr($t, 'A')) return true;
                    $aaaa = @dns_get_record($t, DNS_AAAA);
                    if (!empty($aaaa)) return true;
                }
            }
        }
    }

    return false;
}

/**
 * Parallel DNS resolver using pcntl_fork to evaluate A/AAAA quickly.
 * Returns [activeDomains[], inactiveDomains[]]
 */
function parallelDnsCheck(array $batch, int $concurrency = 10): array {
    $active   = [];
    $inactive = [];
    $pids     = [];
    $checked  = 0;

    foreach ($batch as $domain) {
        $checked++;
        if ($checked % 1000 === 0) {
            echo "  Checked $checked domains in this batch...\n";
            flush();
        }

        // Throttle maximum concurrent children
        while (count($pids) >= $concurrency) {
            $ended = pcntl_wait($status);
            if ($ended > 0 && isset($pids[$ended])) {
                $childDomain = $pids[$ended];
                $code = pcntl_wexitstatus($status);
                if ($code === 0) $active[] = $childDomain;
                else             $inactive[] = $childDomain;
                unset($pids[$ended]);
            }
        }

        $pid = pcntl_fork();
        if ($pid === -1) {
            // Fork failed: do synchronous fallback for this domain
            if (dns_resolves($domain)) $active[] = $domain;
            else                       $inactive[] = $domain;
        } elseif ($pid === 0) {
            // Child: perform DNS check and exit 0 (active) or 1 (inactive)
            $ok = dns_resolves($domain);
            exit($ok ? 0 : 1);
        } else {
            // Parent: remember which domain this PID is checking
            $pids[$pid] = $domain;
        }
    }

    // Reap remaining children
    while (!empty($pids)) {
        $ended = pcntl_wait($status);
        if ($ended > 0 && isset($pids[$ended])) {
            $childDomain = $pids[$ended];
            $code = pcntl_wexitstatus($status);
            if ($code === 0) $active[] = $childDomain;
            else             $inactive[] = $childDomain;
            unset($pids[$ended]);
        }
    }

    return [$active, $inactive];
}

function write_lines_sorted_unique(string $file, array $lines): void {
    $lines = array_values(array_unique($lines));
    sort($lines, SORT_STRING);
    file_put_contents($file, implode("\n", $lines) . "\n");
}

// ---------- Load & normalize domains for this chunk ----------
if (!is_file($chunkFile)) {
    fwrite(STDERR, "Error: $chunkFile not found.\n");
    exit(1);
}

$raw = file($chunkFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
$domains = [];
foreach ($raw as $ln) {
    $d = norm_domain($ln);
    if ($d !== '' && $d[0] !== '#') {
        // very light sanity check (allowing IDNs/punycode pass-through)
        // You can tighten this regex if needed.
        $domains[] = $d;
    }
}
$domains = array_values(array_unique($domains));
$totalDomains = count($domains);

echo "Retesting $totalDomains domains from $chunkFile...\n";
flush();

// ---------- IMPORTANT FIX: do NOT preload previous inactives ----------
$finalWorking  = [];
$finalInactive = [];

// ---------- Batch processing ----------
$batchSize    = 10000; // keep your original size
$batches      = array_chunk($domains, $batchSize);
$totalBatches = count($batches);

echo "Processing in $totalBatches batches (up to $batchSize each)...\n";
flush();

foreach ($batches as $i => $batch) {
    $num = $i + 1;
    echo "Batch $num/$totalBatches: testing " . count($batch) . " domains...\n";
    flush();

    if (function_exists('pcntl_fork')) {
        [$batchActive, $batchInactive] = parallelDnsCheck($batch, 10);
    } else {
        // Fallback: synchronous checks
        $batchActive   = [];
        $batchInactive = [];
        foreach ($batch as $domain) {
            if (dns_resolves($domain)) $batchActive[] = $domain;
            else                       $batchInactive[] = $domain;
        }
    }

    echo "  Active: " . count($batchActive) . " | Inactive: " . count($batchInactive) . "\n";
    flush();

    // Merge chunk results
    $finalWorking  = array_merge($finalWorking,  $batchActive);
    $finalInactive = array_merge($finalInactive, $batchInactive);

    // Write interim (sorted, unique) to keep artifacts visible during long runs
    write_lines_sorted_unique($workingOut,  $finalWorking);
    write_lines_sorted_unique($inactiveOut, $finalInactive);
}

// Final summary
$finalWorking  = array_values(array_unique($finalWorking));
$finalInactive = array_values(array_unique($finalInactive));
echo "DNS retest complete for chunk $chunkNum/$totalChunks: $totalDomains domains.\n";
echo "Final working count: " . count($finalWorking) . "\n";
echo "Final inactive count: " . count($finalInactive) . "\n";
flush();
