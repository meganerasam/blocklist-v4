<?php
/**
 * update_domains.php
 *
 * Aggregates domain data from various sources, DNS-checks them in parallel,
 * updates:
 *   - working_domains.txt          (full active list)
 *   - inactive_domains.txt         (full inactive list)
 *   - working_domains_YYYYMMDD.txt (only the new active domains this run)
 *
 * Commits each batch incrementally to preserve progress.
 */

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// File paths
$activeFile           = __DIR__ . '/working_domains.txt';
$inactiveFile         = __DIR__ . '/inactive_domains.txt';
$activeFileRecent     = __DIR__ . "/working_domains_20250416.txt";

// Load existing lists
$prevActiveDomains       = file_exists($activeFile)
    ? file($activeFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
    : [];
$prevInactiveDomains     = file_exists($inactiveFile)
    ? file($inactiveFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
    : [];
$prevActiveDomainsRecent = file_exists($activeFileRecent)
    ? file($activeFileRecent, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
    : [];

// Source URLs
$txtUrls = [
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
    'https://v.firebog.net/hosts/AdguardDNS.txt',
    'https://v.firebog.net/hosts/Admiral.txt',
    'https://v.firebog.net/hosts/Easylist.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/data/KADhosts/hosts'
];
$txtWhitelist = [
    'https://raw.githubusercontent.com/meganerasam/whitelist-domains/master/whitelistes.txt',
    'https://raw.githubusercontent.com/meganerasam/whitelist-domains/master/whitelistes2.txt',
    'https://raw.githubusercontent.com/meganerasam/whitelist-domains/master/whitelistes3.txt'
];
$csvUrls = [
    'https://raw.githubusercontent.com/meganerasam/blocklist/main/blocklist.csv'
];

// Normalize a domain
function normalizeDomain(string $domain): string {
    $domain = preg_replace('/^(0\.0\.0\.0|127\.0\.0\.1|\|\|)\s*/', '', $domain);
    $domain = trim($domain);
    $domain = str_replace('"', '', $domain);
    $domain = rtrim($domain, ',');
    $domain = preg_replace('/^https?:\/\//i', '', $domain);
    return rtrim($domain, '/');
}

// 1. Gather new candidate domains
$newDomains = [];

// TXT sources
foreach ($txtUrls as $url) {
    $content = @file_get_contents($url);
    if ($content === false) continue;
    foreach (explode("\n", $content) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        $d = normalizeDomain($line);
        if ($d !== '' &&
            !in_array($d, $prevActiveDomains, true) &&
            !in_array($d, $prevInactiveDomains, true)
        ) {
            $newDomains[] = $d;
        }
    }
}

// CSV sources
foreach ($csvUrls as $url) {
    $content = @file_get_contents($url);
    if ($content === false) continue;
    $rows = array_map('str_getcsv', explode("\n", $content));
    if (count($rows) < 2) continue;
    $headers = array_shift($rows);
    $idx = array_search('Block List v3', $headers, true);
    if ($idx === false) continue;
    foreach ($rows as $row) {
        if (empty($row[$idx]) || $row[$idx] === 'Grand Total') continue;
        $d = normalizeDomain($row[$idx]);
        if ($d !== '' &&
            !in_array($d, $prevActiveDomains, true) &&
            !in_array($d, $prevInactiveDomains, true)
        ) {
            $newDomains[] = $d;
        }
    }
}

// Whitelist filter
$whitelist = [];
foreach ($txtWhitelist as $url) {
    $content = @file_get_contents($url);
    if ($content === false) continue;
    foreach (explode("\n", $content) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        $whitelist[] = normalizeDomain($line);
    }
}
$newDomains = array_values(array_unique(array_diff($newDomains, $whitelist)));

echo "Found " . count($newDomains) . " new candidate domains.\n"; flush();

// Partition into batches
$batchSize = 5000;
$batches   = array_chunk($newDomains, $batchSize);

echo "Processing " . count($batches) . " batches of up to $batchSize domains each.\n"; flush();

/**
 * Performs parallel DNS checks via pcntl_fork.
 * Returns [activeDomains, inactiveDomains].
 */
function parallelDnsCheck(array $domains, int $concurrency = 10): array {
    $active = [];
    $inactive = [];
    $pids = [];
    $count = 0;

    foreach ($domains as $d) {
        $count++;
        if ($count % 1000 === 0) {
            echo "  Checked $count in batch\n"; flush();
        }
        // Wait for remaining children
        while (count($pids) > 0) {
            $ended = pcntl_wait($status);
            if ($ended > 0 && isset($pids[$ended])) {
                $code = pcntl_wexitstatus($status);
                if ($code === 0) {
                    $active[] = $pids[$ended];
                } else {
                    $inactive[] = $pids[$ended];
                }
                unset($pids[$ended]);
            }
        }
        $pid = pcntl_fork();
        if ($pid === -1) {
            // fallback
            if (checkdnsrr($d, 'A')) $active[] = $d;
            else                     $inactive[] = $d;
        } elseif ($pid === 0) {
            exit(checkdnsrr($d, 'A') ? 0 : 1);
        } else {
            $pids[$pid] = $d;
        }
    }
    // Wait for remaining children
    while (count($pids) > 0) {
        $ended = pcntl_wait($status);
        if ($ended > 0 && isset($pids[$ended])) {
            $code = pcntl_wexitstatus($status);
            if ($code === 0) {
                $active[] = $pids[$ended];
            } else {
                $inactive[] = $pids[$ended];
            }
            unset($pids[$ended]);
        }
    }
    return [$active, $inactive];
}

// Initialize totals
$totalActive   = $prevActiveDomains;
$totalInactive = $prevInactiveDomains;

// Ensure recent file exists
if (!file_exists($activeFileRecent)) {
    file_put_contents($activeFileRecent, "");
}

// Batch processing
foreach ($batches as $i => $batch) {
    $num = $i + 1;
    echo "Batch $num/" . count($batches) . "\n"; flush();

    if (function_exists('pcntl_fork')) {
        list($bAct, $bInact) = parallelDnsCheck($batch, 10);
    } else {
        $bAct = [];
        $bInact = [];
        foreach ($batch as $d) {
            if (checkdnsrr($d, 'A')) $bAct[] = $d;
            else                      $bInact[] = $d;
        }
    }
    echo "  Active: " . count($bAct) . "  Inactive: " . count($bInact) . "\n"; flush();

    // Merge full lists
    $totalActive   = array_values(array_unique(array_merge($totalActive,   $bAct)));
    $totalInactive = array_values(array_unique(array_merge($totalInactive, $bInact)));

    // Write master lists
    file_put_contents($activeFile,   implode("\n", $totalActive)   . "\n");
    file_put_contents($inactiveFile, implode("\n", $totalInactive) . "\n");

    // Compute only newly added for the recent file
    $newForRecent = array_diff($bAct, $prevActiveDomainsRecent);
    if (!empty($newForRecent)) {
        file_put_contents(
            $activeFileRecent,
            implode("\n", $newForRecent) . "\n",
            FILE_APPEND
        );
        // Update snapshot so next batch skips these
        $prevActiveDomainsRecent = array_merge($prevActiveDomainsRecent, $newForRecent);
    }

    // Commit changes incrementally
    echo "  Committing batch $num\n"; flush();
    exec("git add "
        . escapeshellarg($activeFile)   . " "
        . escapeshellarg($inactiveFile) . " "
        . escapeshellarg($activeFileRecent)
    );
    exec("git config user.name 'github-actions[bot]'");
    exec("git config user.email 'github-actions[bot]@users.noreply.github.com'");
    $msg = "Batch $num/" . count($batches) . " (" . date('Y-m-d H:i') . ")";
    exec("git commit -m " . escapeshellarg($msg));
    exec("git push");
}

// Done
echo "Update complete: "
   . count($totalActive) . " total active, "
   . count($totalInactive) . " total inactive.\n";
flush();
?>
