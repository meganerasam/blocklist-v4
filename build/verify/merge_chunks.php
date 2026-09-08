<?php
// File: merge_chunks.php
declare(strict_types=1);

$ROOT = __DIR__;
$RESULTS_DIR = $ROOT . '/results';
$OUT_WORKING  = $ROOT . '/working_domains.txt';
$OUT_INACTIVE = $ROOT . '/inactive_domains.txt';

function readLines(string $file): array {
    if (!is_file($file)) return [];
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $out = [];
    foreach ($lines as $ln) {
        $ln = trim($ln);
        if ($ln === '' || $ln[0] === '#') continue;
        $out[] = strtolower($ln);
    }
    return $out;
}

function writeLines(string $file, array $lines): void {
    file_put_contents($file, implode("\n", $lines) . "\n");
}

$workingAll  = [];
$inactiveAll = [];

// 1) Carry forward previously inactive
$prevInactive = readLines($OUT_INACTIVE);
if ($prevInactive) $inactiveAll = array_merge($inactiveAll, $prevInactive);

// 2) Gather all chunk outputs under results/retest-results-*/
if (is_dir($RESULTS_DIR)) {
    $dirs = array_filter(glob($RESULTS_DIR . '/retest-results-*') ?: [], 'is_dir');
    sort($dirs, SORT_NATURAL);

    foreach ($dirs as $d) {
        foreach (glob($d . '/working_domains_chunk_*_result.txt') ?: [] as $f) {
            $workingAll = array_merge($workingAll, readLines($f));
        }
        foreach (glob($d . '/inactive_domains_chunk_*_result.txt') ?: [] as $f) {
            $inactiveAll = array_merge($inactiveAll, readLines($f));
        }
    }
}

// 3) Unique and make sets disjoint (inactive wins)
$workingAll  = array_values(array_unique($workingAll));
$inactiveAll = array_values(array_unique($inactiveAll));
$inactiveSet = array_flip($inactiveAll);
$workingAll  = array_values(array_filter($workingAll, fn($d) => !isset($inactiveSet[$d])));

// 4) Sort for stable diffs
sort($workingAll,  SORT_STRING);
sort($inactiveAll, SORT_STRING);

// 5) Write final lists
writeLines($OUT_WORKING,  $workingAll);
writeLines($OUT_INACTIVE, $inactiveAll);

// 6) Summary for CI logs
echo "Merged working: " . count($workingAll) . PHP_EOL;
echo "Merged inactive: " . count($inactiveAll) . PHP_EOL;
