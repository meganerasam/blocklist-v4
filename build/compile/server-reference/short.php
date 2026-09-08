<?php
// Set caching headers
header("Cache-Control: public, max-age=43200"); // 12 hours in seconds
header("Expires: " . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
// URL of the CSV file hosted on GitHub (adjust as needed)
$csvUrl = 'https://raw.githubusercontent.com/meganerasam/blocklist/main/blocklist.csv';

// Library mode = require'd by generate_compiled_rules.php (possibly inside a live sync
// request). There, failures must THROW (caught by the caller) instead of die(), which
// killed the whole request mid-flight with a non-JSON body (2026-07-15 incident hardening).
$isLibShort = (realpath(__FILE__) !== realpath($_SERVER['SCRIPT_FILENAME']));

// Fetch CSV content from GitHub — bounded, a GitHub slowdown must not hang the worker.
// Timeout raised 10s -> 30s (2026-07-23): in library mode this now runs POST-FLUSH on a
// detached worker (ninja-adb21.php section 5), no user-facing request is waiting.
$csvContent = @file_get_contents($csvUrl, false, stream_context_create(['http' => ['timeout' => 30]]));

// LAST-GOOD MIRROR (2026-07-23): save every successful fetch; on failure fall back to
// the saved copy instead of aborting the whole compiled-rules generation. The freeze
// of 07-17..07-23 was exactly this failure aborting generation daily.
$shortMirror = __DIR__ . '/sources/blocklist.csv';
if ($csvContent !== false && strlen($csvContent) > 100) {
    if (!is_dir(__DIR__ . '/sources')) @mkdir(__DIR__ . '/sources', 0755);
    @file_put_contents($shortMirror, $csvContent);
} else {
    $csvContent = @file_get_contents($shortMirror);
    if ($csvContent !== false) error_log("short.php: GitHub fetch failed - using last-good mirror");
}
if ($csvContent === false) {
    if ($isLibShort) throw new \RuntimeException("short.php: unable to fetch CSV data (and no mirror).");
    die("Error: Unable to fetch CSV data.");
}

// Convert CSV content into an array of lines then parse each line as CSV
$lines = explode("\n", $csvContent);
$rows = [];
foreach ($lines as $line) {
    if (trim($line) === '') continue;
    $rows[] = str_getcsv($line);
}

// Check if we have at least one row for headers
if (count($rows) < 1) {
    if ($isLibShort) throw new \RuntimeException("short.php: CSV data is empty or invalid.");
    die("Error: CSV data is empty or invalid.");
}

// The first row is the header row
$headers = array_shift($rows);

// Find the index of the "Block List v3" column
$colIndex = array_search("Block List v3", $headers);
if ($colIndex === false) {
    if ($isLibShort) throw new \RuntimeException("short.php: 'Block List v3' column not found.");
    die("Error: 'Block List v3' column not found.");
}

// Function to normalize domains
function normalizeDomain($domain) {
    // Trim whitespace and remove double quotes and trailing commas
    $domain = trim($domain);
    $domain = str_replace('"', '', $domain);
    $domain = rtrim($domain, ',');
    
    // Remove http:// or https:// if present (case-insensitive)
    $domain = preg_replace('/^https?:\/\//i', '', $domain);
    
    // Remove "www." prefix if present (but keep other subdomains intact)
    if (strpos($domain, 'www.') === 0) {
        $domain = substr($domain, 4);
    }
    
    // Remove any trailing slash
    $domain = rtrim($domain, '/');
    
    return $domain;
}

// Determine the requested output format (default to "3").
// LIBRARY MODE IGNORES $_GET (2026-07-23): when require'd for compilation, the query
// string belongs to whatever outside request happened to trigger the regen (often a
// bot probing ninja-adb21.php) — e.g. ?format=1 here would make this file echo text
// instead of returning the array, silently aborting generation. Direct API calls
// keep full parameter support.
$format = $isLibShort ? "3" : (isset($_GET['format']) ? $_GET['format'] : "3");

switch ($format) {
    case "1":
        // Format 1: Output each domain value as plain text, formatted as:
        // "domain",
        // with the last line having no trailing comma.
        header('Content-Type: text/plain');
        $domains = [];
        foreach ($rows as $row) {
            $domain = normalizeDomain($row[$colIndex]);
            // Skip if empty or equals "Grand Total"
            if ($domain === '' || $domain === "Grand Total") {
                continue;
            }
            $domains[] = $domain;
        }
        $total = count($domains);
        foreach ($domains as $index => $domain) {
            // Append a comma to every line except the last one
            if ($index === $total - 1) {
                echo '"' . $domain . '"' . "\n";
            } else {
                echo '"' . $domain . '",' . "\n";
            }
        }
        break;

    case "2":
        // Format 2: Output JSON objects with key "redirect"
        $result = [];
        foreach ($rows as $row) {
            $domain = normalizeDomain($row[$colIndex]);
            if ($domain === '' || $domain === "Grand Total") {
                continue;
            }
            $result[] = ["redirect" => $domain];
        }
        header('Content-Type: application/json');
        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        break;

    case "3":
        // Build the array of domains
        $domains = [];
        foreach ($rows as $row) {
            $domain = normalizeDomain($row[$colIndex]);
            if ($domain === '' || $domain === "Grand Total") {
                continue;
            }
            $domains[] = $domain;
        }

        // Check if this file is being accessed directly (API mode) or required (library mode)
        if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'])) {
            // Direct access -> behave like API
            header('Content-Type: application/json');
            echo json_encode($domains, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            exit;
        } else {
            // Included via require_once -> return PHP array
            return $domains;
        }

    default:
        header('Content-Type: text/plain');
        echo "Invalid format specified. Use format=1, format=2, or format=3.";
        break;
}
?>
