<?php
// Set caching headers
header("Cache-Control: public, max-age=43200"); // 12 hours in seconds
header("Expires: " . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
// Array of URLs of the TXT files hosted on GitHub (adjust as needed)
$txtUrls = [
    'https://raw.githubusercontent.com/meganerasam/blocklist-v2/refs/heads/master/working_domains.txt',
    'https://raw.githubusercontent.com/meganerasam/blocklist-v2/refs/heads/master/working_domains_20250416.txt'
];

// Library mode = require'd by generate_compiled_rules.php (post-flush on a detached
// worker since 2026-07-23). There, failures must THROW (caught by the caller) instead
// of die(), which killed the whole request mid-flight with a non-JSON body
// (2026-07-15 incident hardening).
$isLibLong = (realpath(__FILE__) !== realpath($_SERVER['SCRIPT_FILENAME']));

// Allow caller to pick which source to use (0-based index).
// LIBRARY MODE IGNORES $_GET (2026-07-23): when require'd, the query string belongs to
// whatever outside request triggered the regen — a stray ?source= must not silently
// drop one of the two lists from the compiled blocklist.
$sourceParam = (!$isLibLong && isset($_GET['source'])) ? intval($_GET['source']) : null;
if ($sourceParam !== null && isset($txtUrls[$sourceParam])) {
    // Only keep the selected URL
    $txtUrls = [ $txtUrls[$sourceParam] ];
}

$domains = [];

// Timeout raised 10s -> 60s (2026-07-23): these files are ~4.3MB each and this now
// runs post-flush (no user waiting); the bound only protects the worker from a hang.
$fetchCtxLong = stream_context_create(['http' => ['timeout' => 60]]);

// Loop through each TXT URL, fetch the content, and push the domains into the array
foreach ($txtUrls as $txtUrl) {
    // Fetch TXT content from each URL using file(), which automatically removes newlines and skips empty lines.
    $lines = @file($txtUrl, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES, $fetchCtxLong);

    // LAST-GOOD MIRROR (2026-07-23): save every successful fetch; on failure fall back
    // to the saved copy instead of aborting the whole compiled-rules generation (the
    // 07-17..07-23 freeze was this abort happening daily).
    $longMirror = __DIR__ . '/sources/' . basename(parse_url($txtUrl, PHP_URL_PATH));
    if ($lines !== false && count($lines) > 100) {
        if (!is_dir(__DIR__ . '/sources')) @mkdir(__DIR__ . '/sources', 0755);
        @file_put_contents($longMirror, implode("\n", $lines));
    } else {
        $lines = @file($longMirror, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines !== false) error_log("long.php: GitHub fetch failed for $txtUrl - using last-good mirror");
    }
    if ($lines === false) {
        if ($isLibLong) throw new \RuntimeException("long.php: unable to fetch TXT data from $txtUrl (and no mirror).");
        die("Error: Unable to fetch TXT data from $txtUrl.");
    }

    // Process each line: skip comments (lines starting with '#')
    foreach ($lines as $line) {
        $line = trim($line);
        if (strpos($line, '#') === 0) {
            continue;
        }
        $domains[] = $line;
    }
}

// Remove duplicate domains and reindex the array
$domains = array_values(array_unique($domains));

// Retrieve URL parameters (with defaults).
// LIBRARY MODE IGNORES $_GET (2026-07-23): a stray ?number=50&random=yes on the
// triggering request would otherwise compile a 50-domain blocklist and SHIP it
// fleet-wide with a valid version bump. Library mode always returns the full list.
$format = ($isLibLong || !isset($_GET['format'])) ? "3" : $_GET['format'];           // Format: 1, 2, or 3
$order   = ($isLibLong || !isset($_GET['order']))  ? "none"   : strtolower($_GET['order']); // Order: asc, desc, or none
$start   = ($isLibLong || !isset($_GET['start']))  ? "bottom" : strtolower($_GET['start']); // Start: top or bottom
$number  = ($isLibLong || !isset($_GET['number'])) ? count($domains) : intval($_GET['number']); // Number of domains to return
$random  = ($isLibLong || !isset($_GET['random'])) ? "no"     : strtolower($_GET['random']);    // Random: yes or no

// Validate $number to be non-negative
if ($number < 0) {
    $number = count($domains);
}

// Process the list of domains based on the parameters
if ($random === "yes") {
    // Random branch: order and start parameters are ignored when random is activated.
    if ($number < count($domains)) {
        shuffle($domains);
        $domains = array_slice($domains, 0, $number);
    }
} else {
    // Order the domains if specified
    if ($order === "asc") {
        sort($domains, SORT_STRING);
    } else if ($order === "desc") {
        rsort($domains, SORT_STRING);
    }
    
    // Select a slice of domains according to the 'start' parameter if $number limits the output
    if ($number < count($domains)) {
        if ($start === "top") {
            $domains = array_slice($domains, 0, $number);
        } else if ($start === "bottom") {
            $domains = array_slice($domains, -$number, $number);
        }
    }
}

// Output in different formats based on the 'format' parameter
switch ($format) {
    case "1":
        // Format 1: Each domain is output as plain text (each line: "domain", with no trailing comma on the last line)
        header('Content-Type: text/plain');
        $total = count($domains);
        foreach ($domains as $index => $domain) {
            if ($index === $total - 1) {
                echo '"' . $domain . '"' . "\n";
            } else {
                echo '"' . $domain . '",' . "\n";
            }
        }
        break;

    case "2":
        // Format 2: JSON objects with key "redirect"
        $result = [];
        foreach ($domains as $domain) {
            $result[] = ["redirect" => $domain];
        }
        header('Content-Type: application/json');
        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        break;
        
    case "3":
        // Format 3: Simple JSON array of domain strings (API mode) or return array (library mode)
        if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'])) {
            // Direct access -> behave like API
            header('Content-Type: application/json');
            echo json_encode($domains, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            exit;
        } else {
            // Included via require_once -> return PHP array
            return $domains;
        }
        break;

    default:
        header('Content-Type: text/plain');
        echo "Invalid format specified. Use format=1, format=2, or format=3.";
        break;
}

/*
Example API Calls:

1. Default Call (all domains, no special formatting):
   http://example.com/path/to/script.php

2. Plain Text Format (Format 1):
   http://example.com/path/to/script.php?format=1

3. JSON Objects (Format 2, each object has a "redirect" key):
   http://example.com/path/to/script.php?format=2

4. JSON Array (Format 3, simple array of domain strings):
   http://example.com/path/to/script.php?format=3

5. Ordered Ascending:
   http://example.com/path/to/script.php?order=asc

6. Ordered Descending:
   http://example.com/path/to/script.php?order=desc

7. Top Slice (first 10 domains from an ascending ordered list):
   http://example.com/path/to/script.php?order=asc&start=top&number=10

8. Bottom Slice (last 10 domains from an ascending ordered list):
   http://example.com/path/to/script.php?order=asc&start=bottom&number=10

9. Random Subset (10 random domains, ignoring order and start):
   http://example.com/path/to/script.php?random=yes&number=10

10. Combining Multiple Parameters (e.g., descending order, top 15 domains, plain text format):
    http://example.com/path/to/script.php?order=desc&start=top&number=15&format=1

11. Only first TXT source (index 0):
    http://example.com/path/to/script.php?source=0

12. Only second TXT source (index 1):
    http://example.com/path/to/script.php?source=1

Note:
- `source` must be a 0-based index into the `$txtUrls` array. If omitted or out of range, all URLs will be processed.
*/
?>
