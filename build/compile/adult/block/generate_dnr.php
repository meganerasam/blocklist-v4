<?php
/**
 * generate_dnr.php — UNIFIED DNR GENERATOR (EasyList Adult)
 * Location: all-in-one/adult/block/
 *
 * Reads the mirrored EasyList Adult blocking filter sources (6 lists) and converts
 * them into Chrome declarativeNetRequest (DNR) rule sets.
 *
 * SOURCES (6 lists):
 *   adult_thirdparty_popup
 *   adult_thirdparty
 *   adult_specific_block_popup
 *   adult_specific_block
 *   adult_adservers_popup
 *   adult_adservers
 *
 * OUTPUT FILES (all in the same directory):
 *   domains.json
 *     → DNR rules targeting entire ad/tracker domains (domain-anchored).
 *       Domains with identical conditions are batched into a single rule.
 *
 *   popup.json
 *     → DNR rules specifically for popup blocking ($popup modifier).
 *
 *   urlfilter.json
 *     → DNR rules for path-pattern filters (URL substrings, wildcards).
 *       Each filter becomes one DNR rule with a urlFilter condition.
 *
 * CLASSIFICATION LOGIC:
 *   1. Has $popup modifier?         → popup.json
 *   2. Domain-anchor (||domain^)?   → domains.json (batched by condition)
 *   3. Everything else              → urlfilter.json
 *
 * Usage:
 *   php generate_dnr.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ─── Configuration ────────────────────────────────────────────────────

// Snapshots in, workspace out — never live URLs (sources/upstream.yml owns those).
$ROOT = dirname(__DIR__, 4);
$SNAP = $ROOT . '/sources/easylist';
$WORK = $ROOT . '/build/compile/.work/adult/block';
if (!is_dir($WORK)) mkdir($WORK, 0777, true);

$sourceFiles = [
    $SNAP . '/easylist_adult/adult_thirdparty_popup.txt',
    $SNAP . '/easylist_adult/adult_thirdparty.txt',
    $SNAP . '/easylist_adult/adult_specific_block_popup.txt',
    $SNAP . '/easylist_adult/adult_specific_block.txt',
    $SNAP . '/easylist_adult/adult_adservers_popup.txt',
    $SNAP . '/easylist_adult/adult_adservers.txt',
];

// Output files (all in the same directory as this script)
$outputFiles = [
    'domains'   => $WORK . '/domains.json',
    'popup'     => $WORK . '/popup.json',
    'urlfilter' => $WORK . '/urlfilter.json',
];

// ─── Fetch all sources ────────────────────────────────────────────────
$allLines  = [];
$totalDown = 0;

echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║       UNIFIED DNR GENERATOR — EasyList Adult                ║\n";
echo "╚══════════════════════════════════════════════════════════════╝\n\n";

echo "Reading snapshot files...\n";
foreach ($sourceFiles as $i => $url) { // $url = local snapshot path
    $num = $i + 1;
    $filename = basename($url);
    echo "  [$num/" . count($sourceFiles) . "] $filename\n";

    $raw = @file_get_contents($url);
    if ($raw === false || trim($raw) === '') {
        fwrite(STDERR, "    ERROR: snapshot missing or empty: $url — aborting (fail-closed).\n");
        exit(1);
    }

    $lines = explode("\n", $raw);
    echo "    ✓ " . count($lines) . " lines\n";
    $allLines  = array_merge($allLines, $lines);
    $totalDown += count($lines);
}

echo "  Total: $totalDown lines from " . count($sourceFiles) . " source(s).\n\n";

if (empty($allLines)) {
    fwrite(STDERR, "ERROR: No lines downloaded from any source.\n");
    exit(1);
}

// ─── Mapping: EasyList option → DNR resourceType ──────────────────────
function mapResourceTypes(array $options): ?array {
    $map = [
        'script'         => 'script',
        'image'          => 'image',
        'stylesheet'     => 'stylesheet',
        'object'         => 'object',
        'xmlhttprequest' => 'xmlhttprequest',
        'subdocument'    => 'sub_frame',
        'sub_frame'      => 'sub_frame',
        'document'       => 'main_frame',
        'main_frame'     => 'main_frame',
        'font'           => 'font',
        'media'          => 'media',
        'websocket'      => 'websocket',
        'ping'           => 'ping',
        'popup'          => 'main_frame',
        'other'          => 'other',
    ];

    $include = [];
    $exclude = [];

    foreach ($options as $opt) {
        $opt = strtolower(trim($opt));
        if (strpos($opt, '~') === 0) {
            $negated = substr($opt, 1);
            if (isset($map[$negated])) {
                $exclude[] = $map[$negated];
            }
        } elseif (isset($map[$opt])) {
            $include[] = $map[$opt];
        }
    }

    if (!empty($include)) {
        return array_values(array_unique($include));
    }

    if (!empty($exclude)) {
        $all = [
            'main_frame', 'sub_frame', 'stylesheet', 'script', 'image',
            'font', 'object', 'xmlhttprequest', 'ping', 'media',
            'websocket', 'webtransport', 'webbundle', 'other'
        ];
        $result = array_values(array_diff($all, array_unique($exclude)));
        return empty($result) ? null : $result;
    }

    return null;
}

// ─── Parse a single filter line ───────────────────────────────────────
function parseFilter(string $line): ?array {
    $line = trim($line);

    if ($line === '')                          return null;
    if ($line[0] === '!')                     return null;
    if (strpos($line, '##') !== false)        return null;
    if (strpos($line, '#@#') !== false)       return null;
    if (strpos($line, '#?#') !== false)       return null;
    if (strpos($line, '##+js') !== false)     return null;
    if (strpos($line, '@@') === 0)            return null;

    if ($line[0] === '/' && substr($line, -1) === '/') return null;
    $filterPart = preg_replace('/\$.*$/', '', $line);
    if (preg_match('#^/.*/$#', $filterPart))  return null;

    // ── Separate filter from options ──────────────────────────────────
    $options    = [];
    $thirdParty = null;
    $domains    = null;
    $isPopup    = false;

    $dollarPos = strrpos($line, '$');
    if ($dollarPos !== false && $dollarPos > 0) {
        $optStr = substr($line, $dollarPos + 1);
        $filter = substr($line, 0, $dollarPos);

        foreach (explode(',', $optStr) as $opt) {
            $opt = strtolower(trim($opt));
            if ($opt === 'third-party' || $opt === '3p') {
                $thirdParty = true;
            } elseif ($opt === '~third-party' || $opt === '~3p') {
                $thirdParty = false;
            } elseif (strpos($opt, 'domain=') === 0) {
                $domains = substr($opt, 7);
            } elseif ($opt === 'popup') {
                $isPopup = true;
                $options[] = $opt;
            } else {
                $options[] = $opt;
            }
        }
    } else {
        $filter = $line;
    }

    if ($filter === '') return null;

    // ── Determine if this is a domain-anchor rule ─────────────────────
    $isDomainAnchor = false;
    $domain         = null;
    $urlFilter      = null;

    if (strpos($filter, '||') === 0) {
        $remainder = substr($filter, 2);

        if (preg_match('/^([a-zA-Z0-9._-]+)\^(.*)$/', $remainder, $m)) {
            $domain   = strtolower($m[1]);
            $pathPart = $m[2];

            if ($pathPart === '' || $pathPart === '/') {
                $isDomainAnchor = true;
            } else {
                $urlFilter = '||' . $domain . '^' . $pathPart;
            }
        } elseif (preg_match('/^([a-zA-Z0-9._-]+)$/', $remainder, $m)) {
            $domain         = strtolower($m[1]);
            $isDomainAnchor = true;
        } else {
            $urlFilter = $filter;
        }
    } elseif (isset($filter[0]) && $filter[0] === '|' && strpos($filter, '||') !== 0) {
        $urlFilter = $filter;
    } else {
        $urlFilter = $filter;
    }

    // ── Build extra condition properties ─────────────────────────────
    $extraCondition = [];

    $resourceTypes = mapResourceTypes($options);
    if ($resourceTypes !== null) {
        sort($resourceTypes);
        $extraCondition['resourceTypes'] = $resourceTypes;
    }

    if ($thirdParty === true) {
        $extraCondition['domainType'] = 'thirdParty';
    } elseif ($thirdParty === false) {
        $extraCondition['domainType'] = 'firstParty';
    }

    if ($domains !== null) {
        $include = [];
        $exclude = [];
        foreach (explode('|', $domains) as $d) {
            $d = trim($d);
            if ($d === '') continue;
            if ($d[0] === '~') {
                $exclude[] = substr($d, 1);
            } else {
                $include[] = $d;
            }
        }
        if (!empty($include)) {
            sort($include);
            $extraCondition['initiatorDomains'] = $include;
        }
        if (!empty($exclude)) {
            sort($exclude);
            $extraCondition['excludedInitiatorDomains'] = $exclude;
        }
    }

    // ── Classify into category ───────────────────────────────────────
    if ($isPopup) {
        $category = 'popup';
    } elseif ($isDomainAnchor && $domain !== null) {
        $category = 'domains';
    } else {
        $category = 'urlfilter';
    }

    // ── Return parsed result ─────────────────────────────────────────
    if ($isDomainAnchor && $domain !== null) {
        return [
            'category'  => $category,
            'type'      => 'domain',
            'domain'    => $domain,
            'condition' => $extraCondition,
        ];
    } elseif ($urlFilter !== null) {
        return [
            'category'  => $category,
            'type'      => 'urlFilter',
            'urlFilter' => $urlFilter,
            'condition' => $extraCondition,
        ];
    }

    return null;
}

function conditionSignature(array $condition): string {
    ksort($condition);
    return json_encode($condition);
}

// ─── Process all lines ────────────────────────────────────────────────
echo "Parsing and classifying filters...\n";

$buckets = [
    'domains'   => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
    'popup'     => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
    'urlfilter' => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
];

$skipped  = 0;
$comments = 0;

foreach ($allLines as $line) {
    $line = trim($line);

    if ($line === '' || (isset($line[0]) && $line[0] === '!')) {
        $comments++;
        continue;
    }

    $parsed = parseFilter($line);

    if ($parsed === null) {
        $skipped++;
        continue;
    }

    $cat = $parsed['category'];
    $buckets[$cat]['parsed']++;

    if ($parsed['type'] === 'domain') {
        $sig = conditionSignature($parsed['condition']);
        if (!isset($buckets[$cat]['domainBuckets'][$sig])) {
            $buckets[$cat]['domainBuckets'][$sig] = [
                'domains'   => [],
                'condition' => $parsed['condition'],
            ];
        }
        $buckets[$cat]['domainBuckets'][$sig]['domains'][$parsed['domain']] = true;
    } else {
        $buckets[$cat]['urlFilterRules'][] = $parsed;
    }
}

$totalParsed = $buckets['domains']['parsed'] + $buckets['popup']['parsed'] + $buckets['urlfilter']['parsed'];

echo "  ✓ Parsed:     $totalParsed filters\n";
echo "  ○ Skipped:    $skipped (cosmetic/scriptlet/allowlist/regex)\n";
echo "  ○ Comments:   $comments\n";
echo "  ── Routed to: ──\n";
echo "    domains/   : " . $buckets['domains']['parsed'] . " filters\n";
echo "    popup/     : " . $buckets['popup']['parsed'] . " filters\n";
echo "    urlfilter/ : " . $buckets['urlfilter']['parsed'] . " filters\n\n";

// Ensure directory exists
if (!is_dir(__DIR__)) {
    mkdir(__DIR__, 0755, true);
}

// ─── Build and write each JSON ────────────────────────────────────────

foreach ($outputFiles as $cat => $outputFile) {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    echo "  Building: $cat/\n";
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

    $rules  = [];
    $ruleId = 1;

    // Domain-batched rules
    foreach ($buckets[$cat]['domainBuckets'] as $sig => $bucket) {
        $domains = array_keys($bucket['domains']);
        sort($domains);

        $condition = $bucket['condition'];
        $condition['requestDomains'] = $domains;

        $rules[] = [
            'id'        => $ruleId++,
            'priority'  => 1,
            'action'    => ['type' => 'block'],
            'condition' => $condition,
        ];
    }

    $batchedCount = $ruleId - 1;

    // urlFilter rules (one each)
    foreach ($buckets[$cat]['urlFilterRules'] as $parsed) {
        $condition = $parsed['condition'];
        $condition['urlFilter'] = $parsed['urlFilter'];

        $rules[] = [
            'id'        => $ruleId++,
            'priority'  => 1,
            'action'    => ['type' => 'block'],
            'condition' => $condition,
        ];
    }

    $urlFilterCount = count($buckets[$cat]['urlFilterRules']);

    echo "  Domain-batched rules: $batchedCount\n";
    echo "  URL-filter rules:     $urlFilterCount\n";
    echo "  Total DNR rules:      " . count($rules) . "\n";

    if (!empty($buckets[$cat]['domainBuckets'])) {
        echo "  ── Domain buckets ──\n";
        $bucketNum = 0;
        foreach ($buckets[$cat]['domainBuckets'] as $sig => $bucket) {
            $bucketNum++;
            $domainCount = count($bucket['domains']);
            $condLabel = ($sig === '[]' || $sig === '{}') ? '(no extra conditions)' : $sig;
            echo "    Rule $bucketNum: $domainCount domains — $condLabel\n";
        }
    }

    // Write JSON
    $json = json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) { fwrite(STDERR, "  ERROR: JSON encoding failed: " . json_last_error_msg() . " — aborting (fail-closed).\n"); exit(1); }

    if ($json === false) {
        fwrite(STDERR, "  ERROR: JSON encoding failed for $cat: " . json_last_error_msg() . "\n");
        exit(1);
    }

    $bytes = file_put_contents($outputFile, $json . "\n");
    if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }

    if ($bytes === false) {
        fwrite(STDERR, "  ERROR: Failed to write $outputFile\n");
        exit(1);
    }

    echo "  ✓ Written: " . basename($outputFile) . " ($bytes bytes)\n\n";
}

// ─── Final summary ────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║  DONE ✓                                                     ║\n";
echo "╠══════════════════════════════════════════════════════════════╣\n";

foreach ($outputFiles as $cat => $path) {
    $size = file_exists($path) ? filesize($path) : 0;
    $sizeKB = round($size / 1024);
    printf("║  %-12s → %s (%s KB)%s║\n",
        $cat . '/',
        basename($path),
        str_pad($sizeKB, 5, ' ', STR_PAD_LEFT),
        str_repeat(' ', max(0, 14 - strlen(basename($path))))
    );
}

echo "╚══════════════════════════════════════════════════════════════╝\n";
