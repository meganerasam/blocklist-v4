<?php
/**
 * generate_allow.php — UNIFIED ALLOWLIST GENERATOR (EasyList Adult)
 * Location: all-in-one/adult/allow/
 *
 * Reads the mirrored EasyList Adult allowlist sources (1 list)
 * and routes each parsed rule into the correct output file.
 *
 * SOURCES (1 list):
 *   adult_allowlist                   — Network allow rules (exceptions)
 *
 * OUTPUT FILES (all in the same directory):
 *   network.json
 *     → DNR "allow" rules that override network blocking.
 *       Uses "action": { "type": "allow" } with priority 2 to
 *       override the block rules (priority 1).
 *
 *   popup.json
 *     → DNR "allow" rules for popups (if any $popup exceptions exist).
 *       Uses "action": { "type": "allow" } with priority 2.
 *
 *   unhide.json
 *     → Domain-to-selectors mapping for CSS un-hiding. These are
 *       exception rules (#@#) that re-show elements hidden by
 *       generic.css on specific sites.
 *       Format: { "domain.com": ["#el1", ".class1"], ... }
 *
 * CLASSIFICATION LOGIC:
 *   For network rules (@@):
 *     1. Has $popup modifier?       → popup.json
 *     2. Everything else            → network.json
 *   For cosmetic rules (#@#):
 *     3. Domain-scoped un-hide      → unhide.json
 *
 * Usage:
 *   php generate_allow.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ─── Configuration ────────────────────────────────────────────────────

// Snapshots in, workspace out — never live URLs (sources/upstream.yml owns those).
$ROOT = dirname(__DIR__, 4);
$SNAP = $ROOT . '/sources/easylist';
$WORK = $ROOT . '/build/compile/.work/adult/allow';
if (!is_dir($WORK)) mkdir($WORK, 0777, true);

$sourceFiles = [
    // Network allow rules (exceptions)
    $SNAP . '/easylist_adult/adult_allowlist.txt',
];

// Output files (all in the same directory as this script)
$outputFiles = [
    'network' => $WORK . '/network.json',
    'popup'   => $WORK . '/popup.json',
    'unhide'  => $WORK . '/unhide.json',
];

// ─── Fetch all sources ────────────────────────────────────────────────
$allLines  = [];
$totalDown = 0;

echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║       UNIFIED ALLOWLIST GENERATOR — EasyList Adult          ║\n";
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

// ─── Parse a single allowlist network rule (@@...) ────────────────────
function parseAllowFilter(string $line): ?array {
    $line = trim($line);

    if (strpos($line, '@@') !== 0) return null;

    $line = substr($line, 2);
    if ($line === '') return null;

    $options      = [];
    $thirdParty   = null;
    $domains      = null;
    $isPopup      = false;

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
            } elseif ($opt === 'generichide' || $opt === 'csp') {
                // generichide handled separately, CSP not supported in DNR
                return null;
            } else {
                $options[] = $opt;
            }
        }
    } else {
        $filter = $line;
    }

    if ($filter === '') return null;
    if ($filter[0] === '/' && substr($filter, -1) === '/') return null;

    $isDomainAnchor = false;
    $domain         = null;
    $urlFilter      = null;

    if (strpos($filter, '||') === 0) {
        $remainder = substr($filter, 2);

        if (preg_match('/^([a-zA-Z0-9.*_-]+)\^(.*)$/', $remainder, $m)) {
            $domain   = strtolower($m[1]);
            $pathPart = $m[2];

            if ($pathPart === '' || $pathPart === '/') {
                $isDomainAnchor = true;
            } else {
                $urlFilter = '||' . $domain . '^' . $pathPart;
            }
        } elseif (preg_match('/^([a-zA-Z0-9.*_-]+)$/', $remainder, $m)) {
            $domain         = strtolower($m[1]);
            $isDomainAnchor = true;
        } else {
            $urlFilter = $filter;
        }
    } else {
        $urlFilter = $filter;
    }

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

    $category = $isPopup ? 'popup' : 'network';

    $result = [
        'category'  => $category,
        'condition' => $extraCondition,
    ];

    if ($isDomainAnchor && $domain !== null) {
        $result['type']   = 'domain';
        $result['domain'] = $domain;
    } elseif ($urlFilter !== null) {
        $result['type']      = 'urlFilter';
        $result['urlFilter'] = $urlFilter;
    } else {
        return null;
    }

    return $result;
}

function conditionSignature(array $condition): string {
    ksort($condition);
    return json_encode($condition);
}

// ─── Process all lines ────────────────────────────────────────────────
echo "Parsing and classifying allowlist rules...\n";

$buckets = [
    'network' => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
    'popup'   => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
];

$unhideMap = [];
$skipped   = 0;
$comments  = 0;

foreach ($allLines as $line) {
    $line = trim($line);

    if ($line === '' || (isset($line[0]) && $line[0] === '!')) {
        $comments++;
        continue;
    }

    // ── CSS unhide rules (#@#) ───────────────────────────────────────
    if (strpos($line, '#@#') !== false) {
        $parts = explode('#@#', $line, 2);
        $domainPart = trim($parts[0]);
        $selector   = trim($parts[1] ?? '');

        if ($selector === '' || $domainPart === '') {
            $skipped++;
            continue;
        }

        $domains = explode(',', $domainPart);
        foreach ($domains as $d) {
            $d = trim($d);
            if ($d === '') continue;
            if (!isset($unhideMap[$d])) {
                $unhideMap[$d] = [];
            }
            $unhideMap[$d][$selector] = true;
        }
        continue;
    }

    // ── Network allow rules (@@) ─────────────────────────────────────
    if (strpos($line, '@@') === 0) {
        $parsed = parseAllowFilter($line);

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
        continue;
    }

    $skipped++;
}

$unhideCount = 0;
foreach ($unhideMap as $sels) {
    $unhideCount += count($sels);
}

$totalNetwork = $buckets['network']['parsed'];
$totalPopup   = $buckets['popup']['parsed'];

echo "  ✓ Network allow:  $totalNetwork rules\n";
echo "  ✓ Popup allow:    $totalPopup rules\n";
echo "  ✓ CSS unhide:     $unhideCount selectors across " . count($unhideMap) . " domains\n";
echo "  ○ Skipped:        $skipped\n";
echo "  ○ Comments:       $comments\n\n";

// ─── Build and write network.json & popup.json ────────────────────────

// Ensure directory exists
if (!is_dir(__DIR__)) {
    mkdir(__DIR__, 0755, true);
}

foreach (['network', 'popup'] as $cat) {
    $outputFile = $outputFiles[$cat];

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    echo "  Building: " . basename($outputFile) . "\n";
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

    $rules  = [];
    $ruleId = 1;

    foreach ($buckets[$cat]['domainBuckets'] as $sig => $bucket) {
        $domains = array_keys($bucket['domains']);
        sort($domains);

        $condition = $bucket['condition'];
        $condition['requestDomains'] = $domains;

        $rules[] = [
            'id'        => $ruleId++,
            'priority'  => 2,
            'action'    => ['type' => 'allow'],
            'condition' => $condition,
        ];
    }

    $batchedCount = $ruleId - 1;

    foreach ($buckets[$cat]['urlFilterRules'] as $parsed) {
        $condition = $parsed['condition'];
        $condition['urlFilter'] = $parsed['urlFilter'];

        $rules[] = [
            'id'        => $ruleId++,
            'priority'  => 2,
            'action'    => ['type' => 'allow'],
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

    $json = json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) { fwrite(STDERR, "  ERROR: JSON encoding failed: " . json_last_error_msg() . " — aborting (fail-closed).\n"); exit(1); }
    $bytes = file_put_contents($outputFile, $json . "\n");
    if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }
    echo "  ✓ Written: " . basename($outputFile) . " ($bytes bytes)\n\n";
}

// ─── Build and write unhide.json ──────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  Building: unhide.json\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$unhideOutput = [];
ksort($unhideMap);
foreach ($unhideMap as $domain => $sels) {
    $selList = array_keys($sels);
    sort($selList);
    $unhideOutput[$domain] = $selList;
}

$json = json_encode($unhideOutput, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($json === false) { fwrite(STDERR, "  ERROR: JSON encoding failed: " . json_last_error_msg() . " — aborting (fail-closed).\n"); exit(1); }
$bytes = file_put_contents($outputFiles['unhide'], $json . "\n");
if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }
echo "  ✓ $unhideCount selectors across " . count($unhideOutput) . " domains → unhide.json ($bytes bytes)\n\n";

// ─── Final summary ────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║  DONE ✓                                                     ║\n";
echo "╠══════════════════════════════════════════════════════════════╣\n";

foreach ($outputFiles as $cat => $path) {
    $size = file_exists($path) ? filesize($path) : 0;
    $sizeKB = round($size / 1024);
    printf("║  %-10s → %s (%s KB)%s║\n",
        $cat,
        basename($path),
        str_pad($sizeKB, 5, ' ', STR_PAD_LEFT),
        str_repeat(' ', max(0, 20 - strlen(basename($path))))
    );
}

echo "╚══════════════════════════════════════════════════════════════╝\n";
