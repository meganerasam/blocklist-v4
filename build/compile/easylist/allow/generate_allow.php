<?php
/**
 * generate_allow.php — UNIFIED ALLOWLIST GENERATOR
 * Location: all-in-one/easylist/allow/
 *
 * Reads the mirrored EasyList allowlist sources (4 lists) and automatically
 * routes each parsed rule into the correct output file based on its type.
 *
 * SOURCES (4 lists):
 *   allowlist           — Network allow rules (override ad-server blocks)
 *   allowlist_popup     — Popup allow rules (override popup blocks)
 *   allowlist_dimensions— Dimension-pattern allow rules (override dimension blocks)
 *   allowlist_general_hide — CSS unhide rules (override element hiding)
 *
 * OUTPUT FILES (all in the same directory):
 *   network.json
 *     → DNR "allow" rules that override network blocking. These are
 *       exception rules for legitimate ad infrastructure that certain
 *       sites need to function (e.g. video players, captcha, prebid).
 *       Includes both domain-anchored and URL-pattern exceptions.
 *       Uses "action": { "type": "allow" } with priority 2 to
 *       override the block rules (priority 1).
 *
 *   popup.json
 *     → DNR "allow" rules for popups. Exceptions for legitimate
 *       popup navigations (e.g. ad platform dashboards, ticketing).
 *       Uses "action": { "type": "allow" } with priority 2.
 *
 *   unhide.json
 *     → Domain-to-selectors mapping for CSS un-hiding. These are
 *       exception rules (#@#) that re-show elements hidden by
 *       generic.css on specific sites. The extension reads this JSON,
 *       checks the current domain, and injects matching selectors
 *       with { display: block !important; } to override the hide.
 *       Format: { "domain.com": ["#ad1", ".banner"], ... }
 *
 * CLASSIFICATION LOGIC:
 *   For network rules (@@):
 *     1. Has $popup modifier?       → popup.json
 *     2. Has $generichide modifier? → generichide list in network.json
 *     3. Everything else            → network.json
 *   For cosmetic rules (#@#):
 *     4. Domain-scoped un-hide      → unhide.json
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
$WORK = $ROOT . '/build/compile/.work/easylist/allow';
if (!is_dir($WORK)) mkdir($WORK, 0777, true);

$sourceFiles = [
    // Network allow rules (override ad-server blocks, prebid, captcha, etc.)
    $SNAP . '/easylist/easylist_allowlist.txt',
    // Popup allow rules (override popup blocks for ad dashboards, ticketing)
    $SNAP . '/easylist/easylist_allowlist_popup.txt',
    // Dimension-pattern allow rules (override dimension-based blocks)
    $SNAP . '/easylist/easylist_allowlist_dimensions.txt',
    // CSS unhide rules (re-show elements hidden by generic.css on specific sites)
    $SNAP . '/easylist/easylist_allowlist_general_hide.txt',
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
echo "║     UNIFIED ALLOWLIST GENERATOR — EasyList Exceptions       ║\n";
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

    // Must start with @@
    if (strpos($line, '@@') !== 0) return null;

    // Strip the @@ prefix
    $line = substr($line, 2);

    if ($line === '') return null;

    // ── Separate filter from options ──────────────────────────────────
    $options      = [];
    $thirdParty   = null;
    $domains      = null;
    $isPopup      = false;
    $isGenericHide = false;

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
            } elseif ($opt === 'generichide') {
                $isGenericHide = true;
            } elseif ($opt === 'csp') {
                // CSP rules not supported in DNR
                return null;
            } else {
                $options[] = $opt;
            }
        }
    } else {
        $filter = $line;
    }

    if ($filter === '') return null;

    // Skip regex patterns
    if ($filter[0] === '/' && substr($filter, -1) === '/') return null;

    // ── Determine if domain-anchor ───────────────────────────────────
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
    } else {
        $category = 'network';
    }

    // ── Return parsed result ─────────────────────────────────────────
    $result = [
        'category'      => $category,
        'condition'     => $extraCondition,
        'isGenericHide' => $isGenericHide,
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

// DNR buckets for network & popup
$buckets = [
    'network' => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
    'popup'   => ['domainBuckets' => [], 'urlFilterRules' => [], 'parsed' => 0],
];

// CSS unhide map: domain => [selectors]
$unhideMap    = [];
$skipped      = 0;
$comments     = 0;
$genericHides = 0;

foreach ($allLines as $line) {
    $line = trim($line);

    // Skip empty lines and comments
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

        // Track generichide rules (they go into network.json as allow rules)
        if ($parsed['isGenericHide']) {
            $genericHides++;
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

    // Anything else is not an allowlist rule
    $skipped++;
}

// Count unhide selectors
$unhideCount = 0;
foreach ($unhideMap as $sels) {
    $unhideCount += count($sels);
}

$totalNetwork = $buckets['network']['parsed'];
$totalPopup   = $buckets['popup']['parsed'];

echo "  ✓ Network allow:  $totalNetwork rules\n";
echo "  ✓ Popup allow:    $totalPopup rules\n";
echo "  ✓ CSS unhide:     $unhideCount selectors across " . count($unhideMap) . " domains\n";
echo "  ✓ Generichide:    $genericHides rules (in network.json)\n";
echo "  ○ Skipped:        $skipped\n";
echo "  ○ Comments:       $comments\n\n";

// ─── Build and write network.json & popup.json ────────────────────────

foreach (['network', 'popup'] as $cat) {
    $outputFile = $outputFiles[$cat];

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    echo "  Building: " . basename($outputFile) . "\n";
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
            'priority'  => 2,
            'action'    => ['type' => 'allow'],
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
