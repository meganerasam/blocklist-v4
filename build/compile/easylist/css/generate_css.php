<?php
/**
 * generate_css.php — UNIFIED CSS COSMETIC FILTER GENERATOR
 * Location: all-in-one/easylist/css/
 *
 * Reads the mirrored EasyList cosmetic/element-hiding filter sources (3 lists)
 * and converts them into injectable CSS files for a browser extension.
 *
 * SOURCES (3 lists):
 *   general_hide       — Element-hiding selectors applied on ALL websites
 *   specific_hide      — Element-hiding selectors scoped to specific domains
 *   specific_hide_abp  — ABP extended CSS (uses :has-text(), CSS injection, etc.)
 *
 * OUTPUT FILES (all in the same directory):
 *   generic.css
 *     → All selectors combined into one CSS rule with a single
 *       { display: none !important; } declaration.
 *       Injected via content_scripts with "matches": ["<all_urls>"].
 *
 *   specific.json
 *     → Domain-to-selectors mapping for per-site element hiding.
 *       The extension's content script reads this JSON, checks the
 *       current domain, and injects only the relevant selectors.
 *       Format: { "domain.com": ["#ad1", ".banner"], ... }
 *
 *   extended.json
 *     → ABP extended CSS rules that require JavaScript processing.
 *       These use non-standard selectors like :has-text() which
 *       cannot be expressed in pure CSS. The extension needs a JS
 *       content script to evaluate and apply these rules.
 *       Format: { "domain.com": [{ "selector": "...", "type": "..." }], ... }
 *
 * CLASSIFICATION LOGIC:
 *   1. No domain prefix (##)      → generic.css
 *   2. Domain prefix (site##)     → specific.json
 *   3. Extended CSS (#?#)         → extended.json
 *   4. CSS injection ({...})      → extended.json (property override)
 *
 * Usage:
 *   php generate_css.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ─── Configuration ────────────────────────────────────────────────────

// Snapshots in, workspace out — never live URLs (sources/upstream.yml owns those).
$ROOT = dirname(__DIR__, 4);
$SNAP = $ROOT . '/sources/easylist';
$WORK = $ROOT . '/build/compile/.work/easylist/css';
if (!is_dir($WORK)) mkdir($WORK, 0777, true);

$sourceFiles = [
    // General element-hiding selectors (apply on all websites)
    $SNAP . '/easylist/easylist_general_hide.txt',
    // Site-specific element-hiding selectors
    $SNAP . '/easylist/easylist_specific_hide.txt',
    // ABP extended CSS (content-aware hiding with :has-text, CSS injection)
    $SNAP . '/easylist/easylist_specific_hide_abp.txt',
];

// Output files (all in the same directory as this script)
$outputFiles = [
    'generic'  => $WORK . '/generic.css',
    'specific' => $WORK . '/specific.json',
    'extended' => $WORK . '/extended.json',
];

// ─── Fetch all sources ────────────────────────────────────────────────
$allLines  = [];
$totalDown = 0;

echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║       UNIFIED CSS GENERATOR — EasyList Cosmetic Filters     ║\n";
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

// ─── Parse cosmetic filters ──────────────────────────────────────────

echo "Parsing and classifying cosmetic filters...\n";

$generalSelectors  = [];   // Selectors for general.css
$specificMap       = [];   // domain => [selectors] for specific.json
$extendedMap       = [];   // domain => [{selector, type}] for extended.json
$skipped           = 0;
$comments          = 0;

foreach ($allLines as $line) {
    $line = trim($line);

    // Skip empty lines and comments
    if ($line === '' || (isset($line[0]) && $line[0] === '!')) {
        $comments++;
        continue;
    }

    // Skip exception rules (#@#) — these are whitelist rules
    if (strpos($line, '#@#') !== false) {
        $skipped++;
        continue;
    }

    // ── Detect ABP extended CSS (#?#) ────────────────────────────────
    if (strpos($line, '#?#') !== false) {
        $parts = explode('#?#', $line, 2);
        $domainPart = trim($parts[0]);
        $selector   = trim($parts[1]);

        if ($domainPart === '') {
            // General extended CSS (rare)
            $extendedMap['*'][] = [
                'selector' => $selector,
                'type'     => 'extended',
            ];
        } else {
            // Domain-specific extended CSS
            $domains = explode(',', $domainPart);
            foreach ($domains as $d) {
                $d = trim($d);
                if ($d === '') continue;
                $extendedMap[$d][] = [
                    'selector' => $selector,
                    'type'     => 'extended',
                ];
            }
        }
        continue;
    }

    // ── Detect standard element hiding (##) ──────────────────────────
    $hashPos = strpos($line, '##');
    if ($hashPos === false) {
        $skipped++;
        continue;
    }

    $domainPart = trim(substr($line, 0, $hashPos));
    $selector   = trim(substr($line, $hashPos + 2));

    if ($selector === '') {
        $skipped++;
        continue;
    }

    // ── Check for CSS injection rules (contain { }) ──────────────────
    // e.g. benzinga.com##.cUDaEv {margin-top:162px !important;}
    if (preg_match('/\{[^}]+\}/', $selector)) {
        // This is a CSS property injection, not just element hiding
        if ($domainPart === '') {
            $extendedMap['*'][] = [
                'selector' => $selector,
                'type'     => 'css-injection',
            ];
        } else {
            $domains = explode(',', $domainPart);
            foreach ($domains as $d) {
                $d = trim($d);
                if ($d === '') continue;
                $extendedMap[$d][] = [
                    'selector' => $selector,
                    'type'     => 'css-injection',
                ];
            }
        }
        continue;
    }

    // ── General selector (no domain prefix) ──────────────────────────
    if ($domainPart === '') {
        $generalSelectors[$selector] = true;
        continue;
    }

    // ── Domain-specific selector ─────────────────────────────────────
    $domains = explode(',', $domainPart);
    foreach ($domains as $d) {
        $d = trim($d);
        if ($d === '') continue;
        if (!isset($specificMap[$d])) {
            $specificMap[$d] = [];
        }
        $specificMap[$d][$selector] = true;
    }
}

$generalCount  = count($generalSelectors);
$specificCount = 0;
foreach ($specificMap as $sels) {
    $specificCount += count($sels);
}
$extendedCount = 0;
foreach ($extendedMap as $rules) {
    $extendedCount += count($rules);
}

echo "  ✓ General selectors:  $generalCount (apply on all websites)\n";
echo "  ✓ Specific selectors: $specificCount across " . count($specificMap) . " domains\n";
echo "  ✓ Extended/ABP rules: $extendedCount across " . count($extendedMap) . " domains\n";
echo "  ○ Skipped:            $skipped\n";
echo "  ○ Comments:           $comments\n\n";

// ─── Generate generic.css ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  Building: generic.css\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$css  = "/*\n";
$css .= " * generic.css — EasyList Generic Element Hiding\n";
$css .= " * Auto-generated by generate_css.php\n";
$css .= " * Generated: " . date('Y-m-d H:i:s T') . "\n";
$css .= " *\n";
$css .= " * These selectors hide ad elements on ALL websites.\n";
$css .= " * Inject via content_scripts with matches: [\"<all_urls>\"]\n";
$css .= " *\n";
$css .= " * Total selectors: $generalCount\n";
$css .= " */\n\n";

// All selectors share the same declaration, so we combine them
// into one comma-separated rule for compact output.
$selectors = array_keys($generalSelectors);
sort($selectors);

$css .= implode(",\n", $selectors);
$css .= " {\n  display: none !important;\n}\n";

$bytes = file_put_contents($outputFiles['generic'], $css);
if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }
echo "  ✓ $generalCount selectors → generic.css ($bytes bytes)\n\n";

// ─── Generate specific.json ──────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  Building: specific.json\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

// Convert sets to arrays and sort
$specificOutput = [];
ksort($specificMap);
foreach ($specificMap as $domain => $sels) {
    $selList = array_keys($sels);
    sort($selList);
    $specificOutput[$domain] = $selList;
}

$json = json_encode($specificOutput, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($json === false) { fwrite(STDERR, "  ERROR: JSON encoding failed: " . json_last_error_msg() . " — aborting (fail-closed).\n"); exit(1); }
$bytes = file_put_contents($outputFiles['specific'], $json . "\n");
if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }
$domainCount = count($specificOutput);
echo "  ✓ $specificCount selectors across $domainCount domains → specific.json ($bytes bytes)\n\n";

// ─── Generate extended.json ──────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  Building: extended.json\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

ksort($extendedMap);
$json = json_encode($extendedMap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($json === false) { fwrite(STDERR, "  ERROR: JSON encoding failed: " . json_last_error_msg() . " — aborting (fail-closed).\n"); exit(1); }
$bytes = file_put_contents($outputFiles['extended'], $json . "\n");
if ($bytes === false) { fwrite(STDERR, "  ERROR: output write failed — aborting (fail-closed).\n"); exit(1); }
$extDomainCount = count($extendedMap);
echo "  ✓ $extendedCount rules across $extDomainCount domains → extended.json ($bytes bytes)\n\n";

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
