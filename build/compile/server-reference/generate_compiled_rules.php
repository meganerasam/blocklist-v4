<?php
// backend/prod/generate_compiled_rules_v2.php
// v2: Separates sources by intent — short+popup→redirect, long→block, dnr.json→as-is
ini_set('memory_limit', '512M');
set_time_limit(300);
ignore_user_abort(true); // safe as a bg_run/self-call target: an early client close must not kill the run

// LAST-GOOD SOURCE MIRRORS (2026-07-23): every successful GitHub fetch (here and in
// short.php/long.php) is saved under sources/; a failed fetch falls back to the saved
// copy instead of aborting the whole generation. Created on demand.
if (!is_dir(__DIR__ . '/sources')) {
    @mkdir(__DIR__ . '/sources', 0755);
}

// TMP-ORPHAN SWEEP (2026-07-15 incident): a run that dies between file_put_contents and
// rename (300s timeout, fatal) leaves a multi-MB compiled_rules_cache_<uniqid>.tmp behind
// FOREVER — the incident stampede left GBs of them. Sweep anything older than 1h.
foreach ((glob(__DIR__ . '/compiled_rules_cache_*.tmp') ?: []) as $__orphan) {
    if (@filemtime($__orphan) < time() - 3600) @unlink($__orphan);
}

$latestUpdatedBlockList   = require_once __DIR__ . '/short.php'; // From our Google sheet popup list
$latestUpdatedBlockListv2 = require_once __DIR__ . '/long.php'; // Automated collection of domains on our GitHub

if (!is_array($latestUpdatedBlockList) || empty($latestUpdatedBlockList)) {
    error_log("ERROR: Unable to fetch short blocklist data - skipping generation");
    return;
}
if (!is_array($latestUpdatedBlockListv2) || empty($latestUpdatedBlockListv2)) {
    error_log("ERROR: Unable to fetch long blocklist data - skipping generation");
    return;
}

$rules = [];

// ============================================
// UNIFIED ID COUNTERS — ALL compiled rules use IDs >= 11000
// IDs < 11000 are RESERVED for PHP inline rules (injectGoogleScripts, rule 2002, rule 8002, etc.)
// ============================================
$idCounters = [
    'redirect'         => 11000,
    'block'            => 21000,
    'modifyHeaders'    => 31000,
    'allow'            => 41000,
    'allowAllRequests' => 51000,
];

// ============================================
// STEP 1: REDIRECT RULES — short.php (popup/malicious domains → blocked.html)
// These are domains where main_frame navigation should be intercepted and
// redirected to the extension's "blocked" page.
// ============================================
$shortDomains = array_values(array_unique($latestUpdatedBlockList));
$shortChunks = array_chunk($shortDomains, 5000);

foreach ($shortChunks as $domains) {
    $rules[] = [
        'id' => $idCounters['redirect']++,
        'priority' => 3,
        'action' => [
            'type' => 'redirect',
            'redirect' => [
                'regexSubstitution' => "chrome-extension://__EXT_ID__/pages/popup-tracker.html?url=\\0",
            ],
        ],
        'condition' => [
            'regexFilter' => '^http.+',
            'requestDomains' => $domains,
            'resourceTypes' => ['main_frame'],
        ],
    ];
}

error_log(sprintf(
    "INFO [v2]: Short (redirect) — %d unique domains, %d chunked rules",
    count($shortDomains),
    count($shortChunks)
));


// ============================================
// STEP 2: BLOCK + REDIRECT RULES — long.php (ad/tracker domains)
// Block: sub-resource types (scripts, images, xhr, etc.) — priority 1
// Redirect: main_frame navigation → popup-tracker.html — priority 3
// ============================================
$longDomains = array_values(array_unique($latestUpdatedBlockListv2));
$last50000 = array_slice($longDomains, -50000);
$longChunks = array_chunk($last50000, 5000);

foreach ($longChunks as $domains) {
    // Block rule — sub-resource blocking (priority 1)
    $rules[] = [
        'id' => $idCounters['block']++,
        'priority' => 1,
        'action' => ['type' => 'block'],
        'condition' => [
            'resourceTypes' => ['script', 'xmlhttprequest', 'sub_frame', 'image', 'media'],
            'requestDomains' => $domains,
        ],
    ];

    // Redirect rule — main_frame navigation (priority 3)
    $rules[] = [
        'id' => $idCounters['redirect']++,
        'priority' => 3,
        'action' => [
            'type' => 'redirect',
            'redirect' => [
                'regexSubstitution' => "chrome-extension://__EXT_ID__/pages/popup-tracker.html?url=\\0",
            ],
        ],
        'condition' => [
            'regexFilter' => '^http.+',
            'requestDomains' => $domains,
            'resourceTypes' => ['main_frame'],
        ],
    ];
}

error_log(sprintf(
    "INFO [v2]: Long — %d total, %d used (last 50k), %d chunks × 2 rules (block+redirect)",
    count($longDomains),
    count($last50000),
    count($longChunks)
));

// ============================================
// STEP 3: dnr.json from GitHub — kept exactly as-is
// These are surgical filter rules (block, allow, modifyHeaders, etc.)
// with urlFilter patterns, specific conditions, etc. No conversion needed.
// Only:
//   - Re-assign sequential IDs (avoid collisions)
//   - Inject whitelist placeholders into block rules
// ============================================
// Timeout raised 10s -> 60s (2026-07-23): this generator now runs POST-FLUSH on a
// detached worker (ninja-adb21.php section 5), so a slow GitHub fetch no longer pins
// a user-facing request; the bound only protects the worker from a hung stream.
$dnrJsonStr = @file_get_contents('https://raw.githubusercontent.com/meganerasam/blocklist-v3/refs/heads/master/all-in-one/merged-dnr/dnr.json', false, stream_context_create(['http' => ['timeout' => 60]]));
$dnrStats = ['block' => 0, 'allow' => 0, 'other' => 0, 'duplicatedAsRedirect' => 0, 'vetoed' => 0];

// LAST-GOOD MIRROR (2026-07-23): save on success, fall back on failure.
$dnrMirror = __DIR__ . '/sources/dnr.json';
if ($dnrJsonStr !== false && strlen($dnrJsonStr) > 1000) {
    @file_put_contents($dnrMirror, $dnrJsonStr);
} else {
    error_log("WARN: dnr.json GitHub fetch failed - falling back to last-good mirror");
    $dnrJsonStr = @file_get_contents($dnrMirror);
}

$dnrRules = ($dnrJsonStr !== false) ? json_decode($dnrJsonStr, true) : null;
if (!is_array($dnrRules) || empty($dnrRules)) {
    // HARD ABORT (2026-07-23): the old behavior logged the failure but STILL wrote a
    // cache containing only the short/long domain rules — a silent fleet-wide downgrade
    // that drops every surgical filter AND bumps the version so every client installs
    // it. Keeping the previous cache/version untouched is strictly safer (same doctrine
    // as the cosmetic flip-flop guard).
    error_log("ERROR: dnr.json unavailable (fetch failed and no usable mirror) - skipping generation");
    return;
}

// FIRST-PARTY-INFRASTRUCTURE VETO (2026-07-23): the upstream daily merge shipped
// ||abs.twimg.com/responsive-web/client-web/main. from 07-12 to 07-18 — a block on
// x.com's own app bundle that broke the site outright for every client that synced it.
// Never trust the merge on these hosts: any BLOCK rule whose filter touches a site's
// app-shell CDN is dropped (and counted in the stats line) no matter what upstream
// says. Allow rules are never vetoed. Extend the list if a new incident of this class
// appears.
$firstPartyInfraVeto = ['abs.twimg.com', 'abs-0.twimg.com', 'twimg.com/responsive-web'];

foreach ($dnrRules as $rule) {
    $type = $rule['action']['type'] ?? 'block';

    if ($type === 'block') {
        $vetoHaystack = (string)($rule['condition']['urlFilter'] ?? '')
            . ' ' . (string)($rule['condition']['regexFilter'] ?? '');
        foreach ($firstPartyInfraVeto as $vetoNeedle) {
            if (stripos($vetoHaystack, $vetoNeedle) !== false) {
                $dnrStats['vetoed']++;
                continue 2;
            }
        }
    }
    if (!isset($idCounters[$type])) {
        $idCounters[$type] = 91000; // Fallback for unknown action types
    }
    $rule['id'] = $idCounters[$type]++;

    // Inject whitelist placeholders for block rules
    if ($type === 'block') {
        // Set block priority to 1
        $rule['priority'] = 1;

        if (!isset($rule['condition'])) {
            $rule['condition'] = [];
        }

        // Detect domain-level main_frame-only block rules → duplicate as redirect
        // Matches rules with requestDomains and/or initiatorDomains (any domain-based condition)
        $hasRequestDomains = isset($rule['condition']['requestDomains']) && is_array($rule['condition']['requestDomains']);
        $hasInitiatorDomains = isset($rule['condition']['initiatorDomains']) && is_array($rule['condition']['initiatorDomains']);
        $hasDomainCondition = $hasRequestDomains || $hasInitiatorDomains;
        $resourceTypes = $rule['condition']['resourceTypes'] ?? [];
        $isMainFrameOnly = is_array($resourceTypes) && $resourceTypes === ['main_frame'];

        if ($hasDomainCondition && $isMainFrameOnly) {
            // Create a redirect duplicate — carry over all domain conditions
            $redirectCondition = [
                'regexFilter' => '^http.+',
                'resourceTypes' => ['main_frame'],
            ];
            if ($hasRequestDomains) {
                $redirectCondition['requestDomains'] = $rule['condition']['requestDomains'];
            }
            if ($hasInitiatorDomains) {
                $redirectCondition['initiatorDomains'] = $rule['condition']['initiatorDomains'];
            }

            $redirectRule = [
                'id' => $idCounters['redirect']++,
                'priority' => 3,
                'action' => [
                    'type' => 'redirect',
                    'redirect' => [
                        'regexSubstitution' => "chrome-extension://__EXT_ID__/pages/popup-tracker.html?url=\\0",
                    ],
                ],
                'condition' => $redirectCondition,
            ];
            $rules[] = $redirectRule;
            $dnrStats['duplicatedAsRedirect']++;
        }

        $dnrStats['block']++;
    } elseif ($type === 'allow') {
        $dnrStats['allow']++;
    } else {
        $dnrStats['other']++;
    }

    $rules[] = $rule;
}

error_log(sprintf(
    "INFO [v2]: DNR — block: %d, allow: %d, other: %d, duplicated→redirect: %d, vetoed(first-party infra): %d",
    $dnrStats['block'], $dnrStats['allow'], $dnrStats['other'], $dnrStats['duplicatedAsRedirect'], $dnrStats['vetoed']
));

error_log("INFO [v2]: Total compiled rules: " . count($rules));

// ============================================
// STEP 4: Write compiled rules cache + version file for lazy-fetch
// ============================================
$tmpFile = __DIR__ . '/compiled_rules_cache_' . uniqid() . '.tmp';
file_put_contents($tmpFile, json_encode($rules, JSON_UNESCAPED_SLASHES));
rename($tmpFile, __DIR__ . '/compiled_rules_cache.json');

// Version hash (used by extension to detect changes)
$versionHash = md5_file(__DIR__ . '/compiled_rules_cache.json');
file_put_contents(__DIR__ . '/compiled_rules_version.txt', $versionHash);
