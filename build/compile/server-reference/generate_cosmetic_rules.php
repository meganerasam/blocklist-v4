<?php
// backend/prod/generate_cosmetic_rules.php
// Handles all 3 cosmetic CSS sources:
//   1. generic.css       → cosmetic_css_cache.css + cosmetic_css_version.txt
//   2. specific.json  }
//      unhide.json    }  → cosmetic_specific_cache.json + cosmetic_specific_version.txt
//
// Called by wonder-3_7-dev.php when cache is stale (24h TTL).

ini_set('memory_limit', '512M');
set_time_limit(300);
ignore_user_abort(true); // safe as a bg_run/self-call target: an early client close must not kill the run

// Bounded fetches (2026-07-15 hardening): a GitHub slowdown must not hang the caller.
// Timeout raised 10s -> 30s (2026-07-23): runs POST-FLUSH on a detached worker now
// (ninja-adb21.php section 6), no user-facing request is waiting.
$__cosmeticFetchCtx = stream_context_create(['http' => ['timeout' => 30]]);

// LAST-GOOD SOURCE MIRRORS (2026-07-23): every successful fetch is saved under
// sources/; a failed fetch falls back to the saved copy so one flaky GitHub day can
// no longer freeze the cosmetic pipeline (07-16..07-23 freeze).
if (!is_dir(__DIR__ . '/sources')) {
    @mkdir(__DIR__ . '/sources', 0755);
}
if (!function_exists('ninja_fetch_with_mirror')) { // include-safe, like the funnel helpers
    function ninja_fetch_with_mirror($url, $ctx, $mirrorBasename, $minLen) {
        $str = @file_get_contents($url, false, $ctx);
        $mirror = __DIR__ . '/sources/' . $mirrorBasename;
        if ($str !== false && strlen($str) >= $minLen) {
            @file_put_contents($mirror, $str);
            return $str;
        }
        $fallback = @file_get_contents($mirror);
        if ($fallback !== false) {
            error_log("generate_cosmetic_rules: fetch failed for {$mirrorBasename} - using last-good mirror");
        }
        return $fallback;
    }
}

// TMP-ORPHAN SWEEP (2026-07-15 incident): a run that dies between file_put_contents and
// rename leaves cosmetic_*_cache_<uniqid>.tmp files behind forever — the incident
// stampede left GBs of them. Sweep anything older than 1h.
foreach ((glob(__DIR__ . '/cosmetic_css_cache_*.tmp') ?: []) as $__orphan) {
    if (@filemtime($__orphan) < time() - 3600) @unlink($__orphan);
}
foreach ((glob(__DIR__ . '/cosmetic_specific_cache_*.tmp') ?: []) as $__orphan) {
    if (@filemtime($__orphan) < time() - 3600) @unlink($__orphan);
}

// ============================================================
// 1. Generic CSS (global hide rules — applied on ALL pages)
// ============================================================
$cosmeticCssStr = ninja_fetch_with_mirror('https://raw.githubusercontent.com/meganerasam/blocklist-v3/refs/heads/master/all-in-one/css/generic.css', $__cosmeticFetchCtx, 'generic.css', 100);
if ($cosmeticCssStr !== false && strlen($cosmeticCssStr) > 100) {
    $cssHash = md5($cosmeticCssStr);
    $tmpCss = __DIR__ . '/cosmetic_css_cache_' . uniqid() . '.tmp';
    file_put_contents($tmpCss, $cosmeticCssStr);
    rename($tmpCss, __DIR__ . '/cosmetic_css_cache.css');
    file_put_contents(__DIR__ . '/cosmetic_css_version.txt', $cssHash);
} else {
    error_log("ERROR: Unable to fetch generic.css from GitHub");
}

// ============================================================
// 2. Specific + Unhide merge (per-domain scoped rules)
// ============================================================
$specificStr = ninja_fetch_with_mirror('https://raw.githubusercontent.com/meganerasam/blocklist-v3/refs/heads/master/all-in-one/css/specific.json', $__cosmeticFetchCtx, 'specific.json', 100);
$unhideStr   = ninja_fetch_with_mirror('https://raw.githubusercontent.com/meganerasam/blocklist-v3/refs/heads/master/all-in-one/allow/unhide.json', $__cosmeticFetchCtx, 'unhide.json', 10);

$specificData = ($specificStr !== false) ? json_decode($specificStr, true) : null;
$unhideData   = ($unhideStr !== false)   ? json_decode($unhideStr, true)   : null;

// VERSION FLIP-FLOP GUARD (2026-07-15): if EITHER source failed to fetch/decode, keep the
// previous cache and version untouched (mirror the generic.css behavior above). Before,
// a partial failure fell through to the merge with an empty array, producing a DIFFERENT
// merged JSON and md5 — then the next successful run flipped it back. Every flip made the
// ENTIRE fleet re-download cosmetic_specific_cache.json for nothing.
if (!is_array($specificData) || !is_array($unhideData)) {
    error_log("ERROR: cosmetic specific/unhide fetch or decode failed (specific="
        . (is_array($specificData) ? 'ok' : 'FAIL') . ", unhide=" . (is_array($unhideData) ? 'ok' : 'FAIL')
        . ") — keeping previous cosmetic_specific cache/version");
    return;
}

// Build merged map: { "domain": { "hide": [...], "unhide": [...] } }
$merged = [];

// Process specific.json (hide rules)
foreach ($specificData as $domain => $selectors) {
    if (!is_string($domain) || !is_array($selectors)) continue;

    // Skip wildcard domains like "24high.*" — can't handle in pure CSS domain matching
    if (strpos($domain, '*') !== false) continue;

    $domain = strtolower(trim($domain));
    if (!$domain) continue;

    if (!isset($merged[$domain])) {
        $merged[$domain] = ['hide' => [], 'unhide' => []];
    }
    $merged[$domain]['hide'] = array_values(array_unique(array_merge($merged[$domain]['hide'], $selectors)));
}

// Process unhide.json (unhide/whitelist rules)
foreach ($unhideData as $domain => $selectors) {
    if (!is_string($domain) || !is_array($selectors)) continue;

    // Skip wildcard domains
    if (strpos($domain, '*') !== false) continue;

    $domain = strtolower(trim($domain));
    if (!$domain) continue;

    if (!isset($merged[$domain])) {
        $merged[$domain] = ['hide' => [], 'unhide' => []];
    }

    foreach ($selectors as $sel) {
        // If this selector was also in the hide list for this domain, they cancel out
        $hideIdx = array_search($sel, $merged[$domain]['hide']);
        if ($hideIdx !== false) {
            // Remove from hide — no CSS needed for this selector on this domain
            array_splice($merged[$domain]['hide'], $hideIdx, 1);
        } else {
            // Not in the hide list → it's overriding a generic.css rule
            $merged[$domain]['unhide'][] = $sel;
        }
    }

    $merged[$domain]['unhide'] = array_values(array_unique($merged[$domain]['unhide']));
}

// Clean up: remove domains that ended up with both arrays empty
foreach ($merged as $domain => $entry) {
    if (empty($entry['hide']) && empty($entry['unhide'])) {
        unset($merged[$domain]);
    }
}

// Write the merged JSON cache
$mergedJson = json_encode($merged, JSON_UNESCAPED_SLASHES);
if ($mergedJson !== false && strlen($mergedJson) > 10) {
    $specificHash = md5($mergedJson);
    $tmpSpecific = __DIR__ . '/cosmetic_specific_cache_' . uniqid() . '.tmp';
    file_put_contents($tmpSpecific, $mergedJson);
    rename($tmpSpecific, __DIR__ . '/cosmetic_specific_cache.json');
    file_put_contents(__DIR__ . '/cosmetic_specific_version.txt', $specificHash);
} else {
    error_log("ERROR: Failed to encode merged cosmetic specific JSON");
}
