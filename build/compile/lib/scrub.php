<?php
/**
 * lib/scrub.php — the whitelist scrub engine (verbatim from v3's
 * all-in-one/scrub_whitelist.php; only the URL fetcher was dropped — the
 * input is now the locally-assembled exclusion set, never a fetched file).
 *
 * Guarantees that no domain of the given set can be matched by a block rule:
 *   1. requestDomains entries equal to a set member (or living under one,
 *      e.g. cdn.W) are removed from the rule; a rule left with no domains
 *      is dropped.
 *   2. urlFilter rules anchored on a member or a subdomain of one
 *      (||W^..., ||x.W/...) are dropped entirely.
 *   3. If a rule blocks a PARENT of a member (blocklist has example.com,
 *      W = app.example.com), the parent stays blocked but W is carved out
 *      via excludedRequestDomains, so W keeps working.
 *
 * Generic path-only urlFilter rules (e.g. "/ads/banner*") are left alone:
 * they are not tied to a specific domain.
 */

/**
 * Strict parent suffixes of a domain, keeping at least 2 labels.
 * "a.b.example.com" -> ["b.example.com", "example.com"]
 */
function domainAncestors(string $domain): array {
    $labels = explode('.', $domain);
    $out = [];
    for ($i = 1; $i <= count($labels) - 2; $i++) {
        $out[] = implode('.', array_slice($labels, $i));
    }
    return $out;
}

/**
 * True if $domain is a whitelisted domain or lives under one.
 */
function isWhitelistCovered(string $domain, array $whitelist): bool {
    if (isset($whitelist[$domain])) return true;
    foreach (domainAncestors($domain) as $parent) {
        if (isset($whitelist[$parent])) return true;
    }
    return false;
}

/**
 * Scrub an array of DNR rules so no whitelisted domain can be blocked.
 * $stats accumulates: domainsRemoved, rulesDropped, exclusionsAdded.
 */
function scrubBlockRules(array $rules, array $whitelist, array &$stats): array {
    $out = [];

    foreach ($rules as $rule) {
        $isBlock = isset($rule['action']['type']) && $rule['action']['type'] === 'block';
        if (!$isBlock || !isset($rule['condition']) || empty($whitelist)) {
            $out[] = $rule;
            continue;
        }

        $cond = $rule['condition'];

        if (isset($cond['requestDomains']) && is_array($cond['requestDomains'])) {
            // 1. Remove whitelisted domains (and their subdomains) from the batch.
            $kept = [];
            foreach ($cond['requestDomains'] as $d) {
                if (isWhitelistCovered(strtolower($d), $whitelist)) {
                    $stats['domainsRemoved']++;
                    continue;
                }
                $kept[] = $d;
            }
            if (empty($kept)) {
                $stats['rulesDropped']++;
                continue;
            }
            $cond['requestDomains'] = $kept;

            // 2. If a kept domain is a PARENT of a whitelisted domain, carve
            //    the whitelisted domain out of the block via exclusion.
            $keptSet = array_flip(array_map('strtolower', $kept));
            $carve = [];
            foreach ($whitelist as $w => $_) {
                foreach (domainAncestors($w) as $parent) {
                    if (isset($keptSet[$parent])) {
                        $carve[$w] = true;
                        break;
                    }
                }
            }
            if (!empty($carve)) {
                $excl = isset($cond['excludedRequestDomains']) ? $cond['excludedRequestDomains'] : [];
                foreach (array_keys($carve) as $w) {
                    if (!in_array($w, $excl, true)) {
                        $excl[] = $w;
                        $stats['exclusionsAdded']++;
                    }
                }
                sort($excl);
                $cond['excludedRequestDomains'] = $excl;
            }
        } elseif (isset($cond['urlFilter']) && strpos($cond['urlFilter'], '||') === 0) {
            // Domain-anchored urlFilter: ||domain^path, ||domain/path, ...
            if (preg_match('/^\|\|([a-z0-9.-]+)/i', $cond['urlFilter'], $m)) {
                $anchor = strtolower(trim($m[1], '.'));

                // Wildcard-TLD anchor (||pornhub.*): '*' matches anything, so the
                // rule covers every whitelisted domain sharing the prefix — drop it
                // when one exists (2026-09-08; the plain-anchor case always did this).
                if (substr($cond['urlFilter'], 2 + strlen($m[1]), 1) === '*'
                    && str_ends_with($m[1], '.')) {
                    $prefix = strtolower($m[1]);
                    foreach ($whitelist as $w => $_) {
                        if (str_starts_with($w, $prefix)) {
                            $stats['rulesDropped']++;
                            continue 2;   // next $rule of the outer scrub loop
                        }
                    }
                }

                if (isWhitelistCovered($anchor, $whitelist)) {
                    $stats['rulesDropped']++;
                    continue;
                }

                // Anchor is a PARENT of a whitelisted domain: keep the rule
                // but exclude the whitelisted domain from matching it.
                $carve = [];
                foreach ($whitelist as $w => $_) {
                    if (in_array($anchor, domainAncestors($w), true)) {
                        $carve[$w] = true;
                    }
                }
                if (!empty($carve)) {
                    $excl = isset($cond['excludedRequestDomains']) ? $cond['excludedRequestDomains'] : [];
                    foreach (array_keys($carve) as $w) {
                        if (!in_array($w, $excl, true)) {
                            $excl[] = $w;
                            $stats['exclusionsAdded']++;
                        }
                    }
                    sort($excl);
                    $cond['excludedRequestDomains'] = $excl;
                }
            }
        }

        $rule['condition'] = $cond;
        $out[] = $rule;
    }

    return $out;
}
