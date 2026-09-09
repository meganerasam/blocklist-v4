<?php
/**
 * lib/scrub.php — the whitelist scrub engine (from v3's
 * all-in-one/scrub_whitelist.php; only the URL fetcher was dropped — the
 * input is now the CURATION SET assembled by build/curate/curate.php,
 * never a fetched file; since 2026-09-08 the scrub runs at the curate stage).
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
                    // 2026-09-08 (adversarial review): a || anchor matches at EVERY
                    // subdomain boundary, so a member sitting DEEPER in the family —
                    // mail.google.com under ||google.* while apex google.com is G-vetoed —
                    // dodges the prefix test above AND the parent-carve below (the bare
                    // anchor label never appears in domainAncestors). Carve those members.
                    $carve = [];
                    foreach ($whitelist as $w => $_) {
                        foreach (domainAncestors($w) as $anc) {
                            if (str_starts_with($anc, $prefix)) { $carve[$w] = true; break; }
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

        // 3. Generic-pattern main_frame blocks scoped to a whitelisted INITIATOR:
        //    ABP's $popup maps to DNR main_frame, which catches ORDINARY navigation —
        //    including the whitelisted site's own internal links (the blocked request's
        //    destination can be the whitelisted domain itself, e.g. "|http*://*?" from
        //    pornhub matching /view_video.php?...). Strip those initiators; drop the
        //    rule when none remain. Destination-scoped rules (requestDomains or a
        //    ||-anchored filter) are kept — they block popups TO a specific target,
        //    never the site's own navigation. (2026-09-08)
        if (isset($cond['initiatorDomains']) && is_array($cond['initiatorDomains'])
            && !isset($cond['requestDomains'])
            && in_array('main_frame', $cond['resourceTypes'] ?? [], true)
            && !(isset($cond['urlFilter']) && strpos($cond['urlFilter'], '||') === 0)) {
            $keptInit = [];
            foreach ($cond['initiatorDomains'] as $d) {
                if (isWhitelistCovered(strtolower($d), $whitelist)) {
                    $stats['initiatorsStripped'] = ($stats['initiatorsStripped'] ?? 0) + 1;
                    continue;
                }
                $keptInit[] = $d;
            }
            if (empty($keptInit)) {
                $stats['rulesDropped']++;
                continue;
            }
            $cond['initiatorDomains'] = $keptInit;
        }

        $rule['condition'] = $cond;
        $out[] = $rule;
    }

    return $out;
}

/**
 * Curate ALLOW rules — the SELF-PROTECTION policy (user decision 2026-09-08, revised the
 * same evening after adversarial-review evidence; cosmetic rules never pass through here).
 *
 * An allow rule whose destination IS a curated domain is an unbreakage exception ON the
 * very site curation protects: generic path-pattern blocks (not domain-scoped, invisible
 * to domain curation) still match on its pages, and dropping the exception would INCREASE
 * blocking there (live regression pair: the nytimes.com EventTracker.js exception,
 * anchor @@||nytimes.com^, vs a generic EventTracker path block). So:
 *
 *   · ||-anchored / wildcard-family allows: NEVER dropped, NEVER carved — an anchor on
 *     (or over) a curated domain is self-protection.
 *   · initiatorDomains: never touched — initiator-scoped exceptions protect the curated
 *     site's pages.
 *   · requestDomains batches: a batch made ENTIRELY of curated destinations is kept
 *     untouched (pure self-protection). A MIXED batch strips its curated members — the
 *     rule exists for the other destinations, and a leftover allow entry could
 *     neutralize a deliberate Sheet-D/F append on the curated domain.
 *
 * The cardinal safety rule still holds: scope is never widened — stripping only happens
 * while other entries remain.
 *
 * $stats accumulates: domainsRemoved, rulesDropped, exclusionsAdded (the latter two stay
 * 0 under this policy; kept for report-schema stability).
 */
function scrubAllowRules(array $rules, array $whitelist, array &$stats): array {
    $out = [];

    foreach ($rules as $rule) {
        $isAllow = ($rule['action']['type'] ?? '') === 'allow';
        if (!$isAllow || !isset($rule['condition']) || empty($whitelist)) {
            $out[] = $rule;
            continue;
        }
        $cond = $rule['condition'];

        if (isset($cond['requestDomains']) && is_array($cond['requestDomains'])) {
            $covered = [];
            $kept = [];
            foreach ($cond['requestDomains'] as $d) {
                if (isWhitelistCovered(strtolower($d), $whitelist)) $covered[] = $d;
                else $kept[] = $d;
            }
            if ($covered && $kept) {          // mixed batch: strip the curated members
                $stats['domainsRemoved'] += count($covered);
                $cond['requestDomains'] = $kept;
            }
            // all-covered => pure self-protection, kept untouched
        }

        $rule['condition'] = $cond;
        $out[] = $rule;
    }

    return $out;
}

/**
 * scrubGVetoAllows — the second half of Sheet G: "to be removed from rules generated by
 * public host" (summary sheet, ruled 2026-09-09).
 *
 * Sheet G is the anti-whitelist: a G host must never end up un-blocked, no matter who
 * asks — not the fleet vote (handled in curate.php step 2), and not an upstream EasyList
 * exception either. This pass is deliberately NOT the curation scrub and must not be
 * confused with it:
 *
 *   · curation set (H ∪ I ∪ userWL) — allows ON its members are SELF-PROTECTION and are
 *     kept; see scrubAllowRules above.
 *   · Sheet G — the inverse. An allow that un-blocks a G host defeats the sheet's entire
 *     purpose, so it is removed.
 *
 * Scope is kept as narrow as the ruling: only BLANKET allows, meaning no urlFilter AND no
 * resourceTypes — a rule that un-blocks every request on its axis. Path- and type-scoped
 * upstream exceptions are left alone on purpose: they are why reCAPTCHA and Google Docs
 * keep working (||google.com/recaptcha/api.js and friends), and dropping them would break
 * pages without protecting anything.
 *
 * Matching is EXACT host, never subdomains — the same asymmetry G has everywhere else
 * (google.com in G must not reach cloud.google.com).
 *
 * The cardinal safety rule of this file still holds: scope is NEVER widened. Emptying an
 * axis would turn "allow requests to X" into "allow everything", so a rule whose axis is
 * left empty is dropped whole instead. Dropping an allow can only ever increase blocking,
 * which is exactly what G asks for.
 *
 * $stats accumulates: domainsRemoved, rulesDropped.
 */
function scrubGVetoAllows(array $rules, array $G, array &$stats): array {
    if (!$G) return $rules;
    $veto = [];
    foreach ($G as $g) $veto[g_veto_key($g)] = true;

    $out = [];
    foreach ($rules as $rule) {
        if (($rule['action']['type'] ?? '') !== 'allow' || !isset($rule['condition'])) {
            $out[] = $rule;
            continue;
        }
        $cond = $rule['condition'];
        if (!empty($cond['urlFilter']) || !empty($cond['resourceTypes'])) {   // not blanket
            $out[] = $rule;
            continue;
        }

        $drop = false;
        foreach (['requestDomains', 'initiatorDomains'] as $axis) {
            if (!isset($cond[$axis]) || !is_array($cond[$axis])) continue;
            $kept = [];
            $removed = 0;
            foreach ($cond[$axis] as $d) {
                if (isset($veto[g_veto_key((string) $d)])) { $removed++; continue; }
                $kept[] = $d;
            }
            if ($removed === 0) continue;
            if (!$kept) { $drop = true; break; }        // never widen scope — drop instead
            $stats['domainsRemoved'] += $removed;
            $cond[$axis] = $kept;
        }
        if ($drop) { $stats['rulesDropped']++; continue; }

        $rule['condition'] = $cond;
        $out[] = $rule;
    }

    return $out;
}

/**
 * gVetoAllowLeaks — the guard for the pass above. Returns every place a blanket allow
 * still names an exact Sheet G host; curate.php fails the build on a non-empty result, so
 * a future generator change can never quietly re-open the hole.
 */
function gVetoAllowLeaks(array $rules, array $G): array {
    if (!$G) return [];
    $veto = [];
    foreach ($G as $g) $veto[g_veto_key($g)] = true;

    $leaks = [];
    foreach ($rules as $rule) {
        if (($rule['action']['type'] ?? '') !== 'allow' || !isset($rule['condition'])) continue;
        $cond = $rule['condition'];
        if (!empty($cond['urlFilter']) || !empty($cond['resourceTypes'])) continue;
        foreach (['requestDomains', 'initiatorDomains'] as $axis) {
            foreach ($cond[$axis] ?? [] as $d) {
                if (isset($veto[g_veto_key((string) $d)])) {
                    $leaks[] = ($rule['id'] ?? '?') . ":$axis:$d";
                }
            }
        }
    }
    return $leaks;
}

/** Normalisation shared by the two functions above, so they can never disagree. */
function g_veto_key(string $d): string {
    return rtrim(strtolower(trim($d)), '.');
}
