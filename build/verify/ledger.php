<?php
// build/verify/ledger.php — the domain ledger: tiered DNS verification.
//
// Replaces blocklist-v2's daily full retest (183k domains, ~6 h, flat files) with
// per-domain scheduling. One record per domain in state/domain-ledger.json:
//   s  = sources (anudeep|peterlowe|adguarddns|kadhosts|sheet-a)
//   fs = first_seen        ll = last_listed (in a snapshot / Sheet A)
//   lo = last_ok (DNS)     f  = consecutive fails
//   nc = next_check        st = n(ew) | a(ctive) | d(ead)
//
// Scope (user decisions, 2026-09-08 — curation re-conception):
//   candidates = the SANITIZED sources (sanitized/hosts/*.txt + sanitized/gsheet/
//   popup.json), i.e. exactly what can ship. build/curate/curate.php already
//   subtracted the curation set (H ∪ I download-sites ∪ user whitelist), so the old
//   skip rules are gone — there is nothing left to skip. Sheets D/F are NEVER verified.
//   Sheet A is verified but never modified — dead entries only surface in the report.
//   Sheet C is product-only (dist/whitelist/default.json): its domains CAN ship as
//   blocks, so they get tested like any other candidate.
// Scheduling: alive -> recheck +7 d. fail -> backoff 1d, 7d, 30d, then quarterly.
// Retention: dead + delisted 180 d -> purged; delisted (any status) 365 d -> purged.
//   A purged domain re-listed later returns as "new" and costs one test.
// Seed (first run, no ledger file): trust legacy v2 knowledge for snapshot-listed
//   domains via SEED_WORKING / SEED_INACTIVE paths; everything else starts "new".
//
// Env: MAX_TESTS (default 60000) · WORKERS (default 16)
//      SEED_WORKING / SEED_INACTIVE (optional, seed run only)
//      GITHUB_STEP_SUMMARY (markdown report appended when set; always echoed)

declare(strict_types=1);
ini_set('memory_limit', '2048M'); // ~300k ledger records + seed files

$ROOT   = dirname(__DIR__, 2);
$LEDGER = $ROOT . '/state/domain-ledger.json';
$TODAY  = gmdate('Y-m-d');
// note: "0" is falsy in PHP — a plain ?: would silently turn MAX_TESTS=0 into the default
$MAX_TESTS = max(0, (int) ((($v = getenv('MAX_TESTS')) === false || $v === '') ? 60000 : $v));
$WORKERS   = max(1, (int) ((($v = getenv('WORKERS'))   === false || $v === '') ? 16    : $v));

const BACKOFF_DAYS         = [1 => 1, 2 => 7, 3 => 30]; // fails => days; >3 => 90
const ACTIVE_RECHECK_DAYS  = 7;
const PURGE_DEAD_DELISTED  = 180;
const PURGE_ANY_DELISTED   = 365;

function day_add(string $ymd, int $days): string
{
    return gmdate('Y-m-d', strtotime($ymd . ' UTC') + $days * 86400);
}

// ---------------------------------------------------------------- inputs ----
function clean_domain(string $d): ?string
{
    $d = strtolower(trim($d));
    $d = rtrim($d, '.');
    if ($d === '' || !str_contains($d, '.') || preg_match('/[\s\/:]/', $d)) return null;
    if (filter_var($d, FILTER_VALIDATE_IP) !== false) return null;
    return $d;
}

function load_hosts_file(string $path): array
{
    $out = [];
    if (!is_file($path)) return $out;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim(explode('#', $line, 2)[0]);
        if ($line === '') continue;
        if (preg_match('/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$/', $line, $m)) $line = $m[1];
        $d = clean_domain($line);
        if ($d !== null && $d !== 'localhost' && $d !== 'localhost.localdomain' && $d !== 'broadcasthost') $out[$d] = true;
    }
    return $out;
}

function load_json_domains(string $path): array
{
    if (!is_file($path)) return [];
    $arr = json_decode((string) file_get_contents($path), true);
    if (!is_array($arr)) return [];
    $out = [];
    foreach ($arr as $d) if (is_string($d) && ($c = clean_domain($d)) !== null) $out[$c] = true;
    return $out;
}

/** True when $d equals a set member or is a subdomain of one. */
function covered_subdomain(string $d, array $set): bool
{
    $parts = explode('.', $d);
    for ($i = 0, $n = count($parts) - 1; $i < $n; $i++) {
        if (isset($set[implode('.', array_slice($parts, $i))])) return true;
    }
    return false;
}

// candidates: domain => [source, ...] — read from the SANITIZED layer only.
// The curation set was already subtracted by build/curate/curate.php; testing anything
// it removed would be waste, and nothing here needs a skip rule anymore.
$SOURCES = [
    'anudeep'    => "$ROOT/sanitized/hosts/anudeep.txt",
    'peterlowe'  => "$ROOT/sanitized/hosts/peterlowe.txt",
    'adguarddns' => "$ROOT/sanitized/hosts/adguarddns.txt",
    'kadhosts'   => "$ROOT/sanitized/hosts/kadhosts.txt",
];
$cand = [];
foreach ($SOURCES as $tag => $path) {
    foreach (load_hosts_file($path) as $d => $_) $cand[$d][] = $tag;
}
foreach (load_json_domains("$ROOT/sanitized/gsheet/popup.json") as $d => $_) $cand[$d][] = 'sheet-a';
if (!$cand) { fwrite(STDERR, "FATAL: no candidates — run build/curate/curate.php first (sanitized/ missing or empty)\n"); exit(1); }

// ---------------------------------------------------------------- ledger ----
$seeded = false;
$ledger = [];
if (is_file($LEDGER)) {
    $ledger = json_decode((string) file_get_contents($LEDGER), true);
    if (!is_array($ledger) || !$ledger) {
        // fail-closed (adversarial review): a corrupt/truncated ledger silently reseeding
        // would wipe the dead-set memory the whole dead-never-ships guarantee depends on
        fwrite(STDERR, "FATAL: $LEDGER exists but is invalid or empty — refusing the silent reseed (delete the file deliberately to reseed)\n");
        exit(1);
    }
} else {
    $seeded = true;
    $working = $inactive = [];
    $slurp = function (string $path, array &$set): void { // streamed — seed files run to 863k lines
        $fh = fopen($path, 'r');
        while (($l = fgets($fh)) !== false) { if (($d = clean_domain($l)) !== null) $set[$d] = true; }
        fclose($fh);
    };
    if (($p = getenv('SEED_WORKING'))  && is_file($p)) $slurp($p, $working);
    if (($p = getenv('SEED_INACTIVE')) && is_file($p)) $slurp($p, $inactive);
    foreach ($cand as $d => $srcs) {
        if (isset($working[$d])) {        // trusted alive per legacy v2 (ran this very morning)
            $ledger[$d] = ['s' => $srcs, 'fs' => $TODAY, 'll' => $TODAY, 'lo' => $TODAY, 'f' => 0,
                           'nc' => day_add($TODAY, random_int(1, ACTIVE_RECHECK_DAYS)), 'st' => 'a'];
        } elseif (isset($inactive[$d])) { // trusted dead — backoff, don't burn a test on day 1
            $ledger[$d] = ['s' => $srcs, 'fs' => $TODAY, 'll' => $TODAY, 'lo' => null, 'f' => 3,
                           'nc' => day_add($TODAY, 30), 'st' => 'd'];
        } else {
            $ledger[$d] = ['s' => $srcs, 'fs' => $TODAY, 'll' => $TODAY, 'lo' => null, 'f' => 0,
                           'nc' => $TODAY, 'st' => 'n'];
        }
    }
}

// refresh listing state + admit new domains
$newDomains = 0;
foreach ($cand as $d => $srcs) {
    if (!isset($ledger[$d])) {
        $ledger[$d] = ['s' => $srcs, 'fs' => $TODAY, 'll' => $TODAY, 'lo' => null, 'f' => 0, 'nc' => $TODAY, 'st' => 'n'];
        $newDomains++;
    } else {
        $ledger[$d]['ll'] = $TODAY;
        // REPLACE the tag set with today's truth (was append-only): a lane that delisted
        // the domain must stop retaining it in compile's per-lane retention — role bleed
        // (e.g. a stale kadhosts tag keeps redirecting a domain only hosts-lanes still
        // list). Fully-delisted domains are not candidates, so their tags persist until
        // the purge — exactly the retention memory the design wants.
        $ledger[$d]['s'] = $srcs;
    }
}

// retention: purge what nothing references anymore
$purged = 0;
foreach ($ledger as $d => $r) {
    if ($r['ll'] === $TODAY) continue;
    $delistedDays = (int) ((strtotime($TODAY) - strtotime($r['ll'])) / 86400);
    if (($r['st'] === 'd' && $delistedDays > PURGE_DEAD_DELISTED) || $delistedDays > PURGE_ANY_DELISTED) {
        unset($ledger[$d]);
        $purged++;
    }
}

// ------------------------------------------------------------- test plan ----
// No skip rules: candidates come pre-curated from sanitized/, so every currently-listed,
// due domain is worth a test. (Curated-out domains stop being listed → ll ages →
// retention purges them.)
$due = [];
foreach ($ledger as $d => $r) {
    if ($r['ll'] !== $TODAY) continue;              // delisted: stop spending tests on it
    if ($r['nc'] > $TODAY) continue;
    $due[] = $d;
}
usort($due, function ($a, $b) use ($ledger) {       // Sheet A first, then longest-overdue
    $pa = in_array('sheet-a', $ledger[$a]['s'], true) ? 0 : 1;
    $pb = in_array('sheet-a', $ledger[$b]['s'], true) ? 0 : 1;
    return [$pa, $ledger[$a]['nc'], $a] <=> [$pb, $ledger[$b]['nc'], $b];
});
$deferred = max(0, count($due) - $MAX_TESTS);
$plan = array_slice($due, 0, $MAX_TESTS);

// -------------------------------------------------------------- DNS test ----
function dns_alive(string $d): bool
{
    return @checkdnsrr($d . '.', 'A') || @checkdnsrr($d . '.', 'AAAA') || @checkdnsrr($d . '.', 'CNAME');
}

$results = []; // domain => bool
if ($plan) {
    if (function_exists('pcntl_fork') && $WORKERS > 1) {
        $chunks = array_chunk($plan, (int) ceil(count($plan) / $WORKERS));
        $files = [];
        foreach ($chunks as $i => $chunk) {
            $tmp = sys_get_temp_dir() . "/ledger-w{$i}-" . getmypid();
            $files[] = $tmp;
            $pid = pcntl_fork();
            if ($pid === 0) {
                $fh = fopen($tmp, 'w');
                foreach ($chunk as $d) fwrite($fh, $d . "\t" . (dns_alive($d) ? 1 : 0) . "\n");
                fclose($fh);
                exit(0);
            }
        }
        while (pcntl_waitpid(-1, $status) > 0);
        foreach ($files as $tmp) {
            foreach (file($tmp, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                [$d, $ok] = explode("\t", $line);
                $results[$d] = $ok === '1';
            }
            @unlink($tmp);
        }
    } else {
        foreach ($plan as $d) $results[$d] = dns_alive($d);
    }
}

// ------------------------------------------------------- apply + schedule ----
$alive = $died = $resurrected = 0;
$sheetADead = [];
foreach ($results as $d => $ok) {
    $r = &$ledger[$d];
    if ($ok) {
        if ($r['st'] === 'd') $resurrected++;
        $r['st'] = 'a'; $r['lo'] = $TODAY; $r['f'] = 0;
        $r['nc'] = day_add($TODAY, ACTIVE_RECHECK_DAYS);
        $alive++;
    } else {
        $r['f']++;
        if ($r['st'] === 'a') $died++;
        $r['st'] = 'd';
        $r['nc'] = day_add($TODAY, BACKOFF_DAYS[$r['f']] ?? 90);
        if (in_array('sheet-a', $r['s'], true)) $sheetADead[] = $d;
    }
    unset($r);
}

// ---------------------------------------------------------------- output ----
ksort($ledger, SORT_STRING);
if (!is_dir("$ROOT/state")) mkdir("$ROOT/state", 0755, true);
$fh = fopen($LEDGER . '.tmp', 'w');
fwrite($fh, "{\n");
$first = true;
foreach ($ledger as $d => $r) {
    fwrite($fh, ($first ? '' : ",\n") . json_encode($d) . ':' . json_encode($r, JSON_UNESCAPED_SLASHES));
    $first = false;
}
fwrite($fh, "\n}\n");
fclose($fh);
rename($LEDGER . '.tmp', $LEDGER);

$byStatus = ['a' => 0, 'd' => 0, 'n' => 0];
$dueTomorrow = 0;
$tomorrow = day_add($TODAY, 1);
foreach ($ledger as $r) { $byStatus[$r['st']]++; if ($r['nc'] <= $tomorrow && $r['ll'] === $TODAY) $dueTomorrow++; }

$rep = [];
$rep[] = '# Domain ledger — ' . $TODAY . ($seeded ? ' · **SEED RUN**' : '');
$rep[] = '';
$rep[] = '| metric | value |';
$rep[] = '|---|---|';
$rep[] = '| ledger size | ' . count($ledger) . ' (active ' . $byStatus['a'] . ' · dead ' . $byStatus['d'] . ' · never-tested ' . $byStatus['n'] . ') |';
$rep[] = '| new domains admitted | ' . $newDomains . ' |';
$rep[] = '| purged (retention) | ' . $purged . ' |';
$rep[] = '| tested | ' . count($results) . ' (alive ' . $alive . ' · dead ' . (count($results) - $alive) . ' · newly-died ' . $died . ' · resurrected ' . $resurrected . ') |';
$rep[] = '| deferred beyond MAX_TESTS | ' . $deferred . ' |';
$rep[] = '| due by tomorrow | ' . $dueTomorrow . ' |';
if ($sheetADead) {
    $rep[] = '';
    $rep[] = '**Sheet A domains that failed DNS** (' . count($sheetADead) . ' — clean the sheet when convenient): ' . implode(', ', array_slice($sheetADead, 0, 50)) . (count($sheetADead) > 50 ? ' … +' . (count($sheetADead) - 50) : '');
}
$md = implode("\n", $rep) . "\n";
echo $md;
if (($sum = getenv('GITHUB_STEP_SUMMARY')) !== false && $sum !== '') {
    file_put_contents($sum, $md, FILE_APPEND);
}
exit(0);
