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
// Scope (user decisions, 2026-09-08):
//   candidates = 4 hosts snapshots + Sheet A. Sheets D/F are NEVER verified.
//   Sheet A is verified but never modified — dead entries only surface in the report.
// Skip rules:
//   Sheet H (never-block floor)  -> skip EVERY lane, domain + subdomains.
//   Exclusion set (C ∪ E ∪ fleet≥200) − G[exact-host] -> skip hosts lanes only
//   (those domains can never ship as block rules; testing them is waste).
//   Sheet A ∩ exclusion set -> tested anyway, flagged in the report.
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
$MAX_TESTS = max(0, (int) (getenv('MAX_TESTS') ?: 60000));
$WORKERS   = max(1, (int) (getenv('WORKERS') ?: 16));

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

// candidates: domain => [source, ...]
$SOURCES = [
    'anudeep'    => "$ROOT/sources/hosts/anudeep.txt",
    'peterlowe'  => "$ROOT/sources/hosts/peterlowe.txt",
    'adguarddns' => "$ROOT/sources/hosts/adguarddns.txt",
    'kadhosts'   => "$ROOT/sources/hosts/kadhosts.txt",
];
$cand = [];
foreach ($SOURCES as $tag => $path) {
    foreach (load_hosts_file($path) as $d => $_) $cand[$d][] = $tag;
}
foreach (load_json_domains("$ROOT/sources/gsheet/popup.json") as $d => $_) $cand[$d][] = 'sheet-a';
if (!$cand) { fwrite(STDERR, "FATAL: no candidates — are sources/ snapshots present?\n"); exit(1); }

// exclusion set = (C ∪ E ∪ fleet≥200) − G[exact]  ·  H = never-block floor [subdomain]
// Fleet component = all-extension.csv merged votes ≥ 200 (keep in sync with compile.php
// COMMUNITY_MIN_VOTES — the flat ≥20 export is only the backends' export contract).
// Missing CSV degrades gracefully: smaller skip set just means more DNS tests.
$fleet = [];
$fleetCsv = "$ROOT/sources/extension/whitelist/raw/all-extension.csv";
if (is_file($fleetCsv)) {
    foreach (array_slice(file($fleetCsv, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [], 1) as $line) {
        [$fd, $fc] = array_pad(explode(',', $line, 2), 2, '0');
        if ((int) $fc >= 200 && ($fd = clean_domain($fd)) !== null) $fleet[$fd] = true;
    }
}
$excl = load_json_domains("$ROOT/sources/gsheet/default-whitelist.json")
      + load_json_domains("$ROOT/sources/gsheet/manual-whitelist.json")
      + $fleet;
foreach (load_json_domains("$ROOT/sources/gsheet/omit-from-whitelist.json") as $g => $_) unset($excl[$g]);
$never = load_json_domains("$ROOT/sources/gsheet/omit-from-blocklist.json");

// ---------------------------------------------------------------- ledger ----
$seeded = false;
$ledger = [];
if (is_file($LEDGER)) {
    $ledger = json_decode((string) file_get_contents($LEDGER), true) ?: [];
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
        $ledger[$d]['s'] = array_values(array_unique(array_merge($ledger[$d]['s'], $srcs)));
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
$due = [];
$skippedNever = $skippedExcl = 0;
$sheetAFlagged = [];
foreach ($ledger as $d => $r) {
    if ($r['ll'] !== $TODAY) continue;              // delisted: stop spending tests on it
    if ($r['nc'] > $TODAY) continue;
    if (covered_subdomain($d, $never)) { $skippedNever++; continue; }
    $isSheetA = in_array('sheet-a', $r['s'], true);
    $inExcl = covered_subdomain($d, $excl);
    if ($inExcl) {
        if ($isSheetA) $sheetAFlagged[] = $d;       // tested anyway, but surfaced
        else { $skippedExcl++; continue; }
    }
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
$rep[] = '| skipped — never-block floor (H) | ' . $skippedNever . ' |';
$rep[] = '| skipped — exclusion set (hosts lanes) | ' . $skippedExcl . ' |';
$rep[] = '| tested | ' . count($results) . ' (alive ' . $alive . ' · dead ' . (count($results) - $alive) . ' · newly-died ' . $died . ' · resurrected ' . $resurrected . ') |';
$rep[] = '| deferred beyond MAX_TESTS | ' . $deferred . ' |';
$rep[] = '| due by tomorrow | ' . $dueTomorrow . ' |';
if ($sheetAFlagged) {
    $rep[] = '';
    $rep[] = '**Sheet A ∩ exclusion set** (tested anyway — review): ' . implode(', ', array_slice($sheetAFlagged, 0, 30)) . (count($sheetAFlagged) > 30 ? ' … +' . (count($sheetAFlagged) - 30) : '');
}
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
