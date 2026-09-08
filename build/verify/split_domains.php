<?php
// Usage: php split_domains.php <num_chunks>
$numChunks = isset($argv[1]) ? intval($argv[1]) : 30;
$inputFile = __DIR__ . '/working_domains.txt';
$domains = file($inputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$total = count($domains);
$chunkSize = ceil($total / $numChunks);

for ($i = 0; $i < $numChunks; $i++) {
    $start = $i * $chunkSize;
    $chunk = array_slice($domains, $start, $chunkSize);
    file_put_contents(__DIR__ . "/working_domains_chunk_" . ($i+1) . ".txt", implode("\n", $chunk) . "\n");
}
echo "Split into $numChunks chunks.\n";