<?php

declare(strict_types=1);

// The PHP half's tests, with nothing but PHP: the process answers the probe,
// its command and its tool, refuses what it does not know with a fix, and
// speaks JSON on standard output when run as aamio runs it.
//
//     php tests/run.php

require dirname(__DIR__) . '/autoload.php';

use AamioExample\Process;

$passed = 0;
$failed = 0;
$check = static function (bool $ok, string $label) use (&$passed, &$failed): void {
    $ok ? $passed++ : $failed++;
    echo ($ok ? '  ok    ' : '  FAIL  ') . $label . "\n";
};
$request = static fn (string $kind, string $call, array $arguments = []): array => ['aamio_addon' => 2, 'kind' => $kind, 'name' => $call, 'arguments' => $arguments, 'subject' => null, 'own_key' => null, 'state_dir' => null, 'deadline_seconds' => 10, 'aamio' => ['version' => '0.3.13', 'runtime' => 'php']];
$manifest = json_decode((string) file_get_contents(dirname(__DIR__) . '/aamio-addon.json'), true);

$check(Process::handle($request('probe', 'probe')) === ['result' => ['ok' => true, 'name' => $manifest['name'], 'version' => $manifest['version'], 'aamio_addon' => 2], 'exit_code' => 0, 'is_error' => false], 'the probe says who this is, as the manifest does');
$check(Process::handle($request('command', 'wave', ['to' => 'Kari']))['result'] === ['hello' => 'Kari'], 'the command answers');
$check(Process::handle($request('command', 'wave'))['result'] === ['hello' => 'world'], 'with its default when the option is left out');
$check(Process::handle($request('tool', 'aamio_addon_' . Process::NAME . '_wave', ['to' => 'Ola']))['result'] === ['hello' => 'Ola'], 'and so does the tool');
$said = Process::handle($request('command', 'wave', ['to' => str_repeat('x', 65)]));
$check($said['exit_code'] === 2 && $said['is_error'] === true && ($said['result']['fix'] ?? '') !== '', 'a refusal has a fix');
$check(Process::handle($request('command', 'shout'))['result']['reason'] === 'unknown_call', 'an unknown call is refused');
$check(Process::handle(['aamio_addon' => 3])['result']['reason'] === 'not_contract_2' && Process::handle(null)['result']['reason'] === 'not_contract_2', 'and so is another contract');

$errFile = (string) tempnam(sys_get_temp_dir(), 'aamio-template-');
$process = proc_open([PHP_BINARY, dirname(__DIR__) . '/process.php'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $errFile, 'w']], $pipes);
fwrite($pipes[0], (string) json_encode($request('command', 'wave', ['to' => 'Kari'])));
fclose($pipes[0]);
$out = (string) stream_get_contents($pipes[1]);
fclose($pipes[1]);
$code = proc_close($process);
@unlink($errFile);
$check($code === 0 && json_decode($out, true) === ['result' => ['hello' => 'Kari'], 'exit_code' => 0, 'is_error' => false], 'run as aamio runs it, it writes one JSON answer and nothing else');

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
