<?php

declare(strict_types=1);

namespace AamioExample;

/**
 * The process aamio runs for each call of this add-on: one JSON request on
 * standard input, one JSON answer on standard output.
 *
 *     php process.php < request.json
 *
 * The request, contract 2 of aamio's add-ons (https://aamio.at/docs/addons):
 *
 *     aamio_addon       2
 *     kind              probe | command | tool
 *     name              the command (wave) or the tool (aamio_addon_example_wave)
 *     arguments         what the caller gave, by name
 *     subject           a key the core resolved, when the manifest asks for one, or null
 *     own_key           the runtime's public key, when needs says own_key, or null
 *     state_dir         a directory of the add-on's own, or null
 *     deadline_seconds  how long the core waits before it stops the process
 *     aamio             {"version", "runtime"}
 *
 * The answer is {"result": ..., "exit_code": n, "is_error": bool}, with
 * "stderr" for a line to the user on the command line if you like. Write
 * nothing else to standard output, and give every refusal a fix that says what
 * to do instead. The Python half in python/ answers the same.
 */
final class Process
{
    public const CONTRACT = 2;
    public const NAME = 'example';
    public const VERSION = '0.1.0';

    /** @return array<string, mixed> */
    public static function answer(mixed $result, int $exitCode = 0): array
    {
        return ['result' => $result, 'exit_code' => $exitCode, 'is_error' => $exitCode !== 0];
    }

    /** @return array<string, mixed> */
    public static function refused(string $reason, string $fix): array
    {
        return self::answer(['status' => 'invalid', 'reason' => $reason, 'fix' => $fix], 2);
    }

    /**
     * @param array<string, mixed> $arguments
     * @return array<string, mixed>
     */
    public static function wave(array $arguments): array
    {
        $to = $arguments['to'] ?? null;
        if ($to === null || $to === '') {
            $to = 'world';
        }
        if (!is_string($to) || strlen($to) > 64) {
            return self::refused('invalid_to', 'to is a name of at most 64 characters.');
        }

        return self::answer(['hello' => $to]);
    }

    /** @return array<string, mixed> */
    public static function handle(mixed $request): array
    {
        if (!is_array($request) || ($request['aamio_addon'] ?? null) !== self::CONTRACT) {
            return self::refused('not_contract_2', "This add-on speaks contract 2 of aamio's add-ons. Upgrade aamio, or install a version of this add-on made for yours.");
        }
        $kind = $request['kind'] ?? null;
        $name = $request['name'] ?? null;
        $arguments = is_array($request['arguments'] ?? null) ? $request['arguments'] : [];
        if ($kind === 'probe') {
            // What enable asks before it records the choice: who this is.
            return self::answer(['ok' => true, 'name' => self::NAME, 'version' => self::VERSION, 'aamio_addon' => self::CONTRACT]);
        }
        if (($kind === 'command' && $name === 'wave') || ($kind === 'tool' && $name === 'aamio_addon_' . self::NAME . '_wave')) {
            return self::wave($arguments);
        }

        return self::refused('unknown_call', 'The add-on ' . self::NAME . ' has no ' . json_encode($kind) . ' called ' . json_encode($name) . '. aamio addon ' . self::NAME . ' --help lists its commands.');
    }

    /** Standard input to standard output, once. */
    public static function main(): int
    {
        $request = json_decode((string) stream_get_contents(STDIN), true);
        $said = self::handle($request);
        fwrite(STDOUT, (string) json_encode($said, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        fflush(STDOUT);

        return $said['exit_code'];
    }
}
