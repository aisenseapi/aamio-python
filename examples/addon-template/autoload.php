<?php

declare(strict_types=1);

// The add-on's own classes, for the process aamio starts with nothing but PHP,
// and for the tests. A class Composer already knows is left to Composer.
spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'AamioExample\\')) {
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen('AamioExample\\'))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
