<?php

declare(strict_types=1);

// The process aamio runs for each call of this add-on, named in aamio-addon.json
// under process.php: one JSON request on standard input, one JSON answer on
// standard output. It needs nothing of aamio's core, only its own classes.
require __DIR__ . '/autoload.php';

exit(\AamioExample\Process::main());
