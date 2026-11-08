# aamio add-on template

A starting point for an add-on to [aamio](https://aamio.at): a package of its
own that gives the Python or PHP runtime commands under `aamio addon NAME` and
MCP tools named `aamio_addon_NAME_*`. It is on contract 2 of aamio's add-ons:
the core reads `aamio-addon.json` without running anything, and runs your code
in a process of its own for each call, with a deadline. The whole contract is at
[aamio.at/docs/addons](https://aamio.at/docs/addons).

The template answers one command and one tool, `wave`, in both runtimes: the
PHP package at the root, where Packagist wants it, and the Python package in
`python/`. Keep the runtime you want and delete the other.

## Start

1. Press **Use this template** on GitHub, or copy the files.
2. Give the add-on its name. It becomes the command, the tool names, the
   Python package `aamio_NAME`, the distribution `aamio-NAME` and the PHP
   namespace `AamioName`:

   ```bash
   python rename.py weather
   ```

3. Set your own vendor in `composer.json`, write your own README, and run
   `python check.py` whenever you change a name or a version: it says which
   file disagrees.

## Try it

Python, with aamio 0.6.27 or later:

```bash
cd python
pip install -e ".[test]"
python -m pytest
aamio addon enable weather
aamio addon weather wave --to Kari
```

PHP, with aisenseapi/aamio 0.3.13 or later in a project of your own.
AAMIO_ADDONS names a checkout to run without installing or enabling it:

```bash
php tests/run.php
composer require aisenseapi/aamio
AAMIO_ADDONS=/path/to/this/checkout vendor/bin/aamio addon weather wave --to Kari
```

## Where the name and the version are

| File | What it says |
|---|---|
| `aamio-addon.json` and `python/src/aamio_NAME/aamio-addon.json` | name, version, the process to run, the commands and the tools. Keep the two copies the same |
| `python/pyproject.toml` | the entry point, `NAME = "aamio_NAME"`, which is how the core finds the package |
| `python/src/aamio_NAME/__init__.py` | `NAME` and `__version__` |
| `composer.json` | `extra.aamio-addon.name` and `"contract": 2` |
| `src/Process.php` and `autoload.php` | `NAME`, `VERSION` and the namespace |

## Write your own

A command goes in the manifest under `commands`, with its `help` and its
`arguments`, and in `handle()` in both processes. A tool goes under `tools`,
with a name that starts with `aamio_addon_NAME_`, a description an agent can
act on, and an `inputSchema` with `additionalProperties: false`: the core
refuses any argument the schema does not have.

An answer is `{"result": ..., "exit_code": n, "is_error": bool}`. Every refusal
carries a `reason` and a `fix` that says what to do instead. Standard output
carries the answer and nothing else.

What the core can give a call, when the manifest asks:

- `"needs": ["own_key"]` on a command: the runtime's public key. Never the
  private key: no add-on gets it.
- an argument with `"subject": "partner"`: the core looks the name up in the
  address book and hands over the key.
- an argument with `"host": true`: a website the user must have allowed with
  `aamio addon NAME allow`.
- `"environment"`: the names of variables your process reads. `aamio addon
  list` shows them before the add-on is enabled.
- `"runtime": false` on a command that needs no home.
- `"deadline_seconds"`, 1 to 120. An answer is at most 1 MB and standard error
  64 KB.

## Publish

Python: `cd python && python -m build && twine upload dist/*`. PHP: tag a
version and submit the repository to Packagist. Users then run
`pip install aamio-NAME` or `composer require YOUR-VENDOR/aamio-NAME`, and
`aamio addon enable NAME`. Installed is not enabled: nothing of an add-on runs
until the user enables it, and enabling starts the process once, to see that
it answers as its manifest says.

## Trust

An add-on on contract 2 is not a sandbox. It runs as the user, with the user's
file permissions and network, and users enable what they trust. Ask for
nothing your add-on does not use, and say in your README what it sends where.

The template is under MIT No Attribution: use it as you like.
