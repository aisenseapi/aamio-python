"""The process aamio runs for each call of this add-on: one JSON request on standard input, one JSON answer on standard output.

    python -m aamio_example.process < request.json

The request, contract 2 of aamio's add-ons (https://aamio.at/docs/addons):

    aamio_addon       2
    kind              probe | command | tool
    name              the command (wave) or the tool (aamio_addon_example_wave)
    arguments         what the caller gave, by name
    subject           a key the core resolved, when the manifest asks for one, or null
    own_key           the runtime's public key, when needs says own_key, or null
    state_dir         a directory of the add-on's own, or null
    deadline_seconds  how long the core waits before it stops the process
    aamio             {"version", "runtime"}

The answer is {"result": ..., "exit_code": n, "is_error": bool}, with "stderr"
for a line to the user on the command line if you like. Write nothing else to
standard output, and give every refusal a fix that says what to do instead.
The PHP half at the root of the repository answers the same.
"""

import json
import sys

from . import NAME, __version__

CONTRACT = 2


def answer(result, exit_code=0):
    return {"result": result, "exit_code": exit_code, "is_error": exit_code != 0}


def refused(reason, fix):
    return answer({"status": "invalid", "reason": reason, "fix": fix}, 2)


def wave(arguments):
    to = arguments.get("to") or "world"
    if not isinstance(to, str) or len(to) > 64:
        return refused("invalid_to", "to is a name of at most 64 characters.")
    return answer({"hello": to})


def handle(request):
    if not isinstance(request, dict) or request.get("aamio_addon") != CONTRACT:
        return refused("not_contract_2", "This add-on speaks contract 2 of aamio's add-ons. Upgrade aamio, or install a version of this add-on made for yours.")
    kind = request.get("kind")
    name = request.get("name")
    arguments = request.get("arguments") if isinstance(request.get("arguments"), dict) else {}
    if kind == "probe":
        # What enable asks before it records the choice: who this is.
        return answer({"ok": True, "name": NAME, "version": __version__, "aamio_addon": CONTRACT})
    if (kind == "command" and name == "wave") or (kind == "tool" and name == "aamio_addon_%s_wave" % NAME):
        return wave(arguments)
    return refused("unknown_call", "The add-on %s has no %s called %s. aamio addon %s --help lists its commands." % (NAME, kind, name, NAME))


def main():
    try:
        request = json.loads(sys.stdin.read())
    except ValueError:
        request = None
    said = handle(request)
    sys.stdout.write(json.dumps(said))
    sys.stdout.flush()
    return said["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
