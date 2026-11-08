"""The process the core runs for each call of this add-on: one request on standard input, one answer on standard output.

    python -m aamio_domain_keys.process < request.json

The request and the answer are contract 2 of aamio's add-ons, written up at
https://aamio.at/docs/addons. The core has already settled what is the core's:
the website is one the user agreed to, the subject carries the key it resolved
from the address book or from a signature it checked, and own_key is the
runtime's public key where a command needs it. Nothing here opens the home.

    kind    command | tool | probe
    name    file | validate | check | aamio_addon_domain_check

An answer is {"result": …, "exit_code": n, "is_error": bool}, or {"raw": base64}
for bytes that go to standard output as they are, with "stderr" for a line to
the user. Standard output carries the answer and nothing else.
"""

import base64
import json
import sys

from . import NAME, __version__, lists, policy

CONTRACT = 2


def answer(result=None, exit_code=0, is_error=None, raw=None, stderr=None):
    said = {"exit_code": exit_code, "is_error": (exit_code != 0) if is_error is None else is_error}
    if raw is not None:
        said["raw"] = base64.b64encode(raw).decode("ascii")
    else:
        said["result"] = result
    if stderr:
        said["stderr"] = stderr
    return said


def handle(request, **network):
    """The answer to one request. network goes to fetch.check, for tests."""
    if not isinstance(request, dict) or request.get("aamio_addon") != CONTRACT:
        return answer({"error": "this add-on speaks contract %d of aamio's add-ons, and the request is not on it" % CONTRACT, "fix": "Upgrade aamio, or install the version of aamio-domain-keys made for yours."}, 2, True)
    kind = request.get("kind")
    name = request.get("name")
    arguments = request.get("arguments") if isinstance(request.get("arguments"), dict) else {}
    subject = request.get("subject")
    if kind == "probe":
        return answer({"ok": True, "name": NAME, "version": __version__, "aamio_addon": CONTRACT})
    if kind == "command" and name == "file":
        try:
            raw = lists.make([{"key": request.get("own_key"), "name": arguments.get("name")}])
        except lists.InvalidDocument as error:
            # To the user and not to standard output: `aamio addon domain file > aamio-keys.json`
            # would publish the complaint.
            return answer(exit_code=2, is_error=True, stderr=json.dumps({"error": error.reason, "fix": "--name is a label of 1 to 64 characters of a-z, 0-9, dot, underscore and dash."}))
        return answer(raw=raw, stderr="aamio: this holds your public key and nothing secret. Publish it at https://YOUR-DOMAIN%s, with no login and no redirect, on a domain you already control." % lists.PATH)
    if kind == "command" and name == "validate":
        result, code = lists.check_file(arguments.get("file"))
        return answer(result, code)
    if (kind == "command" and name == "check") or (kind == "tool" and name == "aamio_addon_domain_check"):
        found = policy.check(arguments.get("domain"), subject, arguments.get("name"), **network)
        return answer(found, policy.EXIT_CODES[found["status"]], "fix" in found)
    return answer({"error": "the add-on %s has no %s called %s" % (NAME, kind, name), "fix": "aamio addon %s --help lists its commands, and aamio addon list its tools." % NAME}, 2, True)


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
