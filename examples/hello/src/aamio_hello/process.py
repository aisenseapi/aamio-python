"""The process aamio runs for each call: one JSON request on standard input, one JSON answer on standard output.

    python -m aamio_hello.process < request.json

The request says kind (probe, command or tool), name and arguments; the answer
carries result, exit_code and is_error. The whole contract is at
https://aamio.at/docs/addons.
"""

import json
import sys

from . import __version__


def handle(request):
    if request.get("kind") == "probe":
        return {"result": {"ok": True, "name": "hello", "version": __version__, "aamio_addon": 2}, "exit_code": 0}
    arguments = request.get("arguments") or {}
    return {"result": {"hello": arguments.get("to") or "world"}, "exit_code": 0, "is_error": False}


if __name__ == "__main__":
    print(json.dumps(handle(json.loads(sys.stdin.read()))))
