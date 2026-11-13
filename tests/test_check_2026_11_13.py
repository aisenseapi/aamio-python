"""serve says why it cannot start on standard error (a check of 13 November 2026).

Its standard output is the protocol's alone. A server that could not open its
inbox, as with no service to answer, wrote the reason there as JSON, the way
every other command answers, and the host read a line it could not take as a
message. Each command runs as a process of its own here, against a port where
nothing listens, with its input closed: a server that did start would end at
once and say 0.
"""

import json
import os
import subprocess
import sys

SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def run(home, *words):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD="http://127.0.0.1:9")
    env.pop("AAMIO_ADDONS", None)
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(home), "--host", "http://127.0.0.1:9"] + list(words),
                          stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=120)
    return done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")


def test_serve_that_cannot_start_says_why_on_standard_error_and_nothing_on_the_protocol(tmp_path):
    code, out, err = run(tmp_path / "home", "serve")
    assert (code, out) == (1, ""), err
    assert "aamio: could not open inbox" in err


def test_another_command_that_cannot_do_what_it_was_asked_still_answers_with_json(tmp_path):
    code, out, err = run(tmp_path / "home", "channel", "close", "no-such-channel")
    assert code == 1, err
    told = json.loads(out)
    assert sorted(told) == ["error", "error_code"] and "no-such-channel" in told["error"]
