"""The live tests run only with AAMIO_LIVE set to exactly 1.

K3 of the health check of 24 September 2026: 0.6.18 checked whether the
variable was set at all, so a CI that sets it to 0 or false to keep the live
tests off would have run them against the service. The gate is read here as
pytest reads it, by running one offline test of each live file under each
value and reading what pytest reports.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ("tests/test_e2e.py::test_crypto_roundtrip", "tests/test_robust.py::test_one_runtime_per_home")


def outcome(value):
    """What pytest reports for one offline test of each live file under this value of AAMIO_LIVE."""
    env = {k: v for k, v in os.environ.items() if k != "AAMIO_LIVE"}
    if value is not None:
        env["AAMIO_LIVE"] = value
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", TESTS[0]], cwd=os.path.dirname(HERE), env=env, capture_output=True, text=True, timeout=120)
    return run.stdout.strip().splitlines()[-1]


def test_the_gate_opens_for_one_and_nothing_else():
    for value in (None, "", "0", "false", "no", "yes", "true"):
        assert "1 skipped" in outcome(value), (value, outcome(value))
    assert "1 passed" in outcome("1")


def test_both_live_files_carry_the_same_gate():
    for name in ("test_e2e.py", "test_robust.py"):
        with open(os.path.join(HERE, name), encoding="utf-8") as handle:
            assert 'os.environ.get("AAMIO_LIVE") != "1"' in handle.read(), name
