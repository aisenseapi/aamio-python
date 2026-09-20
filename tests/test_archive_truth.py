"""A message is only called archived when something was written.

Found by a Codex project review, 20 September 2026 (F2). archive() returns
without writing when the folder has archiving off, and the receiving loop then
set archived=True regardless. An application was told it could find the message
in an archive that does not exist, and there is no file to correct it with.

Three outcomes, not two: written, off, and failed. Each false says which.
"""

import os
import shutil
import sys
import tempfile
import time

import pytest

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime
from signing import stored

W = "a" * 20


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-archive-truth-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def one_message(runtime):
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels["inbox"] = channel
    runtime.client.read = lambda w, read_key, after, wait: (
        200,
        {"exists": True, "created_at": 1, "messages": [stored(W, 1, "hello", None)], "next": 1},
    )

    return runtime.poll(channel)[1]


def test_with_the_archive_off_nothing_is_called_archived(home):
    runtime = Runtime(home=home, archive=False)

    try:
        entries = one_message(runtime)

        assert entries, "no message came back"
        assert entries[0]["archived"] is False, "it said the message is in an archive this folder never writes"
        assert entries[0].get("archive_off") is True, "and did not say why it is not"
        assert not os.path.exists(os.path.join(home, "archive", "inbox.jsonl")), "and no file was written"
    finally:
        runtime.close()


def test_with_the_archive_on_it_is_archived_and_the_file_is_there(home):
    runtime = Runtime(home=home)

    try:
        entries = one_message(runtime)

        assert entries[0]["archived"] is True
        assert entries[0].get("archive_off") is None
        assert os.path.exists(os.path.join(home, "archive", "inbox.jsonl"))
    finally:
        runtime.close()


def test_a_write_that_failed_is_told_apart_from_one_that_was_off(home):
    runtime = Runtime(home=home)

    def refuse(label, record):
        raise OSError("disk is full")

    runtime.archive = refuse

    try:
        entries = one_message(runtime)

        assert entries[0]["archived"] is False
        assert entries[0].get("archive_off") is None, "a failure is not the same as a folder that keeps nothing"
        assert "disk is full" in entries[0]["archive_error"]
    finally:
        runtime.close()
