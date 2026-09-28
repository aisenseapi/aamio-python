"""The lock on a home, found by a health check on 17 September 2026.

The command line took the lock and never let go, so the next command read a
pid from the lock file and asked whether it lived with os.kill(pid, 0). On
Windows that call is TerminateProcess. Windows hands pids out again quickly, so
the process it ended was as often some other program as an old aamio, and the
command then refused to start because the pid had answered.

A second round the same day found three more. Letting go of the lock on the
way out saved state.json and outbox.json after commands that only read them. A
lock whose pid had since gone to another program was refused for as long as
that program ran. And the MCP server closed twice.
"""

import os
import subprocess
import sys
import tempfile
import shutil
import time

import pytest

sys.path.insert(0, "src")

from aamio import cli
from aamio.runtime import Runtime, pid_alive, process_started_at


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-lock-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def test_asking_whether_a_pid_lives_leaves_the_process_running():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    try:
        time.sleep(0.3)
        assert pid_alive(child.pid) is True
        time.sleep(0.3)
        assert child.poll() is None, "the check ended the process it asked about"
    finally:
        child.kill()
        child.wait()

    assert pid_alive(child.pid) is False
    assert pid_alive(os.getpid()) is True


def test_a_command_lets_go_of_the_lock_when_it_is_done(home, capsys):
    assert cli.main(["--home", home, "whoami"]) == 0
    assert not os.path.exists(os.path.join(home, "lock"))

    # And the next command starts, twice over, with no lock to argue with.
    assert cli.main(["--home", home, "scope", "list"]) == 0
    assert cli.main(["--home", home, "whoami"]) == 0
    assert '"key"' in capsys.readouterr().out


def test_a_lock_left_by_a_process_that_is_gone_is_taken_over(home):
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    with open(os.path.join(home, "lock"), "w", encoding="utf-8") as handle:
        handle.write('{"pid": %d, "at": 1}' % child.pid)

    runtime = Runtime(home=home)

    try:
        assert runtime.owns_lock is True
    finally:
        runtime.close()


def test_a_lock_held_by_a_live_runtime_is_still_refused(home):
    holder = subprocess.Popen([sys.executable, "-c", "import sys, time; sys.path.insert(0, 'src'); from aamio.runtime import Runtime; r = Runtime(home=sys.argv[1]); print('held', flush=True); time.sleep(30)", home], stdout=subprocess.PIPE, text=True)

    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(RuntimeError, match="another aamio"):
            Runtime(home=home)
        assert holder.poll() is None, "asking about the holder ended it"
    finally:
        holder.kill()
        holder.wait()


def test_a_command_that_only_reads_leaves_the_files_it_read_as_they_were(home, capsys):
    state = os.path.join(home, "state.json")
    written = '{"tags":["kept.as.written"],"peers":{},"channels":[]}'

    with open(state, "w", encoding="utf-8") as handle:
        handle.write(written)

    assert cli.main(["--home", home, "scope", "list"]) == 0
    assert cli.main(["--home", home, "whoami"]) == 0
    assert open(state, encoding="utf-8").read() == written
    assert not os.path.exists(os.path.join(home, "outbox.json"))
    assert "kept.as.written" in capsys.readouterr().out


def test_a_home_whose_files_cannot_be_read_is_refused_by_the_command_line_with_the_reason(home, capsys):
    state = os.path.join(home, "state.json")

    with open(state, "w", encoding="utf-8") as handle:
        handle.write("{not json")

    assert cli.main(["--home", home, "whoami"]) == 1
    assert "state.json could not be read" in capsys.readouterr().err
    assert open(state, encoding="utf-8").read() == "{not json"
    assert not os.path.exists(os.path.join(home, "lock"))


def test_a_lock_whose_pid_went_to_a_later_process_is_taken_over(home):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    try:
        time.sleep(0.3)
        started = process_started_at(child.pid)

        if started is None:
            pytest.skip("this system does not say when a process started")

        assert 0 <= time.time() - started < 60

        with open(os.path.join(home, "lock"), "w", encoding="utf-8") as handle:
            handle.write('{"pid": %d, "at": %d}' % (child.pid, int(time.time()) - 3600))

        runtime = Runtime(home=home)

        try:
            assert runtime.owns_lock is True
        finally:
            runtime.close()

        assert child.poll() is None, "taking the lock over ended the process"
    finally:
        child.kill()
        child.wait()


def test_closing_twice_saves_once(home):
    runtime = Runtime(home=home)
    saves = []
    runtime.save_state = lambda: saves.append("state")
    runtime.save_outbox = lambda: saves.append("outbox")
    runtime.close()
    runtime.close()

    assert saves == ["state", "outbox"]
    assert not os.path.exists(os.path.join(home, "lock"))


# A review on 28 September 2026 gave the PHP runtime three answers to whether a
# process lives: alive, proven gone, and not known. This one still had two, and
# every error that was not "no such process" counted as gone.


class StandInForWindows:
    """kernel32 as far as pid_alive uses it, answering what a test tells it to."""

    def __init__(self, handle, code=259, exit_code_known=True):
        self.handle = handle
        self.code = code
        self.exit_code_known = exit_code_known
        self.closed = []

    def OpenProcess(self, access, inherit, pid):
        return self.handle

    def GetExitCodeProcess(self, handle, code):
        if not self.exit_code_known:
            return 0

        code._obj.value = self.code

        return 1

    def CloseHandle(self, handle):
        self.closed.append(handle.value)

        return 1


@pytest.mark.parametrize("error, answer", [(5, True), (87, False), (8, None), (1455, None), (0, None)])
def test_on_windows_only_the_error_for_no_such_process_means_gone(error, answer):
    from aamio.runtime import _pid_alive_windows

    assert _pid_alive_windows(4321, StandInForWindows(handle=0), lambda: error) is answer


def test_on_windows_an_exit_code_that_cannot_be_read_proves_nothing():
    from aamio.runtime import _pid_alive_windows

    running = StandInForWindows(handle=77, code=259)
    ended = StandInForWindows(handle=78, code=1)
    unread = StandInForWindows(handle=79, exit_code_known=False)

    assert _pid_alive_windows(4321, running, lambda: 0) is True
    assert _pid_alive_windows(4321, ended, lambda: 0) is False
    assert _pid_alive_windows(4321, unread, lambda: 0) is None
    assert (running.closed, ended.closed, unread.closed) == ([77], [78], [79]), "a handle was left open"


def test_on_posix_only_the_error_for_no_such_process_means_gone():
    import errno

    from aamio.runtime import _pid_alive_posix

    def answering(error):
        def kill(pid, signal):
            assert signal == 0, "anything but signal 0 touches the process"

            if error is not None:
                raise error

        return kill

    assert _pid_alive_posix(4321, answering(None)) is True
    assert _pid_alive_posix(4321, answering(PermissionError(errno.EPERM, "not yours to signal"))) is True
    assert _pid_alive_posix(4321, answering(ProcessLookupError(errno.ESRCH, "no such process"))) is False
    assert _pid_alive_posix(4321, answering(OSError(errno.EINVAL, "something else"))) is None
    assert _pid_alive_posix(4321, answering(OverflowError("too large for a pid"))) is None


@pytest.mark.parametrize("pid", [0, -1, -4321, True, "4321", 4321.0, None, 2 ** 40])
def test_what_is_not_the_number_of_a_process_is_not_asked_about(pid, monkeypatch):
    import aamio.runtime as runtime_module

    asked = []
    monkeypatch.setattr(runtime_module, "_pid_alive_windows", lambda number: asked.append(number))
    monkeypatch.setattr(runtime_module, "_pid_alive_posix", lambda number: asked.append(number))

    assert pid_alive(pid) is None
    assert asked == [], "kill(0, 0) and kill(-1, 0) are questions about process groups"


@pytest.mark.parametrize("inspection", ["says it cannot tell", "fails"])
def test_a_lock_whose_owner_cannot_be_inspected_is_left_alone(home, monkeypatch, inspection):
    import aamio.runtime as runtime_module

    lock = os.path.join(home, "lock")
    # Any pid but this one: a lock with this process's own pid is its own.
    other = 4321 if os.getpid() != 4321 else 4322
    written = '{"pid": %d, "at": 1, "host": "https://fake.test"}' % other

    with open(lock, "w", encoding="utf-8") as handle:
        handle.write(written)

    def cannot_tell(pid):
        if inspection == "fails":
            raise OSError("process inspection is not available here")

        return None

    monkeypatch.setattr(runtime_module, "pid_alive", cannot_tell)

    with pytest.raises(RuntimeError, match="could not determine whether aamio") as refused:
        Runtime(home=home)

    assert "(pid %d) is still using" % other in str(refused.value)
    assert "the lock is left untouched" in str(refused.value)
    assert "Do not remove the lock unless" in str(refused.value)
    assert open(lock, encoding="utf-8").read() == written, "the lock was rewritten by the runtime that was refused"
    files = sorted(name for name in os.listdir(home) if os.path.isfile(os.path.join(home, name)))
    assert files == ["lock"], "the refused runtime wrote a file into a home it does not hold"

    # And once the owner is proven gone, the same lock is taken over as before.
    monkeypatch.setattr(runtime_module, "pid_alive", lambda pid: False)
    runtime = Runtime(home=home)

    try:
        assert runtime.owns_lock is True
    finally:
        runtime.close()


def test_the_command_line_says_why_it_stopped_when_it_cannot_tell(home, monkeypatch, capsys):
    import aamio.runtime as runtime_module

    other = 4321 if os.getpid() != 4321 else 4322

    with open(os.path.join(home, "lock"), "w", encoding="utf-8") as handle:
        handle.write('{"pid": %d, "at": 1}' % other)

    monkeypatch.setattr(runtime_module, "pid_alive", lambda pid: None)

    assert cli.main(["--home", home, "whoami"]) == 1
    said = capsys.readouterr()
    assert said.out == ""
    assert "could not determine whether aamio (pid %d) is still using" % other in said.err
