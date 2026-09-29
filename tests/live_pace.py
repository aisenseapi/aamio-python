"""The live tests, spaced out to what the service allows one address.

The service takes thirty opens and closes of threads in sixty seconds from one
address, in one counter, and answers 429 past that. The live tests of this
client made 23 of them until the first exchange got its own test, and 43 after:
run straight through, three tests failed on the 429 and none of them on the
code. Found on 28 September 2026, and the agents that share the address were
refused for the rest of that minute as well.

So every open and close of a thread that a live test makes waits until fewer
than LIMIT of them fall inside the last WINDOW seconds. Nothing else is held
back: reads, writes and presence have counters of their own, and a wide margin.

The count is kept in a file in the temp folder, not in this process. The live
tests of aamio-php keep the same file, so the two suites run one after the
other are counted as the one client the service sees. A turn is taken only once
it is written there, under a lock both keep.

The lock is one the operating system holds on the file beside the count, TURN,
and lets go of when its process ends, however that comes. So it is never taken
over, and nothing has to guess whether its holder is gone. The first version
made a folder for a lock and took over one older than ten seconds, and two
things went wrong with that. A lock let go of between a failed attempt and the
look after it was taken for one that could not be made, and the turn went on
without it. And a writer that was only slow lost its lock to another run while
it wrote (a review, 29 September 2026). Both let 21 through a window of 20.

Where the folder for the file does not exist nobody can keep it, and this
process counts its own, with a warning. A lock or a file out of reach for
longer than PATIENCE stops the test with the reason.
"""

import collections
import json
import os
import re
import tempfile
import threading
import time
import urllib.parse
import warnings

# Twenty of the thirty. The rest is for whoever else writes from this address.
LIMIT = 20
# One second more than the service's window, so a stamp that has left this
# window has left that one.
WINDOW = 61.0
# How long a turn waits for the lock, or for a file another program has open,
# before it stops the test and says why.
PATIENCE = 30.0
# Beside the count: the file whose lock says whose turn it is. aamio-php
# locks the same file.
TURN = ".turn"
THREAD = re.compile(r"^/[a-z2-7]{20}$")


def lock_file(fd):
    """Locks an open file for this process without waiting, or raises OSError.

    One byte with msvcrt on Windows, flock elsewhere. PHP's flock() takes the
    same lock: on Windows it locks the whole file, which covers the byte. The
    runtime's own lock on a home is the same mechanism, in aamio.storage.hold;
    this copy keeps the helper free of the package, for the processes the
    tests start with nothing but this folder on their path.
    """
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def unlock_file(fd):
    """Lets go of the lock and closes the file, which would let go of it anyway."""
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        os.close(fd)


def ledger_path():
    return os.environ.get("AAMIO_LIVE_LEDGER") or os.path.join(tempfile.gettempdir(), "aamio-live-pace.json")


def counted(method, url, host):
    """Whether this request is an open or a close of a thread at the service under test."""
    if method not in ("PUT", "DELETE") or not url.startswith(host.rstrip("/") + "/"):
        return False

    return THREAD.match(urllib.parse.urlsplit(url).path) is not None


class Pace:
    def __init__(self, limit=LIMIT, window=WINDOW, path=None, clock=time.time, sleep=time.sleep, patience=PATIENCE):
        self.limit = int(limit)
        self.window = float(window)
        self.path = path or ledger_path()
        self.clock = clock
        self.sleep = sleep
        self.patience = float(patience)
        self.own = []
        # The stamp of the last turn, as it was written.
        self.last = None
        # Whether the count is kept in this process only, for want of a folder.
        self.alone = False
        self.waited = 0.0
        self.taken = 0
        self.mutex = threading.Lock()

    def take(self):
        """Waits until there is room for one more, takes it, and returns the seconds waited."""
        waited = 0.0

        with self.mutex:
            while True:
                hold = self._take_or_hold()

                if hold is None:
                    self.taken += 1
                    self.waited += waited

                    return waited

                self.sleep(hold)
                waited += hold

    def _take_or_hold(self):
        turn = self._lock()
        held = turn is not None

        try:
            now = self.clock()
            shared = collections.Counter(stamp for stamp in (self._read() if held else []) if 0 <= now - stamp < self.window)
            own = collections.Counter(stamp for stamp in self.own if 0 <= now - stamp < self.window)
            # What this process took is in the file as well, where the file
            # could be written, and is counted once. Two that fell on the same
            # instant are two: a clock is coarser than the requests it times.
            stamps = sorted((shared | own).elements())

            if len(stamps) >= self.limit:
                # Room opens when the oldest that still counts has left the window.
                return self.window - (now - stamps[len(stamps) - self.limit]) + 0.05

            stamps.append(now)

            if held:
                # Written before the turn is taken. A turn the other runs
                # cannot see is the one that takes the count over the limit.
                self._write(stamps)

            self.own = sorted(own.elements()) + [now]
            self.last = now

            return None
        finally:
            if held:
                unlock_file(turn)

    def _lock(self):
        """The open TURN file once its lock is held, and None only where there is no folder to keep the count in.

        A lock held by another run is waited for as long as that run holds it,
        up to PATIENCE, and never taken away: however old, it is held by a
        process that is still there, since the lock of one that ended is gone.
        """
        deadline = time.monotonic() + self.patience

        while True:
            try:
                fd = os.open(self.path + TURN, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
            except FileNotFoundError:
                # No folder for the file, so no other run can keep it either.
                self._keep_alone("%s does not exist" % os.path.dirname(self.path + TURN))

                return None
            except OSError as error:
                reason = error
            else:
                try:
                    lock_file(fd)

                    return fd
                except OSError as error:
                    os.close(fd)
                    reason = error

            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "the count of opens and closes in %s was out of reach for %g seconds (%s). Another run holds it, or its "
                    "folder cannot be written: set AAMIO_LIVE_LEDGER to a file in a folder this process can write." % (self.path, self.patience, reason)
                )

            time.sleep(0.05)

    def _keep_alone(self, why):
        if not self.alone:
            self.alone = True
            warnings.warn("%s, so this process counts its own opens and closes and no other run sees them" % why, RuntimeWarning, stacklevel=2)

    def _read(self):
        """The stamps in the file. A file that is not there holds none. One that is there and will not open is waited for, never taken for empty."""
        deadline = time.monotonic() + self.patience

        while True:
            try:
                with open(self.path, "rb") as handle:
                    raw = handle.read()

                break
            except FileNotFoundError:
                return []
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError("the count in %s could not be read for %g seconds: %s" % (self.path, self.patience, error))

                time.sleep(0.05)

        try:
            found = json.loads(raw.decode("utf-8"))
        except ValueError:
            # Not written here, since the file is only ever replaced whole.
            # Taken for empty, and the next turn writes it over.
            return []

        if not isinstance(found, list):
            return []

        stamps = []

        for stamp in found:
            if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
                continue

            try:
                stamps.append(float(stamp))
            except OverflowError:
                continue

        return stamps

    def _write(self, stamps):
        """Replaces the file whole, so a reader never meets half of it, and waits out another program that has it open."""
        temporary = "%s.%d.tmp" % (self.path, os.getpid())
        deadline = time.monotonic() + self.patience

        while True:
            try:
                with open(temporary, "w", encoding="utf-8") as handle:
                    json.dump(stamps, handle)

                os.replace(temporary, self.path)

                return
            except OSError as error:
                if time.monotonic() >= deadline:
                    try:
                        os.unlink(temporary)
                    except OSError:
                        pass

                    raise RuntimeError("the count in %s could not be written for %g seconds: %s" % (self.path, self.patience, error))

                time.sleep(0.05)


def install(pace=None, host=None):
    """Puts the pace in front of every request the client makes. Once, however often it is asked.

    Only the service the live tests run against is paced: AAMIO_HOST, or the
    default. A test that stands a service of its own up on another address is
    not held back by a limit that address does not have.
    """
    from aamio import client

    if getattr(client.AamioClient.http, "paced", None) is not None:
        return client.AamioClient.http.paced

    pace = pace or Pace()
    plain = client.AamioClient.http
    target = host or os.environ.get("AAMIO_HOST") or client.DEFAULT_HOST

    def http(self, method, url, *rest, **named):
        if counted(method, url, target):
            pace.take()

        return plain(self, method, url, *rest, **named)

    http.paced = pace
    http.plain = plain
    client.AamioClient.http = http

    return pace


def remove():
    """Takes it out again, for a test that put it in."""
    from aamio import client

    plain = getattr(client.AamioClient.http, "plain", None)

    if plain is not None:
        client.AamioClient.http = plain
