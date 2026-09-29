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
it is written there, under a lock both keep: the first version went on without
the lock when it could not get it at once, and four runs on one file let 21
through a window of 20. Where the folder for the file does not exist nobody can
keep it, and this process counts its own, with a warning. A lock or a file out
of reach for longer than PATIENCE stops the test with the reason.
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
# A lock this old was left by a run that was stopped while it held it.
STALE = 10.0
# How long a turn waits for the lock, or for a file another program has open,
# before it stops the test and says why. Longer than STALE, so a lock left by a
# run that was stopped is taken over first.
PATIENCE = 30.0
THREAD = re.compile(r"^/[a-z2-7]{20}$")


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
        held = self._lock()

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
                self._unlock()

    # The lock is a folder, because making one either happens or does not on
    # every system and in every language that keeps this file.

    def _lock(self):
        """True once the lock is held, and False only where there is no folder to keep the count in."""
        folder = self.path + ".lock"
        deadline = time.monotonic() + self.patience

        while True:
            try:
                os.mkdir(folder)

                return True
            except FileExistsError as error:
                reason = error

                if self._stale(folder):
                    continue
            except FileNotFoundError:
                # No folder for the file, so no other run can keep it either.
                self._keep_alone("%s does not exist" % os.path.dirname(folder))

                return False
            except OSError as error:
                # On Windows a lock another process has just let go of can
                # refuse to be made again for a moment, with access denied.
                # That is a lock in the way, not a count nobody can keep.
                reason = error

            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "the count of opens and closes in %s was out of reach for %g seconds (%s). Another run holds it, or its "
                    "folder cannot be written: set AAMIO_LIVE_LEDGER to a file in a folder this process can write." % (self.path, self.patience, reason)
                )

            time.sleep(0.05)

    @staticmethod
    def _stale(folder):
        """Takes a lock away from a run that was stopped while it held it. True when it was taken away."""
        try:
            if time.time() - os.path.getmtime(folder) <= STALE:
                return False

            os.rmdir(folder)
        except OSError:
            return False

        return True

    def _unlock(self):
        # A lock that stays is taken over after STALE seconds, so this tries a
        # few times and then leaves it to that.
        for _ in range(20):
            try:
                os.rmdir(self.path + ".lock")

                return
            except FileNotFoundError:
                return
            except OSError:
                time.sleep(0.01)

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
