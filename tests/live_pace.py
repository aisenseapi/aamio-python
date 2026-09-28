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
other are counted as the one client the service sees. Where the file cannot be
kept, the count of this process is kept in memory and the tests run as before.
"""

import collections
import json
import os
import re
import tempfile
import threading
import time
import urllib.parse

# Twenty of the thirty. The rest is for whoever else writes from this address.
LIMIT = 20
# One second more than the service's window, so a stamp that has left this
# window has left that one.
WINDOW = 61.0
# A lock this old was left by a run that was stopped while it held it.
STALE = 10.0
THREAD = re.compile(r"^/[a-z2-7]{20}$")


def ledger_path():
    return os.environ.get("AAMIO_LIVE_LEDGER") or os.path.join(tempfile.gettempdir(), "aamio-live-pace.json")


def counted(method, url, host):
    """Whether this request is an open or a close of a thread at the service under test."""
    if method not in ("PUT", "DELETE") or not url.startswith(host.rstrip("/") + "/"):
        return False

    return THREAD.match(urllib.parse.urlsplit(url).path) is not None


class Pace:
    def __init__(self, limit=LIMIT, window=WINDOW, path=None, clock=time.time, sleep=time.sleep):
        self.limit = int(limit)
        self.window = float(window)
        self.path = path or ledger_path()
        self.clock = clock
        self.sleep = sleep
        self.own = []
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
            # Read without the lock too: the file is replaced whole, never
            # written in place, so what is there is what somebody finished.
            shared = collections.Counter(stamp for stamp in self._read() if 0 <= now - stamp < self.window)
            own = collections.Counter(stamp for stamp in self.own if 0 <= now - stamp < self.window)
            # What this process took is in the file as well, where the file
            # could be written, and is counted once. Two that fell on the same
            # instant are two: a clock is coarser than the requests it times.
            stamps = sorted((shared | own).elements())

            if len(stamps) >= self.limit:
                # Room opens when the oldest that still counts has left the window.
                return self.window - (now - stamps[len(stamps) - self.limit]) + 0.05

            stamps.append(now)
            self.own = sorted(own.elements()) + [now]

            if held:
                self._write(stamps)

            return None
        finally:
            if held:
                self._unlock()

    # The lock is a folder, because making one either happens or does not on
    # every system and in every language that keeps this file.

    def _lock(self):
        folder = self.path + ".lock"
        deadline = time.monotonic() + 5.0

        while True:
            try:
                os.mkdir(folder)

                return True
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(folder) > STALE:
                        os.rmdir(folder)

                        continue
                except OSError:
                    pass
            except OSError:
                return False

            if time.monotonic() >= deadline:
                return False

            time.sleep(0.05)

    def _unlock(self):
        try:
            os.rmdir(self.path + ".lock")
        except OSError:
            pass

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as handle:
                found = json.load(handle)
        except (OSError, ValueError):
            return []

        if not isinstance(found, list):
            return []

        return [float(stamp) for stamp in found if isinstance(stamp, (int, float)) and not isinstance(stamp, bool)]

    def _write(self, stamps):
        try:
            with open(self.path + ".tmp", "w", encoding="utf-8") as handle:
                json.dump(stamps, handle)

            os.replace(self.path + ".tmp", self.path)
        except OSError:
            pass


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
