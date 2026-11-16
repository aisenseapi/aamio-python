"""Transports for one home: profiles, bindings to partners, and the service the owner of the home runs (contract 3, B).

The home keeps, under transports/: profiles.json, the security profiles of B5;
bindings.json, for each partner's key an ordered list of a transport and a
profile; and carry.json, the carrier state of aamio-carry-v1-tilstand. The
address book, partners.json, is shared with aamio-php and the Node runtime and
is written again as {name, key} by partner add, so the bindings live here, by
the partner's key. A partner without a binding goes over HTTPS as before; a
partner with one goes over its transport only, and never over HTTPS instead.

Only the process that owns the home runs a transport (B2): aamio serve for as
long as it serves, and a send or a read that waits, on the command line, for as
long as it runs. The service starts every transport that is enabled and bound
to a partner, in a working folder of its own outside the home, pumps the
carriers in one thread, starts a transport again after a crash after 1, 5 and
30 seconds, leaves it down after three crashes in ten minutes, and stops it with
the owner. The carrier and the state hold no locks of their own, so every call
into them goes through the service's lock.
"""

import base64
import hashlib
import json
import os
import re
import sys
import threading
import time

from . import __version__ as CORE_VERSION
from . import carry, carry_state, storage
from .addon_process import ENVIRONMENT, NEVER_PASSED, AddonError, TransportManifest, child_environment, process_command
from .carrier import Carrier
from .carry import CarryRefused
from .crypto import is_key
from .errors import CodedLookupError, CodedRuntimeError, CodedValueError
from .transport_host import TransportFailed, TransportProcess

PROFILE_VERSION = 1
DEFAULT_PROFILE = "sealed"
RESTART_AFTER = (1, 5, 30)
CRASH_WINDOW, CRASHES_MOST = 600, 3
WAIT_DEFAULT = 30
# How often a running carrier's list of whom it takes messages from is read again: a partner removed meanwhile, over MCP
# or by another runtime on the same home, is taken from no longer than this after.
KNOWN_REFRESH = 2.0
# How often a file under transports/ is tried again while another program holds it, as an indexer or a sync client
# does on Windows for a moment, and how long between: a replace that met a reader is not a file that cannot be written.
# Within this process readers and writers take turns under a lock of the folder's own, so they never meet.
HELD_TRIES, HELD_PAUSE = 100, 0.05
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def _folder_lock(folder):
    """One lock per transports/ folder in this process, whichever Config reads or writes it."""
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(os.path.normcase(os.path.abspath(folder)), threading.RLock())
# What a carried message is filed under when the partner it came from is no longer bound to a transport.
UNBOUND_CHANNEL = "carry"
_PROFILE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def profile_record(name, mode="sealed", lifetime=carry_state.LIFETIME_DEFAULT, window=carry_state.CHALLENGE_WINDOW_DEFAULT, max_content=carry.MAX_CONTENT):
    """A profile as B5 writes it: with a challenge, on a medium both ways, the clock trusted."""
    return {"name": name, "version": PROFILE_VERSION, "mode": mode, "challenge": True, "accept_unchallenged": False, "lifetime": lifetime,
            "challenge_window": window, "clock_trusted": True, "max_content": max_content, "radio": None}


def checked(record):
    """The profile the core holds to (B5), from a record in profiles.json; CodedValueError when it is not one."""
    if not isinstance(record, dict) or record.get("version") != PROFILE_VERSION:
        raise CodedValueError("transport_profile_unknown", "the profile %s is of a version this aamio does not know, so nothing is sent with it" % (record or {}).get("name"))
    if record.get("radio") is not None:
        raise CodedValueError("transport_profile_incomplete", "the profile %s has radio settings, and v1 has no radio transport" % record.get("name"))
    if not isinstance(record.get("name"), str) or _PROFILE_NAME.fullmatch(record["name"]) is None:
        raise CodedValueError("transport_profile_invalid", "a profile's name is 1 to 32 characters of a-z, 0-9, dash and underscore")
    flags = ("challenge", "accept_unchallenged", "clock_trusted")
    numbers = ("lifetime", "challenge_window", "max_content")
    if any(not isinstance(record.get(field), bool) for field in flags) or any(type(record.get(field)) is not int for field in numbers):
        raise CodedValueError("transport_profile_invalid", "the profile %s has a field of the wrong kind" % record["name"])
    try:
        return carry_state.profile(mode=record["mode"], challenge=record["challenge"], accept_unchallenged=record["accept_unchallenged"],
                                   lifetime=record["lifetime"], challenge_window=record["challenge_window"], clock_trusted=record["clock_trusted"],
                                   max_content=record["max_content"])
    except (KeyError, TypeError, ValueError) as error:
        raise CodedValueError("transport_profile_invalid", "the profile %s cannot be used: %s" % (record.get("name"), error)) from None


def working_folder(home, name, make=True):
    """B2: the transport's folder, outside the home and private to the user, one per home and transport."""
    h = hashlib.sha256(os.path.abspath(home).encode("utf-8")).hexdigest()[:8]
    if sys.platform == "win32":
        base = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local"), "aamio-transports")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support/aamio-transports")
    else:
        base = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "aamio-transports")
    path = os.path.join(base, "%s-%s" % (name, h))
    if make:
        os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def environment_for(manifest, cwd, base=None, declared=True):
    """B2: contract 2's short list, AAMIO_ADDON=3 and, unless declared is False, what the manifest declares, made safe as contract 2 makes it."""
    base = os.environ if base is None else base
    env = {key: value for key, value in base.items() if key.upper() in ENVIRONMENT}
    if declared:
        for name in manifest.environment:
            if name.upper() not in NEVER_PASSED and name in base:
                env[name] = base[name]
    env["AAMIO_ADDON"] = "3"
    return child_environment(env, cwd)


def probe(manifest, home):
    """What enable asks of a transport before anything is recorded: it starts, describes itself as its manifest says, and stops.

    hello says probe, and a transport then takes nothing of its medium in use:
    no port is opened, nothing is sent and nothing is listened to (B3). It
    runs with the short list and none of the variables its manifest asks for,
    as contract 2's probe does: the user sees those names before the first
    real start gets them.
    """
    folder = working_folder(home, manifest.NAME)
    heard = []
    process = TransportProcess(manifest.NAME, manifest.__version__, process_command(manifest.start_module), folder,
                               environment_for(manifest, folder, declared=False), log=heard.append)
    try:
        process.start(CORE_VERSION, "python", folder, probe=True)
    except (TransportFailed, OSError) as error:
        until = time.monotonic() + 0.5
        while not heard and time.monotonic() < until:
            time.sleep(0.05)
        said = (" It said: %s" % heard[-1]) if heard else ""
        raise AddonError("the transport %s did not start and describe itself as its manifest says: %s.%s Nothing was recorded; reinstall it, or %s to go on without it." % (manifest.NAME, error, said, manifest.fix)) from None
    finally:
        process.stop()
    if process.medium != manifest.medium:
        raise AddonError("the transport %s describes itself as one over %s, and its manifest says %s. Nothing was recorded; reinstall it, or %s to go on without it." % (manifest.NAME, process.medium, manifest.medium, manifest.fix))


class Config:
    """profiles.json and bindings.json under transports/ in the home, read whole and written atomically."""

    def __init__(self, home):
        self.home = home
        self.dir = os.path.join(home, "transports")
        # The transports' own thread reads these files while the runtime may change them: on Windows a replace that met
        # a reader failed, also after a second of tries under load (the follow-up check of 15 November 2026).
        self.lock = _folder_lock(self.dir)

    def _read(self, name, field):
        with self.lock:
            return self._read_held(name, field)

    def _read_held(self, name, field):
        path = os.path.join(self.dir, name)
        value = None
        for attempt in range(HELD_TRIES):
            try:
                with open(path, "rb") as handle:
                    value = json.loads(handle.read().decode("utf-8"))
                break
            except FileNotFoundError:
                return {}
            except PermissionError:
                # Windows: the file is being replaced this moment. Read as unreadable it stopped a send, and a running
                # transport took messages from no one until the next look.
                if attempt == HELD_TRIES - 1:
                    value = None
                    break
                time.sleep(HELD_PAUSE)
            except (OSError, ValueError):
                value = None
                break
        if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get(field), dict):
            raise CodedRuntimeError("transport_config_unreadable", "%s could not be read. Which partners go over a transport is not known while it cannot, so nothing is sent to a partner until it is repaired or moved away" % path)
        return value[field]

    def _write(self, name, field, value):
        with self.lock:
            self._write_held(name, field, value)

    def _write_held(self, name, field, value):
        storage.make_private_dir(self.dir)
        path = os.path.join(self.dir, name)
        with storage.open_private(path + ".tmp") as handle:
            json.dump({"version": 1, field: value}, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(HELD_TRIES):
            try:
                os.replace(path + ".tmp", path)
                break
            except PermissionError:
                # Windows: a reader holds the file for a moment, as the transports' own thread reading the bindings.
                if attempt == HELD_TRIES - 1:
                    raise CodedRuntimeError("not_saved", "%s could not be replaced: another reader holds it. Nothing changed; try again." % path) from None
                time.sleep(HELD_PAUSE)
        storage.sync_dir(self.dir)

    def profiles(self):
        return self._read("profiles.json", "profiles")

    def bindings(self):
        found = self._read("bindings.json", "partners")
        for key, routes in found.items():
            if not isinstance(routes, list) or not routes or any(not isinstance(route, dict) or set(route) != {"transport", "profile"}
                                                                 or not all(isinstance(route[field], str) for field in route) for route in routes):
                raise CodedRuntimeError("transport_config_unreadable", "%s has a binding that is not a list of transport and profile. Nothing is sent to a partner until it is repaired or moved away" % os.path.join(self.dir, "bindings.json"))
        return found

    def profile(self, name):
        found = self.profiles().get(name)
        if found is None and name == DEFAULT_PROFILE:
            return profile_record(DEFAULT_PROFILE)
        if found is None:
            raise CodedLookupError("transport_profile_unknown", "no profile called %s: aamio transport profile add %s" % (name, name))
        return found

    def add_profile(self, record):
        checked(record)
        profiles = self.profiles()
        if record["name"] in profiles and self._in_use(record["name"]) and profiles[record["name"]] != record:
            # A change under a bound partner changes how its messages are checked while they are under way.
            raise CodedValueError("transport_profile_in_use", "the profile %s is bound to a partner: aamio transport unbind first, or add a profile of another name" % record["name"])
        profiles[record["name"]] = record
        self._write("profiles.json", "profiles", profiles)

    def _in_use(self, name):
        return any(route["profile"] == name for routes in self.bindings().values() for route in routes)

    def remove_profile(self, name):
        if self._in_use(name):
            raise CodedValueError("transport_profile_in_use", "the profile %s is bound to a partner: aamio transport unbind first" % name)
        profiles = self.profiles()
        if profiles.pop(name, None) is None:
            raise CodedLookupError("transport_profile_unknown", "no profile called %s" % name)
        self._write("profiles.json", "profiles", profiles)

    def bind(self, key, transport, profile):
        record = self.profile(profile)
        checked(record)
        if profile not in self.profiles():
            self.add_profile(record)
        bindings = self.bindings()
        routes = bindings.setdefault(key, [])
        if any(route["transport"] == transport for route in routes):
            raise CodedValueError("transport_already_bound", "%s is bound to that partner already" % transport)
        routes.append({"transport": transport, "profile": profile})
        self._write("bindings.json", "partners", bindings)
        return routes

    def unbind(self, key, transport=None):
        """The partner's bindings without transport, or none at all: what is left."""
        bindings = self.bindings()
        if key not in bindings or (transport is not None and not any(route["transport"] == transport for route in bindings[key])):
            raise CodedLookupError("transport_unbound", "that partner is not bound to %s" % (transport or "a transport"))
        routes = [route for route in bindings[key] if transport is not None and route["transport"] != transport]
        if routes:
            bindings[key] = routes
        else:
            bindings.pop(key, None)
        self._write("bindings.json", "partners", bindings)
        return routes

    def routes(self, key):
        return self.bindings().get(key, [])

    def state_path(self):
        return os.path.join(self.dir, "carry.json")


def body_of(runtime, content, sealed):
    """What read shows of carried content: the body over HTTPS has the same fields, text or data, re and seen."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return {"text": None}, {"signed": True, "encrypted": sealed, "format": "unreadable"}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"text": text}, {"signed": True, "encrypted": sealed, "format": "text"}
    if isinstance(parsed, dict):
        body, extra = runtime._canonical(parsed)
        return body, dict({"signed": True, "encrypted": sealed, "format": "json"}, **extra)
    return {"text": text}, {"signed": True, "encrypted": sealed, "format": "json"}


class Service:
    """The transports this owner runs, with one carrier each, and what goes in and out through them."""

    def __init__(self, runtime):
        self.runtime = runtime
        self.config = Config(runtime.home)
        self.lock = threading.RLock()
        self.state = None
        self.running = {}     # transport name -> {"manifest", "process", "carrier", "crashes", "next", "down"}
        self.thread = None
        self.stopping = threading.Event()
        self.stopped = False   # stop has been called: the service stops once, with its owner
        # Where a runtime with a listener wants what comes in, and what it was given and has not had taken.
        self.offer = None
        self.offered = set()
        # The environment a transport's variables are read from: os.environ, unless a test or an embedder says otherwise.
        self.environ = None
        self.known_at = 0.0

    # ------------------------------------------------------------ what is there

    def manifests(self):
        from . import addons

        return {module.NAME: module for module in addons.loaded(self.runtime.home) if isinstance(module, TransportManifest)}

    def carry(self):
        if self.state is None:
            self.state = carry_state.CarryState(self.runtime.keys, self.config.state_path())
        return self.state

    def bound(self):
        """Whether some partner in the address book is bound to a transport; transport_config_unreadable when that cannot be known."""
        return any(self.runtime.partner_by_key(key) is not None for key in self.config.bindings())

    def has_pending(self):
        """Whether something came over a transport and waits for a read, whatever is bound now: an unbind leaves it to be read."""
        if not os.path.exists(self.config.state_path()):
            return False
        with self.lock:
            return bool(self.carry().pending())

    def wanted(self):
        """Every transport a partner in the address book is bound to, in the order first named."""
        names = []
        for key, routes in self.config.bindings().items():
            if self.runtime.partner_by_key(key) is None:
                continue
            for route in routes:
                if route["transport"] not in names:
                    names.append(route["transport"])
        return names

    def known_for(self, transport):
        """The keys a transport takes messages from: partners in the address book bound to it, and no one who has left the book."""
        return [unb64url(key) for key, routes in self.config.bindings().items()
                if self.runtime.partner_by_key(key) is not None and any(route["transport"] == transport for route in routes)]

    def route_of(self, pk):
        routes = self.config.routes(b64url(pk))
        return routes[0] if routes else None

    def profile_for(self, pk):
        route = self.route_of(pk)
        return checked(self.config.profile(route["profile"] if route else DEFAULT_PROFILE))

    # ------------------------------------------------------------ running

    def start(self, background=True, offer=None):
        """Every transport that is bound and enabled, started; with background, pumped in a thread of its own.

        offer, for a runtime with a listener, is given each message that comes
        over a transport, once, in the read's own shape.
        """
        with self.lock:
            if self.stopped:
                # Stopped with its owner, and for good. A start that comes after, as from a read still under way in
                # another thread, starts nothing in a runtime that has let go of its home (the check of 16 November
                # 2026 found the same in aamio-js).
                return self
            if offer is not None:
                self.offer = offer
            self._add(self.wanted())
            self._start_due()
            if self.offer is not None:
                self._offer()
            # Under the lock with the rest, so stop either finds this thread or has stopped this start before it.
            if background and self.running and self.thread is None:
                self.thread = threading.Thread(target=self._loop, daemon=True)
                self.thread.start()
        return self

    def _add(self, names):
        """Transports to run, each once, with the manifests read only when one is new."""
        manifests = None
        for name in names:
            if name in self.running:
                continue
            manifests = self.manifests() if manifests is None else manifests
            self.running[name] = {"manifest": manifests.get(name), "process": None, "carrier": None, "crashes": [], "next": 0.0, "down": None}
            if manifests.get(name) is None:
                self.running[name]["down"] = "%s is bound to a partner and is not an enabled transport here: aamio addon enable %s" % (name, name)
                self.runtime.log("transport %s: %s" % (name, self.running[name]["down"]))

    def _say(self, name, text):
        """What a carrier has to tell the user, in attention under the transport's name: added to what waits there unread."""
        runtime = self.runtime
        note = getattr(runtime, "_note_trouble", None)
        if note is None:
            runtime.log("transport %s: %s" % (name, text))
            return
        with runtime.lock:
            earlier = (getattr(runtime, "attention", None) or {}).get((name, "not_sent_again"))
        note(name, "not_sent_again", text if earlier is None else "%s %s" % (earlier["what"], text))

    def _refresh(self):
        """Who each running carrier takes messages from, read again; a transport no partner is bound to any more is
        stopped, so it no longer holds its port, and one bound meanwhile is started (the follow-up check of 15 November)."""
        try:
            wanted = self.wanted()
        except RuntimeError as error:
            # Whom to take messages from is not known while the bindings cannot be read: no one, then, and nothing stopped.
            for name, entry in self.running.items():
                if entry["carrier"] is not None:
                    entry["carrier"].known = []
            self.runtime.log("transports: %s" % error)
            return
        for name in [name for name in self.running if name not in wanted]:
            entry = self.running.pop(name)
            if entry["process"] is not None:
                entry["process"].stop()
            self.runtime.log("transport %s: stopped, since no partner in the address book is bound to it any more" % name)
        self._add(wanted)
        for name, entry in self.running.items():
            if entry["carrier"] is not None:
                entry["carrier"].known = self.known_for(name)

    def _start_due(self):
        now = time.monotonic()
        for name, entry in self.running.items():
            if entry["carrier"] is not None or entry["manifest"] is None or entry["down"] is not None or now < entry["next"]:
                continue
            manifest = entry["manifest"]
            folder = working_folder(self.runtime.home, name)
            process = TransportProcess(name, manifest.__version__, process_command(manifest.start_module), folder,
                                       environment_for(manifest, folder, base=self.environ), log=self.runtime.log)
            try:
                process.start(CORE_VERSION, "python", folder)
                entry["carrier"] = Carrier(self.carry(), process, self.profile_for, self.known_for(name), log=self.runtime.log,
                                           note=lambda text, name=name: self._say(name, text))
                entry["process"] = process
                self.runtime.log("transport %s: up" % name)
            except (TransportFailed, OSError) as error:
                process.stop()
                self._crashed(name, error)
            except (CarryRefused, ValueError, LookupError, RuntimeError) as error:
                # Not the transport: the carrier state is closed after a write failed, or a profile cannot be read. It
                # stays down with the reason rather than start again every second.
                process.stop()
                entry["down"] = "%s. It stays down until that is put right and aamio starts again" % error
                self.runtime.log("transport %s: down: %s" % (name, entry["down"]))

    def _crashed(self, name, error):
        entry = self.running[name]
        if entry["process"] is not None:
            entry["process"].stop()
        entry["process"] = entry["carrier"] = None
        now = time.monotonic()
        entry["crashes"] = [at for at in entry["crashes"] if now - at < CRASH_WINDOW] + [now]
        if len(entry["crashes"]) >= CRASHES_MOST:
            entry["down"] = "it stopped %d times in %d minutes, last: %s. It stays down until aamio starts again" % (CRASHES_MOST, CRASH_WINDOW // 60, error)
            self.runtime.log("transport %s: down: %s" % (name, entry["down"]))
            return
        entry["next"] = now + RESTART_AFTER[len(entry["crashes"]) - 1]
        self.runtime.log("transport %s: down: %s, started again in %d seconds" % (name, error, RESTART_AFTER[len(entry["crashes"]) - 1]))

    def pump(self, timeout=0.02):
        """One round: every carrier pumped, transports that are due started again, and what came in offered."""
        with self.lock:
            if self.stopped:
                # The loop's thread may have waited for the lock while stop held it: no round after the stop, which
                # could add a transport and start it with nobody left to stop it.
                return
            now = time.monotonic()
            if now - self.known_at >= KNOWN_REFRESH:
                self.known_at = now
                self._refresh()
            for name, entry in list(self.running.items()):
                if entry["carrier"] is None:
                    continue
                try:
                    entry["carrier"].pump(timeout=timeout)
                except TransportFailed as failed:
                    self._crashed(name, failed)
            self._start_due()
            if self.offer is not None:
                self._offer()

    def _loop(self):
        while not self.stopping.is_set():
            try:
                self.pump()
            except Exception as error:
                # The state closed after a write that failed, or something else no carrier caught: said, and tried again.
                self.runtime.log("transports: %s: %s" % (error.__class__.__name__, error))
                self.stopping.wait(1.0)
                continue
            if not any(entry["carrier"] is not None for entry in self.running.values()):
                self.stopping.wait(0.2)

    def stop(self):
        # From here on nothing is added or started: a start that waited for the lock finds the service stopped.
        with self.lock:
            self.stopped = True
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)
            self.thread = None
        with self.lock:
            for entry in self.running.values():
                if entry["process"] is not None:
                    entry["process"].stop()
                entry["process"] = entry["carrier"] = None
            self.running.clear()

    def drain(self, seconds=1.0):
        """Before a stop: what the carriers have queued is given to the transports and answered, for a moment at most.

        A read on the command line that got a message returns at once, and
        the receipt for it was queued in the same round: stopped before it was
        written, it was withdrawn, and the sender heard nothing.
        """
        with self.lock:
            if not any(entry["carrier"] is not None for entry in self.running.values()):
                return
        self._wait(self._quiet, time.monotonic() + seconds)

    def _quiet(self):
        for entry in self.running.values():
            carrier = entry["carrier"]
            if carrier is not None and (carrier.queue or any(frame["status"] == "waiting" for frame in carrier.process.frames.values())):
                return False
        return True

    def status(self):
        with self.lock:
            return {name: ("up" if entry["carrier"] is not None else "down: " + (entry["down"] or "waiting to start again")) for name, entry in self.running.items()}

    def _carrier(self, name):
        """The carrier of a transport now, or None while it waits to start again; transport_down when it will not run here."""
        entry = self.running.get(name)
        if entry is None or entry["down"] is not None:
            why = (entry or {}).get("down") or "it is not running in this process"
            raise CodedRuntimeError("transport_down", "%s cannot carry the message now: %s. Nothing was sent." % (name, why))
        return entry["carrier"]

    # ------------------------------------------------------------ in and out

    def _wait(self, condition, until):
        """Until condition holds, read under the lock, or until: the thread pumps meanwhile, or this does when there is none."""
        while True:
            with self.lock:
                if condition():
                    return True
            if time.monotonic() >= until:
                return False
            if self.thread is not None and self.thread.is_alive():
                time.sleep(0.05)
            else:
                self.pump()

    def _session(self, carrier, pk):
        """The newest session of this party's that still has room in its lifetime, or None."""
        profile = self.profile_for(pk)
        return carrier.usable_session(pk, profile["lifetime"] - profile["challenge_window"])

    def send(self, pk, content, wait=WAIT_DEFAULT):
        """content to pk over its first transport, in an open session or in a new one: its mark, the sha256 of its
        envelope and how far it came, and for the trace its size and whether it went sealed.

        The sha256 is the one the partner's runtime reads it under and names as
        seen once it has read it.

        status is confirmed when the receipt came, handed_over when every frame
        of a try was given to the medium and no receipt came within wait,
        queued when the message waits in the outbox for room, and unknown when
        its tries are used without a receipt. A partner that gives no
        challenge within wait gets nothing: carry_not_sent.
        """
        route = self.route_of(pk)
        if route is None:
            raise CodedLookupError("transport_unbound", "that partner has no transport")
        name = route["transport"]
        until = time.monotonic() + wait
        self.start()
        asked = {"carrier": None}

        def open_session():
            # Under the lock. A carrier that started again after a crash knows nothing of the ask, so it asks again.
            carrier = self._carrier(name)
            if carrier is None:
                return False
            if self._session(carrier, pk) is not None:
                return True
            if asked["carrier"] is not carrier:
                carrier.open(pk)
                asked["carrier"] = carrier
            return False

        if not self._wait(open_session, until):
            raise CodedRuntimeError("carry_not_sent", "the partner did not answer on %s within %d seconds, so nothing was sent. Its aamio has to run on the same network, "
                                    "as aamio serve or aamio read --wait, with this key bound to %s" % (name, wait, name))
        with self.lock:
            carrier = self._carrier(name)
            try:
                key = carrier.send(pk, self._session(carrier, pk), content)
            except CarryRefused as refused:
                raise CodedValueError(refused.code, "%s. Nothing was sent." % refused) from None
            # What went, as the outbox keeps it: the envelope, and its sha256.
            written = self.carry().durable["outbox"][key]
            envelope = bytes.fromhex(written["envelope"])
        state = self.carry()
        self._wait(lambda: state.outcome(key) != "waiting", until)
        with self.lock:
            outcome = state.outcome(key)
            current = self.running.get(name, {}).get("carrier")
            handed = current is not None and current.handed_over(key)
        if outcome == "waiting":
            outcome = "handed_over" if handed else "queued"
        return {"via": name, "profile": route["profile"], "mark": key, "status": outcome, "sha256": written["sha256"],
                "bytes": len(envelope), "sealed": envelope[len(carry.MAGIC)] == carry.SEALED}

    def outbox(self):
        """What was sent over a transport, as aamio transport list shows it: mark and outcome, oldest first."""
        with self.lock:
            state = self.carry()
            return [{"mark": key, "outcome": state.outcome(key)} for key in state.durable["outbox"]]

    def entries(self, skip=()):
        """What came over a transport and the program has not taken, in read's shape and in the order it came.

        Each says the transport and profile its partner is bound to now, and
        whether it came sealed and when, as the state kept it then.
        """
        out = []
        with self.lock:
            state = self.carry()
            try:
                bindings = self.config.bindings()
            except CodedRuntimeError:
                bindings = {}
            for key, pk, _session, _counter, content in state.pending():
                if key in skip:
                    continue
                kept = state.kept(key)
                routes = bindings.get(b64url(pk)) or []
                route = routes[0] if routes else {"transport": UNBOUND_CHANNEL, "profile": None}
                partner = self.runtime.partner_by_key(b64url(pk))
                body, meta = body_of(self.runtime, content, kept["sealed"])
                entry = {"channel": route["transport"], "w": None, "seq": None, "at": kept["at"], "verified": True, "from_key": b64url(pk),
                         "known_contact": partner is not None, "sender": partner["name"] if partner else "unknown key", "sha256": kept["sha256"],
                         "replay": False, "body": body, "via": route["transport"], "profile": route["profile"], "mark": key}
                entry.update(meta)
                out.append(entry)
        return out

    def _offer(self):
        """In a runtime with a listener: what came over a transport and was not offered yet, given to it once."""
        for entry in self.entries(skip=self.offered):
            self.offered.add(entry["mark"])
            self.offer(entry)

    def taken(self, keys):
        """The program has these: the state keeps only their marks from now on."""
        with self.lock:
            state = self.carry()
            for key in keys:
                state.handed_over(key)
                self.offered.discard(key)


# ------------------------------------------------------------ the commands

def _partner(runtime, which):
    partner = runtime.partner_by_key(which) if is_key(str(which)) else runtime.partner_by_name(which)
    if partner is None:
        raise CodedValueError("unknown_partner", "unknown partner: %s. A transport carries messages between partners: aamio partner add NAME KEY first" % which)
    return partner


def listing(runtime):
    """aamio transport list: the transports enabled here, the profiles, which partner goes over which, and what was carried."""
    service = runtime.transport_service()
    config = service.config
    enabled = service.manifests()
    bindings = config.bindings()
    stored = config.profiles()
    rows = []
    for key, routes in bindings.items():
        partner = runtime.partner_by_key(key)
        rows.append({"partner": partner["name"] if partner else None, "key": key, "in_address_book": partner is not None, "routes": routes})
    transports = []
    for name, manifest in enabled.items():
        partners = [row["partner"] or row["key"] for row in rows if row["in_address_book"] and any(route["transport"] == name for route in row["routes"])]
        transports.append({"name": name, "version": manifest.__version__, "medium": manifest.medium, "permissions": list(manifest.permissions), "partners": partners})
    profiles = [dict(record, stored=True) for record in stored.values()]
    if DEFAULT_PROFILE not in stored:
        profiles.insert(0, dict(profile_record(DEFAULT_PROFILE), stored=False))
    answer = {"transports": transports, "profiles": profiles, "bindings": rows, "outbox": service.outbox(), "pending": len(service.carry().pending())}
    missing = sorted({route["transport"] for row in rows if row["in_address_book"] for route in row["routes"]} - set(enabled))
    if missing:
        answer["note"] = "%s %s bound to a partner and not enabled here: aamio addon enable %s." % (", ".join(missing), "is" if len(missing) == 1 else "are", missing[0])
    elif not transports:
        answer["note"] = "No transport is enabled here. A transport is an add-on: install one, as aamio-lan, and aamio addon enable lan."
    return answer


def profile_add(runtime, name, readable=False, lifetime=None, window=None, max_content=None):
    record = profile_record(name, mode="readable" if readable else "sealed",
                            lifetime=carry_state.LIFETIME_DEFAULT if lifetime is None else lifetime,
                            window=carry_state.CHALLENGE_WINDOW_DEFAULT if window is None else window,
                            max_content=carry.MAX_CONTENT if max_content is None else max_content)
    runtime.transport_service().config.add_profile(record)
    note = ("A readable profile signs and does not seal: everyone who hears the medium can read what goes under it. Bind it only where that is meant."
            if readable else "Sealed: only the partner can read what goes under it, and everyone who hears the medium sees that it goes and how big it is.")
    return {"profile": record, "note": note}


def profile_remove(runtime, name):
    runtime.transport_service().config.remove_profile(name)
    return {"removed": name}


def bind(runtime, which, transport, profile=None):
    partner = _partner(runtime, which)
    service = runtime.transport_service()
    if transport not in service.manifests():
        raise CodedLookupError("transport_unknown", "no enabled transport is called %s. aamio addon list shows what is installed, and aamio addon enable %s lets it run here" % (transport, transport))
    routes = service.config.bind(partner["key"], transport, profile or DEFAULT_PROFILE)
    return {"partner": partner["name"], "key": partner["key"], "routes": routes,
            "note": "Messages to %s go over %s from now on, and never over HTTPS instead, and %s takes messages from %s. %s binds your key to %s the same way. "
                    "Only the process that owns this home runs the transport: aamio serve, or aamio send and aamio read --wait while they run." % (
                        partner["name"], routes[0]["transport"], routes[0]["transport"], partner["name"], partner["name"], transport)}


def unbind(runtime, which, transport=None):
    partner = _partner(runtime, which)
    routes = runtime.transport_service().config.unbind(partner["key"], transport)
    return {"partner": partner["name"], "key": partner["key"], "routes": routes,
            "note": ("Messages to %s go over %s." % (partner["name"], routes[0]["transport"])) if routes else
                    ("Messages to %s go over HTTPS again. What came over a transport and was not read is still read." % partner["name"])}
