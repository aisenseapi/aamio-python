"""Transports for one home: profiles, bindings to partners, and the service the owner of the home runs (contract 3, B).

The home keeps, under transports/: profiles.json, the security profiles of B5;
bindings.json, for each partner's key an ordered list of a transport and a
profile; and carry.json, the carrier state of aamio-carry-v1-tilstand. The
address book, partners.json, is shared with aamio-php and the Node runtime and
is written again as {name, key} by partner add, so the bindings live here, by
the partner's key. A partner without a binding goes over HTTPS as before; a
partner with one goes over its transport only, and never over HTTPS instead.

Two files beside them are hints, and never stop a send: here.json, where each
transport said it is reached, for cards that say it; and addresses.json, where
each bound partner is reached on each transport, as the user gave it to bind
or as a fresh envelope from the partner showed it. They are files of their own
because a core of 0.7.0 refuses a binding with a field it does not know, and
the same home is read by all three runtimes, of any version.

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
from .transport_host import STOP_SECONDS, TransportFailed, TransportProcess, here_of

PROFILE_VERSION = 1
DEFAULT_PROFILE = "sealed"
RESTART_AFTER = (1, 5, 30)
CRASH_WINDOW, CRASHES_MOST = 600, 3
WAIT_DEFAULT = 30
# How long a start of a moment waits for a transport's first ready, to learn where it is reached (B2).
LEARN_SECONDS = 10
# How much of what a transport said of its medium, as status down, transport here passes on: its own words, kept short.
DOWN_SAID_MOST = 300
ADDRESS_FROM = ("you", "heard")
# The window a profile for a slow medium is told to give, at the least.
CHALLENGE_WINDOW_SLOW = 300
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
        try:
            self.drop_addresses(key, transport)
        except (CodedRuntimeError, OSError):
            pass  # a hint left for a partner no longer bound is never used: addresses are looked up by binding
        return routes

    def routes(self, key):
        return self.bindings().get(key, [])

    # ------------------------------------------------------------ hints

    def _read_hint(self, name, field):
        """A hint file's field, or {} when it is not there or cannot be read: where something is reached never stops a send."""
        try:
            return self._read(name, field)
        except CodedRuntimeError:
            return {}

    def here(self):
        """transport name -> {"medium", "here", "at", "version"}: where each transport said it is reached, the last time it
        said, and the version that said it. An empty here is a transport that said nothing of it: kept, so one whose medium
        has no addresses, as sound, is not started again for every card. version is None in a file without it."""
        found = {}
        for name, entry in self._read_hint("here.json", "transports").items():
            if (isinstance(entry, dict) and isinstance(entry.get("medium"), str) and type(entry.get("at")) is int
                    and here_of(entry.get("here"), entry["medium"]) is not None):
                version = entry.get("version") if isinstance(entry.get("version"), str) else None
                found[name] = {"medium": entry["medium"], "here": list(entry["here"]), "at": entry["at"], "version": version}
        return found

    def set_here(self, name, medium, here, at, version=None):
        with self.lock:
            known = self._read_hint("here.json", "transports")
            known[name] = {"medium": medium, "here": list(here), "at": int(at)}
            if version is not None:
                known[name]["version"] = version
            self._write_held("here.json", "transports", known)

    def addresses(self):
        """partner key -> transport -> {"address", "from", "at"}: where each bound partner is reached on each transport."""
        found = {}
        for key, by in self._read_hint("addresses.json", "partners").items():
            if not isinstance(by, dict):
                continue
            for transport, entry in by.items():
                if (isinstance(entry, dict) and isinstance(entry.get("address"), str) and entry.get("from") in ADDRESS_FROM
                        and type(entry.get("at")) is int and here_of([entry["address"]], entry["address"].split(":", 1)[0]) is not None):
                    found.setdefault(key, {})[transport] = {"address": entry["address"], "from": entry["from"], "at": entry["at"]}
        return found

    def set_address(self, key, transport, address, source, at):
        with self.lock:
            known = self._read_hint("addresses.json", "partners")
            by = known.get(key) if isinstance(known.get(key), dict) else {}
            by[transport] = {"address": address, "from": source, "at": int(at)}
            known[key] = by
            self._write_held("addresses.json", "partners", known)

    def drop_addresses(self, key, transport=None):
        with self.lock:
            known = self._read_hint("addresses.json", "partners")
            by = known.get(key)
            if not isinstance(by, dict):
                return
            if transport is None:
                known.pop(key)
            else:
                if transport not in by:
                    return
                by.pop(transport)
                if not by:
                    known.pop(key)
            self._write_held("addresses.json", "partners", known)

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
        # A start of a moment under way, by transport name: {"done": Event, "result": (here, how)}. One at a time per
        # transport, never beside its ordinary start, and none after the stop (a review of 20 November 2026).
        self.learning = {}
        # What a transport said of its medium the last time a start of a moment did not come up, by name: the reason
        # transport here gives. A transport says it as status down on the protocol, not on standard error, and here said
        # only that "the lines it wrote above" said why, with none written (a check of 22 November 2026).
        self.down_said = {}
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

    def _check_windows(self, name, carrier):
        """Say it when a partner's profile gives a challenge less time than this medium needs for it and its open.

        Over sound a challenge and its open take close to a minute in the air
        alone, and two with the waits for a turn, and the profile sealed gives 60
        seconds: most opens would come too late and be turned down, few sessions
        would open, and sends would end in carry_not_sent or without a receipt,
        with nothing to say why.
        """
        need = carrier.handshake_seconds()
        if need <= 0:
            return
        try:
            bindings = self.config.bindings()
        except CodedRuntimeError:
            return
        for key, routes in bindings.items():
            route = next((route for route in routes if route.get("transport") == name), None)
            partner = self.runtime.partner_by_key(key)
            if route is None or partner is None:
                continue
            try:
                window = checked(self.config.profile(route["profile"]))["challenge_window"]
            except (CodedRuntimeError, CodedValueError, KeyError):
                continue
            if window >= need:
                continue
            # Long enough for an open to have three tries, in whole minutes, as long as a profile can give at the most.
            longer = max(CHALLENGE_WINDOW_SLOW, int(-(-carrier.window_for_opens() // 60) * 60))
            note = getattr(self.runtime, "_note_trouble", None) or (lambda where, state, what: self.runtime.log("transport %s: %s" % (where, what)))
            longer = min(longer, 600)
            note(name, "window_too_short", "the profile %s gives a challenge %d seconds to be answered, and on %s a challenge and its open take up "
                            "to %d seconds in the air, more with the waits for a turn: most sessions with %s cannot open, and a send to %s "
                            "ends in carry_not_sent or gets no receipt. A window of %d seconds gives an open three tries: aamio transport "
                            "profile add %s-slow --window %d --lifetime 3600, then aamio transport unbind %s and aamio transport bind %s %s "
                            "--profile %s-slow" % (route["profile"], window, name, int(carrier.airtime_of_handshake()), partner["name"], partner["name"],
                                                   longer, route["profile"], longer, partner["name"], partner["name"], name, route["profile"]))

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

    def _attention(self, name, state, text):
        """What a carrier has to tell the user once, in attention under the transport's name and the state it gives, added
        to what waits there unread under the same state, and the log where there is no attention."""
        runtime = self.runtime
        note = getattr(runtime, "_note_trouble", None)
        if note is None:
            runtime.log("transport %s: %s" % (name, text))
            return
        with runtime.lock:
            earlier = (getattr(runtime, "attention", None) or {}).get((name, state))
        note(name, state, text if earlier is None or text in earlier["what"] else "%s %s" % (earlier["what"], text))

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
        addresses = self.config.addresses()
        for name, entry in self.running.items():
            if entry["carrier"] is not None:
                entry["carrier"].known = self.known_for(name)
                # Given to bind meanwhile, or learned by another owner of this home: what the home keeps is the newest.
                entry["carrier"].addresses.update(self._addresses_for(name, addresses))

    # ------------------------------------------------------------ where things are reached

    def _addresses_for(self, name, addresses=None):
        """partner pk -> where it is reached on the transport, as the home keeps it, for the partners bound to it: a hint
        left behind for one no longer bound, or no longer in the address book, is never used."""
        addresses = self.config.addresses() if addresses is None else addresses
        bound = {b64url(pk) for pk in self.known_for(name)}
        return {unb64url(key): by[name]["address"] for key, by in addresses.items() if name in by and key in bound}

    def _heard(self, name, pk, address):
        """A fresh envelope from the partner came from address: kept, so the next owner of the home asks there first."""
        try:
            self.config.set_address(b64url(pk), name, address, "heard", int(time.time()))
        except (CodedRuntimeError, OSError) as error:
            self.runtime.log("transport %s: where a partner was heard from could not be kept: %s" % (name, error))

    def _here(self, name, medium, here, version=None):
        """The transport said where it is reached, or said nothing of it (an empty list): kept for cards, as an add-on that
        needs here gets it, with the version that said it."""
        try:
            self.config.set_here(name, medium, here, int(time.time()), version)
        except (CodedRuntimeError, OSError) as error:
            self.runtime.log("transport %s: where it is reached could not be kept: %s" % (name, error))

    def _name_of(self, pk):
        partner = self.runtime.partner_by_key(b64url(pk))
        return partner["name"] if partner else "the key %s" % b64url(pk)[:8]

    def learn_here(self, name, seconds=LEARN_SECONDS):
        """Where an enabled transport is reached: (addresses or None, how it is known).

        The running one says it on its ready. One that does not run is started for
        a moment, as B2 allows for this alone, and stopped at its first ready:
        the ready says where it is reached, or that it says nothing of it.
        """
        manifest = self.manifests().get(name)
        if manifest is None:
            raise CodedLookupError("transport_unknown", "no enabled transport is called %s. aamio addon list shows what is installed, and aamio addon enable %s lets it run here" % (name, name))
        with self.lock:
            if self.stopped:
                # Its owner has let go of the home: nothing starts any more, not even for a moment. Two lookups that
                # overlapped a close started a transport after the next owner held the home (a review of
                # 20 November 2026).
                return None, "stopping"
            entry = self.running.get(name)
            process = entry["process"] if entry is not None else None
            if process is not None:
                # Never a second one beside it: the two would fight over the medium, as a port or a channel.
                return process.here, ("running" if process.readied else "starting")
            waiting = self.learning.get(name)
            mine = waiting is None
            if mine:
                waiting = self.learning[name] = {"done": threading.Event(), "result": (None, "not_ready")}
        if not mine:
            # One start of a moment per transport: a second lookup waits for the first one's answer, a failure
            # included. Only the first was told why the start failed, and the second heard not_ready (a review of
            # 21 November 2026).
            if waiting["done"].wait(seconds + STOP_SECONDS):
                failed = waiting.get("failure")
                if failed is not None:
                    raise failed.__class__(failed.error_code, str(failed))
                return waiting["result"]
            return None, "starting"
        failure = None
        try:
            waiting["result"] = self._learn_once(name, manifest, seconds, waiting)
        except (CodedRuntimeError, CodedLookupError) as error:
            failure = waiting["failure"] = error
        finally:
            with self.lock:
                self.learning.pop(name, None)
            waiting["done"].set()
        if failure is not None:
            raise failure
        return waiting["result"]

    def _learn_once(self, name, manifest, seconds, waiting):
        """The start of a moment itself, reserved by learn_here: started, asked, stopped, and kept unless stopped meanwhile.

        Its process is known to the service before it starts, so a stop can end it at any point (stop cancels it)."""
        folder = working_folder(self.runtime.home, name)
        process = TransportProcess(name, manifest.__version__, process_command(manifest.start_module), folder,
                                   environment_for(manifest, folder, base=self.environ), log=self.runtime.log)
        with self.lock:
            if self.stopped:
                return None, "stopping"
            waiting["process"] = process
        try:
            process.start(CORE_VERSION, "python", folder)
            until = time.monotonic() + seconds
            said = None
            while not process.readied and time.monotonic() < until and not self.stopping.is_set():
                for event in process.poll(timeout=0.1):
                    if event[0] == "status" and event[1] == "down" and isinstance(event[2], str) and event[2].strip():
                        said = event[2].strip()[:DOWN_SAID_MOST]
        except (TransportFailed, OSError) as error:
            if self.stopping.is_set():
                # Ended by the stop while it started, which is no failure of the transport.
                return None, "stopping"
            raise CodedRuntimeError("transport_down", "%s did not start to say where it is reached: %s" % (name, error)) from None
        finally:
            process.stop()
        with self.lock:
            if self.stopped:
                # Stopped while it started: an owner that has let go of the home writes nothing into it.
                return None, "stopping"
            if not process.readied:
                self.down_said[name] = said
                return None, "not_ready"
            self.down_said.pop(name, None)
            # Said nothing is kept too, as an empty list, so a transport over a medium without addresses is not started
            # again for every card: the microphone of a transport over sound opened each time (the review of
            # 19 November 2026).
            self._here(name, manifest.medium, process.here or [], manifest.__version__)
        return process.here, "learned"

    def here_for_addons(self):
        """What an add-on that needs here gets: each enabled transport's medium and where it is reached, as the running one
        says it, else as the home keeps it from this version of the transport, else learned now by a start of a moment, at
        most once per version. Never a partner's.

        A transport that says nothing of it is there with an empty list: the medium is this machine's, and it has no
        address on it, as sound or Bluetooth LE, so a card names the medium alone and says nothing is wrong. One that
        could not say now, as when its medium is off, is left out (the review of 19 November 2026)."""
        manifests = self.manifests()
        kept = self.config.here()
        out = []
        for name, manifest in manifests.items():
            with self.lock:
                entry = self.running.get(name)
                process = entry["process"] if entry is not None else None
                running = list(process.here or []) if process is not None and process.readied else None
            said = kept.get(name)
            if running is not None:
                here, at = running, int(time.time())
            elif said is not None and said["medium"] == manifest.medium and said["version"] in (None, manifest.__version__):
                here, at = said["here"], said["at"]
            else:
                try:
                    here, how = self.learn_here(name)
                except (CodedRuntimeError, CodedLookupError) as error:
                    self.runtime.log("transport %s: %s" % (name, error))
                    here, how = None, "failed"
                if how in ("learned", "running"):
                    # It said ready: what it said of where it is reached, or nothing, which is an empty list.
                    here = list(here or [])
                at = int(time.time())
            if here is not None:
                out.append({"transport": name, "medium": manifest.medium, "here": list(here), "at": at})
        return out

    def media_for_addons(self):
        """What an add-on that needs media gets: each enabled transport's name and medium, as its manifest says them,
        ordered by name. From the manifests alone, and nothing is started: a reader of a card asks only which media this
        machine has, and a transport over Bluetooth LE announces this machine as it starts (19 November 2026)."""
        return [{"transport": name, "medium": manifest.medium} for name, manifest in sorted(self.manifests().items())]

    def _start_due(self):
        now = time.monotonic()
        for name, entry in self.running.items():
            if entry["carrier"] is not None or entry["manifest"] is None or entry["down"] is not None or now < entry["next"]:
                continue
            if name in self.learning:
                # Started for a moment just now, to say where it is reached: the ordinary start waits for that one to end.
                continue
            manifest = entry["manifest"]
            folder = working_folder(self.runtime.home, name)
            process = TransportProcess(name, manifest.__version__, process_command(manifest.start_module), folder,
                                       environment_for(manifest, folder, base=self.environ), log=self.runtime.log)
            try:
                process.start(CORE_VERSION, "python", folder)
                entry["carrier"] = Carrier(self.carry(), process, self.profile_for, self.known_for(name), log=self.runtime.log,
                                           note=lambda text, name=name: self._say(name, text), addresses=self._addresses_for(name),
                                           heard=lambda pk, address, name=name: self._heard(name, pk, address), name_of=self._name_of,
                                           on_here=lambda here, name=name, medium=manifest.medium, version=manifest.__version__: self._here(name, medium, here, version),
                                           attention=lambda state, text, name=name: self._attention(name, state, text))
                entry["process"] = process
                self.runtime.log("transport %s: up" % name)
                self._check_windows(name, entry["carrier"])
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
            learning = list(self.learning.values())
        # A start of a moment under way is ended here, before its process begins or while it waits for describe, and its
        # process has ended when cancel returns: the home is let go of with no child of this owner left in it. The stop
        # waited six seconds for it, and such a start can wait ten for describe alone and five more for its stop (a
        # review of 21 November 2026). Any that registers after this finds the service stopped.
        for waiting in learning:
            process = waiting.get("process")
            if process is not None:
                process.cancel()
        for waiting in learning:
            waiting["done"].wait(STOP_SECONDS + 1)

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

    def send(self, pk, content, wait=WAIT_DEFAULT, stretch=False):
        """content to pk over its first transport, in an open session or in a new one: its mark, the sha256 of its
        envelope and how far it came, and for the trace its size and whether it went sealed.

        The sha256 is the one the partner's runtime reads it under and names as
        seen once it has read it.

        With stretch, the wait is as long as the medium needs as well, once its
        carrier is up and has said its rate: a session and a message over sound
        take minutes. waited says how long it was.

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
        began = time.monotonic()
        until = began + wait
        self.start()
        if stretch and self._wait(lambda: self._carrier(name) is not None, until):
            with self.lock:
                carrier = self._carrier(name)
                if carrier is not None:
                    until = max(until, began + carrier.patience(len(content)))
        asked = {"carrier": None}

        def open_session():
            # Under the lock. A carrier that started again after a crash knows nothing of the ask, so it asks again.
            carrier = self._carrier(name)
            if carrier is None:
                return False
            if self._session(carrier, pk) is not None:
                return True
            if asked["carrier"] is not carrier:
                # An ask under way, as one an earlier send made before it gave up, is answered all the same: a new one
                # beside it only adds frames, and on a half-duplex medium they take each other's turns.
                if not carrier.asking(pk):
                    carrier.open(pk)
                asked["carrier"] = carrier
            return False

        if not self._wait(open_session, until):
            hint = "" if stretch else self._not_sent_hint(name, pk, content, until - began)
            raise CodedRuntimeError("carry_not_sent", "the partner did not answer on %s within %d seconds, so nothing was sent.%s Its aamio has to be "
                                    "within reach of %s and running, as aamio serve or aamio read --wait, with this key bound to %s%s"
                                    % (name, int(until - began), hint, name, name, self._transport_said(name, began)))
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
                "bytes": len(envelope), "sealed": envelope[len(carry.MAGIC)] == carry.SEALED, "waited": int(until - began)}

    def _transport_said(self, name, since):
        """What the transport said of the latest frame it could not send since the send began, for carry_not_sent, or
        an empty string. It knows the medium: a Bluetooth address nobody answers on, a network that is down."""
        with self.lock:
            entry = self.running.get(name)
            process = entry["process"] if entry is not None else None
            said = process.last_error if process is not None else None
        if said is None or said[0] < since or not said[2]:
            return ""
        return ". %s said of the last frame it could not send: %s" % (name, said[2].rstrip("."))

    def _not_sent_hint(self, name, pk, content, waited):
        """What carry_not_sent adds when the wait was shorter than a send takes on the medium, as over MCP, where it is the
        work budget: the ask goes on in the background, and a send after its answer came uses the session it opened.
        Empty otherwise."""
        with self.lock:
            try:
                carrier = self._carrier(name)
            except CodedRuntimeError:
                return ""
            if carrier is None or waited >= carrier.patience(len(content)):
                return ""
            due = carrier.ask_due(pk)
        return "" if due is None else (" The ask for a session is still under way on %s, and its answer is due in about %d seconds: send again then, and that send "
                                       "uses the session it opens." % (name, max(5, int(due))))

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
    kept = config.here()
    addresses = config.addresses()
    rows = []
    for key, routes in bindings.items():
        partner = runtime.partner_by_key(key)
        row = {"partner": partner["name"] if partner else None, "key": key, "in_address_book": partner is not None, "routes": routes}
        reached = {transport: entry for transport, entry in addresses.get(key, {}).items() if any(route["transport"] == transport for route in routes)}
        if reached:
            # Where the partner is reached on each transport: given to bind ("you") or shown by a fresh envelope ("heard").
            row["addresses"] = reached
        rows.append(row)
    transports = []
    for name, manifest in enabled.items():
        partners = [row["partner"] or row["key"] for row in rows if row["in_address_book"] and any(route["transport"] == name for route in row["routes"])]
        item = {"name": name, "version": manifest.__version__, "medium": manifest.medium, "permissions": list(manifest.permissions), "partners": partners}
        said = kept.get(name)
        if said is not None and said["medium"] == manifest.medium:
            item["here"], item["here_at"] = said["here"], said["at"]
        else:
            item["here"] = None
            item["here_fix"] = "aamio transport here %s starts it for a moment and says where it is reached, for a card" % name
        transports.append(item)
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


def here(runtime, name):
    """aamio transport here NAME: where an enabled transport is reached, from the running one or a start of a moment."""
    service = runtime.transport_service()
    manifests = service.manifests()
    if name not in manifests:
        raise CodedLookupError("transport_unknown", "no enabled transport is called %s. aamio addon list shows what is installed, and aamio addon enable %s lets it run here" % (name, name))
    found, how = service.learn_here(name)
    medium = manifests[name].medium
    if how == "stopping":
        return {"transport": name, "medium": medium, "here": None,
                "note": "This runtime is letting go of the home, so %s was not started and nothing was learned. Ask again from the aamio that owns it now." % name}
    if how == "starting":
        return {"transport": name, "medium": medium, "here": None,
                "note": "%s is starting in this process and has not said it is ready yet: ask again in a moment." % name}
    if how == "not_ready":
        said = service.down_said.get(name)
        return {"transport": name, "medium": medium, "here": None,
                "note": "%s did not say it was ready within %d seconds, so nothing was learned. %s" % (
                    name, LEARN_SECONDS, "It said: %s" % said if said else
                    "It said nothing of why, as when its medium is off or another program holds it.")}
    if not found:
        # Nothing said and an empty list say the same: a card names the medium alone. found[0] below stopped on [] with
        # an IndexError (the Node port of 19 November 2026 found it).
        return {"transport": name, "medium": medium, "here": found,
                "note": "%s says nothing of where it is reached: a version from before here (contract 3, B3), or a medium without addresses. "
                        "A card can name the medium %s without an address." % (name, medium)}
    started = "It runs, and said so itself." if how == "running" else "It was started for a moment to say this, and stopped again."
    return {"transport": name, "medium": medium, "here": found,
            "note": "%s %s is kept in the home for cards: over MCP an Earshot card that names %s carries it by itself, and on the command line "
                    "aamio addon earshot card ADDRESS --via %s --key KEY does. A partner binds it with aamio transport bind NAME TRANSPORT --address %s."
                    % (started, ", ".join(found), medium, found[0], found[0])}


def bind(runtime, which, transport, profile=None, address=None):
    """A partner bound to a transport, or the address it is reached at there, for a partner bound to it already."""
    partner = _partner(runtime, which)
    service = runtime.transport_service()
    manifests = service.manifests()
    if transport not in manifests:
        raise CodedLookupError("transport_unknown", "no enabled transport is called %s. aamio addon list shows what is installed, and aamio addon enable %s lets it run here" % (transport, transport))
    medium = manifests[transport].medium
    if address is not None and here_of([address], medium) is None:
        raise CodedValueError("transport_address_invalid", "an address on %s is %s: and then where the partner is reached, as its card or aamio transport here on its machine "
                                                           "says it, at most 128 characters of printable ASCII without spaces" % (transport, medium))
    bound = next((route for route in service.config.routes(partner["key"]) if route["transport"] == transport), None)
    if bound is not None and (address is None or (profile is not None and profile != bound["profile"])):
        raise CodedValueError("transport_already_bound", "%s is bound to that partner already%s" % (
            transport, ", under the profile %s: aamio transport unbind first to bind it under another" % bound["profile"] if address is not None else
            ". With --address, bind says where the partner is reached on it"))
    routes = service.config.routes(partner["key"]) if bound is not None else service.config.bind(partner["key"], transport, profile or DEFAULT_PROFILE)
    answer = {"partner": partner["name"], "key": partner["key"], "routes": routes}
    if address is not None:
        service.config.set_address(partner["key"], transport, address, "you", int(time.time()))
        answer["address"] = address
    if bound is not None:
        answer["note"] = ("The first ask to %s on %s goes to %s from now on; when it stops answering there, every second ask goes to nobody in particular, "
                          "and a fresh envelope from %s moves the address to where it came from." % (partner["name"], transport, address, partner["name"]))
        return answer
    reached = (" The first ask goes to %s; when it stops answering there, every second ask goes to nobody in particular, and a fresh envelope from %s "
               "moves the address to where it came from." % (address, partner["name"])) if address is not None else ""
    answer["note"] = ("Messages to %s go over %s from now on, and never over HTTPS instead, and %s takes messages from %s.%s %s binds your key to %s the same way. "
                      "Only the process that owns this home runs the transport: aamio serve, or aamio send and aamio read --wait while they run." % (
                          partner["name"], routes[0]["transport"], routes[0]["transport"], partner["name"], reached, partner["name"], transport))
    return answer


def unbind(runtime, which, transport=None):
    partner = _partner(runtime, which)
    routes = runtime.transport_service().config.unbind(partner["key"], transport)
    return {"partner": partner["name"], "key": partner["key"], "routes": routes,
            "note": ("Messages to %s go over %s." % (partner["name"], routes[0]["transport"])) if routes else
                    ("Messages to %s go over HTTPS again. What came over a transport and was not read is still read." % partner["name"])}
