"""Add-ons on contract 2: a manifest the core reads without running the add-on, and a process of the add-on's own per call.

An add-on on contract 1 is a module loaded into this process with the runtime
in its hands (addons.py). On contract 2 the package carries aamio-addon.json,
which says what the add-on offers, and a module the core runs as a child
process for each call: one JSON request on its standard input, one JSON answer
on its standard output, and a deadline. The core keeps what is the core's: the
key, the home and its lock, the address book, the messages this process
verified, and the user's consent to the websites an add-on may read. The
add-on gets the call's arguments, a subject the core resolved to a key, and a
directory of its own, and a short list of environment variables rather than
the user's. It is not a sandbox: the process runs as the same user, with the
user's own file permissions, and reads what the user reads. What it gives is
that the core never sends the home's key, only the public key a call asks for,
that nothing an add-on answers changes state here, that an add-on that hangs
or crashes does not take the runtime with it, and that list and help run none
of the add-on's code: enable starts it once, before the choice is recorded, to
see that it answers as its manifest says. It is for add-ons the user trusts.

The manifest and the protocol are written up in the service repository under
docs/aamio-tillegg-kontrakt-2-2026-11-08.md and on https://aamio.at/docs/addons.
"""

import argparse
import base64
import collections
import errno
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

from . import __version__ as CORE_VERSION
from .crypto import key_hash
from .storage import HOME_ENCODING

MANIFEST_FILE = "aamio-addon.json"
KNOWN_CONTRACTS = (1, 2)
DEADLINE_DEFAULT = 30
DEADLINE_MAX = 120
PROBE_DEADLINE = 20
MAX_AT_ONCE = 2
MAX_PER_WINDOW = 20
WINDOW_SECONDS = 60.0
# The consent list lives beside the add-on's own directory, not in it: the
# add-on's process must not be able to widen what it may read.
HOSTS_SUFFIX = ".hosts.json"
HOST_COMMANDS = ("allow", "forget", "list")
# Commands of aamio addon itself, which no add-on may be called.
RESERVED = ("list", "enable", "disable", "run")
# The question a tool asks, under this name in inputRequests, for a website that is not on the user's list.
HOST_QUESTION = "aamio_addon_host"
# The most an answer may be, and the most standard error may carry: a process
# that streams past either is stopped while it runs, not read to the end.
MAX_ANSWER_BYTES = 1_000_000
MAX_STDERR_BYTES = 65_536
# How long a stopped process gets to go away before it is given up on.
STOP_WAIT = 5.0
# Names an add-on may not ask for in its environment list.
NEVER_PASSED = ("AAMIO_HOME", "AAMIO_ADDONS", "AAMIO_ADDON")
# What the process gets of the environment: what the interpreter, the path, a
# temporary directory, the locale, TLS roots and a proxy need, and nothing else.
# A token in the user's environment is not the add-on's to read, unless its
# manifest names it, and then aamio addon list says so before it is enabled.
ENVIRONMENT = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ",
    "PYTHONPATH", "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONNOUSERSITE", "VIRTUAL_ENV", "CONDA_PREFIX",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
)

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
# Names Windows takes for a device. An add-on's short name is the name of its
# list of websites and of its own directory in the home.
_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])")
_COMMAND = re.compile(r"[a-z][a-z0-9-]{0,31}")
_POSITIONAL = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_OPTION = re.compile(r"--[a-z][a-z0-9-]{0,31}")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_VARIABLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC = re.compile(r"[0-9]+")
_KEY = re.compile(r"[A-Za-z0-9_-]{43}")
_HASH = re.compile(r"[0-9a-f]{64}")


class AddonError(RuntimeError):
    """An add-on that cannot be used as one, with what to do about it."""


class Refused(Exception):
    """A call settled before the add-on's process starts: a bad argument, no such subject, a website the user has not agreed to."""

    def __init__(self, reason, fix, status="invalid"):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix
        self.status = status


def refusal(refused, **known):
    answer = {"status": refused.status, "reason": refused.reason, "fix": refused.fix}
    answer.update({field: value for field, value in known.items() if value is not None})
    return answer


# ------------------------------------------------------------------ manifest

def _editable(dist):
    """Whether pip installed the distribution editable (PEP 610, pip install -e): its files are then the installation's own metadata, and the package is in its source tree."""
    try:
        text = dist.read_text("direct_url.json")
    except Exception:
        return False
    if not text:
        return False
    try:
        info = json.loads(text)
    except ValueError:
        return False
    return isinstance(info, dict) and isinstance(info.get("dir_info"), dict) and info["dir_info"].get("editable") is True


def manifest_path(module, dist=None):
    """Where the add-on's manifest would be, found without importing anything, or None.

    The manifest sits in the top-level package the entry point names. An
    installed distribution lists its files, and the manifest is looked for
    there: a manifest the list does not have is not the distribution's. An
    editable install lists only the installation's own metadata, and a
    checkout named in AAMIO_ADDONS has no distribution; for both,
    importlib.util.find_spec on the top-level name locates the package without
    running it. A dotted module name is never given to find_spec: that would
    import the parent package. A single-file module cannot carry a manifest.
    """
    top = module.split(":")[0].split(".")[0]
    files = None
    if dist is not None:
        try:
            files = dist.files
        except Exception:
            files = None
    if files is not None:
        for entry in files:
            parts = entry.parts
            if len(parts) == 2 and parts[0] == top and parts[1] == MANIFEST_FILE:
                return str(entry.locate())
        if not _editable(dist):
            return None
    try:
        spec = importlib.util.find_spec(top)
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    path = os.path.join(list(spec.submodule_search_locations)[0], MANIFEST_FILE)
    return path if os.path.exists(path) else None


def read_manifest(module, distribution, fix, dist=None):
    """The add-on's manifest, read without importing it, or None for a package that has none and so is on contract 1."""
    name = module.split(":")[0]
    path = manifest_path(module, dist)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise AddonError("the add-on %s has a manifest, %s, that cannot be read: %s: %s. Reinstall it, or %s to go on without it." % (name, path, error.__class__.__name__, error, fix)) from None
    number = data.get("aamio_addon") if isinstance(data, dict) else None
    if number == 2:
        return Manifest(distribution, name, path, data, fix)
    raise AddonError("the add-on %s is written for contract %s of aamio's add-ons, and this aamio (%s) knows %s. Upgrade aamio, or install a version of the add-on for this one; %s goes on without it." % (name, json.dumps(number), CORE_VERSION, " and ".join(str(n) for n in KNOWN_CONTRACTS), fix))


class Manifest:
    """What a contract-2 add-on offers, as its manifest says it. It stands where a contract-1 module stands in the registry: NAME, __version__, TOOLS, and the four hooks."""

    CONTRACT = 2

    def __init__(self, distribution, module, path, data, fix):
        self.distribution = distribution
        self.module = module
        self.__name__ = module
        self.path = path
        self.fix = fix
        self.NAME = data.get("name")
        self.__version__ = data.get("version")
        process = data.get("process")
        self.process_module = process.get("python") if isinstance(process, dict) else None
        self.deadline = data.get("deadline_seconds", DEADLINE_DEFAULT)
        self.description = data.get("description")
        self.environment = data.get("environment") or []
        self.hosts = data.get("hosts")
        self.commands = data.get("commands") or {}
        self.tools_spec = data.get("tools") or []
        self._validate()
        self.TOOLS = [self._tool(spec) for spec in self.tools_spec]

    def _wrong(self, what):
        raise AddonError("%s cannot be used as an add-on: %s. Reinstall it, or %s to go on without it." % (self.module, what, self.fix))

    def _validate(self):
        if not isinstance(self.NAME, str) or _NAME.fullmatch(self.NAME) is None:
            self._wrong("its manifest has no name of 1 to 32 characters of a-z, 0-9, dash and underscore")
        if self.NAME in RESERVED:
            raise AddonError("%s cannot be called %s: that is a command of aamio addon itself. To go on without it: %s." % (self.module, self.NAME, self.fix))
        # On Windows a file of that name is the device: a list of websites written to nul.hosts.json is written nowhere.
        if _DEVICE.fullmatch(self.NAME) is not None:
            self._wrong("its manifest's name, %s, is one Windows keeps for a device, and it names the add-on's files in the home" % self.NAME)
        if not isinstance(self.__version__, str) or not self.__version__:
            self._wrong("its manifest has no version")
        if not isinstance(self.process_module, str) or _MODULE.fullmatch(self.process_module) is None:
            self._wrong("its manifest names no Python module to run under process.python")
        if not isinstance(self.deadline, int) or isinstance(self.deadline, bool) or not 1 <= self.deadline <= DEADLINE_MAX:
            self._wrong("deadline_seconds in its manifest is not a whole number from 1 to %d" % DEADLINE_MAX)
        if self.description is not None and not isinstance(self.description, str):
            self._wrong("description in its manifest is not text")
        if not isinstance(self.environment, list) or any(not isinstance(name, str) or _VARIABLE.fullmatch(name) is None for name in self.environment):
            self._wrong("environment in its manifest is not a list of variable names in A-Z, 0-9 and underscore")
        if any(name in NEVER_PASSED for name in self.environment):
            self._wrong("environment in its manifest asks for %s, which no add-on gets" % ", ".join(name for name in self.environment if name in NEVER_PASSED))
        if self.hosts is True:
            self.hosts = {}
        if self.hosts is not None and self.hosts is not False:
            if not isinstance(self.hosts, dict):
                self._wrong("hosts in its manifest is neither true nor an object")
            legacy = self.hosts.get("legacy_file")
            if legacy is not None and (not isinstance(legacy, str) or not legacy or os.path.basename(legacy) != legacy):
                self._wrong("hosts.legacy_file in its manifest is not a plain file name")
        else:
            self.hosts = None
        if not isinstance(self.commands, dict):
            self._wrong("commands in its manifest is not an object")
        for name, spec in self.commands.items():
            if not isinstance(name, str) or _COMMAND.fullmatch(name) is None:
                self._wrong("the command %r in its manifest is not a name of a-z, 0-9 and dashes" % (name,))
            if self.hosts is not None and name in HOST_COMMANDS:
                self._wrong("its manifest has a command %s, which aamio provides for an add-on with hosts" % name)
            if not isinstance(spec, dict):
                self._wrong("the command %s in its manifest is not an object" % name)
            if not isinstance(spec.get("help", ""), str):
                self._wrong("the help of the command %s is not text" % name)
            if not isinstance(spec.get("runtime", True), bool):
                self._wrong("runtime on the command %s is not true or false" % name)
            needs = spec.get("needs", [])
            if not isinstance(needs, list) or any(need != "own_key" for need in needs):
                self._wrong("needs on the command %s names something other than own_key" % name)
            if needs and spec.get("runtime", True) is False:
                self._wrong("the command %s needs own_key and says it runs without a runtime" % name)
            self._check_arguments(name, spec)
        if not isinstance(self.tools_spec, list):
            self._wrong("tools in its manifest is not a list")
        seen = set()
        for spec in self.tools_spec:
            if not isinstance(spec, dict) or not isinstance(spec.get("name"), str) or not spec["name"]:
                self._wrong("a tool of its has no name")
            if spec["name"] in seen:
                self._wrong("its manifest has two tools called %s" % spec["name"])
            seen.add(spec["name"])
            if not isinstance(spec.get("description"), str) or not spec["description"]:
                self._wrong("the tool %s has no description" % spec["name"])
            schema = spec.get("inputSchema")
            if not isinstance(schema, dict) or schema.get("type") != "object" or not isinstance(schema.get("properties", {}), dict):
                self._wrong("the tool %s has no inputSchema of type object" % spec["name"])
            fields = set(schema.get("properties", {}))
            if "oneOf" in schema or "anyOf" in schema:
                self._wrong("the tool %s has oneOf or anyOf at the top of its schema, which hosts refuse" % spec["name"])
            host = spec.get("host")
            if host is not None and (not isinstance(host, str) or host not in fields):
                self._wrong("host on the tool %s names no field of its schema" % spec["name"])
            if host is not None and self.hosts is None:
                self._wrong("the tool %s has a host field, and the manifest has no hosts" % spec["name"])
            subject = spec.get("subject")
            if subject is not None:
                if not isinstance(subject, dict) or not subject or any(role not in ("partner", "message") or not isinstance(field, str) or field not in fields for role, field in subject.items()):
                    self._wrong("subject on the tool %s is not an object of partner or message to a field of its schema" % spec["name"])
            needs = spec.get("needs", [])
            if not isinstance(needs, list) or any(need != "own_key" for need in needs):
                self._wrong("needs on the tool %s names something other than own_key" % spec["name"])
            if spec.get("annotations") is not None and not isinstance(spec["annotations"], dict):
                self._wrong("annotations on the tool %s is not an object" % spec["name"])

    def _check_arguments(self, command, spec):
        arguments = spec.get("arguments", [])
        if not isinstance(arguments, list):
            self._wrong("the arguments of the command %s are not a list" % command)
        hosts = subjects = 0
        dests = set()
        for argument in arguments:
            if not isinstance(argument, dict) or not isinstance(argument.get("name"), str):
                self._wrong("an argument of the command %s has no name" % command)
            name = argument["name"]
            if name.startswith("-"):
                if _OPTION.fullmatch(name) is None:
                    self._wrong("the option %s of the command %s is not --name in a-z, 0-9 and dashes" % (name, command))
            elif _POSITIONAL.fullmatch(name) is None:
                self._wrong("the argument %s of the command %s is not a name in a-z, 0-9, dash and underscore" % (name, command))
            elif argument.get("required") is not None:
                self._wrong("the argument %s of the command %s is positional, and required is for options" % (name, command))
            dest = _dest(name)
            if dest in dests or dest == self.NAME + "_command":
                self._wrong("the command %s has two arguments that would be called %s" % (command, dest))
            dests.add(dest)
            if not isinstance(argument.get("help", ""), str) or not isinstance(argument.get("required", False), bool) or not isinstance(argument.get("host", False), bool):
                self._wrong("the argument %s of the command %s has help, required or host of the wrong kind" % (name, command))
            if argument.get("host"):
                hosts += 1
                if self.hosts is None:
                    self._wrong("the argument %s of the command %s is a host, and the manifest has no hosts" % (name, command))
                if spec.get("runtime", True) is False:
                    self._wrong("the argument %s of the command %s is a host, which needs the runtime the command says it does without" % (name, command))
            if argument.get("subject") is not None:
                subjects += 1
                if argument["subject"] not in ("partner", "message"):
                    self._wrong("subject on the argument %s of the command %s is neither partner nor message" % (name, command))
                if spec.get("runtime", True) is False:
                    self._wrong("the argument %s of the command %s is a subject, which needs the runtime the command says it does without" % (name, command))
        if hosts > 1 or subjects > 1:
            self._wrong("the command %s has more than one host or more than one subject argument" % command)

    @staticmethod
    def _tool(spec):
        tool = {"name": spec["name"], "description": spec["description"], "inputSchema": spec["inputSchema"]}
        annotations = spec.get("annotations")
        if annotations is not None:
            tool["annotations"] = annotations
        return tool

    # The four hooks, as the registry, the command line and the MCP server call them on a contract-1 module.

    def add_commands(self, parser):
        add_commands(self, parser)

    def early(self, args):
        return early(self, args)

    def command(self, args, runtime):
        return command(self, args, runtime)

    def dispatch(self, runtime, name, arguments, ask):
        return dispatch(self, runtime, name, arguments, ask)


def _dest(name):
    return name.lstrip("-").replace("-", "_")


# -------------------------------------------------------------------- hosts

def normalise_host(value):
    """The exact host a list is read from, in lowercase, or Refused.

    Plain ASCII names of two labels or more. No port, path, IP literal, trailing
    dot, underscore or space is trimmed into shape: anything but a host name is
    refused. www.example.org and example.org are different places.
    """
    refused = Refused("invalid_host", "A website is a plain host name of two labels or more, as example.org, with no https://, port or path. www.example.org and example.org are different places. Internationalised names are not read yet.")
    if not isinstance(value, str) or not value.isascii():
        raise refused
    host = value.lower()
    labels = host.split(".")
    if not 1 <= len(host) <= 253 or len(labels) < 2:
        raise refused
    if any(_LABEL.fullmatch(label) is None or label.startswith("xn--") for label in labels):
        raise refused
    if _NUMERIC.fullmatch(labels[-1]):
        raise refused
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise refused


def is_same_host(typed, host):
    try:
        return normalise_host(typed) == host
    except Refused:
        return False


def _hosts_dir(runtime):
    return os.path.join(runtime.home, "addons")


def hosts_file(runtime, manifest):
    return os.path.join(_hosts_dir(runtime), manifest.NAME + HOSTS_SUFFIX)


def _unreadable(path, manifest):
    return Refused("hosts_unreadable", "%s could not be read as a list of websites, so no website is read. Repair the file, or move it away and add the websites again with aamio addon %s allow." % (path, manifest.NAME))


def _read_hosts(path, manifest):
    try:
        with open(path, "rb") as handle:
            rows = json.loads(handle.read().decode(HOME_ENCODING))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise _unreadable(path, manifest) from None
    if not isinstance(rows, list):
        raise _unreadable(path, manifest)
    for row in rows:
        try:
            if normalise_host(row) != row:
                raise _unreadable(path, manifest)
        except Refused:
            raise _unreadable(path, manifest) from None
    return rows


def _write_hosts(runtime, manifest, rows):
    folder = _hosts_dir(runtime)
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        with runtime.lock:
            runtime.save_json(os.path.join("addons", manifest.NAME + HOSTS_SUFFIX), rows)
    except OSError:
        raise Refused("hosts_unwritable", "%s could not be written, so the list is as it was. Check the disk and the home's permissions." % hosts_file(runtime, manifest)) from None


def allowed_hosts(runtime, manifest):
    """The websites the user has agreed to for this add-on, from the file as it is now. A file that cannot be read is Refused, never an empty list.

    When the list does not exist yet and the manifest names a file an earlier
    version kept in the home, that file is read once and becomes the list, so
    the user who allowed websites before finds them again.
    """
    path = hosts_file(runtime, manifest)
    with runtime.lock:
        rows = _read_hosts(path, manifest)
    if rows is not None:
        return rows
    legacy = (manifest.hosts or {}).get("legacy_file")
    if legacy:
        old = os.path.join(runtime.home, legacy)
        with runtime.lock:
            rows = _read_hosts(old, manifest)
        if rows:
            _write_hosts(runtime, manifest, rows)
            return rows
    return []


def allow_host(runtime, manifest, value):
    host = normalise_host(value)
    rows = allowed_hosts(runtime, manifest)
    added = host not in rows
    if added:
        _write_hosts(runtime, manifest, rows + [host])
    return {"host": host, "added": added, "hosts": rows + [host] if added else rows}


def forget_host(runtime, manifest, value):
    host = normalise_host(value)
    rows = allowed_hosts(runtime, manifest)
    removed = host in rows
    if removed:
        _write_hosts(runtime, manifest, [row for row in rows if row != host])
    return {"host": host, "removed": removed, "hosts": [row for row in rows if row != host]}


def not_allowed(manifest, host):
    tool = next((spec["name"] for spec in manifest.tools_spec if spec.get("host")), None)
    over = " Over MCP %s asks them." % tool if tool else ""
    return Refused("host_not_allowed", "This runtime reads only websites the user has put on its list, and this one is not there. The user adds it with aamio addon %s allow %s, from their own records and never from the message being checked.%s" % (manifest.NAME, host, over))


# ------------------------------------------------------------------ subject

def subject_for(runtime, source, value):
    """The key to check and where it came from, resolved by the core: a partner in the address book, or the signer of a message this process verified."""
    if source == "partner":
        if not isinstance(value, str) or not value:
            raise Refused("invalid_partner", "partner is a name in the address book.")
        with runtime.lock:
            row = runtime.partner_by_name(value)
            if row is None or not isinstance(row.get("key"), str) or _KEY.fullmatch(row["key"]) is None:
                raise Refused("partner_unavailable", "No partner by that name with a usable key is in the address book. aamio_partners or aamio partner list shows who is.")
            key, label = row["key"], row["name"]
        return {"key": key, "subject_source": "partner", "partner": label, "signature_checked_locally": None}
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise Refused("invalid_message_hash", "message is the sha256 of a message as read shows it: 64 lowercase hexadecimal characters.")
    keys = runtime.verified_signers(value)
    if any(not isinstance(key, str) or _KEY.fullmatch(key) is None for key in keys):
        raise Refused("invalid_local_observation", "The message is recorded here without a usable signing key, so it cannot be checked.")
    if not keys:
        raise Refused("source_unavailable", "This process holds no verified message with that hash. Only a message this process read itself and whose signature checked out can be used: an unsigned one has no key to check, and what an earlier process read is not kept and cannot be read again. Check a later message from the same sender, or the partner by name.")
    if len(keys) != 1:
        raise Refused("ambiguous_signer", "Different keys signed the same bytes, so the hash does not say which one to check. Check the partner by name.")
    return {"key": keys[0], "subject_source": "message", "message_sha256": value, "signature_checked_locally": True}


def _subject_fields(subject):
    return {field: value for field, value in subject.items() if field != "key"}


# ------------------------------------------------------------------ process

class _Limits:
    """At most so many calls of one add-on at once, and so many started per minute: a process per call is a cost, and a model can loop."""

    def __init__(self):
        self.lock = threading.Lock()
        self.at_once = 0
        self.started = collections.deque()

    def take(self, clock=time.monotonic):
        with self.lock:
            now = clock()
            while self.started and now - self.started[0] > WINDOW_SECONDS:
                self.started.popleft()
            if self.at_once >= MAX_AT_ONCE:
                return "addon_busy"
            if len(self.started) >= MAX_PER_WINDOW:
                return "addon_rate"
            self.at_once += 1
            self.started.append(now)
            return None

    def give_back(self):
        with self.lock:
            self.at_once = max(0, self.at_once - 1)


_limits = {}
_limits_lock = threading.Lock()


def limits_of(name):
    with _limits_lock:
        if name not in _limits:
            _limits[name] = _Limits()
        return _limits[name]


def _failure(manifest, reason, fix):
    return {"result": {"status": "unreachable", "reason": reason, "fix": fix, "addon": manifest.NAME}, "exit_code": 5, "is_error": True}


def run(manifest, kind, name, arguments, subject=None, own_key=None, state_dir=None, stderr=None, deadline=None, declared=True):
    """One call to the add-on's process: the request on its standard input, its answer from standard output, within the deadline.

    stderr is a callable given what the process wrote to standard error, or None
    to drop it. declared False keeps the variables the manifest asks for out of
    the environment: the probe at enable runs so, before the user has seen the
    names in aamio addon list. The answer is always a dict with result or raw,
    exit_code and is_error; a process that cannot be started, answers nothing
    this aamio can read or runs past the deadline becomes an unreachable result
    with the reason, and the deadline kills it.
    """
    deadline = manifest.deadline if deadline is None else deadline
    request = {
        "aamio_addon": 2,
        "kind": kind,
        "name": name,
        "arguments": arguments,
        "subject": subject,
        "own_key": own_key,
        "state_dir": state_dir,
        "deadline_seconds": deadline,
        "aamio": {"version": CORE_VERSION, "runtime": "python"},
    }
    # What the process gets of the environment: the short list, and what its
    # manifest declared it reads, when set and when this is a call and not the
    # probe at enable. Never the home or the user's rest.
    env = {key: value for key, value in os.environ.items() if key.upper() in ENVIRONMENT or (declared and key in manifest.environment)}
    env["AAMIO_ADDON"] = "2"
    stop = "Reinstall it, or aamio addon disable %s to go on without it." % manifest.NAME
    # The request, the answer and standard error go through files in a directory
    # of this call's own, private from the start: a pipe would block a request
    # the process does not read, and the files' sizes are watched while it runs.
    with tempfile.TemporaryDirectory(prefix="aamio-addon-", ignore_cleanup_errors=True) as folder:
        paths = {kind_: os.path.join(folder, kind_) for kind_ in ("in", "out", "err")}
        with open(paths["in"], "wb") as handle:
            handle.write(json.dumps(request).encode("utf-8"))
        with open(paths["in"], "rb") as stdin, open(paths["out"], "wb") as stdout, open(paths["err"], "wb") as stderr_file:
            try:
                child = subprocess.Popen([sys.executable, "-m", manifest.process_module], stdin=stdin, stdout=stdout, stderr=stderr_file, env=env)
            except OSError as error:
                return _failure(manifest, "addon_failed", "the process of the add-on %s could not be started: %s. %s" % (manifest.NAME, error, stop))
            until = time.monotonic() + deadline
            stopped = None
            while child.poll() is None:
                if os.path.getsize(paths["out"]) > MAX_ANSWER_BYTES:
                    stopped = ("addon_failed", "the add-on %s wrote more than the %d bytes an answer may be, and was stopped. %s" % (manifest.NAME, MAX_ANSWER_BYTES, stop))
                elif os.path.getsize(paths["err"]) > MAX_STDERR_BYTES:
                    stopped = ("addon_failed", "the add-on %s wrote more than %d bytes to standard error, and was stopped. %s" % (manifest.NAME, MAX_STDERR_BYTES, stop))
                elif time.monotonic() > until:
                    stopped = ("addon_timeout", "the add-on %s did not answer within %d seconds and was stopped. Nothing else here was affected. Try again, or run the command by hand to see what it does." % (manifest.NAME, deadline))
                if stopped is not None:
                    _stop(child)
                    break
                time.sleep(0.02)
        if stopped is not None:
            return _failure(manifest, *stopped)
        with open(paths["out"], "rb") as handle:
            out = handle.read(MAX_ANSWER_BYTES + 1)
        with open(paths["err"], "rb") as handle:
            err = handle.read(MAX_STDERR_BYTES + 1)
    # The same limits whether the process was slow or had exited before the
    # next look: past either, the answer is refused and nothing is relayed.
    if len(out) > MAX_ANSWER_BYTES:
        return _failure(manifest, "addon_failed", "the add-on %s answered with more than the %d bytes an answer may be. %s" % (manifest.NAME, MAX_ANSWER_BYTES, stop))
    if len(err) > MAX_STDERR_BYTES:
        return _failure(manifest, "addon_failed", "the add-on %s wrote more than %d bytes to standard error. %s" % (manifest.NAME, MAX_STDERR_BYTES, stop))
    text = err.decode("utf-8", "replace")
    if stderr is not None and text:
        stderr(text)
    try:
        answer = json.loads(out.decode("utf-8"))
        if not isinstance(answer, dict):
            raise ValueError("not an object")
    except ValueError:
        said = text.strip().splitlines()
        return _failure(manifest, "addon_failed", "the add-on %s exited with code %s and gave no answer this aamio can read%s. %s" % (manifest.NAME, child.returncode, (": " + said[-1][:200]) if said else "", stop))
    code = answer.get("exit_code", 0 if child.returncode == 0 else child.returncode)
    if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255:
        code = 1
    is_error = answer.get("is_error", code != 0)
    normal = {"exit_code": code, "is_error": bool(is_error)}
    if isinstance(answer.get("raw"), str):
        try:
            normal["raw"] = base64.b64decode(answer["raw"], validate=True)
        except (ValueError, TypeError):
            return _failure(manifest, "addon_failed", "the add-on %s answered with raw bytes that are not base64. %s" % (manifest.NAME, stop))
    else:
        normal["result"] = answer.get("result")
    if isinstance(answer.get("stderr"), str) and answer["stderr"] and stderr is not None:
        stderr(answer["stderr"] if answer["stderr"].endswith("\n") else answer["stderr"] + "\n")
    return normal


def _stop(child):
    """Kill the process and give it a moment to go away, so the files it holds can be removed; after that it is left to the system."""
    child.kill()
    try:
        child.wait(timeout=STOP_WAIT)
    except subprocess.TimeoutExpired:
        pass


def probe(manifest):
    """What enable asks before anything is recorded: the process starts, speaks the protocol, and is the add-on the manifest says.

    It runs with the short list of environment variables and none the manifest
    asks for: the user sees those names in aamio addon list before anything of
    the add-on has run, and the first call is what gets them.
    """
    answer = run(manifest, "probe", "probe", {}, deadline=min(manifest.deadline, PROBE_DEADLINE), declared=False)
    said = answer.get("result")
    if not isinstance(said, dict) or said.get("ok") is not True:
        reason = said.get("reason") if isinstance(said, dict) else None
        detail = said.get("fix") if isinstance(said, dict) and reason in ("addon_timeout", "addon_failed") else "it answered %s" % json.dumps(said)[:200]
        raise AddonError("the add-on %s did not answer the probe: %s" % (manifest.NAME, detail))
    if said.get("aamio_addon") != 2 or said.get("name") != manifest.NAME or said.get("version") != manifest.__version__:
        raise AddonError("the add-on %s answered the probe as %s %s on contract %s, and its manifest says %s %s on contract 2. Reinstall it, or %s to go on without it." % (manifest.NAME, said.get("name"), said.get("version"), said.get("aamio_addon"), manifest.NAME, manifest.__version__, manifest.fix))


def enable_note(distribution, environment, probed=True):
    """What enable says of an add-on on contract 2: the same words as aamio-php and https://aamio.at/docs/addons.

    probed is whether the probe ran now; it does not for an add-on that was enabled already.
    """
    asked = (", and %s, which its manifest asks for" % ", ".join(environment)) if environment else ""
    ran = ("enable started it once just now, before the choice was recorded, to see that it answers as its manifest says." if probed
           else "It was enabled already, and nothing of it ran now.")
    return ("%s runs here from now on, in a process of its own for each call. %s "
            "A call gets its arguments, a key aamio resolved for it, the runtime's public key where a "
            "command asks for it, a directory of its own under the home, and a short list of environment variables: the path, a temporary directory, "
            "the locale, the interpreter's own settings, TLS roots and the proxy variables, which can carry credentials of their own%s, and never the "
            "home's key or the rest of your environment. Nothing it answers changes state in aamio. It runs with your own file permissions." % (distribution, ran, asked))


def state_dir(runtime, manifest):
    """A directory of the add-on's own under the home, made on first use, private to the user."""
    path = os.path.join(runtime.home, "addons", manifest.NAME)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _own_directory(runtime, manifest):
    """The add-on's own directory for this call, or the answer that says it could not be made.

    A home whose disk is full, or with a file in the way of addons/, stops the
    call before the process starts, as an answer like any other. It was an
    error out of the core: a traceback on the command line (a check of 12
    November 2026, found while the Node runtime's add-ons were built).
    """
    try:
        return state_dir(runtime, manifest), None
    except OSError as error:
        why = errno.errorcode.get(error.errno, error.__class__.__name__)
        return None, _failure(manifest, "addon_failed", "the add-on %s has no directory of its own: addons/%s in the home could not be made (%s). Nothing of the add-on ran. Check the disk and the home's permissions." % (manifest.NAME, manifest.NAME, why))


# ------------------------------------------------------------- the command line

def add_commands(manifest, parser):
    if manifest.description:
        parser.description = manifest.description
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
    sub = parser.add_subparsers(dest=manifest.NAME + "_command", required=True)
    for name, spec in manifest.commands.items():
        one = sub.add_parser(name, help=spec.get("help"))
        for argument in spec.get("arguments", []):
            if argument["name"].startswith("-"):
                one.add_argument(argument["name"], help=argument.get("help"), required=bool(argument.get("required")), default=None)
            else:
                one.add_argument(argument["name"], help=argument.get("help"))
    if manifest.hosts is not None:
        sub.add_parser("allow", help="put a website on this runtime's list, from your own records").add_argument("host", help="the host name, as example.org")
        sub.add_parser("forget", help="take a website off the list").add_argument("host")
        sub.add_parser("list", help="the websites this runtime may read for this add-on")


def _chosen(manifest, args):
    return getattr(args, manifest.NAME + "_command")


def early(manifest, args):
    """A command that runs without a home: the process is started all the same, with no state directory."""
    name = _chosen(manifest, args)
    spec = manifest.commands.get(name)
    if spec is None or spec.get("runtime", True):
        return None
    return _run_command(manifest, name, spec, args, None)


def command(manifest, args, runtime):
    from .cli import out

    name = _chosen(manifest, args)
    if manifest.hosts is not None and name in HOST_COMMANDS:
        try:
            if name == "allow":
                out(dict(allow_host(runtime, manifest, args.host), note="This runtime may now read this website for the add-on %s when a call asks for it. Nothing was read now." % manifest.NAME))
            elif name == "forget":
                out(forget_host(runtime, manifest, args.host))
            else:
                out({"hosts": allowed_hosts(runtime, manifest)})
        except Refused as refused:
            out(refusal(refused))
            return 2
        return 0
    return _run_command(manifest, name, manifest.commands[name], args, runtime)


def _run_command(manifest, name, spec, args, runtime):
    from .cli import out

    arguments = {}
    for argument in spec.get("arguments", []):
        arguments[_dest(argument["name"])] = getattr(args, _dest(argument["name"]), None)
    subject = own_key = None
    host = None
    try:
        for argument in spec.get("arguments", []):
            dest = _dest(argument["name"])
            if argument.get("host") and arguments[dest] is not None:
                host = arguments[dest] = normalise_host(arguments[dest])
                if host not in allowed_hosts(runtime, manifest):
                    raise not_allowed(manifest, host)
            if argument.get("subject") and arguments[dest] is not None:
                subject = subject_for(runtime, argument["subject"], arguments[dest])
        if "own_key" in spec.get("needs", []):
            own_key = runtime.keys.public
    except Refused as refused:
        out(refusal(refused, host=host, **(_subject_fields(subject) if subject else {})))
        return 2
    directory, no_directory = _own_directory(runtime, manifest) if runtime is not None else (None, None)
    if no_directory is not None:
        out(no_directory["result"])
        return no_directory["exit_code"]
    limits = limits_of(manifest.NAME)
    busy = limits.take()
    if busy is not None:
        out(refusal(Refused(busy, "At most %d calls of the add-on %s run at once and %d start per minute here. Nothing was done. Try again shortly." % (MAX_AT_ONCE, manifest.NAME, MAX_PER_WINDOW), status="unreachable"), host=host))
        return 5
    try:
        answer = run(manifest, "command", name, arguments, subject, own_key, directory, stderr=lambda text: (sys.stderr.write(text), sys.stderr.flush()))
    finally:
        limits.give_back()
    if "raw" in answer:
        # The bytes as they are: print would turn a line break into CRLF on Windows.
        sys.stdout.flush()
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is None:
            sys.stdout.write(answer["raw"].decode("utf-8", "replace"))
        else:
            buffer.write(answer["raw"])
            buffer.flush()
    elif answer.get("result") is not None:
        out(answer["result"])
    return answer["exit_code"]


# --------------------------------------------------------------------- MCP

def host_question(manifest, subject):
    """The form for a website that is not on the user's list. The user types the domain, and is not shown the one asked for.

    A lookalike reads as right when it is put in front of someone, and a form that
    offered it could be answered with one click. So the domain the agent asked
    for is not in the form: what the user types has to match it, or nothing is
    read. Who is being checked is said in words this runtime holds, a name from
    the address book or a key's hash, and nothing a message wrote is in the text.
    """
    if subject is None:
        who = "what the add-on %s was asked about" % manifest.NAME
    elif subject["subject_source"] == "partner":
        who = "your partner %s" % subject["partner"]
    else:
        who = "the key that signed a message (hash %s)" % key_hash(subject["key"])[:8]
    return {
        "message": "Your agent asks to read a website, through the add-on %s, about %s. Which website do you expect? "
                   "Type the domain from your own records, such as a contract or an earlier exchange, and not from a message: anyone can publish what they like on their own site. "
                   "What you type has to match what your agent asked for, or nothing is read. A match stays on this runtime's list of websites it may read for %s until you run aamio addon %s forget." % (manifest.NAME, who, manifest.NAME, manifest.NAME),
        "requestedSchema": {"type": "object", "properties": {"domain": {"type": "string", "title": "Website domain", "description": "the host name only, as example.org, with no https:// and no path", "minLength": 3, "maxLength": 253}}, "required": ["domain"]},
    }


def dispatch(manifest, runtime, name, arguments, ask):
    """One tool call, through the add-on's process, after the core has settled consent and the subject."""
    from .mcp_server import NoDialog, result_of

    spec = next((tool for tool in manifest.tools_spec if tool["name"] == name), None)
    if spec is None:
        return None
    fields = set(spec["inputSchema"].get("properties", {}))
    extra = sorted(field for field in arguments if field not in fields)
    if extra:
        return result_of({
            "error": "%s takes %s, and was given %s" % (name, ", ".join(sorted(fields)), ", ".join(extra)),
            "fix": "Call it with those alone. A key comes from the address book or from the signature this process checked, never from the conversation.",
            "given": extra,
        }, True)
    arguments = dict(arguments)
    host = subject = own_key = None
    try:
        if spec.get("host") and arguments.get(spec["host"]) is not None:
            host = arguments[spec["host"]] = normalise_host(arguments[spec["host"]])
        roles = spec.get("subject") or {}
        given = {role: arguments.get(field) for role, field in roles.items() if arguments.get(field) is not None}
        if roles and len(given) != 1:
            raise Refused("choose_subject", "Name exactly one of %s. A key is never given here." % " or ".join("%s (%s)" % (field, role) for role, field in roles.items()))
        if given:
            (role, value), = given.items()
            subject = subject_for(runtime, role, value)
        if "own_key" in spec.get("needs", []):
            own_key = runtime.keys.public
        if host is not None and host not in allowed_hosts(runtime, manifest):
            answer = _consent(manifest, runtime, name, host, subject, arguments, ask, NoDialog)
            if answer is not None:
                return result_of(answer, "fix" in answer)
    except Refused as refused:
        return result_of(refusal(refused, host=host, **(_subject_fields(subject) if subject else {})), True)
    directory, no_directory = _own_directory(runtime, manifest)
    if no_directory is not None:
        return result_of(no_directory["result"], True)
    limits = limits_of(manifest.NAME)
    busy = limits.take()
    if busy is not None:
        return result_of(refusal(Refused(busy, "At most %d calls of the add-on %s run at once and %d start per minute here. Nothing was done. Try again shortly." % (MAX_AT_ONCE, manifest.NAME, MAX_PER_WINDOW), status="unreachable"), host=host), True)
    try:
        answer = run(manifest, "tool", name, arguments, subject, own_key, directory)
    finally:
        limits.give_back()
    if "raw" in answer:
        return result_of({"raw_base64": base64.b64encode(answer["raw"]).decode("ascii")}, answer["is_error"])
    return result_of(answer["result"], answer["is_error"])


def _consent(manifest, runtime, tool_name, host, subject, arguments, ask, NoDialog):
    """A website not on the list: the user is asked in a form, or the call is refused with the way by hand. None once the host is allowed."""
    if subject is not None and subject["subject_source"] == "message":
        by_hand = "run aamio addon %s allow %s the next time this server is stopped, and check a later message from the same sender. Stopping it for this message would lose it: what this process verified is not kept, and a message cannot be read again" % (manifest.NAME, host)
    else:
        by_hand = "stop this server, run aamio addon %s allow %s, and start it again" % (manifest.NAME, host)
    known = dict(host=host, **(_subject_fields(subject) if subject else {}))
    if ask is None:
        return refusal(Refused("host_not_allowed", "This website is not on the user's list, and this app did not say it can show them a form (the elicitation capability of MCP), so nothing was read. The user adds it from their own records: %s." % by_hand), **known)
    # The whole call is what the answer belongs to, so an answer cannot be
    # carried over to another website or another subject.
    about = json.dumps([manifest.NAME, tool_name, host, arguments], sort_keys=True)
    try:
        answer = ask(host_question(manifest, subject), about, tool_name, HOST_QUESTION)
    except NoDialog as why:
        return refusal(Refused("host_not_allowed", "%s, so nothing was read. Call %s again to ask the user again, or the user adds the website on the command line: %s." % (why, tool_name, by_hand)), **known)
    action = answer.get("action")
    if action != "accept":
        return {"status": "invalid", "reason": "host_declined" if action == "decline" else "host_not_answered", "host": host, "note": "The user did not agree to this website, so nothing was read and nothing was added. Do not ask again unless the user says so."}
    content = answer.get("content") if isinstance(answer.get("content"), dict) else {}
    if not is_same_host(content.get("domain"), host):
        return refusal(Refused("host_not_confirmed", "The user typed a different website from the one you asked for, so nothing was read and nothing was added. Ask the user which website they meant, and take it from them and not from a message."), **known)
    allow_host(runtime, manifest, host)
    return None
