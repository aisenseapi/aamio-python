"""The runtime: what a sidecar does for an agent so the model never touches a secret.

State lives under AAMIO_HOME (default ~/.aamio):

    key              32-byte seed, hex, mode 600. The runtime's identity.
    partners.json    [{"name": ..., "key": ...}] from the contract. Keys, not addresses.
    scopes.json      [{"name": ..., "key": ..., "address": ...}], mode 600. Scope keys stay here.
    state.json       open channels (read keys, mode 600), learned peers, tags.
    archive/*.jsonl  decrypted messages and receipts, per channel. The party's own record.

The inbox is a thread with the maximum lifetime. Before it expires the runtime
opens a new one and republishes presence, so partners keep finding it.
"""

import copy
import json
import os
import queue
import re
import threading
import time

from . import storage
from .client import AamioClient, DEFAULT_HOST, is_scope_address, is_scope_key, make_scope_key, normalize_allow, scope_address
from .gate import GateStop, board_advised_bits, describe as describe_seconds, plan as gate_plan, solve as gate_solve, solve_board
from .crypto import Keys, board_delete_signing_input, board_signing_input, check_message, is_envelope, is_key, key_hash, presence_signing_input, sha256hex, thread_signing_input, unb64url

INBOX_TTL = 3600
# The board's own default, mirrored here so an ordinary post gets the same
# lifetime whether the field is sent or left out. The board decides; this is a
# copy, and it is the only copy in this client.
BOARD_TTL = 1800
# How much longer than the post itself a reply address should live. The poster
# reads answers on their own schedule, and a minute either way is the
# difference between a conversation and a dead end.
ANSWER_MARGIN = 600
PRESENCE_TTL = 120
PRESENCE_REFRESH = 60
RENEW_BEFORE = 180


def home_dir() -> str:
    return os.environ.get("AAMIO_HOME") or os.path.join(os.path.expanduser("~"), ".aamio")


def pid_alive(pid):
    """Whether a process with this pid is running, without touching it.

    os.kill(pid, 0) asks that on POSIX. On Windows it is TerminateProcess:
    it ended whatever process held the pid, and then reported it as alive.
    A lock file outlives its process and Windows hands pids out again
    quickly, so the process ended was as often somebody else's program as
    an old aamio. There the question goes to OpenProcess instead.
    """
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            # Access denied means the process is there and not ours to look at.
            return ctypes.get_last_error() == 5
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def process_started_at(pid):
    """When the process with this pid started, in Unix seconds, or None where that cannot be asked cheaply.

    A pid is handed out again once its process is gone, so a live pid in a
    lock file is not proof of a live owner. A process that started after the
    lock was written is some other program that got the number.
    """
    try:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = ctypes.c_void_p
            handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                return None
            try:
                created, ignored = ctypes.c_ulonglong(), (ctypes.c_ulonglong * 3)()
                if not kernel32.GetProcessTimes(ctypes.c_void_p(handle), ctypes.byref(created), ctypes.byref(ignored, 0), ctypes.byref(ignored, 8), ctypes.byref(ignored, 16)):
                    return None
                # 100 nanosecond steps since 1601.
                return created.value / 1e7 - 11644473600
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
        with open("/proc/%d/stat" % int(pid), encoding="ascii", errors="replace") as handle:
            ticks = int(handle.read().rsplit(")", 1)[1].split()[19])
        with open("/proc/stat", encoding="ascii", errors="replace") as handle:
            boot = next(int(line.split()[1]) for line in handle if line.startswith("btime "))
        return boot + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration, AttributeError):
        return None


# Homes locked by this process. The file on disk catches another process;
# this catches two runtimes in one, which is just as bad for the state.
_LOCKED_HOMES = set()


# What an HTTP status says about sending the same bytes again.
#
# outbox_retry already had to know this and carried its own list inline. The
# MCP error handler then grew a second answer that disagreed with it: every
# refusal became "change the request", including 429, which is a rate window
# and needs no change at all. Two places knowing the same thing differently is
# how advice ends up contradicting the mechanism meant to act on it.
#
# Deterministic: the same bytes will be refused again, so repeating is waste.
# Later: nothing about the message is wrong, only the moment.
# Anything else answered by the server is left undecided on purpose. It told us
# it failed, but not whether it had already stored the message.
SEND_DETERMINISTIC = (400, 403, 410, 413, 415, 422, 428, 501)
SEND_TRY_LATER = (429, 503)
# Answers that prove the message was never stored. The deterministic ones, and a
# rate window, which aamio decides before it reads the body. 503 is deliberately
# not here: it can be a front door that saw nothing or the service failing after
# it had written, and this side cannot tell which.
SEND_NOT_STORED = SEND_DETERMINISTIC + (429,)


def send_advice(outcome, status):
    """(retryable, fix) for one send outcome. retryable is about the same
    stored bytes, and is never a permission to repeat something automatically.

    False  the same message will fail the same way
    True   the message is fine; the moment was not
    None   it cannot be decided from what we know
    """
    if outcome == "unknown":
        return None, (
            "No answer came back, so this message may already have been delivered. Keep its message_id. "
            "aamio_pending lists what has no settled outcome on this machine; it does not confirm delivery, "
            "and nothing here can, because the address it went to is not yours to read. Do not pass the "
            "message_id to aamio_send and do not compose a replacement. An approved retry sends the stored "
            "bytes again: aamio_outbox_retry with this id, or aamio outbox retry --id on the command line."
        )

    if status in SEND_TRY_LATER:
        return True, (
            "aamio declined this for now, not because of the message: %d is a rate window or a busy service. "
            "Do not change the content. Wait, then send the stored message again through the runtime's outbox "
            "retry rather than composing a new one." % status
        )

    if status in SEND_DETERMINISTIC:
        return False, (
            "aamio refused this and will refuse the same bytes again. Read the error, correct the request, and "
            "send the corrected one as a new message."
        )

    return None, (
        "aamio answered %s, which this client does not classify. It may or may not have stored the message "
        "before failing, so treat delivery as unsettled: keep the message_id, read the error, and do not "
        "resend blindly." % status
    )


class SendFailed(RuntimeError):
    """A send that did not end in a stored message.

    outcome is refused when aamio answered and said no, and unknown when no
    answer came back at all. Unknown is not failure: the message may be on
    the other side. The entry stays in the outbox under message_id.
    """

    def __init__(self, outcome, message_id, status, detail, opened=None):
        super().__init__("send %s (http %s): %s" % (outcome, status, detail))
        self.outcome = outcome
        self.message_id = message_id
        self.status = status
        self.detail = detail
        # When the message that did not land was the one carrying the address
        # of a channel just opened: the channel is there, and the caller has
        # to be told which, or it is a thread nobody knows about.
        self.opened = opened


def outbox_retryable(entry):
    """Whether sending these same bytes again is the right next move.

    Not the same question as outbox_open, and retry was asking that one. A rate
    window is settled -- the service turned the request away without reading the
    body, so nothing was stored -- and it is also the one refusal whose advice is
    do not change the content, wait, send it again. Retry refused to do the thing
    its own advice asked for.

    A refusal the service will repeat is not here, and a delivery is not here.
    """
    if entry is None:
        return False

    if outbox_open(entry):
        return True

    return (outbox_outcome(entry) == "refused"
            and entry.get("last_status") in SEND_TRY_LATER)


def outbox_open(entry):
    """Whether this message still has something to decide.

    One place, because two places disagreed: pending listed a message and retry
    called the same message settled, in the same runtime, in the same second.
    """
    return outbox_outcome(entry) in ("attempted", "unknown")


def outbox_outcome(entry):
    """Which of five things happened to a send, for a caller deciding whether to replace it.

    Only a stop before the first POST may be called safely unsent. An attempt that was
    answered 500 does not prove the message is absent, and one that was delivered is
    certainly not unsent: both were reported as never sent until 20 September, which
    invites a second copy.
    """
    if entry is None:
        return "not_found"

    status = entry.get("status")

    # Read before the statuses, because a retry sets the status back to working
    # while the first attempt is still with the other side.
    if entry.get("posting") and status == "working":
        return "attempted"

    if status == "delivered":
        return "delivered"

    if status == "unknown":
        return "unknown"

    if status == "attempted":
        # It left this machine and what came back settles nothing.
        return "attempted"

    if status == "refused":
        # The service turned it away without storing it. An earlier attempt that
        # was left open is not undone by any later refusal, and _record_answer
        # keeps that as ever_open; this is the same rule for an entry written by
        # an older version, which had no such field.
        if entry.get("ever_open"):
            return "attempted"

        return "refused" if entry.get("last_status") in SEND_NOT_STORED else "attempted"

    # The flag is set in the moment before the post, so it is the only mark that means
    # bytes were on their way. attempts counts calls to deliver, and the proof of work
    # runs inside one of those: a message still working has attempts 1 and has sent
    # nothing.
    if entry.get("posting"):
        return "attempted"

    if status in ("working", "stopped"):
        return "never_sent"

    if int(entry.get("attempts") or 0) > 0:
        return "attempted"

    return "never_sent"


OUTBOX_NOTES = {
    "never_sent": "nothing had left this machine for it, and nothing will now",
    "attempted": "a send was attempted and its answer does not prove the message is absent, so its outcome stays unknown and nothing here can recall it",
    "delivered": "the service had already stored it when this was dropped; dropping the entry does not unsend it",
    "refused": "the service answered that it refused this one, so it was not stored, but the attempt did leave this machine",
    "unknown": "a send was already away when this was dropped, so its outcome stays unknown and nothing here can recall it",
    "not_found": "this outbox has no message with that id, so nothing was dropped and nothing was sent",
}


class WorkDropped(RuntimeError):
    """The proof of work finished after the message was dropped, so nothing was sent.

    Not a failure and not an unknown outcome: the send stopped because this side asked
    it to, through aamio_outbox_forget or close(), and it stopped before the POST.
    """


def check_gate(gate):
    """The shape of a gate, refused here rather than a round trip later.

    Only the shape. What the numbers may be is the service's to decide, it decides
    that in one place, and its refusal carries the detail. Duplicating the whole
    rule here would give an agent two answers that can drift apart, and the one it
    could reach without a network would be the wrong one.

    Worth catching before the call because a gate is set once, when the inbox is
    opened, and never changes. A gate that quietly went nowhere leaves an inbox
    open for its whole life without the conditions its owner meant it to have.
    """
    shape = ('A gate is an object with "require", "advise" or both, as in '
             '{"require": {"pow": {"bits": 20}, "per_key": 5}}. require refuses a '
             'write that does not meet it; advise lets the write in and reports on it.')

    if not isinstance(gate, dict):
        raise ValueError("a gate must be an object, not %s. %s" % (type(gate).__name__, shape))

    unknown = [key for key in gate if key not in ("require", "advise")]

    if unknown:
        raise ValueError("a gate has no field %s. %s" % (", ".join(sorted(unknown)), shape))

    if not gate:
        raise ValueError("an empty gate asks for nothing; leave the gate out instead. %s" % shape)

    for key in ("require", "advise"):
        if key in gate and not isinstance(gate[key], dict):
            raise ValueError("gate.%s must be an object. %s" % (key, shape))

    return gate


def is_message_hash(value):
    """The sha256 of a message as the service gives it: 64 lowercase hex characters."""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def message_shape(body, envelope):
    """What a message was made of, for the trace, without what it said."""
    shape = {
        "bytes": len(envelope.encode("utf-8") if isinstance(envelope, str) else envelope),
        "fields": sorted(body) if isinstance(body, dict) else [],
        "text_chars": len(body["text"]) if isinstance(body, dict) and isinstance(body.get("text"), str) else None,
    }

    for field in ("re", "seen"):
        if isinstance(body, dict) and is_message_hash(body.get(field)):
            shape[field] = body[field]

    return shape


# What a row of the trace may hold, and of what type. trace.json is this
# runtime's own file and is still read as if anyone could have written it: on
# 25 September 2026 a nested field of the wrong type reached the code that
# records a send, after the message had gone, and the caller heard an error
# about a message that was delivered (finding R3 of that evening's review).
TRACE_SENT_FIELDS = {
    "message_id": str, "at": int, "w": str, "status": int, "outcome": str, "seq": int, "sha256": "hash",
    "sealed": bool, "bytes": int, "fields": list, "text_chars": int, "re": "hash", "seen": "hash",
}
TRACE_RECEIVED_FIELDS = {
    "at": int, "channel": str, "w": str, "seq": int, "sha256": "hash", "encrypted": bool, "format": str,
    "error": str, "fields": list, "text_chars": int, "re": "hash", "seen": "hash",
}
TRACE_READ_FIELDS = {"sha256": "hash", "seq": int, "w": str, "at": int}


def _trace_value(kind, value):
    if kind == "hash":
        return value if is_message_hash(value) else None
    if kind is list:
        return sorted(item for item in value if isinstance(item, str)) if isinstance(value, list) else None
    # type() rather than isinstance(): True is an int to isinstance.
    return value if type(value) is kind else None


def trace_row(row, fields):
    """One row of a trace as this runtime writes it: the fields it knows, each of the type it writes or None."""
    if not isinstance(row, dict):
        return None

    return {name: _trace_value(kind, row[name]) for name, kind in fields.items() if name in row}


def _trace_rows(found, fields, keep, required):
    """Rows as the file held them. A row without what names it, the message id of a send or the hash of what arrived, says nothing and is left out."""
    rows = [trace_row(item, fields) for item in found] if isinstance(found, list) else []

    return [row for row in rows if row is not None and row.get(required) is not None][-keep:]


def normalize_traces(traces, keep, keys):
    """trace.json as this runtime writes it, whatever the file held: a book per key, rows of a known shape, within the bounds."""
    books = {}

    for key, book in (traces.items() if isinstance(traces, dict) else ()):
        if not isinstance(key, str) or not is_key(key) or not isinstance(book, dict):
            continue

        last = trace_row(book.get("last_read"), TRACE_READ_FIELDS)
        books[key] = {
            "sent": _trace_rows(book.get("sent"), TRACE_SENT_FIELDS, keep, "message_id"),
            "received": _trace_rows(book.get("received"), TRACE_RECEIVED_FIELDS, keep, "sha256"),
            "last_read": last if last and last.get("sha256") else None,
            "active": book["active"] if type(book.get("active")) is int else 0,
        }

    for stale in sorted(books, key=lambda k: books[k]["active"])[:max(0, len(books) - keys)]:
        books.pop(stale)

    return books


def trace_view(book, limit):
    """One counterpart's record, with each message sent next to what came back about it.

    A claim is exact. A verified message from them whose seen names a sha256
    says their runtime read and opened that message, and nothing more: not the
    ones sent before it, not another channel's. The first version read one seen
    as covering every earlier send, so a side channel nobody had read showed as
    read (finding R1). A message nothing names is unknown, never unread.
    """
    sent_rows = [row for row in book.get("sent") or [] if isinstance(row, dict)]
    received_rows = [row for row in book.get("received") or [] if isinstance(row, dict)]
    claimed = {row["seen"] for row in received_rows if is_message_hash(row.get("seen"))}
    answered = {row["re"] for row in received_rows if is_message_hash(row.get("re"))}
    mine = {row["sha256"]: row for row in sent_rows if is_message_hash(row.get("sha256"))}
    delivered = [row for row in sent_rows if row.get("status") == 201 and is_message_hash(row.get("sha256"))]
    no_claim = [row.get("message_id") for row in delivered if row["sha256"] not in claimed]
    sent = []

    for record in sent_rows[-limit:]:
        row = dict(record)
        stored = record.get("sha256") if record.get("status") == 201 and is_message_hash(record.get("sha256")) else None
        row["seen_by_them"] = True if stored is not None and stored in claimed else None
        row["answered_by_them"] = True if stored is not None and stored in answered else None
        sent.append(row)

    received = []

    for record in received_rows[-limit:]:
        row = dict(record)

        for field, as_ in (("re", "answers"), ("seen", "acknowledges")):
            if is_message_hash(record.get(field)):
                ours = mine.get(record[field])
                row[as_] = {"seq": ours.get("seq"), "sha256": ours["sha256"], "at": ours.get("at")} if ours else {"sha256": record[field], "note": "no confirmed send in this record has this sha256"}

        received.append(row)

    return {
        "sent": sent,
        "received": received,
        "no_read_claim": no_claim,
        "note": trace_note(sent_rows, received_rows, delivered, no_claim, claimed - set(mine)),
    }


def trace_note(sent, received, delivered, no_claim, elsewhere):
    """What the record says, in words, and no more than it says.

    A send the service did not confirm is not a send it did not store: the
    answer can be lost after the message was stored. The first version said the
    service stored none of the messages in a trace whose one send had an unknown
    outcome and had been stored all the same, and whoever trusts that sends the
    text again as new bytes, which is a second message. A claim naming such a
    send was put down to a message older than the record or sent from elsewhere.
    R5 of the follow-up review of 25 September 2026.
    """
    if not sent:
        return "Nothing sent to them is recorded here."

    named = any(is_message_hash(row.get("seen")) for row in received)
    turned_away = sum(1 for row in sent if row.get("outcome") == "refused" and row.get("status") != 201)
    unsettled = len(sent) - len(delivered) - turned_away

    if not delivered:
        note = "No message here has an answer from the service that confirms it was stored."
    elif not named:
        said = "Nothing from them has named a message of yours as read" if received else "Nothing has come back from them"
        note = (said + ", so each is unknown, not unread. A client that does not send seen says nothing, and neither does one "
                "that cannot open what it gets: every message here is sealed to their key, so a reader without it sees an "
                "envelope and no text. The sha256 of each message is what the service stored, byte for byte; ask them for "
                "the sha256 they read.")
    else:
        note = "%d delivered, and their runtime says it read and opened %d of them." % (len(delivered), len(delivered) - len(no_claim))

        if no_claim:
            note += (" For %d there is no claim kept here: that is unknown, not unread, since each message from them names only "
                     "the last of yours it had read when it was written, and this record keeps fifty each way." % len(no_claim))

    if elsewhere:
        note += (" They named %d message(s) this record cannot match to a send the service confirmed: older than this record, "
                 "sent from elsewhere, or sent from here without an answer that confirmed it." % len(elsewhere))

    if unsettled:
        note += (" For %d no answer settled whether the service stored it, so it may be stored already. Check each one's status "
                 "and outcome first, and if it must go again, retry it from the outbox: the same bytes are marked a replay "
                 "where the first arrived, and new bytes would be a second message." % unsettled)

    if turned_away:
        note += " The service turned away %d; the status of each says why." % turned_away

    if named:
        note += " A claim covers the one message it names. It says their runtime opened it, not that anyone understood it or acted on it."

    return note


class Channel:
    def __init__(self, label, read_key, w, expire_at, allow=None, after=0, created_at=None):
        self.label = label
        self.read_key = read_key
        self.w = w
        self.expire_at = int(expire_at)
        self.allow = normalize_allow(allow)
        self.after = int(after)
        # Which thread at this address the cursor and the hashes belong to. A
        # restart can take the thread and a write can open a new one at the
        # same address, counting from one again, and created_at is the only
        # thing that tells the two apart.
        self.created_at = created_at
        self.gone = False
        # Read no more, kept for its records and its receipt until it expires.
        # An inbox is muted when a partner is removed: the removed key can
        # still write to the address it was given until the thread expires,
        # and nothing from there is delivered.
        self.muted = False
        # How many messages the last poll had fetched and left for the next
        # one, because the caller's limit was reached. They are still at the
        # service and the cursor stands before them.
        self.left_waiting = 0
        # Whether the service itself held some back, because the read asked
        # for fewer bytes than the thread holds. A different fact from the
        # one above -- nothing was fetched and left here -- and a count this
        # side never learns, so it is a flag and not a made-up number.
        self.more_at_service = False
        self.seen = set()
        self.received = []
        self.observed = {}
        self.lock = threading.Lock()
        self.poller = None
        self.closed = False

    def forget_thread(self):
        """The cursor belonged to a thread that is not there now. The hashes stay.

        They are what this reader has been handed, whichever thread carried it.
        They used to be cleared here with the cursor, and that lost the replay
        mark at the one moment it is most needed: after the service loses its
        store, every sender whose message went with it sends the same bytes
        again, and a reader that had already acted on them acted twice.
        """
        self.after = 0
        self.created_at = None
        self.observed.clear()

    def to_state(self):
        # seen travels with the channel: without it a restart cannot tell a
        # redelivered message from a new one, and the model may act twice.
        return {"label": self.label, "read_key": self.read_key, "w": self.w, "expire_at": self.expire_at, "allow": self.allow, "after": self.after, "created_at": self.created_at, "gone": self.gone, "muted": self.muted, "seen": sorted(value for value in self.seen if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))}

    @classmethod
    def from_state(cls, item):
        channel = cls(item["label"], item["read_key"], item["w"], item["expire_at"], item.get("allow"), item.get("after", 0), item.get("created_at"))
        channel.seen = {value for value in item.get("seen") or [] if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)}
        channel.gone = item.get("gone") is True
        channel.muted = item.get("muted") is True

        return channel


class Runtime:
    # Files a runtime writes back. One that is there and cannot be read stops
    # the runtime before anything is saved over it: a save is how a broken
    # file becomes a lost one, with the channels, partners or scope keys in it.
    KEPT_FILES = ("partners.json", "scopes.json", "state.json", "outbox.json", "effects.json")

    # How long close waits for its threads. A poller sits in a long poll of up
    # to twenty seconds, and close does not wait that out: what comes back
    # after it finds the home let go and writes nothing.
    CLOSE_WAIT = 2.0

    def __init__(self, home=None, host=None, tags=None, archive=None, log=None):
        self.home = home or home_dir()
        self.host = host or os.environ.get("AAMIO_HOST") or DEFAULT_HOST
        self.client = AamioClient(self.host)
        self.log = log or (lambda line: None)
        self.closed = False
        self.home_released = False
        self.archive_lock = threading.Lock()
        storage.make_private_dir(self.home)
        storage.make_private_dir(os.path.join(self.home, "archive"))
        # The archive is the home's own choice, kept in config.json: keep, off,
        # or so many days. archive=False turns it off for this process, which
        # is what --no-archive does, and archive=True turns it on whatever the
        # home says. It used to be on unless every command said otherwise.
        self.archive_policy = storage.read_policy(self.home)
        self.archive_enabled = self.archive_policy["mode"] != "off" if archive is None else bool(archive)
        self.pruned_at = 0.0
        self.owns_lock = self._take_lock()
        try:
            self._load(tags)
            self._tidy()
        except BaseException:
            self._release_lock()
            raise

    def _tidy(self):
        """What the home needs before the first read: private files, no leftovers, no archive past its lifetime."""
        for path in storage.leftovers(self.home):
            # A write that was interrupted. The file it was to replace is whole,
            # since the rename never happened.
            try:
                os.unlink(path)
            except OSError:
                pass
        for path in storage.tighten(self.home):
            self.log("made private: %s (an older version wrote it with the default mode)" % path)
        if not storage.is_windows():
            # Mode bits cost nothing to read. On Windows it is the access list
            # that decides and reading it starts a shell, so that is left to
            # `aamio doctor` and `aamio init`.
            found = storage.check(self.home)
            for finding in found["findings"][:5]:
                self.log("WARNING: %s: %s. %s" % (finding.get("path", self.home), finding["problem"], found.get("fix", "")))
        self._prune()

    def _prune(self):
        policy = getattr(self, "archive_policy", None) or storage.DEFAULT_POLICY
        if not self.archive_enabled or not (policy.get("days") or policy.get("max_mb")):
            return
        self.pruned_at = time.time()
        try:
            with self.archive_lock:
                gone = storage.prune(self.home, policy)
        except OSError as error:
            self.log("archive not pruned: %s" % error)
            return
        if gone["removed"]:
            self.log("archive: %d record(s) past their lifetime removed" % gone["removed"])

    def _load(self, tags):
        self.keys = self._load_or_create_keys()
        self.partners = self._load_json("partners.json", [])
        self.scopes, self.scopes_aside = self._usable_scopes(self._load_json("scopes.json", []))
        state = self._load_json("state.json", {})
        self.tags = tags if tags is not None else state.get("tags") or [t for t in (os.environ.get("AAMIO_TAGS") or "").split(",") if t]
        self.peers = dict(state.get("peers") or {})          # write address -> partner key
        self.channels = {}
        for item in state.get("channels") or []:
            channel = Channel.from_state(item)
            if channel.expire_at > time.time():
                held = self.channels.get(channel.label)
                if held is not None:
                    if held.expire_at > channel.expire_at:
                        self._retire_channel(channel)
                        continue
                    self._retire_channel(held)
                self.channels[channel.label] = channel
        self.outbox = self._load_json("outbox.json", {})
        self.effects = self._load_json("effects.json", {})
        # What was sent to each key and what came back, as hashes and shapes,
        # never content. Not a kept file: a trace that cannot be read is a
        # trace that starts again, not a reason to stop. And read field by
        # field, as if anyone could have written it (R3).
        self.traces = normalize_traces(self._load_json("trace.json", {}), self.TRACE_KEEP, self.TRACE_KEYS)
        self.gates = {}                                       # write address -> the gate it was opened with
        # Anything still pending was in flight when the last process stopped.
        # Whether it reached aamio is unknown, and it stays unknown until
        # somebody looks. Retrying is a decision, not a default.
        for entry in self.outbox.values():
            # A post that happened is history, and a retry rewrites the status, so
            # the flag carries it instead. Without this an entry that came back as
            # unknown or refused reported never_sent while its retry did the work.
            if entry.get("status") in ("sending", "unknown", "refused", "delivered"):
                entry["posting"] = True

            if entry.get("status") == "sending":
                entry["status"] = "unknown"
                entry["note"] = "the process stopped while this was in flight"
            # The proof of work comes before the post, so work that never
            # finished was never sent. It used to stay working for good, with
            # nothing working on it, and the outcome promised to the caller
            # never came.
            #
            # Unless it is a retry. Then an earlier attempt already left this
            # machine, posting says so, and the unfinished work changes nothing
            # about it: the outcome is the one the first attempt left behind.
            # Calling that stopped, and offering to send again, asks for a second
            # copy of a message that may already be there.
            elif entry.get("status") == "working":
                if entry.get("posting"):
                    entry["status"] = "unknown"
                    entry["note"] = "the process stopped while a retry was doing its proof of work. An earlier attempt had already left this machine and its answer never came, so the outcome is still unknown"
                else:
                    entry["status"] = "stopped"
                    entry["note"] = "the process stopped before its proof of work was done, so nothing was sent"
        self.presence_at = 0.0
        # The last attempt and the last success are two different times: a
        # failed publish used to count as a fresh one, and the new address
        # went unpublished for a minute while the old one was still announced.
        self.presence_ok_at = 0.0
        self.presence_failed = False
        self.presence_retry_at = 0.0
        self.presence_backoff = 0.0
        # What a read could not do, kept by channel and state until it is
        # handed to a caller. An empty read means nothing arrived. An empty
        # read on a thread that has expired, or that the service would not
        # answer for, means something else entirely, and both used to look
        # exactly the same from outside.
        self.attention = {}
        self.inbound = queue.Queue()
        # Fetched by the listener, offered to a caller, and not taken because the
        # caller's byte budget was full. In front of the queue on the next read.
        self.held_back = []
        # Re-entrant on purpose: poll holds this lock while it applies a message,
        # and the helpers it calls, binding an address or keeping a scope, take
        # it again. A stub runtime in a test needs an RLock here for the same
        # reason.
        self.lock = threading.RLock()
        # Partners may have changed while this process was not running. The
        # current inbox is compared with the address book on the first read;
        # the older generations are judged here, so a key removed while the
        # runtime was down is read no more from any address it was given.
        self._mute_generations("a restart")
        self.stop = threading.Event()
        self.listener = None
        # Told once, on the first read after the restart, since the caller was
        # promised how the send would end. Two different things to say: one
        # message never left and can be sent again, the other left once and
        # must not be sent again until somebody knows what became of it.
        untold = [e for e in self.outbox.values() if e.get("status") == "stopped" and not e.get("told")]
        for entry in untold:
            self._note_trouble("send %s" % entry["id"], "stopped", "the message to %s was not sent: the process stopped before its proof of work was done. Send it again if it still matters." % entry.get("w"))
            entry["told"] = True

        interrupted = [e for e in self.outbox.values()
                       if e.get("status") == "unknown" and e.get("posting") and not e.get("told")
                       and "retry" in (e.get("note") or "")]

        for entry in interrupted:
            self._note_trouble(
                "send %s" % entry["id"],
                "unknown",
                "the message to %s may have arrived: an attempt left this machine and no answer came back, and the process then stopped during a retry. Its outcome is still open. Do not compose a replacement; aamio_outbox_retry sends the same stored bytes again, and aamio_outbox_forget stops waiting without claiming it was not sent."
                % entry.get("w"))
            entry["told"] = True

        untold = untold + interrupted

        if untold:
            # So the next restart does not say it again.
            self.save_outbox()

    # -------------------------------------------------------------- lock --

    def _take_lock(self):
        """One live runtime per home. Two would overwrite each other's state.

        The file holds the pid, and a pid that is gone is not an owner. This
        catches the ordinary mistake, two sidecars on one home, not a shared
        network filesystem.
        """
        real = os.path.realpath(self.home)

        if real in _LOCKED_HOMES:
            raise RuntimeError("another aamio in this process is already using %s" % self.home)

        held = self._load_json("lock", None)

        if isinstance(held, dict) and isinstance(held.get("pid"), int) and held["pid"] != os.getpid():
            try:
                alive = pid_alive(held["pid"])
            except Exception:
                alive = True

            if alive and isinstance(held.get("at"), (int, float)):
                # The lock is written after its owner started. A process that
                # started later got the pid after the owner was gone.
                started = process_started_at(held["pid"])
                if started is not None and started > held["at"] + 2:
                    alive = False

            if alive:
                raise RuntimeError(
                    "another aamio (pid %s) is using %s. Stop it, or use a different AAMIO_HOME. If no aamio is running, "
                    "the one that took the lock stopped without letting go of it: delete %s and start again." % (held["pid"], self.home, self._path("lock"))
                )

        self._save_json("lock", {"pid": os.getpid(), "at": int(time.time()), "host": self.host})
        _LOCKED_HOMES.add(real)

        return True

    def _release_lock(self):
        if not getattr(self, "owns_lock", False):
            return
        held = self._load_json("lock", None)
        if isinstance(held, dict) and held.get("pid") == os.getpid():
            try:
                os.unlink(self._path("lock"))
            except OSError:
                pass
        _LOCKED_HOMES.discard(os.path.realpath(self.home))
        self.owns_lock = False

    # ----------------------------------------------------------- storage --

    def _path(self, name):
        return os.path.join(self.home, name)

    def _load_json(self, name, default):
        """What a file holds, or default when it is not there or empty.

        A file in KEPT_FILES that is there and cannot be read, or holds
        something other than the list or object it should, raises instead.
        """
        try:
            with open(self._path(name), "rb") as handle:
                text = handle.read().decode("utf-8")
            value = json.loads(text) if text.strip() else default
        except FileNotFoundError:
            return default
        except (OSError, ValueError) as error:
            if name not in self.KEPT_FILES:
                return default
            why = "not UTF-8 JSON" if isinstance(error, ValueError) else error.__class__.__name__
            raise RuntimeError(self._unreadable(name, why)) from None
        if name in self.KEPT_FILES and not isinstance(value, type(default)):
            raise RuntimeError(self._unreadable(name, "not a JSON %s" % ("list" if isinstance(default, list) else "object")))
        return value

    def _unreadable(self, name, why):
        return (
            "%s could not be read (%s), so this runtime stops here rather than save over it. Repair the file, "
            "or move it away to start without what was in it." % (self._path(name), why)
        )

    def _save_json(self, name, value, private=True):
        """Every file here is private, from its first byte.

        effects.json and partners.json used to be written with the default
        mode: what this agent has done, and whom it talks to, readable by
        anyone on the machine. private stays as an argument and means nothing
        now; there is no file in this folder that others should read.
        """
        if getattr(self, "home_released", False) is True:
            # After close the home may be another process's. A poller that
            # comes back from its long poll then must not write its cursor:
            # what it read went into a queue nobody reads again, and the next
            # process reads those messages only if the cursor stays behind them.
            self.log("%s not written: this runtime is closed" % name)
            return
        path = self._path(name)
        with storage.open_private(path + ".tmp") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            # The rename is atomic, but only over bytes that reached the disk,
            # and the new name is there only when the folder is.
            os.fsync(handle.fileno())
        os.replace(path + ".tmp", path)
        storage.sync_dir(os.path.dirname(path))

    def _load_or_create_keys(self):
        path = self._path("key")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read().strip()
        except FileNotFoundError:
            text = ""
        except (OSError, ValueError) as error:
            raise RuntimeError(self._unreadable("key", error.__class__.__name__)) from None
        if text:
            # A new key over it would be a new identity, and the old one gone
            # for good. Partners know this runtime by that key.
            if re.fullmatch(r"[0-9a-f]{64}", text) is None:
                raise RuntimeError(self._unreadable("key", "not a 64 character hex seed"))
            return Keys(bytes.fromhex(text))
        keys = Keys.generate()
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as handle:
            handle.write(keys.seed.hex() + "\n")
        return keys

    def save_state(self):
        with self.lock:
            self._save_json("state.json", {"tags": self.tags, "peers": self.peers, "channels": [c.to_state() for c in self.channels.values()]}, private=True)

    def save_outbox(self):
        with self.lock:
            self._save_json("outbox.json", self.outbox, private=True)

    def save_effects(self):
        with self.lock:
            self._save_json("effects.json", self.effects)

    def archive(self, label, record):
        """Writes one record, and says whether it wrote one.

        A folder that keeps nothing is not a failure, and it is not a write either.
        Returning nothing let the caller call both of them archived.
        """
        if not self.archive_enabled or getattr(self, "home_released", False) is True:
            return False
        # ensure_ascii=False so ordinary non-English text stays readable in the
        # file. Some text cannot be written that way at all: JSON can carry a
        # lone surrogate, Python will happily parse it into a str, and UTF-8
        # cannot encode it. It arrives as plain ASCII on the wire, so it is the
        # sender who decides which of the two kinds of text this is. That one
        # record gets escaped instead, which loses nothing and keeps every other
        # record readable.
        line = json.dumps(record, ensure_ascii=False)
        try:
            line.encode("utf-8")
        except UnicodeEncodeError:
            line = json.dumps(record, ensure_ascii=True)
        path = os.path.join(self.home, "archive", "%s.jsonl" % label)
        # One writer at a time: every channel has a poller, and they archive.
        with getattr(self, "archive_lock", None) or threading.Lock():
            # A crash in the middle of a write leaves a last line with no end.
            # Appended to as it was, the next record became part of that line,
            # and a reader passed over both.
            torn = False
            try:
                with open(path, "rb") as existing:
                    existing.seek(0, os.SEEK_END)
                    if existing.tell() > 0:
                        existing.seek(-1, os.SEEK_END)
                        torn = existing.read(1) != b"\n"
            except OSError:
                pass
            with storage.open_private(path, append=True) as handle:
                handle.write(("\n" if torn else "") + line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        if time.time() - getattr(self, "pruned_at", 0.0) > 3600:
            self._prune()

        return True

    # ---------------------------------------------------------- partners --

    def whoami(self):
        inbox = self.channels.get("inbox")
        return {"key": self.keys.public, "hash": self.keys.hash, "hash_prefix": self.keys.hash[:8], "inbox": inbox.w if inbox else None, "inbox_expires_at": inbox.expire_at if inbox else None, "host": self.host, "tags": self.tags}

    def partner_add(self, name, key):
        """A partner into the address book, and into the inbox at once.

        The address book and the inbox used to drift apart: this wrote
        partners.json and nothing else, the inbox kept the list it was opened
        with for up to 57 minutes, and the partner just added was refused with
        403 at the address presence pointed to, which the owner never saw. Now
        an inbox that does not name the key is replaced by one that does, and
        the answer says which address the partner can write to.
        """
        if not is_key(key):
            raise ValueError("not a base64url Ed25519 public key of 32 bytes")
        self.partners = [p for p in self.partners if p["name"] != name and p["key"] != key]
        self.partners.append({"name": name, "key": key})
        self._save_json("partners.json", self.partners)
        return self._inbox_after_change("partner %s was added" % name, {"partner": name, "key": key})

    def partner_remove(self, name):
        """A partner out of the address book, and out of the inbox at once.

        Forgetting the name is not a revocation: the service takes the removed
        key's writes to the old address until that thread expires. So the old
        inbox is muted, read no more, and a new one is opened without the key.
        Once the last partner is gone the new inbox takes signed writes from any
        key, each shown as an unknown one, rather than unsigned writes from
        anyone at an address the partners were given.
        """
        known = self.partner_by_name(name)
        self.partners = [p for p in self.partners if p["name"] != name]
        self._save_json("partners.json", self.partners)
        outcome = {"partner": name, "known": known is not None}
        if known is None:
            inbox = self.channels.get("inbox")
            outcome["inbox"] = inbox.w if inbox else None
            return outcome
        return self._inbox_after_change("partner %s was removed" % name, outcome)

    def _inbox_after_change(self, reason, outcome):
        """Whether the inbox still matches the address book, and a new one if not."""
        inbox = self.channels.get("inbox")
        if inbox is None:
            # Registration before the first read: the inbox opens with this
            # list when it opens, and there is no address to hand out yet.
            outcome.update({"inbox": None, "rotated": False})
            return outcome
        if self._inbox_matches(inbox, self._wanted_allow()):
            outcome.update({"inbox": inbox.w, "rotated": False, "expire_at": inbox.expire_at})
            return outcome
        outcome.update(self._rotate_inbox(reason))
        return outcome

    def partner_list(self):
        return [{"name": p["name"], "key": p["key"], "hash_prefix": key_hash(p["key"])[:8]} for p in self.partners]

    def partner_by_name(self, name):
        for p in self.partners:
            if p["name"].lower() == str(name).lower():
                return p
        return None

    def partner_by_key(self, key):
        for p in self.partners:
            if p["key"] == key:
                return p
        return None

    def name_for_key(self, key):
        p = self.partner_by_key(key)
        return p["name"] if p else None

    # ----------------------------------------------------------- scopes --
    #
    # A scope keeps board posts unlisted for a group. Here each one has a name,
    # and the name is all a caller passes or sees. The key is the read
    # capability: it stays in scopes.json, and scope_share hands it to a partner
    # sealed, so no model has to hold it. The address is the write capability
    # and is no secret. Unlisted is not private.

    SCOPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

    def _usable_scopes(self, entries):
        """The entries of scopes.json this runtime can use, and the rest.

        The rest are never dropped. They go back into the file on every save
        as they were, so a hand edit with a typo is there to be corrected
        rather than gone with the key in it.
        """
        usable, aside, names = [], [], set()
        for entry in entries:
            key = entry.get("key") if isinstance(entry, dict) else None
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("name"), str)
                and self.SCOPE_NAME.fullmatch(entry["name"]) is not None
                and entry["name"].lower() not in names
                and is_scope_address(entry.get("address"))
                and (key is None or (is_scope_key(key) and scope_address(key) == entry["address"]))
            ):
                usable.append(entry)
                names.add(entry["name"].lower())
            else:
                aside.append(entry)
        if aside:
            self.log("scopes.json: %d entries are not scopes this runtime can use, and stay in the file as they are" % len(aside))
        return usable, aside

    def _save_scopes(self, scopes):
        """Writes the scopes, and only then holds them: a save that fails changes nothing."""
        with self.lock:
            self._save_json("scopes.json", scopes + getattr(self, "scopes_aside", []), private=True)
            self.scopes = scopes

    def _scope(self, name):
        for entry in self.scopes:
            if entry["name"].lower() == str(name).lower():
                return entry
        return None

    def _scope_named(self, name):
        entry = self._scope(name)
        if entry is None:
            raise LookupError("no scope called %s here. The scope list shows the ones this runtime holds" % name)
        return entry

    @staticmethod
    def _scope_view(entry):
        return {"name": entry["name"], "address": entry["address"], "can_read": bool(entry.get("key"))}

    def _scope_name_ok(self, name):
        if not isinstance(name, str) or self.SCOPE_NAME.fullmatch(name) is None:
            raise ValueError("a scope name is 1 to 64 letters, digits, dots, dashes and underscores, starting with a letter or a digit")

    def scope_new(self, name):
        """A new scope, its key from the system's secure generator. The key stays here."""
        self._scope_name_ok(name)
        with self.lock:
            if self._scope(name) is not None:
                raise ValueError("there is a scope called %s already" % name)
            key = make_scope_key()
            entry = {"name": name, "key": key, "address": scope_address(key)}
            self._save_scopes(self.scopes + [entry])
        return self._scope_view(entry)

    def scope_add(self, name, key=None, address=None):
        """A scope made elsewhere: the key, to read and post, or the address, to post only."""
        self._scope_name_ok(name)
        if key is None and address is None:
            raise ValueError("give the key, to read and post, or the address, to post only")
        if key is not None and not is_scope_key(key):
            raise ValueError("a scope key is 26 to 64 characters of a-z and 0-9. The 20 character address goes in address")
        if address is not None and not is_scope_address(address):
            raise ValueError("a scope address is the 20 characters of a-z and 2-7 that go on a post")
        derived = scope_address(key) if key is not None else address
        if address is not None and derived != address:
            raise ValueError("that key does not give that address, so one of the two is wrong")
        with self.lock:
            named = self._scope(name)
            if named is not None and named["address"] != derived:
                raise ValueError("there is a scope called %s already, with another address. Remove it or choose another name" % name)
            held = named or next((s for s in self.scopes if s["address"] == derived), None)
            if held is None:
                held = {"name": name, "key": key, "address": derived}
                self._save_scopes(self.scopes + [held])
            elif key is not None and not held.get("key"):
                # Held to post only until now. The key adds reading.
                before, held = held, dict(held, key=key)
                self._save_scopes([held if s is before else s for s in self.scopes])
        return self._scope_view(held)

    def scope_list(self):
        return [self._scope_view(entry) for entry in self.scopes]

    def scope_remove(self, name):
        with self.lock:
            entry = self._scope_named(name)
            self._save_scopes([s for s in self.scopes if s is not entry])
        return {"removed": entry["name"]}

    def scope_key(self, name):
        """The key itself, for a person to pass on by hand. The MCP server never calls this."""
        entry = self._scope_named(name)
        if not entry.get("key"):
            raise ValueError("scope %s is held to post only, so there is no key here" % entry["name"])
        return {"name": entry["name"], "key": entry["key"], "address": entry["address"]}

    def scope_share(self, name, to, access):
        """Hand a scope to a partner in a sealed message. read gives the key, write only the address.

        Only to a partner in the address book, by name or key. An address is
        learned from the board and from messages, so it can be anyone's, and
        the key would be sealed to whoever it was learned from: a post asking
        for a scope would get it.
        """
        entry = self._scope_named(name)
        if access not in ("read", "write"):
            raise ValueError("access is read, which gives the key to read and post, or write, which gives the address to post only")
        if access == "read" and not entry.get("key"):
            raise ValueError("scope %s is held to post only, so it can only be shared with access write" % entry["name"])
        partner = self.partner_by_key(to) if is_key(str(to)) else self.partner_by_name(to)
        if partner is None:
            raise ValueError("a scope is shared only with a partner in your address book, by name. Never with an address, which can be anyone's")
        share = {"name": entry["name"], "key": entry["key"]} if access == "read" else {"name": entry["name"], "address": entry["address"]}
        w, key = self.address_for(partner["name"])
        # The archive keeps what was shared and with whom, never the key.
        sent = self._send(w, key, partner["name"], "Scope %s, shared to %s." % (entry["name"], "read and post" if access == "read" else "post only"), {"aamio_scope": share}, archived_data={"aamio_scope": {"name": entry["name"], "access": access}})
        return dict(sent, scope=entry["name"], access=access)

    def _shared_scope_name(self, partner, name):
        """The name a scope from a partner is kept under: the partner's name, a dot and the scope's.

        A partner names its own scopes, and a name is where posts go. Kept
        under the bare name, a partner could take review before review was
        made here, and the posts meant for it would go where that partner reads.
        """
        self._scope_name_ok(name)
        prefix = re.sub(r"[^A-Za-z0-9._-]+", "-", partner["name"]).strip("._-")[:24] or key_hash(partner["key"])[:8]
        return ("%s.%s" % (prefix, name))[:64]

    def _take_scope_share(self, entry, apply=True):
        """A scope in an incoming message. Kept only when it came sealed and
        verified from a partner in the address book, and not seen before. The
        key is taken out of the message either way, and aamio_scope is replaced
        whatever it holds and wherever it sits, so whoever reads the message
        never sees a key in it. With apply False nothing is kept, and the key
        still comes out: for a message read on a channel that was muted
        meanwhile, which stays on the record and goes to the archive."""
        body = entry.get("body")
        if not isinstance(body, dict):
            return
        if "aamio_scope" in body:
            body["aamio_scope"] = {"kept": False, "note": "not kept: a scope is shared in data.aamio_scope"}
        data = body.get("data")
        if not isinstance(data, dict) or "aamio_scope" not in data:
            return
        share = data["aamio_scope"]
        if not isinstance(share, dict):
            data["aamio_scope"] = {"kept": False, "note": "not kept: data.aamio_scope is an object with name, and key or address"}
            return
        key = share.get("key")
        view = {"shared_as": share.get("name") if isinstance(share.get("name"), str) else None, "can_read": key is not None, "kept": False}
        partner = self.partner_by_key(entry.get("from_key")) if entry.get("from_key") else None
        if not apply:
            view["note"] = "not kept: this channel was muted while the message was being read, so nothing from it is taken"
        elif not (entry.get("verified") and entry.get("encrypted") and entry.get("known_contact") and partner is not None):
            view["note"] = "not kept: a scope is only taken when it comes sealed from a partner in your address book"
        elif entry.get("replay"):
            view["note"] = "not kept again: this message arrived before, and a scope removed since stays removed"
        else:
            try:
                local = self._shared_scope_name(partner, share.get("name"))
                view.update(self.scope_add(local, key=key, address=None if key is not None else share.get("address")), kept=True)
            except Exception as error:
                # This share alone, and nothing held that was not saved. The
                # rest of the messages are delivered either way.
                view["note"] = "not kept: %s" % error
        data["aamio_scope"] = view

    # ------------------------------------------------------------ inbox --

    def _retire_channel(self, channel):
        """Keep both channels, also when old state used one label twice."""
        base = "%s-%d" % (channel.label, channel.expire_at)
        label = base
        suffix = 1
        while label in self.channels and self.channels[label] is not channel:
            label = "%s-%d" % (base, suffix)
            suffix += 1
        channel.label = label
        self.channels[label] = channel

    def _wanted_allow(self):
        """The list the inbox should carry now: the partners' keys, or none while
        there are no partners, since a first contact has nobody to name."""
        return [p["key"] for p in self.partners] if self.partners else None

    def _inbox_matches(self, inbox, wanted):
        # No partners: an inbox open to anyone matches, and so does one that
        # takes any signed key, which is what the last removal leaves behind.
        if wanted is None:
            return list(inbox.allow or []) in ([], ["*"])
        return sorted(inbox.allow or []) == sorted(wanted)

    def _rotate_inbox(self, reason):
        """A new inbox with the list as it is now; the old one is dealt with by what changed.

        Keys only added, or an old inbox open to anyone: the old one is still
        read until it expires, since whoever was told the address may still
        write there, and an open one is said to be open until then. A key
        removed: the old one is muted, kept for its records and its receipt but
        read no more, so nothing from the removed key arrives through the
        address it was given. That is this runtime's delivery stopping, not a
        revocation: the service takes the write until the thread expires.

        A rotation that fails leaves the old inbox in use, and says so.
        """
        old = self.channels.get("inbox")
        wanted = self._wanted_allow()
        if wanted is None and old is not None and old.allow:
            # The last partner is gone. An inbox open to anyone would take
            # unsigned writes at an address the partners had: signed only, and
            # every message shown as an unknown key.
            wanted = ["*"]
        status, data, read_key, w = self.client.open_thread(INBOX_TTL, wanted)
        if status != 201:
            what = "the inbox could not be opened again after %s: %s %s. The old inbox stays in use with its old list." % (reason, status, data)
            self._note_trouble("inbox", "rotation_failed", what, w=old.w if old else None)
            return {"rotated": False, "inbox": old.w if old else None, "allow": self._allow_names(old.allow if old else []), "error": what}
        inbox = Channel("inbox", read_key, w, data["expire_at"], wanted)
        outcome = {"rotated": True, "inbox": w, "allow": self._allow_names(inbox.allow), "expire_at": inbox.expire_at}
        with self.lock:
            if old is not None:
                self._retire_channel(old)
            self.channels["inbox"] = inbox
        # Every generation is judged, not only the one just retired: an inbox
        # from two rotations ago that still names the removed key was read on
        # until it expired, and delivered that key's messages as an unknown
        # contact.
        muted = self._mute_generations(reason)
        if old is not None:
            if not old.muted and not old.allow:
                self._note(old, "open", "inbox %s was open to anyone and is still read until %d; after %s the new inbox %s names %d key(s)" % (old.w, old.expire_at, reason, w, len(inbox.allow or [])))
            outcome["old_inbox"] = {"w": old.w, "muted": old.muted, "until": old.expire_at}
        if muted:
            outcome["muted"] = muted
        self.save_state()
        self.log("inbox %s until %d, %s%s" % (w, inbox.expire_at, reason, " (allowlist %d keys)" % len(inbox.allow) if inbox.allow else ""))
        outcome["presence"] = self.publish_presence(force=True)
        return outcome

    def _allow_names(self, allow):
        return [self.name_for_key(k) or k for k in (allow or [])]

    def _mute_generations(self, reason):
        """Every inbox generation that names a key no longer in the address book is muted.

        Muted means read no more: no poller, nothing handed over, the record
        and the receipt kept until the address expires. It is this runtime's
        delivery stopping, not a revocation; the service takes the removed
        key's writes until the thread expires. An open generation, or one that
        takes any signed key, names nobody and is left as it is.
        """
        partners = {p["key"] for p in self.partners}
        current = self.channels.get("inbox")
        muted = []
        for channel in list(self.channels.values()):
            if channel is current or channel.muted or not channel.label.startswith("inbox"):
                continue
            gone = [k for k in (channel.allow or []) if k != "*" and k not in partners]
            if not gone:
                continue
            # Under the lock poll holds while it applies a message, so a
            # message being applied as the partner goes sees the mute before
            # it binds or shares anything.
            with self.lock:
                channel.muted = True
            muted.append(channel.w)
            self._note(channel, "muted", "inbox %s is read no more after %s: %d removed key(s) can still write there until %d, and nothing from there is delivered" % (channel.w, reason, len(gone), channel.expire_at))
        return muted

    def _muted_address(self, w):
        with self.lock:
            return any(c.muted and c.w == w for c in self.channels.values())

    def ensure_inbox(self):
        inbox = self.channels.get("inbox")
        # A gone inbox is opened again at once. A write to the old address
        # opens a thread there with none of this inbox's allowlist, so the
        # partners are pointed at a new one that has it. The old address is
        # still read until its time runs out, for whoever writes there anyway.
        # So is an inbox whose list no longer matches the address book: a
        # partner added or removed while this process was not running, or by
        # an older version that changed partners.json and nothing else.
        usable = inbox is not None and inbox.expire_at - time.time() > RENEW_BEFORE and not inbox.gone
        if usable and self._inbox_matches(inbox, self._wanted_allow()):
            return inbox
        reason = "the address book changed" if usable else ("the inbox was gone" if inbox is not None and inbox.gone else "renewal")
        outcome = self._rotate_inbox(reason)
        if outcome["rotated"]:
            return self.channels["inbox"]
        if inbox is None or inbox.gone or inbox.expire_at <= time.time():
            raise RuntimeError("could not open inbox: %s" % outcome["error"])
        # The old one still holds; it is read on, and attention says why.
        return inbox

    def publish_presence(self, force=False):
        """Where this runtime can be reached, published; a failure said, and tried again soon.

        A failed publish used to be silent and to count as a fresh one, so the
        new inbox went unpublished for a minute while the record from before
        still pointed partners at the old address, which refused the one just
        added. Now attention says so, and the next try comes after a short
        wait that doubles up to the normal interval, so a service in trouble
        is not asked every two seconds.
        """
        now = time.time()
        failed = getattr(self, "presence_failed", False)
        if not force:
            fresh = now - self.presence_at < PRESENCE_REFRESH
            retry = failed and now >= getattr(self, "presence_retry_at", 0.0)
            if fresh and not retry:
                return None
        inbox = self.channels.get("inbox")
        if inbox is None:
            return None
        body = json.dumps({"w": inbox.w, "tags": self.tags[:8], "ttl": PRESENCE_TTL}, separators=(",", ":"))
        status, data = self.client.presence_put(self.keys.public, body, self.keys.sign(presence_signing_input(self.keys.public, body)))
        self.presence_at = now
        if status != 200:
            backoff = min(float(PRESENCE_REFRESH), max(2.0, 2 * getattr(self, "presence_backoff", 0.0)))
            self.presence_backoff = backoff
            self.presence_retry_at = now + backoff
            self.presence_failed = True
            self._note_trouble("presence", "presence_failed", "presence for inbox %s could not be published: %s %s. A partner who looks you up is sent to the address published before, while that record lives, and may be refused there. The next try is in %d seconds." % (inbox.w, status, data, backoff), w=inbox.w)
            return False
        self.presence_ok_at = now
        self.presence_failed = False
        self.presence_backoff = 0.0
        return True

    # --------------------------------------------------------- channels --

    def open_channel(self, label, ttl, allow_names=None, gate=None):
        if label in self.channels or label.startswith("inbox"):
            raise ValueError("channel exists or reserved: " + label)
        keys = []
        for name in allow_names or []:
            partner = self.partner_by_name(name)
            if partner is None:
                raise ValueError("unknown partner: " + str(name))
            keys.append(partner["key"])

        if gate is not None:
            gate = check_gate(gate)

        status, data, read_key, w = self.client.open_thread(int(ttl), keys or None, gate)
        if status != 201:
            raise RuntimeError("could not open channel: %s %s" % (status, data))
        channel = Channel(label, read_key, w, data["expire_at"], keys)
        with self.lock:
            self.channels[label] = channel
        self.save_state()
        # The gate is in the answer whether or not there is one, since a channel
        # with no conditions answered exactly like one whose gate went nowhere.
        # It is not kept here: the inbox holds it and GET /{w}/gate serves it,
        # and a second copy on this machine could only disagree with the first.
        return {"label": label, "w": w, "expire_at": channel.expire_at, "allow": [self.name_for_key(k) or k for k in keys], "gate": gate}

    def close_channel(self, label):
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.delete(channel.w, channel.read_key)
        channel.closed = True
        with self.lock:
            self.channels.pop(label, None)
        self.save_state()
        return {"label": label, "status": status, "deleted": status == 200}

    def channel_list(self):
        # expired, since a channel past its time was listed like any other
        # until a read took it away.
        return [{"label": c.label, "w": c.w, "expire_at": c.expire_at, "seconds_left": max(0, int(c.expire_at - time.time())), "expired": c.expire_at <= time.time(), "allow": [self.name_for_key(k) or k for k in c.allow], "received": len(c.received), "muted": c.muted} for c in self.channels.values()]


    # ------------------------------------------------------------ board --

    def ensure_board_inbox(self, seconds=900):
        """An inbox for board answers: any key, signed only. Reused while it lasts.

        It cannot have an allowlist of partners: whoever answers a post is by
        definition someone we have not met. X-Allow: * is the middle ground,
        and the answers themselves are sealed to our key, so the open address
        does not mean an open conversation.
        """
        held = self.channels.get("board")
        if held and held.expire_at - time.time() > seconds and not held.gone:
            return held
        ttl = min(INBOX_TTL, max(int(seconds) + 60, 900))
        status, data, read_key, w = self.client.open_thread(ttl, ["*"])
        if status != 201:
            raise RuntimeError("could not open the board inbox: %s %s" % (status, data))
        channel = Channel("board", read_key, w, data["expire_at"], ["*"])
        with self.lock:
            if held is not None:
                self._retire_channel(held)
            self.channels["board"] = channel
        self.save_state()
        self.log("board inbox %s until %d (any key, signed only)" % (w, channel.expire_at))
        if self.listener is not None:
            self._start_poller(channel)
        return channel

    def board_post(self, kind, title, text, tags=None, ttl=BOARD_TTL, lang=None, deadline=None, scope=None):
        """Put a need or an offer on the board. The reply inbox is opened for you.

        With scope, the name of a scope held here, the post carries that
        scope's address and is unlisted: only a find with the scope's key
        returns it. Unlisted is not private.
        """
        # Before the inbox is opened, so a name that is not here costs nothing.
        held = self._scope_named(scope) if scope is not None else None
        channel = self.ensure_board_inbox(int(ttl))
        # The board refuses a post that would outlive the inbox behind it, so
        # that an address on the board is always an address that still works.
        # At the top of the range the inbox cannot be opened for longer than
        # the post asked for, so the post gives way, not the promise.
        life = min(int(ttl), int(channel.expire_at - time.time()))
        if life < int(ttl):
            self.log("board post shortened to %ds to stay inside the inbox" % life)
        fields = {"kind": kind, "title": title, "text": text, "w": channel.w, "ttl": life}
        if tags:
            fields["tags"] = list(tags)[:8]
        if lang:
            fields["lang"] = lang
        if deadline:
            fields["deadline"] = deadline
        if held is not None:
            # Inside the signed body, so nobody can post the same bytes without it.
            fields["scope"] = held["address"]
        body = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        # The work the board advises is done without asking, as on an inbox,
        # over the same bytes that are signed. The number is the board's, read
        # from its descriptor once, never a constant of ours: a board that
        # advises none gets no header.
        bits = self._board_advised_bits()
        work = solve_board(self.keys.public, body, bits) if bits else None
        status, data = self.client.board_post(body, self.keys.public, self.keys.sign(board_signing_input(self.keys.public, body)), work)
        if status not in (200, 201):
            raise RuntimeError("board post failed: %s %s" % (status, data))
        self.archive("board", {"kind": "posted", "at": time.time(), "post": data})
        # Where the answers go, and how to read them, in the answer itself. An
        # agent took board replies for the whole inbox, got nothing back, and
        # spent an hour decrypting by hand what read would have shown at once.
        posted = {"post": data, "inbox": channel.w, "answers_arrive_on": "board", "read_them_with": "Read them with read, aamio read on the command line and aamio_read over MCP, which shows every message on your inboxes. board replies lists only the answers, the messages that name a post of yours or arrived on a board inbox, and says how many it left out."}
        if held is not None:
            posted["scope"] = held["name"]
        return posted

    def _board_advised_bits(self):
        """What the board advises posts to carry, read from its descriptor once per runtime."""
        cached = getattr(self, "board_advised_bits", None)

        if cached is not None:
            return cached

        try:
            status, descriptor = self.client.board_descriptor()
        except Exception:
            status, descriptor = 0, None

        self.board_advised_bits = board_advised_bits(descriptor) if status == 200 else 0

        return self.board_advised_bits

    def board_find(self, kind=None, tags=None, lang=None, key=None, after=0, wait=0, min_work_bits=0, scope=None):
        """Live posts that match. A tag covers its dotted children. min_work_bits keeps only posts whose work_bits is at least that.

        With scope, the name of a scope held here with its key, the find reads
        that scope instead of the public board.
        """
        held = self._scope_named(scope) if scope is not None else None
        if held is not None and not held.get("key"):
            raise ValueError("scope %s is held to post only. Reading it takes the key, which a partner can share with access read" % held["name"])
        body = {"after": int(after)}
        if kind:
            body["kind"] = kind
        if tags:
            body["tags"] = list(tags)[:20]
        if lang:
            body["lang"] = lang
        if key:
            body["key"] = key
        if wait:
            body["wait"] = min(int(wait), 25)
        if min_work_bits:
            body["min_work_bits"] = int(min_work_bits)
        if held is not None:
            # In the body and nowhere else. A board older than scopes answers
            # 400 to the field, so it never reads the public board instead.
            body["scope_key"] = held["key"]
        status, data = self.client.board_find(body, int(wait or 0))
        if status != 200:
            raise RuntimeError("board find failed: %s %s" % (status, data))
        if held is not None:
            # The answer names the scope it read. Without that it did not read this one.
            if data.get("scope") != held["address"]:
                raise RuntimeError("the board did not say it read scope %s, so these posts are not shown" % held["name"])
            data["scope_name"] = held["name"]
        for post in data.get("posts", []):
            if post.get("w") and post.get("key"):
                with self.lock:
                    self.peers[post["w"]] = post["key"]
        return data

    def board_get(self, post_id):
        """The post, or None when the board says there is none. Anything else raises.

        Every status but 200 used to be None, and the caller turned None into
        "no live post with that id". A board that was down, rate limiting or
        unreachable was therefore reported as a post that does not exist, which
        is the opposite of what a reader should do about it.
        """
        status, data = self.client.board_get(post_id)
        if status == 200:
            return data
        if status in (404, 410):
            return None
        raise RuntimeError("the board answered %s for post %s, so whether that post is live is unknown. Ask again rather than treating it as gone" % (status, post_id))

    def board_tags(self):
        status, data = self.client.board_tags()
        if status != 200:
            raise RuntimeError("board tags failed: %s %s" % (status, data))
        return data

    def board_withdraw(self, post_id):
        body = json.dumps({"at": int(time.time())}, separators=(",", ":"))
        status, data = self.client.board_withdraw(post_id, body, self.keys.sign(board_delete_signing_input(post_id, body)))
        if status != 200:
            raise RuntimeError("withdraw failed: %s %s" % (status, data))
        self.archive("board", {"kind": "withdrawn", "at": time.time(), "id": post_id})
        return data

    def board_answer(self, post, text=None, data=None, scope=None):
        """Answer a post, sealed to the poster's key and signed by ours.

        The message carries the post id and our reply address, so the poster
        can sort answers by post and write back. A post in a scope is never
        served by id alone, so with scope the post is looked up in that scope.
        """
        if isinstance(post, str):
            post_id = post
            post = self.board_get(post_id) if scope is None else None
            after = 0
            # A page holds up to 200 posts, and a scope can hold more. The
            # cursor goes on until the post turns up or the pages run out.
            for _ in range(50 if scope is not None else 0):
                page = self.board_find(scope=scope, after=after)
                post = next((p for p in page.get("posts", []) if p.get("id") == post_id), None)
                if post is not None or not page.get("posts") or int(page.get("next") or 0) <= after:
                    break
                after = int(page["next"])
            if post is None:
                raise LookupError("no live post with that id" + (" in scope %s" % scope if scope is not None else ". A post in a scope is found with the scope's name"))
        # The address on this answer has to outlive the post it answers.
        #
        # It did not. ensure_board_inbox() defaults to 900, which opens a
        # sixteen minute inbox, and a board post lives up to sixty. Measured in
        # the wild: an answer went out at 13:11:39 with a return address that
        # died at 13:27:39, and the poster's agent read it at 13:35:35 and
        # could not write back. Everything worked; the door had simply closed.
        #
        # The service already refuses a *post* whose reply address is shorter
        # than the post -- "a post whose address is dead reaches nobody" -- and
        # we were breaking the same rule in the other direction, in our own
        # client, with nothing checking it.
        remaining = max(0, int(post.get("expire_at") or 0) - int(time.time()))
        channel = self.ensure_board_inbox(remaining + ANSWER_MARGIN)
        own_post = post.get("key") == self.keys.public

        if channel.expire_at < (post.get("expire_at") or 0):
            self.log(
                "your reply address expires %d s before the post does, so an answer that arrives late "
                "cannot be answered back" % ((post.get("expire_at") or 0) - channel.expire_at)
            )
        if own_post:
            self.log("this post is signed by your own key, so the answer is sealed to you and nobody else will read it")
        with self.lock:
            self.peers[post["w"]] = post["key"]
        body = {"post": post["id"], "reply_to": channel.w, "from": self.keys.hash[:8]}
        body.update(self._conversation(post["key"]))
        if text is not None:
            body["text"] = str(text)
        if data is not None:
            body["data"] = data
        plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        envelope = self.keys.seal(post["key"], plaintext)
        # An answer is a send, and goes the way a send goes: one outbox entry
        # written before the first attempt, and an outcome that tells refused
        # from unknown. It used to post the envelope directly. When no answer
        # came back it raised "answer failed", with no message id and nothing
        # in the outbox, although the message may have landed; the only move
        # left was to answer again, which seals a new envelope with a new
        # nonce, and the poster cannot tell that from a second answer. From
        # the outbox the same bytes go again, and a copy is a replay there.
        entry = self._outbox_add(post["w"], post["key"], envelope, body)
        status, result = self._deliver(entry)
        self.archive("board", {"kind": "answered", "at": time.time(), "post": post["id"], "w": post["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "body": body})
        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, result)
        answer = {"post": post["id"], "w": post["w"], "message_id": entry["id"], "seq": result["seq"], "at": result["at"], "replies_arrive_on": "board", "reply_to": channel.w}
        if "met" in result:
            answer["met"] = result["met"]
            answer["proof_id"] = result.get("proof_id")
        if entry.get("gate_notes"):
            answer["notes"] = entry["gate_notes"]
        if own_post:
            answer["warning"] = "You answered your own post. The answer is sealed to your own key, so it reaches nobody but you."
        return answer

    def board_poll(self, wait=0):
        """Reads the board inboxes, and only those, when nothing listens in the background.

        `board replies` used to read them only when it was given a wait, so a
        one-shot command said `replies: []` while answers lay on the inbox: an
        outside agent watched that for twenty minutes. What waits on the other
        channels is left where it is, for `read`.
        """
        if self.listener is not None:
            return []
        collected = []
        waited = False
        for channel in [c for c in list(self.channels.values()) if c.label == "board" or c.label.startswith("board-")]:
            try:
                state, entries = self.poll(channel, 0 if waited else wait)
            except Exception as error:
                self._note(channel, "unread", "this channel could not be read: %s." % error.__class__.__name__)
                continue
            waited = waited or state in ("ok", "gone")
            collected.extend(entries)
        return collected

    def board_replies(self, post_id=None):
        """Answers received on the board inbox, decrypted and verified, newest last.

        Reads the archive as well as this process's memory. `received` lives in
        the process that polled, and the command line is one process per call,
        so a run of `board replies` used to show only what arrived inside its
        own wait -- everything from before was past the cursor and invisible,
        though it was on disk the whole time. That is how a real answer went
        unread and the silence got blamed on the sender.
        """
        out = []
        seen = set()
        skipped = []

        def wanted(entry):
            body = entry.get("body")

            if post_id is not None:
                return isinstance(body, dict) and body.get("post") == post_id

            # An answer names the post it answers, and most do. One that does
            # not is still an answer if it arrived on the address a post gave
            # out, and it used to be dropped here: the command reported no
            # replies while the inbox held two, which reads as silence from
            # the other side rather than as a filter of ours.
            if str(entry.get("channel") or "").startswith("board"):
                return True

            return isinstance(body, dict) and isinstance(body.get("post"), str)

        # Every channel, not only the ones named board: an answer can arrive on
        # a private channel opened for the conversation, and scoping this to
        # "board" once hid exactly those. That is a separate fix and it stays.
        for channel in list(self.channels.values()):
            with channel.lock:
                for entry in channel.received:
                    seen.add(entry.get("sha256"))
                    if wanted(entry):
                        out.append(entry)
                    else:
                        skipped.append(entry)

        # A board inbox is renewed while the old one still holds answers, and
        # the old one keeps its own label and its own archive. Once that
        # channel expires it leaves self.channels, and reading only the
        # channels this process holds made those answers vanish from here
        # although they had arrived, been decrypted and been written down.
        for label in sorted(self._archive_labels() | set(self.channels) | {"board"}):
            for entry in self._archived(label, "received"):
                if entry.get("sha256") in seen:
                    continue
                seen.add(entry.get("sha256"))
                if wanted(entry):
                    out.append(dict(entry, from_archive=True))
                else:
                    skipped.append(entry)

        out.sort(key=lambda e: (e.get("at") or 0, e.get("seq") or 0))
        self.board_replies_left_out = len(skipped)

        # An empty list here used to be read as an empty inbox, and the reader
        # went looking for the fault at the other end. Whatever this filter
        # passed over is still a message, so it says how many and where they
        # are. An agent that is told this does not leave the client.
        if skipped and not out:
            unopened = sum(1 for entry in skipped if not entry.get("verified"))
            unread = ", and %d of them arrived unsigned, so the body was never opened" % unopened if unopened else ""

            if post_id is not None:
                self._note_trouble("board replies", "filtered", "Nothing here answers post %s, but %d other message(s) are on your channels%s. Run board replies without a post, or read, to see them." % (post_id, len(skipped), unread))
            else:
                self._note_trouble("board replies", "filtered", "%d message(s) are here and none of them looks like a board answer, because they name no post and did not arrive on a board inbox%s. Run read to see them." % (len(skipped), unread))

        return out

    def _archive_labels(self, prefix=""):
        """Labels this runtime has an archive for, the ones a board inbox uses."""
        home = getattr(self, "home", None)

        if not home or not getattr(self, "archive_enabled", False):
            return set()

        try:
            names = os.listdir(os.path.join(home, "archive"))
        except OSError as error:
            self._note_trouble("archive", "unread", "the archive could not be listed (%s), so answers written down earlier are not in this result" % error.__class__.__name__)
            return set()

        return {name[: -len(".jsonl")] for name in names if name.endswith(".jsonl") and name.startswith(prefix)}

    def _archived(self, label, kind):
        """Entries this client wrote down for a channel, oldest first. Silent
        when archiving is off or the file is not there: an empty archive is not
        an error, it is a client that was told not to keep one."""
        home = getattr(self, "home", None)

        if not home or not getattr(self, "archive_enabled", False):
            return []

        path = os.path.join(home, "archive", "%s.jsonl" % label)

        if not os.path.isfile(path):
            return []

        found = []

        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except ValueError:
                    continue

                if isinstance(record, dict) and record.get("kind") == kind:
                    found.append(record)

        return found

    def board_reply_address(self):
        """Where answers to our answers would arrive, and whether it is still
        open. A board inbox that has expired is the difference between "nobody
        replied" and "nobody could"."""
        channel = self.channels.get("board")

        if channel is None:
            return {"w": None, "open": False, "why": "No board inbox on this machine. One is opened when you answer or post."}

        left = int(channel.expire_at - time.time())

        if left > 0:
            return {"w": channel.w, "open": True, "expires_at": int(channel.expire_at), "seconds_left": left}

        return {
            "w": channel.w,
            "open": False,
            "expires_at": int(channel.expire_at),
            "why": "The address you answered from closed %d s ago. Anything sent to it after that was refused at the door, "
                   "so an empty result here does not mean nobody wrote back." % -left,
        }

    def open_channel_with(self, key, ttl=900, label=None, reply_to=None, note=None):
        """A private channel only that key may write to, with its address handed over.

        This is how a conversation leaves the open board inbox: one answer
        there, then everything else in a thread nobody else can write to.
        """
        if not is_key(str(key)):
            partner = self.partner_by_name(str(key))
            if partner is None:
                raise ValueError("not a key and not a known partner: " + str(key))
            key = partner["key"]
        label = label or ("with-" + key_hash(key)[:8])
        if label in self.channels:
            label = "%s-%d" % (label, int(time.time()))
        status, data, read_key, w = self.client.open_thread(int(ttl), [key])
        if status != 201:
            raise RuntimeError("could not open channel: %s %s" % (status, data))
        channel = Channel(label, read_key, w, data["expire_at"], [key])
        with self.lock:
            self.channels[label] = channel
        self.save_state()
        if self.listener is not None:
            self._start_poller(channel)
        handed = None
        if reply_to:
            body = {"channel": w, "expire_at": channel.expire_at}
            if note:
                body["text"] = str(note)
            body.update(self._conversation(key))
            envelope = self.keys.seal(key, json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            # The message that carries the address is a send, and goes through
            # the outbox like one. It was posted directly, and a refusal was a
            # RuntimeError: a traceback on the command line, with the channel
            # open and the address delivered to nobody.
            entry = self._outbox_add(reply_to, key, envelope, body)
            status, handed = self._deliver(entry)
            if status != 201:
                raise SendFailed(entry["status"], entry["id"], status, handed, opened={"label": label, "w": w, "expire_at": channel.expire_at})
        return {"label": label, "w": w, "expire_at": channel.expire_at, "with": self.name_for_key(key) or key, "address_sent_to": reply_to}

    # ----------------------------------------------------------- lookup --

    def lookup(self, names=None, wait=0):
        partners = self.partners if not names else [p for p in self.partners if p["name"].lower() in [str(n).lower() for n in names]]
        if not partners:
            return {"online": [], "offline": [], "error": "no partners to look up"}
        prefixes = [key_hash(p["key"])[:8] for p in partners]
        status, data = self.client.presence_lookup(prefixes, wait)
        if status != 200:
            return {"online": [], "offline": [p["name"] for p in partners], "error": "lookup failed: %s %s" % (status, data)}
        online = []
        found = set()
        for match in data.get("matches", []):
            partner = self.partner_by_key(match.get("key"))
            if partner is None:
                continue
            found.add(partner["name"])
            with self.lock:
                self.peers[match["w"]] = partner["key"]
            online.append({"name": partner["name"], "w": match["w"], "tags": match.get("tags", []), "expires_at": match.get("expire_at")})
        self.save_state()
        return {"online": online, "offline": [p["name"] for p in partners if p["name"] not in found]}

    def address_for(self, name):
        """The write address a partner currently answers on, from presence."""
        partner = self.partner_by_name(name)
        if partner is None:
            raise ValueError("unknown partner: " + str(name))
        result = self.lookup([name])
        for entry in result["online"]:
            return entry["w"], partner["key"]
        raise LookupError("%s is not online right now" % partner["name"])

    # ------------------------------------------------------------- send --

    def send(self, to, text=None, data=None, reply_to=None, answers=None):
        """to: a partner name, or a write address learned from presence or from a message.

        answers is the sha256 of the message this one answers, as read shows it.
        It goes in the sealed body as re, so the other side can tell which of its
        messages this is about.
        """
        if answers is not None and not is_message_hash(answers):
            raise ValueError("re is the sha256 of the message this answers: 64 lowercase hex characters, as read shows it")
        if is_key(str(to)):
            partner = self.partner_by_key(to)
            if partner is None:
                raise ValueError("key is not in partners")
            to = partner["name"]
        if isinstance(to, str) and re.fullmatch(r"[a-z2-7]{20}", to):
            key = self.peers.get(to)
            if key is None:
                raise LookupError("no key known for address %s; look the partner up or reply to a message" % to)
            return self._send(to, key, None, text, data, reply_to, answers=answers)
        w, key = self.address_for(to)
        return self._send(w, key, to, text, data, reply_to, answers=answers)

    def _send(self, w, key, partner, text=None, data=None, reply_to=None, archived_data=None, answers=None):
        """One message sealed to key and written to w.

        partner is the name presence is asked again with when that address has
        gone, and None for an address given as it is. archived_data stands in
        for data in the archive, for a message carrying what no file should.
        """
        # What the inbox asks of writers is read before anything is stored, so
        # a requirement this client cannot meet stops here with its reason,
        # rather than as an outbox entry that can never be delivered.
        advice = self._plan_for(w)
        inbox = self.ensure_inbox()
        body = {"from": self.keys.hash[:8], "reply_to": reply_to or inbox.w}
        if text is not None:
            body["text"] = str(text)
        if data is not None:
            body["data"] = data
        body.update(self._conversation(key, answers))
        plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        envelope = self.keys.seal(key, plaintext)
        # The entry exists before the first attempt, and every retry sends the
        # same bytes. The recipient hashes those bytes, so a message that
        # lands twice is marked a replay there instead of acted on twice.
        entry = self._outbox_add(w, key, envelope, body)

        # A caller with a time limit, a model on MCP whose host cuts a tool call
        # after a minute or so, is not held for work that takes longer. The work
        # goes on here, the answer comes at once, and how it ends is told on
        # the next read, where it would otherwise be a call that timed out
        # with nobody knowing whether the message went.
        budget = getattr(self, "work_budget", None)
        if budget is not None and advice.get("expected_seconds", 0) > budget:
            entry["status"] = "working"
            entry["work"] = {"bits": advice["bits"], "expected_seconds": int(advice["expected_seconds"]), "seconds_left": None if advice.get("seconds_left") is None else int(advice["seconds_left"])}
            self.save_outbox()
            threading.Thread(target=self._deliver_after_work, args=(entry, body, key, archived_data), daemon=True).start()
            return {
                "to": self.name_for_key(key) or key,
                "w": w,
                "message_id": entry["id"],
                "status": "working",
                "work": entry["work"],
                "note": "This inbox asks for %d bits of proof of work, about %s here, so it is being done in the background and the message is sent when it is done. aamio_pending shows it until then, and the next aamio_read says how it ended." % (advice["bits"], describe_seconds(advice["expected_seconds"])),
            }

        status, result = self._deliver(entry)

        if status in (404, 410) and partner is not None:
            # The partner may have renewed its inbox. Ask presence again, once.
            # A new address means new bytes, so this is a new outbox entry.
            w, key = self.address_for(partner)
            envelope = self.keys.seal(key, plaintext)
            entry = self._outbox_add(w, key, envelope, body, replaces=entry["id"])
            status, result = self._deliver(entry)

        archived = body if archived_data is None else dict(body, data=archived_data)
        record = {"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": entry["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": archived}
        # The archive is a record of the send, not the send. A full disk after
        # a 201 raised here, and the caller heard an error for a message that
        # was delivered, and might send it again as new bytes: a real duplicate.
        archive_error = self._archive_sent(record)

        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, result)

        sent = {"to": record["to"], "w": entry["w"], "message_id": entry["id"], "seq": result["seq"], "at": result["at"], "sha256": result["sha256"], "expire_at": result["expire_at"]}
        # Only from an inbox with a gate: what it found, and what the caller
        # should hear although the message went out.
        if "met" in result:
            sent["met"] = result["met"]
            sent["proof_id"] = result.get("proof_id")
        if entry.get("gate_notes"):
            sent["notes"] = entry["gate_notes"]
        if archive_error is not None:
            sent["archive_error"] = archive_error
        return sent

    def _archive_sent(self, record):
        """Write a sent record, and say what went wrong instead of raising it."""
        try:
            self.archive("sent", record)
        except Exception as error:
            self.log("archive sent %s: %s" % (record.get("message_id"), error))
            return "%s: %s" % (error.__class__.__name__, error)
        return None


    # ----------------------------------------------------------- outbox --

    def _outbox_add(self, w, key, envelope, body, replaces=None):
        """One durable entry per logical message, written before the first attempt."""
        entry = {
            "id": "m-" + sha256hex("%s|%s|%s" % (self.keys.public, w, envelope))[:16],
            "w": w,
            "to_key": key,
            "envelope": envelope,
            "summary": {k: v for k, v in body.items() if k in ("post", "reply_to", "channel")},
            # For the trace: what the message was made of, without what it said.
            "shape": message_shape(body, envelope),
            "created_at": int(time.time()),
            "attempts": 0,
            "status": "sending",
            "last_status": None,
            "replaces": replaces,
            # This entry is the outbox's to hand out and to drop. An entry built by a
            # caller and delivered directly is not, and its absence from the outbox
            # means it was never there rather than that somebody dropped it.
            "tracked": True,
        }
        with self.lock:
            self.outbox[entry["id"]] = entry
        self.save_outbox()

        return entry

    # ------------------------------------------------------------- gate --

    def _gate_for(self, w):
        """What an inbox asks of writers, read once per address.

        A gate never changes while its thread lives, so one read is enough. An
        inbox without a gate, or one whose gate cannot be read right now, gives
        {}: the message then goes out without work, and if the inbox did require
        some, its 428 carries the gate and is answered once.
        """
        gates = getattr(self, "gates", None)

        if gates is None:
            gates = self.gates = {}

        if w in gates:
            return gates[w]

        left = None
        try:
            if hasattr(self.client, "gate_timed"):
                status, data, left = self.client.gate_timed(w)
            else:
                status, data = self.client.gate(w)
        except Exception:
            status, data = 0, None

        # Only a gate that was actually read is kept. A 404 is an inbox nobody
        # has opened yet, and it may be opened with a gate a moment later.
        if status == 200 and isinstance(data, dict):
            gates[w] = data
            if left is not None:
                self._gate_clock()[w] = (left, time.monotonic())
            return data

        return {}

    def _forget_gate(self, w):
        """The gate read for w, and the time it said, may belong to an inbox that is not there now."""
        getattr(self, "gates", {}).pop(w, None)
        self._gate_clock().pop(w, None)

    def _plan_for(self, w):
        """What the gate of w asks, read again once before a no that rests on a gate read earlier.

        A gate never changes while its thread lives, which is why it is kept.
        But an address can have more than one life. The time a kept gate said
        counted down to nothing and stayed there, and a new inbox at the same
        address, with no gate at all, was refused on the old one's terms
        without the service ever being asked. One more read, only when the
        answer would be no, is what that costs.
        """
        cached = w in getattr(self, "gates", {})
        try:
            return gate_plan(self._gate_for(w), w, self.host, self._seconds_left(w))
        except GateStop:
            if not cached:
                raise
            self._forget_gate(w)
            return gate_plan(self._gate_for(w), w, self.host, self._seconds_left(w))

    def _gate_clock(self):
        clock = getattr(self, "gate_clock", None)
        if clock is None:
            clock = self.gate_clock = {}
        return clock

    def _seconds_left(self, w):
        """How long w still takes writes, counted down from what its gate said, or None."""
        said = self._gate_clock().get(w)
        if said is None:
            return None
        left, at = said
        return max(0, left - (time.monotonic() - at))

    def _post(self, w, body_text, notes, entry=None):
        """POST to an inbox with the work its gate asks for, answering a 428 once.

        Never more than one more attempt. Each costs a place in the rate window,
        and a 428 after that means the inbox wants something this client cannot
        give it. Work already done and refused anyway is not done again: the
        same bytes give the same nonce and the same refusal. notes collects what
        the caller should hear although the message went out.
        """
        signature = self.keys.sign(thread_signing_input(w, body_text))
        advice = self._plan_for(w)
        notes.extend(advice["notes"])
        status, result = self._post_with_work(w, body_text, signature, advice["bits"], self._seconds_left(w), entry)

        if status == 428 and isinstance(result, dict) and isinstance(result.get("gate"), dict):
            self.gates[w] = result["gate"]
            left = result.get("seconds_left") if isinstance(result.get("seconds_left"), int) else None
            if left is not None:
                self._gate_clock()[w] = (left, time.monotonic())
            asked = gate_plan(result["gate"], w, self.host, left)
            notes.extend(note for note in asked["notes"] if note not in notes)

            if asked["bits"] and asked["bits"] != advice["bits"]:
                status, result = self._post_with_work(w, body_text, signature, asked["bits"], left, entry)

        return status, result

    def _about_to_post(self, entry):
        """The last moment before bytes leave this machine, for every path that sends.

        aamio_outbox_forget and close() both say nothing is sent afterwards, so the check
        belongs where the sending is and not where the work is. It guarded the
        proof-of-work line alone for a few hours, and a send with no work went out
        through the other line unchecked and unmarked.

        The flag it sets is what lets forget say whether it stopped anything.
        """
        if entry is None:
            return

        with self.lock:
            dropped = entry.get("tracked") is True and self.outbox.get(entry["id"]) is not entry

            if dropped or getattr(self, "home_released", False) is True:
                raise WorkDropped(
                    "this message was dropped before it was sent, so nothing was sent"
                )

            entry["posting"] = True

    def _post_with_work(self, w, body_text, signature, bits, seconds_left=None, entry=None):
        if not bits:
            self._about_to_post(entry)

            return self.client.post(w, body_text, self.keys.public, signature)

        # While the work runs nothing has been sent, and the entry says so, so
        # a process that stops here leaves a message it knows was not sent
        # rather than one whose fate is unknown.
        if entry is not None:
            entry["status"] = "working"
            self.save_outbox()

        # The work stops when the inbox would close, less a few seconds for the
        # post itself: past that point a nonce buys nothing but a 410.
        deadline = None if seconds_left is None else time.monotonic() + max(0, seconds_left - 5)
        nonce = gate_solve(w, self.keys.public, body_text, bits, deadline)

        # None is gate_solve saying the time ran out, and it used to fall through to
        # the line below, which sets the flag that means bytes were on their way. The
        # transport was never called, and forget answered attempted, already_sending:
        # true, about a message that had not moved. A caller told that cannot write a
        # replacement for something that was never sent.
        if nonce is None:
            raise GateStop(
                "the inbox asks for %d bits of work and the time it still takes writes ran out before a nonce was found, so nothing was sent" % bits,
                "Nothing left this machine. Open a thread with a longer life, or send this to an inbox whose gate asks for less: the same bytes are still here under this message id.",
            )

        # The work is done and nothing has left yet.
        self._about_to_post(entry)

        if entry is not None:
            entry["status"] = "sending"
            self.save_outbox()

        if nonce is None:
            raise GateStop(
                "The proof of work of %d bits was not done before the inbox stops taking writes, so the work was stopped and nothing was sent." % bits,
                "The estimate before it started said it would fit, and this time it took longer, which happens: the work is a lottery. Ask the owner for a longer inbox, or send from a machine with more compute.",
            )

        return self.client.post(w, body_text, self.keys.public, signature, "text/plain", nonce)

    # ----------------------------------------------------------- deliver --

    def _deliver(self, entry):
        """Send the stored bytes once, and record what the answer allows us to claim."""
        entry["attempts"] += 1
        entry["status"] = "sending"
        self.save_outbox()
        notes = []

        try:
            status, result = self._post(entry["w"], entry["envelope"], notes, entry)
        except GateStop as stop:
            # Nothing left this machine and nothing will. That is not the same as
            # the service turning bytes away: refused with no answer behind it read
            # as an attempt that left, so forget said already_sending about a
            # message the transport had never been asked to send, and a caller told
            # that cannot compose a replacement for something that never went.
            #
            # Unless an earlier attempt is still open. A stop now settles this
            # decision, not that one.
            entry["status"] = "unknown" if entry.get("ever_open") else "stopped"
            entry["error"] = stop.reason
            entry["last_at"] = int(time.time())
            self.save_outbox()
            raise

        if notes:
            entry["gate_notes"] = notes

        self._record_answer(entry, status, result)
        self.save_outbox()
        # After the outcome is saved, and unable to change it.
        self._trace_safely("sent", self._trace_sent, entry, status, result)

        return status, result

    def _record_answer(self, entry, status, result=None):
        """What one answer changes about a message, which is less than it looks.

        The status on an entry used to be the last HTTP answer wearing the name of an
        outcome. Every answer that was not 201 and not silence became refused: a 500,
        a 429, a 503. refused is not a status aamio_pending shows, so a message whose
        fate was wide open vanished from the list of open ones, while its own note
        said it might have been stored. forget then called the same entry attempted.

        Certainty only ever narrows, and only in one direction. A delivery settles a
        message for good. A refusal the service will give again settles it, but only
        if nothing before it was left open: an attempt that got no answer may be on
        the other side, and a 410 an hour later says the thread is gone, not that the
        first attempt never landed.
        """
        entry["last_status"] = status
        entry["last_at"] = int(time.time())
        entry["attempts"] = int(entry.get("attempts") or 0)

        # An inbox that is not there, or has expired, takes its gate with it:
        # the next send to this address reads the gate of whatever is there then.
        if status in (404, 410):
            self._forget_gate(entry["w"])

        if status == 201:
            entry["status"] = "delivered"
            entry["seq"] = (result or {}).get("seq") if isinstance(result, dict) else None

            return

        error = (result or {}).get("error") if isinstance(result, dict) else str(result)[:200]

        if error:
            entry["error"] = error

        # No reply at all. The bytes may be on the other side.
        if status == 0:
            entry["ever_open"] = True
            entry["status"] = "unknown"

            return

        # The service turned the request away without storing it: either it will
        # say the same about these bytes for ever, or it was a rate window, which
        # is decided before the body is read. Both are settled as not stored.
        if status in SEND_NOT_STORED:
            # Unless something earlier was left open. A 410 an hour later says the
            # thread is gone now, not that an attempt which got no answer never
            # landed, and the entry used to be reported as refused and not stored.
            entry["status"] = "attempted" if entry.get("ever_open") else "refused"

            return

        # It answered, and its answer says nothing about whether it stored the
        # message first: a 500 is the service failing, not the service saying no.
        # This wore the status refused, and refused is not one of the statuses
        # pending shows, so a message whose fate was wide open vanished from the
        # list of open ones while its own note said it might have been stored.
        entry["ever_open"] = True
        entry["status"] = "attempted"

    def outbox_pending(self):
        """Messages whose fate is not settled: working, in flight, or open after an answer.

        attempted belongs here and was missing. A 500 set the status to refused, which
        is not in this list, so the one kind of message that most needs a decision was
        the one kind that did not appear on it. And then this list and outbox_retry
        disagreed about the same entry, which is why both now ask outbox_open.
        """
        return [dict(e) for e in self.outbox.values()
                if e["status"] in ("working", "sending") or outbox_open(e)]

    def _deliver_after_work(self, entry, body, key, archived_data=None):
        """The background half of a send whose work was too long to wait for.

        Every way it can end is told on the next read, since the caller was
        answered long before, and an outcome nobody hears about is a message
        that silently did or did not go.
        """
        where = "send %s" % entry["id"]
        try:
            status, result = self._deliver(entry)
        except WorkDropped as dropped:
            # Said before the generic catch below, which would have called this
            # "may or may not have been sent". It was not sent, on purpose.
            self._note_trouble(where, "dropped", "the message to %s was not sent: %s" % (self.name_for_key(key) or entry["w"], dropped))

            return
        except GateStop as stop:
            self._note_trouble(where, "refused", "the message to %s was not sent: %s" % (self.name_for_key(key) or entry["w"], stop.reason))
            return
        except Exception as error:
            self._note_trouble(where, "unknown", "the message to %s may or may not have been sent: %s. aamio_pending shows it." % (self.name_for_key(key) or entry["w"], error.__class__.__name__))
            return

        archived = body if archived_data is None else dict(body, data=archived_data)
        # A failed archive write is said beside the outcome, never instead of
        # it: it used to raise here and take the promised note with it.
        archive_error = self._archive_sent({"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": entry["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": archived})
        tail = "" if archive_error is None else ". It could not be written to the sent archive (%s), which changes nothing about the delivery" % archive_error

        if status == 201:
            self._note_trouble(where, "delivered", "the message to %s, which needed %d bits of proof of work, was delivered as seq %s%s" % (self.name_for_key(key) or entry["w"], (entry.get("work") or {}).get("bits") or 0, (result or {}).get("seq"), tail))
        else:
            self._note_trouble(where, entry["status"], "the message to %s ended %s after its proof of work, http %s%s" % (self.name_for_key(key) or entry["w"], entry["status"], status, tail))

    def outbox_retry(self, message_id=None):
        """Send the same bytes again for entries that never got a clear answer.

        The recipient marks a second copy as a replay, so this is safe for the
        transport. Whether the action behind the message is safe to repeat is
        the application's contract, not this function's.
        """
        out = []
        for entry in list(self.outbox.values()):
            if message_id is not None and entry["id"] != message_id:
                continue

            # Worth sending again, which is not the same as unsettled: a rate window
            # is settled and is exactly what a second attempt is for. One the service
            # will refuse again, or has already stored, is not.
            if not outbox_retryable(entry):
                continue

            status, _ = self._deliver(entry)
            out.append({"id": entry["id"], "w": entry["w"], "status": entry["status"], "http": status})

        return out

    def outbox_forget(self, message_id):
        """Drop an entry once its fate no longer matters. Nothing is retried after this.

        A send that is already away cannot be recalled, and this says so rather than
        reporting a clean stop: the difference decides whether the caller may compose
        a replacement.
        """
        with self.lock:
            entry = self.outbox.pop(message_id, None)
            outcome = outbox_outcome(entry)
            already = outcome not in ("never_sent", "not_found")

        self.save_outbox()

        return {
            "id": message_id,
            "forgotten": entry is not None,
            "already_sending": already,
            "outcome": outcome,
            "note": OUTBOX_NOTES[outcome],
        }

    # ---------------------------------------------------------- effects --

    def effect(self, key, fingerprint=None):
        """Has this operation already been carried out here?

        The key is the application's, not a guess from the text: something
        that names the sender, the task and the action. Returns new, done or
        conflict, and the stored result when there is one.
        """
        record = self.effects.get(str(key))

        if record is None:
            return {"state": "new", "key": key}

        if fingerprint is not None and record.get("fingerprint") not in (None, fingerprint):
            return {"state": "conflict", "key": key, "stored_fingerprint": record.get("fingerprint"), "result": record.get("result")}

        return {"state": "done", "key": key, "result": record.get("result"), "at": record.get("at")}

    def effect_done(self, key, result=None, fingerprint=None):
        """Record that it was carried out, before telling anyone it was."""
        with self.lock:
            self.effects[str(key)] = {"fingerprint": fingerprint, "result": result, "at": int(time.time())}
        self.save_effects()

        return {"state": "done", "key": key, "result": result}

    # ------------------------------------------------------------- read --

    # Only the spellings seen in the wild, and only for an answer to a post.
    # A blanket id -> post or w -> reply_to would rewrite other message kinds
    # into something they are not.
    ANSWER_ALIASES = {
        "post": ("post_id", "postId"),
        "reply_to": ("replyTo", "w", "reply_address"),
        "text": ("reply", "message"),
    }

    @classmethod
    def _canonical(cls, body):
        """The documented field names, from whatever a sender called them.

        The shape is written down in several places and still gets guessed at.
        A signed, useful answer that says post_id instead of post is not worth
        dropping on the floor. We stay strict in what we send.

        Returns the body and a note of what was renamed, kept apart from the
        body so a sender cannot put anything of ours in it.
        """
        if not isinstance(body, dict):
            return body, {}

        # Normalise an answer to a post, nothing else: without a post id in
        # some spelling this is a different kind of message and is left alone.
        if not any(name in body for name in ("post",) + cls.ANSWER_ALIASES["post"]):
            return body, {}

        renamed, conflicts = {}, {}

        for canonical, spellings in cls.ANSWER_ALIASES.items():
            present = [s for s in spellings if isinstance(body.get(s), (str, int))]

            if canonical in body:
                # Both spellings, disagreeing: the canonical one wins and the
                # disagreement is reported rather than quietly dropped. Two
                # values are only comparable when both are scalars; a field
                # holding an object is left exactly as the sender wrote it.
                if isinstance(body[canonical], (str, int)):
                    conflicts.update({s: body[s] for s in present if str(body[s]) != str(body[canonical])})
                continue

            if present:
                body[canonical] = body[present[0]]
                renamed[present[0]] = canonical
                # Two spellings carrying the same value are not a
                # disagreement. Reporting them as one asks a caller to weigh a
                # conflict that is not there.
                conflicts.update({s: body[s] for s in present[1:] if str(body[s]) != str(body[present[0]])})

        meta = {}

        if renamed:
            meta["renamed"] = renamed

        if conflicts:
            meta["conflicting_fields"] = conflicts

        return body, meta

    def _open(self, message):
        """What was said, and separately, what can be trusted about it.

        The two used to be one dict, so a plaintext JSON answer arrived as a
        wrapper with the real object stranded inside a string. Nothing
        downstream could see the fields, the answer was never matched to its
        post, and the reply address was never learned. Keeping the content and
        the metadata apart also means no sender can set a field of ours.
        """
        raw = message["body"]

        if not message.get("verified") or not message.get("from"):
            return {"text": raw}, {"signed": False, "encrypted": False, "format": "unsigned"}

        if not is_envelope(raw):
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {"text": raw}, {"signed": True, "encrypted": False, "format": "text"}

            if isinstance(parsed, dict):
                content, extra = self._canonical(parsed)
                return content, dict({"signed": True, "encrypted": False, "format": "json"}, **extra)

            return {"text": raw}, {"signed": True, "encrypted": False, "format": "json"}

        # Three things, and they used to share one except: opening the envelope,
        # reading the bytes as text, and the text happening to be JSON. Only the
        # first two say anything about whether the message can be read. `for your
        # eyes`, encrypted and signed, opened correctly and came back as text: null,
        # format: unreadable, with the cursor moved past it -- a message that had
        # arrived intact, reported as one nobody could read, and then dropped.
        #
        # The plain branch above has always handed over text that is not JSON. This
        # is the same message with a lid on it.
        try:
            plaintext = self.keys.open(message["from"], raw)
        except Exception as error:
            return {"text": None}, {"signed": True, "encrypted": True, "format": "unreadable", "error": error.__class__.__name__}

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError as error:
            return {"text": None}, {"signed": True, "encrypted": True, "format": "unreadable", "error": error.__class__.__name__}

        try:
            parsed = json.loads(text)
        except ValueError:
            return {"text": text}, {"signed": True, "encrypted": True, "format": "text"}

        if isinstance(parsed, dict):
            content, extra = self._canonical(parsed)
            return content, dict({"signed": True, "encrypted": True, "format": "json"}, **extra)

        return {"text": parsed}, {"signed": True, "encrypted": True, "format": "json"}

    def _note(self, channel, state, what, seqs=None):
        """Something a caller has to hear about, even though the read returned no messages."""
        self._note_trouble(channel.label, state, what, w=channel.w, seqs=seqs)

    def _note_trouble(self, where, state, what, w=None, seqs=None):
        note = {"channel": where, "w": w, "state": state, "what": what, "at": int(time.time())}
        with self.lock:
            if not hasattr(self, "attention"):
                self.attention = {}
            if state in ("kept_out", "unverified", "binding_conflict") and seqs is not None:
                previous = self.attention.get((where, state), {})
                note["seqs"] = previous.get("seqs", []) + list(seqs)
                note["count"] = len(note["seqs"])
                note["details"] = previous.get("details", []) + [what]
                note["what"] = "%d message(s) (seq %s): %s" % (note["count"], ", ".join(str(seq) for seq in note["seqs"]), " ".join(note["details"]))
            self.attention[(where, state)] = note
        self.log("%s: %s" % (where, what))

    def attention_taken(self):
        """What the reads since the last call could not do, once, and then cleared."""
        with self.lock:
            taken = sorted(getattr(self, "attention", {}).values(), key=lambda note: (note["at"], note["channel"]))
            self.attention = {}
        return taken

    def _read_entry(self, channel, raw):
        """Check and decode one message without lending it the service's authority."""
        message = raw if isinstance(raw, dict) else {}
        seq = message.get("seq") if type(message.get("seq")) is int else 0
        at = message.get("at") if type(message.get("at")) is int else 0
        try:
            if not isinstance(raw, dict) or type(message.get("seq")) is not int or type(message.get("at")) is not int:
                raise ValueError("invalid message metadata")
            verified, why_not, digest = check_message(channel.w, message)
            # The HTTP reader already cleared failed claims. Keep its reason
            # instead of replacing it with 'no sender' on this second check.
            if not verified:
                why_not = message.get("unverified_because") or why_not
            sender = message.get("from") if verified else None
            checked = dict(message, verified=verified, sha256=digest, **{"from": sender})
            body, meta = self._open(checked)
            known = self.name_for_key(sender)
            entry = {"channel": channel.label, "w": channel.w, "seq": seq, "at": at, "verified": verified, "from_key": sender, "known_contact": known is not None, "sender": known or ("unknown key" if sender else "unsigned"), "sha256": digest, "replay": digest is not None and digest in channel.seen, "body": body}
            entry.update(meta)
            if why_not:
                entry["unverified_because"] = why_not
            return entry
        except Exception as error:
            why = "the message could not be checked here: " + error.__class__.__name__
            return {"channel": channel.label, "w": channel.w, "seq": seq, "at": at, "verified": False, "from_key": None, "known_contact": False, "sender": "unsigned", "sha256": None, "replay": False, "body": {"text": message.get("body")}, "signed": False, "encrypted": False, "format": "unreadable", "error": error.__class__.__name__, "unverified_because": why}

    def _save_cursor(self, channel, to_seq):
        """Move the cursor and write it down, and say so if the writing fails.

        The cursor and the replay hashes go in one write, before the caller sees a
        message, so that a crash cannot redeliver. The write was allowed to throw
        straight out of poll, and the loop that calls poll logs an exception and
        sleeps -- so messages that had arrived, been checked and been appended to
        the channel never reached the queue, and the reader saw an empty inbox with
        nothing in attention.

        When the write fails the cursor stays where it was last written down. The
        same messages arrive again on the next read and the stored hashes mark them
        as replays, which is exactly what a crash would have given, and is the safe
        direction: a message twice is a nuisance, a message never is a loss.
        """
        was = channel.after
        channel.after = max(channel.after, to_seq)

        if not self._save_quietly(channel, was):
            channel.after = was

            return False

        return True

    def _set_cursor(self, channel, to_seq):
        """The cursor moves to exactly this, forwards or backwards, and is written."""
        was = channel.after
        channel.after = to_seq

        if not self._save_quietly(channel, was):
            channel.after = was

    def _save_quietly(self, channel, was=None):
        """Write the state; a failure is said in attention and never raised.

        Every save inside a poll used to be able to throw straight out at the loop
        that calls it, which logs and sleeps -- and the messages poll had already
        decoded went nowhere.
        """
        try:
            self.save_state()
        except Exception as error:
            self._note(
                channel,
                "unsaved",
                "this machine could not write down what it had read: %s: %s.%s Nothing was lost: what arrived was handed over, and anything whose place was not written down arrives again and comes back marked as a replay. Free some room or fix the permissions on the home folder, and check aamio doctor."
                % (error.__class__.__name__, error,
                   "" if was is None else " The cursor stays at %s." % was),
            )

            return False

        return True

    def poll(self, channel, wait=0, limit=None, max_bytes=None):
        """Reads one channel. With a limit, at most that many messages are handed over.

        The cursor then stops at the last message this call dealt with, and
        what the service returned beyond it is fetched again by the next poll.
        It used to be the caller that cut the list, after the cursor had moved
        past everything: the messages over the limit were gone for good.
        """
        channel.left_waiting = 0
        channel.more_at_service = False
        # A muted channel is read no more, whoever calls: the read path and the
        # listener skip it, and a library caller that asks straight out gets
        # the same answer instead of the removed partner's messages.
        if channel.muted:
            return "muted", []
        # Passed only when there is one, so a client given a plain read function, as
        # every test and every older integration hands over, is called as before.
        #
        # Both of them: the count was taken here, used to cut the list after the
        # answer had arrived, and never sent. A read for two messages still pulled
        # the whole thread over the network and threw most of it away.
        limits = {}

        if limit is not None:
            limits["limit"] = limit

        if max_bytes is not None:
            limits["max_bytes"] = max_bytes

        status, data = self.client.read(channel.w, channel.read_key, channel.after, wait, **limits)
        if status == 410:
            self._note(channel, "expired", "the thread at this address has expired, so anything written to it before now is gone and nothing more will arrive here")
            return "expired", []
        if status != 200:
            self._note(channel, "unread", "the service answered %s, so this channel was not read and there may be messages waiting" % status)
            return "error", []
        if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
            self._note(channel, "unread", "the service returned a malformed read answer; this channel was not read")
            return "error", []
        # Three answers that used to read as a quiet inbox. No thread at the
        # address: never written to, swept after expiry, or taken by a
        # restart. A reset: the cursor was past everything the thread holds, so
        # the service read from the start. And a created_at that is not the one
        # this channel knew: a new thread at the same address whose count has
        # already passed the old cursor, which the service cannot flag, since
        # it does not know what this channel has seen. In all three the old
        # cursor and the old hashes belong to another thread.
        if data.get("exists") is False:
            if not channel.gone:
                self._note(channel, "gone", "there is no thread at this address any more. It expired and was swept, or the service restarted and it went with it. A write opens a new one here with the default lifetime and without the allowlist or gate this channel was opened with" + (", so a new inbox is opened for the partners" if channel.label == "inbox" else ""))
            channel.gone = True
            channel.forget_thread()
            self._save_quietly(channel)
            return "gone", []
        channel.gone = False
        created = data.get("created_at")
        reset = data.get("reset")
        if channel.created_at is not None and created is not None and created != channel.created_at and not reset:
            self._note(channel, "restarted", "the thread at this address is a new one, opened at %s where this channel knew one opened at %s, so it is read again from the start" % (created, channel.created_at))
            channel.forget_thread()
            return self.poll(channel, 0, limit, max_bytes)
        if reset:
            self._note(channel, "restarted", (reset.get("what") if isinstance(reset, dict) else None) or "the service read this thread from the start")
            channel.observed.clear()
        channel.created_at = created

        # What the budget kept out. The service answers a byte budget honestly:
        # whole messages only, because a signed message cut in half does not
        # verify. So a thread holding one message larger than the budget answers
        # with no messages and too_large naming it -- and read that as an empty
        # inbox for as long as nothing here looked at the field. The message is
        # there, it will never arrive at this budget, and nobody was told.
        too_large = data.get("too_large")

        if isinstance(too_large, dict):
            seq = too_large.get("seq")
            size = too_large.get("bytes")
            self._note(
                channel,
                "too_large",
                "message %s on this channel is %s bytes and does not fit the byte budget this read asked for, so it was not sent. It is still there and every read at this budget will leave it. %s"
                % (seq, size, too_large.get("fix") or "Read again with a larger max_bytes, or without one."),
                seqs=[seq] if seq is not None else None,
            )

        # And what it held back that does fit: more messages after the ones sent.
        if data.get("more") is True:
            channel.more_at_service = True

        entries = []
        kept_out = []
        last_seq = None
        fetched = data.get("messages", [])
        for index, raw in enumerate(fetched):
            if limit is not None and len(entries) >= limit:
                channel.left_waiting = len(fetched) - index
                break
            entry = self._read_entry(channel, raw)
            message = raw if isinstance(raw, dict) else {}
            last_seq = entry["seq"] if last_seq is None else max(last_seq, entry["seq"])
            sender_key = entry["from_key"]
            excluded = bool(channel.allow and not (entry["verified"] and ("*" in channel.allow or sender_key in channel.allow)))
            with channel.lock:
                channel.observed[entry["seq"]] = {"seq": entry["seq"], "at": entry["at"], "sha256": entry["sha256"], "from": message.get("service_from", message.get("from")), "verified": entry["verified"], "from_key": sender_key}
            why_not = entry.get("unverified_because")
            if why_not and message.get("service_verified", message.get("verified")):
                disposition = "kept out by this channel's list" if excluded else "handed over as unverified"
                self._note(channel, "unverified", "message %s on this channel was called verified by the service and does not check out here: %s. It is %s. That is a fault in the service or an operator that lies, and whoever runs it should hear of it." % (entry["seq"], why_not, disposition), seqs=[entry["seq"]])
            if excluded:
                kept_out.append(entry["seq"])
                continue
            if entry["sha256"] is not None:
                channel.seen.add(entry["sha256"])
            # Before the message is kept, archived or shown: a scope key in it
            # goes to scopes.json or nowhere, never to the reader. And a
            # verified message that carries an address binds the sender's key
            # to it: reply_to, as always, and channel, which a handoff carries.
            # A handoff used to leave the new address without a key, so the
            # first send to it failed with no key known for the address; an
            # address another key already holds is not rebound by a claim.
            #
            # Under the lock a removal takes to mute this channel, and judged
            # message by message: a partner removed while the read was out, or
            # while this batch is being applied, shares nothing and binds
            # nothing from that moment on. The key comes out of the message
            # either way, since the message stays on the channel's record for
            # the receipt and goes to the archive. Read once before the batch,
            # the mute was missed by everything after that reading; skipped
            # whole, the share left its key in the record. Findings K1 and K2
            # of the health check of 24 September 2026.
            with self.lock:
                applying = not channel.muted
                self._take_scope_share(entry, apply=applying)
                if applying and isinstance(entry["body"], dict) and entry["verified"] and sender_key:
                    for field in ("reply_to", "channel"):
                        self._bind_claimed_address(channel, entry, field, entry["body"].get(field), sender_key)
                # And the trace: what came from this key, and what it says it
                # read of ours. Verified only, since an unsigned message can
                # claim to be from anyone and to have read anything. Whatever
                # goes wrong in the trace costs the trace, never this batch.
                if applying and entry["verified"] and sender_key:
                    self._trace_safely("received", self._trace_received, channel, entry)
            entries.append(entry)
            with channel.lock:
                channel.received.append(entry)
            # Received, readable, archived and handled are four different
            # things, and a failure at one must not be reported as the others.
            # The message above is delivered already; whether it also reached
            # the file on disk is recorded here, and is never allowed to cost
            # the rest of the batch, which is what a full disk would otherwise
            # do. Nor is it swallowed: it stays on the entry and in the log,
            # because a storage failure is worth knowing about.
            try:
                wrote = self.archive(channel.label, dict(entry, kind="received"))
                entry["archived"] = wrote is not False

                if wrote is False:
                    # Nothing went wrong and nothing was written: this folder keeps
                    # nothing decrypted. Said, so the caller does not go looking.
                    entry["archive_off"] = True
            except Exception as error:
                entry["archived"] = False
                entry["archive_error"] = "%s: %s" % (error.__class__.__name__, error)
                self.log("archive %s seq %s: %s" % (channel.label, entry["seq"], error))
        if entries:
            # The cursor moves and the hashes are stored in the same save, and
            # that save happens before the caller sees a single message. A
            # crash after this point redelivers nothing; a crash before it
            # redelivers everything, and the stored hashes mark those replays.
            #
            # It moves past a message the archive refused as well. The archive
            # is a record of what was delivered, not the delivery itself:
            # holding the cursor back would re-read that message forever while
            # the disk stayed full, and redeliver everything after it.
            self._save_cursor(channel, entries[-1]["seq"])
        if kept_out:
            # Past them as well, or the same messages are read and kept out on
            # every call. And said, since a message that does not arrive has to
            # be told from one that was never sent.
            self._save_cursor(channel, last_seq)
            opened_for = "any key, signed only" if "*" in channel.allow else "%d named key(s)" % len(channel.allow)
            self._note(channel, "kept_out", "This channel was opened for %s, and these messages did not satisfy that list as checked here. They are not handed over and not archived." % opened_for, seqs=kept_out)
        # After a reset the service's next is the cursor, and it is lower than
        # the one this channel held. Keeping the higher of the two would ask
        # past the new thread on every call and hand the same messages over
        # each time.
        #
        # A poll that stopped at its limit is the exception: the service's next
        # covers messages this call never looked at, so the cursor is the last
        # one it did look at, handed over or kept out.
        if channel.left_waiting:
            if last_seq is not None:
                # Backwards as well as forwards here, so _save_cursor's max is not
                # the rule: the service's next covers messages this call never
                # looked at. Same care about the write, though.
                self._set_cursor(channel, last_seq)
        elif type(data.get("next")) is int:
            self._set_cursor(channel, data["next"])
        # Muted since the read went out: what came back is on the record and
        # is handed to nobody.
        with self.lock:
            if channel.muted:
                return "muted", []
        return "ok", entries

    def _bind_claimed_address(self, channel, entry, field, address, sender_key):
        """A verified message that names an address binds its signer's key to it, once.

        The signature proves who made the claim, not that the claimant holds an
        address another key is already bound to. On 21 September 2026 a
        stranger's signed message naming a partner's address in channel
        replaced that partner's key, and the next send to the address was
        sealed to the stranger. So a first claim is learned, the same key again
        changes nothing, and a different key is a conflict: the binding stays,
        the message still arrives, and the conflict is on the entry and in
        attention. Whoever holds the address reaches this side through the
        partner list or a fresh handoff, not by claiming.
        """
        if not isinstance(address, str) or not re.fullmatch(r"[a-z2-7]{20}", address):
            return
        with self.lock:
            bound = self.peers.get(address)
            if bound is None:
                self.peers[address] = sender_key
                return
        if bound == sender_key:
            return
        entry.setdefault("binding_conflicts", []).append({"field": field, "address": address, "claimed_by": sender_key, "bound_to": bound})
        self._note(
            channel,
            "binding_conflict",
            "message %s names %s as %s, signed by %s, and that address is already bound to %s. The binding is kept: a signature proves who made the claim, not who holds the address. Reach the claimant through the partner list or a fresh handoff."
            % (entry["seq"], address, field, self.name_for_key(sender_key) or sender_key, self.name_for_key(bound) or bound),
            seqs=[entry["seq"]],
        )

    # ------------------------------------------------------------ trace --
    #
    # A conversation that goes wrong is hard to take apart from one side. On 25
    # September 2026 a participant answered, more than once, that the text of our
    # messages was missing, while the send log here said non-empty and delivered.
    # Both can be true: every message this runtime sends is sealed to the key it
    # goes to, and a reader without that key sees an envelope and no text. So each
    # message now says, inside the sealed body, which message it answers (re) and
    # the last one this side read and opened from the other (seen), and trace lays
    # the two sides next to each other as hashes: the sha256 the service stored,
    # byte for byte, is the one the other side read, or it is not.
    #
    # Each field is a claim about the one message it names. The review of the
    # same evening found the first version saying more than it knew: one seen
    # marked every earlier send as read, a side channel nobody had opened
    # included (R1); a message that arrived and could not be opened moved seen
    # all the same, and so did an old one sent again (R2); a trace file of the
    # wrong shape turned a delivered send into an error, which invites the same
    # message twice (R3); and listing the trace while a read met a new
    # counterpart stopped with RuntimeError (R4).

    TRACE_KEEP = 50
    TRACE_KEYS = 100

    def _trace_book(self, key):
        """The record for one key, made when first needed and kept to a bound. Called under the lock."""
        traces = self.__dict__.setdefault("traces", {})
        book = traces.get(key)

        if not isinstance(book, dict):
            book = traces[key] = {"sent": [], "received": [], "last_read": None, "active": 0}

        book["active"] = int(time.time())

        if len(traces) > self.TRACE_KEYS:
            for stale in sorted(traces, key=lambda k: (traces[k] or {}).get("active") or 0)[:len(traces) - self.TRACE_KEYS]:
                if stale != key:
                    traces.pop(stale, None)

        return book

    def _save_trace(self):
        """Written when it changes. A trace that cannot be written costs the trace and nothing else."""
        try:
            self._save_json("trace.json", self.__dict__.get("traces") or {}, private=True)
        except Exception as error:
            getattr(self, "log", lambda line: None)("trace.json: %s: %s" % (error.__class__.__name__, error))

    def _trace_safely(self, what, update, *args):
        """The trace is diagnostics: whatever goes wrong in it costs the trace, never the send or the read it records."""
        try:
            update(*args)
        except Exception as error:
            try:
                getattr(self, "log", lambda line: None)("trace %s: not recorded: %s: %s" % (what, error.__class__.__name__, error))
            except Exception:
                pass

    def _conversation(self, key, answers=None):
        """The two fields a message carries about the conversation it is part of."""
        fields = {}

        if answers is not None:
            fields["re"] = answers

        # seen is the last message from this key that was read here and could be
        # opened. A trace that cannot say leaves it out, and never stops a send.
        try:
            book = (self.__dict__.get("traces") or {}).get(key)
            last = book.get("last_read") if isinstance(book, dict) else None

            if isinstance(last, dict) and is_message_hash(last.get("sha256")):
                fields["seen"] = last["sha256"]
        except Exception:
            pass

        return fields

    def _trace_sent(self, entry, status, result):
        """One answer to one send: what went where, as the service stored it."""
        key = entry.get("to_key")

        if not key:
            return

        stored = isinstance(result, dict) and status == 201
        record = {
            "message_id": entry.get("id"),
            "at": int(time.time()),
            "w": entry.get("w"),
            "status": status,
            "outcome": entry.get("status"),
            "seq": result.get("seq") if stored else None,
            "sha256": result.get("sha256") if stored else None,
            "sealed": True,
        }

        if isinstance(entry.get("shape"), dict):
            record.update(entry["shape"])

        record = trace_row(record, TRACE_SENT_FIELDS)

        with self.lock:
            book = self._trace_book(key)
            kept = [r for r in book["sent"] if r.get("message_id") != record.get("message_id")]
            book["sent"] = (kept + [record])[-self.TRACE_KEEP:]
            self._save_trace()

    def _trace_received(self, channel, entry):
        """One verified message from a key, as it arrived here. Called under the lock.

        Recorded whether or not it could be opened, since one that could not is
        what a trace is for. Taken as read only when it could: last_read is what
        the next message to this key names as seen, and it names a message this
        side opened, not one that merely arrived. A replay is neither recorded
        nor read: its first arrival was, and an old message sent again must not
        move seen back to it.
        """
        if entry.get("replay"):
            return

        key = entry.get("from_key")
        opened = entry.get("format") in ("text", "json") and not entry.get("error")
        body = entry["body"] if opened and isinstance(entry.get("body"), dict) else {}
        row = trace_row({
            "at": entry.get("at"),
            "channel": channel.label,
            "w": channel.w,
            "seq": entry.get("seq"),
            "sha256": entry.get("sha256"),
            "encrypted": entry.get("encrypted"),
            "format": entry.get("format"),
            "error": entry.get("error"),
            # What a message held is known only if it opened.
            "fields": sorted(body) if opened else None,
            "text_chars": len(body["text"]) if isinstance(body.get("text"), str) else None,
            "re": body.get("re"),
            "seen": body.get("seen"),
        }, TRACE_RECEIVED_FIELDS)
        book = self._trace_book(key)

        if row["sha256"] and any(r.get("sha256") == row["sha256"] for r in book["received"]):
            return

        book["received"] = (book["received"] + [row])[-self.TRACE_KEEP:]

        if opened and entry.get("verified") is True and is_message_hash(entry.get("sha256")):
            book["last_read"] = trace_row({"sha256": entry["sha256"], "seq": entry.get("seq"), "w": channel.w, "at": entry.get("at")}, TRACE_READ_FIELDS)

        self._save_trace()

    def trace(self, who=None, limit=20):
        """What was sent to one counterpart and what came back, as hashes and shapes.

        who is a partner name, a key or a write address; without it, one line per
        counterpart. Nothing here is content: the sha256 is what the service stored,
        byte for byte, so the other side can hold its own trace against this one.
        """
        limit = max(1, min(int(limit or 20), self.TRACE_KEEP))
        key = None if who is None else self._trace_key(who)

        # A copy, taken under the lock a read holds while it records: a read
        # that met a new counterpart while this went through the record itself
        # stopped it with RuntimeError (R4).
        with self.lock:
            traces = copy.deepcopy(self.__dict__.get("traces") or {})

        if who is None:
            everyone = []

            for key, book in traces.items():
                if not isinstance(book, dict):
                    continue

                sent, received = book.get("sent") or [], book.get("received") or []
                everyone.append({
                    "with": self.name_for_key(key) or key,
                    "key": key,
                    "sent": len(sent),
                    "received": len(received),
                    "last_sent_at": sent[-1].get("at") if sent else None,
                    "last_received_at": received[-1].get("at") if received else None,
                    "no_read_claim": len(trace_view(book, self.TRACE_KEEP)["no_read_claim"]),
                })

            everyone.sort(key=lambda row: max(row["last_sent_at"] or 0, row["last_received_at"] or 0), reverse=True)

            return {"counterparts": everyone, "note": "Name one with who for the messages themselves, as hashes."}

        book = traces.get(key) if key else None

        if not isinstance(book, dict):
            raise LookupError("nothing sent to or received from %s is recorded here" % who)

        view = trace_view(book, limit)

        return {
            "with": self.name_for_key(key) or key,
            "key": key,
            "sent": view["sent"],
            "received": view["received"],
            # What this side last read and opened from them: what the next
            # message to them names as seen.
            "last_read": book.get("last_read"),
            "no_read_claim": view["no_read_claim"],
            "note": view["note"],
        }

    def _trace_key(self, who):
        """A partner name, a key or a write address, as the key it stands for."""
        partner = self.partner_by_name(who) if isinstance(who, str) else None

        if partner:
            return partner["key"]

        if is_key(str(who)):
            return str(who)

        with self.lock:
            return self.peers.get(who)

    def _poll_loop(self, channel):
        """One long-poll loop per channel, so mail on any channel is seen at once."""
        # A poller already running when its channel was muted used to run on,
        # and everything it fetched went into the queue: the removed partner's
        # messages arrived through the listener, which the MCP server uses,
        # while the command line delivered nothing.
        while not self.stop.is_set() and not channel.closed and not channel.muted and channel.expire_at > time.time():
            entries = []

            try:
                state, entries = self.poll(channel, 20)
                if state == "expired":
                    break
                if state in ("error", "gone"):
                    time.sleep(2)
            except Exception as error:
                # Whatever went wrong, anything poll had already decoded is on this
                # machine and is handed over below. Losing it here is how a full disk
                # turned two messages into an empty inbox with nothing said.
                self._note_trouble(
                    "poller %s" % channel.label,
                    "unread",
                    "reading this channel stopped part way: %s: %s. Anything already read is handed over; the rest arrives on the next read."
                    % (error.__class__.__name__, error),
                )
                self.log("poller %s: %s" % (channel.label, error))
                time.sleep(3)

            if channel.muted:
                # Muted while this poll was out: what it brought back stays on
                # the channel's record and is handed to nobody.
                entries = []

            for entry in entries:
                self.inbound.put(entry)
        channel.poller = None

    def _start_poller(self, channel):
        """One poller for a channel opened after the listener started."""
        if channel.poller is not None and channel.poller.is_alive():
            return
        poller = threading.Thread(target=self._poll_loop, args=(channel,), daemon=True)
        channel.poller = poller
        poller.start()

    def _listen(self):
        """Keeps the inbox alive and presence fresh, and gives every channel a poller."""
        while not self.stop.is_set():
            try:
                self.ensure_inbox()
                self.publish_presence()
                for label, channel in list(self.channels.items()):
                    if channel.expire_at <= time.time():
                        channel.closed = True
                        if label != "inbox":
                            with self.lock:
                                self.channels.pop(label, None)
                        continue
                    if channel.muted:
                        continue
                    if channel.poller is None:
                        channel.poller = threading.Thread(target=self._poll_loop, args=(channel,), daemon=True)
                        channel.poller.start()
            except Exception as error:
                self.log("listener: %s" % error)
            self.stop.wait(2)

    def start(self):
        if self.listener is None:
            self.ensure_inbox()
            self.listener = threading.Thread(target=self._listen, daemon=True)
            self.listener.start()
        return self

    def read(self, wait=0, limit=50, max_bytes=None):
        """Messages the listener has received and nobody has read yet."""
        if self.listener is None:
            # No background listener: poll directly.
            self.ensure_inbox()
            self.publish_presence()
            collected = []
            waited = False
            left_waiting = 0
            held_back = []
            not_asked = []
            for channel in list(self.channels.values()):
                if channel.muted:
                    continue
                # A channel is only asked for what this call still has room
                # for. poll moves the cursor and saves it before the caller
                # sees a message, so whatever was fetched beyond the limit and
                # cut off here afterwards was past the cursor and never came
                # back: 60 waiting, 50 handed over, the last ten gone.
                room = limit - len(collected)
                if room <= 0:
                    not_asked.append(channel.label)
                    continue
                try:
                    state, entries = self.poll(channel, 0 if waited else wait, room,
                                               **({} if max_bytes is None else {"max_bytes": max_bytes}))
                except Exception as error:
                    self._note(channel, "unread", "this channel could not be read: %s. Messages from the other channels are still returned." % error.__class__.__name__)
                    continue
                # A channel that answered 410 or nothing at all used to eat the
                # whole wait, so a read with wait 25 came back at once and the
                # inbox was only ever asked with wait 0. A gone one did wait:
                # the service holds a read of a missing thread for a write.
                waited = waited or state in ("ok", "gone")
                collected.extend(entries)
                left_waiting += channel.left_waiting

                if channel.more_at_service:
                    held_back.append(channel.label)

            if held_back:
                self._note_trouble("read", "more", "the service had more waiting on %s than the byte budget this read asked for, so it sent what fits and kept the rest. Read again for it: the cursor stands at the last message handed over." % ", ".join(held_back))

            if left_waiting or not_asked:
                # Nothing is lost, and the caller still has to hear it: a read
                # that stopped at its limit is not a read of everything.
                self._note_trouble("read", "more", "this read stopped at its limit of %d message(s). %s Nothing was passed over: every cursor stands at the last message this read dealt with, so read again for the rest." % (
                    limit,
                    " ".join(part for part in (
                        "%d more that the service had already returned were left where they are." % left_waiting if left_waiting else "",
                        "%d channel(s) were not asked this time: %s." % (len(not_asked), ", ".join(not_asked)) if not_asked else "",
                    ) if part),
                ))
            return collected
        # With a listener running, the messages are already here: it fetched them
        # on its own polls, which belong to every caller and cannot take one
        # caller's budget without shortening somebody else's stream. So here the
        # budget bounds the answer rather than the transfer. It was neither until
        # now: max_bytes was taken, carried down two calls, and dropped, in the
        # one mode the MCP server actually runs in.
        collected = []
        used = 0
        deadline = time.time() + max(0, int(wait))
        oversized = None

        # What an earlier read could not fit waits here, in front of the queue and
        # in the order it arrived. It used to go back on the end of the queue, so
        # four messages read with a small budget came back 1, then 3, 2, 4: the one
        # that did not fit had been put behind two nobody had looked at yet. Once a
        # message is on this machine its order is the only order the caller sees.
        with self.lock:
            waiting = list(getattr(self, "held_back", []))
            self.held_back = []

        while len(collected) < limit:
            if waiting:
                entry = waiting.pop(0)
            else:
                remaining = deadline - time.time()

                try:
                    entry = self.inbound.get(timeout=max(0.0, remaining) if not collected else 0.05)
                except queue.Empty:
                    if collected or remaining <= 0:
                        break

                    continue

            # Nothing from a muted inbox is handed over, whatever fetched it: a
            # poller that was already running, or a message that sat in the
            # queue before the partner was removed. It stays on the channel's
            # record, for the receipt.
            if self._muted_address(entry.get("w")):
                continue

            if max_bytes is not None:
                weight = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

                # Whole messages, as the service does it.
                if collected and used + weight > max_bytes:
                    waiting.insert(0, entry)
                    break

                # One message larger than the whole budget is handed over rather
                # than held for ever: it is already here, and a queue that quietly
                # keeps a message is the fault this is here to fix. The caller is
                # told, because 2054 bytes arriving on a budget of 512 with nothing
                # said reads as a budget that does not work.
                if not collected and weight > max_bytes:
                    # Not too_large: that is the service's word for a message that
                    # did not come and is still there. This one came. Under one name
                    # a reader cannot tell which happened, and the two call for
                    # opposite actions.
                    self._note_trouble(
                        "read",
                        "over_budget",
                        "message %s is %d bytes, larger than the whole budget of %d this read asked for. It was already on this machine, so it is handed over rather than held back for ever, and this read is over budget by design." % (entry.get("seq"), weight, max_bytes),
                    )

                used += weight

            collected.append(entry)

        if waiting:
            with self.lock:
                self.held_back = waiting + list(getattr(self, "held_back", []))

            self._note_trouble("read", "more", "this read stopped at the byte budget it asked for, %d bytes. The rest is here in the order it arrived and the next read hands it over; nothing was dropped and nothing changed places." % max_bytes)

        return collected

    # ---------------------------------------------------------- receipt --

    def receipt(self, label="inbox", anchor=False):
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.receipt(channel.w, channel.read_key)
        if status != 200:
            raise RuntimeError("receipt failed: %s %s" % (status, data))
        # Two different checks, and they used to be reported as one.
        #
        # The receipt's own arithmetic can always be checked: hash the lines it
        # itself lists and see whether that is the root it claims. That catches
        # a receipt that does not add up, and it needs nothing from us.
        #
        # Whether it agrees with what we saw is a stronger claim, and one we
        # can make when we hold every message it counts; fewer receipt lines
        # than observed messages is a mismatch too. Observations include
        # kept-out messages but live only in this process, so `aamio-listen
        # receipt` holds none of them and the old field said False: a good
        # receipt reported as a mismatch, which is the one thing a proof must
        # never do. It says None now, with the count, so "not compared" cannot
        # be read as "did not match".
        with channel.lock:
            entries = sorted(channel.observed.values(), key=lambda e: e["seq"])
        held = len(entries)
        line = "%d\t%d\t%s\t%s\n"
        listed = "".join(line % (m["seq"], m["at"], m["sha256"], m.get("from") or "-") for m in (data.get("messages") or []))
        ours = "".join(line % (e["seq"], e["at"], e["sha256"], e.get("from") or "-") for e in entries)
        comparable = held == data["count"]
        verified_keys = {e.get("from_key") for e in entries if e.get("verified") and isinstance(e.get("from_key"), str)}
        claimed_keys = data.get("keys", [])
        unverified_keys = [key for key in claimed_keys if not isinstance(key, str) or key not in verified_keys]
        # Sign what we took, so partners can exchange receipts and compare
        # without trusting the network's word alone.
        attestation = "aamio-receipt-v1\n%s\n%s\n%d\n%d" % (channel.w, data["root"], data["count"], data.get("issued_at", 0))
        result = {"label": label, "w": channel.w, "root": data["root"], "commitment": data.get("commitment"), "count": data["count"], "keys": [(self.name_for_key(k) or k) if isinstance(k, str) and k in verified_keys else k for k in claimed_keys], "keys_unverified_count": len(unverified_keys), "keys_service_claim_only": unverified_keys, "root_adds_up": sha256hex(listed) == data["root"], "held_locally": held, "local_root_matches": (sha256hex(ours) == data["root"]) if comparable else (False if held > data["count"] else None), "signed_by": self.keys.public, "signature": self.keys.sign(attestation), "signed_text": attestation, "receipt": data}

        if comparable:
            local = {entry["seq"]: entry for entry in entries}
            differences = []
            for message in data.get("messages") or []:
                observed = local.get(message["seq"])
                fields = [field for field in ("at", "sha256", "from") if observed is None or observed.get(field) != message.get(field)]
                if fields:
                    differences.append({"seq": message["seq"], "fields": fields})
            result["local_differences"] = differences
            result["signers_not_verified_locally"] = [entry["seq"] for entry in entries if entry.get("from") and not entry.get("verified")]

        if held > data["count"]:
            result["local_check"] = "Mismatch: the receipt counts fewer messages than this process read. The thread was replaced or the service lost messages."
        elif not comparable:
            result["local_check"] = ("Not compared: this process holds %d of the %d messages the receipt counts, so a local root would differ for a reason that is not the receipt's. "
                "root_adds_up checks only the receipt's arithmetic; our signature records what was fetched, not that its claims are true. For the independent check, take the receipt in the process that read the messages." % (held, data["count"]))
        if anchor:
            idem = sha256hex("aamio-listen:%s:%s" % (self.keys.hash, data["root"]))[:32]
            status, proof = self.client.anchor(data["root"], idem)
            result["anchor"] = proof if status == 200 else {"error": status, "detail": proof}
        self.archive(label, {"kind": "receipt", "at": time.time(), "result": result})
        return result

    def close(self):
        """Stops the listener, saves what it holds and lets go of the home, once."""
        if getattr(self, "closed", False):
            return
        self.closed = True
        self.stop.set()
        self._wait_for_threads()
        try:
            self.save_state()
            self.save_outbox()
        finally:
            self._let_go()
            self._release_lock()

    def _wait_for_threads(self):
        """A moment for the threads to finish what they hold, and no longer."""
        until = time.time() + self.CLOSE_WAIT
        threads = [channel.poller for channel in list(getattr(self, "channels", {}).values()) if channel.poller is not None]
        if getattr(self, "listener", None) is not None:
            threads.append(self.listener)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(max(0.0, until - time.time()))

    def _let_go(self):
        """From here on this runtime writes nothing: the home may be another process's."""
        with getattr(self, "lock", None) or threading.RLock():
            self.home_released = True

    def release(self):
        """Lets go of the home without saving, for a command that saved what it changed as it went."""
        self._let_go()
        self._release_lock()
