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

import collections
import copy
import errno
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
# What a post leaves its inbox: time for the work the board advises and the
# round trip. The board refuses a post that would outlive the inbox when it
# arrives, and the lifetime is in the body the work covers, so it is set before
# the work is done. With nothing left over, a post asked for as long as an inbox
# lives was refused whenever the work took a second (a check of 12 November
# 2026). The same in aamio-php and the Node runtime.
BOARD_POST_MARGIN = 30
# How much longer than the post itself a reply address should live. The poster
# reads answers on their own schedule, and a minute either way is the
# difference between a conversation and a dead end.
ANSWER_MARGIN = 600
PRESENCE_TTL = 120
PRESENCE_REFRESH = 60
RENEW_BEFORE = 180
# The most one message may be, as the service takes it. The service refuses
# more with 413; this copy is only for asking before a channel is opened for a
# message that could not carry its address.
MESSAGE_MAX_BYTES = 65536


def home_dir() -> str:
    return os.environ.get("AAMIO_HOME") or os.path.join(os.path.expanduser("~"), ".aamio")


def pid_alive(pid):
    """Whether a process with this pid is running, without touching it.

    True is alive, False is proven gone, and None is an answer that proves
    neither. A lock is taken over on False and on nothing else.

    os.kill(pid, 0) asks that on POSIX. On Windows it is TerminateProcess:
    it ended whatever process held the pid, and then reported it as alive.
    A lock file outlives its process and Windows hands pids out again
    quickly, so the process ended was as often somebody else's program as
    an old aamio. There the question goes to OpenProcess instead.

    Every error but the one that says there is no such process used to count
    as gone. An error that says something else says nothing about the process.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or pid > 0xFFFFFFFF:
        # Zero and below are process groups to kill(), not processes, and a
        # number no system hands out is not a process that is gone.
        return None
    if os.name == "nt":
        return _pid_alive_windows(pid)
    return _pid_alive_posix(pid)


def _pid_alive_windows(pid, kernel32=None, last_error=None):
    """The question as OpenProcess answers it. The two arguments are for a test to stand in for Windows."""
    import ctypes

    if kernel32 is None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        error = (last_error or ctypes.get_last_error)()
        # Access denied means the process is there and not ours to look at.
        if error == 5:
            return True
        # Invalid parameter is the answer for a pid no process holds.
        if error == 87:
            return False
        return None
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
            return None
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def _pid_alive_posix(pid, kill=None):
    """The question as kill(pid, 0) answers it. The argument is for a test to stand in for the system."""
    try:
        (kill or os.kill)(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError):
        return None
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


# Homes locked by this process, for a plainer message. The lock on OWNER_LOCK
# keeps out a second runtime in this process as well as in another one.
_LOCKED_HOMES = set()

# The file in a home that the operating system holds locked for its owner.
# aamio-php takes the same lock on the same file.
OWNER_LOCK = "owner.lock"


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
# 401 and 409 are among them: a signature that does not verify over these
# bytes, a thread that is full, a key that has used up the gate's per_key. The
# service answers each before it stores anything. Left out, a handover answered
# so said the address may have arrived, and retry sent the same bytes to the
# same refusal (a check of 12 November 2026).
SEND_DETERMINISTIC = (400, 401, 403, 409, 410, 413, 415, 422, 428, 501)
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
    if outcome == "never_sent":
        return False, (
            "Nothing left this machine for this message, so it was not delivered and will not be: the error says what "
            "stopped it. Put that right, then send it as a new message. There is nothing to retry."
        )

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


def refused_once(stop):
    """What a stop after a 428 says: the message went once and was refused, and why it was not sent again.

    Built from the stop's why and fix, which say nothing about the message, and
    never from its reason, which was written for one that had not left. The
    reason was reworded here by replacing one phrase, and a stop that put it
    another way still said it sent nothing (a check of 30 September 2026).
    """
    why = stop.why[:1].upper() + stop.why[1:]

    return "The message went once and the inbox refused it with 428, and it was not sent again. %s. %s" % (why, stop.fix)


class SendFailed(RuntimeError):
    """A send that did not end in a stored message.

    outcome is refused when aamio answered and said no, and unknown when no
    answer came back at all. Unknown is not failure: the message may be on
    the other side. The entry stays in the outbox under message_id.
    """

    def __init__(self, outcome, message_id, status, detail, opened=None, trace_error=None, archive_error=None):
        super().__init__("send %s (http %s): %s" % (outcome, status, detail))
        self.outcome = outcome
        self.message_id = message_id
        self.status = status
        self.detail = detail
        # When the message that did not land was the one carrying the address
        # of a channel just opened: the channel is there, and the caller has
        # to be told which, or it is a thread nobody knows about.
        self.opened = opened
        # The trace of this attempt, when it could not be written. A delivery
        # said so on its answer and a failure did not: a command that sends
        # once and exits never fetches attention, and was told of the refusal
        # and not of the trace (a check of 12 November 2026).
        self.trace_error = trace_error
        # And the archive's record of the attempt, when that could not be written.
        self.archive_error = archive_error


def handover_unsettled(outcome):
    """Whether a message that carried a channel's address may be with them, for the words in front of the fix.

    A refusal says the message is not there, and one that never left is not
    there either. Anything else that left may have arrived. "Only the message
    carrying its address did not go" was said of all of them, and of a message
    that was with them it read as leave to open another channel and invite
    again (a check of 12 November 2026).
    """
    return outcome not in ("refused", "never_sent")


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


def check_label(label):
    """A label for a channel of the caller's own.

    It names the channel in every answer and its file in the archive, so it is
    made of what a file's name may hold and nothing else: a label with a path
    in it put what was read on the channel outside the home (a check of 12
    November 2026). The labels that start with inbox or board are the
    runtime's own channels. The rule and its words are the Node runtime's and
    aamio-php's.
    """
    if not storage.is_safe_label(label):
        raise ValueError("a channel's label is 1 to 64 letters, digits, dots, dashes and underscores, starting with a letter or a digit, and not a name the system keeps for a device: it names the channel's file in the archive")
    if re.match(r"(?:inbox|board)", label, re.IGNORECASE):
        raise ValueError("the label %s is the runtime's own: a label that starts with inbox or board names an inbox or a board inbox. Choose another" % label)


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
# How many field names a row keeps, and how long a name may be, in characters.
# The names of a message that arrived are its sender's to choose: one message
# of the largest size can carry thousands of them, fifty such from one key were
# megabytes in a file that is written again at every read, and a board inbox
# takes any signed key (found while the Node runtime's trace was built, 12
# November 2026). The fields the three runtimes write are a handful of short
# names, so what is cut is only what was made to be long.
TRACE_FIELDS = 32
TRACE_FIELD_CHARS = 64


def _trace_value(kind, value):
    if kind == "hash":
        return value if is_message_hash(value) else None
    if kind is list:
        if not isinstance(value, list):
            return None
        return sorted(item for item in value if isinstance(item, str) and len(item) <= TRACE_FIELD_CHARS)[:TRACE_FIELDS]
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


class AmbiguousPartner(ValueError):
    """A name that matches two partners apart from upper and lower case, and neither exactly.

    A name used to be matched without regard to case, and the first partner in
    the book won. With Ada and ADA in it, a send to ADA's key, or to ada, went
    to Ada, sealed to Ada's key, and Ada opened a message meant for someone
    else (finding 1 of the review of 9 November 2026, found in the Node runtime
    first). Two such partners is an error now, never a guess.
    """


def _which_thread(thread):
    """A thread as a receipt's note names it: its instance where it has one, and when it was opened and expires."""
    named = "instance %s, " % thread["instance"] if isinstance(thread.get("instance"), str) else "the one "
    return "%sopened at %s and expiring at %s" % (named, thread.get("created_at"), thread.get("expire_at"))


def _whole(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _hex64(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def receipt_fault(data, w):
    """Why a service's answer is not a receipt for the thread at w, or None when it is one.

    The v1 schema, the address that was asked for, its times, one line in order
    for every message it counts, and a root its commitment names. The same check
    as aamio-js's and aamio-php's, with the same words.
    """
    if not isinstance(data, dict):
        return "it is not an object"
    if data.get("schema") != "aamio-receipt-v1":
        return "its schema is %s, not aamio-receipt-v1" % json.dumps(data.get("schema"))
    if data.get("w") != w:
        return "it is for %s, not for %s, the address asked for" % (json.dumps(data.get("w")), w)
    for field in ("created_at", "expire_at", "issued_at"):
        if not _whole(data.get(field)) or data[field] < 0:
            return "its %s is not a time" % field
    messages = data.get("messages")
    if not isinstance(messages, list):
        return "it has no list of messages"
    if not _whole(data.get("count")) or data["count"] != len(messages):
        return "it counts %s messages and has %d lines" % (json.dumps(data.get("count")), len(messages))
    previous = 0
    for index, m in enumerate(messages):
        fine = (isinstance(m, dict) and _whole(m.get("seq")) and m["seq"] > previous and _whole(m.get("at")) and m["at"] >= 0
                and _hex64(m.get("sha256")) and (m.get("from") is None or isinstance(m.get("from"), str)))
        if not fine:
            return "line %d is not a message line in order" % (index + 1)
        previous = m["seq"]
    if not _hex64(data.get("root")):
        return "its root is not a sha256 in hex"
    if data.get("commitment") != "sha256:" + data["root"]:
        return "its commitment is not sha256: and its root"
    # The signers are the lines' own: the service lists each key that signed a
    # line, once. One that left a signer out was signed as if nobody had signed,
    # and one without keys ended in TypeError (a review of 10 November 2026).
    keys = data.get("keys")
    if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
        return "its keys are not a list of keys"
    signers = {m.get("from") for m in messages if isinstance(m.get("from"), str)}
    if set(keys) != signers:
        return "its keys are not the signers of its lines"
    return None


# One message a channel handed over, as the channel remembers it: the hash of its
# bytes and who signed them, the first 16 hex of sha256 of the key, or - when
# nobody did. The hash alone is of the text, and two signers who both sent "OK"
# made the second a replay of the first (a review of 10 November 2026). ? stands
# beside a hash an earlier version kept without its signer, once that hash is met
# again: who sent it then is not known, and stays not known.
SEEN_FROM = re.compile(r"[0-9a-f]{64}:(?:[0-9a-f]{16}|-|\?)")


def seen_record(digest, from_key):
    """The record of a message handed over: its hash, and the signer it was verified from, or -."""
    return "%s:%s" % (digest, sha256hex(from_key)[:16] if isinstance(from_key, str) and from_key else "-")


def replay_state(channel, digest, from_key):
    """Whether this channel handed these bytes over before from this signer, or unsigned when they are unsigned.

    True when it did, and False when it did not: bytes it handed over from
    another signer make this another message. None when it cannot be told: an
    earlier version kept the hash without its signer, and this signer has no
    record of its own. Taken as a copy, the first answer of another signer with
    the same text was passed over, and taken as new, the same signer's copy was
    acted on twice (a review of 11 November 2026), so it is said as it is.
    """
    if digest is None:
        return False
    if seen_record(digest, from_key) in channel.seen_from:
        return True
    records = [record for record in channel.seen_from if record.startswith(digest + ":")]
    if digest + ":?" in records or (not records and digest in channel.seen):
        return None
    return False


def is_replay(channel, digest, from_key):
    """Whether this is known to be a copy: replay_state, with not known taken as no."""
    return replay_state(channel, digest, from_key) is True


def remember(channel, digest, from_key):
    """A message handed over: its hash, and who it came from.

    A hash an earlier version kept without its signer keeps that, as ?, beside the
    first signer recorded for it, so the next signer with the same bytes is not
    taken for a new one with certainty.
    """
    if digest in channel.seen and not any(record.startswith(digest + ":") for record in channel.seen_from):
        channel.seen_from.add(digest + ":?")
    channel.seen.add(digest)
    channel.seen_from.add(seen_record(digest, from_key))


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
        # An inbox is marked muted when it names a key that has left the
        # address book: the removed key can still write to the address it was
        # given until the thread expires. It is read until then for the
        # partners still in the book, and what the removed key writes there is
        # not handed over.
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
        # Whether that was the count this read asked for, reached, rather than
        # its byte budget: the service says more for both.
        self.more_at_limit = False
        self.seen = set()
        # Who sent each hash in seen: a record per message handed over.
        self.seen_from = set()
        self.received = []
        self.observed = {}
        # The thread the observations were read on: the one opened at this time
        # at this address, and expiring at that. A thread opened at the same
        # address after the service restarted is another one, and its receipt is
        # never compared with them.
        self.observed_created_at = None
        self.observed_expire_at = None
        self.observed_instance = None
        # The instance the service names this thread by, given when it was
        # opened. A thread opened again at the same address in the same second,
        # with the same lifetime and list, looked the same in every other field,
        # and a cursor taken from the old one passed over its first messages (a
        # review of 10 November 2026). None until a read names it, and from a
        # service that names none.
        self.instance = None
        # Whether the last poll stopped at its byte budget, as messages are
        # handed over, and left the rest at the service.
        self.stopped_at_budget = False
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
        # Under the channel's lock like every other touch of observed. Cleared
        # without it, a reader walking the dictionary would meet a change of
        # size halfway, and a receipt or a domain check runs on another thread.
        self.instance = None
        with self.lock:
            self.observed.clear()
            self.observed_created_at = None
            self.observed_expire_at = None
            self.observed_instance = None

    def to_state(self):
        # seen travels with the channel: without it a restart cannot tell a
        # redelivered message from a new one, and the model may act twice.
        return {"label": self.label, "read_key": self.read_key, "w": self.w, "expire_at": self.expire_at, "allow": self.allow, "after": self.after, "created_at": self.created_at, "instance": self.instance, "gone": self.gone, "muted": self.muted, "seen": sorted(value for value in self.seen if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)), "seen_from": sorted(value for value in self.seen_from if isinstance(value, str) and SEEN_FROM.fullmatch(value))}

    @classmethod
    def from_state(cls, item):
        channel = cls(item["label"], item["read_key"], item["w"], item["expire_at"], item.get("allow"), item.get("after", 0), item.get("created_at"))
        channel.seen = {value for value in item.get("seen") or [] if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)}
        channel.seen_from = {value for value in item.get("seen_from") or [] if isinstance(value, str) and SEEN_FROM.fullmatch(value)}
        channel.gone = item.get("gone") is True
        channel.muted = item.get("muted") is True
        channel.instance = item.get("instance") if isinstance(item.get("instance"), str) else None

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
                # Who can read the decrypted archive is not a detail to mention
                # once into a logger that may be a no-op. A caller that never set
                # one was told nothing at all about its own folder.
                self._note_trouble(
                    "home",
                    "unsafe",
                    "%s: %s. %s" % (finding.get("path", self.home), finding["problem"], found.get("fix", "")),
                )
        self._prune()

    def _prune(self):
        policy = getattr(self, "archive_policy", None) or storage.DEFAULT_POLICY
        if not self.archive_enabled or not (policy.get("days") or policy.get("max_mb")):
            return
        self.pruned_at = time.time()
        try:
            with self.archive_lock:
                gone = storage.prune(self.home, policy)
        except (OSError, ValueError) as error:
            # The archive keeps growing, in plain text, and the policy that was
            # meant to bound it did not run. Worth hearing about once per reason.
            self._note_trouble(
                "archive",
                "unpruned",
                "the archive was not pruned: %s: %s. It keeps growing, and what is in it stays readable to whoever can read this folder."
                % (error.__class__.__name__, error),
            )
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

            # An attempt left open before this process, by this version or an
            # older one, stays open: a stop or a refusal from now on settles a
            # later attempt, not that one. Only an answer marked it, so an entry
            # loaded from sending, or saved before the mark existed, had none,
            # and a 428 on its retry called a message that may have landed
            # refused (a check of 30 September 2026).
            if outbox_open(entry):
                entry["ever_open"] = True
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
        # the older generations are marked here. What a key removed while the
        # runtime was down writes to an address it was given is not handed
        # over, since every message is judged against the book as it is.
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

        The operating system holds a lock on owner.lock for as long as this
        runtime runs, and lets go of it when the process ends, however it
        ends. Taking it is one step. With the pid file alone, taking the home
        was three steps, a read, a check and a write, and two runtimes started
        at once both read that nobody had it and both went on (a review, 29
        September 2026). Where owner.lock cannot be opened or locked, as on a
        network filesystem without locks, nothing proves the home free, and
        the runtime stops with the reason instead of going on without it.

        The pid file is still written: it names the owner in the message a
        second runtime gives, and it is all that versions from before
        owner.lock look at. os_lock in it says that its writer held the lock,
        so a runtime that holds the lock now knows that writer is gone.
        """
        real = os.path.realpath(self.home)

        if real in _LOCKED_HOMES:
            raise RuntimeError("another aamio in this process is already using %s" % self.home)

        self._owner_fd = None

        try:
            self._owner_fd = storage.hold(self._path(OWNER_LOCK))
        except OSError as error:
            # Held by nobody and not by this one either, so nothing proves the
            # home is free. 0.6.22 went on with the pid file alone here, which
            # two runtimes started at once could both take, and said so only
            # to a logger that does nothing unless the caller sets one (a
            # review, 30 September 2026).
            raise RuntimeError(
                "cannot establish exclusive ownership of %s: %s could not be opened or locked (%s). Restore file access or "
                "locking support, or use a different AAMIO_HOME on a local disk." % (self.home, self._path(OWNER_LOCK), error)
            ) from error

        if self._owner_fd is None:
            held = self._lock_holder()
            # The owner writes its pid just after it takes the lock, so a
            # moment may pass with none, or an old one, there to name.
            named = " (pid %s)" % held["pid"] if isinstance(held, dict) and isinstance(held.get("pid"), int) else ""
            raise RuntimeError("another aamio%s is using %s. Stop it, or use a different AAMIO_HOME." % (named, self.home))

        try:
            self._check_older_owner()
            self._save_json("lock", {"pid": os.getpid(), "at": int(time.time()), "host": self.host, "os_lock": True})
        except BaseException:
            self._let_go_of_owner_lock()
            raise

        _LOCKED_HOMES.add(real)

        return True

    def _lock_holder(self):
        """What the pid file says, for a message. Nothing when it cannot be read."""
        try:
            return self._load_json("lock", None)
        except Exception:
            return None

    def _check_older_owner(self):
        """An owner the operating system's lock cannot see: a version from before owner.lock, which writes the pid file alone."""
        held = self._load_json("lock", None)

        if not (isinstance(held, dict) and isinstance(held.get("pid"), int) and held["pid"] != os.getpid()):
            return

        if held.get("os_lock") is True:
            # Written by a runtime that held owner.lock. This one holds it now,
            # so that one has let go of it or ended: no pid needs asking about.
            return

        try:
            alive = pid_alive(held["pid"])
        except Exception:
            alive = None

        if alive is None:
            # Not known to be gone is not gone: taking the lock here would
            # let two runtimes write one home.
            raise RuntimeError(
                "could not determine whether aamio (pid %s) is still using %s; the lock is left untouched. Process inspection was "
                "unavailable or inconclusive. Stop the other runtime or restore process inspection, or use a different AAMIO_HOME. "
                "Do not remove the lock unless you have independently confirmed its owner has stopped." % (held["pid"], self.home)
            )

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

    def _let_go_of_owner_lock(self):
        fd, self._owner_fd = getattr(self, "_owner_fd", None), None

        if fd is not None:
            storage.let_go(fd)

    def _release_lock(self):
        if not getattr(self, "owns_lock", False):
            return
        held = self._load_json("lock", None)
        if isinstance(held, dict) and held.get("pid") == os.getpid():
            try:
                os.unlink(self._path("lock"))
            except OSError:
                pass
        # After the pid file, so a runtime that takes the lock the moment it is
        # free finds no pid file of this one's to wonder about.
        self._let_go_of_owner_lock()
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
                text = handle.read().decode(storage.HOME_ENCODING)
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
            # Not past a mark, as the home's other files are: the key holds
            # the seed and nothing else, in all three runtimes.
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
        path = os.path.join(self.home, "archive", "%s.jsonl" % storage.archive_name(label))
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
        near = [p for p in self.partners if p["name"] != name and p["name"].lower() == str(name).lower() and p["key"] != key]
        if near:
            raise AmbiguousPartner(
                "%s is in the address book with another key, and %s differs from it only in upper and lower case, which would make a send by name a guess. "
                "Give %s exactly to replace its key, or choose another name." % (near[0]["name"], name, near[0]["name"])
            )
        # The new book counts only once partners.json holds it. Put in place
        # first, a write that failed left this process sealing to the new key
        # and opening its inbox to it, and the next start back on the old one
        # (the release check of 9 November 2026, found in the Node runtime).
        partners = [p for p in self.partners if p["name"] != name and p["key"] != key]
        partners.append({"name": name, "key": key})
        self._save_partners(partners)
        return self._inbox_after_change("partner %s was added" % name, {"partner": name, "key": key})

    def partner_remove(self, name):
        """A partner out of the address book, and out of the inbox at once.

        Forgetting the name is not a revocation: the service takes the removed
        key's writes to the old address until that thread expires. So a new
        inbox is opened without the key, and the old one is read until it
        expires for the partners still in the book, who may not have the new
        address yet, while what the removed key writes there is not handed
        over. Once the last partner is gone the new inbox takes signed writes from any
        key, each shown as an unknown one, rather than unsigned writes from
        anyone at an address the partners were given.
        """
        # A key or a name, as a send takes them: the refusal of an ambiguous
        # name says to give the key, and partner remove did not take one.
        known = self.partner_by_key(name) if is_key(str(name)) else self.partner_by_name(name)
        if known is None:
            inbox = self.channels.get("inbox")
            return {"partner": name, "known": False, "inbox": inbox.w if inbox else None}
        # The partner the name finds, as a send finds it: apart from upper and
        # lower case when only one is so named. Filtered by the name as given,
        # a name in another case was said to be known and removed nothing (a
        # check of 12 November 2026).
        partners = [p for p in self.partners if p["name"] != known["name"]]
        self._save_partners(partners)
        return self._inbox_after_change("partner %s was removed" % known["name"], {"partner": known["name"], "known": True})

    def _save_partners(self, partners):
        """Writes the address book, and only then holds it. One that cannot be written is an error that says so, with the book as it was: it was a traceback."""
        try:
            self._save_json("partners.json", partners)
        except OSError as error:
            raise RuntimeError("partners.json could not be written (%s), so the address book is as it was. Free the disk, or give this user write access to %s, then do it again."
                               % (errno.errorcode.get(error.errno, error.__class__.__name__), self.home)) from None
        # Under the lock a read holds while it judges a message by the book, so
        # a message being applied as the partner goes sees one book or the other.
        with self.lock:
            self.partners = partners

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
        outcome.update(self._rotate_inbox(reason, caller=True))
        return outcome

    def partner_list(self):
        return [{"name": p["name"], "key": p["key"], "hash_prefix": key_hash(p["key"])[:8]} for p in self.partners]

    # ------------------------------------------------ what an add-on may use --
    #
    # An add-on keeps what it keeps in this home and asks this runtime which key
    # it means. These are the ways in, so that an add-on never reaches into
    # channels and files by their private names.

    def home_file(self, name):
        """The path of a file of that name in this home."""
        return self._path(name)

    def save_json(self, name, value):
        """Write a file in this home, private from its first byte, and not at all after close."""
        self._save_json(name, value)

    def verified_signers(self, sha256):
        """The keys that signed a message this process read and verified, by its hash. The same bytes may carry more than one.

        What this process checked lives in its memory and not in state.json, so a
        message read by an earlier process is not here. An observation the
        channel's allowlist kept out is: a signature that checked is not a
        permission. Read under the locks and held by none of them.
        """
        with self.lock:
            channels = list(self.channels.values())
        keys = []
        for channel in channels:
            with channel.lock:
                rows = [dict(row) for row in channel.observed.values()]
            for row in rows:
                if row.get("sha256") == sha256 and row.get("verified") is True and row.get("from_key") not in keys:
                    keys.append(row.get("from_key"))
        return keys

    def partner_by_name(self, name):
        """The partner with this name: the one so named exactly, or the only one so named apart from upper and lower case.

        Two of those and no exact one raises AmbiguousPartner: a guess seals the
        message to the wrong key.
        """
        for p in self.partners:
            if p["name"] == str(name):
                return p
        folded = [p for p in self.partners if p["name"].lower() == str(name).lower()]
        if len(folded) > 1:
            raise AmbiguousPartner(
                "%d partners are called %s apart from upper and lower case (%s). Give the name exactly as it is in the address book, or the key."
                % (len(folded), name, ", ".join(p["name"] for p in folded))
            )
        return folded[0] if folded else None

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

    # What a scope share says when scopes.json could not be written, and attention
    # says why. Shorter than the form a kept share takes, which a share is
    # weighed at when that is the longer.
    SCOPE_NOT_SAVED = "not kept: could not be saved"
    SCOPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    # How many invitations whose scope was removed scopes.json remembers. One is
    # only read again while its thread lives, and the oldest go first.
    SCOPE_REMOVED_KEEP = 256

    @staticmethod
    def _is_removed_share(entry):
        """An entry of scopes.json that remembers an invitation whose scope was removed, as aamio-php writes it too."""
        return isinstance(entry, dict) and set(entry) == {"removed_share"} and isinstance(entry["removed_share"], str) and SEEN_FROM.fullmatch(entry["removed_share"]) is not None

    def _removed_shares(self):
        return {entry["removed_share"] for entry in getattr(self, "scopes_aside", []) if self._is_removed_share(entry)}

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
        # An invitation whose scope was removed is remembered among the rest,
        # where an earlier version keeps it too, and is no typo to report.
        unusable = [entry for entry in aside if not self._is_removed_share(entry)]
        if unusable:
            self.log("scopes.json: %d entries are not scopes this runtime can use, and stay in the file as they are" % len(unusable))
        return usable, aside

    def _save_scopes(self, scopes, aside=None):
        """Writes the scopes, and only then holds them: a save that fails changes nothing."""
        with self.lock:
            aside = getattr(self, "scopes_aside", []) if aside is None else aside
            self._save_json("scopes.json", scopes + aside, private=True)
            self.scopes = scopes
            self.scopes_aside = aside

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
        with self.lock:
            held, keep = self._scope_add_plan(name, key=key, address=address)
            if keep is not None:
                self._save_scopes(keep)
        return self._scope_view(held)

    def _scope_add_plan(self, name, key=None, address=None):
        """What scope_add would hold and the list it would keep, or None when nothing changes. Nothing is kept here."""
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
                return held, self.scopes + [held]
            if key is not None and not held.get("key"):
                # Held to post only until now. The key adds reading.
                before, held = held, dict(held, key=key)
                return held, [held if s is before else s for s in self.scopes]
        return held, None

    def scope_list(self):
        return [self._scope_view(entry) for entry in self.scopes]

    def scope_remove(self, name):
        """Removes a scope, and remembers the invitations it came from in the same write.

        The cursor and the hashes of what was read live in state.json, and the
        scope in scopes.json. When state.json could not be written, the
        invitation came again after a restart as a message never seen, and a
        scope removed since was taken back (a check of 11 November 2026). Now
        the invitation is remembered here, and the same one read again keeps
        nothing. A new invitation is another message, and is taken.
        """
        with self.lock:
            entry = self._scope_named(name)
            aside = list(getattr(self, "scopes_aside", []))
            removed = self._removed_shares()
            aside += [{"removed_share": share} for share in entry.get("taken_from") or [] if isinstance(share, str) and SEEN_FROM.fullmatch(share) and share not in removed]
            held = [item for item in aside if self._is_removed_share(item)]
            if len(held) > self.SCOPE_REMOVED_KEEP:
                dropped = held[: len(held) - self.SCOPE_REMOVED_KEEP]
                aside = [item for item in aside if not any(item is old for old in dropped)]
            self._save_scopes([s for s in self.scopes if s is not entry], aside)
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

    @staticmethod
    def _share_record(entry):
        """What an invitation is known by: the hash of its bytes and its signer, as seen_from records it, or None."""
        digest = entry.get("sha256")
        return seen_record(digest, entry.get("from_key")) if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) else None

    def _take_scope_share(self, entry, apply=True, weigh=False):
        """A scope in an incoming message. Kept only when it came sealed and
        verified from a partner in the address book, and not seen before. The
        key is taken out of the message either way, and aamio_scope is replaced
        whatever it holds and wherever it sits, so whoever reads the message
        never sees a key in it. With apply False nothing is kept, and the key
        still comes out: for a message whose signer left the address book
        while it was being read, which goes to the archive."""
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
            view["note"] = "not kept: the key that signed it left the address book while the message was being read, so nothing from it is taken"
        elif not (entry.get("verified") and entry.get("encrypted") and entry.get("known_contact") and partner is not None):
            view["note"] = "not kept: a scope is only taken when it comes sealed from a partner in your address book"
        elif entry.get("replay"):
            view["note"] = "not kept again: this message arrived before, and a scope removed since stays removed"
        elif entry.get("replay_unknown"):
            view["note"] = "not kept: these bytes arrived here before, recorded by an earlier version without who sent them, so this may be that message again, and a scope removed since stays removed"
        elif self._share_record(entry) in self._removed_shares():
            view["note"] = "not kept again: this invitation was taken here before, and its scope was removed since. A scope removed stays removed: ask for it to be shared again"
        else:
            try:
                local = self._shared_scope_name(partner, share.get("name"))
                address = None if key is not None else share.get("address")
                held, keep = self._scope_add_plan(local, key=key, address=address)
                # Held already, nothing but the record of this invitation to write.
                plain = keep is None
                # The invitation goes with the scope, in the same write, so
                # that removing the scope can remember it.
                invitation = self._share_record(entry)
                if invitation is not None and invitation not in (held.get("taken_from") or []):
                    noted = dict(held, taken_from=list(held.get("taken_from") or []) + [invitation])
                    keep = [noted if s is held else s for s in (keep if keep is not None else self.scopes)]
                    held = noted
            except Exception as error:
                # This share alone, and nothing held that was not saved. The
                # rest of the messages are delivered either way.
                view["note"] = "not kept: %s" % error
            else:
                shown = dict(view, **self._scope_view(held), kept=True)
                unsaved = dict(view, note=self.SCOPE_NOT_SAVED)
                if weigh:
                    # Weighed, nothing is kept, and it is shown in the longer of
                    # the two forms it can take: kept, or not saved. An error of
                    # its own length in place of the kept form let a message
                    # through a byte budget it was weighed under (a review of 10
                    # November 2026).
                    view = max((shown, unsaved), key=lambda form: len(json.dumps(form, ensure_ascii=False, separators=(",", ":")).encode("utf-8")))
                else:
                    try:
                        if keep is not None:
                            self._save_scopes(keep)
                        view = shown
                    except Exception as error:
                        if plain:
                            # Held from before, and shown as it is held: only
                            # the record of this invitation was not written.
                            # Said in attention, where the reader looks: it
                            # stood in the log alone, and the reader was told
                            # kept with nothing more (a check of 11 November
                            # 2026).
                            view = shown
                            seq = entry.get("seq")
                            self._note_trouble(entry.get("channel") or "scopes", "scope_share_not_recorded", "message %s shared scope %s, which is held here already as %s, and the invitation could not be recorded with it in scopes.json: %s: %s. The scope stays as it is. Removing it will not remember this invitation, so the same message read again after that would bring the scope back." % (seq, share.get("name"), held["name"], error.__class__.__name__, error), w=entry.get("w"), seqs=[seq] if type(seq) is int else None)
                            data["aamio_scope"] = view
                            return
                        # Said in attention, with what went wrong, and on the
                        # message in the form it was weighed at.
                        view = unsaved
                        seq = entry.get("seq")
                        self._note_trouble(entry.get("channel") or "scopes", "scope_not_saved", "message %s shared scope %s, and scopes.json could not be written: %s: %s. The scope is not kept." % (seq, share.get("name"), error.__class__.__name__, error), w=entry.get("w"), seqs=[seq] if type(seq) is int else None)
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

    def _rotate_inbox(self, reason, caller=False):
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
        # The new inbox, and what it changes in the older ones, count only once
        # state.json holds them. Kept when the save failed, the next read
        # published an address whose read key this home did not have after a
        # restart, and a partner wrote where nobody could read (the release
        # check of 9 November 2026, found in the Node runtime).
        with self.lock:
            before = dict(self.channels)
            flags = [(channel, channel.label, channel.muted) for channel in before.values()]
            noted = dict(getattr(self, "attention", {}))
            if old is not None:
                self._retire_channel(old)
            self.channels["inbox"] = inbox
        # Every generation is judged, not only the one just retired: an inbox
        # from two rotations ago that still names the removed key was read on
        # until it expired, and delivered that key's messages as an unknown
        # contact.
        muted = self._mute_generations(reason)
        if old is not None:
            outcome["old_inbox"] = {"w": old.w, "muted": old.muted, "until": old.expire_at}
            if not old.muted and not old.allow:
                # In the answer of the call that changed the book, since partner
                # add on the command line is a process of its own and its notes
                # were gone before the next read; in the notes of a read otherwise.
                if caller and inbox.allow:
                    who = "any signed key" if "*" in inbox.allow else "the %d key(s) in the address book" % len(inbox.allow)
                    outcome["old_inbox"].update(open=True, note="inbox %s was open to anyone, signed or not, and is still read until %d: whoever has that address can write there until then. After %s the new inbox %s takes writes from %s only." % (old.w, old.expire_at, reason, w, who))
                else:
                    self._note(old, "open", "inbox %s was open to anyone and is still read until %d; after %s the new inbox %s names %d key(s)" % (old.w, old.expire_at, reason, w, len(inbox.allow or [])))
        if muted:
            outcome["muted"] = muted
        try:
            self.save_state()
        except OSError as error:
            with self.lock:
                self.channels = before
                for channel, label, was_muted in flags:
                    channel.label, channel.muted = label, was_muted
                self.attention = noted
            what = "the inbox opened again after %s could not be written down (%s), so it is not used: a partner would write where this home cannot read after a restart. %s" % (
                reason, errno.errorcode.get(error.errno, error.__class__.__name__), "The old inbox stays in use with its old list." if old is not None else "There is no inbox until state.json can be written.")
            self._note_trouble("inbox", "rotation_failed", what, w=old.w if old else None)
            return {"rotated": False, "inbox": old.w if old else None, "allow": self._allow_names(old.allow if old else []), "error": what}
        self.log("inbox %s until %d, %s%s" % (w, inbox.expire_at, reason, " (allowlist %d keys)" % len(inbox.allow) if inbox.allow else ""))
        outcome["presence"] = self.publish_presence(force=True)
        return outcome

    def _allow_names(self, allow):
        return [self.name_for_key(k) or k for k in (allow or [])]

    def _mute_generations(self, reason):
        """Every inbox generation that names a key no longer in the address book is marked muted.

        It is still read until it expires: what the partners still in the
        book write there is handed over, and what a removed key writes there
        is not. Read no more, as it was, a partner that had not yet learned
        the new address wrote where nobody read (a check of 12 November 2026).
        It is this runtime's delivery stopping for that key, not a revocation;
        the service takes the removed key's writes until the thread expires.
        An open generation, or one that takes any signed key, names nobody and
        is left as it is.
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
            with self.lock:
                channel.muted = True
            muted.append(channel.w)
            self._note(channel, "muted", "inbox %s names %d key(s) no longer in the address book after %s. They can still write there until %d, and what they write is not handed over; what the partners still in the book write there is read until then." % (channel.w, len(gone), reason, channel.expire_at))
        return muted

    def _left_the_book(self, channel, key):
        """Whether a message on this channel is signed by a key that has left the address book.

        On an inbox that named the key, which is read on for the partners
        still in the book. Judged message by message against the book as it
        is, so a key taken back in is read again. Called under the lock a
        removal takes to change the book.
        """
        if not isinstance(key, str) or not channel.label.startswith("inbox"):
            return False
        allow = channel.allow or []
        if "*" in allow or key not in allow:
            return False
        return key not in {p["key"] for p in self.partners}

    def _withheld_since(self, entry):
        """A message read before its signer left the address book, still waiting to be handed over: it is not, and that is said."""
        with self.lock:
            channel = next((c for c in self.channels.values() if c.w == entry.get("w")), None)
            if channel is None or entry.get("verified") is not True or not self._left_the_book(channel, entry.get("from_key")):
                return False
        self._note(channel, "removed_key", "This message was read before the key that signed it left the address book, and was waiting to be handed over. It is not handed over; the archive has it if one is kept.", seqs=[entry.get("seq")])
        return True

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

    def open_channel(self, label, ttl, allow_names=None, gate=None, to=None, note=None):
        """A channel with its own lifetime and, with to, its address handed to whoever is to write there.

        to is a partner's name or key, or a write address a verified message
        gave as reply_to or channel. That key goes on the allowlist beside the
        partners in allow, and the address goes to it sealed and signed, which
        is what makes the other runtime bind it: an address pasted into text or
        data binds nothing. Until 30 September 2026 only the command line could
        hand an address over, with aamio board channel.
        """
        check_label(label)
        taken = self._channel_called(label)
        if taken is not None:
            raise ValueError("there is a channel called %s already. Close it or choose another label" % taken.label)
        if note is not None and to is None:
            raise ValueError("note travels with the address to whoever to names, so without to there is nothing to carry it")
        keys = []
        for name in allow_names or []:
            partner = self.partner_by_name(name)
            if partner is None:
                raise ValueError("unknown partner: " + str(name))
            keys.append(partner["key"])

        if gate is not None:
            gate = check_gate(gate)

        handover = None

        if to is not None:
            # Where the address goes and whose key seals it, before anything is
            # opened: a partner who is not online, an address nobody bound, or
            # an inbox whose gate cannot be met stops here, with no channel
            # left open behind it.
            reply_to, key, _ = self._recipient(to)
            self._can_hand_over(reply_to)
            self._handover_fits(key, int(ttl), note)
            if key not in keys:
                keys.append(key)
            handover = (reply_to, key)

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
        opened = {"label": label, "w": w, "expire_at": channel.expire_at, "allow": [self.name_for_key(k) or k for k in keys], "gate": gate}

        if handover is None:
            return opened

        # The listener gives the channel a poller when it next looks, within
        # two seconds, and that first poll reads from the start, so an answer
        # to the handover that comes sooner waits for it and is not lost.
        reply_to, key = handover
        told = self._hand_over(channel, key, reply_to, note)
        opened.update({"handed_to": self.name_for_key(key) or key, "address_sent_to": reply_to}, **told)

        return opened

    def _channel_called(self, label):
        """The channel a label names, apart from upper and lower case: two labels that differ only so are one file in the archive where the file system says so."""
        wanted = str(label).lower()
        for channel in list(self.channels.values()):
            if channel.label.lower() == wanted:
                return channel
        return None

    def _can_hand_over(self, reply_to):
        """Whether the inbox at reply_to takes a handover from here, asked before a channel is opened for it.

        Its gate is read as a send reads it. Work that takes longer than a
        caller with a time limit may wait stops here: a send can do its work in
        the background, and a handover that did would leave the channel open
        while the address was still on its way.
        """
        advice = self._plan_for(reply_to)
        budget = getattr(self, "work_budget", None)

        if budget is not None and advice.get("expected_seconds", 0) > budget:
            raise GateStop(
                "the inbox at %s asks for %d bits of proof of work, about %s here, longer than this call may take, so no channel was opened"
                % (reply_to, advice["bits"], describe_seconds(advice["expected_seconds"])),
                "Hand the channel over from the command line, where the work has the time it needs: aamio board channel KEY --reply-to ADDRESS.",
            )

    def _invitation(self, key, w, expire_at, note=None):
        """The body that carries a channel's address, and the envelope it is sealed in."""
        body = {"channel": w, "expire_at": expire_at}
        if note:
            body["text"] = str(note)
        body.update(self._conversation(key))
        return body, self.keys.seal(key, json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def _handover_fits(self, key, ttl, note=None):
        """Whether the message that will carry a channel's address fits in one message, asked before the channel is opened.

        The address and the expiry are not known yet. Both have a fixed length,
        so a stand-in of the same length seals to the same size. A note too long
        for it used to open the channel first, and the message carrying the
        address was then refused, or counted in aamio-php as one that might
        have landed (a review, 30 September 2026).
        """
        body, _ = self._invitation(key, "a" * 20, int(time.time()) + int(ttl), note)
        # seen can appear before the handover, if a message from this key is read
        # meanwhile, and it is always 64 characters: counted as there already.
        body.setdefault("seen", "0" * 64)
        size = len(self.keys.seal(key, json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).encode("utf-8"))

        if size > MESSAGE_MAX_BYTES:
            raise ValueError(
                "with this note the message carrying the address would be %d bytes, and a message is at most %d, so no channel was opened. "
                "Shorten the note, and send the rest on the channel once it is open." % (size, MESSAGE_MAX_BYTES)
            )

    def _hand_over(self, channel, key, reply_to, note=None):
        """The channel's address sent to reply_to, sealed to key and signed, through the outbox like any send.

        Returns what the caller's answer should carry besides: nothing, or that
        the address went and the record of it did not reach the disk.

        Whatever stops it, the channel is open by now, and the failure says so
        and says whether anything left this machine. Only a refusal and a gate
        used to: a file that would not write, found in a review of 30 September
        2026, left an open channel out of the answer.
        """
        opened = {"label": channel.label, "w": channel.w, "expire_at": channel.expire_at}
        entry = None
        try:
            body, envelope = self._invitation(key, channel.w, channel.expire_at, note)
            # The message that carries the address is a send, and goes through
            # the outbox like one. It was posted directly, and a refusal was a
            # RuntimeError: a traceback on the command line, with the channel
            # open and the address delivered to nobody.
            entry = self._outbox_add(reply_to, key, envelope, body)
            status, handed = self._deliver(entry)
        except GateStop as stop:
            # The channel is open whatever stopped the message, and the caller
            # has to hear that as well as why.
            stop.opened = opened
            raise
        except Exception as error:
            why = "%s: %s" % (error.__class__.__name__, error)
            # posting is set in the moment before the bytes leave, so without it
            # nothing did, and the entry says so, as a stop before the post does.
            if entry is None or not entry.get("posting"):
                if entry is not None:
                    entry["status"] = "unknown" if entry.get("ever_open") else "stopped"
                    entry["error"] = why
                raise SendFailed("never_sent", entry["id"] if entry is not None else None, 0, why, opened=opened) from error
            settled = outbox_outcome(entry)
            if settled == "delivered":
                # The service stored it, and only the record here did not reach the disk.
                return {"outbox_error": why}
            # A refusal the service answered settles it, and anything else that
            # left may have landed.
            raise SendFailed("refused" if settled == "refused" else "unknown", entry["id"], entry.get("last_status") or 0, why, opened=opened, trace_error=entry.get("trace_error")) from error
        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, handed, opened=opened, trace_error=entry.get("trace_error"))
        return {}

    def close_channel(self, label):
        """Closes a channel before it expires, and says what happened here and at the service.

        The thread is asked gone at the service first, and the channel leaves
        this home when the service says it is gone: deleted now, or not there
        any more. When the service does not say so, the channel stays and is
        still read. It used to leave the home whatever the answer was: with no
        answer at all the thread lived on at the service, and whoever wrote
        there wrote where nobody read (a check of 12 November 2026, found
        while the Node runtime's channels were built).
        """
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.delete(channel.w, channel.read_key)
        if status not in (200, 404, 410):
            return {
                "label": label, "w": channel.w, "status": status, "deleted": False, "closed_here": False,
                "note": "%s, so the thread may still be there, and the channel is kept and still read. Close it again, or let it expire at %d."
                        % ("The service did not answer" if status == 0 else "The service answered %s" % status, channel.expire_at),
            }
        with self.lock:
            self.channels.pop(label, None)
        try:
            self.save_state()
        except OSError as error:
            with self.lock:
                self.channels[label] = channel
            raise RuntimeError(
                "%s, and state.json could not be written (%s), so this home still lists %s. Close it again once the disk takes writes."
                % ("the thread is deleted at the service" if status == 200 else "there is no thread at the service any more", errno.errorcode.get(error.errno, error.__class__.__name__), label)
            ) from None
        channel.closed = True
        closed = {"label": label, "w": channel.w, "status": status, "deleted": status == 200, "closed_here": True}
        if status != 200:
            closed["note"] = "There was no thread at this address any more: it had expired, or was closed before. The channel is taken out of this home."
        return closed

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
            before = dict(self.channels)
            label = held.label if held is not None else None
            if held is not None:
                self._retire_channel(held)
            self.channels["board"] = channel
        try:
            self.save_state()
        except OSError as error:
            # As with the inbox: an address this home cannot read after a restart is never put on a post.
            with self.lock:
                self.channels = before
                if held is not None:
                    held.label = label
            raise RuntimeError("the board inbox could not be written down (%s), so nothing was posted or sent: an answer would come where this home cannot read after a restart" % errno.errorcode.get(error.errno, error.__class__.__name__)) from None
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
        channel = self.ensure_board_inbox(int(ttl) + BOARD_POST_MARGIN)
        # The board refuses a post that would outlive the inbox behind it, so
        # that an address on the board is always an address that still works.
        # At the top of the range the inbox cannot be opened for longer than
        # the post asked for, so the post gives way, not the promise, and it
        # leaves the inbox the margin the work and the round trip take.
        life = min(int(ttl), int(channel.expire_at - time.time()) - BOARD_POST_MARGIN)
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
        archive_error = self._archive_done("board", {"kind": "posted", "at": time.time(), "post": data}, "the post %s" % (data.get("id") if isinstance(data, dict) else ""))
        # Where the answers go, and how to read them, in the answer itself. An
        # agent took board replies for the whole inbox, got nothing back, and
        # spent an hour decrypting by hand what read would have shown at once.
        # And until when that inbox is open, which is not the post's own time:
        # post.expire_at is when the post leaves the board, and the inbox
        # outlives it. The three runtimes say it under the same name.
        posted = {"post": data, "inbox": channel.w, "inbox_expires_at": channel.expire_at, "answers_arrive_on": "board", "read_them_with": "Read them with read, aamio read on the command line and aamio_read over MCP, which shows every message on your inboxes. board replies lists only the answers, the messages that name a post of yours or arrived on a board inbox, and says how many it left out."}
        if held is not None:
            posted["scope"] = held["name"]
        if archive_error is not None:
            posted["archive_error"] = archive_error
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
        archive_error = self._archive_done("board", {"kind": "withdrawn", "at": time.time(), "id": post_id}, "the withdrawal of post %s" % post_id)
        return dict(data, archive_error=archive_error) if archive_error is not None and isinstance(data, dict) else data

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
        archive_error = self._archive_done("board", {"kind": "answered", "at": time.time(), "post": post["id"], "w": post["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "body": body}, "the answer %s" % entry["id"])
        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, result, trace_error=entry.get("trace_error"), archive_error=archive_error)
        answer = {"post": post["id"], "w": post["w"], "message_id": entry["id"], "seq": result["seq"], "at": result["at"], "replies_arrive_on": "board", "reply_to": channel.w}
        if "met" in result:
            answer["met"] = result["met"]
            answer["proof_id"] = result.get("proof_id")
        if entry.get("gate_notes"):
            answer["notes"] = entry["gate_notes"]
        # The call this whole round came from: answer a post and exit, with no
        # logger and no second call to fetch attention.
        if entry.get("trace_error"):
            answer["trace_error"] = entry["trace_error"]
        if archive_error is not None:
            answer["archive_error"] = archive_error
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
        skipped = []

        # One delivery is one row. The hash alone is of the text, and of two
        # signers who sent the same answer to one post the second was left out
        # once the list came from the archive; and a thread opened again at the
        # same address in the same second gives a message the same seq and the
        # same time as one of the old thread, so the address, the seq, the time
        # and the hash together still made two deliveries one (two reviews of
        # 11 November 2026). A row with its thread's instance, as every copy in
        # memory and every row the archive writes has it now, is one delivery by
        # its address, instance and seq, and the first of its copies stands, as
        # it was first handed over: a copy in memory that knew only what it
        # showed hid an answer on the other thread, and a delivery read twice was
        # listed twice (a check of the same day). The first copy is the one the
        # archive has from before, when it has one this process did not write:
        # an answer read again after a restart was listed with the mark of the
        # reading, replay, by the process that read it, and with the mark it
        # first came with by the next (a check of 0.7.42, the same day). Any
        # other row is told by all it shows, its verified signer too, and two
        # such rows that show the same are both kept: nothing says they are one.
        def one(entry):
            instance = entry.get("instance")
            return (entry.get("w"), instance, entry.get("seq")) if isinstance(instance, str) else None

        def shown(entry):
            return (entry.get("w"), entry.get("seq"), entry.get("at"), entry.get("sha256"), entry.get("from_key"))

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
        held = []
        for channel in list(self.channels.values()):
            with channel.lock:
                held.extend(channel.received)

        # A board inbox is renewed while the old one still holds answers, and
        # the old one keeps its own label and its own archive. Once that
        # channel expires it leaves self.channels, and reading only the
        # channels this process holds made those answers vanish from here
        # although they had arrived, been decrypted and been written down.
        # By the files that are there, and the files the channels held here
        # write to: a file an earlier version wrote under a label as it stood
        # is read under the name it has.
        rows = []
        for name in sorted(self._archive_labels() | {storage.archive_name(label) for label in self.channels} | {"board"}):
            rows.extend(self._archived(name, "received"))

        # A delivery the archive has more rows of than this process wrote was
        # written down before this process read it: that row is its first
        # copy, and the copies held here are later readings of it.
        stored = collections.Counter(delivery for delivery in map(one, rows) if delivery is not None)
        written = collections.Counter(one(entry) for entry in held if one(entry) is not None and entry.get("archived") is not False)
        earlier = {delivery for delivery, count in stored.items() if count > written[delivery]}

        named = set()
        for entry in held:
            delivery = one(entry)
            if delivery is not None:
                if delivery in named or delivery in earlier:
                    continue
                named.add(delivery)
            if wanted(entry):
                out.append(entry)
            else:
                skipped.append(entry)

        # A copy in memory without the instance, from a service that names
        # none, has its row in the archive as well when it was written down,
        # and stands for one row there that shows the same. One that was not
        # written down has no row there and stands for none: it would hide
        # another delivery that shows the same.
        on_disk = collections.Counter(shown(entry) for entry in held if one(entry) is None and entry.get("archived") is not False)

        for entry in rows:
            delivery = one(entry)
            if delivery is not None:
                if delivery in named:
                    continue
                named.add(delivery)
            elif on_disk[shown(entry)] > 0:
                on_disk[shown(entry)] -= 1
                continue
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
        """Labels this runtime has an archive for, the ones a board inbox uses, whether the archive is on or off."""
        home = getattr(self, "home", None)

        if not home:
            return set()

        try:
            names = os.listdir(os.path.join(home, "archive"))
        except OSError as error:
            self._note_trouble("archive", "unread", "the archive could not be listed (%s), so answers written down earlier are not in this result" % error.__class__.__name__)
            return set()

        return {name[: -len(".jsonl")] for name in names if name.endswith(".jsonl") and name.startswith(prefix)}

    def _archived(self, label, kind):
        """Entries this client wrote down for a channel, or in one file of the archive by its name, oldest first. Silent
        when the file is not there: an empty archive is not an error, it is a
        client that was told not to keep one.

        With the archive off nothing is written, and what an earlier run wrote
        is still read: it stays the record of what arrived until it is pruned.
        A process with the archive off did not look, and listed an answer
        written down before it with the mark of its own later reading (a check
        of 11 November 2026)."""
        home = getattr(self, "home", None)

        if not home:
            return []

        # The file the folder lists under this name, when it lists one, and
        # else the file archive() writes for this label. Board replies read
        # by the names the folder lists, so each file is read once: the one
        # an earlier version wrote under a label as it stood, a name with a
        # space in it, as well as the one written now. A name is the folder's
        # own or made here, never a path a caller gave.
        name = label if label in self._archive_labels() else storage.archive_name(label)
        path = os.path.join(home, "archive", "%s.jsonl" % name)

        if not os.path.isfile(path):
            return []

        found = []

        for raw in storage.raw_lines(path):
            # A line that is not UTF-8 is no record, as one cut short by a
            # crash is not. Read as text, it stopped the whole read.
            try:
                line = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                continue

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
        if label:
            # A label the caller chose is a file's name too, as in open_channel.
            check_label(label)
        label = label or ("with-" + key_hash(key)[:8])
        # Taken apart from case counts as taken: the two would be one file in
        # the archive where the file system says so.
        if self._channel_called(label) is not None:
            label = "%s-%d" % (label, int(time.time()))
        if reply_to:
            # The gate of the inbox the address goes to, read before anything
            # is opened, as open_channel and the Node runtime read it: a gate
            # that cannot be met stopped the handover after the channel was
            # open, and it stayed open with nobody given its address.
            self._can_hand_over(reply_to)
            self._handover_fits(key, int(ttl), note)
        status, data, read_key, w = self.client.open_thread(int(ttl), [key])
        if status != 201:
            raise RuntimeError("could not open channel: %s %s" % (status, data))
        channel = Channel(label, read_key, w, data["expire_at"], [key])
        with self.lock:
            self.channels[label] = channel
        self.save_state()
        if self.listener is not None:
            self._start_poller(channel)
        told = self._hand_over(channel, key, reply_to, note) if reply_to else {}
        return dict({"label": label, "w": w, "expire_at": channel.expire_at, "with": self.name_for_key(key) or key, "address_sent_to": reply_to}, **told)

    # ----------------------------------------------------------- lookup --

    def lookup(self, names=None, wait=0):
        """Which partners are reachable now, and where.

        A name is chosen as a send chooses it: exactly, or apart from case when
        only one partner is so named, and AmbiguousPartner when two are.
        Matched without regard to case, ADA brought Ada back as well, and a
        caller that took the first address answered the wrong partner (the
        release check of 9 November 2026, found in the Node runtime). A name
        that is nobody's is said in unknown, and only the partners asked for
        are answered for.
        """
        unknown = []
        if names:
            partners = []
            for name in names:
                partner = self.partner_by_name(name)
                if partner is None:
                    unknown.append(str(name))
                elif all(p["key"] != partner["key"] for p in partners):
                    partners.append(partner)
        else:
            partners = self.partners
        if not partners:
            return dict({"online": [], "offline": [], "error": "no partners to look up"}, **({"unknown": unknown} if unknown else {}))
        prefixes = [key_hash(p["key"])[:8] for p in partners]
        status, data = self.client.presence_lookup(prefixes, wait)
        if status != 200:
            # What was settled here before the service was asked stays said: a
            # name that is nobody's went missing from the answer when the lookup
            # failed (a review of 10 November 2026).
            return dict({"online": [], "offline": [p["name"] for p in partners], "error": "lookup failed: %s %s" % (status, data)}, **({"unknown": unknown} if unknown else {}))
        online = []
        found = set()
        asked = {p["key"] for p in partners}
        for match in data.get("matches", []):
            partner = self.partner_by_key(match.get("key"))
            if partner is None or partner["key"] not in asked:
                continue
            found.add(partner["name"])
            with self.lock:
                self.peers[match["w"]] = partner["key"]
            online.append({"name": partner["name"], "w": match["w"], "tags": match.get("tags", []), "expires_at": match.get("expire_at")})
        self.save_state()
        result = {"online": online, "offline": [p["name"] for p in partners if p["name"] not in found]}
        if unknown:
            result["unknown"] = unknown
        return result

    def address_for(self, name):
        """The write address a partner currently answers on, from presence: that partner's own record, never another's.

        The lookup is by name without regard to case, so with Ada and ADA in the
        book both came back, and the first one online was taken whichever was
        asked for: a message sealed to one key went to the other's inbox.
        """
        partner = name if isinstance(name, dict) else self.partner_by_name(name)
        if partner is None:
            raise ValueError("unknown partner: " + str(name))
        result = self.lookup([partner["name"]])
        for entry in result["online"]:
            if entry["name"] == partner["name"]:
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
        w, key, partner = self._recipient(to)
        return self._send(w, key, partner, text, data, reply_to, answers=answers)

    def _recipient(self, to):
        """Where a message for to goes, the key it is sealed to, and the partner's name when it is one.

        to is a partner's name or key, reached at the address presence gives,
        or a write address whose key this runtime knows: from presence, or from
        reply_to or channel in a verified message. A send and a handover find
        their recipient the same way.
        """
        if is_key(str(to)):
            # The partner the key names, kept as it is: turned into its name and
            # looked up again, it could become another partner of that name.
            partner = self.partner_by_key(to)
            if partner is None:
                raise ValueError("key is not in partners")
            w, key = self.address_for(partner)
            return w, key, partner["name"]
        if isinstance(to, str) and re.fullmatch(r"[a-z2-7]{20}", to):
            key = self.peers.get(to)
            if key is None:
                # What to do instead, said where it stops. An address pasted into
                # text or data is the dead end an agent on MCP walks into: the
                # tool that opens a channel returns an address, and nothing here
                # learns whose it is from reading it (item 5 of the round-2 list).
                raise LookupError(
                    "no key known for address %s. A runtime learns whose an address is from presence, or from reply_to or channel in a "
                    "verified message; one pasted into text or data binds nothing. Send to the partner by name, answer a message at its "
                    "reply_to, or ask the owner to hand the address over: aamio_open_channel with to, or aamio board channel KEY --reply-to ADDRESS "
                    "on the command line" % to
                )
            return to, key, None
        partner = self.partner_by_name(to)
        if partner is None:
            raise ValueError("unknown partner: " + str(to))
        w, key = self.address_for(partner)
        # The book's own spelling, so asking presence again after a 404 or a
        # 410 asks for this partner and no other.
        return w, key, partner["name"]

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
            raise SendFailed(entry["status"], entry["id"], status, result, trace_error=entry.get("trace_error"), archive_error=archive_error)

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
        # A script that sends once and exits never fetches attention, so the
        # failure rides on the answer it does read. A review, 26 September.
        if entry.get("trace_error"):
            sent["trace_error"] = entry["trace_error"]
        return sent

    def _archive_done(self, label, record, what):
        """Write the record of something that is done already, and say what went wrong instead of raising it.

        The post is made, the answer delivered, the receipt taken. A record of
        it that cannot be written is said beside it and in attention. Raised,
        it told the caller that the thing itself had failed: an answer on the
        board was stored at the service and settled as delivered in the
        outbox while the call raised OSError, and over MCP the advice that
        went with it was to call again, which is a second answer (a check of
        12 November 2026, found while the Node runtime's archive was built). A
        send has had this since _archive_sent.
        """
        try:
            self.archive(label, record)
        except Exception as error:
            how = "%s: %s" % (error.__class__.__name__, error)
            self.log("archive %s: %s" % (label, how))
            # Attention keeps one note for each place and state, so a second
            # record that could not be written would take the place of the
            # first. Each is said, in the one note, until the note is taken.
            with self.lock:
                missing = list(getattr(self, "archive_missing", [])) + ["%s could not be written to the archive: %s." % (what, how)]
                self.archive_missing = missing
            self._note_trouble("archive", "archive_failed", "%s The archive does not have %s." % (" ".join(missing), "it" if len(missing) == 1 else "them"))
            return how
        return None

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
        size = len(envelope.encode("utf-8"))

        # Every send passes here, so a message too large for any inbox stops here,
        # before an entry exists, a byte leaves or a gate is worked for. aamio-php
        # stored one and its client refused it afterwards, which left a message
        # that could never go looking as if it might have (a health check of 30
        # September 2026); here it went out and came back 413.
        if size > MESSAGE_MAX_BYTES:
            raise ValueError("this message is %d bytes sealed, and a message is at most %d, so nothing was stored or sent. Send a URL and a hash instead." % (size, MESSAGE_MAX_BYTES))

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
            earlier = self.outbox.get(entry["id"])
            self.outbox[entry["id"]] = entry
        try:
            self.save_outbox()
        except Exception:
            # An entry that could not be written is taken out again: nothing was
            # sent for it, and left in memory the next save that works wrote it as
            # a send in flight, which a restart made unknown and offered to send
            # again. A review of 30 September 2026.
            with self.lock:
                if self.outbox.get(entry["id"]) is entry:
                    if earlier is None:
                        del self.outbox[entry["id"]]
                    else:
                        self.outbox[entry["id"]] = earlier
            raise

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
            try:
                asked = gate_plan(result["gate"], w, self.host, left)
                notes.extend(note for note in asked["notes"] if note not in notes)

                if asked["bits"] and asked["bits"] != advice["bits"]:
                    status, result = self._post_with_work(w, body_text, signature, asked["bits"], left, entry)
            except GateStop as stop:
                # It went once, and the inbox refused it with 428. Not sending it
                # again leaves that refusal as the answer, with why it was not met.
                # A stop here used to read as one before anything left, so the
                # message was called never sent, or left open to a retry, and it
                # had gone (a health check of 30 September 2026).
                result = dict(result, fix=refused_once(stop))

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
                "the inbox asks for %d bits of work and the time it still takes writes ran out before a nonce was found" % bits,
                "Open a thread with a longer life, or send this to an inbox whose gate asks for less: the same bytes are still here under this message id.",
            )

        # The work is done and nothing has left yet.
        self._about_to_post(entry)

        if entry is not None:
            entry["status"] = "sending"
            self.save_outbox()

        return self.client.post(w, body_text, self.keys.public, signature, "text/plain", nonce)

    # ----------------------------------------------------------- deliver --

    def _deliver(self, entry):
        """Send the stored bytes once, and record what the answer allows us to claim."""
        entry["attempts"] += 1
        entry["status"] = "sending"
        try:
            self.save_outbox()
        except Exception as error:
            # Nothing has left this machine, and nothing will: the send stops here
            # with its reason, and the entry says so, as a stop at a gate does. As
            # sending, the next save that works wrote it as a send in flight, and
            # a restart offered to send it again. Unless an earlier attempt is
            # still open: a stop now settles this decision, not that one.
            entry["status"] = "unknown" if entry.get("ever_open") else "stopped"
            entry["error"] = "%s: %s" % (error.__class__.__name__, error)
            entry["last_at"] = int(time.time())
            raise
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
        # After the outcome is saved, and unable to change it. What the entry
        # says of the trace is this attempt's: a retry whose trace was written
        # does not go on saying that the first attempt's could not be.
        entry.pop("trace_error", None)
        self._trace_safely("sent", self._trace_sent, entry, status, result, on=entry)

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
            row = {"id": entry["id"], "w": entry["w"], "status": entry["status"], "http": status}
            # A retry run once from a script never fetches attention either.
            if entry.get("trace_error"):
                row["trace_error"] = entry["trace_error"]
            out.append(row)

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
            if state in ("kept_out", "removed_key", "unverified", "binding_conflict", "archive_failed", "scope_not_saved", "scope_share_not_recorded", "replay_unknown") and seqs is not None:
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
            self.archive_missing = []
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
            replay = replay_state(channel, digest, sender)
            entry = {"channel": channel.label, "w": channel.w, "seq": seq, "at": at, "verified": verified, "from_key": sender, "known_contact": known is not None, "sender": known or ("unknown key" if sender else "unsigned"), "sha256": digest, "replay": replay is True, "body": body}
            entry.update(meta)
            if replay is None:
                entry["replay_unknown"] = True
            if why_not:
                entry["unverified_because"] = why_not
            return entry
        except Exception as error:
            why = "the message could not be checked here: " + error.__class__.__name__
            return {"channel": channel.label, "w": channel.w, "seq": seq, "at": at, "verified": False, "from_key": None, "known_contact": False, "sender": "unsigned", "sha256": None, "replay": False, "body": {"text": message.get("body")}, "signed": False, "encrypted": False, "format": "unreadable", "error": error.__class__.__name__, "unverified_because": why}

    def _binding_conflict(self, field, address, sender_key):
        """The conflict a verified claim of this address would be, or None: nothing is bound here."""
        if not isinstance(address, str) or not re.fullmatch(r"[a-z2-7]{20}", address):
            return None
        with self.lock:
            bound = self.peers.get(address)
        if bound is None or bound == sender_key:
            return None
        return {"field": field, "address": address, "claimed_by": sender_key, "bound_to": bound}

    def _weight_as_handed_over(self, channel, raw):
        """The bytes of a row as this read would hand it over, or None when the channel's list keeps it out.

        Worked out on a copy, keeping nothing: the scope share in it as shown
        when it is not taken, the binding conflicts it would carry, and the
        archive's mark. The listener's measure: compact JSON in UTF-8.
        """
        entry = self._read_entry(channel, copy.deepcopy(raw))
        sender_key = entry["from_key"]
        if channel.allow and not (entry["verified"] and ("*" in channel.allow or sender_key in channel.allow)):
            return None
        self._take_scope_share(entry, weigh=True)
        if isinstance(entry["body"], dict) and entry["verified"] and sender_key:
            conflicts = [c for c in (self._binding_conflict(field, entry["body"].get(field), sender_key) for field in ("reply_to", "channel")) if c is not None]
            if conflicts:
                entry["binding_conflicts"] = conflicts
        # The archive's mark is weighed at its longer value, false: a write that
        # fails turns true into false after the weighing, and a budget must hold
        # for what is handed over. One written is a byte under.
        entry["archived"] = False
        if not (getattr(self, "archive_enabled", False) and getattr(self, "home_released", False) is not True):
            entry["archive_off"] = True
        return len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def _set_cursor(self, channel, to_seq):
        """The cursor moves to exactly this, forwards or backwards, and is written down with the hashes.

        When the writing fails the cursor stays where it was last written
        down, and attention says so. The same messages arrive again on the
        next read, and the hashes kept in memory mark them as replays while
        this process runs, which is what a crash would have given, and the
        safe direction: a message twice is a nuisance, a message never is a
        loss. It used to throw straight out of poll, and the loop that calls
        poll logged it and slept, so messages that had arrived and been
        checked never reached the queue.
        """
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
        channel.more_at_limit = False
        channel.stopped_at_budget = False
        # A muted inbox is read like any other, until it expires: each message
        # is judged against the address book below, and what a removed key
        # writes there is not handed over, whoever calls.
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
        expires = data.get("expire_at") if _whole(data.get("expire_at")) else None
        reset = data.get("reset")
        # A thread is known by when it was opened and when it expires. One that a
        # write opened after the service restarted has the service's own
        # lifetime, so it is told apart even when it was opened in the same second.
        instance = data.get("instance") if isinstance(data.get("instance"), str) else None
        # The instance the service names the thread by decides where there is
        # one; when and how long it was opened for, where there is none.
        known = channel.instance is not None and instance is not None
        if known:
            another = instance != channel.instance
        else:
            another = channel.created_at is not None and ((created is not None and created != channel.created_at) or (expires is not None and expires != channel.expire_at))
        if another and not reset:
            if known:
                self._note(channel, "restarted", "the thread at this address is a new one, instance %s where this channel knew instance %s, so it is read again from the start" % (instance, channel.instance))
            else:
                self._note(channel, "restarted", "the thread at this address is a new one, opened at %s and expiring at %s, where this channel knew one opened at %s and expiring at %s, so it is read again from the start" % (created, expires, channel.created_at, channel.expire_at))
            channel.forget_thread()
            return self.poll(channel, 0, limit, max_bytes)
        # A cursor kept by a client that did not keep the thread's instance,
        # this one before 10 November 2026 among them, cannot be checked against
        # it: a thread opened again at this address in the same second, with the
        # same lifetime and list, looks the same in every other field, and its
        # first messages were passed over without a word (a review of 10
        # November 2026). So the thread is read again from the start, once, and
        # all of it is handed over: what this channel handed over before comes
        # again marked replay, as after a restart. Nothing is passed over by its
        # hash, which is the hash of the text alone: another sender's message
        # with the same text has it too (the same review).
        if not another and not reset and channel.after > 0 and channel.instance is None and instance is not None:
            self._note(channel, "reread", "this channel's cursor, %s, was kept by a client that did not keep the thread's instance, so it cannot be told whether the thread here is the one that cursor was kept on. It is read again from the start this once: what this channel handed over before comes again, marked replay, or replay_unknown where an earlier version kept it without who sent it, and nothing is passed over." % channel.after)
            channel.after = 0
            return self.poll(channel, 0, limit, max_bytes)
        if reset:
            self._note(channel, "restarted", (reset.get("what") if isinstance(reset, dict) else None) or "the service read this thread from the start")
            with channel.lock:
                channel.observed.clear()
        # The channel follows the thread that is there, all of it at once: one
        # taken up after its cursor was forgotten, or read from the start by the
        # service after a restart, may expire at another time than the one
        # opened. A channel that took the new instance and kept the old expiry
        # chose an inbox that had expired, and one that expired later was given
        # up early (a review of 10 November 2026). The list this channel was
        # opened with is its own, and stays.
        if (channel.created_at is None or another or reset) and expires is not None:
            channel.expire_at = expires
        channel.created_at = created
        if instance is not None:
            channel.instance = instance

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
            # The advice is this runtime's own. The service's speaks of the
            # header this read sent and of stepping past the message with after,
            # and whoever reads this note set max_bytes and holds no cursor.
            self._note(
                channel,
                "too_large",
                "message %s on this channel is %s bytes and does not fit the byte budget this read asked for, so it was not sent. It is still there, what was written after it waits behind it, and every read at this budget will leave it. Read again with a larger budget to take it: max_bytes, or --max-bytes on the command line."
                % (seq, size),
                seqs=[seq] if seq is not None else None,
            )

        # And what it held back that does fit: more messages after the ones
        # sent. The service says more both when the count this read asked for
        # was reached and when the byte budget was, and the note says which: a
        # read for one message blamed a budget nobody had set (a review of 10
        # November 2026).
        if data.get("more") is True:
            channel.more_at_service = True
            channel.more_at_limit = limit is not None and len(data.get("messages") or []) >= limit

        entries = []
        kept_out = []
        # Messages signed by a key that has left the address book, on an inbox
        # that named it: passed by like the ones the list keeps out, and said.
        withheld = []
        last_seq = None
        # The budget is kept here as well, for what is handed over, measured as
        # it is handed over: the service counts its own form of each message, and
        # a read of 512 bytes handed over 660 (a review of 10 November 2026). A
        # row that does not fit is not taken: it is not observed, not remembered,
        # binds and shares nothing, and the cursor stays before it.
        used = 0
        oversized = None
        fetched = data.get("messages", [])
        for index, raw in enumerate(fetched):
            if limit is not None and len(entries) >= limit:
                channel.left_waiting = len(fetched) - index
                break
            if max_bytes is not None:
                weight = self._weight_as_handed_over(channel, raw)
                if weight is not None:
                    if entries and used + weight > max_bytes:
                        channel.stopped_at_budget = True
                        break
                    # Alone and still over the budget: it has come, so it is
                    # handed over on its own rather than kept back for ever.
                    if not entries and weight > max_bytes:
                        oversized = (raw.get("seq") if isinstance(raw, dict) else None, weight)
                    used += weight
            entry = self._read_entry(channel, raw)
            message = raw if isinstance(raw, dict) else {}
            last_seq = entry["seq"] if last_seq is None else max(last_seq, entry["seq"])
            sender_key = entry["from_key"]
            excluded = bool(channel.allow and not (entry["verified"] and ("*" in channel.allow or sender_key in channel.allow)))
            with channel.lock:
                # The rows belong to the thread they were read on. After the
                # service restarted, a receipt of the new thread at the same
                # address was compared with rows of the old one (a review of 10
                # November 2026).
                if (channel.observed_created_at, channel.observed_expire_at, channel.observed_instance) != (channel.created_at, channel.expire_at, channel.instance):
                    channel.observed.clear()
                    channel.observed_created_at = channel.created_at
                    channel.observed_expire_at = channel.expire_at
                    channel.observed_instance = channel.instance
                channel.observed[entry["seq"]] = {"seq": entry["seq"], "at": entry["at"], "sha256": entry["sha256"], "from": message.get("service_from", message.get("from")), "verified": entry["verified"], "from_key": sender_key}
            why_not = entry.get("unverified_because")
            if why_not and message.get("service_verified", message.get("verified")):
                disposition = "kept out by this channel's list" if excluded else "handed over as unverified"
                self._note(channel, "unverified", "message %s on this channel was called verified by the service and does not check out here: %s. It is %s. That is a fault in the service or an operator that lies, and whoever runs it should hear of it." % (entry["seq"], why_not, disposition), seqs=[entry["seq"]])
            if excluded:
                kept_out.append(entry["seq"])
                continue
            with self.lock:
                gone = entry["verified"] is True and self._left_the_book(channel, sender_key)
            if gone:
                withheld.append(entry["seq"])
                continue
            if entry["sha256"] is not None:
                remember(channel, entry["sha256"], entry["from_key"])
            # Before the message is kept, archived or shown: a scope key in it
            # goes to scopes.json or nowhere, never to the reader. And a
            # verified message that carries an address binds the sender's key
            # to it: reply_to, as always, and channel, which a handoff carries.
            # A handoff used to leave the new address without a key, so the
            # first send to it failed with no key known for the address; an
            # address another key already holds is not rebound by a claim.
            #
            # Under the lock a removal takes to change the book, and judged
            # message by message: a partner removed while the read was out, or
            # while this batch is being applied, shares nothing and binds
            # nothing from that moment on. The key comes out of the message
            # either way, since the message goes to the archive. Read once
            # before the batch, a removal was missed by everything after that
            # reading; skipped whole, the share left its key in the record.
            # Findings K1 and K2 of the health check of 24 September 2026.
            with self.lock:
                applying = not (entry["verified"] is True and self._left_the_book(channel, sender_key))
                self._take_scope_share(entry, apply=applying)
                if applying and isinstance(entry["body"], dict) and entry["verified"] and sender_key:
                    for field in ("reply_to", "channel"):
                        self._bind_claimed_address(channel, entry, field, entry["body"].get(field), sender_key)
                # And the trace: what came from this key, and what it says it
                # read of ours. Verified only, since an unsigned message can
                # claim to be from anyone and to have read anything. Whatever
                # goes wrong in the trace costs the trace, never this batch, and
                # is said in attention, not on the message: a message has to be
                # the size it was weighed at, and an error added after the
                # weighing let 1310 bytes through a budget of 716 (a review of
                # 10 November 2026).
                if applying and entry["verified"] and sender_key:
                    self._trace_safely("received", self._trace_received, channel, entry)
            entries.append(entry)
            # Received, readable, archived and handled are four different
            # things, and a failure at one must not be reported as the others.
            # The message above is delivered already; whether it also reached
            # the file on disk is recorded here, and is never allowed to cost
            # the rest of the batch, which is what a full disk would otherwise
            # do. Nor is it swallowed: it stays on the entry and in the log,
            # because a storage failure is worth knowing about.
            try:
                # With the thread's instance: a thread opened again at the same
                # address in the same second gives a message the same seq and
                # the same time as one of the old thread, and board replies had
                # nothing else to tell the two by (a review of 11 November 2026).
                row = dict(entry, kind="received")
                if isinstance(channel.instance, str):
                    row["instance"] = channel.instance
                wrote = self.archive(channel.label, row)
                entry["archived"] = wrote is not False

                if wrote is False:
                    # Nothing went wrong and nothing was written: this folder keeps
                    # nothing decrypted. Said, so the caller does not go looking.
                    entry["archive_off"] = True
            except Exception as error:
                # Said in attention, not on the message: a message has to be the
                # size it was weighed at, and an error of any length added after
                # the weighing let 1108 bytes through a budget of 724 (a review of
                # 10 November 2026). false is the longer of the two marks, and the
                # one the budget counts.
                entry["archived"] = False
                self._note(channel, "archive_failed", "message %s was handed over and could not be written to the archive: %s: %s. The archive does not have it." % (entry["seq"], error.__class__.__name__, error), seqs=[entry["seq"]])
                self.log("archive %s seq %s: %s" % (channel.label, entry["seq"], error))
            # The copy board replies keep, with the archive's mark and the
            # thread's instance, which the message handed over does not carry:
            # one delivery is known by its address, instance and seq in memory
            # as it is in the archive (a check of 11 November 2026).
            with channel.lock:
                channel.received.append(dict(entry, instance=channel.instance) if isinstance(channel.instance, str) else dict(entry))
        # Messages whose bytes this channel handed over before, which an earlier
        # version recorded without who sent them: whether each is a copy cannot
        # be told, and it is said rather than guessed.
        unknown = [entry["seq"] for entry in entries if entry.get("replay_unknown")]
        if unknown:
            self._note(channel, "replay_unknown", "these carry the bytes of a message this channel handed over before, which an earlier version recorded without who sent it, so whether each is a copy cannot be told: each comes with replay false and replay_unknown true.", seqs=unknown)
        # The cursor moves once, to where this read leaves it, and is written
        # down once, with the hashes, before the caller sees a single message.
        # A crash after this point redelivers nothing; a crash before it
        # redelivers everything, and the stored hashes mark those replays. Two
        # writes in one read let attention say the cursor stayed at 0 when the
        # second had written 1 (a check of 11 November 2026).
        #
        # It moves past a message the archive refused as well. The archive is a
        # record of what was delivered, not the delivery itself: holding the
        # cursor back would re-read that message forever while the disk stayed
        # full, and redeliver everything after it. And past messages the list
        # kept out, or the same messages are read and kept out on every call,
        # and past those of a key that has left the book, for the same reason.
        #
        # After a reset the service's next is the cursor, and it is lower than
        # the one this channel held. Keeping the higher of the two would ask past
        # the new thread on every call and hand the same messages over each
        # time. A poll that stopped at its limit is the exception: the service's
        # next covers messages this call never looked at, so the cursor is the
        # last one it did look at, handed over or kept out.
        to = channel.after
        moved = bool(entries or kept_out or withheld)
        if entries:
            to = max(to, entries[-1]["seq"])
        if kept_out or withheld:
            to = max(to, last_seq)
        if channel.left_waiting or channel.stopped_at_budget:
            if last_seq is not None:
                to = last_seq
                moved = True
        elif type(data.get("next")) is int:
            to = data["next"]
            moved = True
        if moved:
            self._set_cursor(channel, to)
        if kept_out:
            # Said, since a message that does not arrive has to be told from
            # one that was never sent.
            opened_for = "any key, signed only" if "*" in channel.allow else "%d named key(s)" % len(channel.allow)
            self._note(channel, "kept_out", "This channel was opened for %s, and these messages did not satisfy that list as checked here. They are not handed over and not archived." % opened_for, seqs=kept_out)
        if withheld:
            # Said as well: what the removed key writes is passed by, never dropped in silence.
            self._note(channel, "removed_key", "These messages are signed by a key that is no longer in the address book, on an inbox that was given to it. They are not handed over and not archived. Add the key as a partner again to take what it writes from then on.", seqs=withheld)
        if oversized is not None:
            self._note(channel, "over_budget", "message %s on this channel is %d bytes as handed over here, larger than the whole byte budget of %d this read asked for. It had already come, so it is handed over on its own rather than kept back for ever, and this read is over its budget on purpose." % (oversized[0], oversized[1], max_bytes))
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

    def _save_trace(self, on=None):
        """Written when it changes. A trace that cannot be written costs the trace and nothing else."""
        try:
            self._save_json("trace.json", self.__dict__.get("traces") or {}, private=True)
        except Exception as error:
            self._untraced("trace.json: %s: %s" % (error.__class__.__name__, error), on)

    def _untraced(self, line, on=None):
        """A trace that did not happen, said in the two places a caller may be looking.

        Costing the trace is the contract and it still holds. Costing it in
        silence was not: four sends once left no record and no message, and a
        logger nobody had wired is one way that happens. It is not established
        that it was the way it happened those four times -- a sender process
        running older code would look the same -- so this closes the silence
        without claiming to have closed the case.

        `attention` is read by the CLI and the MCP server without anyone wiring
        anything, but it has to be fetched, and a script that sends once and
        exits never fetches it. So `on`, when given, is the answer that call is
        about to return, and the failure is marked on it the way an archive
        that could not be written already marks the send it belongs to.

        `line` reaches the log as it was written. Through `_note_trouble` it
        arrives with its channel in front, as every other note does.
        """
        if isinstance(on, dict):
            on["trace_error"] = line

        try:
            self._note_trouble("trace", "untraced", line
                               + " The sends and reads themselves are unaffected; what is behind is the record of them.")
        except Exception:
            # Never at the cost of the thing being traced, even here.
            try:
                getattr(self, "log", lambda text: None)(line)
            except Exception:
                pass

    def _trace_safely(self, what, update, *args, on=None):
        """The trace is diagnostics: whatever goes wrong in it costs the trace, never the send or the read it records.

        `on` is the record this trace is about, and it is passed down rather
        than kept on the runtime: `_deliver` holds no lock and the background
        half of a send runs in its own thread, so a field on `self` would
        belong to whichever send finished last.
        """
        try:
            update(*args, on=on)
        except Exception as error:
            self._untraced("trace %s: not recorded: %s: %s" % (what, error.__class__.__name__, error), on)

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

    def _trace_sent(self, entry, status, result, on=None):
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
            self._save_trace(on)

    def _trace_received(self, channel, entry, on=None):
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

        self._save_trace(on)

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
        # A muted inbox is polled too, until it expires, for the partners still
        # in the book: poll judges every message against the book, and what a
        # removed key writes there is not handed over, by the listener the MCP
        # server uses as by the command line.
        while not self.stop.is_set() and not channel.closed and channel.expire_at > time.time():
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
                    if channel.poller is None:
                        channel.poller = threading.Thread(target=self._poll_loop, args=(channel,), daemon=True)
                        channel.poller.start()
            except Exception as error:
                # The listener is what starts the pollers. One that keeps failing
                # means a channel opened now is never read, and the inbox looks
                # empty rather than unwatched.
                self._note_trouble(
                    "listener",
                    "stopped",
                    "the listener failed and will try again: %s: %s. A channel opened while this lasts is not being read."
                    % (error.__class__.__name__, error),
                )
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
            left_waiting = 0
            held_back = []
            held_here = []
            at_limit = []
            not_asked = []
            not_asked_after = []
            budget = {} if max_bytes is None else {"max_bytes": max_bytes}

            def ask(channel, seconds, passed_over):
                """One channel asked, for what this call still has room for; how it answered, or None."""
                nonlocal left_waiting
                # A channel is only asked for what this call still has room
                # for. poll moves the cursor and saves it before the caller
                # sees a message, so whatever was fetched beyond the limit and
                # cut off here afterwards was past the cursor and never came
                # back: 60 waiting, 50 handed over, the last ten gone.
                room = limit - len(collected)
                if room <= 0:
                    passed_over.append(channel.label)
                    return None
                try:
                    state, entries = self.poll(channel, seconds, room, **budget)
                except Exception as error:
                    self._note(channel, "unread", "this channel could not be read: %s. Messages from the other channels are still returned." % error.__class__.__name__)
                    return None
                collected.extend(entries)
                left_waiting += channel.left_waiting

                if channel.stopped_at_budget:
                    held_here.append(channel.label)
                elif channel.more_at_service:
                    (at_limit if channel.more_at_limit else held_back).append(channel.label)

                return state

            # Every channel is asked at once before anything waits, so mail
            # already waiting on any of them comes now. The wait used to go to
            # the first channel before the others were asked, and a reply
            # waiting on a private thread sat behind a quiet inbox for the
            # whole wait, until 30 September 2026.
            answered = []
            for channel in list(self.channels.values()):
                # A channel that answered 410 or nothing at all never gets the
                # wait: it used to eat it, so a read with wait 25 came back at
                # once and the inbox was only ever asked with wait 0. A gone
                # one does: the service holds a read of a missing thread for a
                # write.
                if ask(channel, 0, not_asked) in ("ok", "gone"):
                    answered.append(channel)

            # Only when nothing was waiting anywhere does the read wait, on the
            # first channel that answered, usually the inbox. The others are
            # asked once more when it ends, so what reached them meanwhile comes
            # with this answer, at the end of the wait: only the first channel
            # can end the wait early.
            if not collected and wait and answered:
                ask(answered[0], wait, not_asked_after)
                for channel in answered[1:]:
                    ask(channel, 0, not_asked_after)

            # One note for the read, under one key: a second note under the
            # same key used to replace the first, so a read that met both its
            # limit and a byte budget said only one of them.
            budget_said = None
            if held_back:
                held = ", ".join(dict.fromkeys(held_back))
                budget_said = ("the service had more waiting on %s than the byte budget this read asked for, so it sent what fits and kept the rest. Read again for it: the cursor stands at the last message handed over." % held
                               if max_bytes is not None else
                               "the service says it has more waiting on %s than it sent. Nothing was passed over: the cursor stands at the last message handed over, so read again for the rest." % held)

            limit_said = None
            if left_waiting or not_asked or not_asked_after or at_limit:
                # Nothing is lost, and the caller still has to hear it: a read
                # that stopped at its limit is not a read of everything.
                limit_said = "this read stopped at its limit of %d message(s). %s Nothing was passed over: every cursor stands at the last message this read dealt with, so read again for the rest." % (
                    limit,
                    " ".join(part for part in (
                        "The service has more waiting on %s." % ", ".join(dict.fromkeys(at_limit)) if at_limit else "",
                        "%d more that the service had already returned were left where they are." % left_waiting if left_waiting else "",
                        "%d channel(s) were not asked this time: %s." % (len(not_asked), ", ".join(not_asked)) if not_asked else "",
                        "%d channel(s) were asked before the wait and not after it: %s." % (len(not_asked_after), ", ".join(not_asked_after)) if not_asked_after else "",
                    ) if part),
                )

            here_said = None
            if held_here:
                here_said = "this read stopped at the byte budget it asked for on %s, %d bytes of messages as they are handed over here, and left the rest at the service. Nothing was passed over: the cursor stands at the last message handed over, so read again for the rest." % (", ".join(dict.fromkeys(held_here)), max_bytes)

            said = [part for part in (limit_said, budget_said, here_said) if part]
            if said:
                self._note_trouble("read", "more", " ".join([said[0]] + [part[0].upper() + part[1:] for part in said[1:]]))
            return collected
        # With a listener running, the messages are already here: it fetched them
        # on its own polls, which belong to every caller and cannot take one
        # caller's budget without shortening somebody else's stream. So here the
        # budget bounds the answer rather than the transfer. It was neither until
        # now: max_bytes was taken, carried down two calls, and dropped, in the
        # one mode the MCP server actually runs in.
        collected = []
        # The budget is per channel, as aamio_read says and as a read on request
        # keeps it: it used to be one budget for the whole answer (a review of 10
        # November 2026). A channel whose budget is reached keeps what else came
        # on it, in the order it came, for the next read; the others go on.
        used = {}
        taken = {}
        full = []
        held = []
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

            # Nothing from a key that has left the address book is handed over
            # from an inbox that named it, whatever fetched it: a message that
            # sat in the queue before the partner was removed is not either,
            # and that is said.
            if self._withheld_since(entry):
                continue

            if max_bytes is not None:
                where = entry.get("w") or entry.get("channel")
                if where in full:
                    held.append(entry)
                    continue

                weight = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

                # Whole messages, as the service does it.
                if taken.get(where) and used.get(where, 0) + weight > max_bytes:
                    full.append(where)
                    held.append(entry)
                    continue

                # One message larger than the whole budget is handed over rather
                # than held for ever: it is already here, and a queue that quietly
                # keeps a message is the fault this is here to fix. The caller is
                # told, because 2054 bytes arriving on a budget of 512 with nothing
                # said reads as a budget that does not work.
                if not taken.get(where) and weight > max_bytes:
                    # Not too_large: that is the service's word for a message that
                    # did not come and is still there. This one came. Under one name
                    # a reader cannot tell which happened, and the two call for
                    # opposite actions.
                    self._note_trouble(
                        "read",
                        "over_budget",
                        "message %s is %d bytes, larger than the whole budget of %d this read asked for. It was already on this machine, so it is handed over rather than held back for ever, and this read is over budget by design." % (entry.get("seq"), weight, max_bytes),
                    )

                used[where] = used.get(where, 0) + weight
                taken[where] = taken.get(where, 0) + 1

            collected.append(entry)

        if held or waiting:
            with self.lock:
                self.held_back = held + waiting + list(getattr(self, "held_back", []))

        if held:
            labels = ", ".join(dict.fromkeys(entry.get("channel") or entry.get("w") for entry in held))
            self._note_trouble("read", "more", "this read stopped at the byte budget it asked for on %s, %d bytes of messages per channel. The rest is here in the order it arrived and the next read hands it over; nothing was dropped and nothing changed places." % (labels, max_bytes))

        return collected

    # ---------------------------------------------------------- receipt --

    def receipt(self, label="inbox", anchor=False):
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.receipt(channel.w, channel.read_key)
        if status != 200:
            raise RuntimeError("receipt failed: %s %s" % (status, data))
        # Checked as a receipt for this channel before anything is compared,
        # signed or anchored: one for another address, and one that counted
        # seven messages and listed one, were signed with root_adds_up true (a
        # review of 10 November 2026).
        fault = receipt_fault(data, channel.w)
        if fault is not None:
            raise RuntimeError("receipt failed: the service's answer is not a receipt for this channel: %s. Nothing was compared, signed or anchored." % fault)
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
        # What this process read counts only for the thread it was read on. After
        # the service restarted, a new thread at the same address was compared
        # with what was read of the old one, and its signer named as checked
        # here (a review of 10 November 2026).
        with channel.lock:
            if isinstance(data.get("instance"), str) and channel.observed_instance is not None:
                same_thread = channel.observed_instance == data["instance"]
            else:
                same_thread = (channel.observed_created_at is not None and channel.observed_created_at == data["created_at"]
                               and (not _whole(channel.observed_expire_at) or channel.observed_expire_at == data["expire_at"]))
            earlier = {"instance": channel.observed_instance, "created_at": channel.observed_created_at, "expire_at": channel.observed_expire_at} if channel.observed and not same_thread else None
            entries = sorted(channel.observed.values(), key=lambda e: e["seq"]) if same_thread else []
        held = len(entries)
        line = "%d\t%d\t%s\t%s\n"
        listed = "".join(line % (m["seq"], m["at"], m["sha256"], m.get("from") or "-") for m in (data.get("messages") or []))
        ours = "".join(line % (e["seq"], e["at"], e["sha256"], e.get("from") or "-") for e in entries)
        comparable = held == data["count"]
        # A signer is named only for a row this process checked and the receipt
        # lists as it was read: the same seq, time, hash and signer. A row read on
        # a thread the fields cannot tell from this one is not taken for it (a
        # review of 10 November 2026).
        listed_by_seq = {m["seq"]: m for m in data["messages"]}

        def as_listed(e):
            m = listed_by_seq.get(e["seq"])
            return m is not None and m["at"] == e["at"] and m["sha256"] == e["sha256"] and (m.get("from") or None) == (e.get("from") or None)

        verified_keys = {e.get("from_key") for e in entries if e.get("verified") and isinstance(e.get("from_key"), str) and as_listed(e)}
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
            result["local_check"] = (
                "Not compared: this process holds %d of the %d messages the receipt counts, so a local root would differ for a reason that is not the receipt's." % (held, data["count"])
                + (" What this process read at this address was on another thread, %s; this receipt is for %s, so none of that counts here." % (_which_thread(earlier), _which_thread(data)) if earlier is not None else "")
                + " root_adds_up checks only the receipt's arithmetic; our signature records what was fetched, not that its claims are true. For the independent check, take the receipt in the process that read the messages."
            )
        if anchor:
            idem = sha256hex("aamio-listen:%s:%s" % (self.keys.hash, data["root"]))[:32]
            status, proof = self.client.anchor(data["root"], idem)
            # A proof is a 200 with a proof_id from a tool that did not answer with an error.
            # A proof_id of blanks names no proof (a review of 10 November 2026).
            if status == 200 and isinstance(proof, dict) and isinstance(proof.get("proof_id"), str) and proof["proof_id"].strip() and not proof.get("tool_error"):
                result["anchor"] = proof
            else:
                result["anchor"] = {"error": status, "detail": proof.get("detail") if isinstance(proof, dict) and proof.get("tool_error") else proof}
        # Taken, and anchored when that was asked: a record of it that cannot
        # be written is said beside it.
        archive_error = self._archive_done(label, {"kind": "receipt", "at": time.time(), "result": dict(result)}, "the receipt for %s" % label)
        if archive_error is not None:
            result["archive_error"] = archive_error
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
