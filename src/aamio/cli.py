"""Command line for aamio.

    aamio init [--tags a,b]        make a key and an inbox, print your identity
    aamio whoami                   your key, hash prefix and inbox
    aamio partner add NAME KEY     add a partner from the contract
    aamio partner list
    aamio partner remove NAME
    aamio lookup [NAME ...]        who is online now
    aamio send NAME TEXT           encrypt, sign, send
    aamio read [--wait 25]         read new messages
    aamio receipt [--channel inbox] [--anchor]
    aamio scope new NAME           a scope with a key from the system's secure generator
    aamio scope add NAME --key KEY | --address ADDRESS
    aamio scope list               names, addresses and whether each can read
    aamio scope key NAME           the key, to pass on by hand
    aamio scope share NAME PARTNER --access read|write
    aamio scope remove NAME
    aamio addon list               the add-ons installed beside aamio, and which of them run here
    aamio addon enable NAME        let an installed add-on run here; disable takes it out again
    aamio addon NAME ...           an add-on's commands: aamio addon domain --help with Domain Keys
    aamio serve                    MCP server on stdio

Environment: AAMIO_HOME (default ~/.aamio) and AAMIO_TAGS, and AAMIO_HOST, AAMIO_BOARD
and AAMIO_VERIFYUM over the hosts at the top of aamio/client.py.
"""

import argparse
import json
import re
import sys

from .client import NotJson
from . import __version__, addons, compat, storage
from .gate import GateStop
from .errors import code_of
from .runtime import (BODY_MAX_DEPTH, unfit_json, Runtime, SendFailed, send_advice, BOARD_TTL, SEND_TRY_LATER, handover_unsettled, check_channel_ttl, check_gate, check_label,
                      check_partner, check_re, check_scope_add, check_scope_name)


def out(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def runtime_tags(args):
    """The presence tags of this runtime, when the command is one that sets them.

    --tags on `board post` are the tags of that post, and on `board find` a
    filter. Every --tags used to become the runtime's own: whoami showed the
    last post's tags, and presence published them as where this key can be
    reached.
    """
    if getattr(args, "command", None) == "board" or not getattr(args, "tags", None):
        return None

    return [t for t in args.tags.split(",") if t]


def set_archive(runtime, policy):
    """The home's own choice, written where the next process finds it."""
    runtime._save_json("config.json", {"archive": policy})
    runtime.archive_policy = policy
    runtime.archive_enabled = policy["mode"] != "off"
    runtime._prune()


def not_health(body):
    """What /health said when it is not aamio's health answer, and None when it is.

    aamio's answer is an object with "service": "aamio" and "status": "ok", as
    the service gives it. A 200 from a proxy or a login page in front of the
    host was said as healthy, beside "answered 200 and not 200" (a check of 13
    November 2026). As the Node runtime and aamio-php say it.
    """
    if isinstance(body, NotJson):
        return "an empty body" if body == "" else "a body that is not JSON"
    if not isinstance(body, dict) or body.get("service") != "aamio" or body.get("status") != "ok":
        return "JSON that is not aamio's health answer"
    return None


def doctor(runtime):
    """One answer to three questions: does this client fit the service, who can read the home, what is kept.

    Nothing here is a guess reported as a finding. What could not be checked
    says so, and is never called fine.
    """
    status, health = runtime.client.health()
    # Whether the service answered and whether it is well are two things, and
    # both apart from whether this client fits it. A 503 from /health was said
    # as no answer, beside a fit read from the descriptor, which had answered
    # (a check of 13 November 2026). As the Node runtime and aamio-php say it.
    unlike = not_health(health) if status == 200 else None
    service = {"host": runtime.host, "reachable": status > 0, "healthy": status == 200 and unlike is None, "status": status}
    if service["healthy"]:
        service.update(version=health.get("version"), revision=health.get("revision"))
    elif status == 0:
        service["problem"] = "no answer from /health, so the service's version and health were not read"
    elif status != 200:
        service["problem"] = "/health answered %s and not 200: the service is reachable and not healthy, and its version was not read" % status
    else:
        service["problem"] = "/health answered 200 with %s, so the service's version and health were not read: check that --host names the aamio service and not a page in front of it" % unlike
    status, descriptor = runtime.client.descriptor()
    fits = compat.check(descriptor if status == 200 else None)
    if status != 200:
        fits.update(verdict="unknown", why="the descriptor could not be read (%s), so compatibility was not checked" % status)
    return {
        "client": {"name": "aamio-python", "version": __version__, "protocol": compat.PROTOCOL},
        "service": service,
        "compatibility": fits,
        "storage": storage.check(runtime.home),
        "archive": storage.status(runtime.home, runtime.archive_policy),
        "outbox_pending": len(runtime.outbox_pending()),
    }


def gate_stopped(stop):
    """A stop at the gate, as JSON: the reason, the fix, and the channel when one was opened for a message that was then stopped.

    board channel caught a failed send and not this, so a stop at the gate
    came out as an error with no fix, and with no word of the channel that was
    open by then (a check of 12 November 2026).
    """
    told = {"error": stop.reason, "error_code": "gate", "fix": stop.fix}
    opened = getattr(stop, "opened", None)

    if opened:
        told["opened"] = opened
        told["fix"] = "The channel %s is open and listed by `aamio channel list`: only the message carrying its address did not go. Nothing was sent, so nobody has been given its address: close it with `aamio channel close %s`, and open a new one when the inbox's conditions can be met. %s" % (opened["label"], opened["label"], stop.fix)

    out(told)

    return 1


def send_failed(error, operation):
    """A send that stored nothing, as JSON and not as a traceback.

    One command is one process, so an exception that escaped was a traceback on
    stderr, and the message id a retry needs was nowhere in it. Unknown is not
    failure: the message may be on the other side, and sending it again as a
    new message makes a second one. What goes again is the stored bytes, and
    here there is a command for that.
    """
    retryable, _ = send_advice(error.outcome, error.status)

    if error.outcome == "unknown":
        fix = ("No answer came back, so this message may already have been delivered. Do not send it again as a new message: "
               "`aamio outbox retry --id %s` sends the same stored bytes again, and a copy that did land is marked a replay where it arrives. "
               "`aamio outbox pending` lists what has no settled outcome on this machine." % error.message_id)
    elif retryable:
        fix = ("aamio declined this for now, not because of the message: %s is a rate window or a busy service. Do not change the content. "
               "Wait, then run `aamio outbox retry --id %s`, which sends the stored bytes again." % (error.status, error.message_id))
    else:
        fix = send_advice(error.outcome, error.status)[1]

    told = {"error": str(error), "error_code": "send_" + error.outcome, "operation": operation, "outcome": error.outcome, "message_id": error.message_id, "status": error.status, "retryable": retryable, "fix": fix}

    if getattr(error, "opened", None):
        told["opened"] = error.opened
        # What is said of the message follows what is known of it.
        if handover_unsettled(error.outcome):
            still = ("The channel %s is open and listed by `aamio channel list`, and the message carrying its address may have arrived: its outcome is not known. "
                     "Do not open another channel for this: a new attempt is the same message, under the same message_id." % error.opened["label"])
        else:
            still = "The channel %s is open and listed by `aamio channel list`: only the message carrying its address did not land." % error.opened["label"]
        # A message that never left has nothing to send again, and an address
        # goes only with a channel: "send it as a new message" named a thing
        # the command line cannot do.
        if error.outcome == "never_sent":
            fix = "Nothing left this machine, so nobody has been given its address. Close it with `aamio channel close %s`, put right what the error says, and open a new one." % error.opened["label"]
        elif error.outcome == "refused" and error.status not in SEND_TRY_LATER:
            # Nobody has the address either: a corrected message would need it.
            fix = "aamio refused it, so nobody has been given its address. Close it with `aamio channel close %s`, put right what the error says, and open a new one." % error.opened["label"]
        told["fix"] = "%s %s" % (still, fix)

    # The trace that could not be written, beside the failure it belongs to,
    # and the archive's record of the attempt.
    if getattr(error, "trace_error", None):
        told["trace_error"] = error.trace_error
    if getattr(error, "archive_error", None):
        told["archive_error"] = error.archive_error

    out(told)

    return 1


def addon_change(verb, name):
    """aamio addon enable NAME or disable NAME: the list afterwards, or the refusal and 2."""
    try:
        out(getattr(addons, verb)(name))
    except addons.AddonError as error:
        print("aamio: %s" % error, file=sys.stderr)
        return 2
    return 0


# A key is 43 characters of base64url, and one in 64 begins with a dash, which
# argparse takes for an option: `partner add bob -quTO...` stopped with "the
# following arguments are required: key", and so did send, lookup and every
# command that takes a key (a check of 13 November 2026). Such a word is marked
# before the parsing and given back after it. No option here looks like one,
# and an argument from the system cannot hold the mark.
KEY_WORD = re.compile(r"-[A-Za-z0-9_-]{42}")
KEY_MARK = "\x00"


def _marked(argv):
    return [KEY_MARK + word if isinstance(word, str) and KEY_WORD.fullmatch(word) else word for word in argv]


def _given_back(value):
    if isinstance(value, str) and value.startswith(KEY_MARK):
        return value[len(KEY_MARK):]
    if isinstance(value, list):
        return [_given_back(item) for item in value]
    return value


class Usage(Exception):
    """What can be seen to be wrong from the command line alone: said on standard error with 2, before the home is opened or made."""


def _whole(value, name, low, high=None):
    """A whole number as the Node runtime and aamio-php take one on the command line: digits only, within its bounds."""
    if value is None or isinstance(value, int):
        return value
    if re.fullmatch(r"[0-9]{1,15}", value) is None or int(value) < low or (high is not None and int(value) > high):
        raise Usage("%s is a whole number, %d or more." % (name, low) if high is None else "%s is a whole number from %d to %d." % (name, low, high))
    return int(value)


def _as_usage(check, *given):
    """A check of the runtime's, said as a usage error: a capital first and a full stop last, as the Node runtime says it."""
    try:
        check(*given)
    except ValueError as error:
        text = str(error)
        raise Usage(text[:1].upper() + text[1:] + ("" if text.endswith(".") else ".")) from None


def _not_json(name):
    raise ValueError("%s is not JSON" % name)


def _json(value, wrong, option="--data"):
    """A JSON value given on the command line, or the usage error that says it is none. NaN and Infinity are none.

    A number that is not finite, as 1e999 is, is refused too, and --data
    nested so deep that the message around it passes BODY_MAX_DEPTH: a reader
    would hand it over as text. The three runtimes refuse both alike (a
    security review of 13 November 2026).
    """
    if value is None:
        return None
    try:
        parsed = json.loads(value, parse_constant=_not_json)
    except RecursionError:
        raise Usage("%s is nested too deep: with the message around it, it is deeper than %d, and a reader hands such a message over as text." % (option, BODY_MAX_DEPTH)) from None
    except ValueError:
        raise Usage(wrong) from None
    unreadable = unfit_json(parsed, BODY_MAX_DEPTH - 1 if option == "--data" else 1000000)
    if unreadable is not None and unreadable[1] == "not finite":
        raise Usage("%s holds a number that is not finite, as 1e999 is: JSON can write it, and nothing that reads it can hold it." % option)
    if unreadable is not None and unreadable[1] == "half a pair":
        raise Usage("%s holds half of a UTF-16 surrogate pair, as \"\\ud800\" is: JSON can write it, and UTF-8 cannot carry it." % option)
    if unreadable is not None:
        raise Usage("%s is nested too deep: with the message around it, it is deeper than %d, and a reader hands such a message over as text." % (option, BODY_MAX_DEPTH))
    return parsed


def check_usage(args):
    """What the command line was given that can be seen to be wrong without the home.

    Checked before the home is opened or made, as in the Node runtime and
    aamio-php: a usage error raises Usage. A partner's name or key and --re
    raise the runtime's own error, which is the command's answer, as JSON
    with 1. A number that was no number, out of its bounds, or JSON that was
    no JSON went to the service or into the home first, and came back as an
    error of the runtime's (a check of 13 November 2026).
    """
    command = args.command
    if command == "init":
        if args.archive is not None:
            _as_usage(storage.parse_policy, args.archive)
    elif command == "archive":
        policy = args.policy or "status"
        size = args.max_mb
        if size is not None and (re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,6})?", size) is None or not float(size) > 0):
            raise Usage("--max-mb is a size in megabytes above zero.")
        if policy in ("status", "prune"):
            if size is not None:
                raise Usage("--max-mb goes with a choice: archive keep, archive off or archive days:N.")
            if args.all and policy != "prune":
                raise Usage("--all goes with archive prune, and removes the whole archive.")
        else:
            if args.all:
                raise Usage("--all goes with archive prune, and removes the whole archive.")
            _as_usage(storage.parse_policy, policy, None if size is None else float(size))
        args.max_mb = None if size is None else float(size)
    elif command == "partner" and args.action == "add":
        check_partner(args.name, args.key)
    elif command == "lookup":
        args.wait = _whole(args.wait, "--wait", 0, 25)
    elif command == "send":
        check_re(args.re)
        _json(args.data, "--data is not JSON. Give a JSON value, quoted for the shell.")
    elif command == "trace":
        args.limit = _whole(args.limit, "--limit", 1, 50)
    elif command == "read":
        args.wait = _whole(args.wait, "--wait", 0, 25)
        args.limit = _whole(args.limit, "--limit", 1, 200)
        args.max_bytes = _whole(args.max_bytes, "--max-bytes", 512)
    elif command == "receipt":
        if not args.channel:
            raise Usage("--channel names a channel, as a message's channel field does: inbox, board or an older generation.")
    elif command == "outbox":
        if args.outbox_command == "retry" and args.id is not None and not args.id:
            raise Usage("--id names one message, as outbox pending shows it.")
        if args.outbox_command == "forget" and not args.id:
            raise Usage("outbox forget takes the id of one message, as outbox pending shows it.")
    elif command == "channel":
        if args.action == "open":
            _as_usage(check_label, args.label)
            args.ttl = _whole(args.ttl, "--ttl", 30, 3600)
            _as_usage(check_channel_ttl, args.ttl)
            if args.gate is not None:
                gate = _json(args.gate, "--gate is not JSON. Quote it as one argument, as in --gate '{\"require\": {\"pow\": {\"bits\": 20}}}'.", "--gate")
                _as_usage(check_gate, gate)
        elif args.action == "close" and not args.label:
            raise Usage("channel close takes the label of one channel, as channel list shows it.")
    elif command == "board":
        sub = args.board_command
        if sub == "post":
            args.ttl = _whole(args.ttl, "--ttl", 60, 3600)
            if args.scope is not None:
                _as_usage(check_scope_name, args.scope)
        elif sub == "find":
            args.after = _whole(args.after, "--after", 0, 999999)
            args.wait = _whole(args.wait, "--wait", 0, 25)
            args.min_work_bits = _whole(args.min_work_bits, "--min-work-bits", 0, 16)
            if args.scope is not None:
                _as_usage(check_scope_name, args.scope)
        elif sub == "answer":
            _json(args.data, "--data is not JSON. Give a JSON value, quoted for the shell.")
            if args.scope is not None:
                _as_usage(check_scope_name, args.scope)
        elif sub == "replies":
            args.wait = _whole(args.wait, "--wait", 0, 25)
            if args.post is not None and not args.post:
                raise Usage("--post names one post by its id, as board post answered it.")
        elif sub == "channel":
            args.ttl = _whole(args.ttl, "--ttl", 30, 3600)
            if args.reply_to is not None and re.fullmatch(r"[a-z2-7]{20}", args.reply_to) is None:
                raise Usage("--reply-to is a write address: 20 characters of a-z and 2-7, as a verified answer gives it in reply_to.")
            if args.note is not None and args.reply_to is None:
                raise Usage("--note travels with the address to the inbox --reply-to names, so without --reply-to there is nothing to carry it.")
            if not args.key:
                raise Usage("board channel takes a key, or a partner's name.")
    elif command == "scope":
        sub = args.scope_command
        if sub in ("new", "key", "share", "remove"):
            _as_usage(check_scope_name, args.name)
        elif sub == "add":
            _as_usage(check_scope_add, args.name, args.key, args.address)


def main(argv=None):
    # The answers are JSON, and JSON is UTF-8. A pipe on Windows was written in
    # the locale's code page: a name outside ASCII came out as bytes no reader
    # takes for UTF-8, and one outside the code page stopped the answer after
    # the command had done its work, a partner added or messages read off the
    # service, with an encoding error said instead (a check of 12 November
    # 2026). backslashreplace writes a lone surrogate as the escape JSON has
    # for it. aamio serve sets its own streams, as before.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    # The home before the parser is built: which add-ons run here is kept in
    # it, and the parser has a command for each. And `addon disable` before
    # the add-ons are loaded, so that a broken one can be taken out again.
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--home", default=None)
    probe.add_argument("--host", default=None)
    probe.add_argument("--no-archive", action="store_true")
    argv = _marked(sys.argv[1:] if argv is None else list(argv))
    known, rest = probe.parse_known_args(argv)
    known.home, known.host = _given_back(known.home), _given_back(known.host)
    # An empty value is not the default. `--home=` or `--home ""`, from a
    # script whose variable was never set, would otherwise act in the default
    # home; the option left out still means the default.
    for option, value, shape in (("--home", known.home, "DIR"), ("--host", known.host, "URL")):
        if value is not None and not value.strip():
            sys.stderr.write("%s needs a value: aamio %s %s <command> ...\n" % (option, option, shape))
            return 2
    addons.use_home(known.home)
    # Exactly `addon disable NAME` and nothing else. Help, or any other word,
    # goes through the parser like every command, and changes nothing.
    if len(rest) == 3 and rest[:2] == ["addon", "disable"] and not rest[2].startswith("-"):
        return addon_change("disable", rest[2])
    parser = argparse.ArgumentParser(prog="aamio", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--no-archive", action="store_true", help="do not keep decrypted messages and receipts locally")
    parser.add_argument("--version", action="version", version="aamio " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init")
    p.add_argument("--tags", default=None, help="comma separated presence tags")
    p.add_argument("--archive", default=None, help="keep, off or days:N: what happens to decrypted messages on this machine")
    p = sub.add_parser("archive", help="what is kept on this machine, and for how long")
    p.add_argument("policy", nargs="?", default="status", help="status (default), keep, off, days:N, or prune")
    p.add_argument("--max-mb", default=None, help="a size the archive is cut to, oldest first out, each time it is tidied")
    p.add_argument("--all", action="store_true", help="with prune: remove the whole archive")
    sub.add_parser("doctor", help="does this client fit the service, who can read the home, what is kept")
    sub.add_parser("whoami")
    p = sub.add_parser("partner")
    ps = p.add_subparsers(dest="action", required=True)
    pa = ps.add_parser("add")
    pa.add_argument("name")
    pa.add_argument("key")
    ps.add_parser("list")
    pr = ps.add_parser("remove")
    pr.add_argument("name")
    p = sub.add_parser("lookup")
    p.add_argument("names", nargs="*")
    p.add_argument("--wait", default=0)
    p = sub.add_parser("send")
    p.add_argument("to")
    p.add_argument("text")
    p.add_argument("--data", default=None, help="JSON object")
    p.add_argument("--re", default=None, help="the sha256 of the message this answers, as read shows it")
    p = sub.add_parser("trace", help="what was sent to one counterpart and what came back, as hashes: for when a message did not arrive, or arrived empty")
    p.add_argument("who", nargs="?", default=None, help="a partner name, a key or a write address; leave out for everyone")
    p.add_argument("--limit", default=20)
    p = sub.add_parser("read")
    p.add_argument("--wait", default=0)
    p.add_argument("--limit", default=None, help="at most this many messages")
    p.add_argument("--max-bytes", default=None, dest="max_bytes",
                   help="bytes of messages to hand over, per channel; whole messages only, and one larger than the budget still comes")
    p = sub.add_parser("receipt")
    p.add_argument("--channel", default="inbox")
    p.add_argument("--anchor", action="store_true")
    p = sub.add_parser("channel")
    cs = p.add_subparsers(dest="action", required=True)
    co = cs.add_parser("open")
    co.add_argument("label")
    co.add_argument("--ttl", default=600)
    co.add_argument("--allow", default=None, help="comma separated partner names")
    co.add_argument("--gate", default=None,
                    help='conditions for whoever writes, as JSON: \'{"require": {"pow": {"bits": 20}, "per_key": 5}}\'. Set once and never changed.')
    cs.add_parser("list")
    cc = cs.add_parser("close")
    cc.add_argument("label")
    p = sub.add_parser("board")
    bs = p.add_subparsers(dest="board_command", required=True)
    bp = bs.add_parser("post")
    bp.add_argument("kind", choices=["need", "offer"])
    bp.add_argument("title")
    bp.add_argument("text")
    bp.add_argument("--tags", default="")
    bp.add_argument("--ttl", default=BOARD_TTL)
    bp.add_argument("--lang")
    bp.add_argument("--deadline")
    bp.add_argument("--scope", help="the name of one of your scopes: the post is then unlisted, and unlisted is not private")
    bf = bs.add_parser("find")
    bf.add_argument("--kind", choices=["need", "offer"])
    bf.add_argument("--tags", default="")
    bf.add_argument("--lang")
    bf.add_argument("--after", default=0)
    bf.add_argument("--wait", default=0)
    bf.add_argument("--min-work-bits", default=0, help="keep only posts whose work_bits is at least this; 1 means any work, 16 is what the board advises")
    bf.add_argument("--scope", help="the name of a scope you hold with its key: read that scope instead of the public board")
    bs.add_parser("tags")
    ba = bs.add_parser("answer")
    ba.add_argument("post")
    ba.add_argument("text")
    ba.add_argument("--data", default=None, help="JSON object, beside the text")
    ba.add_argument("--scope", help="the name of the scope the post is in")
    br = bs.add_parser("replies", help="answers to your posts. This filters. read shows everything on the inbox, including messages that name no post and bodies that could not be opened")
    br.add_argument("--post")
    br.add_argument("--wait", default=0)
    bw = bs.add_parser("withdraw")
    bw.add_argument("post")
    bc = bs.add_parser("channel")
    bc.add_argument("key")
    bc.add_argument("--ttl", default=900)
    bc.add_argument("--reply-to")
    bc.add_argument("--note")

    p = sub.add_parser("scope")
    ss = p.add_subparsers(dest="scope_command", required=True)
    sn = ss.add_parser("new")
    sn.add_argument("name")
    sa = ss.add_parser("add")
    sa.add_argument("name")
    sa.add_argument("--key", help="26 to 64 characters of a-z and 0-9: read and post. A key typed here stays in the shell history, so scope share from runtime to runtime is better")
    sa.add_argument("--address", help="the 20 characters that go on a post: post only")
    ss.add_parser("list")
    sk = ss.add_parser("key")
    sk.add_argument("name")
    sh = ss.add_parser("share")
    sh.add_argument("name")
    sh.add_argument("partner")
    sh.add_argument("--access", choices=["read", "write"], required=True)
    sr = ss.add_parser("remove")
    sr.add_argument("name")

    p = sub.add_parser("outbox")
    os_ = p.add_subparsers(dest="outbox_command", required=True)
    os_.add_parser("pending")
    orr = os_.add_parser("retry")
    orr.add_argument("--id")
    ofg = os_.add_parser("forget")
    ofg.add_argument("id")

    sub.add_parser("serve")

    # What is installed beyond the core, each under its short name. An add-on
    # that cannot be used stops here with the reason: a broken install is not a
    # quiet absence.
    try:
        installed = addons.loaded()
    except addons.AddonError as error:
        if rest == ["addon", "list"]:
            # The list still answers, from metadata, and says what is broken
            # and how to take it out: a broken add-on must not hide itself.
            try:
                out(addons.describe())
                return 1
            except addons.AddonError:
                pass
        print("aamio: %s" % error, file=sys.stderr)
        return 1
    p = sub.add_parser("addon", help="the add-ons installed beside aamio, and their commands")
    asub = p.add_subparsers(dest="addon", required=True)
    asub.add_parser("list", help="which add-ons are installed, and which of them run here")
    asub.add_parser("enable", help="let an installed add-on run here").add_argument("name", help="its short name, or its distribution")
    asub.add_parser("disable", help="take an add-on out again").add_argument("name", help="its short name, or its distribution")
    for addon in installed:
        addon.add_commands(asub.add_parser(addon.NAME, help="%s %s" % (addon.__name__, addon.__version__)))
    # An add-on that is installed and not enabled is a command that says so,
    # not an unknown word; nothing of it runs, so it has no commands yet.
    for row in addons.installed():
        if row["name"] not in asub.choices:
            asub.add_parser(row["name"], help="installed, not enabled").add_argument("rest", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    for field, value in vars(args).items():
        setattr(args, field, _given_back(value))
    # Before the runtime: creating one takes the home's lock and tidies the home.
    # Listing the add-ons reads nothing, and an add-on may have commands of its
    # own that need no home, as a check of a local file beside a running server.
    if args.command == "addon":
        if args.addon == "list":
            out(addons.describe())
            return 0
        if args.addon in ("enable", "disable"):
            return addon_change(args.addon, args.name)
        if args.addon not in {addon.NAME for addon in installed}:
            print("aamio: the add-on %s is installed and not enabled. aamio addon enable %s lets it run here." % (args.addon, args.addon), file=sys.stderr)
            return 2
        code = addons.by_name(args.addon).early(args)
        if code is not None:
            return code
    try:
        check_usage(args)
    except Usage as wrong:
        print("aamio: %s" % wrong, file=sys.stderr)
        return 2
    except ValueError as error:
        # A partner's name or key, or --re: the command's answer, as JSON with
        # 1, as the other two answer it, and no home is made for it.
        out({"error": str(error), "error_code": code_of(error)})
        return 1
    tags = runtime_tags(args)
    try:
        runtime = Runtime(home=args.home, host=args.host, tags=tags, archive=False if args.no_archive else None, log=lambda line: print(line, file=sys.stderr))
    except RuntimeError as error:
        # Another runtime holds the home, or a file in it cannot be read. The
        # reason is the whole message, and it is not a crash.
        print("aamio: %s" % error, file=sys.stderr)
        return 1
    try:
        return run(args, runtime)
    except SendFailed as failed:
        return send_failed(failed, args.command)
    except (RuntimeError, LookupError, ValueError, OSError) as error:
        # serve's standard output is the protocol's alone: a server that cannot
        # start, as with no service to open its inbox at, says why on standard
        # error, where the host keeps its log. As JSON on standard output it was
        # a line the host could not read as a message (a check of 13 November
        # 2026), as aamio-php and the Node runtime say it.
        if args.command == "serve":
            print("aamio: %s" % error, file=sys.stderr)
            return 1
        # One command is one process, and what it could not do is the answer,
        # as JSON like every other answer here. It used to be a traceback.
        out({"error": str(error), "error_code": code_of(error)})
        return 1
    finally:
        # One command, one process: the lock goes with it, as in aamio-php.
        # Left behind, the next command had to guess from a pid whether an
        # old owner still lived, and on Windows pids come back quickly. Only
        # the lock: every command saves what it changed as it goes, and a
        # save on the way out would write files a command only read.
        runtime.release()


def run(args, runtime):
    if args.command == "init":
        if getattr(args, "archive", None):
            set_archive(runtime, storage.parse_policy(args.archive))
        runtime.ensure_inbox()
        runtime.save_state()
        # Said once, where a person sets the runtime up: the service forgets,
        # and this folder does not unless it is told to.
        out(dict(runtime.whoami(), local_storage=dict(storage.status(runtime.home, runtime.archive_policy), home=runtime.home, who_can_read=storage.check(runtime.home))))
    elif args.command == "archive":
        policy = getattr(args, "policy", "status") or "status"
        if policy == "prune":
            with runtime.archive_lock:
                gone = storage.prune(runtime.home, runtime.archive_policy, everything=bool(getattr(args, "all", False)))
            out(dict(storage.status(runtime.home, runtime.archive_policy), removed=gone["removed"]))
        elif policy == "status":
            out(storage.status(runtime.home, runtime.archive_policy))
        else:
            set_archive(runtime, storage.parse_policy(policy, getattr(args, "max_mb", None)))
            out(storage.status(runtime.home, runtime.archive_policy))
    elif args.command == "doctor":
        out(doctor(runtime))
    elif args.command == "whoami":
        out(runtime.whoami())
    elif args.command == "partner":
        # What the change did to the inbox is in the answer: the address a
        # partner can write to now, or that the old one stays because the new
        # one could not be opened.
        changed = {}
        if args.action == "add":
            changed = runtime.partner_add(args.name, args.key)
        elif args.action == "remove":
            changed = runtime.partner_remove(args.name)
        out(dict(changed, partners=runtime.partner_list()))
    elif args.command == "lookup":
        runtime.ensure_inbox()
        out(runtime.lookup(args.names or None, args.wait))
    elif args.command == "send":
        data = json.loads(args.data) if args.data else None
        try:
            out(runtime.send(args.to, args.text, data, **({"answers": args.re} if getattr(args, "re", None) else {})))
        except SendFailed as failed:
            return send_failed(failed, "send")
        except GateStop as stop:
            # Not a crash: the inbox asked for something this client does not
            # do, nothing was sent, and the reader needs the reason and the way on.
            return gate_stopped(stop)
    elif args.command == "read":
        # attention carries what the read could not do. Without it an expired
        # thread and a service that did not answer both read as "no messages".
        messages = runtime.read(args.wait, args.limit or 50, max_bytes=args.max_bytes)
        out({"messages": messages, "count": len(messages), "attention": runtime.attention_taken()})
    elif args.command == "trace":
        try:
            out(runtime.trace(args.who, args.limit))
        except LookupError as error:
            print("aamio: %s" % error, file=sys.stderr)
            return 1
    elif args.command == "receipt":
        out(runtime.receipt(args.channel, args.anchor))
    elif args.command == "channel":
        if args.action == "open":
            # A shell eats quotes, so a gate that will not parse is named by the
            # argument the person typed rather than by a decoder they cannot see.
            gate = getattr(args, "gate", None)

            if gate is not None:
                try:
                    gate = json.loads(gate)
                except ValueError as broken:
                    raise ValueError("--gate is not JSON: %s. Quote it as one argument, as in --gate '{\"require\": {\"pow\": {\"bits\": 20}}}'" % broken)

            out(runtime.open_channel(args.label, args.ttl, [n for n in args.allow.split(",") if n] if args.allow else None, gate))
        elif args.action == "list":
            out({"channels": runtime.channel_list()})
        else:
            out(runtime.close_channel(args.label))
    elif args.command == "board":
        tags = [t for t in getattr(args, "tags", "").split(",") if t]
        if args.board_command == "post":
            out(runtime.board_post(args.kind, args.title, args.text, tags, args.ttl, args.lang, args.deadline, args.scope))
        elif args.board_command == "find":
            out(runtime.board_find(args.kind, tags, args.lang, None, args.after, args.wait, args.min_work_bits, args.scope))
        elif args.board_command == "tags":
            out(runtime.board_tags())
        elif args.board_command == "answer":
            try:
                # The runtime has taken data since board answers existed, and
                # the tool beside this on the local MCP server offers it. Here
                # an agent could answer with prose and not with a price, a time
                # and a reference.
                out(runtime.board_answer(args.post, args.text, json.loads(args.data) if getattr(args, "data", None) else None, scope=args.scope))
            except SendFailed as failed:
                return send_failed(failed, "board_answer")
            except GateStop as stop:
                return gate_stopped(stop)
        elif args.board_command == "replies":
            # Always, and the board inboxes only. With no wait given this read
            # nothing at all, and said nobody had answered.
            runtime.board_poll(args.wait or 0)
            # The address comes with the answers. An empty list means one of
            # two very different things, and only this tells them apart.
            replies = runtime.board_replies(args.post)
            # How many messages this left out, every time and not only when it
            # found nothing: an answer that names no post is still somebody
            # answering, and a list of two with a third left out said nothing
            # about the third.
            left_out = getattr(runtime, "board_replies_left_out", 0)
            answer = {"replies": replies, "left_out": left_out, "reply_address": runtime.board_reply_address()}
            if left_out:
                answer["note"] = "%d message(s) on your inboxes are not listed here, because they name no post of yours and did not arrive on a board inbox. aamio read shows every message." % left_out
            if args.post is not None:
                # What else is on the board inbox, so an empty list for one
                # post is never read as an empty inbox.
                everything = runtime.board_replies()
                answer["others_on_the_board_inbox"] = len(everything) - len(replies)
            # Last, so it carries what both calls above had to say.
            answer["attention"] = runtime.attention_taken()
            out(answer)
        elif args.board_command == "withdraw":
            out(runtime.board_withdraw(args.post))
        else:
            try:
                out(runtime.open_channel_with(args.key, args.ttl, None, args.reply_to, args.note))
            except SendFailed as failed:
                return send_failed(failed, "board_channel")
            except GateStop as stop:
                return gate_stopped(stop)
    elif args.command == "scope":
        if args.scope_command == "new":
            out(runtime.scope_new(args.name))
        elif args.scope_command == "add":
            out(runtime.scope_add(args.name, args.key, args.address))
        elif args.scope_command == "list":
            out({"scopes": runtime.scope_list()})
        elif args.scope_command == "key":
            out(runtime.scope_key(args.name))
        elif args.scope_command == "share":
            out(runtime.scope_share(args.name, args.partner, args.access))
        else:
            out(runtime.scope_remove(args.name))
    elif args.command == "addon":
        return addons.by_name(args.addon).command(args, runtime)
    elif args.command == "outbox":
        if args.outbox_command == "pending":
            out({"pending": runtime.outbox_pending()})
        elif args.outbox_command == "retry":
            out({"retried": runtime.outbox_retry(args.id)})
        else:
            out(runtime.outbox_forget(args.id))
    elif args.command == "serve":
        from .mcp_server import serve

        serve(runtime)
    return 0


if __name__ == "__main__":
    sys.exit(main())
