"""The inbox follows the address book.

Two runtimes talking in the field, 21 September 2026, found the two halves of
one defect. partner add wrote partners.json and nothing else: the inbox kept
the list it was opened with for up to 57 minutes, and the partner just added
was refused with 403 at the address presence pointed to, which the owner never
saw. partner remove was the other half: forgetting the name is no revocation,
the service takes the removed key's writes to the old address until the thread
expires, and they arrived as an unknown contact.

The fake service here enforces allowlists the way the real one does, so a test
can say who could write where, not only what the runtime believes.
"""

import base64
import sys
import threading
import time

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime


def key(n):
    return base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


B, C, D = key(1), key(2), key(3)


class Service:
    """Threads with allowlists, enforced on every write like the service does."""

    def __init__(self):
        self.threads = {}
        self.opened = []
        self.count = 0
        self.refuse_opens = False

    def open_thread(self, ttl, allow_keys=None, gate=None):
        if self.refuse_opens:
            return 503, {"error": "the fake is full", "fix": "later"}, None, None
        self.count += 1
        w = ("w%d" % self.count).ljust(20, "x")
        allow = list(allow_keys or [])
        self.threads[w] = {"allow": allow, "messages": []}
        self.opened.append(allow)
        return 201, {"w": w, "expire_at": int(time.time()) + 3600, "created_at": int(time.time())}, "read-" + w, w

    def write(self, w, signer):
        allow = self.threads[w]["allow"]
        if allow and signer is None:
            return 403
        if allow and allow != ["*"] and signer not in allow:
            return 403
        self.threads[w]["messages"].append(signer)
        return 201


def build(service, partners, inbox_allow=None, with_inbox=True):
    runtime = object.__new__(Runtime)
    runtime.channels = {}
    if with_inbox:
        status, data, read_key, w = service.open_thread(3600, inbox_allow)
        runtime.channels["inbox"] = Channel("inbox", read_key, w, data["expire_at"], inbox_allow)
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = [dict(p) for p in partners]
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime.saved = []
    runtime._save_json = lambda name, data: runtime.saved.append((name, data))
    runtime.published = []
    runtime.publish_presence = lambda force=False: runtime.published.append(force) or True
    runtime.client = service
    return runtime


def notes(runtime):
    return {note["state"] for note in runtime.attention.values()}


def test_a_partner_added_can_write_to_the_inbox_presence_points_to():
    service = Service()
    runtime = build(service, [{"name": "c", "key": C}], inbox_allow=[C])
    old = runtime.channels["inbox"]
    assert service.write(old.w, B) == 403

    outcome = runtime.partner_add("b", B)

    inbox = runtime.channels["inbox"]
    assert outcome["rotated"] is True and outcome["inbox"] == inbox.w and inbox is not old
    assert sorted(service.threads[inbox.w]["allow"]) == sorted([B, C])
    assert service.write(inbox.w, B) == 201, "the partner just added writes to the address presence points to"
    assert runtime.published == [True], "presence was published again, pointing at the new inbox"
    # The old address is still read until it expires: whoever was told it may
    # still write there, and nobody was removed.
    assert old in runtime.channels.values() and old.muted is False
    assert outcome["old_inbox"] == {"w": old.w, "muted": False, "until": old.expire_at}
    assert notes(runtime) == set()
    assert ("partners.json", runtime.partners) in runtime.saved


def test_a_key_the_inbox_already_names_changes_nothing():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], inbox_allow=[B])
    before = service.count

    outcome = runtime.partner_add("b again", B)

    assert outcome["rotated"] is False and outcome["inbox"] == runtime.channels["inbox"].w
    assert service.count == before and runtime.published == []
    assert [p["name"] for p in runtime.partners] == ["b again"], "one key is one partner, under its latest name"


def test_registration_before_the_first_inbox_opens_nothing():
    service = Service()
    runtime = build(service, [], with_inbox=False)

    outcome = runtime.partner_add("b", B)

    assert outcome == {"partner": "b", "key": B, "inbox": None, "rotated": False}
    assert service.count == 0
    inbox = runtime.ensure_inbox()
    assert service.threads[inbox.w]["allow"] == [B], "the inbox opens with the list as it is then"


def test_a_removed_partner_is_read_no_more():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}, {"name": "c", "key": C}], inbox_allow=[B, C])
    old = runtime.channels["inbox"]

    outcome = runtime.partner_remove("c")

    inbox = runtime.channels["inbox"]
    assert outcome["known"] is True and outcome["rotated"] is True and inbox is not old
    assert service.threads[inbox.w]["allow"] == [B]
    assert service.write(inbox.w, C) == 403
    # The service still takes C's writes to the old address until it expires.
    # This runtime reads nothing from there any more, and says so once.
    assert service.write(old.w, C) == 201
    assert old.muted is True and old in runtime.channels.values()
    assert outcome["old_inbox"] == {"w": old.w, "muted": True, "until": old.expire_at}
    assert notes(runtime) == {"muted"}
    listed = {c["w"]: c["muted"] for c in runtime.channel_list()}
    assert listed[old.w] is True and listed[inbox.w] is False
    assert runtime.published == [True]


def test_the_last_partner_removed_leaves_a_signed_only_inbox():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], inbox_allow=[B])
    old = runtime.channels["inbox"]

    outcome = runtime.partner_remove("b")

    inbox = runtime.channels["inbox"]
    assert service.threads[inbox.w]["allow"] == ["*"], "signed writes from any key, none unsigned"
    assert service.write(inbox.w, D) == 201 and service.write(inbox.w, None) == 403
    assert old.muted is True and outcome["allow"] == ["*"]
    # With no partners this inbox matches the address book: nothing to replace.
    assert runtime.ensure_inbox() is inbox and service.count == 2


def test_an_open_inbox_gets_its_first_partner():
    service = Service()
    runtime = build(service, [], inbox_allow=None)
    old = runtime.channels["inbox"]
    assert service.write(old.w, None) == 201, "open to anyone, as a first contact is"

    outcome = runtime.partner_add("b", B)

    inbox = runtime.channels["inbox"]
    assert outcome["rotated"] is True and service.threads[inbox.w]["allow"] == [B]
    # The old one was open to anyone and stays open until it expires; it is
    # still read, and attention says it is open, since nothing was removed.
    assert old.muted is False and old in runtime.channels.values()
    assert notes(runtime) == {"open"}


def test_a_rotation_that_fails_keeps_the_old_inbox_and_says_so():
    service = Service()
    runtime = build(service, [{"name": "c", "key": C}], inbox_allow=[C])
    old = runtime.channels["inbox"]
    service.refuse_opens = True

    outcome = runtime.partner_add("b", B)

    assert outcome["rotated"] is False and outcome["inbox"] == old.w and "503" in outcome["error"]
    assert runtime.channels["inbox"] is old and old.muted is False
    assert notes(runtime) == {"rotation_failed"}
    assert [p["key"] for p in runtime.partners] == [C, B], "the address book changed; only the inbox could not follow yet"
    # A read does not fail over it: the old inbox holds, and attention says why.
    assert runtime.ensure_inbox() is old
    service.refuse_opens = False
    assert runtime.ensure_inbox() is not old, "the next read catches up once the service answers"


def test_after_a_restart_the_inbox_is_matched_against_the_address_book():
    # partners.json changed while the runtime was not running, or by an older
    # version that wrote the file and nothing else.
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}, {"name": "c", "key": C}], inbox_allow=[C])
    old = runtime.channels["inbox"]
    inbox = runtime.ensure_inbox()
    assert inbox is not old and sorted(service.threads[inbox.w]["allow"]) == sorted([B, C])
    assert old.muted is False, "a key was added, none removed: the old address is still read"

    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], inbox_allow=[B, C])
    old = runtime.channels["inbox"]
    inbox = runtime.ensure_inbox()
    assert inbox is not old and service.threads[inbox.w]["allow"] == [B]
    assert old.muted is True, "a key was removed: the old address is read no more"


def test_a_matching_inbox_is_kept():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], inbox_allow=[B])
    assert runtime.ensure_inbox() is runtime.channels["inbox"] and service.count == 1


def test_removing_an_unknown_name_touches_nothing():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], inbox_allow=[B])

    outcome = runtime.partner_remove("nobody")

    assert outcome == {"partner": "nobody", "known": False, "inbox": runtime.channels["inbox"].w}
    assert service.count == 1 and runtime.published == []


def test_muted_travels_with_the_state():
    channel = Channel("inbox-1", "read-key", "x" * 20, int(time.time()) + 100, [C])
    channel.muted = True
    again = Channel.from_state(channel.to_state())
    assert again.muted is True and Channel.from_state({"label": "inbox", "read_key": "r", "w": "y" * 20, "expire_at": 1}).muted is False
