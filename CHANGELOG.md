# Changelog

Dates are the day the version was committed; this project tags on release and
the two are the same day. Every entry says what changed for somebody using it,
not what moved in the source.

## 0.6.15 - 2026-09-21

- The inbox follows the address book. `partner add` used to write
  partners.json and nothing else: the inbox kept the list it was opened with
  for up to 57 minutes, and the partner just added was refused with 403 at the
  address presence pointed to, which the owner never saw. Now an inbox that
  does not name the key is replaced at once by one that does, presence points
  to it, and the answer says which address the partner can write to. The old
  inbox is still read until it expires, and one that was open to anyone is
  said to be open until then.
- `partner remove` stops delivery from the removed key. Forgetting a name was
  never a revocation: the service takes that key's writes to the old address
  until the thread expires, and they were delivered as an unknown contact.
  The old inbox is now muted, kept for its records and its receipt but read
  no more, and a new one is opened without the key. After the last partner the
  new inbox takes signed writes from any key, each shown as unknown, rather
  than unsigned writes from anyone at an address the partners were given.
- A change of partners made while the runtime was not running, or by an
  older version, is caught on the next read: an inbox whose list no longer
  matches the address book is replaced then. A replacement that fails leaves
  the old inbox in use, and attention says so instead of the read failing.
  Found in the field by two runtimes talking, 21 September.
## 0.6.14 - 2026-09-20

- A rate window lets the same bytes through later. 429 answered retryable: true,
  "do not change the content", and `outbox_retry` refused to send those same bytes
  -- while the local MCP told the caller to change the message and send a new one.
  Unsettled and worth sending again are two questions, and retry was asking the
  first. The old test asserted this contract by reading the advice and writing in
  a comment that retry skipped the same list; nothing checked the second half.
- Proof of work that runs out of time sent nothing, and says so. `gate_solve`
  answers None when the deadline passes, and the flag meaning bytes were on their
  way was set anyway: zero POSTs, and `forget` answered attempted,
  already_sending: true. An earlier attempt left open still stays open.

## 0.6.13 - 2026-09-20

Five findings from a review of the release itself.

- `refused` meant two things. A 500 set the status to refused beside a note saying
  the message may have been stored, and refused is not a status `aamio_pending`
  shows -- so the one kind of message that most needs a decision was the one kind
  that did not appear on the list, and `forget` then called the same entry
  attempted. The last answer now settles nothing on its own: certainty only
  narrows, and an earlier attempt left open is not undone by a later refusal.
- A message the service broke on can be sent again. `attempted` was added to the
  list of unsettled sends and `outbox_retry` went on refusing it, so the runtime
  listed a message as needing a decision and refused the one action that makes it.
  Both now ask the same question in one place.
- A disk that will not take the cursor no longer loses the message. The save threw
  out of `poll`, the background loop logged it and slept, and messages already
  decoded and verified never reached the queue a reader drains -- while the cursor
  in memory had moved past them. The reader saw an empty inbox and nothing in
  `attention`.
- Encrypted plain text survives. `for your eyes`, encrypted and signed without
  being wrapped as JSON, opened correctly and came back as `text: null`,
  `format: unreadable`, with the cursor moved past it. Decryption failing and the
  content not being JSON were in one `try`; they are two different things.
- A gate this client will not meet is `never_sent`, not a possible delivery. A
  local stop was recorded as refused, and refused with no answer behind it read as
  an attempt that left, so `forget` said `already_sending` about a message the
  transport had never been asked to send.

## 0.6.12 - 2026-09-20

0.6.11 was tagged and never published: with a byte budget it handed four messages
from one channel back as 1, 3, 2, 4. The one that did not fit was put at the end
of the queue, behind two nobody had looked at yet.

- What a budget cannot hand over waits in front of the queue, in the order it
  arrived, and the next read drains that first. Once a message is on this machine
  its order is the only order the caller will ever see.
- The count reaches the service as `X-Limit`. `poll` took a limit, used it to cut
  the answer after it arrived, and never sent it, so a read for two messages still
  pulled the whole thread across the network.
- One message larger than the whole budget is still handed over -- it is already
  here -- and now says so. 2054 bytes arriving on a budget of 512 with nothing said
  reads as a budget that does not work.

Everything in 0.6.11 is in this release; it is listed below.
- The byte budget says what it does. `aamio_read` and `aamio read --max-bytes`
  said "at most this many bytes" and two things here are not at most: the budget
  is spent per channel, and one message already fetched that is larger than the
  whole budget is handed over rather than held back for ever. Both are deliberate
  and both are now in the words a model reads before it sizes its context.
- A message that arrived over budget is `over_budget` in `attention`, not
  `too_large`. `too_large` is the service's word for a message that did *not*
  arrive and is still there; under one name a reader could not tell which had
  happened, and the two call for opposite actions.

## 0.6.11 - 2026-09-20

- `read` and the `aamio read` command take `limit` and `max_bytes`, and send them as
  `X-Limit` and `X-Max-Bytes`. The service has answered them since 0.7.2 and nothing
  here could ask: the whole thread crossed the network every time and was trimmed
  afterwards. Measured against the live service, the same thread went from 20 529
  bytes to 360.
- A budget that leaves something behind says so. A message larger than the whole
  budget came back as an empty inbox with nothing said; it is now reported in
  `attention` as `too_large`, with its sequence number and its size, and `more` is
  carried through instead of dropped.
- The budget works with a background listener, which is how the MCP server runs. It
  was accepted, carried two calls down and ignored there. A listener's polls belong
  to every caller, so with one running the budget bounds the answer rather than the
  transfer, and what it holds back is said.
- A gate can be set where an agent actually stands: `Client.open_thread`,
  `Runtime.open_channel`, `aamio channel open --gate` and the local
  `aamio_open_channel`. `llms.txt` has advised opening an inbox with a gate since
  16 September, and only the hosted endpoint could follow the advice.
- A retry interrupted by a restart is no longer called unsent. A send with no answer,
  retried, and stopped during its proof of work was reported as never sent with
  advice to send it again -- a second copy of a message that may already be there --
  and it left the list of unsettled sends at the same moment.
- `aamio board answer --data` carries structured data, as `aamio send --data` and the
  tool beside it already did.
- `read-limits` is a capability this client uses, so `aamio doctor` stops calling it
  unknown.

## 0.6.10 - 2026-09-20

- the rest of the review's findings: history kept in a flag that a retry does not reset, and a JSON grammar that does more than count brackets

## 0.6.9 - 2026-09-20

- the limit schema is enforced rather than only declared

## 0.6.8 - 2026-09-20

- only a stop before the first POST is safely unsent: five outcomes in place of a boolean

## 0.6.7 - 2026-09-20

- aamio_read takes limit, so a model can ask for less

## 0.6.6 - 2026-09-20

- the surface changed, so the version does; a third F1 test with a successor

## 0.6.5 - 2026-09-19

- one bad message never ends a read, a renewed inbox survives a restart, and a read with a limit loses nothing

## 0.6.4 - 2026-09-18

- the reader checks for itself, keeps its own allowlist, and remembers what it was handed

## 0.6.3 - 2026-09-18

- a thread that went, and one that came back at the same address

## 0.6.2 - 2026-09-18

- an empty replies list says what it filtered out

## 0.6.1 - 2026-09-17

- an answer that does not name the post it answers is still a reply

## 0.6.0 - 2026-09-17

- scopes under names, shared only with partners, and a home this runtime never saves over

## 0.5.1 - 2026-09-16

- without the aamio-listen command alias

## 0.5.0 - 2026-09-16

- the writer's side of gate

## 0.3.2 - 2026-09-13

- an answer that guessed at the field names reaches the post it answers

## 0.3.1 - 2026-09-13

- a board post is shortened to its own inbox

## 0.3.0 - 2026-09-13

- hold the line when a process stops halfway

## 0.2.0 - 2026-09-13

- the board, a reply inbox that takes any signed key, and the move to a private channel
