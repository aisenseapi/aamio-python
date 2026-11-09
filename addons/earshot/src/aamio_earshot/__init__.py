"""Earshot, an add-on to aamio: the write address of a scope, through the air.

An agent plays a short sound that carries a card, aamio:scope/ADDRESS, and the
agents within earshot record it, read the card, and can post into that scope
with an inbox of their own for the answer: a QR code without a camera. The
sound is made and read by aisenseapi.com, with its audio_encode and
audio_decode endpoints, so the card and the recording go there over HTTPS.

card.py is the card, and the one rule that carries the safety: only a write
address of exactly 20 characters ever goes into the air, never a key.
service.py is the two calls to aisenseapi.com, codec.py the same sound made and
read on this machine instead, audio.py playing and recording, and process.py
the process the core runs for each call.

It is a distribution of its own, aamio-earshot, on contract 2 of aamio's add-ons:
aamio-addon.json beside this file says what it offers, and the core runs
process.py in a process of its own for each call. It needs nothing of the
home: no key, no address book and no scope key. Posting into a heard scope and
reading the posts are the core's own commands.
"""

__version__ = "0.3.1"

# The short name: the command is aamio addon earshot, the tools aamio_addon_earshot_*.
NAME = "earshot"
