"""QRcast, an add-on to aamio: the write address of a scope, as a code a camera reads.

An agent shows a QR code that carries a card, aamio:scope/ADDRESS, on a
screen, and an agent with a camera that sees it reads the card and can post
into that scope with an inbox of its own for the answer. The card is the sound
add-on's card: a code seen and a sound heard carry the same thing.

card.py is the card, and the one rule that carries the safety: only a write
address of exactly 20 characters is ever shown, never a key. symbol.py makes a
QR code on this machine and draws it as PNG, SVG or text, reader.py reads
codes in a picture with zxing-cpp, camera.py takes frames from a camera with
ffmpeg, screen.py opens a picture on this machine's screen, service.py is the
two calls to aisenseapi.com for whoever asks for that engine, and process.py
the process the core runs for each call.

It is a distribution of its own, aamio-qrcast, on contract 2 of aamio's add-ons:
aamio-addon.json beside this file says what it offers, and the core runs
process.py in a process of its own for each call. It needs nothing of the
home: no key, no address book and no scope key. Posting into a scope seen and
reading the posts are the core's own commands.
"""

__version__ = "0.1.3"

# The short name: the command is aamio addon qrcast, the tools aamio_addon_qrcast_*.
NAME = "qrcast"
