"""Earshot link, a transport to aamio under contract 3: messages through the air, each frame one Earshot packet.

Earshot plays the write address of a scope, and the messages then go over the
internet. This is the other way round: the sound is the medium. Two runtimes
within earshot of each other, each with a speaker and a microphone, carry their
sealed messages and the signed receipts for them through the air, half duplex,
in the audible band unless the high band or ultrasound is chosen. The sound is
made and read on this machine with Earshot's codec, never at aisenseapi.com.

It ships in the aamio-earshot distribution and is a package of its own, since
the core reads a manifest from the top-level package an add-on names.
transport.py is the process the core runs while it owns the home.
"""

__version__ = "0.1.0"

NAME = "earshot-link"
