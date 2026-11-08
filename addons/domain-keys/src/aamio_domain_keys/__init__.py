"""Domain Keys, an add-on to aamio: does a website list this key.

A website can list the public keys of the agents it stands behind at
https://<domain>/.well-known/aamio-keys.json, and this add-on checks a partner's
key, or the key behind a message the runtime verified itself, against that
list. lists.py is the format, fetch.py the hardened read, policy.py the words
an answer comes with, and process.py the process the core runs for each call.

It is a distribution of its own, aamio-domain-keys, so that installing it is the
user's choice: `pip install "aamio[domain-keys]"` brings it, and the core finds
it through the entry point aamio.addons. From 0.2.0 it is on contract 2 of
aamio's add-ons: aamio-addon.json beside this file says what it offers, and the
core runs process.py in a process of its own for each call, with the website
the user agreed to, the key the core resolved from the address book or from a
signature it checked, and nothing else of the home. The commands are
`aamio addon domain file | validate | allow | forget | list | check` and the
MCP tool aamio_addon_domain_check, as before; allow, forget and list are the
core's, kept per add-on.
"""

__version__ = "0.2.0"

# The short name: the command is aamio addon domain, the tool aamio_addon_domain_check.
NAME = "domain"
