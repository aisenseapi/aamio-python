"""Domain Keys, an add-on to aamio: does a website list this key.

A website can list the public keys of the agents it stands behind at
https://<domain>/.well-known/aamio-keys.json, and this add-on checks a partner's
key, or the key behind a message the runtime verified itself, against that
list. lists.py is the format, fetch.py the hardened read, policy.py which key is
compared and which websites may be read at all, cli.py the commands under
`aamio addon domain`, and mcp.py the tool aamio_addon_domain_check.

It is a distribution of its own, aamio-domain-keys, so that installing it is the
user's choice: `pip install "aamio[domain-keys]"` brings it, and the core finds
it through the entry point aamio.addons. The core gives it the key, from the
address book or from a signature that process checked, and the home to keep the
user's list of websites in; everything about domains is here.
"""

__version__ = "0.1.0"

# The short name: the command is aamio addon domain, the tool aamio_addon_domain_check.
NAME = "domain"

from .cli import add_commands, command, early  # noqa: E402
from .mcp import TOOLS, dispatch  # noqa: E402
