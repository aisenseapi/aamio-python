"""An add-on to aamio, made from https://github.com/aisenseapi/aamio-addon-template.

aamio-addon.json beside this file says what the add-on offers, and the core
reads it without running anything. process.py is what the core runs, in a
process of its own, for each call.
"""

__version__ = "0.1.0"

# The short name: the command is aamio addon example, and the tools aamio_addon_example_*.
NAME = "example"
