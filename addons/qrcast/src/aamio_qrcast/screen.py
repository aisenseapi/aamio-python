"""Opening a picture on this machine's screen, in whatever shows pictures here.

Windows opens it with the program set for PNG files, macOS with open, and Linux
with xdg-open when there is a display to open it on: DISPLAY or
WAYLAND_DISPLAY, which the manifest asks for by name. The picture stays where
it was written, for the viewer to show. Nothing is sent.
"""

import os
import subprocess
import sys

from . import programs

# How long a viewer that stops at once is waited for, to hear that it failed.
WAIT = 1.5


class Unavailable(Exception):
    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


def show(path, platform=sys.platform, environ=os.environ, which=programs.find, popen=subprocess.Popen, startfile=None):
    """Open the picture on the screen, and say what opened it. Unavailable when nothing here can."""
    if platform == "win32":
        startfile = startfile or getattr(os, "startfile", None)
        if startfile is None:
            raise Unavailable("no_viewer", "Nothing here opens a picture. Write the code to a file with --out (out over MCP) and show it where it can be seen.")
        try:
            startfile(path)
        except OSError as error:
            raise Unavailable("viewer_failed", "Windows could not open the picture: %s. Write the code to a file with --out (out over MCP) and show it another way." % (error.strerror or error)) from None
        return "windows"
    if platform == "darwin":
        name = "open"
        found = which(name)
        if not found:
            raise Unavailable("no_viewer", "Nothing here opens a picture: open is not in any folder PATH names. Write the code to a file with --out (out over MCP) and show it another way.")
    else:
        if not (environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY")):
            raise Unavailable("no_screen", "This machine has no screen the add-on can reach: neither DISPLAY nor WAYLAND_DISPLAY is set. Write the code to a file with --out (out over MCP) and show it where it can be seen.")
        name = "xdg-open"
        found = which(name)
        if not found:
            raise Unavailable("no_viewer", "Nothing here opens a picture: xdg-open is missing. Install xdg-utils, or write the code to a file with --out (out over MCP) and show it another way.")
    # What starts is the full path the lookup gave, never the bare name.
    command = [found, path]
    try:
        child = popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as error:
        raise Unavailable("viewer_failed", "%s could not be started: %s. Write the code to a file with --out (out over MCP) and show it another way." % (name, error)) from None
    try:
        code = child.wait(timeout=WAIT)
    except subprocess.TimeoutExpired:
        return name
    if code != 0:
        raise Unavailable("viewer_failed", "%s could not open the picture, and stopped with code %s. Write the code to a file with --out (out over MCP) and show it another way." % (name, code))
    return name
