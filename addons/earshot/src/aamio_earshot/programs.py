"""Finding a program by its full path, never in the working directory.

A program asked for by a bare name was looked for in the working directory
first on Windows, and in any folder PATH names relatively: a sox.exe in the
folder the agent ran from was the one that ran (a security review of 13
November 2026). find() looks only in the folders PATH names by a full path,
leaves out the working directory however PATH names it, and gives back the full
path of the file, which is what the add-on then starts. On Windows it takes an
.exe and nothing else, and cmd and powershell come from the folder Windows keeps
them in. It does not use shutil.which, which on Python 3.10 still looks in the
working directory first on Windows (a review of 14 November 2026).

The same file is in aamio-earshot and aamio-qrcast.
"""

import ntpath
import os
import posixpath
import sys

# Programs Windows brings, where Windows keeps them.
SYSTEM = {"cmd": ("System32",), "powershell": ("System32", "WindowsPowerShell", "v1.0")}


def is_absolute(folder, platform=None):
    """A full path: with a drive and a root, or a share, on Windows; from the root elsewhere. C:folder and \\folder are not."""
    platform = sys.platform if platform is None else platform
    if platform == "win32":
        drive, rest = ntpath.splitdrive(folder)
        return bool(drive) and (rest[:1] in ("\\", "/") or (drive[:2] in ("\\\\", "//") and rest == ""))
    return folder.startswith("/")


def _same(folder, here, paths):
    if paths.normcase(paths.normpath(folder)) == paths.normcase(paths.normpath(here)):
        return True
    try:
        return os.path.samefile(folder, here)
    except (OSError, ValueError):
        return False


def find(name, platform=None, environ=None, cwd=None, isfile=os.path.isfile, access=os.access):
    """The full path of the program, or None where no folder PATH names by a full path, other than the working directory, has it."""
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    paths = ntpath if platform == "win32" else posixpath
    here = os.getcwd() if cwd is None else cwd
    file = name + ".exe" if platform == "win32" and not name.lower().endswith(".exe") else name
    if platform == "win32" and name.lower() in SYSTEM:
        root = environ.get("SYSTEMROOT") or environ.get("SystemRoot") or "C:\\Windows"
        candidate = ntpath.join(root, *SYSTEM[name.lower()], file)
        if is_absolute(root, platform) and isfile(candidate):
            return candidate
    for folder in (environ.get("PATH") or environ.get("Path") or "").split(";" if platform == "win32" else ":"):
        folder = folder.strip()
        if platform == "win32":
            folder = folder.strip('"')
        if not folder or not is_absolute(folder, platform) or _same(folder, here, paths):
            continue
        candidate = paths.join(folder, file)
        if isfile(candidate) and (platform == "win32" or access(candidate, os.X_OK)):
            return candidate
    return None
