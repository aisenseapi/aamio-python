"""Frames from a camera on this machine, through ffmpeg.

ffmpeg opens the camera, with DirectShow on Windows, AVFoundation on macOS and
Video4Linux on Linux, and writes grey frames, four a second, as PGM images to a
pipe. No frame touches the disk: each is read and dropped. Sound is never
taken. ffmpeg is the one program the add-on does not bring: on Windows it comes
with winget install Gyan.FFmpeg, and winget's link folder is looked in as well,
so an agent started before the install finds it; on macOS with brew install
ffmpeg, and on Linux as the ffmpeg package.

The operating system decides who may use the camera: Windows under the privacy
settings for desktop apps, macOS once for the app the agent runs in, and Linux
by the video group.
"""

import ntpath
import os
import re
import subprocess
import sys
import tempfile

from . import programs

FPS = 4
MAX_SIDE = 4096
WINGET_LINK = ("Microsoft", "WinGet", "Links", "ffmpeg.exe")
_DSHOW_VIDEO = re.compile(r'"([^"]+)"\s+\(video\)')
_DSHOW_NAME = re.compile(r'\]\s+"([^"@][^"]*)"\s*$')


class Unavailable(Exception):
    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


def install_hint(platform):
    if platform == "win32":
        return "On Windows, ffmpeg comes with winget install Gyan.FFmpeg."
    if platform == "darwin":
        return "On macOS, ffmpeg comes with brew install ffmpeg."
    return "On Linux, it is the ffmpeg package, as apt install ffmpeg."


def privacy_hint(platform):
    if platform == "win32":
        return "Check that the camera is connected and not in use, and that desktop apps may use it: Settings, Privacy, Camera."
    if platform == "darwin":
        return "macOS asks once for the app the agent runs in: Privacy & Security, Camera."
    return "Check that the camera is connected and that this user is in the video group."


def find_ffmpeg(which=programs.find, platform=sys.platform, environ=os.environ, exists=os.path.isfile):
    """The full path of ffmpeg: from PATH, never the working directory, then winget's link folder on Windows."""
    found = which("ffmpeg")
    if found:
        return found
    if platform == "win32" and environ.get("LOCALAPPDATA") and programs.is_absolute(environ["LOCALAPPDATA"], platform):
        link = ntpath.join(environ["LOCALAPPDATA"], *WINGET_LINK)
        if exists(link):
            return link
    return None


def _last_line(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:200] if lines else "no reason given"


def list_cameras(ffmpeg, platform=sys.platform, run=subprocess.run):
    """The cameras ffmpeg sees, by the names it takes them by."""
    if platform == "win32":
        command = [ffmpeg, "-hide_banner", "-list_devices", "true", "-f", "dshow", "-i", "dummy"]
    elif platform == "darwin":
        command = [ffmpeg, "-hide_banner", "-f", "avfoundation", "-list_devices", "true", "-i", ""]
    else:
        return sorted(os.path.join("/dev", name) for name in os.listdir("/dev") if re.fullmatch(r"video[0-9]+", name)) if os.path.isdir("/dev") else []
    try:
        said = run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    except (OSError, subprocess.SubprocessError) as error:
        raise Unavailable("camera_failed", "ffmpeg could not list the cameras: %s." % error) from None
    text = (said.stderr or b"").decode("utf-8", "replace")
    if platform == "darwin":
        section = text.split("AVFoundation video devices:", 1)[-1].split("AVFoundation audio devices:", 1)[0]
        return [match.group(1) for match in re.finditer(r"\]\s+\[[0-9]+\]\s+(.+?)\s*$", section, re.M)]
    names = _DSHOW_VIDEO.findall(text)
    if not names and "DirectShow video devices" in text:
        section = text.split("DirectShow video devices", 1)[1].split("DirectShow audio devices", 1)[0]
        names = [match.group(1) for match in (_DSHOW_NAME.search(line) for line in section.splitlines()) if match]
    return names


def default_camera(ffmpeg, platform=sys.platform, run=subprocess.run, exists=os.path.exists):
    if platform == "win32":
        names = list_cameras(ffmpeg, platform, run)
        if not names:
            raise Unavailable("no_camera", "ffmpeg finds no camera on this machine. %s" % privacy_hint(platform))
        return names[0]
    if platform == "darwin":
        return "0"
    if not exists("/dev/video0"):
        raise Unavailable("no_camera", "There is no /dev/video0 on this machine. Connect a camera, or name one with --camera (camera over MCP), as /dev/video2.")
    return "/dev/video0"


def input_for(platform, camera):
    if platform == "win32":
        return ["-f", "dshow", "-i", "video=" + camera]
    if platform == "darwin":
        return ["-f", "avfoundation", "-framerate", "30", "-i", camera]
    return ["-f", "v4l2", "-i", camera]


def _read_exact(stream, length):
    chunks = []
    left = length
    while left > 0:
        chunk = stream.read(left)
        if not chunk:
            return None
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def read_pgm(stream):
    """One P5 frame from ffmpeg's pipe, as (width, height, bytes), or None at the end of the stream."""
    fields = []
    token = b""
    while len(fields) < 4:
        ch = stream.read(1)
        if not ch:
            return None
        if ch == b"#" and not token:
            while ch not in (b"\n", b""):
                ch = stream.read(1)
            continue
        if ch.isspace():
            if token:
                fields.append(token)
                token = b""
            continue
        token += ch
        if len(token) > 10:
            raise Unavailable("camera_failed", "ffmpeg wrote something other than the grey frames asked for.")
    magic, width, height, depth = fields
    if magic != b"P5" or not width.isdigit() or not height.isdigit() or depth != b"255":
        raise Unavailable("camera_failed", "ffmpeg wrote something other than the grey frames asked for.")
    width, height = int(width), int(height)
    if not (0 < width <= MAX_SIDE and 0 < height <= MAX_SIDE):
        raise Unavailable("camera_failed", "ffmpeg gave a frame of %d x %d pixels, and at most %d a side are read." % (width, height, MAX_SIDE))
    data = _read_exact(stream, width * height)
    return None if data is None else (width, height, data)


def frames(seconds, camera=None, which=programs.find, platform=sys.platform, environ=os.environ, popen=subprocess.Popen, run=subprocess.run):
    """Grey frames from the camera, four a second, for this many seconds, as (width, height, bytes). Closing the generator stops ffmpeg."""
    ffmpeg = find_ffmpeg(which, platform, environ)
    if ffmpeg is None:
        raise Unavailable("no_ffmpeg", "ffmpeg, which reads the camera, is not on this machine. %s Or take a picture another way and read it with aamio addon qrcast read FILE (aamio_addon_qrcast_read)." % install_hint(platform))
    if camera is None:
        camera = default_camera(ffmpeg, platform, run)
    command = [ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin"] + input_for(platform, camera) + [
        "-t", str(seconds), "-an", "-vf", "fps=%d,format=gray" % FPS, "-f", "image2pipe", "-c:v", "pgm", "-"]
    errors = tempfile.TemporaryFile()
    try:
        process = popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
    except OSError as error:
        errors.close()
        raise Unavailable("camera_failed", "ffmpeg could not be started: %s." % error) from None
    got = 0
    try:
        while True:
            frame = read_pgm(process.stdout)
            if frame is None:
                break
            got += 1
            yield frame
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if got == 0:
            errors.seek(0)
            raise Unavailable("camera_failed", "ffmpeg gave no picture from the camera %s: %s. %s" % (camera, _last_line(errors.read(8192)), privacy_hint(platform)))
        # The pictures stop either because the time is up, and ffmpeg ends well,
        # or because the camera went away, and ffmpeg ends with an error. Only the
        # exit code tells the two apart: without it a camera unplugged halfway
        # would read as a scan in which no code was seen.
        if process.returncode not in (None, 0):
            errors.seek(0)
            raise Unavailable("camera_failed", "The camera %s stopped giving pictures after %d, and ffmpeg ended with exit code %d: %s. Check that the camera is connected and not taken by another program, and scan again." % (
                camera, got, process.returncode, _last_line(errors.read(8192))))
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout is not None:
            process.stdout.close()
        errors.close()
