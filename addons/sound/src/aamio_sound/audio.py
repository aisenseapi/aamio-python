"""Playing a WAV file and recording one, on the machine the add-on runs on.

Playing uses what the system has: winsound on Windows, afplay on macOS, and on
Linux paplay, pw-play, aplay or ffplay, with sounddevice as the last resort.
Recording uses sounddevice, which aamio-sound depends on and whose wheels for
Windows and macOS carry PortAudio, then arecord, then sox. A recording is mono
16-bit PCM at 48 kHz, or 44.1 kHz where the microphone takes nothing else: the
two rates aisenseapi.com reads.

The operating system asks the user once for the microphone: macOS for the app
the agent runs in, Windows under the privacy settings for desktop apps. On
Linux a sound server is reached through XDG_RUNTIME_DIR, which the manifest
asks for by name.
"""

import shutil
import subprocess
import sys
import wave

RATES = (48000, 44100)


class Unavailable(Exception):
    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


def _sounddevice():
    """sounddevice, or None where it is not installed or finds no PortAudio."""
    try:
        import sounddevice
    except (ImportError, OSError):
        return None
    return sounddevice


def _last_line(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:200] if lines else "no reason given"


def _run(command, seconds, run):
    try:
        run(command, check=True, timeout=seconds, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        return "%s stopped with code %s: %s" % (command[0], error.returncode, _last_line(error.stderr))
    except subprocess.TimeoutExpired:
        return "%s did not finish within %d seconds" % (command[0], seconds)
    except OSError as error:
        return "%s could not be started: %s" % (command[0], error)
    return None


def players(path, platform):
    if platform == "darwin":
        return [["afplay", path]]
    return [["paplay", path], ["pw-play", path], ["aplay", "-q", path], ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", path]]


def recorders(seconds, path, platform):
    if platform == "win32":
        return [["sox", "-q", "-t", "waveaudio", "default", "-c", "1", "-r", "48000", "-b", "16", path, "trim", "0", str(seconds)]]
    found = [] if platform == "darwin" else [["arecord", "-q", "-f", "S16_LE", "-r", "48000", "-c", "1", "-d", str(seconds), path]]
    return found + [["rec", "-q", "-c", "1", "-r", "48000", "-b", "16", path, "trim", "0", str(seconds)]]


def play(path, which=shutil.which, run=subprocess.run, platform=sys.platform, device=None):
    """Play the file to the end, and say what played it. Unavailable when nothing here can."""
    failed = []
    if platform == "win32":
        try:
            import winsound
        except ImportError:
            winsound = None
        if winsound is not None:
            try:
                winsound.PlaySound(path, winsound.SND_FILENAME)
                return "winsound"
            except RuntimeError as error:
                failed.append("winsound: %s" % error)
    else:
        for command in players(path, platform):
            if which(command[0]):
                why = _run(command, 60, run)
                if why is None:
                    return command[0]
                failed.append(why)
    device = device or _sounddevice()
    if device is not None:
        try:
            with wave.open(path, "rb") as source:
                rate, channels, frames = source.getframerate(), source.getnchannels(), source.readframes(source.getnframes())
            with device.RawOutputStream(samplerate=rate, channels=channels, dtype="int16") as stream:
                stream.write(frames)
            return "sounddevice"
        except Exception as error:
            failed.append("sounddevice: %s" % error)
    if failed:
        raise Unavailable("player_failed", "The sound could not be played: %s. Check the speaker and the volume, or write the sound to a file with --out (out over MCP) and play it another way." % "; ".join(failed))
    raise Unavailable("no_player", "Nothing on this machine plays a sound file: install pulseaudio-utils (paplay), alsa-utils (aplay) or ffmpeg, or write the sound to a file with --out (out over MCP) and play it another way.")


def _record_with(device, seconds, path):
    last = None
    for rate in RATES:
        try:
            chunks = []
            left = rate * seconds
            with device.RawInputStream(samplerate=rate, channels=1, dtype="int16") as stream:
                while left > 0:
                    take = min(rate // 10, left)
                    data, _overflowed = stream.read(take)
                    chunks.append(bytes(data))
                    left -= take
        except Exception as error:
            last = error
            continue
        with wave.open(path, "wb") as out:
            out.setnchannels(1)
            out.setsampwidth(2)
            out.setframerate(rate)
            out.writeframes(b"".join(chunks))
        return None
    return "sounddevice: %s" % last


def record(seconds, path, which=shutil.which, run=subprocess.run, platform=sys.platform, device=None):
    """Record this many seconds from the default microphone into path, and say what recorded it."""
    failed = []
    device = device or _sounddevice()
    if device is not None:
        why = _record_with(device, seconds, path)
        if why is None:
            return "sounddevice"
        failed.append(why)
    for command in recorders(seconds, path, platform):
        if which(command[0]):
            why = _run(command, seconds + 15, run)
            if why is None:
                return command[0]
            failed.append(why)
    if failed:
        raise Unavailable("recorder_failed", "Nothing was recorded: %s. Check that a microphone is connected and that this app may use it: macOS asks once for the app the agent runs in, Windows has it under the privacy settings for desktop apps." % "; ".join(failed))
    raise Unavailable("no_recorder", "Nothing on this machine records from the microphone: sounddevice found no PortAudio, and neither arecord nor sox is installed. Install libportaudio2, alsa-utils or sox, or record the sound another way and read the file with aamio addon sound decode FILE (aamio_addon_sound_decode).")
