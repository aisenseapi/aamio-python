"""The two calls to aisenseapi.com: a card to sound, and sound back to bytes.

    POST https://aisenseapi.com/services/v1/audio_encode          JSON in, WAV out
    POST https://aisenseapi.com/services/v1/audio_decode/MODE     WAV in, JSON out

Both are free and need no key. What is encoded and what is recorded go to AI
SENSE over HTTPS, and are not kept there, as the pages for the two endpoints
say. aisense answers 422 when a recording holds no intact message, 400 when a
file is not one it reads, and 429 or 503 with Retry-After when it cannot serve
now. An answer that is not what the endpoint documents is unreachable here,
never guessed at.
"""

import json
import urllib.error
import urllib.request

from . import __version__

BASE = "https://aisenseapi.com/services/v1"
MODES = ("audible", "high", "ultrasound")
DECODE_MODES = ("auto",) + MODES
# What aisense reads: at most 40 seconds and 8 MiB of PCM16 WAV.
MAX_RECORDING_BYTES = 8 * 1024 * 1024
# The longest message aisense makes is about 17 seconds, 1.6 MB of WAV.
MAX_SOUND_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024
TIMEOUT = 30
AGENT = "aamio-sound/" + __version__


class Unreachable(Exception):
    def __init__(self, reason, fix, retry_after=None):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix
        self.retry_after = retry_after


class Refused(Exception):
    """What aisense would not take, with its own words."""

    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


class NothingHeard(Exception):
    def __init__(self, fix):
        super().__init__(fix)
        self.fix = fix


def is_wav(data):
    return isinstance(data, (bytes, bytearray)) and len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE"


def _post(path, body, content_type, limit, opener):
    request = urllib.request.Request(BASE + path, data=body, method="POST", headers={"Content-Type": content_type, "User-Agent": AGENT})
    try:
        response = (opener or urllib.request.urlopen)(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as error:
        try:
            data = error.read(MAX_JSON_BYTES)
        except Exception:
            data = b""
        finally:
            error.close()
        return error.code, error.headers, data
    except urllib.error.URLError as error:
        reason = error.reason
        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            raise Unreachable("service_unreachable", "The certificate of aisenseapi.com could not be verified on this machine. If the site opens in a browser, this machine's store may lack the root: SSL_CERT_FILE can point Python at a CA bundle. Verification is never switched off.") from None
        raise Unreachable("service_unreachable", "aisenseapi.com, which makes and reads the sound, could not be reached: %s. Check the network and try again." % reason) from None
    except (OSError, ValueError) as error:
        raise Unreachable("service_unreachable", "aisenseapi.com, which makes and reads the sound, could not be reached: %s. Check the network and try again." % error.__class__.__name__) from None
    with response:
        return response.status, response.headers, response.read(limit + 1)


def _words(payload):
    """aisense's own error and fix, when its answer carries them."""
    try:
        said = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None, None
    if not isinstance(said, dict):
        return None, None
    error = said.get("error") if isinstance(said.get("error"), str) else None
    fix = said.get("fix") if isinstance(said.get("fix"), str) else None
    return error, fix


def _failure(status, headers, payload, done, refused):
    retry = headers.get("Retry-After") if headers is not None else None
    later = (" Try again after %s seconds." % retry) if retry else " Try again later."
    if status == 429:
        return Unreachable("rate_limited", "aisenseapi.com counts requests per address and day, and this address has used its share for now." + later, retry)
    if status == 503:
        return Unreachable("service_busy", "aisenseapi.com cannot serve this right now." + later, retry)
    if 400 <= status < 500:
        error, fix = _words(payload)
        return Refused(refused, ("aisenseapi.com would not take it: %s %s" % (error or "HTTP %d." % status, fix or "")).strip())
    return Unreachable("service_unreachable", "aisenseapi.com answered HTTP %d, so nothing was %s." % (status, done) + later)


def encode(card, mode, opener=None):
    """The WAV for a card, made by aisense."""
    body = json.dumps({"data": card, "input_encoding": "utf8", "mode": mode}).encode("utf-8")
    status, headers, payload = _post("/audio_encode", body, "application/json", MAX_SOUND_BYTES, opener)
    if status != 200:
        raise _failure(status, headers, payload, "played", "service_refused")
    if not is_wav(payload) or len(payload) > MAX_SOUND_BYTES:
        raise Unreachable("service_answered_something_else", "aisenseapi.com answered with something other than the WAV file it documents, so nothing was played. Try again later.")
    return payload


def decode(sound, mode, opener=None):
    """What aisense read in a WAV: data_base64, text, protocol, corrected_bits and mode. NothingHeard when it read no message."""
    status, headers, payload = _post("/audio_decode/" + mode, sound, "audio/wav", MAX_JSON_BYTES, opener)
    if status == 422:
        error, fix = _words(payload)
        said = (": " + error[:1].lower() + error[1:].rstrip(".")) if error else ""
        raise NothingHeard("No complete message was heard%s. %s" % (said, fix or "Record the whole sound, close to the speaker, in a quiet room, and try audible mode."))
    if status != 200:
        raise _failure(status, headers, payload, "read", "not_readable")
    try:
        said = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        said = None
    if not isinstance(said, dict) or not isinstance(said.get("data_base64"), str):
        raise Unreachable("service_answered_something_else", "aisenseapi.com answered with something other than the JSON it documents, so nothing was read. Try again later.")
    return said
