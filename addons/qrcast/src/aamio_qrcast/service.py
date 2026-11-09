"""The two calls to aisenseapi.com, for whoever asks for the aisense engine: a card to a code, and a picture back to text.

    POST https://aisenseapi.com/services/v1/qrcode_encode    JSON in, JSON with a PNG out
    POST https://aisenseapi.com/services/v1/qrcode_decode    a picture in, as multipart/form-data, JSON out

Both are free and need no key. The card and the picture go to AI SENSE over
HTTPS. aisense makes its code at error correction level H, blue and softened,
with two modules of quiet zone, so the same card is a larger code with smaller
modules than this add-on's own. It reads a picture with zbarimg and answers
every code it finds, QR codes and barcodes alike, one to a line.

aisense answers 400 both when a picture holds no code and when it cannot read
the picture at all, so its sentence "No QR code or barcode was found" is what
tells the two apart; a 422, as audio_decode answers for no message, is taken
for no code too. It answers 413 for a picture over 10 MiB or 25 megapixels,
415 for a format it does not read, and 429 or 503 with Retry-After when it
cannot serve now. A picture goes as multipart: JSON bodies stop at 256 KB there,
less than a photo. An answer that is not what the endpoint documents is
unreachable here, never guessed at.
"""

import base64
import binascii
import http.client
import json
import secrets
import urllib.error
import urllib.request

from . import __version__

BASE = "https://aisenseapi.com/services/v1"
MAX_IMAGE_BYTES = 10485760
MAX_PIXELS = 25000000
MAX_JSON_BYTES = 1024 * 1024
TIMEOUT = 30
AGENT = "aamio-qrcast/" + __version__
NOTHING = "No QR code or barcode was found"
TYPES = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}


class Unreachable(Exception):
    """aisenseapi.com did not do it. answered is True when it sent an answer back, so the request, with the card or the picture, had reached it."""

    def __init__(self, reason, fix, retry_after=None, answered=False):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix
        self.retry_after = retry_after
        self.answered = answered


class Refused(Exception):
    """What aisense would not take, with its own words."""

    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


class NothingSeen(Exception):
    def __init__(self, fix):
        super().__init__(fix)
        self.fix = fix


def _post(path, body, content_type, opener):
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
        raise Unreachable("service_unreachable", "aisenseapi.com could not be reached: %s. Check the network and try again, or use the local engine." % reason) from None
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise Unreachable("service_unreachable", "aisenseapi.com could not be reached: %s. Check the network and try again, or use the local engine." % error.__class__.__name__) from None
    # Reading the answer can fail as well, a timeout or a connection cut halfway,
    # and that is aisenseapi.com unreachable too, not an error out of the add-on:
    # the local engine takes over. It had the request by then.
    try:
        with response:
            return response.status, response.headers, response.read(MAX_JSON_BYTES + 1)
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise Unreachable("service_unreachable", "aisenseapi.com answered, and the answer broke off: %s. Try again, or use the local engine." % error.__class__.__name__, answered=True) from None


def _json(payload):
    """aisense's JSON, read from the first brace: PHP warnings can come before it."""
    try:
        text = payload.decode("utf-8")
        said = json.loads(text[text.index("{"):])
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None
    return said if isinstance(said, dict) else None


def _words(payload):
    said = _json(payload) or {}
    error = said.get("error") if isinstance(said.get("error"), str) else None
    fix = said.get("fix") if isinstance(said.get("fix"), str) else None
    return error, fix


def _failure(status, headers, payload, done, refused):
    retry = headers.get("Retry-After") if headers is not None else None
    later = (" Try again after %s seconds." % retry) if retry else " Try again later."
    if status == 429:
        return Unreachable("rate_limited", "aisenseapi.com counts requests per address and day, and this address has used its share for now." + later, retry, answered=True)
    if status == 503:
        return Unreachable("service_busy", "aisenseapi.com cannot serve this right now." + later, retry, answered=True)
    if 400 <= status < 500:
        error, fix = _words(payload)
        return Refused(refused, ("aisenseapi.com would not take it: %s %s" % (error or "HTTP %d." % status, fix or "")).strip())
    return Unreachable("service_unreachable", "aisenseapi.com answered HTTP %d, so nothing was %s." % (status, done) + later, answered=True)


def encode(card, opener=None):
    """The PNG of aisense's code for a card."""
    status, headers, payload = _post("/qrcode_encode", json.dumps({"data": card}).encode("utf-8"), "application/json", opener)
    if status != 200:
        raise _failure(status, headers, payload, "made", "service_refused")
    said = _json(payload)
    try:
        png = base64.b64decode(said["qrcode_image"], validate=True) if said and isinstance(said.get("qrcode_image"), str) else b""
    except (binascii.Error, ValueError):
        png = b""
    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        raise Unreachable("service_answered_something_else", "aisenseapi.com answered with something other than the PNG it documents, so nothing was made. Try again later, or use the local engine.", answered=True)
    return png


def decode(picture, kind, opener=None):
    """Every code aisense read in a picture, one text each. NothingSeen when it found none."""
    edge = "aamio-qrcast-" + secrets.token_hex(12)
    head = ('--%s\r\nContent-Disposition: form-data; name="qrcode_image"; filename="picture.%s"\r\nContent-Type: %s\r\n\r\n'
            % (edge, kind, TYPES[kind])).encode("ascii")
    body = head + picture + ("\r\n--%s--\r\n" % edge).encode("ascii")
    status, headers, payload = _post("/qrcode_decode", body, "multipart/form-data; boundary=" + edge, opener)
    if status in (400, 422):
        error, fix = _words(payload)
        # 422 is how audio_decode says it heard no message, and what qrcode_decode may say one day.
        if status == 422 or (error and error.startswith(NOTHING)):
            raise NothingSeen("aisense found no code in the picture. %s" % (fix or "Send a sharper, larger or straighter picture of the code."))
    if status != 200:
        raise _failure(status, headers, payload, "read", "not_readable")
    said = _json(payload)
    if not said or not isinstance(said.get("qrcode_content"), str):
        raise Unreachable("service_answered_something_else", "aisenseapi.com answered with something other than the JSON it documents, so nothing was read. Try again later, or use the local engine.", answered=True)
    texts = [line.rstrip("\r") for line in said["qrcode_content"].split("\n")]
    return [text for text in texts if text != ""]
