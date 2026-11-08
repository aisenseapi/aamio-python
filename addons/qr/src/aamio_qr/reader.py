"""Reading the QR codes in a picture on this machine, with zxing-cpp and Pillow.

zxing-cpp finds codes at an angle, upside down, light on dark as well as dark on
light, and small codes in a large frame. Pillow opens PNG, JPEG, GIF and WebP,
the four formats aisenseapi.com reads too, and the same limits hold: at most
10 MiB and 25 megapixels, checked before a pixel is decoded. Only QR codes are
read, never barcodes. Nothing leaves the machine.
"""

import io

from . import service

FORMATS = ("png", "jpeg", "gif", "webp")


class Unreadable(Exception):
    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


def kind_of(head):
    """png, jpeg, gif or webp from the first bytes of a file, or None."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def _texts(results):
    texts = []
    for result in results:
        raw = getattr(result, "bytes", None)
        text = None
        if isinstance(raw, (bytes, bytearray)):
            try:
                text = bytes(raw).decode("utf-8")
            except UnicodeDecodeError:
                text = None
        if text is None:
            text = getattr(result, "text", None)
        if isinstance(text, str) and text not in texts:
            texts.append(text)
    return texts


def _zxing():
    try:
        import zxingcpp
    except ImportError:
        raise Unreadable("no_reader", "zxing-cpp, which reads the codes on this machine, is not installed: pip install aamio-qr brings it. Or read with engine aisense, which sends the picture to aisenseapi.com.") from None
    return zxingcpp


def read_image(image):
    """The texts of the QR codes in a Pillow image."""
    zxingcpp = _zxing()
    return _texts(zxingcpp.read_barcodes(image.convert("L"), formats=zxingcpp.BarcodeFormat.QRCode))


def read(data):
    """The texts of the QR codes in a picture file's bytes, in the order zxing-cpp finds them."""
    try:
        from PIL import Image
    except ImportError:
        raise Unreadable("no_reader", "Pillow, which opens the picture on this machine, is not installed: pip install aamio-qr brings it. Or read with engine aisense, which sends the picture to aisenseapi.com.") from None
    if kind_of(data[:16]) is None:
        raise Unreadable("not_a_picture", "This is not a PNG, JPEG, GIF or WebP picture.")
    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
            if width * height > service.MAX_PIXELS:
                raise Unreadable("too_big", "The picture is %d x %d pixels, and at most 25 megapixels are read. Send a smaller picture of the code." % (width, height))
            image.load()
            return read_image(image)
    except Unreadable:
        raise
    except Exception as error:
        raise Unreadable("not_readable", "The picture could not be opened: %s." % (str(error)[:200] or error.__class__.__name__)) from None


def read_frame(width, height, gray):
    """The texts of the QR codes in one grey frame from the camera, a byte a pixel."""
    from PIL import Image

    return read_image(Image.frombytes("L", (width, height), bytes(gray)))
