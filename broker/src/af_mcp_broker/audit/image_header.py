"""Pixel dimensions of an image from its header bytes.

Reads only the container header of PNG, JPEG, GIF and WebP (the image types
MCP tools return), with no imaging dependency: the broker needs a width and a
height to estimate token cost, not a decoder, and the bytes come from a
backend the broker does not control, so nothing here decodes pixel data.
"""

from __future__ import annotations

import struct

# JPEG start-of-frame markers carry the dimensions. 0xC4 (DHT), 0xC8 (JPG)
# and 0xCC (DAC) sit in the same range but are not frame headers.
_JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
# JPEG markers with no length field / payload.
_JPEG_STANDALONE = frozenset({0x01, 0xD8, 0xD9, *range(0xD0, 0xD8)})


def image_dimensions(data: bytes) -> tuple[int, int]:
    """Return ``(width, height)`` in pixels of the PNG/JPEG/GIF/WebP in *data*.

    Raises ``ValueError`` for an unsupported format, a truncated header, or a
    zero dimension.
    """
    try:
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            width, height = _png(data)
        elif data.startswith((b"GIF87a", b"GIF89a")):
            width, height = struct.unpack_from("<HH", data, 6)
        elif data.startswith(b"\xff\xd8"):
            width, height = _jpeg(data)
        elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            width, height = _webp(data)
        else:
            raise ValueError("unrecognized image format")
    except (struct.error, IndexError) as exc:
        raise ValueError("truncated image header") from exc
    if width <= 0 or height <= 0:
        raise ValueError(f"image has a zero dimension ({width}x{height})")
    return width, height


def _png(data: bytes) -> tuple[int, int]:
    # IHDR is always the first chunk: 8 signature + 4 length + 4 type, then
    # big-endian width and height.
    if data[12:16] != b"IHDR":
        raise ValueError("PNG image without an IHDR chunk")
    width, height = struct.unpack_from(">II", data, 16)
    return width, height


def _jpeg(data: bytes) -> tuple[int, int]:
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            raise ValueError("malformed JPEG image segment")
        marker = data[pos + 1]
        if marker == 0xFF:  # fill byte before a marker
            pos += 1
            continue
        pos += 2
        if marker in _JPEG_STANDALONE:
            if marker == 0xD9:  # end of image before any frame header
                break
            continue
        if marker in _JPEG_SOF:
            # segment: length(2) precision(1) height(2) width(2)
            height, width = struct.unpack_from(">HH", data, pos + 3)
            return width, height
        (length,) = struct.unpack_from(">H", data, pos)
        pos += length
    raise ValueError("JPEG image without a frame header")


def _webp(data: bytes) -> tuple[int, int]:
    kind = data[12:16]
    if kind == b"VP8 ":  # lossy: 14-bit dimensions after the frame tag + start code
        if data[23:26] != b"\x9d\x01\x2a":
            raise ValueError("WebP image with a bad VP8 start code")
        width, height = struct.unpack_from("<HH", data, 26)
        return width & 0x3FFF, height & 0x3FFF
    if kind == b"VP8L":  # lossless: two packed 14-bit (size - 1) fields
        if data[20] != 0x2F:
            raise ValueError("WebP image with a bad VP8L signature")
        (bits,) = struct.unpack_from("<I", data, 21)
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if kind == b"VP8X":  # extended: two 24-bit (size - 1) fields
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    raise ValueError("unrecognized WebP image chunk")
