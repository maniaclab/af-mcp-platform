"""Hand-built image headers for tests (no imaging library, no fixture files)."""

from __future__ import annotations

import struct
import zlib


def png(width: int, height: int) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(kind + body)
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


def gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def jpeg(width: int, height: int) -> bytes:
    app0 = (
        b"\xff\xe0"
        + struct.pack(">H", 16)
        + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    )
    # A comment segment before the frame header: the parser must skip by length.
    com = b"\xff\xfe" + struct.pack(">H", 7) + b"hello"
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + com + sof + b"\xff\xd9"


def webp_lossy(width: int, height: int) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height)
    body = b"WEBP" + b"VP8 " + struct.pack("<I", len(frame)) + frame
    return b"RIFF" + struct.pack("<I", len(body)) + body


def webp_lossless(width: int, height: int) -> bytes:
    bits = (width - 1) | ((height - 1) << 14)
    frame = b"\x2f" + struct.pack("<I", bits)
    body = b"WEBP" + b"VP8L" + struct.pack("<I", len(frame)) + frame
    return b"RIFF" + struct.pack("<I", len(body)) + body


def webp_extended(width: int, height: int) -> bytes:
    frame = (
        b"\x00\x00\x00\x00"
        + (width - 1).to_bytes(3, "little")
        + (height - 1).to_bytes(3, "little")
    )
    body = b"WEBP" + b"VP8X" + struct.pack("<I", len(frame)) + frame
    return b"RIFF" + struct.pack("<I", len(body)) + body
