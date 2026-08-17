#!/usr/bin/env python3
"""
generate-icons.py — PromptGuard placeholder icons.

Generates icon16.png / icon48.png / icon128.png (a red shield with a white
inner shield and a red checkmark on a transparent background) using only the
Python standard library (zlib + struct — no Pillow needed).

Run from the extension/ folder:
    python icons/generate-icons.py
"""
import os
import struct
import zlib

ICON_DIR = os.path.dirname(os.path.abspath(__file__))

NAVY = (26, 26, 46)      # #1a1a2e
RED = (233, 69, 96)      # #e94560
WHITE = (245, 247, 255)


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", crc32(chunk_type + data))
    )


def point_in_poly(px: float, py: float, poly) -> bool:
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > py) != (yj > py) and px < ((xj - xi) * (py - yi)) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def dist_to_seg(px: float, py: float, a, b) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    length2 = dx * dx + dy * dy
    if length2 == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length2))
    cx, cy = ax + t * dx, ay + t * dy
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5


def shield_pixel(x: float, y: float):
    """Return RGBA for a pixel given normalized coordinates (0..1)."""
    # Outer shield polygon
    outer = [
        (0.5 - 0.30, 0.10),
        (0.5 + 0.30, 0.10),
        (0.5 + 0.30, 0.56),
        (0.5, 0.90),
        (0.5 - 0.30, 0.56),
    ]
    if not point_in_poly(x, y, outer):
        return (0, 0, 0, 0)  # transparent outside the shield

    # Inner shield (white)
    inner = [
        (0.5 - 0.24, 0.238),
        (0.5 + 0.24, 0.238),
        (0.5 + 0.24, 0.505),
        (0.5, 0.8796),
        (0.5 - 0.24, 0.505),
    ]
    if point_in_poly(x, y, inner):
        # Red checkmark inside the inner shield
        if (
            dist_to_seg(x, y, (0.36, 0.55), (0.45, 0.64)) < 0.030
            or dist_to_seg(x, y, (0.45, 0.64), (0.64, 0.38)) < 0.030
        ):
            return RED + (255,)
        return WHITE + (255,)

    return RED + (255,)


def make_png(size: int, draw) -> bytes:
    stride = size * 4 + 1
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            r, g, b, a = draw((x + 0.5) / size, (y + 0.5) / size)
            raw += bytes((r, g, b, a))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", idat)
        + png_chunk(b"IEND", b"")
    )


def main():
    for size in (16, 48, 128):
        path = os.path.join(ICON_DIR, "icon{}.png".format(size))
        with open(path, "wb") as f:
            f.write(make_png(size, shield_pixel))
        print("Wrote {} ({} bytes)".format(path, os.path.getsize(path)))


if __name__ == "__main__":
    main()
