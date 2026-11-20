"""Trace Billow's raster mark into vector paths (numpy only, no potrace).

Marching squares on the alpha channel gives sub-pixel contours; Douglas-Peucker
keeps them small. Contours are emitted as one path with the even-odd rule, so
any enclosed counter stays open.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image

# Edge midpoints of a marching-squares cell, by corner bit layout:
# bit 0 = top-left, 1 = top-right, 2 = bottom-right, 3 = bottom-left.
_SEGMENTS = {
    1: [("L", "T")], 2: [("T", "R")], 3: [("L", "R")], 4: [("R", "B")],
    5: [("L", "T"), ("R", "B")], 6: [("T", "B")], 7: [("L", "B")], 8: [("B", "L")],
    9: [("B", "T")], 10: [("T", "R"), ("B", "L")], 11: [("B", "R")], 12: [("R", "L")],
    13: [("R", "T")], 14: [("T", "L")],
}


def _contours(field: np.ndarray, level: float) -> list[list[tuple[float, float]]]:
    height, width = field.shape
    inside = field >= level

    def point(edge: str, x: int, y: int) -> tuple[tuple, tuple[float, float]]:
        # Interpolated crossing on one cell edge, keyed by the shared edge so
        # neighbouring cells join exactly.
        if edge == "T":
            a, b, key, base = field[y, x], field[y, x + 1], ("h", x, y), (x, y)
            t = (level - a) / (b - a) if b != a else 0.5
            return key, (base[0] + t, base[1])
        if edge == "B":
            a, b, key, base = field[y + 1, x], field[y + 1, x + 1], ("h", x, y + 1), (x, y + 1)
            t = (level - a) / (b - a) if b != a else 0.5
            return key, (base[0] + t, base[1])
        if edge == "L":
            a, b, key, base = field[y, x], field[y + 1, x], ("v", x, y), (x, y)
            t = (level - a) / (b - a) if b != a else 0.5
            return key, (base[0], base[1] + t)
        a, b, key, base = field[y, x + 1], field[y + 1, x + 1], ("v", x + 1, y), (x + 1, y)
        t = (level - a) / (b - a) if b != a else 0.5
        return key, (base[0], base[1] + t)

    links: dict[tuple, list[tuple]] = {}
    coords: dict[tuple, tuple[float, float]] = {}
    for y in range(height - 1):
        for x in range(width - 1):
            case = (int(inside[y, x]) | int(inside[y, x + 1]) << 1
                    | int(inside[y + 1, x + 1]) << 2 | int(inside[y + 1, x]) << 3)
            for start, end in _SEGMENTS.get(case, []):
                ka, pa = point(start, x, y)
                kb, pb = point(end, x, y)
                coords[ka], coords[kb] = pa, pb
                links.setdefault(ka, []).append(kb)
                links.setdefault(kb, []).append(ka)

    loops: list[list[tuple[float, float]]] = []
    seen: set[tuple] = set()
    for origin in links:
        if origin in seen:
            continue
        loop, previous, current = [], None, origin
        while current not in seen:
            seen.add(current)
            loop.append(coords[current])
            following = [key for key in links[current] if key != previous]
            if not following:
                break
            previous, current = current, following[0]
        if len(loop) > 2:
            loops.append(loop)
    return loops


def _simplify(points: list[tuple[float, float]], tolerance: float) -> list[tuple[float, float]]:
    if len(points) < 3:
        return points
    start, end = np.array(points[0]), np.array(points[-1])
    line = end - start
    norm = float(np.hypot(*line)) or 1.0
    best, index = 0.0, 0
    for i in range(1, len(points) - 1):
        offset = np.array(points[i]) - start
        distance = abs(line[0] * offset[1] - line[1] * offset[0]) / norm
        if distance > best:
            best, index = distance, i
    if best <= tolerance:
        return [points[0], points[-1]]
    return _simplify(points[: index + 1], tolerance)[:-1] + _simplify(points[index:], tolerance)


def trace(mask: Image.Image, viewbox: float, padding: float, resolution: int = 384,
          tolerance: float = 0.45, min_area: float = 12.0) -> str:
    """Path data for `mask` (L image) fitted into a square viewbox with padding."""
    small = mask.resize((resolution, resolution), Image.Resampling.LANCZOS)
    # A transparent border guarantees closed contours.
    field = np.pad(np.asarray(small, dtype=np.float32) / 255.0, 1)
    loops = _contours(field, 0.5)
    scale = (viewbox - 2 * padding) / resolution
    commands = []
    for loop in loops:
        xs, ys = zip(*loop)
        area = 0.5 * abs(sum(xs[i] * ys[i - 1] - xs[i - 1] * ys[i] for i in range(len(loop))))
        if area < min_area:
            continue
        # Simplify the closed loop as two open halves so both ends stay anchored.
        half = len(loop) // 2
        simple = _simplify(loop[: half + 1], tolerance)[:-1] + _simplify(loop[half:] + [loop[0]], tolerance)[:-1]
        points = [((x - 1) * scale + padding, (y - 1) * scale + padding) for x, y in simple]
        commands.append("M" + " L".join(f"{x:.2f},{y:.2f}" for x, y in points) + " Z")
    return " ".join(commands)


def silhouette(mark: Image.Image) -> Image.Image:
    return mark.convert("RGBA").getchannel("A")


def accent(mark: Image.Image, color: tuple[int, int, int]) -> Image.Image:
    """Where the mark carries `color` rather than the white body.

    Measured on the channel where the accent differs most from white, so it
    works for any accent hue (cyan, lavender, mint…).
    """
    rgba = np.asarray(mark.convert("RGBA"), dtype=np.int32)
    channel = int(np.argmax([255 - value for value in color]))
    span = max(1, 255 - color[channel])
    weight = np.clip((255 - rgba[..., channel]) * 255 // span, 0, 255)
    return Image.fromarray((weight * rgba[..., 3] // 255).astype(np.uint8), "L")


def write_svg(mark: Image.Image, target: Path, body: str, accent_rgb: tuple[int, int, int]) -> None:
    accent_color = "#%02X%02X%02X" % accent_rgb
    body_path = trace(silhouette(mark), 64, 0)
    accent_path = trace(accent(mark, accent_rgb), 64, 0, min_area=20.0)
    if not accent_path:
        raise ValueError("The accent sliver was not found; check MARK_ACCENT against the mark.")
    target.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        f'<path fill="{body}" fill-rule="evenodd" d="{body_path}"/>'
        + (f'<path fill="{accent_color}" fill-rule="evenodd" d="{accent_path}"/>' if accent_path else "")
        + "</svg>\n",
        encoding="utf-8",
    )


def write_android_vector(mark: Image.Image, target: Path, comment: str, padding: float = 2.0) -> None:
    path = trace(silhouette(mark), 24, padding)
    target.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f"<!-- {comment} Generated by tool/generate_app_icons.py. -->\n"
        '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    android:width="24dp"\n    android:height="24dp"\n'
        '    android:viewportWidth="24"\n    android:viewportHeight="24">\n'
        "    <path\n"
        '        android:fillColor="#FFFFFFFF"\n'
        '        android:fillType="evenOdd"\n'
        f'        android:pathData="{path}" />\n'
        "</vector>\n",
        encoding="utf-8",
    )
