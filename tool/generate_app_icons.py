#!/usr/bin/env python3
"""Generate every Billow icon from one AI-drawn mark (same provider flow as Rillight).

The script asks the image model selected in the local Codex config for one
two-tone wave mark on a flat white background, cuts the mark out with a soft
edge matte, recolours it to the brand palette, and composes every asset from
that single transparent mark:

    assets/icon-source.png      raw generation, kept for --reuse-source
    assets/mark.png             transparent white wave (1024, tight crop)
    assets/icon-desktop.png     rounded tile for Windows / macOS / Linux
    assets/icon.png             full-bleed square (iOS, store listings)
    assets/icon-android-fg.png  adaptive-icon foreground (safe zone)
    assets/icon-android-bg.png  adaptive-icon background
    assets/icon-android-mono.png  themed-icon monochrome layer
    public/brand-mark.svg       in-app logo, traced two-tone vector; the theme draws the tile
    android drawable/ic_tile.xml, ic_stat_billow.xml   Quick Settings tile and notification glyphs

Then `npm run icons` runs `tauri icon` and syncs the web, tray and Android files.

The tile is a mid-tone indigo gradient (not a fixed dark navy), so the logo
sits naturally on both the light and the dark theme; styles.css uses the same stops.

Requirements: Python 3.11+, Pillow.

    python tool/generate_app_icons.py --force          # new generation
    python tool/generate_app_icons.py --reuse-source --force   # offline rebuild
    python tool/generate_app_icons.py --dry-run        # show the request only
"""
from __future__ import annotations

import argparse
import base64
from collections import deque
from io import BytesIO
import json
import os
from pathlib import Path
import tomllib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageOps

from trace_mark import write_android_vector, write_svg

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
PUBLIC = ROOT / "public"
SOURCE = ASSETS / "icon-source.png"
ANDROID_RES = ROOT / "src-tauri/gen/android/app/src/main/res"
DEFAULT_MODEL = "gpt-image-2.6"
CANVAS = 1024

# Brand palette: indigo-violet. Light enough at the top to sit on the light
# theme, deep enough at the bottom to hold its shape on the dark one.
TILE_TOP = (139, 140, 255)       # #8b8cff, same stops as --brand-tile in styles.css
TILE_BOTTOM = (75, 63, 214)      # #4b3fd6
MARK_BODY = (255, 255, 255)
MARK_ACCENT = (201, 211, 255)    # #c9d3ff, the lit underside of the crest

PROMPT = """Use case: logo-brand
Asset type: master artwork for the app icon of "Billow", a calm, fast network proxy client. The artwork is cut out and recoloured afterwards, so it must be a clean two-colour silhouette.
Primary request: one original, elegant ocean-swell mark: a single smooth, full-bodied crest that rises from a short tapering tail at the lower right, sweeps up and curls inward over itself, leaving one rounded open curl of negative space inside. A thin crescent sliver of the second colour runs along the lower inner edge of the crest, like light catching the underside of the wave. It reads as one unified, sculptural shape, not stripes or multiple waves.
Proportion: compact and nearly square; the mark's overall width and height are about equal (never wider than 1.2 times its height). The tail is short; no long flat baseline or horizon line.
Scene/backdrop: a perfectly flat pure white background (#FFFFFF) that reaches all four edges; no texture, no vignette, no frame, no tile, no rounded square, no circle.
Subject: exactly one centered mark, occupying about 60% of the canvas width, generous white space on every side, nothing touching the edges.
Style/medium: premium minimal vector logo, flat fills only, crisp clean edges, confident balanced curves, simple enough to stay recognisable at 16 pixels.
Colour: the wave body in solid near-black (#111111); the crescent sliver in solid vivid blue (#1E6BFF). Only these two flat colours on white. No gradients, no shading, no outlines, no highlights.
Composition/framing: straight-on, square 1024x1024, one focal element, gentle asymmetry.
Text (verbatim): none
Avoid: text, letters, Chinese characters, the letter C or G shape, numbers, watermark, multiple waves, parallel ribbons, water droplets, splash particles, sun, boat, scenery, globe, shield, lock, lightning, arrows, 3D, bevel, glow, drop shadow, gradients, grain, mockups, rounded-square backgrounds, circles, borders."""


def fail(message: str) -> None:
    raise SystemExit(f"Error: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path,
                        default=Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml",
                        help="Codex config.toml path (defaults to CODEX_HOME/config.toml).")
    parser.add_argument("--model", default=os.environ.get("IMAGE_MODEL", DEFAULT_MODEL),
                        help="Image model exposed by the configured provider.")
    parser.add_argument("--quality", default="high", choices=("low", "medium", "high", "auto"))
    parser.add_argument("--force", action="store_true", help="Replace existing icon files.")
    parser.add_argument("--reuse-source", action="store_true",
                        help="Rebuild every asset from assets/icon-source.png without calling the provider.")
    parser.add_argument("--dry-run", action="store_true", help="Print the request without calling the provider.")
    return parser.parse_args()


# ── Provider ────────────────────────────────────────────────────────────────

def load_provider(config_path: Path) -> tuple[str, str, str, str]:
    if not config_path.is_file():
        fail(f"Codex config not found: {config_path}")
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    name = config.get("model_provider")
    provider = config.get("model_providers", {}).get(name, {})
    if not name or not isinstance(provider, dict):
        fail("The selected Codex model provider is missing from config.toml.")
    base_url = provider.get("base_url")
    token = provider.get("experimental_bearer_token") or os.environ.get(provider.get("env_key", "OPENAI_API_KEY"))
    model = config.get("model")
    if not base_url or not token or not model:
        fail("The selected Codex provider needs base_url, a credential and a Responses model.")
    return str(name), str(base_url).rstrip("/"), str(token), str(model)


def request_json(url: str, token: str, payload: dict[str, Any] | None = None, timeout: int = 600) -> dict[str, Any]:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, data=body, headers=headers, method="POST" if body else "GET"), timeout=timeout) as response:
            decoded = json.load(response)
    except HTTPError as error:
        # Never echo a provider body: it can contain request credentials.
        fail(f"Image provider returned HTTP {error.code}")
    except URLError as error:
        fail(f"Could not reach image provider: {error.reason}")
    if not isinstance(decoded, dict):
        fail("Image provider returned an unexpected response shape.")
    return decoded


def generated_image(response: dict[str, Any]) -> bytes:
    for item in response.get("output") or []:
        if isinstance(item, dict) and item.get("type") == "image_generation_call" and item.get("result"):
            result = str(item["result"])
            if result.startswith("data:") and "," in result:
                result = result.split(",", 1)[1]
            return base64.b64decode(result, validate=True)
    fail("Provider returned no completed image_generation_call.")
    raise AssertionError


# ── Cut-out ─────────────────────────────────────────────────────────────────

def edge_background_mask(image: Image.Image, tolerance: int = 40) -> Image.Image:
    """Edge-connected pixels close to the corner colour (the flat backdrop)."""
    rgb = image.convert("RGB")
    pixels = rgb.load()
    width, height = rgb.size
    corners = [pixels[0, 0], pixels[width - 1, 0], pixels[0, height - 1], pixels[width - 1, height - 1]]
    background = tuple(sum(c[i] for c in corners) // 4 for i in range(3))
    spread = max(max(abs(c[i] - background[i]) for i in range(3)) for c in corners)
    if spread > 48 or min(background) < 200:
        fail(f"Expected a flat white backdrop at the canvas edges; got corners {corners}.")

    visited = bytearray(width * height)
    mask = Image.new("L", rgb.size, 0)
    mask_pixels = mask.load()
    queue: deque[tuple[int, int]] = deque()

    def enqueue(x: int, y: int) -> None:
        index = y * width + x
        if visited[index]:
            return
        visited[index] = 1
        color = pixels[x, y]
        if max(abs(color[i] - background[i]) for i in range(3)) > tolerance:
            return
        mask_pixels[x, y] = 255
        queue.append((x, y))

    for x in range(width):
        enqueue(x, 0)
        enqueue(x, height - 1)
    for y in range(height):
        enqueue(0, y)
        enqueue(width - 1, y)
    while queue:
        x, y = queue.popleft()
        if x > 0:
            enqueue(x - 1, y)
        if x + 1 < width:
            enqueue(x + 1, y)
        if y > 0:
            enqueue(x, y - 1)
        if y + 1 < height:
            enqueue(x, y + 1)
    return mask


def extract_mark(source: Image.Image) -> Image.Image:
    """Cut the two-tone mark off its white backdrop and recolour it to the brand palette.

    Alpha is a soft matte (distance from white) limited to what the edge flood
    fill did not claim, so anti-aliased edges stay smooth and enclosed white
    counters stay transparent only when they truly touch the outside. Each
    foreground pixel is un-mixed from white first, then blended between the
    body and accent colours by how blue it is.
    """
    rgb = source.convert("RGB")
    outside = edge_background_mask(rgb)
    # Grow the outside region by a pixel so the soft matte decides the rim.
    outside_core = outside.filter(ImageFilter.MinFilter(3))
    src = rgb.load()
    core = outside_core.load()
    out = Image.new("RGBA", rgb.size, (0, 0, 0, 0))
    dst = out.load()
    for y in range(rgb.height):
        for x in range(rgb.width):
            if core[x, y]:
                continue
            r, g, b = src[x, y]
            distance = max(255 - r, 255 - g, 255 - b)
            alpha = min(1.0, distance / 200)
            if alpha <= 0.02:
                continue
            # Un-mix from the white backdrop: P = a·F + (1 − a)·255.
            fr, fg, fb = ((channel - (1 - alpha) * 255) / alpha for channel in (r, g, b))
            blueness = max(0.0, min(1.0, (fb - fr) / 140))
            color = tuple(round(MARK_BODY[i] * (1 - blueness) + MARK_ACCENT[i] * blueness) for i in range(3))
            dst[x, y] = (*color, round(alpha * 255))
    bounds = out.getchannel("A").point(lambda value: 255 if value > 24 else 0).getbbox()
    if bounds is None:
        fail("The generated image has no visible mark.")
    mark = out.crop(bounds)
    # Canonical form: the mark scaled so its longer side is exactly CANVAS.
    scale = CANVAS / max(mark.size)
    mark = mark.resize((max(1, round(mark.width * scale)), max(1, round(mark.height * scale))), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    canvas.alpha_composite(mark, ((CANVAS - mark.width) // 2, (CANVAS - mark.height) // 2))
    return canvas


# ── Composition ─────────────────────────────────────────────────────────────

def gradient(size: int) -> Image.Image:
    """Diagonal accent gradient, light at the top-left."""
    vertical = Image.linear_gradient("L")              # 0 at the top, 255 at the bottom
    horizontal = vertical.rotate(90)                   # 0 at the left, 255 at the right
    ramp = ImageChops.add(vertical.point(lambda v: v // 2), horizontal.point(lambda v: v // 2))
    ramp = ramp.resize((size, size), Image.Resampling.BICUBIC)
    top = Image.new("RGB", (size, size), TILE_TOP)
    bottom = Image.new("RGB", (size, size), TILE_BOTTOM)
    return Image.composite(bottom, top, ramp).convert("RGBA")


def placed(mark: Image.Image, size: int, fraction: float, offset: tuple[float, float] = (0, 0)) -> Image.Image:
    """The mark scaled to `fraction` of `size`, optically centred on a transparent canvas."""
    target = max(1, round(size * fraction))
    scaled = mark.resize((target, target), Image.Resampling.LANCZOS)
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    x = (size - target) // 2 + round(offset[0] * size)
    y = (size - target) // 2 + round(offset[1] * size)
    layer.alpha_composite(scaled, (x, y))
    return layer


def rounded_mask(size: int, box: tuple[int, int, int, int], radius: int, scale: int = 4) -> Image.Image:
    big = Image.new("L", (size * scale, size * scale), 0)
    ImageDraw.Draw(big).rounded_rectangle(tuple(v * scale for v in box), radius=radius * scale, fill=255)
    return big.resize((size, size), Image.Resampling.LANCZOS)


def desktop_icon(mark: Image.Image) -> Image.Image:
    """macOS-style tile: 824px rounded square on a 1024 canvas with a soft shadow."""
    inset = 100
    box = (inset, inset, CANVAS - inset, CANVAS - inset)
    tile_mask = rounded_mask(CANVAS, box, 186)
    icon = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))

    shadow = Image.new("RGBA", (CANVAS, CANVAS), (40, 30, 120, 0))
    shadow.putalpha(rounded_mask(CANVAS, (box[0], box[1] + 14, box[2], box[3] + 14), 186).point(lambda v: v * 70 // 255))
    icon.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(18)))

    tile = gradient(CANVAS)
    # A restrained sheen on the upper half keeps the tile from looking flat.
    sheen = Image.linear_gradient("L").resize((CANVAS, CANVAS)).point(lambda v: max(0, 40 - v * 40 // 140))
    tile = Image.composite(Image.new("RGBA", (CANVAS, CANVAS), (255, 255, 255, 255)), tile, sheen)
    tile.alpha_composite(placed(mark, CANVAS, 0.47))
    tile.putalpha(tile_mask)
    icon.alpha_composite(tile)
    return icon


def full_bleed_icon(mark: Image.Image) -> Image.Image:
    icon = gradient(CANVAS)
    icon.alpha_composite(placed(mark, CANVAS, 0.58))
    return icon


def monochrome(mark: Image.Image) -> Image.Image:
    layer = Image.new("RGBA", mark.size, (255, 255, 255, 0))
    layer.putalpha(mark.getchannel("A"))
    return layer


def write_assets(source_bytes: bytes, force: bool) -> None:
    targets = {
        ASSETS / "mark.png": None,
        ASSETS / "icon-desktop.png": None,
        ASSETS / "icon.png": None,
        ASSETS / "icon-android-fg.png": None,
        ASSETS / "icon-android-bg.png": None,
        ASSETS / "icon-android-mono.png": None,
        PUBLIC / "brand-mark.svg": None,
    }
    if not force:
        existing = [str(path) for path in targets if path.exists()]
        if existing:
            fail("Icon targets already exist; rerun with --force: " + ", ".join(existing))

    with Image.open(BytesIO(source_bytes)) as raw:
        art = ImageOps.exif_transpose(raw).convert("RGBA")
    # Some providers return the art on transparency instead of the requested white;
    # flatten onto white so one cut-out path handles both.
    backdrop = Image.new("RGBA", art.size, (255, 255, 255, 255))
    backdrop.alpha_composite(art)
    source = ImageOps.fit(backdrop.convert("RGB"), (CANVAS, CANVAS), Image.Resampling.LANCZOS)
    mark = extract_mark(source)
    # Android's adaptive foreground keeps its art inside the central 66% safe zone.
    images = {
        ASSETS / "mark.png": mark,
        ASSETS / "icon-desktop.png": desktop_icon(mark),
        ASSETS / "icon.png": full_bleed_icon(mark),
        ASSETS / "icon-android-fg.png": placed(mark, CANVAS, 0.46),
        ASSETS / "icon-android-bg.png": gradient(CANVAS),
        ASSETS / "icon-android-mono.png": monochrome(placed(mark, CANVAS, 0.46)),
    }
    for path, image in images.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        image.save(path, optimize=True)
        print(f"  wrote {path.relative_to(ROOT)}")

    # Vectors stay crisp at every size and follow the theme / system tint.
    write_svg(mark, PUBLIC / "brand-mark.svg", body="#FFFFFF", accent_rgb=MARK_ACCENT)
    drawables = ANDROID_RES / "drawable"
    if drawables.is_dir():
        write_android_vector(mark, drawables / "ic_tile.xml", "Quick Settings tile icon; the system tints it.")
        write_android_vector(mark, drawables / "ic_stat_billow.xml", "Notification small icon; white silhouette, the system tints it.")
    for path in (PUBLIC / "brand-mark.svg", drawables / "ic_tile.xml", drawables / "ic_stat_billow.xml"):
        if path.exists():
            print(f"  wrote {path.relative_to(ROOT)}")


def main() -> None:
    args = parse_args()
    if args.reuse_source:
        if not SOURCE.is_file():
            fail(f"Source image not found: {SOURCE}")
        print(f"Reusing {SOURCE.relative_to(ROOT)}")
        write_assets(SOURCE.read_bytes(), args.force)
        print("Now run `npm run icons` to derive the native, tray and web icons.")
        return

    name, base_url, token, response_model = load_provider(args.config)
    payload = {
        "model": response_model,
        "input": PROMPT,
        "tools": [{"type": "image_generation", "model": args.model, "action": "generate",
                   "quality": args.quality, "size": "1024x1024"}],
    }
    print(f"Provider: {name} ({base_url})\nResponses model: {response_model}\nImage model: {args.model}")
    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if not args.force and SOURCE.exists():
        fail(f"{SOURCE} exists; rerun with --force to replace it.")

    models = request_json(f"{base_url}/models", token, timeout=60)
    available = {item.get("id") for item in models.get("data", []) if isinstance(item, dict)}
    if args.model not in available:
        fail(f"Provider does not expose {args.model!r}; image models: "
             + ", ".join(sorted(m for m in available if isinstance(m, str) and "image" in m)))

    print("Generating one 1024x1024 source image…", flush=True)
    source_bytes = generated_image(request_json(f"{base_url}/responses", token, payload))
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    SOURCE.write_bytes(source_bytes)
    (ASSETS / "icon-prompt.txt").write_text(f"Model: {args.model}\n\n{PROMPT}\n", encoding="utf-8")
    write_assets(source_bytes, force=True)
    print("Now run `npm run icons` to derive the native, tray and web icons.")


if __name__ == "__main__":
    main()
