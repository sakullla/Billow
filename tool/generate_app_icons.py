#!/usr/bin/env python3
"""Generate Billow artwork with the provider workflow used by Rillight.

Python 3.11+ and Pillow are required. Credentials stay in local Codex config.
Run `python tool/generate_app_icons.py --force`, then `npm run icons`.
Use --reuse-source to rebuild the icon offline without another generation.
"""
from __future__ import annotations

import argparse
import base64
from io import BytesIO
import json
import os
from pathlib import Path
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = "gpt-image-2.6"
PROMPT = """Use case: logo-brand
Asset type: finished mobile launcher icon for Billow, a network client.
Primary request: a single elegant white ocean swell symbol, a smooth rounded crest curling inward around one open navy teardrop of negative space. A compact sculptural silhouette with a short tapering tail and a small soft cyan accent on its lower edge. One unified recognizable mark, not parallel stripes.
Style: premium minimal flat icon, beautifully balanced curves, precise clean edges, readable at 32 pixels. Subtle blue tonal depth only in the background, no material texture.
Composition: square 1024x1024. Deep midnight-blue background #102c52 reaches all four edges. The whole white wave symbol fits within the central 54 percent of the canvas, generous clear navy space surrounding it on every side. The operating system will crop the square into a rounded square or circle; do NOT draw a rounded square or circular container into the image.
Constraints: no text, no letters, no watermark, no border, no drop shadows, no ocean scenery, no multiple horizontal ribbons, no stripes that run off the edges, no shield, no lock, no globe, no shiny 3D bevel, no busy detail.
Output: exactly one finished square icon, no layout or mockup."""


def request(url, token, payload=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = json.dumps(payload).encode() if payload is not None else None
    try:
        with urlopen(Request(url, data=body, headers=headers), timeout=300) as response:
            return json.load(response)
    except HTTPError as error:
        # Never echo a provider response that could contain request credentials.
        raise SystemExit(f"Image provider returned HTTP {error.code}") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--reuse-source", action="store_true")
    parser.add_argument("--config", type=Path, default=Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "config.toml")
    args = parser.parse_args()
    source = ROOT / "assets/icon-source.png"
    target = ROOT / "assets/icon.png"
    if not args.force and (source.exists() or target.exists()):
        raise SystemExit("Icons already exist; use --force to replace them.")
    if args.reuse_source:
        data = source.read_bytes()
    else:
        config = tomllib.loads(args.config.read_text(encoding="utf-8"))
        provider = config["model_providers"][config["model_provider"]]
        url = provider["base_url"].rstrip("/")
        token = provider.get("experimental_bearer_token") or os.environ.get(provider.get("env_key", "OPENAI_API_KEY"))
        if not token:
            raise SystemExit("Configure the selected provider credential locally first.")
        models = request(f"{url}/models", token)
        if args.model not in {item.get("id") for item in models.get("data", [])}:
            raise SystemExit(f"The selected provider does not expose {args.model}.")
        print(f"Generating Billow icon with {args.model}...", flush=True)
        response = request(f"{url}/responses", token, {
            "model": config["model"], "input": PROMPT,
            "tools": [{"type": "image_generation", "model": args.model,
                       "action": "generate", "quality": "high"}],
        })
        results = [item.get("result") for item in response.get("output", [])
                   if item.get("type") == "image_generation_call" and item.get("result")]
        if not results:
            raise SystemExit("Provider returned no completed image generation.")
        encoded = results[0]
        data = base64.b64decode(encoded.split(",", 1)[1] if encoded.startswith("data:") else encoded, validate=True)
    with Image.open(BytesIO(data)) as raw:
        icon = ImageOps.fit(ImageOps.exif_transpose(raw).convert("RGBA"), (1024, 1024), Image.Resampling.LANCZOS)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(data)
    icon.save(target, optimize=True)
    (ROOT / "assets/icon-prompt.txt").write_text(f"Model: {args.model}\n\n{PROMPT}\n", encoding="utf-8")
    print(f"Saved {target}; run npm run icons to derive native and web assets.")


if __name__ == "__main__":
    main()
