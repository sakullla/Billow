"""Derive the macOS monochrome menu-bar template from Billow's app logo."""
from pathlib import Path

from PIL import Image, ImageChops


def build_tray_icon(root: Path) -> None:
    with Image.open(root / "assets/icon.png") as source:
        source = source.convert("RGBA")
        # The white crest and cyan edge are both bright in green; the navy
        # background is dark. Keep their shared silhouette and soft edge.
        mask = source.getchannel("G").point(lambda value: max(0, min(255, (value - 70) * 255 // 160)))
        mask = ImageChops.multiply(mask, source.getchannel("A"))
        bounds = mask.getbbox()
        if bounds is None:
            raise ValueError("The app logo has no visible foreground")
        mask = mask.crop(bounds)
        mask.thumbnail((36, 36), Image.Resampling.LANCZOS)
        template = Image.new("RGBA", (44, 44))
        silhouette = Image.new("RGBA", mask.size)
        silhouette.putalpha(mask)
        template.paste(silhouette, ((44 - mask.width) // 2, (44 - mask.height) // 2))
        template.save(root / "src-tauri/icons/tray-template.png")


if __name__ == "__main__":
    build_tray_icon(Path(__file__).resolve().parents[1])
