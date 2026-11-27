"""Derive the macOS monochrome menu-bar template from Billow's mark."""
from pathlib import Path

from PIL import Image


def build_tray_icon(root: Path) -> None:
    # assets/mark.png is the transparent cut-out written by generate_app_icons.py;
    # its alpha is exactly the silhouette a template image needs.
    with Image.open(root / "assets/mark.png") as source:
        mask = source.convert("RGBA").getchannel("A")
        bounds = mask.getbbox()
        if bounds is None:
            raise ValueError("The app mark has no visible foreground")
        mask = mask.crop(bounds)
        mask.thumbnail((36, 36), Image.Resampling.LANCZOS)
        template = Image.new("RGBA", (44, 44))
        silhouette = Image.new("RGBA", mask.size)
        silhouette.putalpha(mask)
        template.paste(silhouette, ((44 - mask.width) // 2, (44 - mask.height) // 2))
        template.save(root / "src-tauri/icons/tray-template.png")


if __name__ == "__main__":
    build_tray_icon(Path(__file__).resolve().parents[1])
