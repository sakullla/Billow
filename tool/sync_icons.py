"""Derive the tray, web and Android assets after `tauri icon assets/icon-manifest.json`.

generate_app_icons.py writes the in-app logo to public/brand-mark.svg.
The UI draws the theme-aware tile behind it.
"""
from pathlib import Path
import shutil
from PIL import Image
from build_tray_icon import build_tray_icon

root = Path(__file__).resolve().parents[1]
build_tray_icon(root)
public = root / "public"
public.mkdir(exist_ok=True)
with Image.open(root / "assets/icon-desktop.png") as image:
    image.save(public / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
android = root / "src-tauri/icons/android"
if android.exists():
    shutil.copytree(android, root / "src-tauri/gen/android/app/src/main/res", dirs_exist_ok=True)
# With an initialized Android project, Tauri writes directly to its res folder.
assert (root / "src-tauri/gen/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png").exists()
