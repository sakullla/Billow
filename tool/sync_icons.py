"""Derive the tray, web and Android assets after `tauri icon assets/icon-manifest.json`.

The in-app logo (public/brand-mark.png) is written by generate_app_icons.py;
the UI draws the theme-aware tile behind it, so it is not derived here.
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
