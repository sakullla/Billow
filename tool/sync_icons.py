"""Derive the web and Android assets after `tauri icon assets/icon-manifest.json`."""
from pathlib import Path
import shutil
from PIL import Image
from build_tray_icon import build_tray_icon

root = Path(__file__).resolve().parents[1]
build_tray_icon(root)
public = root / "public"
public.mkdir(exist_ok=True)
with Image.open(root / "assets/icon.png") as image:
    image.resize((128, 128), Image.Resampling.LANCZOS).save(public / "icon.png")
desktop_icon = root / "assets/icon-desktop.png"
with Image.open(desktop_icon if desktop_icon.exists() else root / "assets/icon.png") as image:
    image.save(public / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
android = root / "src-tauri/icons/android"
if android.exists():
    shutil.copytree(android, root / "src-tauri/gen/android/app/src/main/res", dirs_exist_ok=True)
# With an initialized Android project, Tauri writes directly to its res folder.
assert (root / "src-tauri/gen/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png").exists()
