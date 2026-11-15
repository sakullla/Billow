#!/usr/bin/env python3
"""Create persistent Billow signing keys outside Git and upload them with gh.

Requires npm dependencies, gh authentication, and JAVA_HOME (JDK 17+).
The private files must be backed up: replacing them breaks existing updates.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
KEYS = Path.home() / ".codex/keys/billow"
REPO = "sakullla/Billow"


def run(args, **kwargs):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, **kwargs)
    if result.returncode:
        # Tool diagnostics can include signing material, so do not echo them.
        raise SystemExit(f"{Path(args[0]).name} failed (exit {result.returncode}); no credentials printed.")
    return result.stdout


def main():
    existing = json.loads(run(["gh", "secret", "list", "-R", REPO, "--json", "name"]))
    if any(item["name"] == "TAURI_SIGNING_PRIVATE_KEY" for item in existing) and not (KEYS / "updater.key").exists():
        raise SystemExit("Remote updater key already exists. Restore its local backup; do not rotate it.")
    KEYS.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        user = run(["whoami"]).decode().strip()
        run(["icacls", str(KEYS), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F", "SYSTEM:(OI)(CI)F"])
    else:
        KEYS.chmod(0o700)
    passwords = KEYS / "passwords.json"
    if not passwords.exists():
        passwords.write_text(json.dumps({"updater": secrets.token_urlsafe(32), "android": secrets.token_urlsafe(32)}))
        if os.name != "nt":
            passwords.chmod(0o600)
    credentials = json.loads(passwords.read_text())
    private_key = KEYS / "updater.key"
    if not private_key.exists():
        run(["node", "node_modules/@tauri-apps/cli/tauri.js", "signer", "generate", "--ci",
             "--password", credentials["updater"], "--write-keys", str(private_key)])
    android_key = KEYS / "android.p12"
    if not android_key.exists():
        java = Path(os.environ["JAVA_HOME"]) / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        env = {**os.environ, "BILLOW_KEY_PASSWORD": credentials["android"]}
        run([str(java), "-genkeypair", "-keystore", str(android_key), "-storetype", "PKCS12",
             "-alias", "billow", "-keyalg", "RSA", "-keysize", "3072", "-validity", "10000",
             "-dname", "CN=Billow, OU=Release, O=Billow", "-storepass:env", "BILLOW_KEY_PASSWORD",
             "-keypass:env", "BILLOW_KEY_PASSWORD"], env=env)
    values = {
        "TAURI_SIGNING_PRIVATE_KEY": private_key.read_text().strip(),
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD": credentials["updater"],
        "ANDROID_KEY_BASE64": base64.b64encode(android_key.read_bytes()).decode(),
        "ANDROID_KEY_ALIAS": "billow",
        "ANDROID_KEY_PASSWORD": credentials["android"],
    }
    for name, value in values.items():
        run(["gh", "secret", "set", name, "-R", REPO], input=value.encode())
        print(f"Configured {name}", flush=True)
    config_path = ROOT / "src-tauri/tauri.conf.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["plugins"]["updater"] = {
        "pubkey": private_key.with_suffix(".key.pub").read_text().strip(),
        "endpoints": [f"https://github.com/{REPO}/releases/latest/download/latest.json"],
        "windows": {"installMode": "passive"},
    }
    config["bundle"]["createUpdaterArtifacts"] = True
    config["bundle"]["macOS"]["signingIdentity"] = "-"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Private backup: {KEYS}. Public verification key written to tauri.conf.json.")


if __name__ == "__main__":
    main()
