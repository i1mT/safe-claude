#!/usr/bin/env python3
"""Mount a SafeClaude disk image read-only and validate its install contents."""
import argparse
import os
import pathlib
import plistlib
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("dmg", type=pathlib.Path)
parser.add_argument("--version", required=True)
parser.add_argument("--build-number", required=True)
parser.add_argument("--bundle-id", default="local.safeclaude.app")
args = parser.parse_args()

dmg = args.dmg.resolve()
if not dmg.is_file() or dmg.suffix.lower() != ".dmg":
    raise SystemExit(f"not a disk image: {dmg}")
with tempfile.TemporaryDirectory(prefix="safeclaude-dmg-mount-") as temporary:
    mountpoint = pathlib.Path(temporary) / "mount"
    mountpoint.mkdir()
    attached = False
    try:
        subprocess.run([
            "hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint",
            str(mountpoint), str(dmg),
        ], check=True, text=True, capture_output=True)
        attached = True
        app = mountpoint / "SafeClaude.app"
        applications = mountpoint / "Applications"
        install_instructions = mountpoint / "Install.txt"
        expected_entries = {"SafeClaude.app", "Applications", "Install.txt"}
        actual_entries = {entry.name for entry in mountpoint.iterdir()}
        if actual_entries != expected_entries:
            raise SystemExit(f"disk image root entries mismatch: {sorted(actual_entries)}")
        if app.is_symlink() or not app.is_dir():
            raise SystemExit("disk image is missing SafeClaude.app")
        if not applications.is_symlink() or os.readlink(applications) != "/Applications":
            raise SystemExit("disk image Applications link must point to /Applications")
        if not install_instructions.is_file():
            raise SystemExit("disk image is missing Install.txt")
        info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
        if info.get("CFBundleShortVersionString") != args.version:
            raise SystemExit("disk image app version does not match")
        if info.get("CFBundleVersion") != args.build_number:
            raise SystemExit("disk image app build number does not match")
        if info.get("CFBundleIdentifier") != args.bundle_id:
            raise SystemExit("disk image app bundle identifier does not match")
        subprocess.run([
            sys.executable, str(pathlib.Path(__file__).resolve().parent / "validate-app-bundle.py"),
            str(app), "--version", args.version, "--build-number", args.build_number,
            "--bundle-id", args.bundle_id,
        ], check=True)
    finally:
        if attached:
            subprocess.run(["hdiutil", "detach", str(mountpoint), "-quiet"], check=True)
print(f"Valid SafeClaude disk image: {dmg}")
