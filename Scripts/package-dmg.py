#!/usr/bin/env python3
"""Create a drag-to-Applications macOS disk image from a packaged app."""
import argparse
import pathlib
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("app", type=pathlib.Path)
parser.add_argument("output", type=pathlib.Path)
parser.add_argument("--volume-name", required=True)
args = parser.parse_args()

app = args.app.resolve()
output = args.output.absolute()
if not app.is_dir() or app.suffix != ".app":
    raise SystemExit(f"source must be an .app bundle: {app}")
if output.exists():
    raise SystemExit(f"output already exists: {output}")
if not args.volume_name or "/" in args.volume_name or len(args.volume_name) > 27:
    raise SystemExit("volume name must be 1–27 characters without slashes")
if not shutil.which("hdiutil") or not shutil.which("ditto"):
    raise SystemExit("hdiutil and ditto are required")

output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="safeclaude-dmg-") as temporary:
    staging = pathlib.Path(temporary) / "SafeClaude Installer"
    staging.mkdir()
    staged_app = staging / "SafeClaude.app"
    subprocess.run(["ditto", str(app), str(staged_app)], check=True)
    (staging / "Applications").symlink_to("/Applications", target_is_directory=True)
    shutil.copy2(
        pathlib.Path(__file__).resolve().parents[1] / "Resources" / "Distribution" / "Install.txt",
        staging / "Install.txt",
    )
    subprocess.run([
        "hdiutil", "create", "-ov", "-format", "UDZO",
        "-volname", args.volume_name,
        "-srcfolder", str(staging),
        str(output),
    ], check=True)
print(output)
