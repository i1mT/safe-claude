#!/usr/bin/env python3
"""Build and validate SafeClaude's standalone universal2 setup executable."""
import argparse
import os
import pathlib
import re
import subprocess
import tempfile

PROJECT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--python", type=pathlib.Path, required=True,
                    help="Python 3.14 interpreter with PyInstaller 6.22.3 installed")
parser.add_argument("--output", type=pathlib.Path,
                    default=PROJECT / "Resources/Installer/safe-claude-setup")
args = parser.parse_args()
python = args.python.absolute()
if not python.is_file() or not os.access(python, os.X_OK):
    raise SystemExit(f"Python interpreter is not executable: {python}")

version = subprocess.check_output([str(python), "--version"], text=True).strip()
if version != "Python 3.14.10":
    raise SystemExit(f"expected the pinned universal runtime, got {version}")
pyinstaller = subprocess.check_output(
    [str(python), "-m", "PyInstaller", "--version"], text=True
).strip()
if pyinstaller != "6.22.3":
    raise SystemExit(f"expected PyInstaller 6.22.3, got {pyinstaller}")

output = args.output.resolve()
output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="safeclaude-setup-runtime-") as temporary:
    temporary = pathlib.Path(temporary)
    dist = temporary / "dist"
    subprocess.run([
        str(python), "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--target-arch", "universal2", "--name", "safe-claude-setup",
        "--distpath", str(dist), "--workpath", str(temporary / "build"),
        "--specpath", str(temporary / "spec"),
        "--add-data", f"{PROJECT / 'Scripts/setup-integration.py'}:.",
        "--add-data", f"{PROJECT / 'Scripts/integration'}:integration",
        "--add-data",
        f"{PROJECT / 'Sources/GuardApp/local.safeclaude.time-status.plist'}:.",
        str(PROJECT / "Scripts/setup-integration-entry.py"),
    ], cwd=PROJECT, check=True)
    candidate = dist / "safe-claude-setup"
    architectures = subprocess.check_output(
        ["lipo", "-archs", str(candidate)], text=True
    ).split()
    if not {"arm64", "x86_64"} <= set(architectures):
        raise SystemExit(f"setup runtime is not universal2: {architectures}")
    for arch in ("arm64", "x86_64"):
        build = subprocess.check_output(
            ["vtool", "-show-build", "-arch", arch, str(candidate)], text=True
        )
        match = re.search(r"^\s*minos\s+(\d+)\.(\d+)", build, re.M)
        if not match:
            match = re.search(
                r"LC_VERSION_MIN_MACOSX[\s\S]*?^\s*version\s+(\d+)\.(\d+)",
                build, re.M,
            )
        if not match or tuple(map(int, match.groups())) > (13, 0):
            raise SystemExit(f"{arch} setup runtime is incompatible with macOS 13")
    subprocess.run([str(candidate), "--help"], check=True,
                   stdout=subprocess.DEVNULL)
    staged = output.with_name(f".{output.name}.staged")
    try:
        staged.write_bytes(candidate.read_bytes())
        staged.chmod(0o755)
        staged.replace(output)
    finally:
        staged.unlink(missing_ok=True)
print(f"Universal2 setup runtime created: {output}")
