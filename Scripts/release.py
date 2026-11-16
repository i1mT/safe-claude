#!/usr/bin/env python3
"""Build, sign, notarize, staple, and publish a SafeClaude macOS release."""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

project = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output-dir", type=pathlib.Path, default=project / "dist" / "release")
parser.add_argument("--version", required=True)
parser.add_argument("--build-number", required=True)
parser.add_argument("--bundle-id", default="com.safeclaude.app")
parser.add_argument("--identity", required=True, help="Developer ID Application certificate name")
parser.add_argument("--notary-profile", required=True, help="notarytool keychain profile")
args = parser.parse_args()
if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
    raise SystemExit("version must use MAJOR.MINOR.PATCH")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}", args.build_number):
    raise SystemExit("build number contains unsupported characters")
if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", args.bundle_id):
    raise SystemExit("bundle identifier must be reverse-DNS style")


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


for tool in ("swift", "codesign", "ditto", "hdiutil", "xcrun", "spctl", "security"):
    if not shutil.which(tool):
        raise SystemExit(f"required Apple tool not found: {tool}")
identities = subprocess.check_output(
    ["security", "find-identity", "-v", "-p", "codesigning"], text=True
)
if args.identity not in identities or "Developer ID Application" not in args.identity:
    raise SystemExit("matching Developer ID Application signing identity is unavailable")
try:
    run(["xcrun", "notarytool", "history", "--keychain-profile", args.notary_profile],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except subprocess.CalledProcessError:
    raise SystemExit("notarytool profile is unavailable or invalid")

out = args.output_dir.resolve()
out.mkdir(parents=True, exist_ok=True)
app_name = f"SafeClaude-{args.version}.app"
app_final = out / app_name
zip_final = out / f"SafeClaude-{args.version}.zip"
dmg_final = out / f"SafeClaude-{args.version}.dmg"
manifest_final = out / f"SafeClaude-{args.version}.sha256.json"
if any(path.exists() for path in (app_final, zip_final, dmg_final, manifest_final)):
    raise SystemExit("release output already exists; choose a clean output directory")

with tempfile.TemporaryDirectory(prefix="safeclaude-release-", dir=out) as temp:
    temp_path = pathlib.Path(temp)
    app = temp_path / app_name
    run([sys.executable, str(project / "Scripts/package.py"), "--output", str(app),
         "--version", args.version, "--build-number", args.build_number,
         "--bundle-id", args.bundle_id])
    run([sys.executable, str(project / "Scripts/validate-app-bundle.py"), str(app),
         "--version", args.version, "--build-number", args.build_number,
         "--bundle-id", args.bundle_id])
    contents = app / "Contents"
    macos = contents / "MacOS"
    sign_options = ["--force", "--options", "runtime", "--timestamp", "--sign", args.identity]
    nested = [macos / "SafeClaude_GuardCore.bundle",
              contents / "Library" / "PrivilegedHelperTools" / "safe-claude-time-status"]
    nested.append(contents / "Resources" / "Installer" / "safe-claude-setup")
    nested += [macos / name for name in ("safe-claude-agent", "safe-claude", "SafeClaudeApp")]
    extension_dir = contents / "Library" / "SystemExtensions"
    extensions = sorted(extension_dir.glob("*.systemextension"))
    if len(extensions) != 1:
        raise SystemExit(f"expected one DNS system extension to sign, found {len(extensions)}")
    dns_extension = extensions[0]
    extension_resources = dns_extension / "Contents" / "Resources" / "SafeClaude_GuardCore.bundle"
    run(["codesign", *sign_options, str(extension_resources)])
    run(["codesign", *sign_options, "--entitlements",
         str(project / "Sources" / "SafeClaudeDNS" / "SafeClaudeDNS.entitlements"),
         str(dns_extension)])
    run(["codesign", *sign_options, "--entitlements",
         str(project / "Sources" / "GuardAgent" / "SafeClaudeAgent.entitlements"),
         str(macos / "safe-claude-agent")])
    for item in nested:
        if item == macos / "safe-claude-agent":
            continue
        run(["codesign", *sign_options, str(item)])
    run(["codesign", *sign_options, "--entitlements",
         str(project / "Sources" / "GuardApp" / "SafeClaudeApp.entitlements"), str(app)])
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
    run(["spctl", "--assess", "--type", "execute", "--verbose=2", str(app)])
    archive = temp_path / zip_final.name
    run(["ditto", "-c", "-k", "--keepParent", str(app), str(archive)])
    submission = subprocess.check_output(
        ["xcrun", "notarytool", "submit", str(archive), "--keychain-profile",
         args.notary_profile, "--wait", "--output-format", "json"], text=True
    )
    result = json.loads(submission)
    if result.get("status") != "Accepted":
        raise SystemExit(f"notarization was not accepted: {result.get('status', 'unknown')}")
    run(["xcrun", "stapler", "staple", str(app)])
    run(["xcrun", "stapler", "validate", str(app)])
    run(["spctl", "--assess", "--type", "execute", "--verbose=2", str(app)])
    archive.unlink()
    run(["ditto", "-c", "-k", "--keepParent", str(app), str(archive)])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    dmg = temp_path / dmg_final.name
    run([
        sys.executable, str(project / "Scripts" / "package-dmg.py"),
        str(app), str(dmg), "--volume-name", "SafeClaude",
    ])
    run(["codesign", "--force", "--timestamp", "--sign", args.identity, str(dmg)])
    run(["codesign", "--verify", "--strict", "--verbose=2", str(dmg)])
    dmg_submission = subprocess.check_output(
        ["xcrun", "notarytool", "submit", str(dmg), "--keychain-profile",
         args.notary_profile, "--wait", "--output-format", "json"], text=True
    )
    dmg_result = json.loads(dmg_submission)
    if dmg_result.get("status") != "Accepted":
        raise SystemExit(f"DMG notarization was not accepted: {dmg_result.get('status', 'unknown')}")
    run(["xcrun", "stapler", "staple", str(dmg)])
    run(["xcrun", "stapler", "validate", str(dmg)])
    run(["spctl", "--assess", "--type", "open", "--context", "context:primary-signature",
         "--verbose=2", str(dmg)])
    run([sys.executable, str(project / "Scripts" / "validate-dmg.py"), str(dmg),
         "--version", args.version, "--build-number", args.build_number,
         "--bundle-id", args.bundle_id])
    dmg_digest = hashlib.sha256(dmg.read_bytes()).hexdigest()

    shutil.copytree(app, temp_path / "published-app")
    shutil.copy2(archive, temp_path / "published.zip")
    shutil.copy2(dmg, temp_path / "published.dmg")
    manifest = {
        "product": "SafeClaude", "version": args.version, "buildNumber": args.build_number,
        "bundleIdentifier": args.bundle_id,
        "notarization": "Accepted",
        "artifacts": [
            {"type": "zip", "file": zip_final.name, "sha256": digest},
            {"type": "dmg", "file": dmg_final.name, "sha256": dmg_digest},
        ],
    }
    manifest_path = temp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (temp_path / "published-app").rename(app_final)
    (temp_path / "published.zip").replace(zip_final)
    (temp_path / "published.dmg").replace(dmg_final)
    manifest_path.replace(manifest_final)
print(f"Release artifacts created in {out}")
