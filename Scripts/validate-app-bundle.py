#!/usr/bin/env python3
"""Validate the structure and metadata of a packaged SafeClaude macOS app."""
import argparse
import pathlib
import plistlib
import re
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("app", type=pathlib.Path)
parser.add_argument("--version")
parser.add_argument("--build-number")
parser.add_argument("--bundle-id")
parser.add_argument("--require-signed", action="store_true")
args = parser.parse_args()

app = args.app.resolve()
errors = []


def validate_universal_macos_binary(path, label):
    architectures = subprocess.run(
        ["lipo", "-archs", str(path)], text=True, capture_output=True
    )
    required = {"arm64", "x86_64"}
    if architectures.returncode or not required <= set(architectures.stdout.split()):
        errors.append(f"{label} must contain arm64 and x86_64 architectures")
        return
    for arch in sorted(required):
        build = subprocess.run(
            ["vtool", "-show-build", "-arch", arch, str(path)],
            text=True, capture_output=True,
        )
        match = re.search(r"^\s*minos\s+(\d+)\.(\d+)", build.stdout, re.M)
        if build.returncode or not match:
            errors.append(f"cannot inspect {arch} deployment target for {label}")
        elif tuple(map(int, match.groups())) > (13, 0):
            errors.append(
                f"{label} {arch} slice requires macOS {match.group(1)}.{match.group(2)}; maximum is 13.0"
            )


if not app.is_dir() or app.suffix != ".app":
    errors.append(f"not an .app directory: {app}")
else:
    plist_path = app / "Contents" / "Info.plist"
    try:
        with plist_path.open("rb") as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        info = {}
        errors.append(f"cannot read Info.plist: {error}")
    expected = {
        "CFBundlePackageType": "APPL",
        "CFBundleExecutable": "SafeClaudeApp",
    }
    if args.version:
        expected["CFBundleShortVersionString"] = args.version
    if args.build_number:
        expected["CFBundleVersion"] = args.build_number
    if args.bundle_id:
        expected["CFBundleIdentifier"] = args.bundle_id
    for key, value in expected.items():
        if info.get(key) != value:
            errors.append(f"{key}: expected {value!r}, got {info.get(key)!r}")
    contents = app / "Contents"
    app_icon = contents / "Resources" / "AppIcon.icns"
    menu_mark = contents / "Resources" / "MenuBarMark.png"
    if info.get("CFBundleIconFile") != "AppIcon.icns" or not app_icon.is_file():
        errors.append("missing or unregistered AppIcon.icns")
    elif sys.platform == "darwin":
        icon_sizes = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", str(app_icon)],
                                    text=True, capture_output=True)
        if icon_sizes.returncode or "1024" not in icon_sizes.stdout:
            errors.append("AppIcon.icns must contain a 512px @2x icon representation")
    if not menu_mark.is_file():
        errors.append("missing template menu bar mark")
    elif sys.platform == "darwin":
        mark_info = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", str(menu_mark)],
                                   text=True, capture_output=True)
        if mark_info.returncode or "36" not in mark_info.stdout:
            errors.append("menu bar mark must be a 36px PNG")
    macos = contents / "MacOS"
    for name in ("SafeClaudeApp", "safe-claude", "safe-claude-agent"):
        path = macos / name
        if not path.is_file():
            errors.append(f"missing executable: {path}")
        elif not path.stat().st_mode & 0o111:
            errors.append(f"not executable: {path}")
        elif sys.platform == "darwin":
            validate_universal_macos_binary(path, name)
    resources = macos / "SafeClaude_GuardCore.bundle"
    if not resources.is_dir():
        errors.append(f"missing SwiftPM resource bundle: {resources}")
    elif not (resources / "claude-model-lifecycle.json").is_file():
        errors.append(f"missing required model lifecycle resource: {resources / 'claude-model-lifecycle.json'}")
    else:
        try:
            import json
            with (resources / "claude-model-lifecycle.json").open(encoding="utf-8") as stream:
                lifecycle = json.load(stream)
            if not isinstance(lifecycle, dict) or not lifecycle:
                errors.append("model lifecycle resource must be a non-empty JSON object")
        except (OSError, ValueError) as error:
            errors.append(f"invalid model lifecycle resource: {error}")
    installer = contents / "Resources" / "Installer"
    setup_runtime = installer / "safe-claude-setup"
    if not setup_runtime.is_file() or not setup_runtime.stat().st_mode & 0o111:
        errors.append(f"missing executable bundled setup runtime: {setup_runtime}")
    elif sys.platform == "darwin":
        architectures = subprocess.run(
            ["lipo", "-archs", str(setup_runtime)], text=True, capture_output=True
        )
        supported = {"arm64", "x86_64"}
        if architectures.returncode or not supported <= set(architectures.stdout.split()):
            errors.append("bundled setup runtime must contain arm64 and x86_64 architectures")
        else:
            for arch in ("arm64", "x86_64"):
                build = subprocess.run(
                    ["vtool", "-show-build", "-arch", arch, str(setup_runtime)],
                    text=True, capture_output=True,
                )
                match = re.search(r"^\s*minos\s+(\d+)\.(\d+)", build.stdout, re.M)
                if not match:
                    match = re.search(
                        r"LC_VERSION_MIN_MACOSX[\s\S]*?^\s*version\s+(\d+)\.(\d+)",
                        build.stdout, re.M,
                    )
                if build.returncode or not match:
                    errors.append(f"cannot inspect {arch} setup runtime minimum OS version")
                elif tuple(map(int, match.groups())) > (13, 0):
                    errors.append(f"{arch} setup runtime requires macOS {match.group(1)}.{match.group(2)}")
    for relative in (
        "setup-integration.py",
        "safe-claude-setup",
        "LICENSE.python.txt",
        "THIRD_PARTY_NOTICES.txt",
        "integration/claude",
        "integration/process-wrapper",
        "local.safeclaude.time-status.plist",
    ):
        if not (installer / relative).is_file():
            errors.append(f"missing packaged installer resource: {installer / relative}")
    helper = contents / "Library" / "PrivilegedHelperTools" / "safe-claude-time-status"
    if not helper.is_file() or not helper.stat().st_mode & 0o111:
        errors.append(f"missing executable privileged time-status helper: {helper}")
    elif sys.platform == "darwin":
        validate_universal_macos_binary(helper, "privileged time-status helper")
    daemon_plist = contents / "Library" / "LaunchDaemons" / "local.safeclaude.time-status.plist"
    try:
        with daemon_plist.open("rb") as stream:
            daemon = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        daemon = {}
        errors.append(f"cannot read time-status LaunchDaemon plist: {error}")
    if daemon.get("Label") != "local.safeclaude.time-status":
        errors.append("time-status LaunchDaemon has an unexpected label")
    if daemon.get("BundleProgram") != "Contents/Library/PrivilegedHelperTools/safe-claude-time-status":
        errors.append("time-status LaunchDaemon BundleProgram does not match the bundled helper")
    expected_mach_services = {"local.safeclaude.time-status": True}
    if daemon.get("RunAtLoad") is not True or daemon.get("KeepAlive") is not True:
        errors.append("time-status LaunchDaemon must start at load and recover after failure")
    if daemon.get("MachServices") != expected_mach_services:
        errors.append("time-status LaunchDaemon must expose its scoped XPC cleanup service")
    if "StartInterval" in daemon:
        errors.append("time-status LaunchDaemon must manage its own sampling interval")
    extensions = contents / "Library" / "SystemExtensions"
    dns_extensions = sorted(extensions.glob("*.systemextension")) if extensions.is_dir() else []
    if len(dns_extensions) != 1:
        errors.append(f"expected one embedded DNS system extension, found {len(dns_extensions)}")
    else:
        extension = dns_extensions[0]
        extension_info_path = extension / "Contents" / "Info.plist"
        try:
            with extension_info_path.open("rb") as stream:
                extension_info = plistlib.load(stream)
        except (OSError, plistlib.InvalidFileException, ValueError) as error:
            extension_info = {}
            errors.append(f"cannot read DNS extension Info.plist: {error}")
        expected_extension = {
            "CFBundleIdentifier": f"{info.get('CFBundleIdentifier', '')}.dnsproxy",
            "CFBundlePackageType": "SYSX",
            "CFBundleExecutable": "SafeClaudeDNS",
            "MinimumOSVersion": "15.0",
        }
        for key, value in expected_extension.items():
            if extension_info.get(key) != value:
                errors.append(f"DNS extension {key}: expected {value!r}, got {extension_info.get(key)!r}")
        extension_point = extension_info.get("NSExtension", {})
        if extension_point.get("NSExtensionPointIdentifier") != "com.apple.networkextension.dns-proxy":
            errors.append("DNS extension has an unexpected extension point")
        if extension_point.get("NSExtensionPrincipalClass") != "SafeClaudeDNS.DNSProxyProvider":
            errors.append("DNS extension principal provider class is missing")
        extension_executable = extension / "Contents" / "MacOS" / "SafeClaudeDNS"
        if not extension_executable.is_file() or not extension_executable.stat().st_mode & 0o111:
            errors.append(f"missing executable DNS extension: {extension_executable}")
        extension_resources = extension / "Contents" / "Resources" / "SafeClaude_GuardCore.bundle"
        if not extension_resources.is_dir():
            errors.append(f"missing DNS extension resources: {extension_resources}")
    if args.require_signed:
        result = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)],
            text=True, capture_output=True,
        )
        if result.returncode:
            errors.append("signature verification failed: " + (result.stderr.strip() or result.stdout.strip()))
        signed_components = [
            ("time-status helper", helper),
            ("DNS system extension", dns_extensions[0]) if len(dns_extensions) == 1 else None,
            ("setup runtime", setup_runtime),
        ]
        for label, path in (item for item in signed_components if item is not None):
            component_result = subprocess.run(
                ["codesign", "--verify", "--strict", "--verbose=2", str(path)],
                text=True, capture_output=True,
            )
            if component_result.returncode:
                errors.append(f"{label} signature verification failed: " +
                              (component_result.stderr.strip() or component_result.stdout.strip()))

if errors:
    print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
    raise SystemExit(1)
print(f"Valid SafeClaude app bundle: {app}")
