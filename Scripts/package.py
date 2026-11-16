#!/usr/bin/env python3
"""Build a local unsigned macOS app bundle; does not install or change user settings."""
import argparse
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import tempfile

project = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=pathlib.Path, default=project / 'dist' / 'SafeClaude.app')
parser.add_argument('--version', default='0.1.0')
parser.add_argument('--build-number', default='1')
parser.add_argument('--bundle-id', default='local.safeclaude.app')
options = parser.parse_args()
output = options.output.absolute()
if not re.fullmatch(r'\d+\.\d+\.\d+', options.version):
    raise SystemExit('version must use MAJOR.MINOR.PATCH')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,63}', options.build_number):
    raise SystemExit('build number contains unsupported characters')
if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', options.bundle_id):
    raise SystemExit('bundle identifier must be reverse-DNS style')
if output.exists():
    raise SystemExit(f'output already exists: {output}')
output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='safe-claude-build-', dir=output.parent) as build_tmp:
    build_tmp = pathlib.Path(build_tmp)
    architecture_bins = {}
    for architecture in ('arm64', 'x86_64'):
        triple = f'{architecture}-apple-macosx13.0'
        subprocess.run(
            ['swift', 'build', '-c', 'release', '--triple', triple],
            cwd=project, check=True,
        )
        architecture_bins[architecture] = pathlib.Path(subprocess.check_output(
            ['swift', 'build', '-c', 'release', '--triple', triple, '--show-bin-path'],
            cwd=project, text=True,
        ).strip())
    bin_dir = architecture_bins['arm64']
    derived_data = build_tmp / 'DNSProxyDerivedData'
    subprocess.run([
        'xcodebuild', '-quiet', '-project', str(project / 'SafeClaudeDNS.xcodeproj'),
        '-scheme', 'SafeClaudeDNS', '-configuration', 'Release',
        '-derivedDataPath', str(derived_data), 'CODE_SIGNING_ALLOWED=NO',
        f'PRODUCT_BUNDLE_IDENTIFIER={options.bundle_id}.dnsproxy',
        f'MARKETING_VERSION={options.version}', f'CURRENT_PROJECT_VERSION={options.build_number}',
        'build',
    ], cwd=project, check=True)
    dns_extension = derived_data / 'Build' / 'Products' / 'Release' / 'SafeClaudeDNS.systemextension'
    if not dns_extension.is_dir():
        raise SystemExit(f'missing DNS system extension product: {dns_extension}')
    with tempfile.TemporaryDirectory(prefix='safe-claude-package-', dir=output.parent) as tmp:
        bundle = pathlib.Path(tmp) / 'SafeClaude.app'
        macos = bundle / 'Contents' / 'MacOS'
        macos.mkdir(parents=True)
        for executable in ('SafeClaudeApp', 'safe-claude', 'safe-claude-agent'):
            subprocess.run([
                'lipo', '-create',
                str(architecture_bins['arm64'] / executable),
                str(architecture_bins['x86_64'] / executable),
                '-output', str(macos / executable),
            ], check=True)
            (macos / executable).chmod(0o755)
        privileged_helpers = bundle / 'Contents' / 'Library' / 'PrivilegedHelperTools'
        privileged_helpers.mkdir(parents=True)
        subprocess.run([
            'lipo', '-create',
            str(architecture_bins['arm64'] / 'safe-claude-time-status'),
            str(architecture_bins['x86_64'] / 'safe-claude-time-status'),
            '-output', str(privileged_helpers / 'safe-claude-time-status'),
        ], check=True)
        (privileged_helpers / 'safe-claude-time-status').chmod(0o755)
        daemon_directory = bundle / 'Contents' / 'Library' / 'LaunchDaemons'
        daemon_directory.mkdir(parents=True)
        shutil.copy2(project / 'Sources' / 'GuardApp' / 'local.safeclaude.time-status.plist',
                     daemon_directory / 'local.safeclaude.time-status.plist')
        resource_bundle = bin_dir / 'SafeClaude_GuardCore.bundle'
        if not resource_bundle.is_dir():
            raise SystemExit(f'missing Swift package resources: {resource_bundle}')
        shutil.copytree(resource_bundle, macos / resource_bundle.name)
        extension_dir = bundle / 'Contents' / 'Library' / 'SystemExtensions'
        extension_dir.mkdir(parents=True)
        shutil.copytree(dns_extension, extension_dir / dns_extension.name)
        installer_resources = bundle / 'Contents' / 'Resources' / 'Installer'
        (installer_resources / 'integration').mkdir(parents=True)
        app_resources = bundle / 'Contents' / 'Resources'
        shutil.copy2(project / 'Resources' / 'AppIcon.icns', app_resources / 'AppIcon.icns')
        shutil.copy2(project / 'Resources' / 'MenuBarMark.png', app_resources / 'MenuBarMark.png')
        setup_runtime = project / 'Resources' / 'Installer' / 'safe-claude-setup'
        if not setup_runtime.is_file() or not os.access(setup_runtime, os.X_OK):
            raise SystemExit(f'missing universal setup runtime: {setup_runtime}')
        shutil.copy2(setup_runtime, installer_resources / 'safe-claude-setup')
        shutil.copy2(project / 'Resources' / 'Installer' / 'LICENSE.python.txt',
                     installer_resources / 'LICENSE.python.txt')
        shutil.copy2(project / 'Resources' / 'Installer' / 'THIRD_PARTY_NOTICES.txt',
                     installer_resources / 'THIRD_PARTY_NOTICES.txt')
        shutil.copy2(project / 'Scripts' / 'setup-integration.py',
                     installer_resources / 'setup-integration.py')
        shutil.copy2(project / 'Scripts' / 'integration' / 'claude',
                     installer_resources / 'integration' / 'claude')
        shutil.copy2(project / 'Scripts' / 'integration' / 'process-wrapper',
                     installer_resources / 'integration' / 'process-wrapper')
        shutil.copy2(project / 'Sources' / 'GuardApp' / 'local.safeclaude.time-status.plist',
                     installer_resources / 'local.safeclaude.time-status.plist')
        info = {'CFBundleName': 'SafeClaude', 'CFBundleDisplayName': 'SafeClaude',
                'CFBundleIdentifier': options.bundle_id, 'CFBundleExecutable': 'SafeClaudeApp',
                'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': options.version,
                'CFBundleVersion': options.build_number, 'LSMinimumSystemVersion': '13.0',
                'CFBundleIconFile': 'AppIcon.icns',
                'LSUIElement': True, 'NSHighResolutionCapable': True}
        with (bundle / 'Contents' / 'Info.plist').open('wb') as stream:
            plistlib.dump(info, stream)
        os.rename(bundle, output)
print(output)
