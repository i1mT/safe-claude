#!/usr/bin/env python3
"""Frozen entry point for the bundled SafeClaude setup runtime."""
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time


bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
installer = bundle_root / "setup-integration.py"
if not installer.is_file():
    print("safe-claude setup: packaged installer resource is missing", file=sys.stderr)
    raise SystemExit(78)

app_bundle = next(
    (parent for parent in Path(sys.executable).resolve().parents if parent.suffix == ".app"),
    None,
)
if app_bundle is not None and "--source-app" not in sys.argv:
    sys.argv += ["--source-app", str(app_bundle)]

sys.argv[0] = str(installer)
runpy.run_path(str(installer), run_name="__main__")
