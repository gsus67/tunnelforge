#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "conectar-gateway"


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_version_from_go() -> str:
    text = (APP / "main.go").read_text(encoding="utf-8")
    m = re.search(r'^const\s+version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        fail("no pude leer const version de main.go")
    return m.group(1)


version = read_version_from_go()
wails = json.loads((APP / "wails.json").read_text(encoding="utf-8"))
package = json.loads((APP / "frontend" / "package.json").read_text(encoding="utf-8"))
manifest = (APP / "build" / "windows" / "wails.exe.manifest").read_text(encoding="utf-8")
app_manifest = (APP / "app.manifest").read_text(encoding="utf-8")
version_info = json.loads((APP / "versioninfo.json").read_text(encoding="utf-8"))
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

checks = {
    "wails.json productVersion": str(wails.get("info", {}).get("productVersion", "")),
    "frontend/package.json version": str(package.get("version", "")),
    "versioninfo FileVersion": str(version_info.get("StringFileInfo", {}).get("FileVersion", "")),
    "versioninfo ProductVersion": str(version_info.get("StringFileInfo", {}).get("ProductVersion", "")),
}
for label, found in checks.items():
    if found != version:
        fail(f"{label}={found!r}, pero main.go={version!r}")

m = re.search(r'<assemblyIdentity\s+version="([0-9]+\.[0-9]+\.[0-9]+)\.0"', manifest)
if not m or m.group(1) != version:
    fail("wails.exe.manifest no coincide con la versión de main.go")

m = re.search(r'<assemblyIdentity\s+version="([0-9]+\.[0-9]+\.[0-9]+)\.0"', app_manifest)
if not m or m.group(1) != version:
    fail("app.manifest no coincide con la versión de main.go")

parts = [int(part) for part in version.split(".")]
for label in ("FileVersion", "ProductVersion"):
    numeric = version_info.get("FixedFileInfo", {}).get(label, {})
    found = [numeric.get("Major"), numeric.get("Minor"), numeric.get("Patch")]
    if found != parts:
        fail(f"versioninfo {label} numérica={found!r}, pero main.go={version!r}")

m = re.search(r'^##\s+v([^\s]+)', changelog, re.M)
if not m or m.group(1) != version:
    fail("la primera entrada de CHANGELOG.md no coincide con la versión de main.go")

tag = os.environ.get("GITHUB_REF_NAME", "")
if tag.startswith("v") and tag[1:] != version:
    fail(f"tag={tag!r}, pero app=v{version}")

print(f"Versiones coherentes: v{version}")
