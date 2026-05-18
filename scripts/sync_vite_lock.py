#!/usr/bin/env python3
"""Bump Vite (and transitive Rolldown + native bindings) in package-lock.json from registry metadata."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def npm_meta(pkg: str, ver: str) -> dict:
    url = f"https://registry.npmjs.org/{quote_pkg(pkg)}/{ver}"
    raw = subprocess.check_output(["curl", "-sfL", url], text=True)
    return json.loads(raw)


def quote_pkg(pkg: str) -> str:
    """Path segment for scoped packages (e.g. @scope/name)."""
    return pkg.replace("/", "%2f")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    lock_path = root / "frontend" / "package-lock.json"
    data = json.loads(lock_path.read_text())
    pkgs = data.setdefault("packages", {})

    vite_ver = "8.0.13"
    vmeta = npm_meta("vite", vite_ver)

    pkgs[""]["devDependencies"]["vite"] = f"^{vite_ver}"
    vite_pkg = pkgs["node_modules/vite"]
    vite_pkg["version"] = vite_ver
    vite_pkg["resolved"] = vmeta["dist"]["tarball"]
    vite_pkg["integrity"] = vmeta["dist"]["integrity"]
    vite_pkg.setdefault("dependencies", {}).update(vmeta.get("dependencies", {}))

    rd_ver = vmeta["dependencies"]["rolldown"]
    rmeta = npm_meta("rolldown", rd_ver)
    rd_pkg = pkgs["node_modules/rolldown"]
    rd_pkg["version"] = rd_ver
    rd_pkg["resolved"] = rmeta["dist"]["tarball"]
    rd_pkg["integrity"] = rmeta["dist"]["integrity"]
    rd_pkg["dependencies"] = rmeta.get("dependencies", {}).copy()
    rd_pkg["optionalDependencies"] = rmeta.get("optionalDependencies", {}).copy()

    oxc_ver = rd_pkg["dependencies"].get("@oxc-project/types", "").removeprefix("=")
    if oxc_ver.startswith("^"):
        oxc_ver = oxc_ver.removeprefix("^")
    if oxc_ver:
        ox_key = "node_modules/@oxc-project/types"
        oxmeta = npm_meta("@oxc-project/types", oxc_ver)
        ox_pkg = pkgs.setdefault(ox_key, {})
        ox_pkg.update(
            {
                "version": oxc_ver,
                "resolved": oxmeta["dist"]["tarball"],
                "integrity": oxmeta["dist"]["integrity"],
                "dev": True,
                "license": oxmeta.get("license", "MIT"),
            }
        )
        funding = oxmeta.get("funding")
        if funding:
            ox_pkg["funding"] = funding

    for opt_name, opt_ver in sorted(rmeta.get("optionalDependencies", {}).items()):
        key = f"node_modules/{opt_name}"
        ometa = npm_meta(opt_name, opt_ver)
        entry = pkgs.setdefault(key, {})
        entry.update(
            {
                "version": opt_ver,
                "resolved": ometa["dist"]["tarball"],
                "integrity": ometa["dist"]["integrity"],
            }
        )
        entry.setdefault("cpu", [])
        entry.setdefault("os", [])
        entry["dev"] = True
        entry.setdefault("license", "MIT")
        entry["optional"] = True

    lock_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Updated {lock_path} to vite@{vite_ver} rolldown@{rd_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
