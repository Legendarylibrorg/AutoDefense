"""Smoke tests for platform host scanners (--json CLI output)."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FINDING_KEYS = frozenset({"category", "severity", "title", "detail", "evidence"})
PAYLOAD_KEYS = frozenset(
    {"platform", "kernel_version", "hostname", "timestamp", "in_container", "findings", "hardening"}
)


def _run_scanner_json(script: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(script), "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    data = json.loads(proc.stdout)
    assert isinstance(data, dict)
    missing = PAYLOAD_KEYS - data.keys()
    assert not missing, f"missing keys: {sorted(missing)}"
    assert isinstance(data["findings"], list)
    assert isinstance(data["hardening"], dict)
    for finding in data["findings"]:
        assert isinstance(finding, dict)
        assert FINDING_KEYS <= finding.keys()
    return data


@pytest.mark.skipif(platform.system() != "Linux", reason="kernel scanner requires Linux /proc")
def test_kernel_scanner_json_output():
    data = _run_scanner_json(REPO_ROOT / "kernel" / "scanner.py")
    assert data["platform"] == "linux"


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS scanner requires Darwin")
def test_macos_scanner_json_output():
    data = _run_scanner_json(REPO_ROOT / "macos" / "scanner.py")
    assert data["platform"] == "darwin"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows scanner requires Windows")
def test_windows_scanner_json_output():
    data = _run_scanner_json(REPO_ROOT / "windows" / "scanner.py")
    assert data["platform"] == "windows"
