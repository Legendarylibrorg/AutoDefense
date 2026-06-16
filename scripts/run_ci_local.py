#!/usr/bin/env python3
"""Run the AutoDefense quality gate locally (see docs/CI_LOCAL.md).

Jobs (former .github/workflows/*.yml):

  1. backend        — uv sync (frozen), ruff lint/format, pytest
  2. frontend       — npm ci, audit, vitest, production build
  3. supply-chain   — OSV lockfile scan (backend/uv.lock + frontend/package-lock.json)

Usage:
  python3 scripts/run_ci_local.py              # all jobs
  python3 scripts/run_ci_local.py --list       # show jobs and recommended matrix
  python3 scripts/run_ci_local.py --job backend
  python3 scripts/run_ci_local.py --fast       # backend + frontend (skip supply-chain)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

CI_DOC = "docs/CI_LOCAL.md"

CI_ENV: dict[str, str] = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
}

ALL_JOBS = ("backend", "frontend", "supply-chain")
FAST_JOBS = ("backend", "frontend")

RECOMMENDED_MATRIX: tuple[tuple[str, str, str], ...] = (
    ("Linux", "3.11", "20"),
    ("Linux", "3.12", "22"),
    ("macOS", "3.12", "22"),
    ("Windows", "3.11", "20"),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_npm_bin() -> str:
    requested = os.environ.get("NPM_BIN")
    if requested:
        return requested
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm not found on PATH; install Node.js 20+ or set NPM_BIN")
    return npm


def _ci_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(CI_ENV)
    return env


def _require_uv() -> str:
    uv = os.environ.get("UV_BIN") or shutil.which("uv")
    if uv is None:
        raise SystemExit(
            "uv is required (https://docs.astral.sh/uv/getting-started/installation/)"
        )
    return uv


def _banner(title: str) -> None:
    width = max(len(title) + 4, 72)
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def _step(title: str, cmd: Sequence[str], *, cwd: Path, env: dict[str, str]) -> None:
    print(f"\n--- {title} ---")
    print("$", " ".join(cmd))
    subprocess.run(list(cmd), cwd=str(cwd), env=env, check=True)


def job_backend(root: Path, env: dict[str, str]) -> None:
    backend = root / "backend"
    uv = _require_uv()
    py_label = os.environ.get("UV_PYTHON") or platform.python_version()
    _banner(f"Job: backend (Python {py_label} via uv)")

    _step(
        "Install dependencies (frozen lockfile)",
        [uv, "sync", "--all-extras", "--frozen"],
        cwd=backend,
        env=env,
    )
    _step("Ruff lint", [uv, "run", "ruff", "check", "."], cwd=backend, env=env)
    _step(
        "Ruff format (check)",
        [uv, "run", "ruff", "format", "--check", "."],
        cwd=backend,
        env=env,
    )
    _step(
        "Pytest",
        [uv, "run", "pytest", "tests/", "-q", "--tb=short"],
        cwd=backend,
        env=env,
    )


def job_frontend(root: Path, env: dict[str, str]) -> None:
    frontend = root / "frontend"
    npm = resolve_npm_bin()
    node = shutil.which("node")
    node_label = os.environ.get("NODE_VERSION") or (
        subprocess.check_output([node, "-v"], text=True).strip() if node else "unknown"
    )
    _banner(f"Job: frontend (Node {node_label})")

    _step(
        "Install from lockfile (no lifecycle scripts)",
        [npm, "ci", "--ignore-scripts"],
        cwd=frontend,
        env=env,
    )
    _step(
        "Audit (moderate+)",
        [npm, "audit", "--audit-level=moderate"],
        cwd=frontend,
        env=env,
    )
    _step("Vitest", [npm, "test"], cwd=frontend, env=env)
    _step("Production build", [npm, "run", "build"], cwd=frontend, env=env)


def job_supply_chain(root: Path, env: dict[str, str]) -> None:
    osv = os.environ.get("OSV_SCANNER_BIN") or shutil.which("osv-scanner")
    if osv is None:
        raise SystemExit(
            "osv-scanner not found on PATH; install from "
            "https://google.github.io/osv-scanner/installation/ "
            "or set OSV_SCANNER_BIN"
        )
    _banner("Job: supply-chain (OSV lockfile scan)")

    _step(
        "OSV lockfile scan",
        [
            osv,
            "scan",
            f"--lockfile={root / 'backend' / 'uv.lock'}",
            f"--lockfile={root / 'frontend' / 'package-lock.json'}",
        ],
        cwd=root,
        env=env,
    )


def _print_plan(*, jobs: Sequence[str]) -> None:
    host = platform.system()
    print(f"Quality gate: {CI_DOC}")
    print(f"Local host: {host}")
    print("\nRecommended matrix (run before release merges):")
    for os_name, py_ver, node_ver in RECOMMENDED_MATRIX:
        print(f"  - {os_name}, Python {py_ver}, Node {node_ver}")
    print("\nAll local jobs:")
    for job in ALL_JOBS:
        print(f"  - {job}")
    print("\nLocal run plan:")
    for job in jobs:
        print(f"  - {job}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local quality gate (docs/CI_LOCAL.md).")
    parser.add_argument(
        "--job",
        choices=ALL_JOBS,
        action="append",
        help="Run one job (repeatable). Default: all jobs.",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run backend + frontend only (skip supply-chain / OSV scan).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print recommended matrix vs local plan and exit.",
    )
    args = parser.parse_args(argv)

    root = repo_root()

    if args.fast:
        jobs = list(FAST_JOBS)
    elif args.job:
        jobs = list(dict.fromkeys(args.job))
    else:
        jobs = list(ALL_JOBS)

    if args.list:
        _print_plan(jobs=jobs)
        return 0

    _print_plan(jobs=jobs)
    env = _ci_env()
    success = False

    try:
        for job in jobs:
            if job == "backend":
                job_backend(root, env)
            elif job == "frontend":
                job_frontend(root, env)
            elif job == "supply-chain":
                job_supply_chain(root, env)
            else:
                raise SystemExit(f"unknown job: {job}")
        success = True
    except subprocess.CalledProcessError as exc:
        print(f"\nLocal quality gate failed (exit {exc.returncode}).", file=sys.stderr)
        return exc.returncode

    if not success:
        return 1

    print("\nOK: run_ci_local.py finished successfully (all selected jobs passed).")
    if len(jobs) == len(ALL_JOBS):
        print(f"See {CI_DOC} for the recommended cross-platform matrix before large merges.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
