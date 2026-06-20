#!/usr/bin/env python3
"""Smoke-test AFLNet live monitor ablation modes across the real bridge."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

MODE_CHANNEL_MASKS = [
    ("oracle-only", 0),
    ("frontier-only", 1),
    ("zone-only", 2),
    ("obligation-only", 4),
    ("progress-only", 8),
    ("frontier+zone", 3),
    ("full", 127),
]


def run(cmd: list[str], *, cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AFLNet live ablation-mode smoke coverage.")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--monitor", required=True)
    parser.add_argument("--afl-fuzz", required=True)
    parser.add_argument("--afl-clang-fast", required=True)
    parser.add_argument("--server-source", required=True)
    parser.add_argument("--smoke-script", default=str(Path(__file__).resolve().with_name("run_aflnet_bizone_smoke.py")))
    parser.add_argument("--duration-sec", type=int, default=6)
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    smoke_script = Path(args.smoke_script).resolve()
    require(smoke_script.is_file(), f"smoke script not found: {smoke_script}")

    for mode, expected_mask in MODE_CHANNEL_MASKS:
        cmd = [
            sys.executable,
            str(smoke_script),
            "--monitor",
            str(Path(args.monitor).resolve()),
            "--afl-fuzz",
            str(Path(args.afl_fuzz).resolve()),
            "--afl-clang-fast",
            str(Path(args.afl_clang_fast).resolve()),
            "--server-source",
            str(Path(args.server_source).resolve()),
            "--workspace",
            str(workspace),
            "--duration-sec",
            str(args.duration_sec),
            "--monitor-mode",
            mode,
            "--disable-test-hint-overrides",
            "--allow-no-active-timing-plan",
            "--force-retry-chain",
            "0",
            "--expect-channel-mask",
            str(expected_mask),
        ]
        result = run(cmd, cwd=workspace, timeout=max(120, args.duration_sec + 60))
        require(
            result.returncode == 0,
            f"mode {mode!r} failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

    print(
        "AFLNet Bi-ZoneFuzz++ ablation matrix smoke passed for "
        + ", ".join(mode for mode, _ in MODE_CHANNEL_MASKS)
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"aflnet ablation matrix smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
