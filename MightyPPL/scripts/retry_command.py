#!/usr/bin/env python3
"""Retry a command a bounded number of times until it succeeds."""

from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Retry a subprocess command until it succeeds.")
    parser.add_argument("--attempts", type=int, default=3, help="Maximum number of attempts")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run after --")
    args = parser.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if args.attempts < 1:
        raise SystemExit("--attempts must be >= 1")
    if not cmd:
        raise SystemExit("no command provided")

    last_code = 1
    for attempt in range(1, args.attempts + 1):
        result = subprocess.run(cmd, check=False)
        last_code = int(result.returncode)
        if last_code == 0:
            if attempt > 1:
                print(f"retry_command: succeeded on attempt {attempt}", file=sys.stderr)
            return 0
        if attempt < args.attempts:
            print(
                f"retry_command: attempt {attempt} failed with exit code {last_code}; retrying",
                file=sys.stderr,
            )

    return last_code


if __name__ == "__main__":
    raise SystemExit(main())
