#!/usr/bin/env python3
"""Smoke-test stage-level ProFuzzBench readiness auditing."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_mock_docker(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "if [ \"$1\" = \"--version\" ]; then",
                "  echo 'Docker version 99.0.0, build mock'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"info\" ]; then",
                "  echo 'mock daemon unavailable' >&2",
                "  exit 1",
                "fi",
                "echo \"unexpected docker invocation: $@\" >&2",
                "exit 2",
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)


def write_mock_docker_daemon_without_images(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "if [ \"$1\" = \"--version\" ]; then",
                "  echo 'Docker version 99.0.0, build mock'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"info\" ]; then",
                "  echo '99.0.0'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"image\" ] && [ \"$2\" = \"inspect\" ]; then",
                "  echo \"mock image missing: $3\" >&2",
                "  exit 1",
                "fi",
                "echo \"unexpected docker invocation: $@\" >&2",
                "exit 2",
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)


def write_mock_docker_daemon_with_images(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "if [ \"$1\" = \"--version\" ]; then",
                "  echo 'Docker version 99.0.0, build mock'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"info\" ]; then",
                "  echo '99.0.0'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"image\" ] && [ \"$2\" = \"inspect\" ]; then",
                "  echo \"sha256:mock-$3\"",
                "  exit 0",
                "fi",
                "echo \"unexpected docker invocation: $@\" >&2",
                "exit 2",
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-test stage-level ProFuzzBench readiness audit.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--audit-tool", default=str(Path(__file__).resolve().with_name("bizone_profuzzbench_stage_audit.py")))
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    audit_tool = Path(args.audit_tool).resolve()

    with tempfile.TemporaryDirectory(prefix="bizone-stage-audit-smoke-") as tmp:
        tmpdir = Path(tmp)
        mock_docker = tmpdir / "mock-docker.sh"
        mock_docker_no_images = tmpdir / "mock-docker-no-images.sh"
        mock_docker_with_images = tmpdir / "mock-docker-with-images.sh"
        write_mock_docker(mock_docker)
        write_mock_docker_daemon_without_images(mock_docker_no_images)
        write_mock_docker_daemon_with_images(mock_docker_with_images)
        out_dir = tmpdir / "audit"

        result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker),
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out-dir",
                str(out_dir),
            ],
            cwd=workspace,
        )
        require(
            result.returncode == 0,
            f"stage audit failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

        summary = json.loads((out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        require(summary.get("schema_version") == "bizonefuzz.profuzzbench.stage_audit.v1", f"unexpected summary: {summary}")
        require(summary.get("gate", {}).get("passed") is True, f"default non-strict gate should pass: {summary}")
        rows = summary.get("stages", [])
        require(isinstance(rows, list) and len(rows) == 2, f"expected two stage rows, saw {rows}")
        by_stage = {row["stage_id"]: row for row in rows}
        require(set(by_stage) == {"bring-up", "main-study"}, f"unexpected stages: {sorted(by_stage)}")

        bring_up = by_stage["bring-up"]
        require(bring_up["subject_count"] == 3, f"unexpected bring-up subject count: {bring_up}")
        require(bring_up["manifest_entries"] == 23, f"unexpected bring-up entry count: {bring_up}")
        require(bring_up["monitor_entries"] == 14, f"unexpected bring-up monitor count: {bring_up}")
        require(bring_up["warning_count"] == 0, f"unexpected bring-up warning count: {bring_up}")
        require(bring_up["policy_exclusion_count"] == 7, f"unexpected bring-up policy exclusions: {bring_up}")
        require(bring_up["ready_for_dry_run"] is True, f"bring-up should be dry-run ready: {bring_up}")
        require(bring_up["ready_for_real_run"] is False, f"bring-up should expose missing daemon: {bring_up}")
        require(bring_up["docker_image_missing_count"] > 0, f"bring-up should expose unchecked/missing images: {bring_up}")

        main_study = by_stage["main-study"]
        require(main_study["subject_count"] == 5, f"unexpected main-study subject count: {main_study}")
        require(main_study["manifest_entries"] == 50, f"unexpected main-study entry count: {main_study}")
        require(main_study["monitor_entries"] == 35, f"unexpected main-study monitor count: {main_study}")
        require(main_study["warning_count"] == 0, f"unexpected main-study warning count: {main_study}")
        require(main_study["policy_exclusion_count"] == 0, f"unexpected main-study policy exclusions: {main_study}")
        require(main_study["ready_for_dry_run"] is True, f"main-study should be dry-run ready: {main_study}")
        require(main_study["ready_for_real_run"] is False, f"main-study should expose missing daemon: {main_study}")
        require(main_study["docker_image_missing_count"] > 0, f"main-study should expose unchecked/missing images: {main_study}")

        csv_rows = list(csv.DictReader((out_dir / "stage_summary.csv").open("r", encoding="utf-8", newline="")))
        require(len(csv_rows) == 2, f"unexpected stage summary csv rows: {csv_rows}")
        markdown = (out_dir / "stage_summary.md").read_text(encoding="utf-8")
        require("# Bi-ZoneFuzz++ Stage Audit" in markdown, "stage summary markdown missing title")
        require("| bring-up | 3 | 23 | 14 | 0 | 7 | yes | no | yes | no |" in markdown, "stage summary markdown missing bring-up row")
        require("| main-study | 5 | 50 | 35 | 0 | 0 | yes | no | yes | no |" in markdown, "stage summary markdown missing main-study row")
        require("## Gate" in markdown and "Passed: `yes`" in markdown, "stage summary markdown missing passing gate section")

        real_gate_out_dir = tmpdir / "audit-require-real"
        real_gate_result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker),
                "--stages",
                "bring-up",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--require-real-run-ready",
                "--out-dir",
                str(real_gate_out_dir),
            ],
            cwd=workspace,
        )
        require(
            real_gate_result.returncode != 0,
            "stage audit real-run gate unexpectedly passed without a Docker daemon",
        )
        real_gate_summary = json.loads((real_gate_out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        require(
            real_gate_summary.get("gate", {}).get("passed") is False
            and any("not ready for real run" in item for item in real_gate_summary.get("gate", {}).get("problems", [])),
            f"real-run gate did not expose daemon readiness failure: {real_gate_summary}",
        )
        real_gate_markdown = (real_gate_out_dir / "stage_summary.md").read_text(encoding="utf-8")
        require("Passed: `no`" in real_gate_markdown and "not ready for real run" in real_gate_markdown, "real-run gate markdown lost failure reason")

        missing_image_gate_out_dir = tmpdir / "audit-require-images"
        missing_image_gate_result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker_no_images),
                "--stages",
                "bring-up",
                "--variants",
                "aflnet-base",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--require-real-run-ready",
                "--out-dir",
                str(missing_image_gate_out_dir),
            ],
            cwd=workspace,
        )
        require(
            missing_image_gate_result.returncode != 0,
            "stage audit real-run gate unexpectedly passed when Docker daemon was available but images were missing",
        )
        missing_image_summary = json.loads((missing_image_gate_out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        missing_image_row = missing_image_summary.get("stages", [])[0]
        require(missing_image_row["docker_daemon_available"] is True, f"mock daemon should be available: {missing_image_row}")
        require(missing_image_row["docker_image_checked"] is True, f"image presence should be checked: {missing_image_row}")
        require(missing_image_row["docker_image_missing_count"] > 0, f"missing images should be counted: {missing_image_row}")
        require(
            missing_image_summary.get("gate", {}).get("passed") is False
            and any("docker_image_missing_count" in item for item in missing_image_summary.get("gate", {}).get("problems", [])),
            f"missing-image gate did not expose image readiness failure: {missing_image_summary}",
        )

        present_image_gate_out_dir = tmpdir / "audit-require-images-present"
        present_image_gate_result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker_with_images),
                "--stages",
                "bring-up",
                "--variants",
                "aflnet-base",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--require-real-run-ready",
                "--out-dir",
                str(present_image_gate_out_dir),
            ],
            cwd=workspace,
        )
        require(
            present_image_gate_result.returncode == 0,
            "stage audit real-run gate failed even though mock daemon and images were available:\n"
            f"STDOUT:\n{present_image_gate_result.stdout}\nSTDERR:\n{present_image_gate_result.stderr}",
        )
        present_image_summary = json.loads((present_image_gate_out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        present_image_row = present_image_summary.get("stages", [])[0]
        require(present_image_row["ready_for_real_run"] is True, f"mock images should make real-run ready: {present_image_row}")
        require(present_image_row["docker_image_checked"] is True, f"image presence should be checked: {present_image_row}")
        require(
            present_image_row["docker_image_present_count"] == present_image_row["docker_image_required_count"],
            f"all required images should be present: {present_image_row}",
        )
        require(present_image_row["docker_image_missing_count"] == 0, f"no images should be missing: {present_image_row}")
        require(present_image_summary.get("gate", {}).get("passed") is True, f"present-image gate should pass: {present_image_summary}")

        draft_out_dir = tmpdir / "audit-draft"
        draft_result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker),
                "--publication-gate",
                "draft",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out-dir",
                str(draft_out_dir),
            ],
            cwd=workspace,
        )
        require(
            draft_result.returncode == 0,
            f"draft stage audit failed:\nSTDOUT:\n{draft_result.stdout}\nSTDERR:\n{draft_result.stderr}",
        )

        draft_summary = json.loads((draft_out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        require(draft_summary.get("publication_gate") == "draft", f"unexpected draft summary gate: {draft_summary}")
        draft_rows = draft_summary.get("stages", [])
        require(isinstance(draft_rows, list) and len(draft_rows) == 2, f"expected two draft stage rows, saw {draft_rows}")
        draft_by_stage = {row["stage_id"]: row for row in draft_rows}
        require(draft_by_stage["bring-up"]["manifest_entries"] == 9, f"unexpected draft bring-up entry count: {draft_by_stage['bring-up']}")
        require(draft_by_stage["bring-up"]["monitor_entries"] == 0, f"unexpected draft bring-up monitor count: {draft_by_stage['bring-up']}")
        require(draft_by_stage["bring-up"]["warning_count"] == 14, f"unexpected draft bring-up warnings: {draft_by_stage['bring-up']}")
        require(draft_by_stage["bring-up"]["policy_exclusion_count"] == 7, f"unexpected draft bring-up policy exclusions: {draft_by_stage['bring-up']}")
        require(draft_by_stage["main-study"]["manifest_entries"] == 15, f"unexpected draft main-study entry count: {draft_by_stage['main-study']}")
        require(draft_by_stage["main-study"]["monitor_entries"] == 0, f"unexpected draft main-study monitor count: {draft_by_stage['main-study']}")
        require(draft_by_stage["main-study"]["warning_count"] == 35, f"unexpected draft main-study warnings: {draft_by_stage['main-study']}")
        require(draft_by_stage["main-study"]["policy_exclusion_count"] == 0, f"unexpected draft main-study policy exclusions: {draft_by_stage['main-study']}")

        review_packet = draft_summary.get("review_packet")
        require(isinstance(review_packet, dict), f"draft stage audit missing review packet: {draft_summary}")
        require(review_packet.get("schema_version") == "bizonefuzz.propertycard.review-packet.v1", f"unexpected review packet: {review_packet}")
        require(int(review_packet.get("pending_actions", 0)) > 0, f"review packet should contain pending actions: {review_packet}")
        review_manifest_path = Path(str(review_packet.get("manifest_path", "")))
        require(review_manifest_path.is_file(), f"review packet manifest missing: {review_manifest_path}")
        generated_files = review_packet.get("generated_files", {})
        require(isinstance(generated_files, dict), f"unexpected review packet generated_files: {review_packet}")
        require(Path(str(generated_files.get("review_queue_csv", ""))).is_file(), f"review queue missing: {generated_files}")
        require(Path(str(generated_files.get("review_commands_sh", ""))).is_file(), f"review commands missing: {generated_files}")

        draft_markdown = (draft_out_dir / "stage_summary.md").read_text(encoding="utf-8")
        require("## Review Packet" in draft_markdown, "draft stage summary markdown missing review packet section")
        require("Pending Actions" in draft_markdown, "draft stage summary markdown missing pending-actions detail")

        draft_monitor_gate_out_dir = tmpdir / "audit-draft-require-monitor"
        draft_monitor_gate_result = run(
            [
                sys.executable,
                str(audit_tool),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker),
                "--publication-gate",
                "draft",
                "--stages",
                "main-study",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--require-monitor-entries",
                "--out-dir",
                str(draft_monitor_gate_out_dir),
            ],
            cwd=workspace,
        )
        require(
            draft_monitor_gate_result.returncode != 0,
            "draft stage audit unexpectedly passed require-monitor-entries with unapproved bundle",
        )
        draft_monitor_gate_summary = json.loads((draft_monitor_gate_out_dir / "stage_summary.json").read_text(encoding="utf-8"))
        require(
            draft_monitor_gate_summary.get("gate", {}).get("passed") is False
            and any("no monitor-enabled entries" in item for item in draft_monitor_gate_summary.get("gate", {}).get("problems", [])),
            f"draft monitor gate did not expose missing approved monitor entries: {draft_monitor_gate_summary}",
        )

    print("Bi-ZoneFuzz++ ProFuzzBench stage audit smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
