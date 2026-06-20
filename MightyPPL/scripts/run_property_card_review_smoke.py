#!/usr/bin/env python3
"""Smoke-test the PropertyCard review / publication workflow."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd: list[str], *, cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a PropertyCard review-workflow smoke test.")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument(
        "--tool",
        default="MightyPPL/scripts/property_card_tools.py",
        help="Path to property_card_tools.py relative to workspace",
    )
    parser.add_argument(
        "--bundle",
        default="MightyPPL/benchmarks/main_study_property_cards_initial.json",
        help="Path to the main-study bundle relative to workspace",
    )
    parser.add_argument(
        "--stage-audit-tool",
        default="MightyPPL/scripts/bizone_profuzzbench_stage_audit.py",
        help="Path to the stage-audit tool relative to workspace",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    tool = (workspace / args.tool).resolve()
    bundle = (workspace / args.bundle).resolve()
    stage_audit_tool = (workspace / args.stage_audit_tool).resolve()
    require(tool.is_file(), f"tool not found: {tool}")
    require(bundle.is_file(), f"bundle not found: {bundle}")
    require(stage_audit_tool.is_file(), f"stage audit tool not found: {stage_audit_tool}")

    review_report = run(
        [sys.executable, str(tool), "review-report", str(bundle), "--format", "json"],
        cwd=workspace,
    )
    require(
        review_report.returncode == 0,
        "review-report failed:\nSTDOUT:\n"
        f"{review_report.stdout}\nSTDERR:\n{review_report.stderr}",
    )
    summary = json.loads(review_report.stdout)
    card_ids = [entry["property_id"] for entry in summary.get("cards", [])]
    require(card_ids, f"review report did not return cards: {summary}")

    with tempfile.TemporaryDirectory(prefix="property-card-review-packet-") as review_tmp:
        review_packet_dir = Path(review_tmp) / "review-packet"
        review_packet = run(
            [
                sys.executable,
                str(tool),
                "review-packet",
                str(bundle),
                "--out-dir",
                str(review_packet_dir),
            ],
            cwd=workspace,
        )
        require(
            review_packet.returncode == 0,
            "review-packet failed:\nSTDOUT:\n"
            f"{review_packet.stdout}\nSTDERR:\n{review_packet.stderr}",
        )
        for relative in (
            "property_cards.json",
            "property_cards.md",
            "review_report.md",
            "review_report.json",
            "formulas_manifest.json",
            "property_index.csv",
            "citation_index.csv",
            "review_queue.csv",
            "review_commands.sh",
            "review_packet.md",
            "review_packet_manifest.json",
        ):
            require((review_packet_dir / relative).is_file(), f"review packet missing {relative}")
        require((review_packet_dir / "formulas").is_dir(), "review packet missing formulas dir")
        review_packet_manifest = json.loads((review_packet_dir / "review_packet_manifest.json").read_text(encoding="utf-8"))
        require(review_packet_manifest.get("pending_actions", 0) > 0, f"review packet should expose pending actions: {review_packet_manifest}")
        review_queue_lines = (review_packet_dir / "review_queue.csv").read_text(encoding="utf-8").splitlines()
        require(len(review_queue_lines) >= 2, f"review queue should contain header + rows: {review_queue_lines}")
        review_commands = (review_packet_dir / "review_commands.sh").read_text(encoding="utf-8")
        require("approve-draft" in review_commands, f"review command templates missing draft approval action:\n{review_commands}")

    original_gate = run(
        [sys.executable, str(tool), "publication-check", str(bundle), "--allow-draft"],
        cwd=workspace,
    )
    require(
        original_gate.returncode != 0,
        "draft publication gate unexpectedly passed before second-reviewer approvals were added",
    )
    gate_text = f"{original_gate.stdout}\n{original_gate.stderr}"
    require(
        "Second reviewer approval" in gate_text or "needs 2 draft approvals" in gate_text,
        f"draft publication gate failed for an unexpected reason:\n{gate_text}",
    )

    with tempfile.TemporaryDirectory(prefix="property-card-review-smoke-") as tmp:
        tmpdir = Path(tmp)
        temp_bundle = tmpdir / bundle.name
        shutil.copy2(bundle, temp_bundle)

        review_packet_dir = tmpdir / "review-packet"
        review_packet = run(
            [
                sys.executable,
                str(tool),
                "review-packet",
                str(temp_bundle),
                "--out-dir",
                str(review_packet_dir),
            ],
            cwd=workspace,
        )
        require(
            review_packet.returncode == 0,
            "temp review-packet failed:\nSTDOUT:\n"
            f"{review_packet.stdout}\nSTDERR:\n{review_packet.stderr}",
        )
        review_queue_path = review_packet_dir / "review_queue.csv"
        with review_queue_path.open("r", encoding="utf-8", newline="") as handle:
            queue_rows = list(csv.DictReader(handle))
            fieldnames = list(queue_rows[0].keys()) if queue_rows else []
        require(queue_rows, f"temp review queue was empty: {review_queue_path}")
        for row in queue_rows:
            row["apply"] = "1"
            row["reviewer_id"] = "reviewer_two"
            row["reviewer_name"] = "Second Reviewer"
            row["review_date"] = "2026-06-17"
            row["role"] = "independent_review"
            row["notes"] = "Synthetic smoke-only second review used to exercise the draft publication gate."
        with review_queue_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(queue_rows)

        reviewed_dir = tmpdir / "reviewed-draft"
        resolve_packet = run(
            [
                sys.executable,
                str(tool),
                "resolve-review-packet",
                str(review_packet_dir / "review_packet_manifest.json"),
                "--out-dir",
                str(reviewed_dir),
                "--allow-draft",
                "--require-gate-pass",
            ],
            cwd=workspace,
        )
        require(
            resolve_packet.returncode == 0,
            "resolve-review-packet failed:\nSTDOUT:\n"
            f"{resolve_packet.stdout}\nSTDERR:\n{resolve_packet.stderr}",
        )
        reviewed_bundle = reviewed_dir / "reviewed_bundle.json"
        resolution_manifest = json.loads((reviewed_dir / "review_resolution_manifest.json").read_text(encoding="utf-8"))
        require(
            resolution_manifest.get("gate_result", {}).get("publication_stage") == "draft"
            and resolution_manifest.get("gate_result", {}).get("passed") is True,
            f"review resolution manifest did not record a passing draft gate: {resolution_manifest}",
        )
        require(
            int(resolution_manifest.get("applied_actions", 0)) >= len(card_ids) + 1,
            f"review resolution manifest applied too few actions: {resolution_manifest}",
        )

        stamped_gate = run(
            [sys.executable, str(tool), "publication-check", str(reviewed_bundle), "--allow-draft"],
            cwd=workspace,
        )
        require(
            stamped_gate.returncode == 0,
            "draft publication gate failed after synthetic second-reviewer approvals:\nSTDOUT:\n"
            f"{stamped_gate.stdout}\nSTDERR:\n{stamped_gate.stderr}",
        )

        stamped_report = run(
            [sys.executable, str(tool), "review-report", str(reviewed_bundle), "--format", "json"],
            cwd=workspace,
        )
        require(
            stamped_report.returncode == 0,
            "stamped review-report failed:\nSTDOUT:\n"
            f"{stamped_report.stdout}\nSTDERR:\n{stamped_report.stderr}",
        )
        stamped_summary = json.loads(stamped_report.stdout)
        require(
            stamped_summary.get("draft_approvals", 0) >= 2,
            f"bundle draft approvals did not increase as expected: {stamped_summary}",
        )
        require(
            all(entry.get("draft_approvals", 0) >= 2 for entry in stamped_summary.get("cards", [])),
            f"not all cards reached the draft approval threshold: {stamped_summary}",
        )

        mock_docker = tmpdir / "mock-docker.sh"
        write_mock_docker(mock_docker)
        stage_audit_dir = tmpdir / "draft-stage-audit"
        draft_stage_audit = run(
            [
                sys.executable,
                str(stage_audit_tool),
                "--workspace",
                str(workspace),
                "--cards-json",
                str(reviewed_bundle),
                "--docker-bin",
                str(mock_docker),
                "--publication-gate",
                "draft",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out-dir",
                str(stage_audit_dir),
            ],
            cwd=workspace,
        )
        require(
            draft_stage_audit.returncode == 0,
            "draft stage audit failed after review-packet application:\nSTDOUT:\n"
            f"{draft_stage_audit.stdout}\nSTDERR:\n{draft_stage_audit.stderr}",
        )
        draft_stage_summary = json.loads((stage_audit_dir / "stage_summary.json").read_text(encoding="utf-8"))
        draft_stage_rows = {row["stage_id"]: row for row in draft_stage_summary.get("stages", [])}
        require(
            draft_stage_rows.get("bring-up", {}).get("manifest_entries") == 23
            and draft_stage_rows.get("bring-up", {}).get("monitor_entries") == 14,
            f"draft bring-up did not recover monitor entries after review application: {draft_stage_rows}",
        )
        require(
            draft_stage_rows.get("bring-up", {}).get("warning_count") == 0
            and draft_stage_rows.get("bring-up", {}).get("policy_exclusion_count") == 7,
            f"draft bring-up counts were unexpected after review application: {draft_stage_rows}",
        )
        require(
            draft_stage_rows.get("main-study", {}).get("manifest_entries") == 50
            and draft_stage_rows.get("main-study", {}).get("monitor_entries") == 35
            and draft_stage_rows.get("main-study", {}).get("warning_count") == 0,
            f"draft main-study did not recover after review application: {draft_stage_rows}",
        )

        draft_publish_dir = tmpdir / "draft-pack"
        draft_publish = run(
            [
                sys.executable,
                str(tool),
                "publish-bundle",
                str(reviewed_bundle),
                "--out-dir",
                str(draft_publish_dir),
                "--allow-draft",
            ],
            cwd=workspace,
        )
        require(
            draft_publish.returncode == 0,
            "draft publish-bundle failed:\nSTDOUT:\n"
            f"{draft_publish.stdout}\nSTDERR:\n{draft_publish.stderr}",
        )
        draft_manifest = json.loads((draft_publish_dir / "publication_manifest.json").read_text(encoding="utf-8"))
        require(draft_manifest.get("publication_stage") == "draft", f"unexpected draft manifest: {draft_manifest}")
        require(draft_manifest.get("cards_count") == len(card_ids), f"draft pack lost card count: {draft_manifest}")
        for relative in (
            "property_cards.json",
            "property_cards.md",
            "review_report.md",
            "review_report.json",
            "formulas_manifest.json",
            "property_index.csv",
            "citation_index.csv",
            "publication_manifest.json",
        ):
            require((draft_publish_dir / relative).is_file(), f"draft pack missing {relative}")
        require((draft_publish_dir / "formulas").is_dir(), "draft pack missing formulas dir")

        final_bundle_stamp = run(
            [
                sys.executable,
                str(tool),
                "stamp-review",
                str(reviewed_bundle),
                "--scope",
                "bundle",
                "--reviewer-id",
                "agent_primary",
                "--reviewer-name",
                "Codex",
                "--decision",
                "approve",
                "--date",
                "2026-06-17",
                "--role",
                "primary_review",
                "--notes",
                "Converted the initial draft approval into a final publication approval for smoke coverage.",
            ],
            cwd=workspace,
        )
        require(
            final_bundle_stamp.returncode == 0,
            "primary final bundle stamp-review failed:\nSTDOUT:\n"
            f"{final_bundle_stamp.stdout}\nSTDERR:\n{final_bundle_stamp.stderr}",
        )
        second_final_bundle_stamp = run(
            [
                sys.executable,
                str(tool),
                "stamp-review",
                str(reviewed_bundle),
                "--scope",
                "bundle",
                "--reviewer-id",
                "reviewer_two",
                "--reviewer-name",
                "Second Reviewer",
                "--decision",
                "approve",
                "--date",
                "2026-06-17",
                "--role",
                "independent_review",
                "--notes",
                "Converted the synthetic draft approval into a final publication approval for smoke coverage.",
            ],
            cwd=workspace,
        )
        require(
            second_final_bundle_stamp.returncode == 0,
            "second final bundle stamp-review failed:\nSTDOUT:\n"
            f"{second_final_bundle_stamp.stdout}\nSTDERR:\n{second_final_bundle_stamp.stderr}",
        )

        for reviewer_id, reviewer_name, role, notes in (
            (
                "agent_primary",
                "Codex",
                "primary_review",
                "Converted the initial draft approval into a final publication approval for smoke coverage.",
            ),
            (
                "reviewer_two",
                "Second Reviewer",
                "independent_review",
                "Converted the synthetic draft approval into a final publication approval for smoke coverage.",
            ),
        ):
            for card_id in card_ids:
                final_card_stamp = run(
                    [
                        sys.executable,
                        str(tool),
                        "stamp-review",
                        str(reviewed_bundle),
                        "--scope",
                        "card",
                        "--card-id",
                        card_id,
                        "--reviewer-id",
                        reviewer_id,
                        "--reviewer-name",
                        reviewer_name,
                        "--decision",
                        "approve",
                        "--date",
                        "2026-06-17",
                        "--role",
                        role,
                        "--notes",
                        notes,
                    ],
                    cwd=workspace,
                )
                require(
                    final_card_stamp.returncode == 0,
                    f"final card stamp-review failed for {card_id}/{reviewer_id}:\nSTDOUT:\n"
                    f"{final_card_stamp.stdout}\nSTDERR:\n{final_card_stamp.stderr}",
                )

        status_update = run(
            [
                sys.executable,
                str(tool),
                "set-review-status",
                str(reviewed_bundle),
                "--review-status",
                "approved-for-publication",
                "--strict",
            ],
            cwd=workspace,
        )
        require(
            status_update.returncode == 0,
            "set-review-status failed:\nSTDOUT:\n"
            f"{status_update.stdout}\nSTDERR:\n{status_update.stderr}",
        )

        final_gate = run(
            [sys.executable, str(tool), "publication-check", str(reviewed_bundle)],
            cwd=workspace,
        )
        require(
            final_gate.returncode == 0,
            "final publication gate failed after final approvals:\nSTDOUT:\n"
            f"{final_gate.stdout}\nSTDERR:\n{final_gate.stderr}",
        )

        final_publish_dir = Path(tmp) / "final-pack"
        final_publish = run(
            [
                sys.executable,
                str(tool),
                "publish-bundle",
                str(reviewed_bundle),
                "--out-dir",
                str(final_publish_dir),
            ],
            cwd=workspace,
        )
        require(
            final_publish.returncode == 0,
            "final publish-bundle failed:\nSTDOUT:\n"
            f"{final_publish.stdout}\nSTDERR:\n{final_publish.stderr}",
        )
        final_manifest = json.loads((final_publish_dir / "publication_manifest.json").read_text(encoding="utf-8"))
        require(final_manifest.get("publication_stage") == "final", f"unexpected final manifest: {final_manifest}")
        require(
            final_manifest.get("review_status") == "approved-for-publication",
            f"final pack lost review_status: {final_manifest}",
        )
        require(
            final_manifest.get("review_summary", {}).get("final_approvals", 0) >= 2,
            f"final pack lost final approvals: {final_manifest}",
        )
        require(
            all(card.get("formula_file", "").endswith(".mitl") for card in final_manifest.get("cards", [])),
            f"final pack card manifest missing formula files: {final_manifest}",
        )

    print("PropertyCard review smoke passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"property-card review smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
