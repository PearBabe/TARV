#!/usr/bin/env python3
"""Stage-level readiness audit for Bi-ZoneFuzz++ ProFuzzBench campaigns."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
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
        raise RuntimeError(message)


def split_csv(text: str) -> list[str]:
    return [item.strip() for item in text.split(",") if item.strip()]


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def render_markdown(rows: list[dict[str, object]],
                    review_packet: dict[str, object] | None = None,
                    gate: dict[str, object] | None = None) -> str:
    lines = [
        "# Bi-ZoneFuzz++ Stage Audit",
        "",
        "| stage | subjects | entries | monitor entries | warnings | policy exclusions | dry-run ready | real-run ready | docker cli | docker daemon | images present | images missing | draft-ready subjects | final-ready subjects |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['stage_id']} | {row['subject_count']} | {row['manifest_entries']} | "
            f"{row['monitor_entries']} | {row['warning_count']} | "
            f"{row['policy_exclusion_count']} | "
            f"{'yes' if row['ready_for_dry_run'] else 'no'} | "
            f"{'yes' if row['ready_for_real_run'] else 'no'} | "
            f"{'yes' if row['docker_cli_available'] else 'no'} | "
            f"{'yes' if row['docker_daemon_available'] else 'no'} | "
            f"{row['docker_image_present_count']} | "
            f"{row['docker_image_missing_count']} | "
            f"{row['draft_ready_subjects']} | {row['final_ready_subjects']} |"
        )
    lines.append("")
    if review_packet:
        blockers = review_packet.get("bundle_publication_blockers", [])
        blocker_text = "; ".join(str(item) for item in blockers) if isinstance(blockers, list) and blockers else "none"
        lines.extend(
            [
                "## Review Packet",
                "",
                f"- Publication Gate: `{review_packet.get('publication_gate', '')}`",
                f"- Pending Actions: `{review_packet.get('pending_actions', 0)}`",
                f"- Review Status: `{review_packet.get('review_status', '')}`",
                f"- Required Approvals: `{review_packet.get('required_approvals', '')}`",
                f"- Packet Manifest: `{review_packet.get('manifest_path', '')}`",
                f"- Bundle Blockers: `{blocker_text}`",
                "",
            ]
        )
    if gate:
        problems = gate.get("problems", [])
        problem_lines = [str(item) for item in problems] if isinstance(problems, list) else []
        lines.extend(
            [
                "## Gate",
                "",
                f"- Passed: `{'yes' if gate.get('passed') else 'no'}`",
                f"- Problem Count: `{gate.get('problem_count', 0)}`",
                "",
            ]
        )
        if problem_lines:
            lines.extend(["### Gate Problems", ""])
            lines.extend(f"- {item}" for item in problem_lines)
            lines.append("")
    return "\n".join(lines)


def evaluate_gate(rows: list[dict[str, object]], args: argparse.Namespace) -> dict[str, object]:
    problems: list[str] = []
    requirements = {
        "require_dry_run_ready": bool(args.require_dry_run_ready),
        "require_real_run_ready": bool(args.require_real_run_ready),
        "require_no_warnings": bool(args.require_no_warnings),
        "require_no_policy_exclusions": bool(args.require_no_policy_exclusions),
        "require_monitor_entries": bool(args.require_monitor_entries),
    }
    for row in rows:
        stage_id = str(row.get("stage_id", ""))
        if args.require_dry_run_ready and not bool(row.get("ready_for_dry_run", False)):
            problems.append(f"{stage_id}: not ready for dry-run")
        if args.require_real_run_ready and not bool(row.get("ready_for_real_run", False)):
            problems.append(f"{stage_id}: not ready for real run")
        if args.require_real_run_ready and int(row.get("docker_image_missing_count", 0) or 0) != 0:
            problems.append(f"{stage_id}: docker_image_missing_count={row.get('docker_image_missing_count', 0)}")
        if args.require_no_warnings and int(row.get("warning_count", 0) or 0) != 0:
            problems.append(f"{stage_id}: warning_count={row.get('warning_count', 0)}")
        if args.require_no_policy_exclusions and int(row.get("policy_exclusion_count", 0) or 0) != 0:
            problems.append(f"{stage_id}: policy_exclusion_count={row.get('policy_exclusion_count', 0)}")
        if args.require_monitor_entries and int(row.get("monitor_entries", 0) or 0) <= 0:
            problems.append(f"{stage_id}: no monitor-enabled entries selected")
    return {
        "passed": not problems,
        "requirements": requirements,
        "problem_count": len(problems),
        "problems": problems,
    }


def stage_row(stage_id: str,
              manifest: dict[str, object],
              matrix_summary: dict[str, object],
              preflight: dict[str, object],
              stage_dir: Path) -> dict[str, object]:
    docker = preflight.get("docker", {}) if isinstance(preflight.get("docker", {}), dict) else {}
    docker_images = preflight.get("docker_images", {}) if isinstance(preflight.get("docker_images", {}), dict) else {}
    return {
        "stage_id": stage_id,
        "subject_count": int(matrix_summary.get("subjects", 0) or 0),
        "manifest_entries": int(matrix_summary.get("manifest_entries", 0) or 0),
        "monitor_entries": int(matrix_summary.get("monitor_entries", 0) or 0),
        "warning_count": len(manifest.get("warnings", [])) if isinstance(manifest.get("warnings", []), list) else 0,
        "policy_exclusion_count": len(manifest.get("policy_exclusions", [])) if isinstance(manifest.get("policy_exclusions", []), list) else 0,
        "ready_for_dry_run": bool(preflight.get("ready_for_dry_run", False)),
        "ready_for_real_run": bool(preflight.get("ready_for_real_run", False)),
        "docker_cli_available": bool(docker.get("cli_available", False)),
        "docker_daemon_available": bool(docker.get("daemon_available", False)),
        "docker_image_checked": bool(docker_images.get("checked", False)),
        "docker_image_required_count": int(docker_images.get("required_count", 0) or 0),
        "docker_image_present_count": int(docker_images.get("present_count", 0) or 0),
        "docker_image_missing_count": int(docker_images.get("missing_count", 0) or 0),
        "draft_ready_subjects": int(matrix_summary.get("draft_ready_subjects", 0) or 0),
        "final_ready_subjects": int(matrix_summary.get("final_ready_subjects", 0) or 0),
        "manifest_path": str((stage_dir / "manifest.json").resolve()),
        "matrix_dir": str((stage_dir / "matrix").resolve()),
        "preflight_path": str((stage_dir / "preflight.json").resolve()),
    }


def audit_stage(stage_id: str, args: argparse.Namespace) -> dict[str, object]:
    stage_dir = args.out_dir / stage_id
    stage_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = stage_dir / "manifest.json"
    matrix_dir = stage_dir / "matrix"
    preflight_path = stage_dir / "preflight.json"
    results_root = stage_dir / "preflight-results"

    plan_cmd = [
        sys.executable,
        str(args.overlay_tool),
        "plan",
        "--catalog",
        str(args.catalog),
        "--cards-json",
        str(args.cards_json),
        "--stage",
        stage_id,
        "--campaign",
        f"{args.campaign_prefix}-{stage_id}",
        "--variants",
        args.variants,
        "--runs",
        str(args.runs),
        "--fuzz-timeout-sec",
        str(args.fuzz_timeout_sec),
        "--skipcount",
        str(args.skipcount),
        "--test-timeout-ms",
        str(args.test_timeout_ms),
        "--publication-gate",
        args.publication_gate,
        "--out",
        str(manifest_path),
    ]
    planned = run(plan_cmd, cwd=args.workspace)
    require(
        planned.returncode == 0,
        f"stage {stage_id} manifest planning failed:\nSTDOUT:\n{planned.stdout}\nSTDERR:\n{planned.stderr}",
    )

    matrix_cmd = [
        sys.executable,
        str(args.overlay_tool),
        "matrix",
        str(manifest_path),
        "--out-dir",
        str(matrix_dir),
    ]
    matrix = run(matrix_cmd, cwd=args.workspace)
    require(
        matrix.returncode == 0,
        f"stage {stage_id} matrix generation failed:\nSTDOUT:\n{matrix.stdout}\nSTDERR:\n{matrix.stderr}",
    )

    preflight_cmd = [
        sys.executable,
        str(args.overlay_tool),
        "preflight",
        str(manifest_path),
        "--results-root",
        str(results_root),
        "--docker-bin",
        args.docker_bin,
        "--out",
        str(preflight_path),
    ]
    if args.require_daemon:
        preflight_cmd.append("--require-daemon")
    preflight_result = run(preflight_cmd, cwd=args.workspace)
    require(
        preflight_result.returncode == 0,
        f"stage {stage_id} preflight failed:\nSTDOUT:\n{preflight_result.stdout}\nSTDERR:\n{preflight_result.stderr}",
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    matrix_summary = json.loads((matrix_dir / "campaign_summary.json").read_text(encoding="utf-8"))
    preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
    return stage_row(stage_id, manifest, matrix_summary, preflight, stage_dir)


def maybe_generate_review_packet(args: argparse.Namespace) -> dict[str, object] | None:
    if args.publication_gate == "none":
        return None
    cards_json_text = str(args.cards_json).strip()
    if not cards_json_text:
        return None

    review_dir = args.out_dir / "review-packet"
    review_cmd = [
        sys.executable,
        str(args.property_card_tool),
        "review-packet",
        cards_json_text,
        "--out-dir",
        str(review_dir),
        "--tool-path-hint",
        args.review_tool_path_hint,
        "--review-date-template",
        args.review_date_template,
    ]
    review_result = run(review_cmd, cwd=args.workspace)
    require(
        review_result.returncode == 0,
        "review-packet generation failed:\n"
        f"STDOUT:\n{review_result.stdout}\nSTDERR:\n{review_result.stderr}",
    )

    manifest_path = review_dir / "review_packet_manifest.json"
    require(manifest_path.is_file(), f"review packet manifest missing: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(
        payload.get("schema_version") == "bizonefuzz.propertycard.review-packet.v1",
        f"unexpected review packet schema: {payload}",
    )
    payload["publication_gate"] = args.publication_gate
    payload["manifest_path"] = str(manifest_path.resolve())
    payload["out_dir"] = str(review_dir.resolve())
    return payload


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run plan/matrix/preflight across one or more ProFuzzBench stages and summarize readiness."
    )
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--overlay-tool", default=str(Path(__file__).resolve().with_name("bizone_profuzzbench.py")))
    parser.add_argument("--catalog", default=str(root / "benchmarks/profuzzbench_campaigns.json"))
    parser.add_argument("--cards-json", default=str(root / "benchmarks/main_study_property_cards_initial.json"))
    parser.add_argument("--property-card-tool", default=str(Path(__file__).resolve().with_name("property_card_tools.py")))
    parser.add_argument("--stages", default="bring-up,main-study")
    parser.add_argument("--variants", default="aflnet-base,oracle-only,frontier-only,zone-only,obligation-only,progress-only,frontier+zone,full,aflnwe,stateafl")
    parser.add_argument("--campaign-prefix", default="stage-audit")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--fuzz-timeout-sec", type=int, default=24 * 3600)
    parser.add_argument("--skipcount", type=int, default=5)
    parser.add_argument("--test-timeout-ms", type=int, default=5000)
    parser.add_argument("--publication-gate", choices=("none", "draft", "final"), default="none")
    parser.add_argument("--review-tool-path-hint", default="MightyPPL/scripts/property_card_tools.py")
    parser.add_argument("--review-date-template", default="YYYY-MM-DD")
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument("--require-daemon", action="store_true")
    parser.add_argument("--require-dry-run-ready", action="store_true", help="fail after writing reports if any stage is not dry-run ready")
    parser.add_argument("--require-real-run-ready", action="store_true", help="fail after writing reports if any stage is not ready for real Docker campaigns")
    parser.add_argument("--require-no-warnings", action="store_true", help="fail after writing reports if any stage emits planning warnings")
    parser.add_argument("--require-no-policy-exclusions", action="store_true", help="fail after writing reports if any stage has baseline-only policy exclusions")
    parser.add_argument("--require-monitor-entries", action="store_true", help="fail after writing reports if a selected stage has zero monitor-enabled entries")
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.workspace = Path(args.workspace).resolve()
    args.overlay_tool = Path(args.overlay_tool).resolve()
    args.catalog = Path(args.catalog).resolve()
    args.cards_json = Path(args.cards_json).resolve()
    args.property_card_tool = Path(args.property_card_tool).resolve()
    args.out_dir = Path(args.out_dir).resolve()

    try:
        rows = [audit_stage(stage_id, args) for stage_id in split_csv(args.stages)]
        review_packet = maybe_generate_review_packet(args)
        gate = evaluate_gate(rows, args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"bizone_profuzzbench_stage_audit.py: error: {exc}", file=sys.stderr)
        return 1

    summary_path = args.out_dir / "stage_summary.json"
    csv_path = args.out_dir / "stage_summary.csv"
    md_path = args.out_dir / "stage_summary.md"
    manifest_path = args.out_dir / "stage_audit_manifest.json"

    summary = {
        "schema_version": "bizonefuzz.profuzzbench.stage_audit.v1",
        "publication_gate": args.publication_gate,
        "cards_json": str(args.cards_json),
        "stages": rows,
        "gate": gate,
    }
    if review_packet:
        summary["review_packet"] = review_packet
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_csv(
        csv_path,
        [
            "stage_id",
            "subject_count",
            "manifest_entries",
            "monitor_entries",
            "warning_count",
            "policy_exclusion_count",
            "ready_for_dry_run",
            "ready_for_real_run",
            "docker_cli_available",
            "docker_daemon_available",
            "docker_image_checked",
            "docker_image_required_count",
            "docker_image_present_count",
            "docker_image_missing_count",
            "draft_ready_subjects",
            "final_ready_subjects",
            "manifest_path",
            "matrix_dir",
            "preflight_path",
        ],
        rows,
    )
    md_path.write_text(render_markdown(rows, review_packet, gate), encoding="utf-8")
    generated_files = {
        "stage_summary_json": str(summary_path.resolve()),
        "stage_summary_csv": str(csv_path.resolve()),
        "stage_summary_md": str(md_path.resolve()),
    }
    if review_packet:
        generated_files["review_packet_dir"] = str(review_packet["out_dir"])
        generated_files["review_packet_manifest_json"] = str(review_packet["manifest_path"])
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "bizonefuzz.profuzzbench.stage_audit_manifest.v1",
                "publication_gate": args.publication_gate,
                "cards_json": str(args.cards_json),
                "gate": gate,
                "generated_files": generated_files,
                "stages": rows,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote stage audit to {args.out_dir}")
    if not gate["passed"]:
        for problem in gate["problems"]:
            print(f"gate-problem: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
