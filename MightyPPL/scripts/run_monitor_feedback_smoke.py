#!/usr/bin/env python3
"""Smoke-test the Bi-ZoneFuzz++ feedback pipeline end to end."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path


EXPECTED_CHANNELS = {
    "frontier",
    "zone",
    "obligation",
    "property_progress",
    "protocol_semantic",
    "mutation_hint",
    "explainability",
}


def run(cmd: list[str], *, cwd: Path, timeout: int = 30) -> subprocess.CompletedProcess[str]:
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


def load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            records.append(json.loads(text))
    return records


def write_events(path: Path, lines: list[str]) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def verify_full_feedback(records: list[dict]) -> None:
    event_types = [record["event_type"] for record in records]
    require(event_types.count("property_eval") == 2, f"expected 2 property_eval records, saw {event_types}")
    require(event_types.count("semantic_state") == 2, f"expected 2 semantic_state records, saw {event_types}")
    require("case_result" in event_types, f"expected at least one case_result record, saw {event_types}")
    require(event_types.count("ablation_result") == 1, f"expected 1 ablation_result record, saw {event_types}")

    property_records = [record for record in records if record["event_type"] == "property_eval"]
    first = property_records[0]
    require(first["run_id"] == "smoke-r0", "run_id did not round-trip into RVEM record")
    require(first["property_id"] == "prop.deadline", "property_set_id did not round-trip into RVEM record")
    require("timed_trace_event" in first, "timed_trace_event missing from property_eval record")
    require("feedback_frame" in first, "feedback_frame missing from property_eval record")

    feedback = first["feedback_frame"]["feedback"]
    require(set(feedback) == EXPECTED_CHANNELS, f"unexpected feedback channels: {sorted(feedback)}")
    require(first["feedback_frame"]["channel_mask"] == 127, "full feedback channel mask should be 127")
    require(property_records[-1]["verdict"] == "NEGATIVE", "negative regression verdict not preserved in RVEM record")

    first_zone = first["feedback_frame"]["feedback"]["zone"]
    second_zone = property_records[1]["feedback_frame"]["feedback"]["zone"]
    require(int(first_zone["zone_hash"]) != 0, f"first zone hash should be populated: {first_zone}")
    require(int(second_zone["zone_hash"]) != 0, f"second zone hash should be populated: {second_zone}")
    require(
        int(first_zone["zone_hash"]) != int(second_zone["zone_hash"]),
        f"zone hash should change across distinct timed DBM/point-zone states: {first_zone} vs {second_zone}",
    )
    require(first_zone["slack_exact"] is True, f"first zone should use exact concrete slack: {first_zone}")
    require(second_zone["slack_exact"] is True, f"second zone should use exact concrete slack: {second_zone}")
    require(
        int(second_zone["min_slack_ms"]) < int(first_zone["min_slack_ms"]),
        f"deadline violation should tighten min_slack_ms across the trace: {first_zone} vs {second_zone}",
    )


def verify_channel_ablation(records: list[dict]) -> None:
    property_records = [record for record in records if record["event_type"] == "property_eval"]
    require(property_records, "expected property_eval records for ablation run")
    feedback = property_records[0]["feedback_frame"]["feedback"]
    require(property_records[0]["feedback_frame"]["channel_mask"] == 3, "frontier+zone ablation should use mask 3")
    require(feedback["frontier"]["frontier_size_pos"] >= 0, "frontier feedback should remain populated")
    require(feedback["zone"]["boundary_class"] != "", "zone feedback should remain populated")
    require(int(feedback["zone"]["zone_hash"]) != 0, f"zone hash should remain populated: {feedback['zone']}")
    require(feedback["zone"]["slack_exact"] is True, f"zone exactness should remain visible: {feedback['zone']}")
    require(feedback["obligation"]["active_obligation_count"] == 0, "obligation feedback should be zeroed when disabled")
    require(feedback["property_progress"]["property_progress_vector"] == [], "progress feedback should be empty when disabled")
    require(feedback["protocol_semantic"]["session_phase"] == "unknown", "protocol feedback should reset when disabled")
    require(feedback["mutation_hint"]["candidate_next_event_classes"] == [], "mutation hints should be empty when disabled")
    require(feedback["explainability"]["dominant_property_id"] == "", "explainability should reset when disabled")


def verify_rvem_pipeline(workspace: Path, rvem_tool: Path, raw_log: Path, out_dir: Path) -> None:
    validate = run([sys.executable, str(rvem_tool), "validate", str(raw_log)], cwd=workspace)
    require(validate.returncode == 0, f"rvem validate failed:\nSTDOUT:\n{validate.stdout}\nSTDERR:\n{validate.stderr}")

    table_dir = out_dir / "tables"
    aggregate = run(
        [sys.executable, str(rvem_tool), "aggregate", str(raw_log), "--out-dir", str(table_dir)],
        cwd=workspace,
    )
    require(aggregate.returncode == 0, f"rvem aggregate failed:\nSTDOUT:\n{aggregate.stdout}\nSTDERR:\n{aggregate.stderr}")

    plot_dir = out_dir / "plots"
    plot = run(
        [sys.executable, str(rvem_tool), "plot", "--table-dir", str(table_dir), "--out-dir", str(plot_dir)],
        cwd=workspace,
        timeout=60,
    )
    require(plot.returncode == 0, f"rvem plot failed:\nSTDOUT:\n{plot.stdout}\nSTDERR:\n{plot.stderr}")

    dashboard_path = out_dir / "dashboard.html"
    dashboard = run(
        [
            sys.executable,
            str(rvem_tool),
            "dashboard",
            "--table-dir",
            str(table_dir),
            "--plot-dir",
            str(plot_dir),
            "--out-html",
            str(dashboard_path),
        ],
        cwd=workspace,
        timeout=60,
    )
    require(
        dashboard.returncode == 0,
        f"rvem dashboard failed:\nSTDOUT:\n{dashboard.stdout}\nSTDERR:\n{dashboard.stderr}",
    )

    report_dir = out_dir / "reports"
    report = run(
        [
            sys.executable,
            str(rvem_tool),
            "report",
            "--table-dir",
            str(table_dir),
            "--plot-dir",
            str(plot_dir),
            "--out-dir",
            str(report_dir),
        ],
        cwd=workspace,
        timeout=60,
    )
    require(
        report.returncode == 0,
        f"rvem report failed:\nSTDOUT:\n{report.stdout}\nSTDERR:\n{report.stderr}",
    )

    expected_csv = {
        "time_series.csv",
        "property_summary.csv",
        "semantic_state_series.csv",
        "slack_distribution.csv",
        "ablation_summary.csv",
        "overhead_yield.csv",
        "case_timeline.csv",
        "frontier_obligation_series.csv",
        "property_progress_series.csv",
        "trace_replay.csv",
    }
    expected_svg = {
        "coverage_over_time.svg",
        "time_to_first_violation.svg",
        "property_heatmap.svg",
        "semantic_state_over_time.svg",
        "slack_ecdf.svg",
        "slack_violin.svg",
        "progress_coverage_bar.svg",
        "ablation_bar.svg",
        "overhead_vs_yield.svg",
        "case_timeline.svg",
        "obligation_lifecycle.svg",
        "timing_hint_origin.svg",
    }
    require(expected_csv.issubset({path.name for path in table_dir.glob("*.csv")}), "missing aggregated RVEM CSV outputs")
    require(expected_svg.issubset({path.name for path in plot_dir.glob("*.svg")}), "missing RVEM SVG outputs")
    require(dashboard_path.exists(), "missing RVEM dashboard output")
    dashboard_text = dashboard_path.read_text(encoding="utf-8")
    require("Frontier &amp; Obligation Evolution" in dashboard_text, "dashboard view label missing")
    require("Trace Replay with Explanation" in dashboard_text, "trace replay view missing")
    require((report_dir / "variant_overview.csv").exists(), "missing RVEM variant overview report")
    require((report_dir / "survival_table.csv").exists(), "missing RVEM survival table report")
    require((report_dir / "progress_obligation_summary.csv").exists(), "missing RVEM progress/obligation report")
    require((report_dir / "subject_variant_summary.csv").exists(), "missing RVEM subject variant summary report")
    require((report_dir / "pooled_variant_summary.csv").exists(), "missing RVEM pooled summary report")
    require((report_dir / "pairwise_variant_comparison.csv").exists(), "missing RVEM pairwise comparison report")
    require((report_dir / "timing_provenance_summary.csv").exists(), "missing RVEM timing provenance report")
    require((report_dir / "subject_metric_matrix.csv").exists(), "missing RVEM subject metric matrix report")
    require((report_dir / "figure_manifest.json").exists(), "missing RVEM figure manifest")
    require((report_dir / "paper_summary.md").exists(), "missing RVEM paper summary")
    require((report_dir / "paper_tables.md").exists(), "missing RVEM paper tables markdown")
    require((report_dir / "paper_tables.tex").exists(), "missing RVEM paper tables LaTeX")
    summary_text = (report_dir / "paper_summary.md").read_text(encoding="utf-8")
    require("Variant Overview" in summary_text, "paper summary missing variant overview section")
    require("Subject Variant Summary" in summary_text, "paper summary missing subject variant section")
    require("Pooled Variant Summary" in summary_text, "paper summary missing pooled variant section")
    require("Pairwise Variant Comparisons" in summary_text, "paper summary missing pairwise section")
    require("Figure Bundle" in summary_text, "paper summary missing figure bundle section")
    paper_tables_text = (report_dir / "paper_tables.md").read_text(encoding="utf-8")
    require("Primary Metrics" in paper_tables_text, "paper tables missing primary metrics section")
    require("Auxiliary Metrics" in paper_tables_text, "paper tables missing auxiliary metrics section")
    require("### smoke" in paper_tables_text, "paper tables missing smoke campaign section")
    require("| monitor |" in paper_tables_text, "paper tables missing monitored subject rows")

    with (report_dir / "subject_variant_summary.csv").open("r", encoding="utf-8", newline="") as handle:
        subject_rows = list(csv.DictReader(handle))
    require(subject_rows, "subject variant summary should not be empty")
    require(
        all("event_fraction_ci_low" in row and "mean_feedback_origin_rows" in row for row in subject_rows),
        f"subject variant summary missing expected columns: {subject_rows}",
    )

    with (report_dir / "subject_metric_matrix.csv").open("r", encoding="utf-8", newline="") as handle:
        matrix_rows = list(csv.DictReader(handle))
    require(matrix_rows, "subject metric matrix should not be empty")
    matrix_fields = set(matrix_rows[0])
    require(
        any(field.endswith("__event_fraction") for field in matrix_fields),
        f"subject metric matrix missing event_fraction projection: {sorted(matrix_fields)}",
    )
    require(
        any(field.endswith("__mean_final_coverage") for field in matrix_fields),
        f"subject metric matrix missing coverage projection: {sorted(matrix_fields)}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an end-to-end feedback+RVEM smoke test.")
    parser.add_argument("--monitor", required=True, help="Path to mitppl-monitor")
    parser.add_argument("--rvem-tool", required=True, help="Path to rvem_tools.py")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    monitor = Path(args.monitor).resolve()
    rvem_tool = Path(args.rvem_tool).resolve()

    with tempfile.TemporaryDirectory(prefix="bizonefuzz-feedback-") as tmp:
        tmpdir = Path(tmp)
        events_path = tmpdir / "events.txt"
        write_events(events_path, ["@0 p", "@5 r"])

        full_log = tmpdir / "full.feedback.jsonl"
        full_run = run(
            [
                str(monitor),
                "--formula",
                "G(p -> G[0,10] (!r))",
                "--input",
                str(events_path),
                "--feedback-jsonl",
                str(full_log),
                "--campaign",
                "smoke",
                "--subject",
                "monitor",
                "--fuzzer-name",
                "bizonefuzz",
                "--mode",
                "full",
                "--run-id",
                "smoke-r0",
                "--property-set-id",
                "prop.deadline",
            ],
            cwd=workspace,
        )
        require(full_run.returncode == 0, f"full feedback run failed:\nSTDOUT:\n{full_run.stdout}\nSTDERR:\n{full_run.stderr}")
        require(full_run.stdout.splitlines() == ["INCONCLUSIVE", "NEGATIVE"], "regression verdicts changed in full mode")
        full_records = load_jsonl(full_log)
        verify_full_feedback(full_records)
        verify_rvem_pipeline(workspace, rvem_tool, full_log, tmpdir / "rvem")

        ablation_log = tmpdir / "frontier_zone.feedback.jsonl"
        ablation_run = run(
            [
                str(monitor),
                "--formula",
                "G(p -> G[0,10] (!r))",
                "--input",
                str(events_path),
                "--feedback-jsonl",
                str(ablation_log),
                "--feedback-channels",
                "frontier,zone",
                "--campaign",
                "smoke",
                "--subject",
                "monitor",
                "--fuzzer-name",
                "bizonefuzz",
                "--mode",
                "frontier+zone",
                "--run-id",
                "smoke-r1",
                "--property-set-id",
                "prop.deadline",
            ],
            cwd=workspace,
        )
        require(ablation_run.returncode == 0, f"ablation run failed:\nSTDOUT:\n{ablation_run.stdout}\nSTDERR:\n{ablation_run.stderr}")
        require(ablation_run.stdout.splitlines() == ["INCONCLUSIVE", "NEGATIVE"], "regression verdicts changed in ablation mode")
        verify_channel_ablation(load_jsonl(ablation_log))

    print("Bi-ZoneFuzz++ feedback smoke passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"feedback smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
