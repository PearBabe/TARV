#!/usr/bin/env python3
"""RVEM ingestion, aggregation, and plotting utilities for Bi-ZoneFuzz++.

The tool intentionally keeps its default path dependency-free. It reads raw
JSONL telemetry, writes CSV tables that can be loaded by Parquet tooling, and
emits SVG plots with the Python standard library. Optional Parquet output uses
pandas/pyarrow when available.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import random
import shutil
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "rvem.raw.v1"
PACKAGE_SCHEMA_VERSION = "rvem.repro_package.v1"

EVENT_TYPES = {
    "run_start",
    "campaign_snapshot",
    "property_eval",
    "semantic_state",
    "case_result",
    "monitor_overhead",
    "ablation_result",
    "timing_audit",
}

VERDICTS = {"POSITIVE", "NEGATIVE", "INCONCLUSIVE", "SAT", "UNSAT", "UNKNOWN", ""}
MONITOR_ABLATION_VARIANTS = {
    "oracle-only",
    "frontier-only",
    "zone-only",
    "obligation-only",
    "progress-only",
    "frontier+zone",
    "full",
}

REQUIRED_PAPER_FIGURES = [
    "coverage_over_time.svg",
    "time_to_first_violation.svg",
    "semantic_state_over_time.svg",
    "property_heatmap.svg",
    "slack_ecdf.svg",
    "slack_violin.svg",
    "progress_coverage_bar.svg",
    "ablation_bar.svg",
    "overhead_vs_yield.svg",
    "case_timeline.svg",
    "obligation_lifecycle.svg",
    "timing_hint_origin.svg",
]

REQUIRED_DASHBOARD_VIEWS = [
    "Overview",
    "Protocol Drill-down",
    "Property Explorer",
    "Frontier & Obligation Evolution",
    "Trace Replay with Explanation",
]

REQUIRED_REPORT_FILES = [
    "variant_overview.csv",
    "survival_table.csv",
    "progress_obligation_summary.csv",
    "subject_variant_summary.csv",
    "subject_metric_matrix.csv",
    "pooled_variant_summary.csv",
    "monitor_ablation_summary.csv",
    "pairwise_variant_comparison.csv",
    "timing_provenance_summary.csv",
    "figure_manifest.json",
    "paper_summary.md",
    "paper_tables.md",
    "paper_tables.tex",
    "report_manifest.json",
]

REQUIRED_EVIDENCE_TABLES = [
    "time_series.csv",
    "frontier_obligation_series.csv",
    "property_progress_series.csv",
    "trace_replay.csv",
    "timing_audit_series.csv",
]

RAW_SCHEMA = {
    "schema_version": SCHEMA_VERSION,
    "required": ["event_type", "run_id", "elapsed_sec"],
    "common_dimensions": ["campaign", "subject", "fuzzer", "variant", "run_id", "elapsed_sec"],
    "event_types": sorted(EVENT_TYPES),
    "coverage_fields": ["coverage_edges", "coverage_blocks", "coverage_paths", "coverage"],
    "rv_fields": ["property_id", "verdict", "slack_ms", "deadline_ms", "semantic_state"],
    "overhead_fields": ["monitor_ms", "target_ms", "total_ms", "execs_per_sec"],
}

CSV_FIELDS = {
    "time_series": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "elapsed_sec",
        "coverage_edges",
        "coverage_blocks",
        "coverage_paths",
        "execs_total",
        "cases_total",
        "bugs_total",
        "violations_total",
        "yield_total",
        "monitor_ms",
        "target_ms",
        "overhead_ratio",
    ],
    "property_summary": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "property_id",
        "evaluations",
        "positive",
        "negative",
        "inconclusive",
        "violation_rate",
        "min_slack_ms",
        "median_slack_ms",
        "mean_slack_ms",
    ],
    "semantic_state_series": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "elapsed_sec",
        "state_id",
        "region",
        "monitor_state_count",
        "frontier_width",
        "verdict",
    ],
    "slack_distribution": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "elapsed_sec",
        "property_id",
        "case_id",
        "slack_ms",
        "deadline_ms",
        "verdict",
    ],
    "ablation_summary": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "ablation",
        "runs",
        "bugs_total",
        "violations_total",
        "coverage_edges_max",
        "yield_total",
        "mean_execs_per_sec",
        "mean_overhead_ratio",
    ],
    "overhead_yield": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "elapsed_sec",
        "monitor_ms",
        "target_ms",
        "total_ms",
        "overhead_ratio",
        "execs_per_sec",
        "yield_total",
        "coverage_edges",
    ],
    "case_timeline": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "case_id",
        "start_sec",
        "end_sec",
        "outcome",
        "property_id",
        "slack_ms",
    ],
    "frontier_obligation_series": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "property_id",
        "elapsed_sec",
        "event_index",
        "timestamp_ms",
        "semantic_state_id",
        "channel_mask",
        "verdict",
        "pos_frontier_hash",
        "neg_frontier_hash",
        "frontier_size_pos",
        "frontier_size_neg",
        "frontier_novelty",
        "zone_hash",
        "min_slack_ms",
        "boundary_class",
        "violated_guard_count",
        "near_deadline_count",
        "slack_exact",
        "active_obligation_count",
        "opened_now",
        "satisfied_now",
        "expired_now",
        "obligation_phase_mask",
        "session_phase",
        "request_class",
        "response_class",
        "parser_state_id",
        "dominant_property_id",
        "critical_deadline_source",
    ],
    "property_progress_series": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "property_id",
        "elapsed_sec",
        "event_index",
        "verdict",
        "property_progress_vector",
        "newly_reached_progress_bins",
        "property_coverage_delta",
        "frontier_novelty",
        "boundary_class",
        "min_slack_ms",
        "active_obligation_count",
        "dominant_property_id",
    ],
    "trace_replay": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "property_id",
        "case_id",
        "elapsed_sec",
        "event_index",
        "timestamp_ms",
        "direction",
        "gap_prev_ms",
        "t_send_ms",
        "t_first_response_ms",
        "t_done_ms",
        "session_phase",
        "request_class",
        "response_class",
        "close_or_reset_seen",
        "parser_state_id",
        "verdict",
        "semantic_state_id",
        "boundary_class",
        "min_slack_ms",
        "active_obligation_count",
        "property_progress_vector",
        "property_coverage_delta",
        "recommended_gap_delta_ms",
        "candidate_next_event_classes",
        "retry_hint",
        "keepalive_hint",
        "silence_hint",
        "dominant_property_id",
        "decisive_transition_id",
        "critical_deadline_source",
        "shortest_witness_summary",
        "raw_event",
    ],
    "timing_audit_series": [
        "campaign",
        "subject",
        "fuzzer",
        "variant",
        "run_id",
        "property_id",
        "elapsed_sec",
        "artifact_scope",
        "artifact_label",
        "artifact_order",
        "stage",
        "stage_hint_origin",
        "stage_gap_hint_ms",
        "stage_hint_mask",
        "stage_preferred_request_class",
        "stage_retry_preferred_request_class",
        "stage_keepalive_preferred_request_class",
        "queue_semantic_state_id",
        "queue_gap_hint_ms",
        "queue_hint_mask",
        "queue_preferred_request_class",
        "queue_retry_preferred_request_class",
        "queue_keepalive_preferred_request_class",
        "feedback_semantic_state_id",
        "feedback_gap_hint_ms",
        "feedback_hint_mask",
        "feedback_preferred_request_class",
        "feedback_retry_preferred_request_class",
        "feedback_keepalive_preferred_request_class",
        "feedback_request_class",
        "feedback_response_class",
        "feedback_session_phase",
        "requested_gap_delta_ms",
        "active",
        "gap_expansion",
        "gap_compression",
        "boundary_bisection",
        "keepalive_bias",
        "silence_window",
        "retry_insertion",
        "keepalive_insertion",
        "keepalive_synthesized",
        "keepalive_contextual",
        "keepalive_profile",
        "retry_contextual",
        "retry_profile",
        "retry_source_request_class",
        "keepalive_anchor_request_class",
        "cross_request_resend",
        "hybrid_keepalive_retry",
        "insertion_count",
        "base_message_count",
        "message_count",
        "poll_wait_base_ms",
        "poll_wait_override_ms",
        "tail_wait_ms",
        "pre_send_delay_ms",
        "injected_plan",
    ],
}

AGGREGATED_SCHEMA = {"tables": CSV_FIELDS}
REPORT_SCHEMA = {
    "schema_version": "rvem.report.v3",
    "files": {
        "variant_overview.csv": [
            "campaign",
            "subject",
            "fuzzer",
            "variant",
            "runs",
            "event_runs",
            "censored_runs",
            "event_fraction",
            "mean_final_coverage",
            "median_final_coverage",
            "max_final_coverage",
            "mean_final_yield_total",
            "max_final_yield_total",
            "mean_final_violations_total",
            "max_final_violations_total",
            "mean_final_semantic_states",
            "max_final_semantic_states",
            "mean_final_overhead_ratio",
            "median_time_to_first_violation_sec",
            "fastest_time_to_first_violation_sec",
        ],
        "survival_table.csv": [
            "campaign",
            "subject",
            "fuzzer",
            "variant",
            "runs_total",
            "time_sec",
            "at_risk",
            "events",
            "censored",
            "survival_probability",
        ],
        "progress_obligation_summary.csv": [
            "campaign",
            "subject",
            "fuzzer",
            "variant",
            "runs",
            "unique_progress_bins",
            "progress_delta_total",
            "progress_events",
            "peak_active_obligations",
            "opened_total",
            "satisfied_total",
            "expired_total",
            "boundary_hits",
            "boundary_hit_rate",
            "min_slack_ms",
        ],
        "subject_variant_summary.csv": [
            "campaign",
            "subject",
            "fuzzer",
            "variant",
            "runs",
            "event_runs",
            "event_fraction",
            "event_fraction_ci_low",
            "event_fraction_ci_high",
            "mean_final_coverage",
            "coverage_ci_low",
            "coverage_ci_high",
            "mean_final_semantic_states",
            "semantic_ci_low",
            "semantic_ci_high",
            "mean_final_overhead_ratio",
            "overhead_ci_low",
            "overhead_ci_high",
            "mean_final_yield_total",
            "mean_final_violations_total",
            "median_time_to_first_violation_sec",
            "fastest_time_to_first_violation_sec",
            "mean_unique_progress_bins",
            "mean_boundary_hit_rate",
            "mean_feedback_origin_rows",
            "mean_queue_origin_rows",
        ],
        "pooled_variant_summary.csv": [
            "campaign",
            "fuzzer",
            "variant",
            "subjects",
            "runs",
            "event_runs",
            "event_fraction",
            "event_fraction_ci_low",
            "event_fraction_ci_high",
            "mean_final_coverage",
            "coverage_ci_low",
            "coverage_ci_high",
            "mean_final_semantic_states",
            "semantic_ci_low",
            "semantic_ci_high",
            "mean_final_overhead_ratio",
            "overhead_ci_low",
            "overhead_ci_high",
            "mean_final_yield_total",
            "mean_final_violations_total",
            "median_time_to_first_violation_sec",
            "fastest_time_to_first_violation_sec",
            "mean_unique_progress_bins",
            "mean_boundary_hit_rate",
            "mean_feedback_origin_rows",
            "mean_queue_origin_rows",
        ],
        "monitor_ablation_summary.csv": [
            "campaign",
            "scope",
            "subject",
            "fuzzer",
            "variant",
            "reference_variant",
            "subjects",
            "runs",
            "event_fraction",
            "reference_event_fraction",
            "delta_event_fraction",
            "mean_final_coverage",
            "reference_mean_final_coverage",
            "delta_mean_final_coverage",
            "mean_final_semantic_states",
            "reference_mean_final_semantic_states",
            "delta_mean_final_semantic_states",
            "mean_final_yield_total",
            "reference_mean_final_yield_total",
            "delta_mean_final_yield_total",
            "mean_final_violations_total",
            "reference_mean_final_violations_total",
            "delta_mean_final_violations_total",
            "mean_unique_progress_bins",
            "reference_mean_unique_progress_bins",
            "delta_mean_unique_progress_bins",
            "mean_boundary_hit_rate",
            "reference_mean_boundary_hit_rate",
            "delta_mean_boundary_hit_rate",
            "mean_final_overhead_ratio",
            "reference_mean_final_overhead_ratio",
            "delta_mean_final_overhead_ratio",
            "mean_feedback_origin_rows",
            "reference_mean_feedback_origin_rows",
            "delta_mean_feedback_origin_rows",
            "mean_queue_origin_rows",
            "reference_mean_queue_origin_rows",
            "delta_mean_queue_origin_rows",
        ],
        "pairwise_variant_comparison.csv": [
            "campaign",
            "scope",
            "subject",
            "reference_label",
            "treatment_label",
            "metric",
            "reference_n",
            "treatment_n",
            "reference_mean",
            "treatment_mean",
            "delta_mean",
            "delta_mean_ci_low",
            "delta_mean_ci_high",
            "mann_whitney_u",
            "mw_pvalue_two_sided",
            "cliffs_delta",
            "a12",
            "significance_tier",
        ],
        "timing_provenance_summary.csv": [
            "campaign",
            "subject",
            "fuzzer",
            "variant",
            "timing_rows",
            "active_timing_rows",
            "feedback_origin_rows",
            "queue_origin_rows",
            "none_origin_rows",
            "retry_plan_rows",
            "keepalive_plan_rows",
            "silence_plan_rows",
            "hybrid_plan_rows",
            "boundary_bisection_rows",
        ],
        "subject_metric_matrix.csv": "wide subject-by-variant metric matrix with dynamic variant-derived columns",
        "figure_manifest.json": "paper-facing figure registry",
        "paper_summary.md": "concise markdown summary for experiment/paper drafting",
        "paper_tables.md": "subject-organized markdown tables ready for experiment write-up",
        "paper_tables.tex": "subject-organized LaTeX longtables ready for paper integration",
        "report_manifest.json": "machine-readable manifest of generated report artifacts",
    },
    "defaults": {
        "reference_label": "aflnet/aflnet-base (auto when present)",
        "bootstrap_samples": 1000,
        "bootstrap_seed": 1337,
    },
}


@dataclass
class RawRecord:
    """Validated raw RVEM event.

    Required fields are deliberately close to ProFuzzBench campaign metadata:
    campaign, subject, fuzzer, run_id, elapsed_sec, plus a flexible variant
    field for Bi-ZoneFuzz++ ablations.
    """

    event_type: str
    run_id: str
    elapsed_sec: float
    campaign: str = ""
    subject: str = ""
    fuzzer: str = ""
    variant: str = "baseline"
    timestamp: str = ""
    case_id: str = ""
    property_id: str = ""
    verdict: str = ""
    coverage_edges: int = 0
    coverage_blocks: int = 0
    coverage_paths: int = 0
    execs_total: int = 0
    cases_total: int = 0
    bugs_total: int = 0
    violations_total: int = 0
    yield_total: int = 0
    monitor_ms: float = 0.0
    target_ms: float = 0.0
    total_ms: float = 0.0
    execs_per_sec: float = 0.0
    slack_ms: float | None = None
    deadline_ms: float | None = None
    state_id: str = ""
    region: str = ""
    monitor_state_count: int = 0
    frontier_width: int = 0
    outcome: str = ""
    ablation: str = ""
    start_sec: float | None = None
    end_sec: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.campaign, self.subject, self.fuzzer, self.variant, self.run_id)


def as_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    return float(value)


def as_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(float(value))


def get_nested(data: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def validate_record(data: dict[str, Any], source: Path, line_number: int) -> RawRecord:
    if not isinstance(data, dict):
        raise ValueError(f"{source}:{line_number}: expected a JSON object")

    schema = data.get("schema_version", SCHEMA_VERSION)
    if schema != SCHEMA_VERSION:
        raise ValueError(f"{source}:{line_number}: unsupported schema_version {schema!r}")

    event_type = str(data.get("event_type", "")).strip()
    if event_type not in EVENT_TYPES:
        raise ValueError(f"{source}:{line_number}: unsupported event_type {event_type!r}")

    run_id = str(data.get("run_id", "")).strip()
    if not run_id:
        raise ValueError(f"{source}:{line_number}: run_id is required")

    elapsed_sec = as_float(data.get("elapsed_sec"))
    if elapsed_sec < 0:
        raise ValueError(f"{source}:{line_number}: elapsed_sec must be non-negative")

    coverage = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
    overhead = data.get("overhead") if isinstance(data.get("overhead"), dict) else {}
    semantic = data.get("semantic_state") if isinstance(data.get("semantic_state"), dict) else {}

    verdict = str(data.get("verdict", "")).upper()
    if verdict not in VERDICTS:
        raise ValueError(f"{source}:{line_number}: unsupported verdict {verdict!r}")

    return RawRecord(
        event_type=event_type,
        run_id=run_id,
        elapsed_sec=elapsed_sec,
        campaign=str(data.get("campaign", "")),
        subject=str(data.get("subject", "")),
        fuzzer=str(data.get("fuzzer", "")),
        variant=str(data.get("variant", data.get("configuration", "baseline"))),
        timestamp=str(data.get("timestamp", "")),
        case_id=str(data.get("case_id", "")),
        property_id=str(data.get("property_id", "")),
        verdict=verdict,
        coverage_edges=as_int(get_nested(data, "coverage_edges", default=coverage.get("edges"))),
        coverage_blocks=as_int(get_nested(data, "coverage_blocks", default=coverage.get("blocks"))),
        coverage_paths=as_int(get_nested(data, "coverage_paths", default=coverage.get("paths"))),
        execs_total=as_int(data.get("execs_total")),
        cases_total=as_int(data.get("cases_total")),
        bugs_total=as_int(data.get("bugs_total")),
        violations_total=as_int(data.get("violations_total")),
        yield_total=as_int(data.get("yield_total", data.get("interesting_total"))),
        monitor_ms=as_float(get_nested(data, "monitor_ms", default=overhead.get("monitor_ms"))),
        target_ms=as_float(get_nested(data, "target_ms", default=overhead.get("target_ms"))),
        total_ms=as_float(get_nested(data, "total_ms", default=overhead.get("total_ms"))),
        execs_per_sec=as_float(data.get("execs_per_sec")),
        slack_ms=None if data.get("slack_ms") is None else as_float(data.get("slack_ms")),
        deadline_ms=None if data.get("deadline_ms") is None else as_float(data.get("deadline_ms")),
        state_id=str(get_nested(data, "state_id", default=semantic.get("state_id", ""))),
        region=str(get_nested(data, "region", default=semantic.get("region", ""))),
        monitor_state_count=as_int(get_nested(data, "monitor_state_count", default=semantic.get("monitor_state_count"))),
        frontier_width=as_int(get_nested(data, "frontier_width", default=semantic.get("frontier_width"))),
        outcome=str(data.get("outcome", "")),
        ablation=str(data.get("ablation", data.get("variant", ""))),
        start_sec=None if data.get("start_sec") is None else as_float(data.get("start_sec")),
        end_sec=None if data.get("end_sec") is None else as_float(data.get("end_sec")),
        raw=data,
    )


def read_jsonl(paths: Iterable[Path]) -> list[RawRecord]:
    records: list[RawRecord] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
                records.append(validate_record(payload, path, line_number))
    return records


def ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def row_from_record(record: RawRecord) -> dict[str, Any]:
    overhead_ratio = ratio(record.monitor_ms, record.target_ms)
    return {
        "campaign": record.campaign,
        "subject": record.subject,
        "fuzzer": record.fuzzer,
        "variant": record.variant,
        "run_id": record.run_id,
        "elapsed_sec": record.elapsed_sec,
        "coverage_edges": record.coverage_edges,
        "coverage_blocks": record.coverage_blocks,
        "coverage_paths": record.coverage_paths,
        "execs_total": record.execs_total,
        "cases_total": record.cases_total,
        "bugs_total": record.bugs_total,
        "violations_total": record.violations_total,
        "yield_total": record.yield_total,
        "monitor_ms": record.monitor_ms,
        "target_ms": record.target_ms,
        "overhead_ratio": overhead_ratio,
    }


def aggregate(records: list[RawRecord]) -> dict[str, list[dict[str, Any]]]:
    tables: dict[str, list[dict[str, Any]]] = {name: [] for name in CSV_FIELDS}
    property_groups: dict[tuple[str, str, str, str, str], list[RawRecord]] = defaultdict(list)
    ablation_groups: dict[tuple[str, str, str, str, str], list[RawRecord]] = defaultdict(list)

    for record in sorted(records, key=lambda item: (item.key, item.elapsed_sec, item.event_type)):
        if record.event_type in {"campaign_snapshot", "case_result", "monitor_overhead", "ablation_result"}:
            tables["time_series"].append(row_from_record(record))

        if record.event_type == "property_eval":
            property_groups[(*record.key[:4], record.property_id)].append(record)
            if record.slack_ms is not None:
                tables["slack_distribution"].append(
                    {
                        "campaign": record.campaign,
                        "subject": record.subject,
                        "fuzzer": record.fuzzer,
                        "variant": record.variant,
                        "run_id": record.run_id,
                        "elapsed_sec": record.elapsed_sec,
                        "property_id": record.property_id,
                        "case_id": record.case_id,
                        "slack_ms": record.slack_ms,
                        "deadline_ms": record.deadline_ms if record.deadline_ms is not None else "",
                        "verdict": record.verdict,
                    }
                )
            frame = feedback_frame(record)
            frontier = feedback_channel(record, "frontier")
            zone = feedback_channel(record, "zone")
            obligation = feedback_channel(record, "obligation")
            progress = feedback_channel(record, "property_progress")
            protocol = feedback_channel(record, "protocol_semantic")
            hint = feedback_channel(record, "mutation_hint")
            explain = feedback_channel(record, "explainability")
            timed = timed_trace_event(record)
            if frame or timed:
                event_index = as_int(get_nested(frame, "event_index", default=timed.get("event_index")))
                timestamp_ms = as_float(get_nested(frame, "timestamp_ms", default=timed.get("timestamp_ms")))
                semantic_state_id = str(frame.get("semantic_state_id", ""))
                channel_mask = as_int(frame.get("channel_mask"))
                tables["frontier_obligation_series"].append(
                    {
                        "campaign": record.campaign,
                        "subject": record.subject,
                        "fuzzer": record.fuzzer,
                        "variant": record.variant,
                        "run_id": record.run_id,
                        "property_id": record.property_id,
                        "elapsed_sec": record.elapsed_sec,
                        "event_index": event_index,
                        "timestamp_ms": timestamp_ms,
                        "semantic_state_id": semantic_state_id,
                        "channel_mask": channel_mask,
                        "verdict": record.verdict,
                        "pos_frontier_hash": str(frontier.get("pos_frontier_hash", "")),
                        "neg_frontier_hash": str(frontier.get("neg_frontier_hash", "")),
                        "frontier_size_pos": as_int(frontier.get("frontier_size_pos")),
                        "frontier_size_neg": as_int(frontier.get("frontier_size_neg")),
                        "frontier_novelty": bool_text(frontier.get("frontier_novelty")),
                        "zone_hash": str(zone.get("zone_hash", "")),
                        "min_slack_ms": "" if zone.get("min_slack_ms") is None else as_float(zone.get("min_slack_ms")),
                        "boundary_class": str(zone.get("boundary_class", "")),
                        "violated_guard_count": as_int(zone.get("violated_guard_count")),
                        "near_deadline_count": as_int(zone.get("near_deadline_count")),
                        "slack_exact": bool_text(zone.get("slack_exact")),
                        "active_obligation_count": as_int(obligation.get("active_obligation_count")),
                        "opened_now": as_int(obligation.get("opened_now")),
                        "satisfied_now": as_int(obligation.get("satisfied_now")),
                        "expired_now": as_int(obligation.get("expired_now")),
                        "obligation_phase_mask": as_int(obligation.get("obligation_phase_mask")),
                        "session_phase": str(protocol.get("session_phase", "")),
                        "request_class": str(protocol.get("request_class", "")),
                        "response_class": str(protocol.get("response_class", "")),
                        "parser_state_id": str(protocol.get("parser_state_id", "")),
                        "dominant_property_id": str(explain.get("dominant_property_id", "")),
                        "critical_deadline_source": str(explain.get("critical_deadline_source", "")),
                    }
                )
                tables["property_progress_series"].append(
                    {
                        "campaign": record.campaign,
                        "subject": record.subject,
                        "fuzzer": record.fuzzer,
                        "variant": record.variant,
                        "run_id": record.run_id,
                        "property_id": record.property_id,
                        "elapsed_sec": record.elapsed_sec,
                        "event_index": event_index,
                        "verdict": record.verdict,
                        "property_progress_vector": encode_compact_json(progress.get("property_progress_vector", [])),
                        "newly_reached_progress_bins": encode_compact_json(progress.get("newly_reached_progress_bins", [])),
                        "property_coverage_delta": as_int(progress.get("property_coverage_delta")),
                        "frontier_novelty": bool_text(frontier.get("frontier_novelty")),
                        "boundary_class": str(zone.get("boundary_class", "")),
                        "min_slack_ms": "" if zone.get("min_slack_ms") is None else as_float(zone.get("min_slack_ms")),
                        "active_obligation_count": as_int(obligation.get("active_obligation_count")),
                        "dominant_property_id": str(explain.get("dominant_property_id", "")),
                    }
                )
                tables["trace_replay"].append(
                    {
                        "campaign": record.campaign,
                        "subject": record.subject,
                        "fuzzer": record.fuzzer,
                        "variant": record.variant,
                        "run_id": record.run_id,
                        "property_id": record.property_id,
                        "case_id": record.case_id,
                        "elapsed_sec": record.elapsed_sec,
                        "event_index": event_index,
                        "timestamp_ms": timestamp_ms,
                        "direction": str(timed.get("direction", "")),
                        "gap_prev_ms": "" if timed.get("gap_prev_ms") is None else as_float(timed.get("gap_prev_ms")),
                        "t_send_ms": "" if timed.get("t_send_ms") is None else as_float(timed.get("t_send_ms")),
                        "t_first_response_ms": "" if timed.get("t_first_response_ms") is None else as_float(timed.get("t_first_response_ms")),
                        "t_done_ms": "" if timed.get("t_done_ms") is None else as_float(timed.get("t_done_ms")),
                        "session_phase": str(protocol.get("session_phase", timed.get("session_phase", ""))),
                        "request_class": str(protocol.get("request_class", timed.get("request_class", ""))),
                        "response_class": str(protocol.get("response_class", timed.get("response_class", ""))),
                        "close_or_reset_seen": bool_text(protocol.get("close_or_reset_seen", timed.get("close_or_reset_seen"))),
                        "parser_state_id": str(protocol.get("parser_state_id", timed.get("parser_state_id", ""))),
                        "verdict": record.verdict,
                        "semantic_state_id": semantic_state_id,
                        "boundary_class": str(zone.get("boundary_class", "")),
                        "min_slack_ms": "" if zone.get("min_slack_ms") is None else as_float(zone.get("min_slack_ms")),
                        "active_obligation_count": as_int(obligation.get("active_obligation_count")),
                        "property_progress_vector": encode_compact_json(progress.get("property_progress_vector", [])),
                        "property_coverage_delta": as_int(progress.get("property_coverage_delta")),
                        "recommended_gap_delta_ms": "" if hint.get("recommended_gap_delta_ms") is None else as_int(hint.get("recommended_gap_delta_ms")),
                        "candidate_next_event_classes": encode_compact_json(hint.get("candidate_next_event_classes", [])),
                        "retry_hint": bool_text(hint.get("retry_hint")),
                        "keepalive_hint": bool_text(hint.get("keepalive_hint")),
                        "silence_hint": bool_text(hint.get("silence_hint")),
                        "dominant_property_id": str(explain.get("dominant_property_id", "")),
                        "decisive_transition_id": str(explain.get("decisive_transition_id", "")),
                        "critical_deadline_source": str(explain.get("critical_deadline_source", "")),
                        "shortest_witness_summary": str(explain.get("shortest_witness_summary", "")),
                        "raw_event": compact_text(timed.get("raw", "")),
                    }
                )

        if record.event_type == "semantic_state":
            tables["semantic_state_series"].append(
                {
                    "campaign": record.campaign,
                    "subject": record.subject,
                    "fuzzer": record.fuzzer,
                    "variant": record.variant,
                    "run_id": record.run_id,
                    "elapsed_sec": record.elapsed_sec,
                    "state_id": record.state_id,
                    "region": record.region,
                    "monitor_state_count": record.monitor_state_count,
                    "frontier_width": record.frontier_width,
                    "verdict": record.verdict,
                }
            )

        if record.event_type in {"monitor_overhead", "campaign_snapshot", "ablation_result"}:
            tables["overhead_yield"].append(
                {
                    "campaign": record.campaign,
                    "subject": record.subject,
                    "fuzzer": record.fuzzer,
                    "variant": record.variant,
                    "run_id": record.run_id,
                    "elapsed_sec": record.elapsed_sec,
                    "monitor_ms": record.monitor_ms,
                    "target_ms": record.target_ms,
                    "total_ms": record.total_ms or record.monitor_ms + record.target_ms,
                    "overhead_ratio": ratio(record.monitor_ms, record.target_ms),
                    "execs_per_sec": record.execs_per_sec,
                    "yield_total": record.yield_total,
                    "coverage_edges": record.coverage_edges,
                }
            )
            ablation_groups[(*record.key[:4], record.ablation or record.variant)].append(record)

        if record.event_type == "case_result":
            start_sec = record.start_sec if record.start_sec is not None else record.elapsed_sec
            end_sec = record.end_sec if record.end_sec is not None else record.elapsed_sec
            tables["case_timeline"].append(
                {
                    "campaign": record.campaign,
                    "subject": record.subject,
                    "fuzzer": record.fuzzer,
                    "variant": record.variant,
                    "run_id": record.run_id,
                    "case_id": record.case_id,
                    "start_sec": start_sec,
                    "end_sec": end_sec,
                    "outcome": record.outcome or record.verdict,
                    "property_id": record.property_id,
                    "slack_ms": "" if record.slack_ms is None else record.slack_ms,
                }
            )

        if record.event_type == "timing_audit":
            plan = timing_plan(record)
            tables["timing_audit_series"].append(
                {
                    "campaign": record.campaign,
                    "subject": record.subject,
                    "fuzzer": record.fuzzer,
                    "variant": record.variant,
                    "run_id": record.run_id,
                    "property_id": record.property_id,
                    "elapsed_sec": record.elapsed_sec,
                    "artifact_scope": str(record.raw.get("artifact_scope", "")),
                    "artifact_label": str(record.raw.get("artifact_label", "")),
                    "artifact_order": as_int(record.raw.get("artifact_order")),
                    "stage": str(plan.get("stage", "")),
                    "stage_hint_origin": str(plan.get("stage_hint_origin", "")),
                    "stage_gap_hint_ms": as_int(plan.get("stage_gap_hint_ms")),
                    "stage_hint_mask": as_int(plan.get("stage_hint_mask")),
                    "stage_preferred_request_class": str(plan.get("stage_preferred_request_class", "")),
                    "stage_retry_preferred_request_class": str(
                        plan.get("stage_retry_preferred_request_class", "")
                    ),
                    "stage_keepalive_preferred_request_class": str(
                        plan.get("stage_keepalive_preferred_request_class", "")
                    ),
                    "queue_semantic_state_id": str(plan.get("queue_semantic_state_id", "")),
                    "queue_gap_hint_ms": as_int(plan.get("queue_gap_hint_ms")),
                    "queue_hint_mask": as_int(plan.get("queue_hint_mask")),
                    "queue_preferred_request_class": str(plan.get("queue_preferred_request_class", "")),
                    "queue_retry_preferred_request_class": str(
                        plan.get("queue_retry_preferred_request_class", "")
                    ),
                    "queue_keepalive_preferred_request_class": str(
                        plan.get("queue_keepalive_preferred_request_class", "")
                    ),
                    "feedback_semantic_state_id": str(plan.get("feedback_semantic_state_id", "")),
                    "feedback_gap_hint_ms": as_int(plan.get("feedback_gap_hint_ms")),
                    "feedback_hint_mask": as_int(plan.get("feedback_hint_mask")),
                    "feedback_preferred_request_class": str(
                        plan.get("feedback_preferred_request_class", "")
                    ),
                    "feedback_retry_preferred_request_class": str(
                        plan.get("feedback_retry_preferred_request_class", "")
                    ),
                    "feedback_keepalive_preferred_request_class": str(
                        plan.get("feedback_keepalive_preferred_request_class", "")
                    ),
                    "feedback_request_class": str(plan.get("feedback_request_class", "")),
                    "feedback_response_class": str(plan.get("feedback_response_class", "")),
                    "feedback_session_phase": str(plan.get("feedback_session_phase", "")),
                    "requested_gap_delta_ms": as_int(plan.get("requested_gap_delta_ms")),
                    "active": bool_text(plan.get("active")),
                    "gap_expansion": bool_text(plan.get("gap_expansion")),
                    "gap_compression": bool_text(plan.get("gap_compression")),
                    "boundary_bisection": bool_text(plan.get("boundary_bisection")),
                    "keepalive_bias": bool_text(plan.get("keepalive_bias")),
                    "silence_window": bool_text(plan.get("silence_window")),
                    "retry_insertion": bool_text(plan.get("retry_insertion")),
                    "keepalive_insertion": bool_text(plan.get("keepalive_insertion")),
                    "keepalive_synthesized": bool_text(plan.get("keepalive_synthesized")),
                    "keepalive_contextual": bool_text(plan.get("keepalive_contextual")),
                    "keepalive_profile": str(plan.get("keepalive_profile", "")),
                    "retry_contextual": bool_text(plan.get("retry_contextual")),
                    "retry_profile": str(plan.get("retry_profile", "")),
                    "retry_source_request_class": str(plan.get("retry_source_request_class", "")),
                    "keepalive_anchor_request_class": str(
                        plan.get("keepalive_anchor_request_class", "")
                    ),
                    "cross_request_resend": bool_text(plan.get("cross_request_resend")),
                    "hybrid_keepalive_retry": bool_text(plan.get("hybrid_keepalive_retry")),
                    "insertion_count": as_int(plan.get("insertion_count")),
                    "base_message_count": as_int(plan.get("base_message_count")),
                    "message_count": as_int(plan.get("message_count")),
                    "poll_wait_base_ms": as_int(plan.get("poll_wait_base_ms")),
                    "poll_wait_override_ms": as_int(plan.get("poll_wait_override_ms")),
                    "tail_wait_ms": as_int(plan.get("tail_wait_ms")),
                    "pre_send_delay_ms": encode_compact_json(plan.get("pre_send_delay_ms", [])),
                    "injected_plan": encode_compact_json(plan.get("injected_plan", [])),
                }
            )

    for (campaign, subject, fuzzer, variant, property_id), group in sorted(property_groups.items()):
        slacks = [item.slack_ms for item in group if item.slack_ms is not None]
        negatives = sum(1 for item in group if item.verdict == "NEGATIVE")
        positives = sum(1 for item in group if item.verdict == "POSITIVE")
        inconclusive = sum(1 for item in group if item.verdict == "INCONCLUSIVE")
        tables["property_summary"].append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "property_id": property_id,
                "evaluations": len(group),
                "positive": positives,
                "negative": negatives,
                "inconclusive": inconclusive,
                "violation_rate": ratio(negatives, len(group)),
                "min_slack_ms": min(slacks) if slacks else "",
                "median_slack_ms": statistics.median(slacks) if slacks else "",
                "mean_slack_ms": statistics.fmean(slacks) if slacks else "",
            }
        )

    for (campaign, subject, fuzzer, variant, ablation), group in sorted(ablation_groups.items()):
        tables["ablation_summary"].append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "ablation": ablation,
                "runs": len({item.run_id for item in group}),
                "bugs_total": max((item.bugs_total for item in group), default=0),
                "violations_total": max((item.violations_total for item in group), default=0),
                "coverage_edges_max": max((item.coverage_edges for item in group), default=0),
                "yield_total": max((item.yield_total for item in group), default=0),
                "mean_execs_per_sec": statistics.fmean([item.execs_per_sec for item in group]) if group else 0,
                "mean_overhead_ratio": statistics.fmean([ratio(item.monitor_ms, item.target_ms) for item in group]) if group else 0,
            }
        )

    return tables


def write_csv_tables(tables: dict[str, list[dict[str, Any]]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, fields in CSV_FIELDS.items():
        with (out_dir / f"{name}.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in tables[name]:
                writer.writerow({field: row.get(field, "") for field in fields})


def write_parquet_tables(tables: dict[str, list[dict[str, Any]]], out_dir: Path) -> None:
    try:
        import pandas as pd  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Parquet output requires pandas and a Parquet engine such as pyarrow") from exc

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, fields in CSV_FIELDS.items():
        frame = pd.DataFrame(tables[name], columns=fields)
        frame.to_parquet(out_dir / f"{name}.parquet", index=False)


def read_csv_table(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def numeric(value: Any, default: float = 0.0) -> float:
    try:
        if value == "" or value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def is_monitor_ablation_variant(variant: Any) -> bool:
    return str(variant or "") in MONITOR_ABLATION_VARIANTS


def nested_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def feedback_frame(record: RawRecord) -> dict[str, Any]:
    return nested_dict(record.raw, "feedback_frame")


def feedback_channel(record: RawRecord, channel_name: str) -> dict[str, Any]:
    frame = feedback_frame(record)
    feedback = nested_dict(frame, "feedback")
    value = feedback.get(channel_name)
    return value if isinstance(value, dict) else {}


def timed_trace_event(record: RawRecord) -> dict[str, Any]:
    return nested_dict(record.raw, "timed_trace_event")


def timing_plan(record: RawRecord) -> dict[str, Any]:
    return nested_dict(record.raw, "timing_plan")


def encode_compact_json(value: Any) -> str:
    if value in ("", None):
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_compact_json(value: Any, default: Any) -> Any:
    if value in ("", None):
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def bool_text(value: Any) -> str:
    return "1" if bool(value) else "0"


def compact_text(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def color(index: int) -> str:
    palette = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2", "#4b5563"]
    return palette[index % len(palette)]


def svg_document(width: int, height: int, title: str, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        "<style>text{font-family:Arial,sans-serif;font-size:12px;fill:#111827}"
        ".title{font-size:18px;font-weight:700}.axis{stroke:#6b7280;stroke-width:1}"
        ".grid{stroke:#e5e7eb;stroke-width:1}.label{fill:#374151;font-size:11px}</style>\n"
        f'<rect width="100%" height="100%" fill="#ffffff"/>\n'
        f'<text class="title" x="24" y="30">{escape_xml(title)}</text>\n'
        f"{body}\n</svg>\n"
    )


def escape_xml(value: Any) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def scale(values: list[float], low: float, high: float) -> tuple[float, float, Any]:
    min_value = min(values) if values else 0.0
    max_value = max(values) if values else 1.0
    if math.isclose(min_value, max_value):
        max_value = min_value + 1.0

    def project(value: float) -> float:
        return low + (value - min_value) * (high - low) / (max_value - min_value)

    return min_value, max_value, project


def grouped(rows: Iterable[dict[str, str]], fields: list[str]) -> dict[tuple[str, ...], list[dict[str, str]]]:
    result: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        result[tuple(row.get(field, "") for field in fields)].append(row)
    return result


def plot_coverage(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    left, right, top, bottom = 70, 30, 55, 70
    groups = grouped(rows, ["fuzzer", "variant", "run_id"])
    all_x = [numeric(row["elapsed_sec"]) for row in rows]
    all_y = [numeric(row["coverage_edges"] or row["coverage_blocks"] or row["coverage_paths"]) for row in rows]
    _, _, x_project = scale(all_x, left, width - right)
    y_min, y_max, y_project_raw = scale(all_y, height - bottom, top)
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{height-25}">elapsed seconds</text>',
        f'<text class="label" x="18" y="{top+10}" transform="rotate(-90 18,{top+10})">coverage edges</text>',
        f'<text class="label" x="{left}" y="{top-8}">{y_max:.0f}</text>',
        f'<text class="label" x="{left}" y="{height-bottom+18}">{y_min:.0f}</text>',
    ]
    for index, (key, items) in enumerate(sorted(groups.items())):
        points = []
        for row in sorted(items, key=lambda item: numeric(item["elapsed_sec"])):
            x = x_project(numeric(row["elapsed_sec"]))
            y = y_project_raw(numeric(row["coverage_edges"] or row["coverage_blocks"] or row["coverage_paths"]))
            points.append(f"{x:.2f},{y:.2f}")
        if points:
            parts.append(f'<polyline fill="none" stroke="{color(index)}" stroke-width="2" points="{" ".join(points)}"/>')
            parts.append(f'<text class="label" x="{width-250}" y="{60 + index * 18}" fill="{color(index)}">{escape_xml("/".join(key))}</text>')
    out_path.write_text(svg_document(width, height, "Coverage Over Time", "\n".join(parts)), encoding="utf-8")


def plot_property_heatmap(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    properties = sorted({row["property_id"] for row in rows})
    variants = sorted({f'{row["fuzzer"]}/{row["variant"]}' for row in rows})
    cell_w = max(45, min(120, (width - 220) // max(1, len(variants))))
    cell_h = max(28, min(55, (height - 120) // max(1, len(properties))))
    lookup = {(row["property_id"], f'{row["fuzzer"]}/{row["variant"]}'): numeric(row["violation_rate"]) for row in rows}
    parts = []
    for y_index, prop in enumerate(properties):
        y = 75 + y_index * cell_h
        parts.append(f'<text class="label" x="24" y="{y + cell_h * 0.65:.1f}">{escape_xml(prop)}</text>')
        for x_index, variant in enumerate(variants):
            x = 170 + x_index * cell_w
            value = lookup.get((prop, variant), 0.0)
            red = int(255)
            green = int(245 - value * 170)
            blue = int(245 - value * 170)
            parts.append(f'<rect x="{x}" y="{y}" width="{cell_w-2}" height="{cell_h-2}" fill="rgb({red},{green},{blue})" stroke="#ffffff"/>')
            parts.append(f'<text class="label" x="{x + 8}" y="{y + cell_h * 0.65:.1f}">{value:.2f}</text>')
    for x_index, variant in enumerate(variants):
        x = 170 + x_index * cell_w + 5
        parts.append(f'<text class="label" x="{x}" y="62" transform="rotate(-35 {x},62)">{escape_xml(variant)}</text>')
    out_path.write_text(svg_document(width, height, "Property Violation Heatmap", "\n".join(parts)), encoding="utf-8")


def plot_semantic_state(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    left, right, top, bottom = 70, 30, 55, 70
    groups = grouped(rows, ["fuzzer", "variant", "run_id"])
    all_x = [numeric(row["elapsed_sec"]) for row in rows]
    all_y = [numeric(row["monitor_state_count"]) for row in rows]
    _, _, x_project = scale(all_x, left, width - right)
    _, y_max, y_project = scale(all_y, height - bottom, top)
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{height-25}">elapsed seconds</text>',
        f'<text class="label" x="18" y="{top+10}" transform="rotate(-90 18,{top+10})">semantic states</text>',
        f'<text class="label" x="{left}" y="{top-8}">{y_max:.0f}</text>',
    ]
    for index, (key, items) in enumerate(sorted(groups.items())):
        points = []
        for row in sorted(items, key=lambda item: numeric(item["elapsed_sec"])):
            points.append(f'{x_project(numeric(row["elapsed_sec"])):.2f},{y_project(numeric(row["monitor_state_count"])):.2f}')
        if points:
            parts.append(f'<polyline fill="none" stroke="{color(index)}" stroke-width="2" points="{" ".join(points)}"/>')
            parts.append(f'<text class="label" x="{width-250}" y="{60 + index * 18}">{escape_xml("/".join(key))}</text>')
    out_path.write_text(svg_document(width, height, "Semantic State Over Time", "\n".join(parts)), encoding="utf-8")


def plot_slack_ecdf(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    left, right, top, bottom = 70, 30, 55, 70
    slacks = sorted(numeric(row["slack_ms"]) for row in rows)
    _, _, x_project = scale(slacks or [0.0], left, width - right)
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{height-25}">slack ms</text>',
        f'<text class="label" x="18" y="{top+10}" transform="rotate(-90 18,{top+10})">ECDF</text>',
    ]
    if slacks:
        points = []
        n = len(slacks)
        for index, value in enumerate(slacks, start=1):
            points.append(f"{x_project(value):.2f},{height - bottom - (index / n) * (height - bottom - top):.2f}")
        parts.append(f'<polyline fill="none" stroke="#2563eb" stroke-width="2" points="{" ".join(points)}"/>')
    out_path.write_text(svg_document(width, height, "Slack ECDF", "\n".join(parts)), encoding="utf-8")


def plot_slack_violin(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    groups = grouped(rows, ["property_id"])
    all_values = [numeric(row["slack_ms"]) for row in rows]
    _, _, y_project = scale(all_values or [0.0], height - 70, 60)
    parts = [f'<line class="axis" x1="70" y1="{height-70}" x2="{width-30}" y2="{height-70}"/>']
    column_w = max(80, (width - 140) // max(1, len(groups)))
    for index, (key, items) in enumerate(sorted(groups.items())):
        values = [numeric(row["slack_ms"]) for row in items]
        if not values:
            continue
        bins = 12
        low, high = min(values), max(values)
        if math.isclose(low, high):
            high = low + 1
        counts = [0] * bins
        for value in values:
            slot = min(bins - 1, int((value - low) / (high - low) * bins))
            counts[slot] += 1
        max_count = max(counts) or 1
        center = 100 + index * column_w + column_w / 2
        polygon_left = []
        polygon_right = []
        for bin_index, count in enumerate(counts):
            y_value = low + (bin_index + 0.5) * (high - low) / bins
            y = y_project(y_value)
            half = 8 + 34 * count / max_count
            polygon_left.append(f"{center - half:.2f},{y:.2f}")
            polygon_right.append(f"{center + half:.2f},{y:.2f}")
        points = " ".join(polygon_left + list(reversed(polygon_right)))
        parts.append(f'<polygon points="{points}" fill="#dbeafe" stroke="#2563eb" stroke-width="1.5"/>')
        median = statistics.median(values)
        parts.append(f'<line x1="{center-38}" y1="{y_project(median):.2f}" x2="{center+38}" y2="{y_project(median):.2f}" stroke="#1d4ed8" stroke-width="2"/>')
        parts.append(f'<text class="label" x="{center-40}" y="{height-40}">{escape_xml(key[0])}</text>')
    out_path.write_text(svg_document(width, height, "Slack Violin", "\n".join(parts)), encoding="utf-8")


def plot_ablation_bar(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    left, top, bottom = 70, 55, 90
    labels = [row["ablation"] or row["variant"] for row in rows]
    values = [numeric(row["yield_total"] or row["bugs_total"] or row["violations_total"]) for row in rows]
    _, max_value, y_project = scale(values or [0.0], height - bottom, top)
    bar_w = max(28, min(80, (width - 130) // max(1, len(rows))))
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-30}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{top-8}">{max_value:.0f}</text>',
    ]
    for index, value in enumerate(values):
        x = left + 25 + index * (bar_w + 18)
        y = y_project(value)
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{height-bottom-y}" fill="{color(index)}"/>')
        parts.append(f'<text class="label" x="{x}" y="{height-55}" transform="rotate(-35 {x},{height-55})">{escape_xml(labels[index])}</text>')
        parts.append(f'<text class="label" x="{x}" y="{y-6}">{value:.0f}</text>')
    out_path.write_text(svg_document(width, height, "Ablation Yield Bar", "\n".join(parts)), encoding="utf-8")


def plot_overhead_yield(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 900, 520
    left, right, top, bottom = 70, 30, 55, 70
    xs = [numeric(row["overhead_ratio"]) for row in rows]
    ys = [numeric(row["yield_total"] or row["coverage_edges"]) for row in rows]
    _, x_max, x_project = scale(xs or [0.0], left, width - right)
    _, y_max, y_project = scale(ys or [0.0], height - bottom, top)
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{height-25}">monitor / target time</text>',
        f'<text class="label" x="18" y="{top+10}" transform="rotate(-90 18,{top+10})">yield</text>',
        f'<text class="label" x="{width-120}" y="{height-52}">{x_max:.2f}</text>',
        f'<text class="label" x="{left}" y="{top-8}">{y_max:.0f}</text>',
    ]
    for index, row in enumerate(rows):
        x = x_project(numeric(row["overhead_ratio"]))
        y = y_project(numeric(row["yield_total"] or row["coverage_edges"]))
        label = f'{row["fuzzer"]}/{row["variant"]}'
        parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="5" fill="{color(index)}"/>')
        parts.append(f'<text class="label" x="{x+7:.2f}" y="{y-7:.2f}">{escape_xml(label)}</text>')
    out_path.write_text(svg_document(width, height, "Overhead vs Yield", "\n".join(parts)), encoding="utf-8")


def plot_case_timeline(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 1000, max(360, 80 + len(rows) * 28)
    left, right, top = 160, 30, 55
    times = [numeric(row["start_sec"]) for row in rows] + [numeric(row["end_sec"]) for row in rows]
    _, _, x_project = scale(times or [0.0], left, width - right)
    parts = [f'<line class="axis" x1="{left}" y1="{height-40}" x2="{width-right}" y2="{height-40}"/>']
    outcome_colors = {"crash": "#dc2626", "violation": "#ea580c", "interesting": "#2563eb", "ok": "#16a34a"}
    for index, row in enumerate(sorted(rows, key=lambda item: (item["run_id"], numeric(item["start_sec"])))):
        y = top + index * 26
        start = x_project(numeric(row["start_sec"]))
        end = max(start + 3, x_project(numeric(row["end_sec"])))
        outcome = row["outcome"].lower() or "ok"
        fill = outcome_colors.get(outcome, "#6b7280")
        parts.append(f'<text class="label" x="18" y="{y+14}">{escape_xml(row["case_id"] or index)}</text>')
        parts.append(f'<rect x="{start:.2f}" y="{y}" width="{end-start:.2f}" height="16" fill="{fill}" opacity="0.85"/>')
        if row["property_id"]:
            parts.append(f'<text class="label" x="{end+5:.2f}" y="{y+13}">{escape_xml(row["property_id"])}</text>')
    out_path.write_text(svg_document(width, height, "Case Timeline", "\n".join(parts)), encoding="utf-8")


def plot_timing_hint_origin(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 980, 560
    left, top, bottom = 80, 55, 100
    variant_labels = sorted({f'{row["fuzzer"]}/{row["variant"]}' for row in rows}) or ["n/a"]
    origins = ["none", "feedback", "queue"]
    counts: dict[str, dict[str, int]] = {
        label: {origin: 0 for origin in origins} for label in variant_labels
    }
    for row in rows:
        label = f'{row["fuzzer"]}/{row["variant"]}'
        origin = (row.get("stage_hint_origin", "") or "none").lower()
        if origin not in counts[label]:
            counts[label][origin] = 0
        counts[label][origin] += 1

    max_value = max((value for origin_counts in counts.values() for value in origin_counts.values()), default=1)
    _, _, y_project = scale([0.0, float(max_value)], height - bottom, top)
    group_w = max(170, (width - left - 40) // max(1, len(variant_labels)))
    bar_w = max(26, min(56, group_w // 5))
    origin_colors = {"none": "#9ca3af", "feedback": "#2563eb", "queue": "#dc2626"}
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-30}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{top-8}">{max_value}</text>',
    ]
    for group_index, label in enumerate(variant_labels):
        group_x = left + 28 + group_index * group_w
        for origin_index, origin in enumerate(origins):
            value = counts[label].get(origin, 0)
            x = group_x + origin_index * (bar_w + 16)
            y = y_project(float(value))
            parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{height-bottom-y}" fill="{origin_colors[origin]}"/>')
            parts.append(f'<text class="label" x="{x}" y="{y-6}">{value}</text>')
            parts.append(f'<text class="label" x="{x-2}" y="{height-58}" transform="rotate(-35 {x-2},{height-58})">{origin}</text>')
        parts.append(f'<text class="label" x="{group_x}" y="{height-28}">{escape_xml(label)}</text>')

    legend_y = 58
    for legend_index, origin in enumerate(origins):
        lx = width - 260 + legend_index * 80
        parts.append(f'<rect x="{lx}" y="{legend_y-10}" width="14" height="14" fill="{origin_colors[origin]}"/>')
        parts.append(f'<text class="label" x="{lx+20}" y="{legend_y+2}">{origin}</text>')

    out_path.write_text(svg_document(width, height, "Timing Hint Origin Breakdown", "\n".join(parts)), encoding="utf-8")


def plot_time_to_first_violation(case_rows: list[dict[str, str]],
                                 time_rows: list[dict[str, str]],
                                 out_path: Path) -> None:
    width, height = 940, 540
    left, right, top, bottom = 80, 40, 55, 80
    run_groups: dict[str, dict[str, dict[str, float | bool]]] = defaultdict(dict)

    for row in time_rows:
        label = f'{row.get("fuzzer", "")}/{row.get("variant", "")}'
        run_id = row.get("run_id", "")
        if not label or not run_id:
            continue
        info = run_groups[label].setdefault(run_id, {"horizon": 0.0, "event": math.inf, "has_event": False})
        info["horizon"] = max(float(info["horizon"]), numeric(row.get("elapsed_sec", 0.0)))

    for row in case_rows:
        label = f'{row.get("fuzzer", "")}/{row.get("variant", "")}'
        run_id = row.get("run_id", "")
        if not label or not run_id:
            continue
        info = run_groups[label].setdefault(run_id, {"horizon": 0.0, "event": math.inf, "has_event": False})
        end_sec = numeric(row.get("end_sec", row.get("elapsed_sec", 0.0)))
        info["horizon"] = max(float(info["horizon"]), end_sec)
        outcome = (row.get("outcome", "") or "").lower()
        if outcome == "violation" or "violation" in outcome:
            info["event"] = min(float(info["event"]), end_sec)
            info["has_event"] = True

    max_time = max(
        (
            max(float(run["horizon"]), float(run["event"]) if bool(run["has_event"]) else 0.0)
            for runs in run_groups.values()
            for run in runs.values()
        ),
        default=1.0,
    )
    _, _, x_project = scale([0.0, max_time], left, width - right)
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{height-28}">elapsed seconds</text>',
        f'<text class="label" x="18" y="{top+10}" transform="rotate(-90 18,{top+10})">survival probability</text>',
        f'<text class="label" x="{left}" y="{top-8}">1.0</text>',
        f'<text class="label" x="{left}" y="{height-bottom+18}">0.0</text>',
    ]

    def y_project(value: float) -> float:
        return height - bottom - value * (height - bottom - top)

    for index, (label, runs) in enumerate(sorted(run_groups.items())):
        if not runs:
            continue
        time_events: dict[float, dict[str, int]] = defaultdict(lambda: {"event": 0, "censor": 0})
        for run in runs.values():
            horizon = float(run["horizon"])
            if bool(run["has_event"]):
                event_time = float(run["event"])
                time_events[event_time]["event"] += 1
            else:
                time_events[horizon]["censor"] += 1

        risk = len(runs)
        survival = 1.0
        prev_x = x_project(0.0)
        points = [f"{prev_x:.2f},{y_project(survival):.2f}"]
        for moment in sorted(time_events):
            x = x_project(moment)
            points.append(f"{x:.2f},{y_project(survival):.2f}")
            event_count = time_events[moment]["event"]
            censor_count = time_events[moment]["censor"]
            if risk > 0 and event_count > 0:
                survival *= (risk - event_count) / risk
                points.append(f"{x:.2f},{y_project(survival):.2f}")
            risk -= event_count + censor_count
        x_end = x_project(max_time)
        points.append(f"{x_end:.2f},{y_project(survival):.2f}")
        parts.append(
            f'<polyline fill="none" stroke="{color(index)}" stroke-width="2.5" points="{" ".join(points)}"/>'
        )
        parts.append(
            f'<text class="label" x="{width-260}" y="{60 + index * 18}" fill="{color(index)}">{escape_xml(label)}</text>'
        )

    out_path.write_text(
        svg_document(width, height, "Time-to-First-Violation Survival", "\n".join(parts)),
        encoding="utf-8",
    )


def plot_obligation_lifecycle(rows: list[dict[str, str]], out_path: Path) -> None:
    variant_groups = grouped(rows, ["fuzzer", "variant"])
    panel_count = max(1, len(variant_groups))
    width, panel_height = 980, 170
    height = 70 + panel_count * panel_height
    left, right = 90, 40
    global_max_time = max((numeric(row.get("elapsed_sec", 0.0)) for row in rows), default=1.0)
    _, _, x_project = scale([0.0, global_max_time], left, width - right)

    parts: list[str] = []
    if not variant_groups:
        out_path.write_text(svg_document(width, height, "Obligation Lifecycle Evolution", ""), encoding="utf-8")
        return

    for index, ((fuzzer, variant), items) in enumerate(sorted(variant_groups.items())):
        panel_top = 52 + index * panel_height
        panel_bottom = panel_top + 95
        label = f"{fuzzer}/{variant}"
        by_time: dict[float, dict[str, float]] = defaultdict(lambda: {"active": 0.0, "opened": 0.0, "satisfied": 0.0, "expired": 0.0})
        for row in items:
            elapsed = numeric(row.get("elapsed_sec", 0.0))
            bucket = by_time[elapsed]
            bucket["active"] = max(bucket["active"], numeric(row.get("active_obligation_count", 0.0)))
            bucket["opened"] += numeric(row.get("opened_now", 0.0))
            bucket["satisfied"] += numeric(row.get("satisfied_now", 0.0))
            bucket["expired"] += numeric(row.get("expired_now", 0.0))

        opened_cum = 0.0
        satisfied_cum = 0.0
        expired_cum = 0.0
        points_active: list[tuple[float, float]] = []
        points_opened: list[tuple[float, float]] = []
        points_satisfied: list[tuple[float, float]] = []
        points_expired: list[tuple[float, float]] = []
        local_max = 1.0
        for elapsed in sorted(by_time):
            bucket = by_time[elapsed]
            opened_cum += bucket["opened"]
            satisfied_cum += bucket["satisfied"]
            expired_cum += bucket["expired"]
            active = bucket["active"]
            local_max = max(local_max, active, opened_cum, satisfied_cum, expired_cum)
            points_active.append((elapsed, active))
            points_opened.append((elapsed, opened_cum))
            points_satisfied.append((elapsed, satisfied_cum))
            points_expired.append((elapsed, expired_cum))

        def local_y(value: float) -> float:
            return panel_bottom - value * (panel_bottom - panel_top) / local_max

        parts.append(f'<line class="axis" x1="{left}" y1="{panel_bottom}" x2="{width-right}" y2="{panel_bottom}"/>')
        parts.append(f'<line class="axis" x1="{left}" y1="{panel_top}" x2="{left}" y2="{panel_bottom}"/>')
        parts.append(f'<text class="label" x="24" y="{panel_top+12}">{escape_xml(label)}</text>')
        parts.append(f'<text class="label" x="{left}" y="{panel_top-6}">{local_max:.0f}</text>')
        parts.append(f'<text class="label" x="{width-120}" y="{panel_bottom+18}">elapsed s</text>')

        active_polygon = [f"{x_project(0.0):.2f},{panel_bottom:.2f}"]
        for elapsed, value in points_active:
            active_polygon.append(f"{x_project(elapsed):.2f},{local_y(value):.2f}")
        active_polygon.append(f"{x_project(global_max_time):.2f},{panel_bottom:.2f}")
        parts.append(
            f'<polygon points="{" ".join(active_polygon)}" fill="rgba(37,99,235,0.18)" stroke="none"/>'
        )

        def add_polyline(points: list[tuple[float, float]], stroke: str, stroke_width: float = 2.0) -> None:
            if not points:
                return
            coords = " ".join(f"{x_project(elapsed):.2f},{local_y(value):.2f}" for elapsed, value in points)
            parts.append(f'<polyline fill="none" stroke="{stroke}" stroke-width="{stroke_width}" points="{coords}"/>')

        add_polyline(points_active, "#2563eb", 2.5)
        add_polyline(points_opened, "#ea580c", 1.8)
        add_polyline(points_satisfied, "#16a34a", 1.8)
        add_polyline(points_expired, "#dc2626", 1.8)
        legend_x = width - 290
        legend_y = panel_top + 12
        legend = [
            ("active", "#2563eb"),
            ("opened+", "#ea580c"),
            ("satisfied+", "#16a34a"),
            ("expired+", "#dc2626"),
        ]
        for legend_index, (legend_label, legend_color) in enumerate(legend):
            lx = legend_x + legend_index * 65
            parts.append(f'<line x1="{lx}" y1="{legend_y}" x2="{lx+14}" y2="{legend_y}" stroke="{legend_color}" stroke-width="2"/>')
            parts.append(f'<text class="label" x="{lx+18}" y="{legend_y+4}">{legend_label}</text>')

    out_path.write_text(
        svg_document(width, height, "Obligation Lifecycle Evolution", "\n".join(parts)),
        encoding="utf-8",
    )


def plot_progress_coverage_bar(rows: list[dict[str, str]], out_path: Path) -> None:
    width, height = 960, 540
    left, top, bottom = 80, 55, 95
    variant_labels = sorted({f'{row.get("fuzzer", "")}/{row.get("variant", "")}' for row in rows if row.get("run_id", "")})
    coverage: dict[str, dict[str, Any]] = {
        label: {"bins": set(), "delta": 0} for label in variant_labels
    }
    for row in rows:
        label = f'{row.get("fuzzer", "")}/{row.get("variant", "")}'
        if label not in coverage:
            continue
        property_id = row.get("property_id", "")
        bins = parse_compact_json(row.get("newly_reached_progress_bins", ""), [])
        if not isinstance(bins, list) or not bins:
            bins = parse_compact_json(row.get("property_progress_vector", ""), [])
        for item in bins if isinstance(bins, list) else []:
            if isinstance(item, (int, float, str)):
                coverage[label]["bins"].add((property_id, str(item)))
        coverage[label]["delta"] += int(numeric(row.get("property_coverage_delta", 0.0)))

    values = [len(coverage[label]["bins"]) for label in variant_labels] or [0]
    _, max_value, y_project = scale([0.0, float(max(values) or 1)], height - bottom, top)
    bar_w = max(30, min(84, (width - 140) // max(1, len(variant_labels) * 2)))
    parts = [
        f'<line class="axis" x1="{left}" y1="{height-bottom}" x2="{width-30}" y2="{height-bottom}"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}"/>',
        f'<text class="label" x="{left}" y="{top-8}">{max_value:.0f}</text>',
        f'<text class="label" x="{left}" y="{height-28}">progress bins covered</text>',
    ]
    for index, label in enumerate(variant_labels):
        value = len(coverage[label]["bins"])
        x = left + 24 + index * (bar_w + 22)
        y = y_project(float(value))
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{height-bottom-y}" fill="{color(index)}"/>')
        parts.append(f'<text class="label" x="{x}" y="{y-6}">{value}</text>')
        parts.append(f'<text class="label" x="{x}" y="{y-20}">Δ{coverage[label]["delta"]}</text>')
        parts.append(
            f'<text class="label" x="{x}" y="{height-55}" transform="rotate(-35 {x},{height-55})">{escape_xml(label)}</text>'
        )
    out_path.write_text(
        svg_document(width, height, "Property Progress Coverage", "\n".join(parts)),
        encoding="utf-8",
    )


def plot_tables(table_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    required = {
        "coverage_over_time.svg": ("time_series.csv", plot_coverage),
        "property_heatmap.svg": ("property_summary.csv", plot_property_heatmap),
        "semantic_state_over_time.svg": ("semantic_state_series.csv", plot_semantic_state),
        "slack_ecdf.svg": ("slack_distribution.csv", plot_slack_ecdf),
        "slack_violin.svg": ("slack_distribution.csv", plot_slack_violin),
        "ablation_bar.svg": ("ablation_summary.csv", plot_ablation_bar),
        "overhead_vs_yield.svg": ("overhead_yield.csv", plot_overhead_yield),
        "case_timeline.svg": ("case_timeline.csv", plot_case_timeline),
        "timing_hint_origin.svg": ("timing_audit_series.csv", plot_timing_hint_origin),
        "obligation_lifecycle.svg": ("frontier_obligation_series.csv", plot_obligation_lifecycle),
        "progress_coverage_bar.svg": ("property_progress_series.csv", plot_progress_coverage_bar),
    }
    for output_name, (input_name, plotter) in required.items():
        rows = read_csv_table(table_dir / input_name)
        plotter(rows, out_dir / output_name)
    plot_time_to_first_violation(
        read_csv_table(table_dir / "case_timeline.csv"),
        read_csv_table(table_dir / "time_series.csv"),
        out_dir / "time_to_first_violation.svg",
    )


def read_optional_csv_table(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return read_csv_table(path)


def field_mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def field_median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def field_max(values: list[float]) -> float:
    return max(values) if values else 0.0


def coverage_value(row: dict[str, str]) -> float:
    return numeric(row.get("coverage_edges")) or numeric(row.get("coverage_blocks")) or numeric(row.get("coverage_paths"))


def bootstrap_ci(values: list[float],
                 *,
                 statistic_fn: Any = statistics.fmean,
                 samples: int = 1000,
                 confidence: float = 0.95,
                 seed: int = 1337) -> tuple[float | str, float | str]:
    if not values:
        return "", ""
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    estimates: list[float] = []
    n = len(values)
    for _ in range(max(100, samples)):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        estimates.append(float(statistic_fn(sample)))
    estimates.sort()
    alpha = max(0.0, min(1.0, (1.0 - confidence) / 2.0))
    low_index = min(len(estimates) - 1, max(0, int(alpha * len(estimates))))
    high_index = min(len(estimates) - 1, max(0, int((1.0 - alpha) * len(estimates)) - 1))
    return estimates[low_index], estimates[high_index]


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float | str, float | str]:
    if total <= 0:
        return "", ""
    p = successes / total
    denom = 1.0 + z * z / total
    centre = p + z * z / (2.0 * total)
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total)
    return (centre - margin) / denom, (centre + margin) / denom


def cliffs_delta(xs: list[float], ys: list[float]) -> float | str:
    if not xs or not ys:
        return ""
    greater = 0
    lower = 0
    for x in xs:
        for y in ys:
            if x > y:
                greater += 1
            elif x < y:
                lower += 1
    total = len(xs) * len(ys)
    return (greater - lower) / total if total else ""


def auto_reference_label(labels: Iterable[str], explicit_reference: str = "") -> str:
    ordered = sorted({label for label in labels if label})
    if explicit_reference and explicit_reference in ordered:
        return explicit_reference
    if "aflnet/aflnet-base" in ordered:
        return "aflnet/aflnet-base"
    baseline_like = [label for label in ordered if label.endswith("/baseline")]
    if baseline_like:
        return baseline_like[0]
    return ordered[0] if ordered else ""


def bootstrap_delta_mean_ci(xs: list[float],
                            ys: list[float],
                            *,
                            samples: int = 1000,
                            confidence: float = 0.95,
                            seed: int = 1337) -> tuple[float | str, float | str]:
    if not xs or not ys:
        return "", ""
    if len(xs) == 1 and len(ys) == 1:
        delta = xs[0] - ys[0]
        return delta, delta
    rng = random.Random(seed)
    n_x = len(xs)
    n_y = len(ys)
    estimates: list[float] = []
    for _ in range(max(100, samples)):
        sample_x = [xs[rng.randrange(n_x)] for _ in range(n_x)]
        sample_y = [ys[rng.randrange(n_y)] for _ in range(n_y)]
        estimates.append(statistics.fmean(sample_x) - statistics.fmean(sample_y))
    estimates.sort()
    alpha = max(0.0, min(1.0, (1.0 - confidence) / 2.0))
    low_index = min(len(estimates) - 1, max(0, int(alpha * len(estimates))))
    high_index = min(len(estimates) - 1, max(0, int((1.0 - alpha) * len(estimates)) - 1))
    return estimates[low_index], estimates[high_index]


def mann_whitney_u_test(xs: list[float], ys: list[float]) -> tuple[float | str, float | str]:
    if not xs or not ys:
        return "", ""
    combined = [(value, 0) for value in xs] + [(value, 1) for value in ys]
    combined.sort(key=lambda item: item[0])
    ranks: list[float] = [0.0] * len(combined)
    tie_counts: list[int] = []
    index = 0
    while index < len(combined):
        end = index + 1
        while end < len(combined) and combined[end][0] == combined[index][0]:
            end += 1
        avg_rank = (index + 1 + end) / 2.0
        for slot in range(index, end):
            ranks[slot] = avg_rank
        tie_counts.append(end - index)
        index = end

    n_x = len(xs)
    n_y = len(ys)
    rank_sum_x = sum(rank for rank, (_, group) in zip(ranks, combined) if group == 0)
    u_x = rank_sum_x - n_x * (n_x + 1) / 2.0
    u_y = n_x * n_y - u_x
    u_stat = min(u_x, u_y)

    total = n_x + n_y
    mu = n_x * n_y / 2.0
    tie_term = sum(count ** 3 - count for count in tie_counts if count > 1)
    if total <= 1:
        return u_stat, ""
    variance = n_x * n_y / 12.0 * ((total + 1) - tie_term / (total * (total - 1) or 1))
    if variance <= 0:
        return u_stat, 1.0
    sigma = math.sqrt(variance)
    correction = 0.5 if u_stat != mu else 0.0
    z = (u_stat - mu + correction if u_stat < mu else u_stat - mu - correction) / sigma
    p_value = math.erfc(abs(z) / math.sqrt(2.0))
    return u_stat, min(1.0, max(0.0, p_value))


def significance_tier(p_value: float | str) -> str:
    if p_value == "":
        return ""
    if p_value < 0.001:
        return "***"
    if p_value < 0.01:
        return "**"
    if p_value < 0.05:
        return "*"
    return "ns"


def stable_seed(parts: Iterable[Any], base: int = 1337) -> int:
    total = base
    for part in parts:
        for char in str(part):
            total = (total * 131 + ord(char)) % 2147483647
    return total


def latest_rows_by_run(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    latest: dict[tuple[str, str, str, str, str], dict[str, str]] = {}
    for row in rows:
        key = (
            row.get("campaign", ""),
            row.get("subject", ""),
            row.get("fuzzer", ""),
            row.get("variant", ""),
            row.get("run_id", ""),
        )
        if key not in latest or numeric(row.get("elapsed_sec")) >= numeric(latest[key].get("elapsed_sec")):
            latest[key] = row
    return list(latest.values())


def survival_run_rows(case_rows: list[dict[str, str]], time_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    runs: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in time_rows:
        key = (
            row.get("campaign", ""),
            row.get("subject", ""),
            row.get("fuzzer", ""),
            row.get("variant", ""),
            row.get("run_id", ""),
        )
        info = runs.setdefault(
            key,
            {
                "campaign": key[0],
                "subject": key[1],
                "fuzzer": key[2],
                "variant": key[3],
                "run_id": key[4],
                "horizon_sec": 0.0,
                "first_violation_sec": "",
                "observed": 0,
            },
        )
        info["horizon_sec"] = max(float(info["horizon_sec"]), numeric(row.get("elapsed_sec")))

    for row in case_rows:
        key = (
            row.get("campaign", ""),
            row.get("subject", ""),
            row.get("fuzzer", ""),
            row.get("variant", ""),
            row.get("run_id", ""),
        )
        info = runs.setdefault(
            key,
            {
                "campaign": key[0],
                "subject": key[1],
                "fuzzer": key[2],
                "variant": key[3],
                "run_id": key[4],
                "horizon_sec": 0.0,
                "first_violation_sec": "",
                "observed": 0,
            },
        )
        end_sec = numeric(row.get("end_sec", row.get("elapsed_sec")))
        info["horizon_sec"] = max(float(info["horizon_sec"]), end_sec)
        outcome = (row.get("outcome", "") or "").lower()
        if outcome == "violation" or "violation" in outcome:
            if not info["observed"] or end_sec < numeric(info["first_violation_sec"]):
                info["first_violation_sec"] = end_sec
            info["observed"] = 1

    return [runs[key] for key in sorted(runs)]


def survival_table_rows(run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped_runs: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        grouped_runs[(row["campaign"], row["subject"], row["fuzzer"], row["variant"])].append(row)

    output: list[dict[str, Any]] = []
    for (campaign, subject, fuzzer, variant), rows in sorted(grouped_runs.items()):
        events_by_time: dict[float, dict[str, int]] = defaultdict(lambda: {"events": 0, "censored": 0})
        for row in rows:
            if row["observed"]:
                events_by_time[float(row["first_violation_sec"])]["events"] += 1
            else:
                events_by_time[float(row["horizon_sec"])]["censored"] += 1

        at_risk = len(rows)
        survival = 1.0
        for moment in sorted(events_by_time):
            events = events_by_time[moment]["events"]
            censored = events_by_time[moment]["censored"]
            output.append(
                {
                    "campaign": campaign,
                    "subject": subject,
                    "fuzzer": fuzzer,
                    "variant": variant,
                    "runs_total": len(rows),
                    "time_sec": moment,
                    "at_risk": at_risk,
                    "events": events,
                    "censored": censored,
                    "survival_probability": survival if not events else survival * ((at_risk - events) / at_risk if at_risk else 0.0),
                }
            )
            if at_risk:
                survival *= (at_risk - events) / at_risk
            at_risk -= events + censored
    return output


def variant_overview_rows(time_rows: list[dict[str, str]],
                          semantic_rows: list[dict[str, str]],
                          run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest_time = latest_rows_by_run(time_rows)
    latest_semantic = latest_rows_by_run(semantic_rows)
    latest_time_groups = grouped(latest_time, ["campaign", "subject", "fuzzer", "variant"])
    latest_semantic_groups = grouped(latest_semantic, ["campaign", "subject", "fuzzer", "variant"])
    run_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        run_groups[(row["campaign"], row["subject"], row["fuzzer"], row["variant"])].append(row)

    output: list[dict[str, Any]] = []
    keys = set(latest_time_groups) | set(latest_semantic_groups) | set(run_groups)
    for key in sorted(keys):
        campaign, subject, fuzzer, variant = key
        time_group = latest_time_groups.get(key, [])
        semantic_group = latest_semantic_groups.get(key, [])
        run_group = run_groups.get(key, [])
        coverage_values = [coverage_value(row) for row in time_group]
        yield_values = [numeric(row.get("yield_total")) for row in time_group]
        violation_values = [numeric(row.get("violations_total")) for row in time_group]
        overhead_values = [numeric(row.get("overhead_ratio")) for row in time_group]
        semantic_values = [numeric(row.get("monitor_state_count")) for row in semantic_group]
        event_times = [float(row["first_violation_sec"]) for row in run_group if row["observed"] and row["first_violation_sec"] != ""]
        event_runs = len(event_times)
        runs = len(run_group) or max(len(time_group), len(semantic_group))
        output.append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "runs": runs,
                "event_runs": event_runs,
                "censored_runs": max(0, runs - event_runs),
                "event_fraction": ratio(event_runs, runs),
                "mean_final_coverage": field_mean(coverage_values),
                "median_final_coverage": field_median(coverage_values),
                "max_final_coverage": field_max(coverage_values),
                "mean_final_yield_total": field_mean(yield_values),
                "max_final_yield_total": field_max(yield_values),
                "mean_final_violations_total": field_mean(violation_values),
                "max_final_violations_total": field_max(violation_values),
                "mean_final_semantic_states": field_mean(semantic_values),
                "max_final_semantic_states": field_max(semantic_values),
                "mean_final_overhead_ratio": field_mean(overhead_values),
                "median_time_to_first_violation_sec": field_median(event_times) if event_times else "",
                "fastest_time_to_first_violation_sec": min(event_times) if event_times else "",
            }
        )
    return output


def run_metric_rows(time_rows: list[dict[str, str]],
                    semantic_rows: list[dict[str, str]],
                    run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest_time = latest_rows_by_run(time_rows)
    latest_semantic = latest_rows_by_run(semantic_rows)
    time_index = {
        (
            row.get("campaign", ""),
            row.get("subject", ""),
            row.get("fuzzer", ""),
            row.get("variant", ""),
            row.get("run_id", ""),
        ): row
        for row in latest_time
    }
    semantic_index = {
        (
            row.get("campaign", ""),
            row.get("subject", ""),
            row.get("fuzzer", ""),
            row.get("variant", ""),
            row.get("run_id", ""),
        ): row
        for row in latest_semantic
    }
    output: list[dict[str, Any]] = []
    for run in run_rows:
        key = (run["campaign"], run["subject"], run["fuzzer"], run["variant"], run["run_id"])
        time_row = time_index.get(key, {})
        semantic_row = semantic_index.get(key, {})
        output.append(
            {
                "campaign": run["campaign"],
                "subject": run["subject"],
                "fuzzer": run["fuzzer"],
                "variant": run["variant"],
                "label": f"{run['fuzzer']}/{run['variant']}",
                "run_id": run["run_id"],
                "final_coverage": coverage_value(time_row),
                "final_yield_total": numeric(time_row.get("yield_total")),
                "final_violations_total": numeric(time_row.get("violations_total")),
                "final_overhead_ratio": numeric(time_row.get("overhead_ratio")),
                "final_semantic_states": numeric(semantic_row.get("monitor_state_count")),
                "event_observed": int(run["observed"]),
                "first_violation_sec": "" if run["first_violation_sec"] == "" else float(run["first_violation_sec"]),
                "horizon_sec": float(run["horizon_sec"]),
            }
        )
    return output


def progress_obligation_summary_rows(progress_rows: list[dict[str, str]],
                                     frontier_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    progress_groups = grouped(progress_rows, ["campaign", "subject", "fuzzer", "variant"])
    frontier_groups = grouped(frontier_rows, ["campaign", "subject", "fuzzer", "variant"])
    keys = set(progress_groups) | set(frontier_groups)
    output: list[dict[str, Any]] = []
    for key in sorted(keys):
        campaign, subject, fuzzer, variant = key
        p_rows = progress_groups.get(key, [])
        f_rows = frontier_groups.get(key, [])
        bins: set[tuple[str, str]] = set()
        progress_delta_total = 0
        progress_events = 0
        for row in p_rows:
            payload = parse_compact_json(row.get("newly_reached_progress_bins", ""), [])
            if not isinstance(payload, list) or not payload:
                payload = parse_compact_json(row.get("property_progress_vector", ""), [])
            if not isinstance(payload, list):
                payload = []
            for item in payload:
                bins.add((row.get("property_id", ""), str(item)))
            delta = int(numeric(row.get("property_coverage_delta")))
            progress_delta_total += delta
            if delta > 0:
                progress_events += 1

        boundary_hits = sum(
            1 for row in f_rows if row.get("boundary_class", "") and row.get("boundary_class", "") != "stable"
        )
        min_slacks = [
            numeric(row.get("min_slack_ms"))
            for row in f_rows
            if row.get("min_slack_ms", "") not in {"", None}
        ]
        output.append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "runs": len({row.get("run_id", "") for row in p_rows + f_rows if row.get("run_id", "")}),
                "unique_progress_bins": len(bins),
                "progress_delta_total": progress_delta_total,
                "progress_events": progress_events,
                "peak_active_obligations": field_max([numeric(row.get("active_obligation_count")) for row in f_rows]),
                "opened_total": sum(numeric(row.get("opened_now")) for row in f_rows),
                "satisfied_total": sum(numeric(row.get("satisfied_now")) for row in f_rows),
                "expired_total": sum(numeric(row.get("expired_now")) for row in f_rows),
                "boundary_hits": boundary_hits,
                "boundary_hit_rate": ratio(boundary_hits, len(f_rows)),
                "min_slack_ms": min(min_slacks) if min_slacks else "",
            }
        )
    return output


def pooled_variant_summary_rows(run_metrics: list[dict[str, Any]],
                                progress_rows: list[dict[str, Any]],
                                timing_rows: list[dict[str, Any]],
                                *,
                                bootstrap_samples: int = 1000,
                                bootstrap_seed: int = 1337) -> list[dict[str, Any]]:
    progress_index = {
        (row["campaign"], row["subject"], row["fuzzer"], row["variant"]): row
        for row in progress_rows
    }
    timing_index = {
        (row["campaign"], row["subject"], row["fuzzer"], row["variant"]): row
        for row in timing_rows
    }
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in run_metrics:
        groups[(row["campaign"], row["fuzzer"], row["variant"])].append(row)

    output: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        campaign, fuzzer, variant = key
        subjects = sorted({row["subject"] for row in rows})
        coverage_values = [float(row["final_coverage"]) for row in rows]
        semantic_values = [float(row["final_semantic_states"]) for row in rows]
        overhead_values = [float(row["final_overhead_ratio"]) for row in rows]
        yield_values = [float(row["final_yield_total"]) for row in rows]
        violation_values = [float(row["final_violations_total"]) for row in rows]
        event_times = [float(row["first_violation_sec"]) for row in rows if row["first_violation_sec"] != ""]
        event_runs = sum(int(row["event_observed"]) for row in rows)
        event_low, event_high = wilson_interval(event_runs, len(rows))
        cov_low, cov_high = bootstrap_ci(
            coverage_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=bootstrap_seed + 1,
        )
        sem_low, sem_high = bootstrap_ci(
            semantic_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=bootstrap_seed + 2,
        )
        ov_low, ov_high = bootstrap_ci(
            overhead_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=bootstrap_seed + 3,
        )
        progress_subject_rows = [
            row for key2, row in progress_index.items() if key2[0] == campaign and key2[2] == fuzzer and key2[3] == variant
        ]
        timing_subject_rows = [
            row for key2, row in timing_index.items() if key2[0] == campaign and key2[2] == fuzzer and key2[3] == variant
        ]
        output.append(
            {
                "campaign": campaign,
                "fuzzer": fuzzer,
                "variant": variant,
                "subjects": len(subjects),
                "runs": len(rows),
                "event_runs": event_runs,
                "event_fraction": ratio(event_runs, len(rows)),
                "event_fraction_ci_low": event_low,
                "event_fraction_ci_high": event_high,
                "mean_final_coverage": field_mean(coverage_values),
                "coverage_ci_low": cov_low,
                "coverage_ci_high": cov_high,
                "mean_final_semantic_states": field_mean(semantic_values),
                "semantic_ci_low": sem_low,
                "semantic_ci_high": sem_high,
                "mean_final_overhead_ratio": field_mean(overhead_values),
                "overhead_ci_low": ov_low,
                "overhead_ci_high": ov_high,
                "mean_final_yield_total": field_mean(yield_values),
                "mean_final_violations_total": field_mean(violation_values),
                "median_time_to_first_violation_sec": field_median(event_times) if event_times else "",
                "fastest_time_to_first_violation_sec": min(event_times) if event_times else "",
                "mean_unique_progress_bins": field_mean([numeric(row.get("unique_progress_bins")) for row in progress_subject_rows]),
                "mean_boundary_hit_rate": field_mean([numeric(row.get("boundary_hit_rate")) for row in progress_subject_rows]),
                "mean_feedback_origin_rows": field_mean([numeric(row.get("feedback_origin_rows")) for row in timing_subject_rows]),
                "mean_queue_origin_rows": field_mean([numeric(row.get("queue_origin_rows")) for row in timing_subject_rows]),
            }
        )
    return output


def subject_variant_summary_rows(run_metrics: list[dict[str, Any]],
                                 progress_rows: list[dict[str, Any]],
                                 timing_rows: list[dict[str, Any]],
                                 *,
                                 bootstrap_samples: int = 1000,
                                 bootstrap_seed: int = 1337) -> list[dict[str, Any]]:
    progress_index = {
        (row["campaign"], row["subject"], row["fuzzer"], row["variant"]): row
        for row in progress_rows
    }
    timing_index = {
        (row["campaign"], row["subject"], row["fuzzer"], row["variant"]): row
        for row in timing_rows
    }
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in run_metrics:
        groups[(row["campaign"], row["subject"], row["fuzzer"], row["variant"])].append(row)

    output: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        campaign, subject, fuzzer, variant = key
        progress_row = progress_index.get(key, {})
        timing_row = timing_index.get(key, {})
        coverage_values = [float(row["final_coverage"]) for row in rows]
        semantic_values = [float(row["final_semantic_states"]) for row in rows]
        overhead_values = [float(row["final_overhead_ratio"]) for row in rows]
        yield_values = [float(row["final_yield_total"]) for row in rows]
        violation_values = [float(row["final_violations_total"]) for row in rows]
        event_times = [float(row["first_violation_sec"]) for row in rows if row["first_violation_sec"] != ""]
        event_runs = sum(int(row["event_observed"]) for row in rows)
        event_low, event_high = wilson_interval(event_runs, len(rows))
        cov_low, cov_high = bootstrap_ci(
            coverage_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=stable_seed((campaign, subject, fuzzer, variant, "coverage"), bootstrap_seed),
        )
        sem_low, sem_high = bootstrap_ci(
            semantic_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=stable_seed((campaign, subject, fuzzer, variant, "semantic"), bootstrap_seed),
        )
        ov_low, ov_high = bootstrap_ci(
            overhead_values,
            statistic_fn=statistics.fmean,
            samples=bootstrap_samples,
            seed=stable_seed((campaign, subject, fuzzer, variant, "overhead"), bootstrap_seed),
        )
        output.append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "runs": len(rows),
                "event_runs": event_runs,
                "event_fraction": ratio(event_runs, len(rows)),
                "event_fraction_ci_low": event_low,
                "event_fraction_ci_high": event_high,
                "mean_final_coverage": field_mean(coverage_values),
                "coverage_ci_low": cov_low,
                "coverage_ci_high": cov_high,
                "mean_final_semantic_states": field_mean(semantic_values),
                "semantic_ci_low": sem_low,
                "semantic_ci_high": sem_high,
                "mean_final_overhead_ratio": field_mean(overhead_values),
                "overhead_ci_low": ov_low,
                "overhead_ci_high": ov_high,
                "mean_final_yield_total": field_mean(yield_values),
                "mean_final_violations_total": field_mean(violation_values),
                "median_time_to_first_violation_sec": field_median(event_times) if event_times else "",
                "fastest_time_to_first_violation_sec": min(event_times) if event_times else "",
                "mean_unique_progress_bins": numeric(progress_row.get("unique_progress_bins")),
                "mean_boundary_hit_rate": numeric(progress_row.get("boundary_hit_rate")),
                "mean_feedback_origin_rows": numeric(timing_row.get("feedback_origin_rows")),
                "mean_queue_origin_rows": numeric(timing_row.get("queue_origin_rows")),
            }
        )
    return output


def monitor_ablation_summary_rows(subject_rows: list[dict[str, Any]],
                                  pooled_rows: list[dict[str, Any]],
                                  *,
                                  reference_variant: str = "full") -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def append_rows(scope: str, rows: list[dict[str, Any]]) -> None:
        if scope == "subject":
            groups = grouped(rows, ["campaign", "subject", "fuzzer"])
        else:
            groups = grouped(rows, ["campaign", "fuzzer"])

        for key, group_rows in sorted(groups.items()):
            if scope == "subject":
                campaign, subject, fuzzer = key
                subjects = 1
            else:
                campaign, fuzzer = key
                subject = "ALL"
                subjects = int(numeric(group_rows[0].get("subjects", 0)))

            row_by_variant = {
                str(row.get("variant", "")): row
                for row in group_rows
                if is_monitor_ablation_variant(row.get("variant", ""))
            }
            reference = row_by_variant.get(reference_variant)
            if not reference:
                continue

            for variant, row in sorted(row_by_variant.items()):
                output.append(
                    {
                        "campaign": campaign,
                        "scope": scope,
                        "subject": subject,
                        "fuzzer": fuzzer,
                        "variant": variant,
                        "reference_variant": reference_variant,
                        "subjects": subjects,
                        "runs": int(numeric(row.get("runs", 0))),
                        "event_fraction": numeric(row.get("event_fraction")),
                        "reference_event_fraction": numeric(reference.get("event_fraction")),
                        "delta_event_fraction": numeric(row.get("event_fraction")) - numeric(reference.get("event_fraction")),
                        "mean_final_coverage": numeric(row.get("mean_final_coverage")),
                        "reference_mean_final_coverage": numeric(reference.get("mean_final_coverage")),
                        "delta_mean_final_coverage": numeric(row.get("mean_final_coverage")) - numeric(reference.get("mean_final_coverage")),
                        "mean_final_semantic_states": numeric(row.get("mean_final_semantic_states")),
                        "reference_mean_final_semantic_states": numeric(reference.get("mean_final_semantic_states")),
                        "delta_mean_final_semantic_states": numeric(row.get("mean_final_semantic_states")) - numeric(reference.get("mean_final_semantic_states")),
                        "mean_final_yield_total": numeric(row.get("mean_final_yield_total")),
                        "reference_mean_final_yield_total": numeric(reference.get("mean_final_yield_total")),
                        "delta_mean_final_yield_total": numeric(row.get("mean_final_yield_total")) - numeric(reference.get("mean_final_yield_total")),
                        "mean_final_violations_total": numeric(row.get("mean_final_violations_total")),
                        "reference_mean_final_violations_total": numeric(reference.get("mean_final_violations_total")),
                        "delta_mean_final_violations_total": numeric(row.get("mean_final_violations_total")) - numeric(reference.get("mean_final_violations_total")),
                        "mean_unique_progress_bins": numeric(row.get("mean_unique_progress_bins")),
                        "reference_mean_unique_progress_bins": numeric(reference.get("mean_unique_progress_bins")),
                        "delta_mean_unique_progress_bins": numeric(row.get("mean_unique_progress_bins")) - numeric(reference.get("mean_unique_progress_bins")),
                        "mean_boundary_hit_rate": numeric(row.get("mean_boundary_hit_rate")),
                        "reference_mean_boundary_hit_rate": numeric(reference.get("mean_boundary_hit_rate")),
                        "delta_mean_boundary_hit_rate": numeric(row.get("mean_boundary_hit_rate")) - numeric(reference.get("mean_boundary_hit_rate")),
                        "mean_final_overhead_ratio": numeric(row.get("mean_final_overhead_ratio")),
                        "reference_mean_final_overhead_ratio": numeric(reference.get("mean_final_overhead_ratio")),
                        "delta_mean_final_overhead_ratio": numeric(row.get("mean_final_overhead_ratio")) - numeric(reference.get("mean_final_overhead_ratio")),
                        "mean_feedback_origin_rows": numeric(row.get("mean_feedback_origin_rows")),
                        "reference_mean_feedback_origin_rows": numeric(reference.get("mean_feedback_origin_rows")),
                        "delta_mean_feedback_origin_rows": numeric(row.get("mean_feedback_origin_rows")) - numeric(reference.get("mean_feedback_origin_rows")),
                        "mean_queue_origin_rows": numeric(row.get("mean_queue_origin_rows")),
                        "reference_mean_queue_origin_rows": numeric(reference.get("mean_queue_origin_rows")),
                        "delta_mean_queue_origin_rows": numeric(row.get("mean_queue_origin_rows")) - numeric(reference.get("mean_queue_origin_rows")),
                    }
                )

    append_rows("subject", subject_rows)
    append_rows("pooled", pooled_rows)
    return output


def pairwise_variant_comparison_rows(run_metrics: list[dict[str, Any]],
                                     explicit_reference: str = "",
                                     *,
                                     bootstrap_samples: int = 1000,
                                     bootstrap_seed: int = 1337) -> list[dict[str, Any]]:
    metric_fields = [
        ("final_coverage", "final_coverage"),
        ("final_semantic_states", "final_semantic_states"),
        ("final_overhead_ratio", "final_overhead_ratio"),
        ("event_observed", "event_observed"),
    ]
    output: list[dict[str, Any]] = []

    def append_group(scope: str, campaign: str, subject: str, rows: list[dict[str, Any]]) -> None:
        labels = sorted({row["label"] for row in rows if row.get("label")})
        reference = auto_reference_label(labels, explicit_reference)
        if not reference:
            return
        ref_rows = [row for row in rows if row["label"] == reference]
        for treatment in labels:
            if treatment == reference:
                continue
            treatment_rows = [row for row in rows if row["label"] == treatment]
            for metric_name, field_name in metric_fields:
                ref_values = [float(row[field_name]) for row in ref_rows if row.get(field_name, "") != ""]
                tr_values = [float(row[field_name]) for row in treatment_rows if row.get(field_name, "") != ""]
                delta = cliffs_delta(tr_values, ref_values)
                delta_ci_low, delta_ci_high = bootstrap_delta_mean_ci(
                    tr_values,
                    ref_values,
                    samples=bootstrap_samples,
                    seed=stable_seed((campaign, subject, treatment, metric_name), bootstrap_seed),
                )
                u_stat, p_value = mann_whitney_u_test(tr_values, ref_values)
                output.append(
                    {
                        "campaign": campaign,
                        "scope": scope,
                        "subject": subject,
                        "reference_label": reference,
                        "treatment_label": treatment,
                        "metric": metric_name,
                        "reference_n": len(ref_values),
                        "treatment_n": len(tr_values),
                        "reference_mean": field_mean(ref_values),
                        "treatment_mean": field_mean(tr_values),
                        "delta_mean": field_mean(tr_values) - field_mean(ref_values),
                        "delta_mean_ci_low": delta_ci_low,
                        "delta_mean_ci_high": delta_ci_high,
                        "mann_whitney_u": u_stat,
                        "mw_pvalue_two_sided": p_value,
                        "cliffs_delta": delta,
                        "a12": "" if delta == "" else (float(delta) + 1.0) / 2.0,
                        "significance_tier": significance_tier(p_value),
                    }
                )

    subject_groups = grouped(run_metrics, ["campaign", "subject"])
    for (campaign, subject), rows in sorted(subject_groups.items()):
        append_group("subject", campaign, subject, rows)

    pooled_groups = grouped(run_metrics, ["campaign"])
    for (campaign,), rows in sorted(pooled_groups.items()):
        append_group("pooled", campaign, "ALL", rows)

    return output


def timing_provenance_summary_rows(timing_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    groups = grouped(timing_rows, ["campaign", "subject", "fuzzer", "variant"])
    output: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        campaign, subject, fuzzer, variant = key
        output.append(
            {
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "timing_rows": len(rows),
                "active_timing_rows": sum(1 for row in rows if row.get("active") == "1"),
                "feedback_origin_rows": sum(1 for row in rows if row.get("stage_hint_origin") == "feedback"),
                "queue_origin_rows": sum(1 for row in rows if row.get("stage_hint_origin") == "queue"),
                "none_origin_rows": sum(1 for row in rows if (row.get("stage_hint_origin", "") or "none") == "none"),
                "retry_plan_rows": sum(1 for row in rows if row.get("retry_insertion") == "1"),
                "keepalive_plan_rows": sum(1 for row in rows if row.get("keepalive_insertion") == "1"),
                "silence_plan_rows": sum(1 for row in rows if row.get("silence_window") == "1"),
                "hybrid_plan_rows": sum(1 for row in rows if row.get("hybrid_keepalive_retry") == "1"),
                "boundary_bisection_rows": sum(1 for row in rows if row.get("boundary_bisection") == "1"),
            }
        )
    return output


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def build_figure_manifest(plot_dir: Path | None) -> list[dict[str, Any]]:
    figures = [
        ("coverage_over_time.svg", "Coverage Over Time", "overview", "baseline growth curve", "primary"),
        ("time_to_first_violation.svg", "Time-to-First-Violation Survival", "overview", "temporal bug-finding speed", "primary"),
        ("semantic_state_over_time.svg", "Semantic State Over Time", "protocol", "semantic-state expansion", "primary"),
        ("property_heatmap.svg", "Property Violation Heatmap", "property", "per-property violation concentration", "secondary"),
        ("slack_ecdf.svg", "Slack ECDF", "property", "boundary-band arrival speed", "secondary"),
        ("slack_violin.svg", "Slack Violin", "property", "boundary-distance distribution", "secondary"),
        ("progress_coverage_bar.svg", "Property Progress Coverage", "property", "progress-bin coverage by variant", "primary"),
        ("ablation_bar.svg", "Ablation Yield Bar", "overview", "ablation-side semantic yield", "secondary"),
        ("overhead_vs_yield.svg", "Overhead vs Yield", "overview", "monitor cost vs. yield tradeoff", "secondary"),
        ("case_timeline.svg", "Case Timeline", "trace", "single-case replay timeline", "primary"),
        ("obligation_lifecycle.svg", "Obligation Lifecycle Evolution", "frontier", "open/satisfy/expire obligation evolution", "primary"),
        ("timing_hint_origin.svg", "Timing Hint Origin Breakdown", "frontier", "feedback vs queue timing provenance", "primary"),
    ]
    manifest: list[dict[str, Any]] = []
    for filename, title, dashboard_view, analytical_role, paper_priority in figures:
        path = plot_dir / filename if plot_dir else None
        manifest.append(
            {
                "filename": filename,
                "title": title,
                "dashboard_view": dashboard_view,
                "analytical_role": analytical_role,
                "paper_priority": paper_priority,
                "available": bool(path and path.exists()),
                "path": str(path) if path else "",
            }
        )
    return manifest


def metric_value(value: Any, digits: int = 2) -> str:
    if value in {"", None}:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def metric_ci(low: Any, high: Any, digits: int = 2) -> str:
    if low in {"", None} or high in {"", None}:
        return "n/a"
    try:
        return f"[{float(low):.{digits}f}, {float(high):.{digits}f}]"
    except (TypeError, ValueError):
        return "n/a"


def variant_label(row: dict[str, Any]) -> str:
    return f"{row.get('fuzzer', '')}/{row.get('variant', '')}"


def sort_variant_rows(rows: Iterable[dict[str, Any]], reference_label: str = "") -> list[dict[str, Any]]:
    baseline = reference_label or auto_reference_label([variant_label(row) for row in rows])

    def sort_key(row: dict[str, Any]) -> tuple[int, str]:
        label = variant_label(row)
        return (0 if baseline and label == baseline else 1, label)

    return sorted(rows, key=sort_key)


def subject_metric_matrix(subject_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    metric_specs = [
        ("runs", "runs"),
        ("event_fraction", "event_fraction"),
        ("median_time_to_first_violation_sec", "median_ttfv_sec"),
        ("mean_final_coverage", "mean_final_coverage"),
        ("mean_final_semantic_states", "mean_final_semantic_states"),
        ("mean_final_overhead_ratio", "mean_final_overhead_ratio"),
        ("mean_unique_progress_bins", "mean_unique_progress_bins"),
        ("mean_boundary_hit_rate", "mean_boundary_hit_rate"),
    ]
    labels = sorted({variant_label(row) for row in subject_rows if variant_label(row)})
    fieldnames = ["campaign", "subject"]
    for label in labels:
        for source_field, column_suffix in metric_specs:
            fieldnames.append(f"{label}__{column_suffix}")

    grouped_rows = grouped(subject_rows, ["campaign", "subject"])
    output: list[dict[str, Any]] = []
    for (campaign, subject), rows in sorted(grouped_rows.items()):
        rendered = {"campaign": campaign, "subject": subject}
        for row in rows:
            label = variant_label(row)
            if not label:
                continue
            rendered[f"{label}__runs"] = row.get("runs", "")
            rendered[f"{label}__event_fraction"] = row.get("event_fraction", "")
            rendered[f"{label}__median_ttfv_sec"] = row.get("median_time_to_first_violation_sec", "")
            rendered[f"{label}__mean_final_coverage"] = row.get("mean_final_coverage", "")
            rendered[f"{label}__mean_final_semantic_states"] = row.get("mean_final_semantic_states", "")
            rendered[f"{label}__mean_final_overhead_ratio"] = row.get("mean_final_overhead_ratio", "")
            rendered[f"{label}__mean_unique_progress_bins"] = row.get("mean_unique_progress_bins", "")
            rendered[f"{label}__mean_boundary_hit_rate"] = row.get("mean_boundary_hit_rate", "")
        output.append(rendered)
    return output, fieldnames


def render_paper_tables_markdown(subject_rows: list[dict[str, Any]], reference_label: str = "") -> str:
    lines = ["# RVEM Subject Tables", "", "## Primary Metrics", ""]
    by_campaign = grouped(subject_rows, ["campaign"])
    for (campaign,), campaign_rows in sorted(by_campaign.items()):
        lines.extend(
            [
                f"### {campaign}",
                "",
                "| subject | variant | runs | event fraction (95% CI) | median first violation (s) | mean coverage (95% CI) | mean semantic states (95% CI) | mean overhead (95% CI) |",
                "| --- | --- | ---: | --- | ---: | --- | --- | --- |",
            ]
        )
        by_subject = grouped(campaign_rows, ["subject"])
        for (subject,), subject_group in sorted(by_subject.items()):
            for row in sort_variant_rows(subject_group, reference_label):
                lines.append(
                    f"| {subject} | {variant_label(row)} | {row['runs']} | "
                    f"{metric_value(row['event_fraction'])} {metric_ci(row['event_fraction_ci_low'], row['event_fraction_ci_high'])} | "
                    f"{metric_value(row['median_time_to_first_violation_sec'])} | "
                    f"{metric_value(row['mean_final_coverage'])} {metric_ci(row['coverage_ci_low'], row['coverage_ci_high'])} | "
                    f"{metric_value(row['mean_final_semantic_states'])} {metric_ci(row['semantic_ci_low'], row['semantic_ci_high'])} | "
                    f"{metric_value(row['mean_final_overhead_ratio'], 4)} {metric_ci(row['overhead_ci_low'], row['overhead_ci_high'], 4)} |"
                )
        lines.append("")

    lines.extend(
        [
            "## Auxiliary Metrics",
            "",
        ]
    )
    for (campaign,), campaign_rows in sorted(by_campaign.items()):
        lines.extend(
            [
                f"### {campaign}",
                "",
                "| subject | variant | mean progress bins | mean boundary hit rate | mean feedback-origin timing rows | mean queue-origin timing rows |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        by_subject = grouped(campaign_rows, ["subject"])
        for (subject,), subject_group in sorted(by_subject.items()):
            for row in sort_variant_rows(subject_group, reference_label):
                lines.append(
                    f"| {subject} | {variant_label(row)} | "
                    f"{metric_value(row['mean_unique_progress_bins'])} | "
                    f"{metric_value(row['mean_boundary_hit_rate'])} | "
                    f"{metric_value(row['mean_feedback_origin_rows'])} | "
                    f"{metric_value(row['mean_queue_origin_rows'])} |"
                )
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def latex_escape(text: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def render_paper_tables_latex(subject_rows: list[dict[str, Any]], reference_label: str = "") -> str:
    primary_lines = [
        "% Auto-generated by rvem_tools.py",
        "% Requires: \\usepackage{booktabs,longtable}",
        r"\begin{longtable}{llrrrrrr}",
        r"\caption{Subject-level primary Bi-ZoneFuzz++ metrics.}\\",
        r"\toprule",
        r"Subject & Variant & Runs & Event frac. & Median TTFV (s) & Mean cov. & Mean sem. & Overhead \\",
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        r"Subject & Variant & Runs & Event frac. & Median TTFV (s) & Mean cov. & Mean sem. & Overhead \\",
        r"\midrule",
        r"\endhead",
    ]
    auxiliary_lines = [
        "",
        r"\begin{longtable}{llrrrrr}",
        r"\caption{Subject-level auxiliary progress, boundary, and timing provenance metrics.}\\",
        r"\toprule",
        r"Subject & Variant & Progress bins & Boundary hit rate & Feedback timing rows & Queue timing rows \\",
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        r"Subject & Variant & Progress bins & Boundary hit rate & Feedback timing rows & Queue timing rows \\",
        r"\midrule",
        r"\endhead",
    ]
    by_campaign = grouped(subject_rows, ["campaign"])
    for (campaign,), campaign_rows in sorted(by_campaign.items()):
        primary_lines.append(rf"\multicolumn{{8}}{{l}}{{\textbf{{{latex_escape(campaign)}}}}} \\")
        by_subject = grouped(campaign_rows, ["subject"])
        for (subject,), subject_group in sorted(by_subject.items()):
            for row in sort_variant_rows(subject_group, reference_label):
                primary_lines.append(
                    " & ".join(
                        [
                            latex_escape(subject),
                            latex_escape(variant_label(row)),
                            str(row["runs"]),
                            metric_value(row["event_fraction"]),
                            metric_value(row["median_time_to_first_violation_sec"]),
                            metric_value(row["mean_final_coverage"]),
                            metric_value(row["mean_final_semantic_states"]),
                            metric_value(row["mean_final_overhead_ratio"], 4),
                        ]
                    ) + r" \\"
                )
        auxiliary_lines.append(rf"\multicolumn{{6}}{{l}}{{\textbf{{{latex_escape(campaign)}}}}} \\")
        by_subject = grouped(campaign_rows, ["subject"])
        for (subject,), subject_group in sorted(by_subject.items()):
            for row in sort_variant_rows(subject_group, reference_label):
                auxiliary_lines.append(
                    " & ".join(
                        [
                            latex_escape(subject),
                            latex_escape(variant_label(row)),
                            metric_value(row["mean_unique_progress_bins"]),
                            metric_value(row["mean_boundary_hit_rate"]),
                            metric_value(row["mean_feedback_origin_rows"]),
                            metric_value(row["mean_queue_origin_rows"]),
                        ]
                    ) + r" \\"
                )
    primary_lines.extend([r"\bottomrule", r"\end{longtable}"])
    auxiliary_lines.extend([r"\bottomrule", r"\end{longtable}", ""])
    return "\n".join(primary_lines + auxiliary_lines)


def render_report_markdown(variant_rows: list[dict[str, Any]],
                           subject_rows: list[dict[str, Any]],
                           pooled_rows: list[dict[str, Any]],
                           progress_rows: list[dict[str, Any]],
                           monitor_ablation_rows: list[dict[str, Any]],
                           pairwise_rows: list[dict[str, Any]],
                           timing_rows: list[dict[str, Any]],
                           figures: list[dict[str, Any]]) -> str:
    lines = [
        "# RVEM Paper Summary",
        "",
        "## Variant Overview",
        "",
        "| subject | variant | runs | event fraction | median first violation (s) | max coverage | max semantic states |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in variant_rows:
        lines.append(
            f"| {row['subject']} | {row['fuzzer']}/{row['variant']} | {row['runs']} | {row['event_fraction']:.2f} | "
            f"{row['median_time_to_first_violation_sec'] if row['median_time_to_first_violation_sec'] != '' else 'n/a'} | "
            f"{row['max_final_coverage']:.0f} | {row['max_final_semantic_states']:.0f} |"
        )

    lines.extend(
        [
            "",
            "## Subject Variant Summary",
            "",
            "| subject | variant | event fraction (95% CI) | mean coverage (95% CI) | mean semantic states (95% CI) | mean overhead ratio (95% CI) |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in subject_rows:
        lines.append(
            f"| {row['subject']} | {row['fuzzer']}/{row['variant']} | "
            f"{metric_value(row['event_fraction'])} {metric_ci(row['event_fraction_ci_low'], row['event_fraction_ci_high'])} | "
            f"{metric_value(row['mean_final_coverage'])} {metric_ci(row['coverage_ci_low'], row['coverage_ci_high'])} | "
            f"{metric_value(row['mean_final_semantic_states'])} {metric_ci(row['semantic_ci_low'], row['semantic_ci_high'])} | "
            f"{metric_value(row['mean_final_overhead_ratio'], 4)} {metric_ci(row['overhead_ci_low'], row['overhead_ci_high'], 4)} |"
        )

    lines.extend(
        [
            "",
            "## Pooled Variant Summary",
            "",
            "| variant | subjects | runs | event fraction | mean coverage | mean semantic states | mean overhead ratio |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in pooled_rows:
        lines.append(
            f"| {row['fuzzer']}/{row['variant']} | {row['subjects']} | {row['runs']} | {row['event_fraction']:.2f} | "
            f"{row['mean_final_coverage']:.2f} | {row['mean_final_semantic_states']:.2f} | {row['mean_final_overhead_ratio']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Monitor Ablation Delta vs Full",
            "",
        ]
    )
    subject_ablation_rows = [row for row in monitor_ablation_rows if row.get("scope") == "subject"]
    if subject_ablation_rows:
        lines.extend(
            [
                "| subject | variant | delta event fraction | delta coverage | delta semantic states | delta progress bins | delta boundary hit rate | delta overhead ratio |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in subject_ablation_rows:
            lines.append(
                f"| {row['subject']} | {row['fuzzer']}/{row['variant']} | {row['delta_event_fraction']:.2f} | "
                f"{row['delta_mean_final_coverage']:.2f} | {row['delta_mean_final_semantic_states']:.2f} | "
                f"{row['delta_mean_unique_progress_bins']:.2f} | {row['delta_mean_boundary_hit_rate']:.2f} | "
                f"{row['delta_mean_final_overhead_ratio']:.4f} |"
            )
    else:
        lines.append("No monitor ablation deltas are available for the current filtered dataset.")

    lines.extend(
        [
            "",
            "## Progress / Obligation Summary",
            "",
            "| subject | variant | progress bins | progress delta | peak obligations | expired | boundary hit rate |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in progress_rows:
        lines.append(
            f"| {row['subject']} | {row['fuzzer']}/{row['variant']} | {row['unique_progress_bins']} | {row['progress_delta_total']} | "
            f"{row['peak_active_obligations']:.0f} | {row['expired_total']:.0f} | {row['boundary_hit_rate']:.2f} |"
        )

    if timing_rows:
        lines.extend(
            [
                "",
                "## Timing Provenance Summary",
                "",
                "| subject | variant | active timing rows | feedback-origin | queue-origin | hybrid plans |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in timing_rows:
            lines.append(
                f"| {row['subject']} | {row['fuzzer']}/{row['variant']} | {row['active_timing_rows']} | "
                f"{row['feedback_origin_rows']} | {row['queue_origin_rows']} | {row['hybrid_plan_rows']} |"
            )

    lines.extend(
        [
            "",
            "## Pairwise Variant Comparisons",
            "",
        ]
    )
    if pairwise_rows:
        lines.extend(
            [
                "| scope | subject | reference | treatment | metric | delta mean | delta CI | MW p | Cliff's delta | A12 | sig |",
                "| --- | --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in pairwise_rows:
            lines.append(
                f"| {row['scope']} | {row['subject']} | {row['reference_label']} | {row['treatment_label']} | "
                f"{row['metric']} | {row['delta_mean']:.4f} | "
                f"[{row['delta_mean_ci_low'] if row['delta_mean_ci_low'] != '' else 'n/a'}, {row['delta_mean_ci_high'] if row['delta_mean_ci_high'] != '' else 'n/a'}] | "
                f"{row['mw_pvalue_two_sided'] if row['mw_pvalue_two_sided'] != '' else 'n/a'} | "
                f"{row['cliffs_delta'] if row['cliffs_delta'] != '' else 'n/a'} | "
                f"{row['a12'] if row['a12'] != '' else 'n/a'} | {row['significance_tier'] or 'n/a'} |"
            )
    else:
        lines.append("No pairwise comparisons are available for the current filtered dataset.")

    lines.extend(["", "## Figure Bundle", ""])
    for figure in figures:
        status = "available" if figure["available"] else "missing"
        lines.append(f"- `{figure['filename']}`: {figure['title']} ({figure['dashboard_view']}, {status})")
    lines.append("")
    return "\n".join(lines)


def write_report_bundle(table_dir: Path,
                        out_dir: Path,
                        plot_dir: Path | None = None,
                        *,
                        reference_label: str = "",
                        bootstrap_samples: int = 1000,
                        bootstrap_seed: int = 1337) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    time_rows = read_optional_csv_table(table_dir / "time_series.csv")
    semantic_rows = read_optional_csv_table(table_dir / "semantic_state_series.csv")
    case_rows = read_optional_csv_table(table_dir / "case_timeline.csv")
    progress_rows = read_optional_csv_table(table_dir / "property_progress_series.csv")
    frontier_rows = read_optional_csv_table(table_dir / "frontier_obligation_series.csv")
    timing_rows = read_optional_csv_table(table_dir / "timing_audit_series.csv")

    survival_runs = survival_run_rows(case_rows, time_rows)
    survival_rows = survival_table_rows(survival_runs)
    variant_rows = variant_overview_rows(time_rows, semantic_rows, survival_runs)
    metric_rows = run_metric_rows(time_rows, semantic_rows, survival_runs)
    progress_summary_rows = progress_obligation_summary_rows(progress_rows, frontier_rows)
    timing_summary_rows = timing_provenance_summary_rows(timing_rows)
    subject_rows = subject_variant_summary_rows(
        metric_rows,
        progress_summary_rows,
        timing_summary_rows,
        bootstrap_samples=bootstrap_samples,
        bootstrap_seed=bootstrap_seed,
    )
    pooled_rows = pooled_variant_summary_rows(
        metric_rows,
        progress_summary_rows,
        timing_summary_rows,
        bootstrap_samples=bootstrap_samples,
        bootstrap_seed=bootstrap_seed,
    )
    monitor_ablation_rows = monitor_ablation_summary_rows(subject_rows, pooled_rows)
    pairwise_rows = pairwise_variant_comparison_rows(
        metric_rows,
        reference_label,
        bootstrap_samples=bootstrap_samples,
        bootstrap_seed=bootstrap_seed,
    )
    subject_matrix_rows, subject_matrix_fields = subject_metric_matrix(subject_rows)
    figure_manifest = build_figure_manifest(plot_dir)

    write_csv(out_dir / "variant_overview.csv", variant_rows, REPORT_SCHEMA["files"]["variant_overview.csv"])
    write_csv(out_dir / "survival_table.csv", survival_rows, REPORT_SCHEMA["files"]["survival_table.csv"])
    write_csv(
        out_dir / "progress_obligation_summary.csv",
        progress_summary_rows,
        REPORT_SCHEMA["files"]["progress_obligation_summary.csv"],
    )
    write_csv(
        out_dir / "subject_variant_summary.csv",
        subject_rows,
        REPORT_SCHEMA["files"]["subject_variant_summary.csv"],
    )
    write_csv(
        out_dir / "pooled_variant_summary.csv",
        pooled_rows,
        REPORT_SCHEMA["files"]["pooled_variant_summary.csv"],
    )
    write_csv(
        out_dir / "monitor_ablation_summary.csv",
        monitor_ablation_rows,
        REPORT_SCHEMA["files"]["monitor_ablation_summary.csv"],
    )
    write_csv(
        out_dir / "pairwise_variant_comparison.csv",
        pairwise_rows,
        REPORT_SCHEMA["files"]["pairwise_variant_comparison.csv"],
    )
    write_csv(
        out_dir / "timing_provenance_summary.csv",
        timing_summary_rows,
        REPORT_SCHEMA["files"]["timing_provenance_summary.csv"],
    )
    write_csv(out_dir / "subject_metric_matrix.csv", subject_matrix_rows, subject_matrix_fields)
    (out_dir / "figure_manifest.json").write_text(
        json.dumps({"schema_version": REPORT_SCHEMA["schema_version"], "figures": figure_manifest}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "paper_summary.md").write_text(
        render_report_markdown(
            variant_rows,
            subject_rows,
            pooled_rows,
            progress_summary_rows,
            monitor_ablation_rows,
            pairwise_rows,
            timing_summary_rows,
            figure_manifest,
        ),
        encoding="utf-8",
    )
    (out_dir / "paper_tables.md").write_text(
        render_paper_tables_markdown(subject_rows, reference_label),
        encoding="utf-8",
    )
    (out_dir / "paper_tables.tex").write_text(
        render_paper_tables_latex(subject_rows, reference_label),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": REPORT_SCHEMA["schema_version"],
        "table_dir": str(table_dir),
        "plot_dir": str(plot_dir) if plot_dir else "",
        "reference_label": reference_label or "auto",
        "bootstrap_samples": bootstrap_samples,
        "bootstrap_seed": bootstrap_seed,
        "generated_files": {
            "variant_overview_csv": str(out_dir / "variant_overview.csv"),
            "survival_table_csv": str(out_dir / "survival_table.csv"),
            "progress_obligation_summary_csv": str(out_dir / "progress_obligation_summary.csv"),
            "subject_variant_summary_csv": str(out_dir / "subject_variant_summary.csv"),
            "pooled_variant_summary_csv": str(out_dir / "pooled_variant_summary.csv"),
            "monitor_ablation_summary_csv": str(out_dir / "monitor_ablation_summary.csv"),
            "pairwise_variant_comparison_csv": str(out_dir / "pairwise_variant_comparison.csv"),
            "timing_provenance_summary_csv": str(out_dir / "timing_provenance_summary.csv"),
            "subject_metric_matrix_csv": str(out_dir / "subject_metric_matrix.csv"),
            "figure_manifest_json": str(out_dir / "figure_manifest.json"),
            "paper_summary_md": str(out_dir / "paper_summary.md"),
            "paper_tables_md": str(out_dir / "paper_tables.md"),
            "paper_tables_tex": str(out_dir / "paper_tables.tex"),
        },
        "figure_count": len(figure_manifest),
        "variant_count": len(variant_rows),
        "subject_variant_count": len(subject_rows),
        "subject_matrix_rows": len(subject_matrix_rows),
        "pooled_variant_count": len(pooled_rows),
        "monitor_ablation_rows": len(monitor_ablation_rows),
        "pairwise_rows": len(pairwise_rows),
    }
    (out_dir / "report_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def csv_header_and_count(path: Path) -> tuple[list[str], int]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        header = list(reader.fieldnames or [])
        count = sum(1 for _ in reader)
    return header, count


def file_audit_entry(path: Path) -> dict[str, Any]:
    exists = path.exists()
    size = path.stat().st_size if exists else 0
    return {
        "path": str(path),
        "exists": exists,
        "size_bytes": size,
        "nonempty_file": exists and size > 0,
    }


def audit_csv_file(path: Path,
                   required_fields: list[str] | None = None) -> dict[str, Any]:
    entry = file_audit_entry(path)
    entry["row_count"] = 0
    entry["header"] = []
    entry["missing_fields"] = []
    if not entry["exists"]:
        return entry

    header, row_count = csv_header_and_count(path)
    entry["row_count"] = row_count
    entry["header"] = header
    if required_fields:
        entry["missing_fields"] = [field for field in required_fields if field not in header]
    return entry


def audit_rvem_artifacts(table_dir: Path,
                         plot_dir: Path | None,
                         report_dir: Path | None,
                         dashboard_html: Path | None,
                         *,
                         require_data: bool = False) -> dict[str, Any]:
    problems: list[str] = []
    warnings: list[str] = []

    table_entries: dict[str, dict[str, Any]] = {}
    for table_name, fields in CSV_FIELDS.items():
        filename = f"{table_name}.csv"
        entry = audit_csv_file(table_dir / filename, fields)
        table_entries[filename] = entry
        if not entry["exists"]:
            problems.append(f"missing aggregated table: {entry['path']}")
        elif entry["missing_fields"]:
            problems.append(f"aggregated table {filename} missing fields: {entry['missing_fields']}")

    for filename in REQUIRED_EVIDENCE_TABLES:
        entry = table_entries.get(filename)
        if not entry or not entry["exists"]:
            continue
        if entry["row_count"] == 0:
            message = f"evidence table {filename} has zero rows"
            if require_data:
                problems.append(message)
            else:
                warnings.append(message)

    figure_entries: dict[str, dict[str, Any]] = {}
    for figure in build_figure_manifest(plot_dir):
        path_text = str(figure.get("path", ""))
        path = Path(path_text) if path_text else None
        entry = {
            **figure,
            "exists": bool(path is not None and path.exists()),
            "size_bytes": path.stat().st_size if path is not None and path.exists() else 0,
        }
        entry["nonempty_file"] = entry["exists"] and entry["size_bytes"] > 0
        figure_entries[figure["filename"]] = entry
        if figure["filename"] in REQUIRED_PAPER_FIGURES and not entry["nonempty_file"]:
            problems.append(f"missing or empty paper figure: {figure['filename']}")

    report_entries: dict[str, dict[str, Any]] = {}
    if report_dir is not None:
        fixed_report_fields = REPORT_SCHEMA["files"]
        for filename in REQUIRED_REPORT_FILES:
            path = report_dir / filename
            report_fields = fixed_report_fields.get(filename)
            if isinstance(report_fields, list):
                entry = audit_csv_file(path, report_fields)
            elif filename == "subject_metric_matrix.csv":
                entry = audit_csv_file(path)
            else:
                entry = file_audit_entry(path)
            report_entries[filename] = entry
            if not entry["exists"]:
                problems.append(f"missing report artifact: {entry['path']}")
            elif not entry["nonempty_file"]:
                problems.append(f"empty report artifact: {entry['path']}")
            elif entry.get("missing_fields"):
                problems.append(f"report artifact {filename} missing fields: {entry['missing_fields']}")
    else:
        warnings.append("report directory was not provided; report artifact files were not audited")

    report_manifest: dict[str, Any] = {}
    if report_dir is not None and (report_dir / "report_manifest.json").exists():
        report_manifest = json.loads((report_dir / "report_manifest.json").read_text(encoding="utf-8"))
        generated_files = report_manifest.get("generated_files", {})
        for key, value in sorted(generated_files.items()):
            if value and not Path(value).exists():
                problems.append(f"report manifest points to missing generated file {key}: {value}")

    report_figure_manifest: dict[str, Any] = {}
    if report_dir is not None and (report_dir / "figure_manifest.json").exists():
        report_figure_manifest = json.loads((report_dir / "figure_manifest.json").read_text(encoding="utf-8"))
        manifest_figures = {
            item.get("filename", ""): item
            for item in report_figure_manifest.get("figures", [])
        }
        for filename in REQUIRED_PAPER_FIGURES:
            item = manifest_figures.get(filename)
            if not item:
                problems.append(f"report figure manifest missing figure entry: {filename}")
            elif not item.get("available"):
                problems.append(f"report figure manifest marks required figure unavailable: {filename}")

    dashboard_entry: dict[str, Any] = {}
    if dashboard_html is not None:
        dashboard_entry = file_audit_entry(dashboard_html)
        dashboard_entry["missing_views"] = []
        if not dashboard_entry["exists"]:
            problems.append(f"missing dashboard artifact: {dashboard_entry['path']}")
        elif not dashboard_entry["nonempty_file"]:
            problems.append(f"empty dashboard artifact: {dashboard_entry['path']}")
        else:
            html_text = html.unescape(dashboard_html.read_text(encoding="utf-8", errors="replace"))
            dashboard_entry["missing_views"] = [
                view for view in REQUIRED_DASHBOARD_VIEWS if view not in html_text
            ]
            if dashboard_entry["missing_views"]:
                problems.append(f"dashboard missing required views: {dashboard_entry['missing_views']}")
    else:
        warnings.append("dashboard HTML was not provided; interactive dashboard was not audited")

    return {
        "schema_version": "rvem.artifact_audit.v1",
        "complete": not problems,
        "require_data": require_data,
        "problem_count": len(problems),
        "warning_count": len(warnings),
        "problems": problems,
        "warnings": warnings,
        "inputs": {
            "table_dir": str(table_dir),
            "plot_dir": str(plot_dir) if plot_dir else "",
            "report_dir": str(report_dir) if report_dir else "",
            "dashboard_html": str(dashboard_html) if dashboard_html else "",
        },
        "tables": table_entries,
        "figures": figure_entries,
        "reports": report_entries,
        "dashboard": dashboard_entry,
        "report_manifest": report_manifest,
        "report_figure_manifest": report_figure_manifest,
    }


def path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_regular_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
        for item in sorted(path.rglob("*")):
            if item.is_file():
                yield item


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(1, 10000):
        candidate = path.with_name(f"{stem}.{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not allocate unique destination under {path.parent}")


def package_add_path(package_root: Path,
                     role: str,
                     source: Path | None,
                     destination_subdir: str,
                     *,
                     required: bool,
                     problems: list[str],
                     warnings: list[str]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "role": role,
        "source_path": str(source) if source else "",
        "destination_subdir": destination_subdir,
        "required": required,
        "exists": False,
        "copied_file_count": 0,
        "total_size_bytes": 0,
        "files": [],
    }
    if source is None:
        if required:
            problems.append(f"missing required package input: {role}")
        else:
            warnings.append(f"optional package input was not provided: {role}")
        return entry

    source = source.resolve()
    entry["source_path"] = str(source)
    if not source.exists():
        if required:
            problems.append(f"missing required package input {role}: {source}")
        else:
            warnings.append(f"optional package input {role} does not exist: {source}")
        return entry

    entry["exists"] = True
    payload_root = package_root / "payload" / destination_subdir
    files = list(iter_regular_files(source))
    if not files:
        message = f"package input {role} has no regular files: {source}"
        if required:
            problems.append(message)
        else:
            warnings.append(message)
        return entry

    for source_file in files:
        if source.is_dir():
            relative = source_file.relative_to(source)
            destination = payload_root / relative
        else:
            destination = unique_destination(payload_root / source_file.name)
        if not path_is_relative_to(source_file, package_root):
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)
            packaged_path = destination
        else:
            packaged_path = source_file

        relative_package_path = packaged_path.relative_to(package_root)
        size = packaged_path.stat().st_size
        entry["files"].append(
            {
                "source_path": str(source_file),
                "package_path": str(relative_package_path),
                "size_bytes": size,
                "sha256": sha256_file(packaged_path),
            }
        )
        entry["copied_file_count"] += 1
        entry["total_size_bytes"] += size

    return entry


def read_optional_json(path: Path | None,
                       role: str,
                       *,
                       required: bool,
                       problems: list[str],
                       warnings: list[str]) -> dict[str, Any]:
    if path is None:
        if required:
            problems.append(f"missing required JSON input: {role}")
        else:
            warnings.append(f"optional JSON input was not provided: {role}")
        return {}
    if not path.is_file():
        if required:
            problems.append(f"missing required JSON input {role}: {path}")
        else:
            warnings.append(f"optional JSON input {role} does not exist: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        problems.append(f"invalid JSON input {role}: {path}: {exc}")
        return {}


def write_package_readme(package_root: Path,
                         manifest: dict[str, Any],
                         *,
                         notes: list[str],
                         limitations: list[str]) -> Path:
    lines = [
        "# Bi-ZoneFuzz++ RVEM Reproducibility Package",
        "",
        "This directory is a packaging layer over existing Bi-ZoneFuzz++ evidence artifacts.",
        "It preserves RVEM tables, figures, reports, dashboard files, audit JSON, result-audit files, and optional review/stage evidence with SHA-256 checksums.",
        "",
        "The package is intentionally conservative: a copied file proves only that the file was present when packaging ran.",
        "Campaign-scale claims still require the included result audit and RVEM artifact audit to prove the relevant run count, coverage, monitor feedback, timing artifacts, and data completeness.",
        "",
        "## Key Files",
        "",
        "- `artifact_package_manifest.json`: machine-readable package inventory, gates, warnings, and problems.",
        "- `checksums.sha256`: SHA-256 checksums for every packaged payload file.",
        "- `payload/`: copied evidence files grouped by role.",
        "",
        "## Gate Summary",
        "",
        f"- Package gate passed: `{str(manifest.get('gate_passed', False)).lower()}`",
        f"- Problem count: `{manifest.get('problem_count', 0)}`",
        f"- Warning count: `{manifest.get('warning_count', 0)}`",
        "",
        "## Notes",
        "",
    ]
    if notes:
        lines.extend(f"- {item}" for item in notes)
    else:
        lines.append("- No user notes were provided.")
    lines.extend(["", "## Limitations", ""])
    if limitations:
        lines.extend(f"- {item}" for item in limitations)
    else:
        lines.append("- No additional limitations were detected by the packaging command.")
    lines.append("")
    path = package_root / "README.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_package_checksums(package_root: Path, artifact_entries: list[dict[str, Any]]) -> Path:
    rows: list[str] = []
    for entry in artifact_entries:
        for file_entry in entry.get("files", []):
            rows.append(f"{file_entry['sha256']}  {file_entry['package_path']}")
    rows.sort()
    path = package_root / "checksums.sha256"
    path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return path


def build_repro_package(args: argparse.Namespace) -> dict[str, Any]:
    package_root = Path(args.out_dir).resolve()
    package_root.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    warnings: list[str] = []
    notes = list(args.note or [])

    rvem_audit_path = Path(args.rvem_audit_json).resolve() if args.rvem_audit_json else None
    result_audit_path = Path(args.result_audit_json).resolve() if args.result_audit_json else None
    rvem_audit = read_optional_json(
        rvem_audit_path,
        "rvem_artifact_audit",
        required=args.require_rvem_audit_complete,
        problems=problems,
        warnings=warnings,
    )
    result_audit = read_optional_json(
        result_audit_path,
        "profuzzbench_result_audit",
        required=args.require_result_audit_gate,
        problems=problems,
        warnings=warnings,
    )

    if args.require_rvem_audit_complete and rvem_audit:
        if rvem_audit.get("schema_version") != "rvem.artifact_audit.v1":
            problems.append("RVEM artifact audit has an unsupported schema_version")
        if rvem_audit.get("complete") is not True or int(rvem_audit.get("problem_count", 0) or 0) != 0:
            problems.append("RVEM artifact audit is not complete")
    if args.require_result_audit_gate and result_audit:
        if result_audit.get("schema_version") != "bizonefuzz.profuzzbench.result_audit.v1":
            problems.append("ProFuzzBench result audit has an unsupported schema_version")
        if result_audit.get("gate_passed") is not True:
            problems.append("ProFuzzBench result audit gate did not pass")

    artifact_entries: list[dict[str, Any]] = []
    artifact_entries.append(
        package_add_path(
            package_root,
            "rvem_tables",
            Path(args.table_dir) if args.table_dir else None,
            "rvem/tables",
            required=args.require_core,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "rvem_plots",
            Path(args.plot_dir) if args.plot_dir else None,
            "rvem/plots",
            required=args.require_core,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "rvem_reports",
            Path(args.report_dir) if args.report_dir else None,
            "rvem/reports",
            required=args.require_core,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "rvem_dashboard",
            Path(args.dashboard_html) if args.dashboard_html else None,
            "rvem/dashboard",
            required=args.require_core,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "rvem_artifact_audit",
            rvem_audit_path,
            "audits",
            required=args.require_rvem_audit_complete,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "profuzzbench_result_audit",
            result_audit_path,
            "audits",
            required=args.require_result_audit_gate,
            problems=problems,
            warnings=warnings,
        )
    )
    artifact_entries.append(
        package_add_path(
            package_root,
            "profuzzbench_result_audit_csv",
            Path(args.result_audit_csv) if args.result_audit_csv else None,
            "audits",
            required=False,
            problems=problems,
            warnings=warnings,
        )
    )

    for raw_path in args.raw_jsonl or []:
        artifact_entries.append(
            package_add_path(
                package_root,
                "rvem_raw_jsonl",
                Path(raw_path),
                "rvem/raw",
                required=False,
                problems=problems,
                warnings=warnings,
            )
        )
    for manifest_path in args.manifest or []:
        artifact_entries.append(
            package_add_path(
                package_root,
                "campaign_manifest",
                Path(manifest_path),
                "manifests",
                required=False,
                problems=problems,
                warnings=warnings,
            )
        )
    for review_packet_dir in args.review_packet_dir or []:
        artifact_entries.append(
            package_add_path(
                package_root,
                "property_review_packet",
                Path(review_packet_dir),
                "property_review_packet",
                required=False,
                problems=problems,
                warnings=warnings,
            )
        )
    for stage_audit_dir in args.stage_audit_dir or []:
        artifact_entries.append(
            package_add_path(
                package_root,
                "stage_audit",
                Path(stage_audit_dir),
                "stage_audit",
                required=False,
                problems=problems,
                warnings=warnings,
            )
        )

    copied_file_count = sum(int(entry.get("copied_file_count", 0) or 0) for entry in artifact_entries)
    copied_size_bytes = sum(int(entry.get("total_size_bytes", 0) or 0) for entry in artifact_entries)
    limitations: list[str] = []
    if not result_audit:
        limitations.append("No ProFuzzBench result audit was provided; run completeness and monitor-artifact evidence are not packaged.")
    else:
        expected_runs = int(result_audit.get("expected_runs", 0) or 0)
        if expected_runs < 20:
            limitations.append(
                f"Result audit covers {expected_runs} expected run(s); this is below the paper-scale 20-run target unless the manifest intentionally selects a smaller smoke study."
            )
        if result_audit.get("complete") is not True:
            limitations.append("Result audit does not report complete=true.")
    if not rvem_audit:
        limitations.append("No RVEM artifact audit was provided; table/figure/dashboard completeness is not certified inside the package.")
    elif rvem_audit.get("complete") is not True:
        limitations.append("RVEM artifact audit does not report complete=true.")
    if copied_file_count == 0:
        problems.append("no evidence files were packaged")

    manifest = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "package_root": str(package_root),
        "gate_passed": not problems,
        "problem_count": len(problems),
        "warning_count": len(warnings),
        "problems": problems,
        "warnings": warnings,
        "requirements": {
            "require_core": bool(args.require_core),
            "require_rvem_audit_complete": bool(args.require_rvem_audit_complete),
            "require_result_audit_gate": bool(args.require_result_audit_gate),
        },
        "summary": {
            "artifact_role_count": len(artifact_entries),
            "copied_file_count": copied_file_count,
            "copied_size_bytes": copied_size_bytes,
        },
        "source_audits": {
            "rvem_artifact_audit": {
                "path": str(rvem_audit_path) if rvem_audit_path else "",
                "schema_version": rvem_audit.get("schema_version", ""),
                "complete": rvem_audit.get("complete", None),
                "problem_count": rvem_audit.get("problem_count", None),
            },
            "profuzzbench_result_audit": {
                "path": str(result_audit_path) if result_audit_path else "",
                "schema_version": result_audit.get("schema_version", ""),
                "complete": result_audit.get("complete", None),
                "gate_passed": result_audit.get("gate_passed", None),
                "expected_runs": result_audit.get("expected_runs", None),
                "completed_runs": result_audit.get("completed_runs", None),
            },
        },
        "notes": notes,
        "limitations": limitations,
        "artifacts": artifact_entries,
    }

    checksum_path = write_package_checksums(package_root, artifact_entries)
    readme_path = write_package_readme(package_root, manifest, notes=notes, limitations=limitations)
    manifest["generated_files"] = {
        "manifest": str(package_root / "artifact_package_manifest.json"),
        "checksums": str(checksum_path),
        "readme": str(readme_path),
    }
    return manifest


def unique_sorted(rows: Iterable[dict[str, str]], field: str) -> list[str]:
    return sorted({row.get(field, "") for row in rows if row.get(field, "")})


def render_dashboard(table_dir: Path, out_path: Path, plot_dir: Path | None = None) -> None:
    dataset: dict[str, list[dict[str, str]]] = {}
    for table_name in CSV_FIELDS:
        dataset[table_name] = read_optional_csv_table(table_dir / f"{table_name}.csv")

    plot_files = [
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
    ]
    plots: dict[str, str] = {}
    if plot_dir is not None:
        for name in plot_files:
            path = plot_dir / name
            if path.exists():
                plots[name] = str(path.relative_to(out_path.parent))

    all_rows: list[dict[str, str]] = []
    for rows in dataset.values():
        all_rows.extend(rows)
    filter_subjects = unique_sorted(all_rows, "subject")
    filter_variants = sorted(
        {
            f'{row.get("fuzzer", "")}/{row.get("variant", "")}'
            for row in all_rows
            if row.get("fuzzer", "") or row.get("variant", "")
        }
    )
    filter_runs = unique_sorted(all_rows, "run_id")
    filter_properties = unique_sorted(all_rows, "property_id")

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bi-ZoneFuzz++ RVEM Dashboard</title>
  <style>
    :root {{
      --bg: #f5efe2;
      --panel: #fffaf0;
      --panel-strong: #f7ead0;
      --ink: #132238;
      --muted: #6a7280;
      --line: #d8c7a4;
      --accent: #b4442a;
      --accent-2: #2f6f5e;
      --accent-3: #315c9b;
      --shadow: 0 18px 48px rgba(19, 34, 56, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(180, 68, 42, 0.12), transparent 34%),
        radial-gradient(circle at top right, rgba(49, 92, 155, 0.10), transparent 30%),
        linear-gradient(180deg, #f9f4ea 0%, #efe4cf 100%);
    }}
    .shell {{
      max-width: 1380px;
      margin: 0 auto;
      padding: 28px 24px 44px;
    }}
    .hero {{
      background: linear-gradient(135deg, rgba(255, 250, 240, 0.94), rgba(247, 234, 208, 0.96));
      border: 1px solid rgba(216, 199, 164, 0.9);
      border-radius: 26px;
      padding: 26px 28px 22px;
      box-shadow: var(--shadow);
    }}
    .eyebrow {{
      margin: 0 0 6px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-size: 12px;
      color: var(--accent);
      font-weight: 700;
    }}
    h1 {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", serif;
      font-size: 36px;
      line-height: 1.05;
    }}
    .subtitle {{
      margin: 10px 0 0;
      max-width: 900px;
      color: var(--muted);
      line-height: 1.6;
    }}
    .toolbar {{
      margin-top: 18px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .filter {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 12px 14px;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(216, 199, 164, 0.8);
      border-radius: 16px;
    }}
    .filter label {{
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .filter select {{
      appearance: none;
      border: none;
      background: transparent;
      color: var(--ink);
      font-size: 15px;
      outline: none;
    }}
    .tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 22px 0 0;
    }}
    .tab {{
      padding: 11px 16px;
      border-radius: 999px;
      border: 1px solid rgba(216, 199, 164, 0.92);
      background: rgba(255, 255, 255, 0.72);
      color: var(--ink);
      cursor: pointer;
      font-weight: 700;
    }}
    .tab.active {{
      background: var(--ink);
      color: #fff;
      border-color: var(--ink);
    }}
    .view {{
      display: none;
      margin-top: 22px;
      background: rgba(255, 250, 240, 0.94);
      border: 1px solid rgba(216, 199, 164, 0.85);
      border-radius: 24px;
      padding: 22px;
      box-shadow: var(--shadow);
    }}
    .view.active {{ display: block; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    .card {{
      padding: 16px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(247,234,208,0.86));
      border: 1px solid rgba(216, 199, 164, 0.88);
    }}
    .card .label {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }}
    .card .value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 800;
    }}
    .card .detail {{
      margin-top: 8px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}
    .plot-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .panel {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.76);
      border: 1px solid rgba(216, 199, 164, 0.8);
    }}
    .panel h2, .panel h3 {{
      margin: 0 0 12px;
      font-size: 18px;
    }}
    .plot {{
      width: 100%;
      border-radius: 14px;
      border: 1px solid rgba(216, 199, 164, 0.65);
      background: #fff;
    }}
    .empty {{
      color: var(--muted);
      font-style: italic;
      padding: 22px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid rgba(216, 199, 164, 0.55);
      vertical-align: top;
    }}
    th {{
      font-size: 12px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .two-col {{
      display: grid;
      grid-template-columns: minmax(0, 1.3fr) minmax(320px, 0.9fr);
      gap: 16px;
    }}
    .explain {{
      display: grid;
      gap: 12px;
    }}
    .note {{
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }}
    code {{
      font-family: "JetBrains Mono", "SFMono-Regular", monospace;
      font-size: 12px;
      background: rgba(47, 111, 94, 0.08);
      padding: 1px 5px;
      border-radius: 6px;
    }}
    @media (max-width: 980px) {{
      .two-col {{
        grid-template-columns: 1fr;
      }}
      h1 {{ font-size: 30px; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <p class="eyebrow">Bi-ZoneFuzz++ / RVEM</p>
      <h1>Interactive Multi-Feedback Fuzzing Dashboard</h1>
      <p class="subtitle">This dashboard replays the current Bi-ZoneFuzz++ evidence chain from aggregated RVEM tables. It keeps protocol, property, frontier, obligation, slack, mutation-hint, and explanation data in one place so campaign review does not stop at code coverage.</p>
      <div class="toolbar">
        <div class="filter"><label for="subjectFilter">Subject</label><select id="subjectFilter"></select></div>
        <div class="filter"><label for="variantFilter">Fuzzer / Variant</label><select id="variantFilter"></select></div>
        <div class="filter"><label for="runFilter">Run</label><select id="runFilter"></select></div>
        <div class="filter"><label for="propertyFilter">Property</label><select id="propertyFilter"></select></div>
      </div>
      <div class="tabs">
        <button class="tab active" data-view="overview">Overview</button>
        <button class="tab" data-view="protocol">Protocol Drill-down</button>
        <button class="tab" data-view="property">Property Explorer</button>
        <button class="tab" data-view="frontier">Frontier &amp; Obligation Evolution</button>
        <button class="tab" data-view="trace">Trace Replay with Explanation</button>
      </div>
    </section>

    <section class="view active" id="view-overview">
      <div class="cards" id="overviewCards"></div>
      <div class="plot-grid" id="overviewPlots"></div>
    </section>

    <section class="view" id="view-protocol">
      <div class="two-col">
        <div class="panel">
          <h2>Protocol Summary</h2>
          <div id="protocolSummary"></div>
        </div>
        <div class="panel">
          <h2>Coverage &amp; Semantic-State Figures</h2>
          <div id="protocolPlots"></div>
        </div>
      </div>
    </section>

    <section class="view" id="view-property">
      <div class="two-col">
        <div class="panel">
          <h2>Property Table</h2>
          <div id="propertyTable"></div>
        </div>
        <div class="panel">
          <h2>Slack &amp; Progress Context</h2>
          <div id="propertyContext"></div>
        </div>
      </div>
    </section>

    <section class="view" id="view-frontier">
      <div class="cards" id="frontierCards"></div>
      <div class="panel">
        <h2>Frontier / Zone / Obligation Timeline</h2>
        <div id="frontierTable"></div>
      </div>
      <div class="plot-grid" id="frontierPlots"></div>
    </section>

    <section class="view" id="view-trace">
      <div class="two-col">
        <div class="panel">
          <h2>Trace Replay</h2>
          <div id="traceTable"></div>
        </div>
        <div class="panel explain">
          <div>
            <h2>Explanation Panel</h2>
            <div id="traceExplanation"></div>
          </div>
          <div>
            <h3>Case Timeline Figure</h3>
            <div id="tracePlot"></div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    const dataset = {json.dumps(dataset, ensure_ascii=False)};
    const plots = {json.dumps(plots, ensure_ascii=False)};
    const options = {{
      subjects: {json.dumps(filter_subjects, ensure_ascii=False)},
      variants: {json.dumps(filter_variants, ensure_ascii=False)},
      runs: {json.dumps(filter_runs, ensure_ascii=False)},
      properties: {json.dumps(filter_properties, ensure_ascii=False)},
    }};
    const state = {{ subject: "all", variant: "all", run: "all", property: "all" }};

    function numeric(value, fallback = 0) {{
      if (value === "" || value === null || value === undefined) return fallback;
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : fallback;
    }}

    function uniqueCount(rows, key) {{
      return new Set(rows.map((row) => row[key]).filter(Boolean)).size;
    }}

    function filterRows(rows) {{
      return rows.filter((row) => {{
        const variantKey = `${{row.fuzzer || ""}}/${{row.variant || ""}}`;
        return (state.subject === "all" || row.subject === state.subject) &&
          (state.variant === "all" || variantKey === state.variant) &&
          (state.run === "all" || row.run_id === state.run) &&
          (state.property === "all" || !row.property_id || row.property_id === state.property);
      }});
    }}

    function latestByRun(rows) {{
      const latest = new Map();
      rows.forEach((row) => {{
        const current = latest.get(row.run_id);
        if (!current || numeric(row.elapsed_sec) >= numeric(current.elapsed_sec)) {{
          latest.set(row.run_id, row);
        }}
      }});
      return [...latest.values()];
    }}

    function mountSelect(id, values, stateKey, labelAll) {{
      const select = document.getElementById(id);
      select.innerHTML = "";
      const all = document.createElement("option");
      all.value = "all";
      all.textContent = labelAll;
      select.appendChild(all);
      values.forEach((value) => {{
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      }});
      select.value = state[stateKey];
      select.onchange = () => {{
        state[stateKey] = select.value;
        render();
      }};
    }}

    function toHtmlTable(rows, columns, emptyMessage) {{
      if (!rows.length) return `<div class="empty">${{emptyMessage}}</div>`;
      const head = `<tr>${{columns.map((column) => `<th>${{column.label}}</th>`).join("")}}</tr>`;
      const body = rows.map((row) => `<tr>${{columns.map((column) => `<td>${{row[column.key] ?? ""}}</td>`).join("")}}</tr>`).join("");
      return `<table><thead>${{head}}</thead><tbody>${{body}}</tbody></table>`;
    }}

    function figureCard(title, description, filename) {{
      if (!plots[filename]) {{
        return `<div class="panel"><h3>${{title}}</h3><div class="empty">Figure not available for this dataset yet.</div><p class="note">${{description}}</p></div>`;
      }}
      return `<div class="panel"><h3>${{title}}</h3><img class="plot" src="${{plots[filename]}}" alt="${{title}}"><p class="note">${{description}}</p></div>`;
    }}

    function renderOverview() {{
      const timeRows = filterRows(dataset.time_series);
      const slackRows = filterRows(dataset.slack_distribution);
      const semanticRows = filterRows(dataset.semantic_state_series);
      const frontierRows = filterRows(dataset.frontier_obligation_series);
      const latest = latestByRun(timeRows);
      const coverageMax = latest.reduce((max, row) => Math.max(max, numeric(row.coverage_edges)), 0);
      const violationsMax = latest.reduce((max, row) => Math.max(max, numeric(row.violations_total)), 0);
      const yieldMax = latest.reduce((max, row) => Math.max(max, numeric(row.yield_total)), 0);
      const minSlack = slackRows.length ? Math.min(...slackRows.map((row) => numeric(row.slack_ms))) : null;
      const maxObligations = frontierRows.length ? Math.max(...frontierRows.map((row) => numeric(row.active_obligation_count))) : 0;
      const cards = [
        ["Runs", String(uniqueCount(timeRows, "run_id")), "Filtered replicate count participating in the current view."],
        ["Max Coverage", String(coverageMax), "Highest observed edge coverage in the filtered slice."],
        ["Violations", String(violationsMax), "Maximum cumulative property violations recorded in the filtered slice."],
        ["Yield", String(yieldMax), "Maximum interesting-case yield recorded in the filtered slice."],
        ["Semantic States", String(uniqueCount(semanticRows, "state_id")), "Distinct semantic monitor states explored by the filtered runs."],
        ["Min Slack", minSlack === null ? "n/a" : minSlack.toFixed(1), "Tightest deadline slack observed; smaller means closer to the temporal boundary."],
        ["Peak Obligations", String(maxObligations), "Largest active obligation count in the filtered slice."],
      ];
      document.getElementById("overviewCards").innerHTML = cards.map(([label, value, detail]) =>
        `<div class="card"><div class="label">${{label}}</div><div class="value">${{value}}</div><div class="detail">${{detail}}</div></div>`
      ).join("");
      document.getElementById("overviewPlots").innerHTML = [
        figureCard("Coverage Over Time", "Primary campaign growth curve aligned with ProFuzzBench-style reporting.", "coverage_over_time.svg"),
        figureCard("Time-to-First-Violation Survival", "Kaplan-Meier style view of how quickly each variant reaches its first property violation.", "time_to_first_violation.svg"),
        figureCard("Overhead vs Yield", "Monitor overhead against semantic yield to expose the RV tradeoff frontier.", "overhead_vs_yield.svg"),
        figureCard("Ablation Yield", "Quick visual comparison of yield across ablations or variants.", "ablation_bar.svg"),
      ].join("");
    }}

    function renderProtocol() {{
      const timeRows = latestByRun(filterRows(dataset.time_series));
      const semanticRows = filterRows(dataset.semantic_state_series);
      const slackRows = filterRows(dataset.slack_distribution);
      const summary = timeRows.map((row) => {{
        const variantKey = `${{row.fuzzer}}/${{row.variant}}`;
        const semanticForRun = semanticRows.filter((item) => item.run_id === row.run_id);
        const slackForRun = slackRows.filter((item) => item.run_id === row.run_id);
        const minSlack = slackForRun.length ? Math.min(...slackForRun.map((item) => numeric(item.slack_ms))) : "";
        return {{
          subject: row.subject,
          variant: variantKey,
          run_id: row.run_id,
          coverage_edges: row.coverage_edges,
          violations_total: row.violations_total,
          execs_total: row.execs_total,
          semantic_states: uniqueCount(semanticForRun, "state_id"),
          min_slack_ms: minSlack === "" ? "" : minSlack.toFixed(1),
        }};
      }});
      document.getElementById("protocolSummary").innerHTML = toHtmlTable(
        summary,
        [
          {{ key: "subject", label: "subject" }},
          {{ key: "variant", label: "variant" }},
          {{ key: "run_id", label: "run" }},
          {{ key: "coverage_edges", label: "coverage" }},
          {{ key: "violations_total", label: "violations" }},
          {{ key: "semantic_states", label: "semantic states" }},
          {{ key: "min_slack_ms", label: "min slack ms" }},
        ],
        "No protocol summary rows match the current filter."
      );
      document.getElementById("protocolPlots").innerHTML = [
        figureCard("Semantic State Over Time", "Semantic-state growth shows whether the multi-feedback scheduler is opening new monitor regions.", "semantic_state_over_time.svg"),
        figureCard("Coverage Over Time", "Coverage view stays alongside semantic-state growth for protocol-level tradeoff review.", "coverage_over_time.svg"),
      ].join("");
    }}

    function renderProperty() {{
      const propertyRows = filterRows(dataset.property_summary);
      const progressRows = filterRows(dataset.property_progress_series);
      const slackRows = filterRows(dataset.slack_distribution).sort((a, b) => numeric(a.slack_ms) - numeric(b.slack_ms)).slice(0, 8);
      const summarized = propertyRows.map((row) => {{
        const progressForProperty = progressRows.filter((item) => item.property_id === row.property_id);
        const maxDelta = progressForProperty.reduce((max, item) => Math.max(max, numeric(item.property_coverage_delta)), 0);
        return {{
          property_id: row.property_id,
          evaluations: row.evaluations,
          negative: row.negative,
          violation_rate: Number(row.violation_rate).toFixed(2),
          min_slack_ms: row.min_slack_ms,
          max_progress_delta: maxDelta,
        }};
      }});
      document.getElementById("propertyTable").innerHTML = toHtmlTable(
        summarized,
        [
          {{ key: "property_id", label: "property" }},
          {{ key: "evaluations", label: "evals" }},
          {{ key: "negative", label: "violations" }},
          {{ key: "violation_rate", label: "rate" }},
          {{ key: "min_slack_ms", label: "min slack" }},
          {{ key: "max_progress_delta", label: "progress delta" }},
        ],
        "No property rows match the current filter."
      );
      const slackTable = toHtmlTable(
        slackRows,
        [
          {{ key: "property_id", label: "property" }},
          {{ key: "run_id", label: "run" }},
          {{ key: "elapsed_sec", label: "elapsed" }},
          {{ key: "slack_ms", label: "slack ms" }},
          {{ key: "verdict", label: "verdict" }},
        ],
        "No slack samples match the current filter."
      );
      document.getElementById("propertyContext").innerHTML = `
        ${{figureCard("Property Heatmap", "Across-property violation intensity by variant.", "property_heatmap.svg")}}
        ${{figureCard("Progress Coverage", "How many distinct property-progress bins each variant actually reaches.", "progress_coverage_bar.svg")}}
        ${{figureCard("Slack ECDF", "How fast each variant reaches the temporal boundary band.", "slack_ecdf.svg")}}
        ${{figureCard("Slack Violin", "Distribution shape of boundary distances per property.", "slack_violin.svg")}}
        <div class="panel"><h3>Most Boundary-Near Samples</h3>${{slackTable}}</div>
      `;
    }}

    function renderFrontier() {{
      const rows = filterRows(dataset.frontier_obligation_series).sort((a, b) => numeric(a.elapsed_sec) - numeric(b.elapsed_sec) || numeric(a.event_index) - numeric(b.event_index));
      const boundaryHits = rows.filter((row) => row.boundary_class && row.boundary_class !== "stable").length;
      const noveltyRate = rows.length ? rows.filter((row) => row.frontier_novelty === "1").length / rows.length : 0;
      const minSlack = rows.length ? Math.min(...rows.filter((row) => row.min_slack_ms !== "").map((row) => numeric(row.min_slack_ms, Infinity))) : Infinity;
      const maxObligations = rows.length ? Math.max(...rows.map((row) => numeric(row.active_obligation_count))) : 0;
      const cards = [
        ["Boundary Hits", String(boundaryHits), "Number of frontier snapshots that reported a non-stable boundary class."],
        ["Frontier Novelty Rate", rows.length ? `${{(noveltyRate * 100).toFixed(1)}}%` : "n/a", "Share of frontier snapshots marked as novel by the monitor."],
        ["Minimum Slack", Number.isFinite(minSlack) ? minSlack.toFixed(1) : "n/a", "Closest deadline distance observed in the filtered frontier slice."],
        ["Peak Obligations", String(maxObligations), "Highest active obligation count reached in the filtered frontier slice."],
      ];
      document.getElementById("frontierCards").innerHTML = cards.map(([label, value, detail]) =>
        `<div class="card"><div class="label">${{label}}</div><div class="value">${{value}}</div><div class="detail">${{detail}}</div></div>`
      ).join("");
      document.getElementById("frontierTable").innerHTML = toHtmlTable(
        rows.slice(-18),
        [
          {{ key: "elapsed_sec", label: "elapsed" }},
          {{ key: "event_index", label: "event" }},
          {{ key: "boundary_class", label: "boundary" }},
          {{ key: "min_slack_ms", label: "slack ms" }},
          {{ key: "frontier_size_pos", label: "front+" }},
          {{ key: "frontier_size_neg", label: "front-" }},
          {{ key: "active_obligation_count", label: "active obl" }},
          {{ key: "opened_now", label: "opened" }},
          {{ key: "expired_now", label: "expired" }},
          {{ key: "request_class", label: "request" }},
          {{ key: "response_class", label: "response" }},
          {{ key: "critical_deadline_source", label: "deadline source" }},
        ],
        "No frontier/obligation rows match the current filter."
      );
      document.getElementById("frontierPlots").innerHTML = [
        figureCard("Obligation Lifecycle Evolution", "Active obligations plus cumulative open/satisfy/expire events over campaign time.", "obligation_lifecycle.svg"),
        figureCard("Timing Hint Origin Breakdown", "Shows whether active timing plans are being driven by fresh feedback or queue-carried semantic history.", "timing_hint_origin.svg"),
      ].join("");
    }}

    function renderTrace() {{
      const rows = filterRows(dataset.trace_replay).sort((a, b) => numeric(a.elapsed_sec) - numeric(b.elapsed_sec) || numeric(a.event_index) - numeric(b.event_index));
      const highlighted = rows.reduce((best, row) => {{
        if (!best) return row;
        return numeric(row.min_slack_ms, Infinity) < numeric(best.min_slack_ms, Infinity) ? row : best;
      }}, null);
      document.getElementById("traceTable").innerHTML = toHtmlTable(
        rows.slice(-18),
        [
          {{ key: "elapsed_sec", label: "elapsed" }},
          {{ key: "event_index", label: "event" }},
          {{ key: "direction", label: "dir" }},
          {{ key: "request_class", label: "request" }},
          {{ key: "response_class", label: "response" }},
          {{ key: "boundary_class", label: "boundary" }},
          {{ key: "min_slack_ms", label: "slack ms" }},
          {{ key: "active_obligation_count", label: "active obl" }},
          {{ key: "candidate_next_event_classes", label: "hint classes" }},
          {{ key: "raw_event", label: "raw event" }},
        ],
        "No trace replay rows match the current filter."
      );
      if (!highlighted) {{
        document.getElementById("traceExplanation").innerHTML = '<div class="empty">No explanation rows match the current filter.</div>';
      }} else {{
        const hintSummary = [highlighted.retry_hint === "1" ? "retry" : "", highlighted.keepalive_hint === "1" ? "keepalive" : "", highlighted.silence_hint === "1" ? "silence" : ""].filter(Boolean).join(", ") || "none";
        document.getElementById("traceExplanation").innerHTML = `
          <div class="card"><div class="label">Dominant Property</div><div class="value">${{highlighted.dominant_property_id || highlighted.property_id || "n/a"}}</div><div class="detail">Most decisive property around the selected boundary-near event.</div></div>
          <div class="card"><div class="label">Witness Summary</div><div class="detail">${{highlighted.shortest_witness_summary || "n/a"}}</div></div>
          <div class="card"><div class="label">Critical Deadline Source</div><div class="detail">${{highlighted.critical_deadline_source || "n/a"}}</div></div>
          <div class="card"><div class="label">Suggested Mutation Family</div><div class="detail"><code>${{hintSummary}}</code> / gap=${{highlighted.recommended_gap_delta_ms || "0"}} ms / next=${{highlighted.candidate_next_event_classes || "[]"}}</div></div>
        `;
      }}
      document.getElementById("tracePlot").innerHTML = figureCard("Case Timeline", "Single-case timeline for replaying outcome changes with explanation context.", "case_timeline.svg");
    }}

    function render() {{
      renderOverview();
      renderProtocol();
      renderProperty();
      renderFrontier();
      renderTrace();
    }}

    document.querySelectorAll(".tab").forEach((button) => {{
      button.addEventListener("click", () => {{
        document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
        document.querySelectorAll(".view").forEach((item) => item.classList.remove("active"));
        button.classList.add("active");
        document.getElementById(`view-${{button.dataset.view}}`).classList.add("active");
      }});
    }});

    mountSelect("subjectFilter", options.subjects, "subject", "All subjects");
    mountSelect("variantFilter", options.variants, "variant", "All variants");
    mountSelect("runFilter", options.runs, "run", "All runs");
    mountSelect("propertyFilter", options.properties, "property", "All properties");
    render();
  </script>
</body>
</html>
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")


def demo_records() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    variants = [("bizonefuzz", "rvem"), ("bizonefuzz", "no_semantic"), ("aflnet", "baseline")]
    for variant_index, (fuzzer, variant) in enumerate(variants):
        run_id = f"{fuzzer}-{variant}-r0"
        for step in range(6):
            elapsed = step * 600
            coverage_edges = 100 + step * (45 - variant_index * 7) + variant_index * 18
            yield_total = step * (5 - min(variant_index, 3))
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "campaign_snapshot",
                    "campaign": "profuzzbench-style-can",
                    "subject": "gear-controller",
                    "fuzzer": fuzzer,
                    "variant": variant,
                    "run_id": run_id,
                    "elapsed_sec": elapsed,
                    "coverage": {"edges": coverage_edges, "blocks": coverage_edges // 2, "paths": step + 1},
                    "execs_total": 2000 + step * 900,
                    "cases_total": 30 + step * 12,
                    "bugs_total": 1 if variant == "rvem" and step >= 4 else 0,
                    "violations_total": 2 if variant == "rvem" and step >= 5 else variant_index,
                    "yield_total": yield_total,
                    "monitor_ms": 11 + variant_index * 4 + step,
                    "target_ms": 120 + step * 8,
                    "total_ms": 131 + step * 9,
                    "execs_per_sec": 92 - variant_index * 9 - step,
                    "ablation": variant,
                }
            )
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "semantic_state",
                    "campaign": "profuzzbench-style-can",
                    "subject": "gear-controller",
                    "fuzzer": fuzzer,
                    "variant": variant,
                    "run_id": run_id,
                    "elapsed_sec": elapsed,
                    "state_id": f"q{step}",
                    "region": "clutch" if step % 2 else "gear",
                    "monitor_state_count": 4 + step * (3 - min(variant_index, 2)),
                    "frontier_width": 2 + step,
                    "verdict": "INCONCLUSIVE",
                }
            )
        for prop_index, property_id in enumerate(["reqnewgear_deadline", "clutch_response", "torque_request"]):
            for case_index in range(5):
                slack = 150 - variant_index * 35 - prop_index * 20 - case_index * 18
                verdict = "NEGATIVE" if slack < 0 else "POSITIVE"
                rows.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "event_type": "property_eval",
                        "campaign": "profuzzbench-style-can",
                        "subject": "gear-controller",
                        "fuzzer": fuzzer,
                        "variant": variant,
                        "run_id": run_id,
                        "elapsed_sec": 300 + case_index * 420,
                        "property_id": property_id,
                        "case_id": f"{property_id}-{case_index}",
                        "verdict": verdict,
                        "slack_ms": slack,
                        "deadline_ms": 300 + prop_index * 100,
                        "timed_trace_event": {
                            "event_index": case_index,
                            "timestamp_ms": 200 + case_index * 90 + variant_index * 15,
                            "direction": "request" if case_index % 2 == 0 else "response",
                            "gap_prev_ms": 18 + case_index * 3,
                            "t_send_ms": 12 + case_index * 5,
                            "t_first_response_ms": 20 + case_index * 6,
                            "t_done_ms": 28 + case_index * 7,
                            "session_phase": "dialog" if property_id == "torque_request" else "setup",
                            "request_class": "invite" if case_index % 2 == 0 else "notify",
                            "response_class": "ok" if case_index % 2 else "provisional",
                            "close_or_reset_seen": False,
                            "parser_state_id": 100 + case_index,
                            "raw": f"demo-event-{property_id}-{case_index}",
                            "candidate_next_event_classes": ["keepalive", "retry"] if case_index % 2 == 0 else ["response"],
                        },
                        "feedback_frame": {
                            "event_index": case_index,
                            "property_set_id": property_id,
                            "semantic_state_id": f"demo-sem-{variant_index}-{prop_index}-{case_index}",
                            "channel_mask": 127,
                            "timestamp_ms": 200 + case_index * 90 + variant_index * 15,
                            "feedback": {
                                "frontier": {
                                    "pos_frontier_hash": 1000 + prop_index * 100 + case_index,
                                    "neg_frontier_hash": 2000 + prop_index * 100 + case_index,
                                    "frontier_size_pos": 1 + case_index,
                                    "frontier_size_neg": 2 + prop_index,
                                    "frontier_novelty": case_index % 2 == 0,
                                },
                                "zone": {
                                    "zone_hash": 3000 + prop_index * 100 + case_index,
                                    "min_slack_ms": slack,
                                    "boundary_class": "near-deadline" if slack < 40 else "stable",
                                    "violated_guard_count": 1 if slack < 0 else 0,
                                    "near_deadline_count": 1 if slack < 40 else 0,
                                    "slack_exact": True,
                                },
                                "obligation": {
                                    "active_obligation_count": 1 + prop_index,
                                    "opened_now": 1 if case_index == 0 else 0,
                                    "satisfied_now": 1 if slack > 0 and case_index == 4 else 0,
                                    "expired_now": 1 if slack < 0 else 0,
                                    "obligation_phase_mask": 16 + prop_index,
                                },
                                "property_progress": {
                                    "property_progress_vector": [prop_index, case_index, max(slack, 0)],
                                    "newly_reached_progress_bins": [case_index],
                                    "property_coverage_delta": max(0, 4 - case_index),
                                },
                                "protocol_semantic": {
                                    "session_phase": "dialog" if property_id == "torque_request" else "setup",
                                    "request_class": "invite" if case_index % 2 == 0 else "notify",
                                    "response_class": "ok" if case_index % 2 else "provisional",
                                    "close_or_reset_seen": False,
                                    "parser_state_id": 100 + case_index,
                                },
                                "mutation_hint": {
                                    "recommended_gap_delta_ms": max(5, 45 - case_index * 7),
                                    "candidate_next_event_classes": ["keepalive", "retry"] if slack < 50 else ["response"],
                                    "retry_hint": slack < 0,
                                    "keepalive_hint": slack < 35,
                                    "silence_hint": case_index == 4,
                                },
                                "explainability": {
                                    "dominant_property_id": property_id,
                                    "decisive_transition_id": 9000 + prop_index * 100 + case_index,
                                    "critical_deadline_source": f"demo deadline source {property_id}#{case_index}",
                                    "shortest_witness_summary": f"verdict={verdict}, slack={slack}",
                                },
                            },
                        },
                    }
                )
        for case_index in range(6):
            outcome = "violation" if variant == "rvem" and case_index in {3, 5} else "interesting" if case_index % 2 else "ok"
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "case_result",
                    "campaign": "profuzzbench-style-can",
                    "subject": "gear-controller",
                    "fuzzer": fuzzer,
                    "variant": variant,
                    "run_id": run_id,
                    "elapsed_sec": 180 + case_index * 310,
                    "case_id": f"{variant}-case-{case_index}",
                    "start_sec": 120 + case_index * 300,
                    "end_sec": 180 + case_index * 310,
                    "outcome": outcome,
                    "property_id": "reqnewgear_deadline" if outcome == "violation" else "",
                    "slack_ms": -20 if outcome == "violation" else 80,
                    "yield_total": case_index + 1,
                    "coverage_edges": 120 + case_index * 20,
                }
            )
    return rows


def write_demo(out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in demo_records():
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def first_present(row: dict[str, str], names: list[str], default: str = "") -> str:
    for name in names:
        if row.get(name, "") != "":
            return row[name]
    return default


def command_import_profuzzbench(args: argparse.Namespace) -> int:
    input_path = Path(args.input_csv)
    output_path = Path(args.output_jsonl)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with input_path.open("r", encoding="utf-8", newline="") as input_handle, output_path.open("w", encoding="utf-8") as output_handle:
        reader = csv.DictReader(input_handle)
        for index, row in enumerate(reader, start=1):
            run_id = first_present(row, ["run_id", "trial", "replicate", "job_id"], f"run-{index}")
            elapsed = first_present(row, ["elapsed_sec", "time_sec", "time", "hour", "hours"], "0")
            elapsed_sec = as_float(elapsed) * 3600 if "hour" in row and row.get("elapsed_sec", "") == "" else as_float(elapsed)
            payload = {
                "schema_version": SCHEMA_VERSION,
                "event_type": "campaign_snapshot",
                "campaign": args.campaign or first_present(row, ["campaign", "experiment"], "profuzzbench"),
                "subject": args.subject or first_present(row, ["subject", "program", "target", "protocol"]),
                "fuzzer": args.fuzzer or first_present(row, ["fuzzer", "tool"]),
                "variant": args.variant or first_present(row, ["variant", "configuration", "mode"], "baseline"),
                "run_id": run_id,
                "elapsed_sec": elapsed_sec,
                "coverage": {
                    "edges": as_int(first_present(row, ["coverage_edges", "edges", "edge_coverage", "cov_edges"])),
                    "blocks": as_int(first_present(row, ["coverage_blocks", "blocks", "block_coverage", "cov_blocks"])),
                    "paths": as_int(first_present(row, ["coverage_paths", "paths", "path_coverage", "cov_paths"])),
                },
                "execs_total": as_int(first_present(row, ["execs_total", "executions", "execs"])),
                "cases_total": as_int(first_present(row, ["cases_total", "testcases", "queue_size", "corpus"])),
                "bugs_total": as_int(first_present(row, ["bugs_total", "bugs", "unique_bugs", "crashes"])),
                "violations_total": as_int(first_present(row, ["violations_total", "violations"])),
                "yield_total": as_int(first_present(row, ["yield_total", "interesting_total", "interesting"])),
                "execs_per_sec": as_float(first_present(row, ["execs_per_sec", "eps"])),
            }
            output_handle.write(json.dumps(payload, sort_keys=True) + "\n")
            count += 1
    print(f"imported {count} ProFuzzBench-style row(s) to {output_path}")
    return 0


def command_schema(args: argparse.Namespace) -> int:
    print(json.dumps({"raw": RAW_SCHEMA, "aggregated": AGGREGATED_SCHEMA, "report": REPORT_SCHEMA}, indent=2, sort_keys=True))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    records = read_jsonl([Path(item) for item in args.raw_jsonl])
    print(f"validated {len(records)} RVEM records")
    return 0


def command_aggregate(args: argparse.Namespace) -> int:
    records = read_jsonl([Path(item) for item in args.raw_jsonl])
    tables = aggregate(records)
    out_dir = Path(args.out_dir)
    write_csv_tables(tables, out_dir)
    if args.parquet:
        write_parquet_tables(tables, out_dir)
    print(f"wrote {len(tables)} RVEM table(s) to {out_dir}")
    return 0


def command_plot(args: argparse.Namespace) -> int:
    plot_tables(Path(args.table_dir), Path(args.out_dir))
    print(f"wrote RVEM SVG plots to {args.out_dir}")
    return 0


def command_dashboard(args: argparse.Namespace) -> int:
    plot_dir = Path(args.plot_dir) if args.plot_dir else None
    render_dashboard(Path(args.table_dir), Path(args.out_html), plot_dir)
    print(f"wrote RVEM dashboard to {args.out_html}")
    return 0


def command_report(args: argparse.Namespace) -> int:
    plot_dir = Path(args.plot_dir) if args.plot_dir else None
    manifest = write_report_bundle(
        Path(args.table_dir),
        Path(args.out_dir),
        plot_dir,
        reference_label=args.reference_label,
        bootstrap_samples=args.bootstrap_samples,
        bootstrap_seed=args.bootstrap_seed,
    )
    print(f"wrote RVEM report bundle to {args.out_dir}")
    print(f"wrote RVEM report manifest: {Path(args.out_dir) / 'report_manifest.json'}")
    print(f"report variants: {manifest['variant_count']}, figures: {manifest['figure_count']}")
    return 0


def command_audit_artifacts(args: argparse.Namespace) -> int:
    audit = audit_rvem_artifacts(
        Path(args.table_dir),
        Path(args.plot_dir) if args.plot_dir else None,
        Path(args.report_dir) if args.report_dir else None,
        Path(args.dashboard_html) if args.dashboard_html else None,
        require_data=args.require_data,
    )
    rendered = json.dumps(audit, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_complete and audit["problem_count"]:
        return 1
    return 0


def command_package_artifacts(args: argparse.Namespace) -> int:
    manifest = build_repro_package(args)
    manifest_path = Path(manifest["generated_files"]["manifest"])
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False))
    if args.require_complete and not manifest["gate_passed"]:
        return 1
    return 0


def command_demo(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    raw_path = out_dir / "rvem_demo.raw.jsonl"
    table_dir = out_dir / "tables"
    plot_dir = out_dir / "plots"
    dashboard_path = out_dir / "dashboard.html"
    report_dir = out_dir / "reports"
    write_demo(raw_path)
    records = read_jsonl([raw_path])
    tables = aggregate(records)
    write_csv_tables(tables, table_dir)
    plot_tables(table_dir, plot_dir)
    render_dashboard(table_dir, dashboard_path, plot_dir)
    write_report_bundle(table_dir, report_dir, plot_dir)
    print(f"wrote demo raw log: {raw_path}")
    print(f"wrote demo tables: {table_dir}")
    print(f"wrote demo plots: {plot_dir}")
    print(f"wrote demo dashboard: {dashboard_path}")
    print(f"wrote demo reports: {report_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build RVEM tables and plots from Bi-ZoneFuzz++ raw JSONL logs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate raw RVEM JSONL logs")
    validate.add_argument("raw_jsonl", nargs="+")
    validate.set_defaults(func=command_validate)

    aggregate_cmd = subparsers.add_parser("aggregate", help="aggregate raw RVEM JSONL logs into CSV tables")
    aggregate_cmd.add_argument("raw_jsonl", nargs="+")
    aggregate_cmd.add_argument("--out-dir", required=True)
    aggregate_cmd.add_argument("--parquet", action="store_true", help="also write Parquet tables when pandas/pyarrow are installed")
    aggregate_cmd.set_defaults(func=command_aggregate)

    plot = subparsers.add_parser("plot", help="render SVG plots from aggregated CSV tables")
    plot.add_argument("--table-dir", required=True)
    plot.add_argument("--out-dir", required=True)
    plot.set_defaults(func=command_plot)

    dashboard = subparsers.add_parser("dashboard", help="build a self-contained interactive HTML dashboard from RVEM tables")
    dashboard.add_argument("--table-dir", required=True)
    dashboard.add_argument("--out-html", required=True)
    dashboard.add_argument("--plot-dir", default="", help="optional SVG plot directory to embed into the dashboard")
    dashboard.set_defaults(func=command_dashboard)

    report = subparsers.add_parser("report", help="build paper-ready RVEM summaries and figure manifests from aggregated tables")
    report.add_argument("--table-dir", required=True)
    report.add_argument("--out-dir", required=True)
    report.add_argument("--plot-dir", default="", help="optional SVG plot directory for figure availability tracking")
    report.add_argument("--reference-label", default="", help="optional explicit reference label such as aflnet/aflnet-base")
    report.add_argument("--bootstrap-samples", type=int, default=1000)
    report.add_argument("--bootstrap-seed", type=int, default=1337)
    report.set_defaults(func=command_report)

    audit = subparsers.add_parser("audit-artifacts", help="audit RVEM table, plot, dashboard, and report artifact completeness")
    audit.add_argument("--table-dir", required=True)
    audit.add_argument("--plot-dir", default="", help="optional SVG plot directory to check")
    audit.add_argument("--report-dir", default="", help="optional report directory to check")
    audit.add_argument("--dashboard-html", default="", help="optional dashboard HTML artifact to check")
    audit.add_argument("--out", default="", help="optional JSON audit output path")
    audit.add_argument("--require-complete", action="store_true", help="exit non-zero if required artifacts are missing or malformed")
    audit.add_argument("--require-data", action="store_true", help="also require key evidence tables to contain data rows")
    audit.set_defaults(func=command_audit_artifacts)

    package = subparsers.add_parser(
        "package-artifacts",
        help="build a checksum-backed reproducibility package from RVEM and campaign audit artifacts",
    )
    package.add_argument("--out-dir", required=True, help="destination package directory")
    package.add_argument("--table-dir", default="", help="RVEM aggregated table directory to copy")
    package.add_argument("--plot-dir", default="", help="RVEM paper figure directory to copy")
    package.add_argument("--report-dir", default="", help="RVEM paper report directory to copy")
    package.add_argument("--dashboard-html", default="", help="RVEM interactive dashboard HTML to copy")
    package.add_argument("--rvem-audit-json", default="", help="strict RVEM artifact audit JSON to copy and gate")
    package.add_argument("--result-audit-json", default="", help="ProFuzzBench result audit JSON to copy and gate")
    package.add_argument("--result-audit-csv", default="", help="optional ProFuzzBench run-level result audit CSV")
    package.add_argument("--raw-jsonl", action="append", default=[], help="optional RVEM raw JSONL file or directory to copy")
    package.add_argument("--manifest", action="append", default=[], help="optional campaign/stage manifest to copy")
    package.add_argument("--review-packet-dir", action="append", default=[], help="optional PropertyCard review packet directory to copy")
    package.add_argument("--stage-audit-dir", action="append", default=[], help="optional stage-audit output directory to copy")
    package.add_argument("--note", action="append", default=[], help="human-readable package note to include in README/manifest")
    package.add_argument("--require-core", action="store_true", help="require tables, plots, reports, and dashboard inputs")
    package.add_argument("--require-rvem-audit-complete", action="store_true", help="require a complete rvem.artifact_audit.v1 JSON")
    package.add_argument("--require-result-audit-gate", action="store_true", help="require a passing bizonefuzz.profuzzbench.result_audit.v1 gate")
    package.add_argument("--require-complete", action="store_true", help="exit non-zero if the package manifest has problems")
    package.set_defaults(func=command_package_artifacts)

    demo = subparsers.add_parser("demo", help="generate a small ProFuzzBench-style demo dataset, tables, and plots")
    demo.add_argument("--out-dir", required=True)
    demo.set_defaults(func=command_demo)

    import_pfb = subparsers.add_parser("import-profuzzbench-csv", help="convert a flat ProFuzzBench-style CSV into RVEM raw JSONL")
    import_pfb.add_argument("input_csv")
    import_pfb.add_argument("output_jsonl")
    import_pfb.add_argument("--campaign", default="")
    import_pfb.add_argument("--subject", default="")
    import_pfb.add_argument("--fuzzer", default="")
    import_pfb.add_argument("--variant", default="")
    import_pfb.set_defaults(func=command_import_profuzzbench)

    schema = subparsers.add_parser("schema", help="print the raw and aggregated RVEM schemas as JSON")
    schema.set_defaults(func=command_schema)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"rvem_tools.py: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
