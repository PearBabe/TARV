#!/usr/bin/env python3
"""Smoke-test the ProFuzzBench overlay planning and RVEM collection path."""

from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

MONITOR_ABLATION_VARIANTS = [
    "oracle-only",
    "frontier-only",
    "zone-only",
    "obligation-only",
    "progress-only",
    "frontier+zone",
    "full",
]

SMOKE_VARIANTS = ["aflnet-base", "aflnet-patched-base", *MONITOR_ABLATION_VARIANTS]
SMOKE_VARIANTS_CSV = ",".join(SMOKE_VARIANTS)

MONITOR_VARIANT_PROFILES = {
    "oracle-only": {
        "cov": dict(second_l_per=10.6, second_l_abs=10, second_b_per=5.1, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=42,
            request_class="options",
            session_phase="idle",
            boundary_class="near-deadline",
            retry_hint=False,
            active_obligation_count=0,
            progress_vector=[1],
            monitor_state_count=1,
            frontier_width=2,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=3, feedback_semantic_state_id=3),
    },
    "frontier-only": {
        "cov": dict(second_l_per=10.9, second_l_abs=11, second_b_per=5.3, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=28,
            request_class="play",
            session_phase="session",
            boundary_class="safe-interior",
            retry_hint=False,
            active_obligation_count=0,
            progress_vector=[1],
            monitor_state_count=3,
            frontier_width=4,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=4, feedback_semantic_state_id=4),
    },
    "zone-only": {
        "cov": dict(second_l_per=11.0, second_l_abs=11, second_b_per=5.5, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=15,
            request_class="pause",
            session_phase="idle",
            boundary_class="near-deadline",
            retry_hint=False,
            active_obligation_count=0,
            progress_vector=[1],
            monitor_state_count=1,
            frontier_width=1,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=5, feedback_semantic_state_id=5),
    },
    "obligation-only": {
        "cov": dict(second_l_per=11.1, second_l_abs=11, second_b_per=5.4, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=18,
            request_class="setup",
            session_phase="session",
            boundary_class="near-deadline",
            retry_hint=False,
            active_obligation_count=2,
            progress_vector=[1],
            monitor_state_count=2,
            frontier_width=2,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=6, feedback_semantic_state_id=6),
    },
    "progress-only": {
        "cov": dict(second_l_per=11.2, second_l_abs=11, second_b_per=5.45, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=12,
            request_class="options",
            session_phase="session",
            boundary_class="near-deadline",
            retry_hint=False,
            active_obligation_count=1,
            progress_vector=[1, 2],
            monitor_state_count=2,
            frontier_width=2,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=7, feedback_semantic_state_id=7),
    },
    "frontier+zone": {
        "cov": dict(second_l_per=11.5, second_l_abs=12, second_b_per=5.7, second_b_abs=5),
        "feedback": dict(
            verdict="INCONCLUSIVE",
            slack_ms=8,
            request_class="play",
            session_phase="session",
            boundary_class="ambiguity-band",
            retry_hint=False,
            active_obligation_count=1,
            progress_vector=[1, 2],
            monitor_state_count=4,
            frontier_width=5,
            include_case_result=False,
            violations_total=0,
            yield_total=0,
            final_verdict="INCONCLUSIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=8, feedback_semantic_state_id=8),
    },
    "full": {
        "cov": dict(second_l_per=12.0, second_l_abs=12, second_b_per=6.0, second_b_abs=6),
        "feedback": dict(
            verdict="NEGATIVE",
            slack_ms=-5,
            request_class="play",
            session_phase="idle",
            boundary_class="crossed-deadline",
            retry_hint=True,
            active_obligation_count=1,
            progress_vector=[1, 2, 3],
            monitor_state_count=2,
            frontier_width=2,
            include_case_result=True,
            outcome="violation",
            violations_total=1,
            yield_total=1,
            final_verdict="NEGATIVE",
        ),
        "timing": dict(stage_hint_origin="queue", queue_semantic_state_id=9, feedback_semantic_state_id=11),
    },
}


def run(cmd: list[str], *, cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
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


def require_float_text(value: str, expected: float, message: str) -> None:
    try:
        actual = float(value)
    except ValueError as exc:
        raise AssertionError(f"{message}: expected numeric value, saw {value!r}") from exc
    if abs(actual - expected) > 1e-9:
        raise AssertionError(f"{message}: expected {expected}, saw {actual}")


def profile_final_coverage(profile: dict[str, object]) -> float:
    cov = profile["cov"]
    if not isinstance(cov, dict):
        raise AssertionError(f"invalid profile coverage payload: {profile!r}")
    return float(cov["second_b_abs"])


def add_text_member(archive: tarfile.TarFile, name: str, text: str) -> None:
    data = text.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


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


def write_mock_docker_builder(path: Path, state_dir: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                f"STATE_DIR='{state_dir}'",
                "mkdir -p \"$STATE_DIR\"",
                "if [ \"$1\" = \"--version\" ]; then",
                "  echo 'Docker version 99.0.0, build mock'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"info\" ]; then",
                "  echo '99.0.0'",
                "  exit 0",
                "fi",
                "if [ \"$1\" = \"image\" ] && [ \"$2\" = \"inspect\" ]; then",
                "  IMAGE=\"$3\"",
                "  SAFE=$(printf '%s' \"$IMAGE\" | tr '/:' '__')",
                "  if [ -f \"$STATE_DIR/$SAFE.present\" ]; then",
                "    echo \"sha256:mock-$SAFE\"",
                "    exit 0",
                "  fi",
                "  echo \"mock image missing: $IMAGE\" >&2",
                "  exit 1",
                "fi",
                "if [ \"$1\" = \"build\" ]; then",
                "  IMAGE=''",
                "  PREV=''",
                "  for ARG in \"$@\"; do",
                "    if [ \"$PREV\" = \"-t\" ]; then IMAGE=\"$ARG\"; fi",
                "    PREV=\"$ARG\"",
                "  done",
                "  if [ -z \"$IMAGE\" ]; then",
                "    echo 'mock build missing -t image' >&2",
                "    exit 3",
                "  fi",
                "  SAFE=$(printf '%s' \"$IMAGE\" | tr '/:' '__')",
                "  touch \"$STATE_DIR/$SAFE.present\"",
                "  printf '%s\\n' \"$@\" >> \"$STATE_DIR/build-commands.log\"",
                "  echo \"mock built $IMAGE\"",
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


def make_cov_csv(
    *,
    second_time: int = 1010,
    second_l_per: float = 12.0,
    second_l_abs: int = 12,
    second_b_per: float = 6.0,
    second_b_abs: int = 6,
) -> str:
    return "\n".join(
        [
            "time,l_per,l_abs,b_per,b_abs",
            "1000,10.0,10,5.0,5",
            f"{second_time},{second_l_per},{second_l_abs},{second_b_per},{second_b_abs}",
            "",
        ]
    )


def make_feedback_jsonl(
    *,
    run_id: str,
    elapsed_sec: float,
    semantic_state_id: int,
    case_id: str,
    variant: str = "full",
    mode: str = "full",
    verdict: str = "NEGATIVE",
    slack_ms: int = -5,
    request_class: str = "play",
    session_phase: str = "idle",
    boundary_class: str = "crossed-deadline",
    retry_hint: bool = True,
    active_obligation_count: int = 1,
    progress_vector: list[int] | None = None,
    monitor_state_count: int = 2,
    frontier_width: int = 2,
    include_case_result: bool = True,
    outcome: str = "violation",
    violations_total: int = 1,
    yield_total: int = 1,
    final_verdict: str | None = None,
    ablation: str | None = None,
) -> str:
    if progress_vector is None:
        progress_vector = [3]
    if final_verdict is None:
        final_verdict = verdict
    records = [
        {
            "schema_version": "rvem.raw.v1",
            "event_type": "property_eval",
            "campaign": "main-study-smoke",
            "subject": "live555",
            "fuzzer": "aflnet",
            "variant": variant,
            "mode": mode,
            "run_id": run_id,
            "elapsed_sec": elapsed_sec,
            "property_id": "rtsp.session_activity_before_default_timeout",
            "case_id": case_id,
            "verdict": verdict,
            "slack_ms": slack_ms,
            "deadline_ms": None,
            "timed_trace_event": {"timestamp_ms": int(elapsed_sec * 1000.0), "request_class": request_class},
            "feedback_frame": {
                "run_id": run_id,
                "event_index": 1,
                "property_set_id": "rtsp.session_activity_before_default_timeout",
                "verdict": verdict,
                "semantic_state_id": semantic_state_id,
                "channel_mask": 127,
                "timestamp_ms": int(elapsed_sec * 1000.0),
                "feedback": {
                    "frontier": {"frontier_size_pos": 1, "frontier_size_neg": 1},
                    "zone": {"boundary_class": boundary_class, "min_slack_ms": slack_ms},
                    "obligation": {"active_obligation_count": active_obligation_count},
                    "property_progress": {"property_progress_vector": progress_vector},
                    "protocol_semantic": {"session_phase": session_phase},
                    "mutation_hint": {"retry_hint": retry_hint},
                    "explainability": {"dominant_property_id": "rtsp.session_activity_before_default_timeout"},
                },
            },
        },
        {
            "schema_version": "rvem.raw.v1",
            "event_type": "semantic_state",
            "campaign": "main-study-smoke",
            "subject": "live555",
            "fuzzer": "aflnet",
            "variant": variant,
            "mode": mode,
            "run_id": run_id,
            "elapsed_sec": elapsed_sec,
            "state_id": str(semantic_state_id),
            "region": "idle",
            "monitor_state_count": monitor_state_count,
            "frontier_width": frontier_width,
            "verdict": verdict,
        },
        {
            "schema_version": "rvem.raw.v1",
            "event_type": "ablation_result",
            "campaign": "main-study-smoke",
            "subject": "live555",
            "fuzzer": "aflnet",
            "variant": variant,
            "mode": mode,
            "run_id": run_id,
            "elapsed_sec": elapsed_sec + 0.5,
            "ablation": ablation or variant,
            "execs_total": 10,
            "cases_total": 10,
            "bugs_total": 0,
            "violations_total": violations_total,
            "yield_total": yield_total,
            "property_id": "rtsp.session_activity_before_default_timeout",
            "final_verdict": final_verdict,
        },
    ]
    if include_case_result:
        records.insert(
            2,
            {
                "schema_version": "rvem.raw.v1",
                "event_type": "case_result",
                "campaign": "main-study-smoke",
                "subject": "live555",
                "fuzzer": "aflnet",
                "variant": variant,
                "mode": mode,
                "run_id": run_id,
                "elapsed_sec": elapsed_sec,
                "case_id": case_id,
                "start_sec": max(0.0, elapsed_sec - 0.5),
                "end_sec": elapsed_sec,
                "outcome": outcome,
                "property_id": "rtsp.session_activity_before_default_timeout",
                "slack_ms": slack_ms,
            },
        )
    return "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"


def make_timing_text(*, stage_hint_origin: str, queue_semantic_state_id: int, feedback_semantic_state_id: int) -> str:
    lines = [
        "active=1",
        "stage=fuzz_one",
        f"stage_hint_origin={stage_hint_origin}",
        "stage_gap_hint_ms=120",
        "stage_hint_mask=3",
        "stage_preferred_request_class=options",
        "stage_retry_preferred_request_class=options",
        "stage_keepalive_preferred_request_class=options",
        f"queue_semantic_state_id={queue_semantic_state_id}",
        "queue_gap_hint_ms=120",
        "queue_hint_mask=3",
        "queue_preferred_request_class=play",
        "queue_retry_preferred_request_class=options",
        "queue_keepalive_preferred_request_class=none",
        "feedback_gap_hint_ms=90",
        "feedback_hint_mask=5",
        f"feedback_semantic_state_id={feedback_semantic_state_id}",
        "feedback_preferred_request_class=options",
        "feedback_retry_preferred_request_class=options",
        "feedback_keepalive_preferred_request_class=options",
        "feedback_request_class=session_activity",
        "feedback_response_class=1",
        "feedback_session_phase=proceeding",
        "base_message_count=2",
        "message_count=3",
        "requested_gap_delta_ms=120",
        "poll_wait_base_ms=50",
        "poll_wait_override_ms=40",
        "tail_wait_ms=0",
        "gap_expansion=1",
        "gap_compression=0",
        "boundary_bisection=1",
        "keepalive_bias=0",
        "silence_window=0",
        "retry_insertion=1",
        "keepalive_insertion=0",
        "keepalive_synthesized=0",
        "keepalive_contextual=0",
        "keepalive_profile=none",
        "retry_contextual=1",
        "retry_profile=rtsp-options-contextual",
        "retry_source_request_class=options",
        "keepalive_anchor_request_class=options",
        "cross_request_resend=1",
        "hybrid_keepalive_retry=0",
        "insertion_count=1",
        "injected_kind[0]=retry",
        "injected_base_message_count[0]=2",
        "injected_source_index[0]=0",
        "injected_after_index[0]=1",
        "injected_slot_index[0]=2",
        "pre_send_delay_ms[1]=60",
        "pre_send_delay_ms[2]=120",
        "",
    ]
    return "\n".join(lines)


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a ProFuzzBench overlay smoke test.")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--overlay-tool", default=str(Path(__file__).resolve().with_name("bizone_profuzzbench.py")))
    parser.add_argument("--property-tool", default=str(Path(__file__).resolve().with_name("property_card_tools.py")))
    parser.add_argument("--rvem-tool", default=str(Path(__file__).resolve().with_name("rvem_tools.py")))
    parser.add_argument("--cards-json", default=str(Path(__file__).resolve().parents[1] / "benchmarks/main_study_property_cards_initial.json"))
    parser.add_argument("--catalog", default=str(Path(__file__).resolve().parents[1] / "benchmarks/profuzzbench_campaigns.json"))
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    overlay_tool = Path(args.overlay_tool).resolve()
    property_tool = Path(args.property_tool).resolve()
    rvem_tool = Path(args.rvem_tool).resolve()
    cards_json = Path(args.cards_json).resolve()
    catalog = Path(args.catalog).resolve()
    cards_payload = json.loads(cards_json.read_text(encoding="utf-8"))
    expected_formula_count = len(cards_payload.get("cards", []))

    with tempfile.TemporaryDirectory(prefix="bizone-profuzzbench-smoke-") as tmp:
        tmpdir = Path(tmp)
        formulas_dir = tmpdir / "formulas"
        formula_manifest = tmpdir / "formulas.json"
        export_result = run(
            [
                sys.executable,
                str(property_tool),
                "export-formulas",
                str(cards_json),
                "--out-dir",
                str(formulas_dir),
                "--manifest-out",
                str(formula_manifest),
            ],
            cwd=workspace,
        )
        require(export_result.returncode == 0, f"export-formulas failed:\nSTDOUT:\n{export_result.stdout}\nSTDERR:\n{export_result.stderr}")
        exported = json.loads(formula_manifest.read_text(encoding="utf-8"))
        require(
            exported["count"] == expected_formula_count,
            f"expected {expected_formula_count} exported formulas, saw {exported['count']}",
        )

        manifest_path = tmpdir / "manifest.json"
        plan_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "plan",
                "--catalog",
                str(catalog),
                "--cards-json",
                str(cards_json),
                "--stage",
                "main-study",
                "--campaign",
                "main-study-smoke",
                "--subjects",
                "live555",
                "--variants",
                SMOKE_VARIANTS_CSV,
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out",
                str(manifest_path),
            ],
            cwd=workspace,
        )
        require(plan_result.returncode == 0, f"manifest planning failed:\nSTDOUT:\n{plan_result.stdout}\nSTDERR:\n{plan_result.stderr}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        require(
            len(manifest["entries"]) == len(SMOKE_VARIANTS),
            f"expected {len(SMOKE_VARIANTS)} manifest entries, saw {len(manifest['entries'])}",
        )

        matrix_dir = tmpdir / "matrix"
        matrix_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "matrix",
                str(manifest_path),
                "--out-dir",
                str(matrix_dir),
            ],
            cwd=workspace,
        )
        require(matrix_result.returncode == 0, f"matrix generation failed:\nSTDOUT:\n{matrix_result.stdout}\nSTDERR:\n{matrix_result.stderr}")
        require((matrix_dir / "entry_matrix.csv").is_file(), "missing experiment entry matrix")
        require((matrix_dir / "subject_readiness.csv").is_file(), "missing subject readiness matrix")
        require((matrix_dir / "paper_matrix.md").is_file(), "missing paper matrix markdown")
        require((matrix_dir / "campaign_summary.json").is_file(), "missing campaign summary json")
        require((matrix_dir / "matrix_manifest.json").is_file(), "missing matrix manifest json")

        matrix_manifest = json.loads((matrix_dir / "matrix_manifest.json").read_text(encoding="utf-8"))
        require(matrix_manifest.get("entry_count") == len(SMOKE_VARIANTS), f"unexpected matrix entry count: {matrix_manifest}")
        require(matrix_manifest.get("subject_count") == 1, f"unexpected matrix subject count: {matrix_manifest}")

        with (matrix_dir / "entry_matrix.csv").open("r", encoding="utf-8", newline="") as handle:
            matrix_rows = list(csv.DictReader(handle))
        require(len(matrix_rows) == len(SMOKE_VARIANTS), f"expected {len(SMOKE_VARIANTS)} entry matrix rows, saw {len(matrix_rows)}")
        matrix_by_variant = {row["variant"]: row for row in matrix_rows}
        require(set(SMOKE_VARIANTS) <= set(matrix_by_variant), f"unexpected matrix variants: {matrix_rows}")
        require(
            matrix_by_variant["aflnet-base"]["variant_family"] == "baseline",
            f"baseline variant family not preserved: {matrix_by_variant['aflnet-base']}",
        )
        require(
            matrix_by_variant["aflnet-patched-base"]["variant_family"] == "patched-baseline",
            f"patched baseline variant family not preserved: {matrix_by_variant['aflnet-patched-base']}",
        )
        require(
            all(matrix_by_variant[variant]["variant_family"] == "monitor-ablation" for variant in MONITOR_ABLATION_VARIANTS),
            f"monitor ablation variants lost their family tag: {matrix_by_variant}",
        )
        require(
            matrix_by_variant["aflnet-base"]["monitor_enabled"] == "0",
            f"baseline row unexpectedly marked monitor-enabled: {matrix_by_variant['aflnet-base']}",
        )
        require(
            matrix_by_variant["aflnet-base"]["inject_local_aflnet"] == "0"
            and matrix_by_variant["aflnet-base"]["fuzzer"] == "aflnet"
            and matrix_by_variant["aflnet-patched-base"]["inject_local_aflnet"] == "0"
            and matrix_by_variant["aflnet-patched-base"]["fuzzer"] == "bizone-aflnet",
            f"official/bizone AFLNet fuzzer split not preserved: {matrix_by_variant}",
        )
        require(
            all(matrix_by_variant[variant]["monitor_enabled"] == "1" for variant in MONITOR_ABLATION_VARIANTS),
            f"monitor_enabled lost in monitor rows: {matrix_by_variant}",
        )
        for variant in MONITOR_ABLATION_VARIANTS:
            require(
                matrix_by_variant[variant]["property_id"] == "rtsp.session_activity_before_default_timeout",
                f"{variant} matrix row lost property id: {matrix_by_variant[variant]}",
            )
        require(
            matrix_by_variant["full"]["draft_gate_ready"] == "0"
            and matrix_by_variant["full"]["final_gate_ready"] == "0",
            f"full matrix row should stay non-publishable with current draft-only approvals: {matrix_by_variant['full']}",
        )
        require(
            "needs 2 draft approvals" in matrix_by_variant["full"]["draft_blockers"],
            f"full matrix row lost draft blockers: {matrix_by_variant['full']}",
        )
        require(
            all(matrix_by_variant[variant]["draft_gate_ready"] == "0" for variant in MONITOR_ABLATION_VARIANTS),
            f"monitor ablation rows unexpectedly became draft-ready: {matrix_by_variant}",
        )

        with (matrix_dir / "subject_readiness.csv").open("r", encoding="utf-8", newline="") as handle:
            subject_rows = list(csv.DictReader(handle))
        require(len(subject_rows) == 1, f"expected 1 subject readiness row, saw {subject_rows}")
        subject_row = subject_rows[0]
        require(
            subject_row["subject_id"] == "live555" and subject_row["protocol"] == "RTSP",
            f"subject readiness row lost subject/protocol: {subject_row}",
        )
        require(
            subject_row["monitor_entry_count"] == str(len(MONITOR_ABLATION_VARIANTS))
            and subject_row["draft_ready_monitor_entries"] == "0"
            and subject_row["final_ready_monitor_entries"] == "0",
            f"subject readiness row lost monitor gate counts: {subject_row}",
        )
        require(
            subject_row["draft_ready_subject"] == "0" and subject_row["final_ready_subject"] == "0",
            f"subject readiness row should remain not publication-ready: {subject_row}",
        )

        matrix_summary = json.loads((matrix_dir / "campaign_summary.json").read_text(encoding="utf-8"))
        require(matrix_summary.get("manifest_entries") == len(SMOKE_VARIANTS), f"unexpected campaign summary: {matrix_summary}")
        require(matrix_summary.get("subjects") == 1, f"unexpected subject count summary: {matrix_summary}")
        require(matrix_summary.get("monitor_entries") == len(MONITOR_ABLATION_VARIANTS), f"unexpected monitor entry summary: {matrix_summary}")
        require(matrix_summary.get("draft_ready_subjects") == 0, f"unexpected draft-ready subject count: {matrix_summary}")
        require(matrix_summary.get("final_ready_subjects") == 0, f"unexpected final-ready subject count: {matrix_summary}")

        paper_matrix = (matrix_dir / "paper_matrix.md").read_text(encoding="utf-8")
        require("# Bi-ZoneFuzz++ Experiment Matrix" in paper_matrix, "paper matrix missing title")
        require("| main-study | live555 | RTSP |" in paper_matrix, "paper matrix missing subject readiness row")
        for variant in MONITOR_ABLATION_VARIANTS:
            require(
                f"| live555 | {variant} | monitor-ablation | 1 | 1 | 60 | rtsp.session_activity_before_default_timeout | 0 | 0 |" in paper_matrix,
                f"paper matrix missing {variant} entry row",
            )

        gated_manifest_path = tmpdir / "manifest.draft-gated.json"
        gated_plan_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "plan",
                "--catalog",
                str(catalog),
                "--cards-json",
                str(cards_json),
                "--stage",
                "main-study",
                "--campaign",
                "main-study-smoke",
                "--subjects",
                "live555",
                "--variants",
                SMOKE_VARIANTS_CSV,
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--publication-gate",
                "draft",
                "--out",
                str(gated_manifest_path),
            ],
            cwd=workspace,
        )
        require(gated_plan_result.returncode == 0, f"draft-gated manifest planning failed:\nSTDOUT:\n{gated_plan_result.stdout}\nSTDERR:\n{gated_plan_result.stderr}")
        gated_manifest = json.loads(gated_manifest_path.read_text(encoding="utf-8"))
        require(gated_manifest.get("publication_gate") == "draft", f"draft gate not recorded in manifest: {gated_manifest}")
        gated_variants = {entry["variant"] for entry in gated_manifest["entries"]}
        require(
            gated_variants == {"aflnet-base", "aflnet-patched-base"},
            f"draft-gated manifest should keep only non-monitor AFLNet baselines: {gated_manifest['entries']}",
        )
        require(
            any("not draft-ready" in warning for warning in gated_manifest.get("warnings", [])),
            f"draft-gated manifest missing readiness warning: {gated_manifest}",
        )

        gated_run_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "run",
                str(gated_manifest_path),
                "--results-root",
                str(tmpdir / "gated-results"),
                "--dry-run",
            ],
            cwd=workspace,
        )
        require(gated_run_result.returncode == 0, f"draft-gated dry-run failed:\nSTDOUT:\n{gated_run_result.stdout}\nSTDERR:\n{gated_run_result.stderr}")
        require(
            "\"variant\": \"aflnet-base\"" in gated_run_result.stdout
            and "\"variant\": \"aflnet-patched-base\"" in gated_run_result.stdout
            and all(f"\"variant\": \"{variant}\"" not in gated_run_result.stdout for variant in MONITOR_ABLATION_VARIANTS),
            f"draft-gated dry-run emitted unexpected variants:\n{gated_run_result.stdout}",
        )

        enforced_run_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "run",
                str(manifest_path),
                "--results-root",
                str(tmpdir / "enforced-results"),
                "--dry-run",
                "--enforce-publication-gate",
                "draft",
            ],
            cwd=workspace,
        )
        require(
            enforced_run_result.returncode != 0,
            "run unexpectedly ignored enforced draft publication gate on an ungated manifest",
        )
        require(
            "not draft-ready" in f"{enforced_run_result.stdout}\n{enforced_run_result.stderr}",
            f"unexpected enforced-gate failure reason:\nSTDOUT:\n{enforced_run_result.stdout}\nSTDERR:\n{enforced_run_result.stderr}",
        )

        lightftp_manifest_path = tmpdir / "manifest.lightftp.json"
        lightftp_plan_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "plan",
                "--catalog",
                str(catalog),
                "--cards-json",
                str(cards_json),
                "--stage",
                "bring-up",
                "--campaign",
                "bring-up-smoke",
                "--subjects",
                "lightftp",
                "--variants",
                SMOKE_VARIANTS_CSV,
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out",
                str(lightftp_manifest_path),
            ],
            cwd=workspace,
        )
        require(lightftp_plan_result.returncode == 0, f"lightftp manifest planning failed:\nSTDOUT:\n{lightftp_plan_result.stdout}\nSTDERR:\n{lightftp_plan_result.stderr}")
        lightftp_manifest = json.loads(lightftp_manifest_path.read_text(encoding="utf-8"))
        lightftp_variants = {entry["variant"] for entry in lightftp_manifest["entries"]}
        require(
            lightftp_variants == {"aflnet-base"},
            f"expected only official lightftp baseline, saw {lightftp_manifest['entries']}",
        )
        require(not lightftp_manifest.get("warnings", []), f"lightftp baseline-only policy should not emit warnings: {lightftp_manifest}")
        exclusions = lightftp_manifest.get("policy_exclusions", [])
        require(len(exclusions) == len(MONITOR_ABLATION_VARIANTS) + 1, f"unexpected lightftp policy exclusions: {exclusions}")
        require(
            all(item.get("subject_id") == "lightftp" and "official timed PropertyCard" in item.get("reason", "") for item in exclusions),
            f"unexpected lightftp policy exclusion payload: {exclusions}",
        )

        mock_docker = tmpdir / "mock-docker.sh"
        write_mock_docker(mock_docker)

        preflight_report = tmpdir / "preflight.json"
        preflight_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "preflight",
                str(manifest_path),
                "--results-root",
                str(tmpdir / "preflight-results"),
                "--docker-bin",
                str(mock_docker),
                "--out",
                str(preflight_report),
            ],
            cwd=workspace,
        )
        require(
            preflight_result.returncode == 0,
            f"preflight unexpectedly failed:\nSTDOUT:\n{preflight_result.stdout}\nSTDERR:\n{preflight_result.stderr}",
        )
        preflight = json.loads(preflight_report.read_text(encoding="utf-8"))
        require(preflight.get("schema_version") == "bizonefuzz.profuzzbench.preflight.v1", f"unexpected preflight schema: {preflight}")
        require(preflight.get("selected_entry_count") == len(SMOKE_VARIANTS), f"unexpected preflight entry count: {preflight}")
        require(preflight.get("ready_for_dry_run") is True, f"preflight should be dry-run ready: {preflight}")
        require(preflight.get("ready_for_real_run") is False, f"preflight should expose missing daemon readiness: {preflight}")
        require(preflight.get("docker", {}).get("cli_available") is True, f"preflight lost docker CLI status: {preflight}")
        require(preflight.get("docker", {}).get("daemon_available") is False, f"preflight lost missing-daemon status: {preflight}")

        strict_preflight_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "preflight",
                str(manifest_path),
                "--results-root",
                str(tmpdir / "strict-preflight-results"),
                "--docker-bin",
                str(mock_docker),
                "--require-daemon",
            ],
            cwd=workspace,
        )
        require(
            strict_preflight_result.returncode != 0,
            "preflight unexpectedly ignored --require-daemon when the mock daemon was unavailable",
        )

        mock_builder_state = tmpdir / "mock-builder-state"
        mock_builder = tmpdir / "mock-docker-builder.sh"
        write_mock_docker_builder(mock_builder, mock_builder_state)
        image_build_dir = tmpdir / "image-build"
        image_build_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "build-images",
                str(lightftp_manifest_path),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_builder),
                "--out-dir",
                str(image_build_dir),
                "--retries",
                "1",
            ],
            cwd=workspace,
        )
        require(
            image_build_result.returncode == 0,
            f"image build workflow failed under mock docker:\nSTDOUT:\n{image_build_result.stdout}\nSTDERR:\n{image_build_result.stderr}",
        )
        image_build_manifest = json.loads((image_build_dir / "image_build_manifest.json").read_text(encoding="utf-8"))
        require(image_build_manifest.get("schema_version") == "bizonefuzz.profuzzbench.image_build.v1", f"unexpected image build schema: {image_build_manifest}")
        require(image_build_manifest.get("summary", {}).get("gate_passed") is True, f"image build gate should pass: {image_build_manifest}")
        require(image_build_manifest.get("summary", {}).get("build_attempted_count") == 1, f"expected one image build: {image_build_manifest}")
        targets = image_build_manifest.get("targets", [])
        require(isinstance(targets, list) and len(targets) == 1, f"expected one image target: {targets}")
        target = targets[0]
        require(target.get("image") == "lightftp", f"unexpected image target: {target}")
        require(target.get("context_found") is True and str(target.get("context", "")).endswith("profuzzbench/subjects/FTP/LightFTP"), f"unexpected context: {target}")
        require(target.get("present_before") is False and target.get("present_after") is True, f"mock build should create image: {target}")
        require(target.get("build_attempted") is True and len(target.get("attempts", [])) == 1, f"missing build attempt evidence: {target}")
        require(Path(str(target["attempts"][0]["log"])).is_file(), f"missing build attempt log: {target}")
        build_command_tokens = (mock_builder_state / "build-commands.log").read_text(encoding="utf-8").splitlines()
        require(
            "build" in build_command_tokens
            and "." in build_command_tokens
            and "--network" in build_command_tokens
            and "host" in build_command_tokens
            and "-t" in build_command_tokens
            and "lightftp" in build_command_tokens,
            f"mock build lost expected docker args: {build_command_tokens}",
        )

        stateafl_manifest_path = tmpdir / "lightftp-stateafl.manifest.json"
        stateafl_plan_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "plan",
                "--stage",
                "bring-up",
                "--subjects",
                "lightftp",
                "--variants",
                "stateafl",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out",
                str(stateafl_manifest_path),
            ],
            cwd=workspace,
        )
        require(stateafl_plan_result.returncode == 0, f"lightftp stateafl planning failed:\nSTDOUT:\n{stateafl_plan_result.stdout}\nSTDERR:\n{stateafl_plan_result.stderr}")
        stateafl_build_dir = tmpdir / "stateafl-image-build-dry-run"
        stateafl_build_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "build-images",
                str(stateafl_manifest_path),
                "--workspace",
                str(workspace),
                "--docker-bin",
                str(mock_docker),
                "--out-dir",
                str(stateafl_build_dir),
                "--dry-run",
            ],
            cwd=workspace,
        )
        require(
            stateafl_build_result.returncode == 0,
            f"stateafl image dry-run failed:\nSTDOUT:\n{stateafl_build_result.stdout}\nSTDERR:\n{stateafl_build_result.stderr}",
        )
        stateafl_build_manifest = json.loads((stateafl_build_dir / "image_build_manifest.json").read_text(encoding="utf-8"))
        stateafl_targets = stateafl_build_manifest.get("targets", [])
        require(isinstance(stateafl_targets, list) and len(stateafl_targets) == 1, f"expected one stateafl image target: {stateafl_targets}")
        stateafl_target = stateafl_targets[0]
        require(stateafl_target.get("image") == "lightftp-stateafl", f"unexpected stateafl image target: {stateafl_target}")
        require(str(stateafl_target.get("dockerfile", "")).endswith("Dockerfile-stateafl"), f"stateafl target should use Dockerfile-stateafl: {stateafl_target}")
        require(stateafl_target.get("dockerfile_found") is True, f"stateafl Dockerfile should exist: {stateafl_target}")
        require(stateafl_build_manifest.get("summary", {}).get("gate_passed") is True, f"stateafl dry-run gate should pass: {stateafl_build_manifest}")

        monitor_missing_run = run(
            [
                sys.executable,
                str(overlay_tool),
                "run",
                str(manifest_path),
                "--results-root",
                str(tmpdir / "monitor-missing-results"),
                "--variants",
                "full",
                "--dry-run",
                "--monitor-bin",
                "/definitely/missing/mitppl-monitor",
                "--docker-bin",
                str(mock_docker),
            ],
            cwd=workspace,
        )
        require(
            monitor_missing_run.returncode != 0,
            "dry-run unexpectedly ignored a missing monitor binary for monitor-enabled entries",
        )
        require(
            "monitor binary not found" in f"{monitor_missing_run.stdout}\n{monitor_missing_run.stderr}",
            f"unexpected missing-monitor failure:\nSTDOUT:\n{monitor_missing_run.stdout}\nSTDERR:\n{monitor_missing_run.stderr}",
        )

        stateafl_manifest_path = tmpdir / "stateafl.manifest.json"
        stateafl_plan_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "plan",
                "--catalog",
                str(catalog),
                "--cards-json",
                str(cards_json),
                "--stage",
                "main-study",
                "--campaign",
                "stateafl-smoke",
                "--subjects",
                "live555",
                "--variants",
                "stateafl",
                "--runs",
                "1",
                "--fuzz-timeout-sec",
                "60",
                "--out",
                str(stateafl_manifest_path),
            ],
            cwd=workspace,
        )
        require(
            stateafl_plan_result.returncode == 0,
            f"stateafl-only manifest planning failed:\nSTDOUT:\n{stateafl_plan_result.stdout}\nSTDERR:\n{stateafl_plan_result.stderr}",
        )

        stateafl_run_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "run",
                str(stateafl_manifest_path),
                "--results-root",
                str(tmpdir / "stateafl-results"),
                "--dry-run",
                "--afl-fuzz",
                "/definitely/missing/afl-fuzz",
                "--docker-bin",
                str(mock_docker),
            ],
            cwd=workspace,
        )
        require(
            stateafl_run_result.returncode == 0,
            f"stateafl dry-run should not require local afl-fuzz injection:\nSTDOUT:\n{stateafl_run_result.stdout}\nSTDERR:\n{stateafl_run_result.stderr}",
        )

        entries = {entry["variant"]: entry for entry in manifest["entries"]}
        require(set(SMOKE_VARIANTS) <= set(entries), f"unexpected manifest variants: {sorted(entries)}")

        results_root = tmpdir / "results"
        missing_audit_path = tmpdir / "missing-result-audit.json"
        missing_audit_csv = tmpdir / "missing-result-audit.csv"
        missing_audit_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "audit-results",
                str(manifest_path),
                "--results-root",
                str(results_root),
                "--out",
                str(missing_audit_path),
                "--csv-out",
                str(missing_audit_csv),
                "--require-complete",
            ],
            cwd=workspace,
        )
        require(
            missing_audit_result.returncode != 0,
            "result audit unexpectedly passed a manifest with no result tarballs",
        )
        missing_audit = json.loads(missing_audit_path.read_text(encoding="utf-8"))
        require(
            missing_audit.get("schema_version") == "bizonefuzz.profuzzbench.result_audit.v1",
            f"unexpected missing-audit schema: {missing_audit}",
        )
        require(
            missing_audit.get("expected_runs") == len(SMOKE_VARIANTS)
            and missing_audit.get("completed_runs") == 0
            and missing_audit.get("missing_runs") == len(SMOKE_VARIANTS),
            f"missing-audit did not expose absent tarballs: {missing_audit}",
        )
        require(
            missing_audit.get("gate_passed") is False
            and any("missing result tarballs" in item for item in missing_audit.get("gate_problems", [])),
            f"missing-audit lost strict gate failure reason: {missing_audit}",
        )
        require(missing_audit_csv.is_file(), "missing-audit did not write run-level CSV")

        missing_finalize_dir = tmpdir / "missing-finalize"
        missing_finalize_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "finalize-artifacts",
                str(manifest_path),
                "--results-root",
                str(results_root),
                "--out-dir",
                str(missing_finalize_dir),
                "--workspace",
                str(workspace),
                "--rvem-tool",
                str(rvem_tool),
            ],
            cwd=workspace,
            timeout=60,
        )
        require(
            missing_finalize_result.returncode != 0,
            "finalize-artifacts unexpectedly passed a manifest with no result tarballs",
        )
        missing_finalize_manifest = json.loads((missing_finalize_dir / "finalization_manifest.json").read_text(encoding="utf-8"))
        require(
            missing_finalize_manifest.get("schema_version") == "bizonefuzz.profuzzbench.finalize.v1",
            f"unexpected finalize schema for missing tarballs: {missing_finalize_manifest}",
        )
        require(
            missing_finalize_manifest.get("gate_passed") is False
            and missing_finalize_manifest.get("failed_stage") == "audit-results",
            f"finalize did not preserve the true missing-tarball failure stage: {missing_finalize_manifest}",
        )
        require(
            missing_finalize_manifest.get("stages", [{}])[0].get("returncode") != 0,
            f"finalize failure manifest lost audit-results return code: {missing_finalize_manifest}",
        )

        broken_results_root = tmpdir / "broken-results"
        broken_results_dir = broken_results_root / "results-live555"
        broken_results_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(broken_results_dir / f"{entries['full']['out_dir']}_1.tar.gz", "w:gz") as archive:
            add_text_member(archive, f"{entries['full']['out_dir']}/cov_over_time.csv", make_cov_csv())
        broken_audit_path = tmpdir / "broken-result-audit.json"
        broken_audit_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "audit-results",
                str(manifest_path),
                "--results-root",
                str(broken_results_root),
                "--variants",
                "full",
                "--out",
                str(broken_audit_path),
                "--require-complete",
                "--require-coverage",
                "--require-monitor-artifacts",
            ],
            cwd=workspace,
        )
        require(
            broken_audit_result.returncode != 0,
            "result audit unexpectedly passed a monitor-enabled tarball without monitor artifacts",
        )
        broken_audit = json.loads(broken_audit_path.read_text(encoding="utf-8"))
        require(
            broken_audit.get("completed_runs") == 1
            and broken_audit.get("missing_runs") == 0
            and broken_audit.get("coverage_present_runs") == 1,
            f"broken-audit should isolate monitor-artifact failure from tarball/coverage failure: {broken_audit}",
        )
        require(
            broken_audit.get("monitor_feedback_missing_runs") == 1
            and broken_audit.get("monitor_timing_missing_runs") == 1
            and broken_audit.get("monitor_feedback_unproven_runs") == 1
            and broken_audit.get("monitor_timing_unproven_runs") == 1,
            f"broken-audit did not expose missing monitor artifacts: {broken_audit}",
        )
        require(
            any("feedback artifacts" in item for item in broken_audit.get("gate_problems", []))
            and any("timing artifacts" in item for item in broken_audit.get("gate_problems", [])),
            f"broken-audit lost monitor-artifact gate reasons: {broken_audit}",
        )

        results_dir = results_root / "results-live555"
        results_dir.mkdir(parents=True, exist_ok=True)

        with tarfile.open(results_dir / f"{entries['aflnet-base']['out_dir']}_1.tar.gz", "w:gz") as archive:
            add_text_member(archive, f"{entries['aflnet-base']['out_dir']}/cov_over_time.csv", make_cov_csv())
        with tarfile.open(results_dir / f"{entries['aflnet-patched-base']['out_dir']}_1.tar.gz", "w:gz") as archive:
            add_text_member(archive, f"{entries['aflnet-patched-base']['out_dir']}/cov_over_time.csv", make_cov_csv(second_b_abs=7))

        for index, variant in enumerate(MONITOR_ABLATION_VARIANTS, start=1):
            profile = MONITOR_VARIANT_PROFILES[variant]
            feedback_profile = profile["feedback"]
            timing_profile = profile["timing"]
            run_id = f"{variant.replace('+', '-plus-')}-seed-{index}"
            case_id = f"{run_id}-e1"
            elapsed_sec = 1.25 + (index * 0.25)
            entry_root = entries[variant]["out_dir"]

            with tarfile.open(results_dir / f"{entry_root}_1.tar.gz", "w:gz") as archive:
                add_text_member(
                    archive,
                    f"{entry_root}/cov_over_time.csv",
                    make_cov_csv(**profile["cov"]),
                )
                add_text_member(
                    archive,
                    f"{entry_root}/queue/.state/bizone-feedback/id:000001.jsonl",
                    make_feedback_jsonl(
                        run_id=run_id,
                        elapsed_sec=elapsed_sec,
                        semantic_state_id=int(timing_profile["queue_semantic_state_id"]),
                        case_id=case_id,
                        variant=variant,
                        mode=variant,
                        ablation=variant,
                        **feedback_profile,
                    ),
                )
                add_text_member(
                    archive,
                    f"{entry_root}/queue/.state/bizone-feedback/id:000001.timing.txt",
                    make_timing_text(**timing_profile),
                )

                if variant == "full":
                    add_text_member(
                        archive,
                        f"{entry_root}/queue/.state/bizone-monitor/exec000098.feedback.jsonl",
                        make_feedback_jsonl(
                            run_id="full-exec-98",
                            elapsed_sec=2.25,
                            semantic_state_id=int(timing_profile["feedback_semantic_state_id"]),
                            case_id="full-exec-98-e1",
                            variant=variant,
                            mode=variant,
                            ablation=variant,
                            **feedback_profile,
                        ),
                    )
                    add_text_member(
                        archive,
                        f"{entry_root}/queue/.state/bizone-monitor/exec000098.timing.txt",
                        make_timing_text(
                            stage_hint_origin="feedback",
                            queue_semantic_state_id=int(timing_profile["queue_semantic_state_id"]),
                            feedback_semantic_state_id=int(timing_profile["feedback_semantic_state_id"]),
                        ),
                    )

        result_audit_path = tmpdir / "result-audit.json"
        result_audit_csv = tmpdir / "result-audit.csv"
        result_audit_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "audit-results",
                str(manifest_path),
                "--results-root",
                str(results_root),
                "--out",
                str(result_audit_path),
                "--csv-out",
                str(result_audit_csv),
                "--require-complete",
                "--require-coverage",
                "--require-monitor-artifacts",
            ],
            cwd=workspace,
        )
        require(
            result_audit_result.returncode == 0,
            f"result audit failed on complete synthetic bundle:\nSTDOUT:\n{result_audit_result.stdout}\nSTDERR:\n{result_audit_result.stderr}",
        )
        result_audit = json.loads(result_audit_path.read_text(encoding="utf-8"))
        require(result_audit.get("complete") is True, f"result audit did not report complete: {result_audit}")
        require(result_audit.get("gate_passed") is True, f"result audit gate failed: {result_audit}")
        require(result_audit.get("gate_problems") == [], f"result audit reported unexpected problems: {result_audit}")
        require(
            result_audit.get("expected_runs") == len(SMOKE_VARIANTS)
            and result_audit.get("completed_runs") == len(SMOKE_VARIANTS)
            and result_audit.get("missing_runs") == 0
            and result_audit.get("invalid_tarballs") == 0,
            f"result audit lost tarball completeness counts: {result_audit}",
        )
        require(
            result_audit.get("coverage_present_runs") == len(SMOKE_VARIANTS)
            and result_audit.get("coverage_unproven_runs") == 0,
            f"result audit lost coverage evidence counts: {result_audit}",
        )
        require(
            result_audit.get("monitor_expected_runs") == len(MONITOR_ABLATION_VARIANTS)
            and result_audit.get("monitor_feedback_present_runs") == len(MONITOR_ABLATION_VARIANTS)
            and result_audit.get("monitor_timing_present_runs") == len(MONITOR_ABLATION_VARIANTS)
            and result_audit.get("monitor_feedback_unproven_runs") == 0
            and result_audit.get("monitor_timing_unproven_runs") == 0,
            f"result audit lost monitor artifact counts: {result_audit}",
        )
        with result_audit_csv.open("r", encoding="utf-8", newline="") as handle:
            result_audit_rows = list(csv.DictReader(handle))
        require(
            len(result_audit_rows) == len(SMOKE_VARIANTS),
            f"result audit CSV should contain one row per expected run: {result_audit_rows}",
        )

        collect_dir = tmpdir / "rvem"
        collect_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "collect-rvem",
                str(manifest_path),
                "--results-root",
                str(results_root),
                "--out-dir",
                str(collect_dir),
                "--workspace",
                str(workspace),
                "--rvem-tool",
                str(rvem_tool),
            ],
            cwd=workspace,
            timeout=120,
        )
        require(collect_result.returncode == 0, f"collect-rvem failed:\nSTDOUT:\n{collect_result.stdout}\nSTDERR:\n{collect_result.stderr}")
        require((collect_dir / "campaign.raw.jsonl").is_file(), "missing combined RVEM raw log")
        require((collect_dir / "tables/time_series.csv").is_file(), "missing RVEM time_series.csv")
        require((collect_dir / "tables/timing_audit_series.csv").is_file(), "missing RVEM timing_audit_series.csv")
        require((collect_dir / "plots/coverage_over_time.svg").is_file(), "missing RVEM coverage plot")
        require((collect_dir / "plots/time_to_first_violation.svg").is_file(), "missing RVEM time-to-first-violation plot")
        require((collect_dir / "plots/case_timeline.svg").is_file(), "missing RVEM case timeline plot")
        require((collect_dir / "plots/progress_coverage_bar.svg").is_file(), "missing RVEM progress coverage plot")
        require((collect_dir / "plots/obligation_lifecycle.svg").is_file(), "missing RVEM obligation lifecycle plot")
        require((collect_dir / "plots/timing_hint_origin.svg").is_file(), "missing RVEM timing hint-origin plot")
        require((collect_dir / "dashboard.html").is_file(), "missing RVEM dashboard artifact")
        require((collect_dir / "reports/variant_overview.csv").is_file(), "missing RVEM variant overview report")
        require((collect_dir / "reports/survival_table.csv").is_file(), "missing RVEM survival report")
        require((collect_dir / "reports/progress_obligation_summary.csv").is_file(), "missing RVEM progress/obligation report")
        require((collect_dir / "reports/subject_variant_summary.csv").is_file(), "missing RVEM subject variant summary report")
        require((collect_dir / "reports/subject_metric_matrix.csv").is_file(), "missing RVEM subject metric matrix report")
        require((collect_dir / "reports/pooled_variant_summary.csv").is_file(), "missing RVEM pooled variant report")
        require((collect_dir / "reports/monitor_ablation_summary.csv").is_file(), "missing RVEM monitor ablation summary report")
        require((collect_dir / "reports/pairwise_variant_comparison.csv").is_file(), "missing RVEM pairwise comparison report")
        require((collect_dir / "reports/figure_manifest.json").is_file(), "missing RVEM figure manifest report")
        require((collect_dir / "reports/paper_summary.md").is_file(), "missing RVEM paper summary report")
        require((collect_dir / "reports/paper_tables.md").is_file(), "missing RVEM paper Markdown tables")
        require((collect_dir / "reports/paper_tables.tex").is_file(), "missing RVEM paper LaTeX tables")

        artifact_audit_path = collect_dir / "reports/artifact_audit.json"
        artifact_audit_result = run(
            [
                sys.executable,
                str(rvem_tool),
                "audit-artifacts",
                "--table-dir",
                str(collect_dir / "tables"),
                "--plot-dir",
                str(collect_dir / "plots"),
                "--report-dir",
                str(collect_dir / "reports"),
                "--dashboard-html",
                str(collect_dir / "dashboard.html"),
                "--out",
                str(artifact_audit_path),
                "--require-complete",
                "--require-data",
            ],
            cwd=workspace,
            timeout=60,
        )
        require(
            artifact_audit_result.returncode == 0,
            f"RVEM artifact audit failed:\nSTDOUT:\n{artifact_audit_result.stdout}\nSTDERR:\n{artifact_audit_result.stderr}",
        )
        artifact_audit = json.loads(artifact_audit_path.read_text(encoding="utf-8"))
        require(artifact_audit.get("complete") is True, f"artifact audit did not report complete: {artifact_audit}")
        require(artifact_audit.get("problem_count") == 0, f"artifact audit reported problems: {artifact_audit}")
        require(
            artifact_audit.get("figures", {}).get("time_to_first_violation.svg", {}).get("nonempty_file") is True,
            f"artifact audit lost survival figure evidence: {artifact_audit}",
        )
        require(
            artifact_audit.get("dashboard", {}).get("missing_views") == [],
            f"artifact audit lost dashboard view evidence: {artifact_audit}",
        )

        broken_package_dir = tmpdir / "broken-artifact-package"
        broken_package_result = run(
            [
                sys.executable,
                str(rvem_tool),
                "package-artifacts",
                "--out-dir",
                str(broken_package_dir),
                "--table-dir",
                str(collect_dir / "tables"),
                "--plot-dir",
                str(collect_dir / "plots"),
                "--report-dir",
                str(collect_dir / "reports"),
                "--dashboard-html",
                str(collect_dir / "dashboard.html"),
                "--rvem-audit-json",
                str(artifact_audit_path),
                "--require-core",
                "--require-rvem-audit-complete",
                "--require-result-audit-gate",
                "--require-complete",
            ],
            cwd=workspace,
            timeout=60,
        )
        require(
            broken_package_result.returncode != 0,
            "strict artifact package unexpectedly passed without a result audit",
        )
        broken_package_manifest = json.loads((broken_package_dir / "artifact_package_manifest.json").read_text(encoding="utf-8"))
        require(
            broken_package_manifest.get("gate_passed") is False
            and any("profuzzbench_result_audit" in item for item in broken_package_manifest.get("problems", [])),
            f"strict artifact package did not report the missing result audit truthfully: {broken_package_manifest}",
        )

        package_dir = tmpdir / "artifact-package"
        package_result = run(
            [
                sys.executable,
                str(rvem_tool),
                "package-artifacts",
                "--out-dir",
                str(package_dir),
                "--table-dir",
                str(collect_dir / "tables"),
                "--plot-dir",
                str(collect_dir / "plots"),
                "--report-dir",
                str(collect_dir / "reports"),
                "--dashboard-html",
                str(collect_dir / "dashboard.html"),
                "--rvem-audit-json",
                str(artifact_audit_path),
                "--result-audit-json",
                str(result_audit_path),
                "--result-audit-csv",
                str(result_audit_csv),
                "--raw-jsonl",
                str(collect_dir / "campaign.raw.jsonl"),
                "--manifest",
                str(manifest_path),
                "--note",
                "synthetic ProFuzzBench overlay smoke package; not a 24h x 20 campaign",
                "--require-core",
                "--require-rvem-audit-complete",
                "--require-result-audit-gate",
                "--require-complete",
            ],
            cwd=workspace,
            timeout=60,
        )
        require(
            package_result.returncode == 0,
            f"artifact package failed:\nSTDOUT:\n{package_result.stdout}\nSTDERR:\n{package_result.stderr}",
        )
        package_manifest_path = package_dir / "artifact_package_manifest.json"
        package_checksum_path = package_dir / "checksums.sha256"
        package_readme_path = package_dir / "README.md"
        require(package_manifest_path.is_file(), "missing artifact package manifest")
        require(package_checksum_path.is_file(), "missing artifact package checksums")
        require(package_readme_path.is_file(), "missing artifact package README")
        package_manifest = json.loads(package_manifest_path.read_text(encoding="utf-8"))
        require(
            package_manifest.get("schema_version") == "rvem.repro_package.v1",
            f"unexpected artifact package schema: {package_manifest}",
        )
        require(package_manifest.get("gate_passed") is True, f"artifact package gate failed: {package_manifest}")
        require(package_manifest.get("problem_count") == 0, f"artifact package reported problems: {package_manifest}")
        require(
            package_manifest.get("source_audits", {}).get("rvem_artifact_audit", {}).get("complete") is True,
            f"artifact package lost RVEM audit evidence: {package_manifest}",
        )
        require(
            package_manifest.get("source_audits", {}).get("profuzzbench_result_audit", {}).get("gate_passed") is True,
            f"artifact package lost result audit evidence: {package_manifest}",
        )
        require(
            package_manifest.get("summary", {}).get("copied_file_count", 0) > 20,
            f"artifact package copied too few files: {package_manifest}",
        )
        checksum_lines = [
            line.strip()
            for line in package_checksum_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        require(len(checksum_lines) == package_manifest["summary"]["copied_file_count"], "checksum count did not match package manifest")
        readme_text = package_readme_path.read_text(encoding="utf-8")
        require(
            "Campaign-scale claims still require" in readme_text
            and "not a 24h x 20 campaign" in readme_text,
            f"artifact package README lost truthfulness caveat: {readme_text}",
        )

        finalize_dir = tmpdir / "finalized-artifacts"
        finalize_result = run(
            [
                sys.executable,
                str(overlay_tool),
                "finalize-artifacts",
                str(manifest_path),
                "--results-root",
                str(results_root),
                "--out-dir",
                str(finalize_dir),
                "--workspace",
                str(workspace),
                "--rvem-tool",
                str(rvem_tool),
            ],
            cwd=workspace,
            timeout=120,
        )
        require(
            finalize_result.returncode == 0,
            f"finalize-artifacts failed on complete synthetic bundle:\nSTDOUT:\n{finalize_result.stdout}\nSTDERR:\n{finalize_result.stderr}",
        )
        finalize_manifest_path = finalize_dir / "finalization_manifest.json"
        require(finalize_manifest_path.is_file(), "finalize-artifacts did not write finalization_manifest.json")
        finalize_manifest = json.loads(finalize_manifest_path.read_text(encoding="utf-8"))
        require(
            finalize_manifest.get("schema_version") == "bizonefuzz.profuzzbench.finalize.v1",
            f"unexpected finalize manifest schema: {finalize_manifest}",
        )
        require(
            finalize_manifest.get("gate_passed") is True
            and finalize_manifest.get("failed_stage") == "",
            f"finalize manifest did not report a clean strict pass: {finalize_manifest}",
        )
        require(
            [stage.get("name") for stage in finalize_manifest.get("stages", [])]
            == ["audit-results", "collect-rvem", "audit-rvem-artifacts", "package-artifacts"],
            f"finalize manifest lost stage ordering: {finalize_manifest}",
        )
        require(
            all(stage.get("passed") is True and stage.get("returncode") == 0 for stage in finalize_manifest.get("stages", [])),
            f"finalize manifest contains a failed stage despite success: {finalize_manifest}",
        )
        require(
            (finalize_dir / "audits/result_audit.json").is_file()
            and (finalize_dir / "audits/rvem_artifact_audit.json").is_file()
            and (finalize_dir / "artifact-package/artifact_package_manifest.json").is_file()
            and (finalize_dir / "artifact-package/checksums.sha256").is_file(),
            f"finalize-artifacts missed expected output files under {finalize_dir}",
        )
        finalized_package = json.loads((finalize_dir / "artifact-package/artifact_package_manifest.json").read_text(encoding="utf-8"))
        require(
            finalized_package.get("gate_passed") is True
            and finalized_package.get("source_audits", {}).get("profuzzbench_result_audit", {}).get("gate_passed") is True,
            f"finalized package lost strict audit provenance: {finalized_package}",
        )

        raw_records = load_jsonl(collect_dir / "campaign.raw.jsonl")
        timing_records = [record for record in raw_records if record.get("event_type") == "timing_audit"]
        expected_timing_rows = len(MONITOR_ABLATION_VARIANTS) + 1
        require(
            len(timing_records) == expected_timing_rows,
            f"expected {expected_timing_rows} timing_audit records, saw {len(timing_records)}",
        )

        with (collect_dir / "tables/timing_audit_series.csv").open("r", encoding="utf-8", newline="") as handle:
            timing_rows = list(csv.DictReader(handle))
        require(len(timing_rows) == expected_timing_rows, f"expected {expected_timing_rows} timing_audit rows, saw {len(timing_rows)}")
        by_scope = {(row["variant"], row["artifact_scope"]): row for row in timing_rows}
        for variant in MONITOR_ABLATION_VARIANTS:
            require((variant, "saved-seed") in by_scope, f"missing {variant} saved-seed timing row: {timing_rows}")
        require(("full", "exec-history") in by_scope, f"missing full exec-history timing row: {timing_rows}")
        require(
            by_scope[("full", "saved-seed")]["stage_hint_origin"] == "queue",
            f"full saved-seed row lost queue stage origin: {by_scope[('full', 'saved-seed')]}",
        )
        for variant in MONITOR_ABLATION_VARIANTS:
            require(
                by_scope[(variant, "saved-seed")]["stage_hint_origin"] == "queue",
                f"{variant} saved-seed row lost queue stage origin: {by_scope[(variant, 'saved-seed')]}",
            )
        require(
            by_scope[("full", "exec-history")]["stage_hint_origin"] == "feedback",
            f"full exec-history row lost feedback stage origin: {by_scope[('full', 'exec-history')]}",
        )
        require(
            by_scope[("full", "saved-seed")]["pre_send_delay_ms"] == "[0,60,120]",
            f"unexpected pre_send_delay_ms encoding: {by_scope[('full', 'saved-seed')]}",
        )
        require(
            by_scope[("full", "saved-seed")]["stage_keepalive_preferred_request_class"] == "options",
            f"full saved-seed row lost stage keepalive preference: {by_scope[('full', 'saved-seed')]}",
        )
        require(
            by_scope[("full", "saved-seed")]["stage_retry_preferred_request_class"] == "options",
            f"full saved-seed row lost stage retry preference: {by_scope[('full', 'saved-seed')]}",
        )
        require(
            by_scope[("full", "exec-history")]["feedback_keepalive_preferred_request_class"] == "options",
            f"full exec-history row lost feedback keepalive preference: {by_scope[('full', 'exec-history')]}",
        )
        require(
            by_scope[("full", "exec-history")]["feedback_retry_preferred_request_class"] == "options",
            f"full exec-history row lost feedback retry preference: {by_scope[('full', 'exec-history')]}",
        )
        require(
            by_scope[("full", "exec-history")]["retry_source_request_class"] == "options",
            f"full exec-history row lost retry source request class: {by_scope[('full', 'exec-history')]}",
        )
        require(
            "\"kind\":\"retry\"" in by_scope[("full", "saved-seed")]["injected_plan"],
            f"unexpected injected_plan encoding: {by_scope[('full', 'saved-seed')]}",
        )
        report_manifest = json.loads((collect_dir / "reports/figure_manifest.json").read_text(encoding="utf-8"))
        figure_names = {item["filename"] for item in report_manifest.get("figures", [])}
        require("time_to_first_violation.svg" in figure_names, f"figure manifest missing survival figure: {report_manifest}")
        require("obligation_lifecycle.svg" in figure_names, f"figure manifest missing obligation figure: {report_manifest}")
        pairwise_rows = list(csv.DictReader((collect_dir / "reports/pairwise_variant_comparison.csv").open("r", encoding="utf-8", newline="")))
        require(pairwise_rows, "expected non-empty pairwise comparison report")
        for variant in MONITOR_ABLATION_VARIANTS:
            require(
                any(
                    row["reference_label"] == "aflnet/aflnet-base"
                    and row["treatment_label"] == f"bizone-aflnet/{variant}"
                    for row in pairwise_rows
                ),
                f"pairwise comparison report missing baseline-vs-{variant} row: {pairwise_rows}",
            )
        require(
            all("mw_pvalue_two_sided" in row and "significance_tier" in row for row in pairwise_rows),
            f"pairwise comparison report missing significance fields: {pairwise_rows}",
        )
        subject_rows = list(csv.DictReader((collect_dir / "reports/subject_variant_summary.csv").open("r", encoding="utf-8", newline="")))
        require(
            len(subject_rows) == len(SMOKE_VARIANTS),
            f"expected {len(SMOKE_VARIANTS)} subject variant summary rows, saw {len(subject_rows)}",
        )
        subject_by_variant = {row["variant"]: row for row in subject_rows}
        require(set(SMOKE_VARIANTS) <= set(subject_by_variant), f"missing subject variants: {subject_rows}")
        for variant, row in subject_by_variant.items():
            require(row["campaign"] == "main-study-smoke", f"{variant} row lost campaign coordinate: {row}")
            require(row["subject"] == "live555", f"{variant} row lost subject coordinate: {row}")
            expected_fuzzer = "aflnet" if variant == "aflnet-base" else "bizone-aflnet"
            require(row["fuzzer"] == expected_fuzzer, f"{variant} row lost fuzzer coordinate: {row}")
            require(row["runs"] == "1", f"{variant} row lost run count: {row}")
            for field in (
                "event_fraction_ci_low",
                "event_fraction_ci_high",
                "coverage_ci_low",
                "coverage_ci_high",
                "semantic_ci_low",
                "semantic_ci_high",
                "overhead_ci_low",
                "overhead_ci_high",
                "mean_unique_progress_bins",
                "mean_boundary_hit_rate",
                "mean_feedback_origin_rows",
                "mean_queue_origin_rows",
            ):
                require(field in row, f"subject variant summary missing {field}: {row}")
        require(
            subject_by_variant["full"]["event_runs"] == "1" and subject_by_variant["full"]["event_fraction"] == "1.0",
            f"full variant should retain violation event summary: {subject_by_variant['full']}",
        )
        require(
            subject_by_variant["aflnet-base"]["event_runs"] == "0" and subject_by_variant["aflnet-base"]["event_fraction"] == "0.0",
            f"baseline variant should remain censored in subject summary: {subject_by_variant['aflnet-base']}",
        )
        for variant in MONITOR_ABLATION_VARIANTS:
            expected_event_runs = "1" if variant == "full" else "0"
            expected_event_fraction = "1.0" if variant == "full" else "0.0"
            require(
                subject_by_variant[variant]["event_runs"] == expected_event_runs
                and subject_by_variant[variant]["event_fraction"] == expected_event_fraction,
                f"{variant} variant lost expected event summary: {subject_by_variant[variant]}",
            )
        for variant in MONITOR_ABLATION_VARIANTS:
            require_float_text(
                subject_by_variant[variant]["mean_queue_origin_rows"],
                1.0,
                f"{variant} variant should retain one queue-origin timing row",
            )
        require(
            subject_by_variant["full"]["mean_feedback_origin_rows"] == "1.0"
            and subject_by_variant["full"]["mean_queue_origin_rows"] == "1.0",
            f"full variant should retain timing provenance in subject summary: {subject_by_variant['full']}",
        )

        monitor_ablation_rows = list(csv.DictReader((collect_dir / "reports/monitor_ablation_summary.csv").open("r", encoding="utf-8", newline="")))
        require(monitor_ablation_rows, "expected non-empty monitor ablation summary report")
        subject_ablation_by_variant = {
            row["variant"]: row for row in monitor_ablation_rows if row["scope"] == "subject"
        }
        require(
            set(MONITOR_ABLATION_VARIANTS) <= set(subject_ablation_by_variant),
            f"missing subject-scope monitor ablation rows: {monitor_ablation_rows}",
        )
        full_profile = MONITOR_VARIANT_PROFILES["full"]
        require_float_text(
            subject_ablation_by_variant["full"]["delta_event_fraction"],
            0.0,
            "full subject ablation row should be zero-delta on event fraction against itself",
        )
        require_float_text(
            subject_ablation_by_variant["full"]["delta_mean_final_coverage"],
            0.0,
            "full subject ablation row should be zero-delta on coverage against itself",
        )
        for variant in MONITOR_ABLATION_VARIANTS:
            row = subject_ablation_by_variant[variant]
            expected_event_delta = 0.0 if variant == "full" else -1.0
            expected_cov_delta = profile_final_coverage(MONITOR_VARIANT_PROFILES[variant]) - profile_final_coverage(full_profile)
            expected_semantic_delta = (
                MONITOR_VARIANT_PROFILES[variant]["feedback"]["monitor_state_count"]
                - full_profile["feedback"]["monitor_state_count"]
            )
            require_float_text(
                row["delta_event_fraction"],
                expected_event_delta,
                f"{variant} subject ablation row lost expected event-fraction delta vs full",
            )
            require_float_text(
                row["delta_mean_final_coverage"],
                expected_cov_delta,
                f"{variant} subject ablation row lost expected coverage delta vs full",
            )
            require_float_text(
                row["delta_mean_final_semantic_states"],
                expected_semantic_delta,
                f"{variant} subject ablation row lost expected semantic-state delta vs full",
            )

        matrix_rows = list(csv.DictReader((collect_dir / "reports/subject_metric_matrix.csv").open("r", encoding="utf-8", newline="")))
        require(len(matrix_rows) == 1, f"expected one subject metric matrix row, saw {matrix_rows}")
        matrix_row = matrix_rows[0]
        expected_matrix_fields = {
            "campaign",
            "subject",
            "aflnet/full__median_ttfv_sec",
            "aflnet/full__mean_final_coverage",
            "aflnet/full__mean_final_semantic_states",
            "aflnet/full__mean_unique_progress_bins",
            "aflnet/full__mean_boundary_hit_rate",
        }
        for variant in SMOKE_VARIANTS:
            expected_matrix_fields.add(f"aflnet/{variant}__runs")
            expected_matrix_fields.add(f"aflnet/{variant}__event_fraction")
        require(expected_matrix_fields <= set(matrix_row), f"subject metric matrix missing fields: {matrix_row}")
        require(
            matrix_row["campaign"] == "main-study-smoke" and matrix_row["subject"] == "live555",
            f"subject metric matrix lost campaign/subject coordinates: {matrix_row}",
        )
        require_float_text(
            matrix_row["aflnet/aflnet-base__event_fraction"],
            0.0,
            "baseline matrix row lost censored event fraction",
        )
        for variant in MONITOR_ABLATION_VARIANTS:
            require_float_text(
                matrix_row[f"aflnet/{variant}__event_fraction"],
                1.0 if variant == "full" else 0.0,
                f"{variant} matrix row lost expected event fraction",
            )

        paper_tables_md = (collect_dir / "reports/paper_tables.md").read_text(encoding="utf-8")
        require("# RVEM Subject Tables" in paper_tables_md, "paper_tables.md missing subject-table title")
        require("## Primary Metrics" in paper_tables_md, "paper_tables.md missing primary metrics section")
        require("## Auxiliary Metrics" in paper_tables_md, "paper_tables.md missing auxiliary metrics section")
        for variant in SMOKE_VARIANTS:
            require(
                f"| live555 | aflnet/{variant} | 1 |" in paper_tables_md,
                f"paper_tables.md missing {variant} subject row",
            )
        paper_summary_md = (collect_dir / "reports/paper_summary.md").read_text(encoding="utf-8")
        require("## Monitor Ablation Delta vs Full" in paper_summary_md, "paper_summary.md missing ablation delta section")
        for variant in MONITOR_ABLATION_VARIANTS:
            cov_delta = profile_final_coverage(MONITOR_VARIANT_PROFILES[variant]) - profile_final_coverage(full_profile)
            semantic_delta = (
                MONITOR_VARIANT_PROFILES[variant]["feedback"]["monitor_state_count"]
                - full_profile["feedback"]["monitor_state_count"]
            )
            event_delta = 0.0 if variant == "full" else -1.0
            require(
                f"| live555 | aflnet/{variant} | {event_delta:.2f} | {cov_delta:.2f} | {semantic_delta:.2f} |" in paper_summary_md,
                f"paper_summary.md missing {variant} ablation delta row",
            )
        paper_tables_tex = (collect_dir / "reports/paper_tables.tex").read_text(encoding="utf-8")
        require("Subject-level primary Bi-ZoneFuzz++ metrics" in paper_tables_tex, "paper_tables.tex missing primary caption")
        require("Subject-level auxiliary progress, boundary, and timing provenance metrics" in paper_tables_tex, "paper_tables.tex missing auxiliary caption")
        for variant in SMOKE_VARIANTS:
            require(f"live555 & aflnet/{variant} & 1" in paper_tables_tex, f"paper_tables.tex missing {variant} subject row")
        report_manifest = json.loads((collect_dir / "reports/report_manifest.json").read_text(encoding="utf-8"))
        generated_files = report_manifest.get("generated_files", {})
        for key in (
            "subject_variant_summary_csv",
            "subject_metric_matrix_csv",
            "monitor_ablation_summary_csv",
            "paper_tables_md",
            "paper_tables_tex",
        ):
            require(key in generated_files, f"report manifest missing {key}: {report_manifest}")
        require(report_manifest.get("variant_count") == len(SMOKE_VARIANTS), f"unexpected variant count: {report_manifest}")
        require(report_manifest.get("subject_variant_count") == len(SMOKE_VARIANTS), f"unexpected subject variant count: {report_manifest}")
        require(
            report_manifest.get("monitor_ablation_rows") == len(MONITOR_ABLATION_VARIANTS) * 2,
            f"unexpected monitor ablation row count: {report_manifest}",
        )
        require(report_manifest.get("subject_matrix_rows") == 1, f"unexpected subject matrix row count: {report_manifest}")

    print("Bi-ZoneFuzz++ ProFuzzBench overlay smoke passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"profuzzbench overlay smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
