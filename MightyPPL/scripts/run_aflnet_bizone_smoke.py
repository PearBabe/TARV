#!/usr/bin/env python3
"""Smoke-test the AFLNet <-> Bi-ZoneFuzz++ live feedback bridge."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

MODE_CHANNEL_MASKS = {
    "oracle-only": 0,
    "frontier-only": 1,
    "zone-only": 2,
    "obligation-only": 4,
    "progress-only": 8,
    "frontier+zone": 3,
    "full": 127,
}


def run(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expected_channel_mask_for_mode(mode: str) -> int:
    normalized = str(mode).strip().lower()
    require(normalized in MODE_CHANNEL_MASKS, f"unknown monitor mode for channel-mask expectation: {mode!r}")
    return MODE_CHANNEL_MASKS[normalized]


def require_disabled_feedback_channels(frame: dict, expected_mask: int) -> None:
    feedback = frame.get("feedback", {})
    frontier = feedback.get("frontier", {})
    zone = feedback.get("zone", {})
    obligation = feedback.get("obligation", {})
    progress = feedback.get("property_progress", {})
    protocol = feedback.get("protocol_semantic", {})
    mutation = feedback.get("mutation_hint", {})
    explain = feedback.get("explainability", {})

    if (expected_mask & 1) == 0:
        require(frontier.get("frontier_size_pos", 0) == 0, f"frontier feedback should be reset when disabled: {frontier}")
        require(frontier.get("frontier_size_neg", 0) == 0, f"frontier feedback should be reset when disabled: {frontier}")
        require(not frontier.get("frontier_novelty", False), f"frontier novelty should be false when disabled: {frontier}")
    if (expected_mask & 2) == 0:
        require(zone.get("boundary_class", "") == "unknown", f"zone feedback should reset to unknown when disabled: {zone}")
        require(int(zone.get("violated_guard_count", 0)) == 0, f"violated_guard_count should be zero when zone is disabled: {zone}")
        require(int(zone.get("near_deadline_count", 0)) == 0, f"near_deadline_count should be zero when zone is disabled: {zone}")
    if (expected_mask & 4) == 0:
        require(int(obligation.get("active_obligation_count", 0)) == 0, f"obligation feedback should be zeroed when disabled: {obligation}")
        require(int(obligation.get("expired_now", 0)) == 0, f"obligation expiry should be zero when disabled: {obligation}")
    if (expected_mask & 8) == 0:
        require(progress.get("property_progress_vector", []) == [], f"progress vector should be empty when progress is disabled: {progress}")
        require(progress.get("newly_reached_progress_bins", []) == [], f"progress bins should be empty when progress is disabled: {progress}")
        require(int(progress.get("property_coverage_delta", 0)) == 0, f"progress delta should be zero when progress is disabled: {progress}")
    if (expected_mask & 16) == 0:
        require(protocol.get("session_phase", "unknown") == "unknown", f"protocol session_phase should reset when disabled: {protocol}")
        require(protocol.get("request_class", "unknown") == "unknown", f"protocol request_class should reset when disabled: {protocol}")
        require(protocol.get("response_class", "unknown") == "unknown", f"protocol response_class should reset when disabled: {protocol}")
    if (expected_mask & 32) == 0:
        require(int(mutation.get("recommended_gap_delta_ms", 0)) == 0, f"recommended_gap_delta_ms should reset when mutation hints are disabled: {mutation}")
        require(mutation.get("candidate_next_event_classes", []) == [], f"candidate_next_event_classes should be empty when mutation hints are disabled: {mutation}")
        require(not mutation.get("retry_hint", False), f"retry_hint should be false when mutation hints are disabled: {mutation}")
        require(not mutation.get("keepalive_hint", False), f"keepalive_hint should be false when mutation hints are disabled: {mutation}")
        require(not mutation.get("silence_hint", False), f"silence_hint should be false when mutation hints are disabled: {mutation}")
    if (expected_mask & 64) == 0:
        require(explain.get("dominant_property_id", "") == "", f"dominant_property_id should reset when explainability is disabled: {explain}")
        require(int(explain.get("decisive_transition_id", 0)) == 0, f"decisive_transition_id should reset when explainability is disabled: {explain}")
        require(explain.get("critical_deadline_source", "") == "", f"critical_deadline_source should reset when explainability is disabled: {explain}")
        require(explain.get("shortest_witness_summary", "") == "", f"shortest_witness_summary should reset when explainability is disabled: {explain}")


def find_free_port(network_scheme: str) -> int:
    sock_type = socket.SOCK_DGRAM if network_scheme.lower() == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            try:
                records.append(json.loads(text))
            except json.JSONDecodeError:
                # AFLNet may be terminated by timeout while the last monitor line
                # is still being flushed; keep the valid prefix instead of
                # discarding the entire smoke result.
                continue
    return records


def collect_artifact_candidates(preferred: Path, fallback_specs: list[tuple[Path, str]]) -> list[Path]:
    candidates: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path)
        if key in seen:
            return
        candidates.append(path)
        seen.add(key)

    add(preferred)
    for directory, pattern in fallback_specs:
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.glob(pattern), reverse=True):
            add(candidate)
    return candidates


def resolve_artifact(candidates: list[Path]) -> Path:
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def load_formula_from_property_card(bundle_path: Path, property_id: str) -> str:
    require(bundle_path.is_file(), f"property-card bundle is missing: {bundle_path}")
    require(property_id.strip(), "property-card formula selection requires a non-empty property id")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    cards = bundle.get("cards", [])
    require(isinstance(cards, list), f"invalid property-card bundle schema in {bundle_path}")
    for card in cards:
        if str(card.get("property_id", "")).strip() != property_id:
            continue
        formula = str(card.get("MITL_formula", "")).strip()
        require(formula, f"property card {property_id!r} has no MITL_formula in {bundle_path}")
        return formula
    raise AssertionError(f"property card {property_id!r} not found in {bundle_path}")


def parse_timing_plan(text: str) -> dict[str, str]:
    plan: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        plan[key] = value
    return plan


def property_eval_records(records: list[dict]) -> list[dict]:
    return [record for record in records if record.get("event_type") == "property_eval"]


def event_line_tokens(line: str) -> list[str]:
    return [token.strip().lower() for token in line.split(",") if token.strip()]


def mutation_hint_for_record(record: dict) -> dict:
    return (
        record.get("feedback_frame", {})
        .get("feedback", {})
        .get("mutation_hint", {})
    )


def mutation_hint_mask(mutation_hint: dict) -> int:
    mask = 0
    if mutation_hint.get("retry_hint"):
        mask |= 1
    if mutation_hint.get("keepalive_hint"):
        mask |= 2
    if mutation_hint.get("silence_hint"):
        mask |= 4
    return mask


def aggregate_feedback_hint_mask(records: list[dict]) -> int:
    mask = 0
    for record in property_eval_records(records):
        mask |= mutation_hint_mask(mutation_hint_for_record(record))
    return mask


def is_retry_label_token(token: str) -> bool:
    lowered = token.strip().lower()
    if lowered == "rtx":
        return True
    if not lowered.startswith("rtx") or len(lowered) == 3:
        return False
    return lowered[3:].isdigit()


def normalize_request_class(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"", "none", "-", "unknown", "req", "rsp", "silence"}:
        return ""
    if text.startswith("req_") and len(text) > 4:
        text = text[4:]
    elif (
        text.startswith("proto_")
        or text.startswith("state_")
        or text.startswith("phase_")
        or text.startswith("rsp_")
        or text.startswith("sip_tx_")
        or text.startswith("rtsp_sess_")
        or text.startswith("invite_rsp")
        or is_retry_label_token(text)
        or text[0].isdigit()
    ):
        return ""
    return text


def candidate_next_event_classes(record: dict) -> list[str]:
    mutation_hint = mutation_hint_for_record(record)
    raw_candidates = mutation_hint.get("candidate_next_event_classes", [])
    if not isinstance(raw_candidates, list):
        return []
    candidates: list[str] = []
    for raw_candidate in raw_candidates:
        candidate = normalize_request_class(raw_candidate)
        if candidate:
            candidates.append(candidate)
    return candidates


def request_class_matches_hint(request_class: str, preferred_request_class: str) -> bool:
    request = request_class.strip().lower()
    preferred = preferred_request_class.strip().lower()
    if not request or not preferred:
        return False
    if request == preferred:
        return True
    return (
        (request == "clienthello" and preferred == "ch")
        or (request == "associate_rq" and preferred == "assoc_req")
    )


def observed_request_classes(event_lines: list[str]) -> set[str]:
    classes: set[str] = set()
    for line in event_lines:
        for token in event_line_tokens(line):
            if not token.startswith("req_"):
                continue
            request_class = normalize_request_class(token)
            if request_class:
                classes.add(request_class)
    return classes


def derive_preferred_request_class_from_feedback(
    records: list[dict],
    event_lines: list[str],
    protocol: str = "",
) -> str:
    history_request_classes = observed_request_classes(event_lines)
    property_records = property_eval_records(records)
    if not property_records:
        return ""

    for record in reversed(property_records):
        for candidate in candidate_next_event_classes(record):
            if history_request_classes and any(
                request_class_matches_hint(request_class, candidate)
                for request_class in history_request_classes
            ):
                return candidate

    return ""


def plan_preferred_request_classes(plan: dict[str, str]) -> dict[str, str]:
    fields = (
        "stage_preferred_request_class",
        "queue_preferred_request_class",
        "feedback_preferred_request_class",
    )
    preferred: dict[str, str] = {}
    for field in fields:
        value = normalize_request_class(plan.get(field, ""))
        if value:
            preferred[field] = value
    return preferred


def plan_retry_preferred_request_classes(plan: dict[str, str]) -> dict[str, str]:
    fields = (
        "stage_retry_preferred_request_class",
        "queue_retry_preferred_request_class",
        "feedback_retry_preferred_request_class",
    )
    preferred: dict[str, str] = {}
    for field in fields:
        value = normalize_request_class(plan.get(field, ""))
        if value:
            preferred[field] = value
    return preferred


def plan_keepalive_preferred_request_classes(plan: dict[str, str]) -> dict[str, str]:
    fields = (
        "stage_keepalive_preferred_request_class",
        "queue_keepalive_preferred_request_class",
        "feedback_keepalive_preferred_request_class",
    )
    preferred: dict[str, str] = {}
    for field in fields:
        value = normalize_request_class(plan.get(field, ""))
        if value:
            preferred[field] = value
    return preferred


def collect_nonzero_pre_send_delays(plan: dict[str, str]) -> list[int]:
    delays: list[int] = []
    for key, value in plan.items():
        if not key.startswith("pre_send_delay_ms["):
            continue
        if value == "0":
            continue
        delays.append(int(value))
    return sorted(delays)


def collect_active_timing_plans(paths: list[Path]) -> list[tuple[Path, dict[str, str]]]:
    active: list[tuple[Path, dict[str, str]]] = []
    for path in paths:
        if not path.is_file():
            continue
        plan = parse_timing_plan(path.read_text(encoding="utf-8"))
        if plan.get("active") != "1":
            continue
        if any(plan.get(field) == "1" for field in (
            "gap_expansion",
            "gap_compression",
            "silence_window",
            "keepalive_bias",
            "boundary_bisection",
            "retry_insertion",
            "keepalive_insertion",
        )):
            active.append((path, plan))
    return active


def validate_insertion_plan(path: Path, plan: dict[str, str]) -> None:
    has_insertion = plan.get("retry_insertion") == "1" or plan.get("keepalive_insertion") == "1"
    insertion_count = int(plan.get("insertion_count", "0"))
    base_message_count = int(plan.get("base_message_count", "0"))
    message_count = int(plan.get("message_count", "0"))
    hybrid_flag = plan.get("hybrid_keepalive_retry", "0")
    retry_contextual = plan.get("retry_contextual", "0")

    require(message_count >= base_message_count, f"timing plan shrank message count in {path}: {plan}")
    require(hybrid_flag in {"0", "1"}, f"invalid hybrid_keepalive_retry flag in {path}: {plan}")
    require(retry_contextual in {"0", "1"}, f"invalid retry_contextual flag in {path}: {plan}")
    if not has_insertion:
        require(
            insertion_count == 0,
            f"non-insertion timing plan reported insertion_count={insertion_count} in {path}: {plan}",
        )
        return

    require(insertion_count > 0, f"insertion plan missing insertion_count in {path}: {plan}")
    require(
        message_count == base_message_count + insertion_count,
        f"insertion plan message_count mismatch in {path}: {plan}",
    )

    delayed_slots = set()
    for key in plan:
        if key.startswith("pre_send_delay_ms[") and plan[key] != "0":
            slot_text = key[len("pre_send_delay_ms[") : -1]
            delayed_slots.add(int(slot_text))

    require(delayed_slots, f"insertion plan missing pre_send_delay_ms entries in {path}: {plan}")

    saw_cross_request = False
    saw_retry_kind = False
    saw_keepalive_kind = False
    for index in range(insertion_count):
        kind_key = f"injected_kind[{index}]"
        base_count_key = f"injected_base_message_count[{index}]"
        source_key = f"injected_source_index[{index}]"
        after_key = f"injected_after_index[{index}]"
        slot_key = f"injected_slot_index[{index}]"
        require(kind_key in plan, f"missing {kind_key} in {path}: {plan}")
        require(base_count_key in plan, f"missing {base_count_key} in {path}: {plan}")
        require(source_key in plan, f"missing {source_key} in {path}: {plan}")
        require(after_key in plan, f"missing {after_key} in {path}: {plan}")
        require(slot_key in plan, f"missing {slot_key} in {path}: {plan}")

        insertion_kind = plan[kind_key]
        insertion_base_count = int(plan[base_count_key])
        source_index = int(plan[source_key])
        after_index = int(plan[after_key])
        slot_index = int(plan[slot_key])
        require(
            insertion_kind in {"retry", "keepalive"},
            f"invalid insertion kind {insertion_kind!r} in {path}: {plan}",
        )
        require(
            1 <= insertion_base_count <= message_count,
            f"invalid insertion base count {insertion_base_count} in {path}: {plan}",
        )
        require(
            0 <= source_index < insertion_base_count,
            f"invalid source index {source_index} in {path}: {plan}",
        )
        require(
            0 <= after_index < insertion_base_count,
            f"invalid after index {after_index} in {path}: {plan}",
        )
        require(
            0 <= slot_index < message_count,
            f"invalid injected slot {slot_index} in {path}: {plan}",
        )
        require(
            slot_index > after_index,
            f"injected slot did not land after base index in {path}: {plan}",
        )
        require(
            slot_index in delayed_slots,
            f"injected slot {slot_index} missing pre-send delay in {path}: {plan}",
        )
        if insertion_kind == "retry" and after_index > source_index:
            saw_cross_request = True
            saw_retry_kind = True
        elif insertion_kind == "retry":
            saw_retry_kind = True
        elif insertion_kind == "keepalive":
            saw_keepalive_kind = True

    cross_request_flag = plan.get("cross_request_resend", "0")
    require(
        cross_request_flag in {"0", "1"},
        f"invalid cross_request_resend flag in {path}: {plan}",
    )
    require(
        (cross_request_flag == "1") == saw_cross_request,
        f"cross_request_resend flag mismatch in {path}: {plan}",
    )
    if hybrid_flag == "1":
        require(
            plan.get("retry_insertion") == "1" and plan.get("keepalive_insertion") == "1",
            f"hybrid plan missing retry/keepalive flags in {path}: {plan}",
        )
        require(
            saw_retry_kind and saw_keepalive_kind,
            f"hybrid plan missing retry/keepalive insertion kinds in {path}: {plan}",
        )

    keepalive_synthesized = plan.get("keepalive_synthesized", "0")
    require(
        keepalive_synthesized in {"0", "1"},
        f"invalid keepalive_synthesized flag in {path}: {plan}",
    )
    require(
        not (keepalive_synthesized == "1" and plan.get("keepalive_insertion") != "1"),
        f"keepalive_synthesized without keepalive insertion in {path}: {plan}",
    )


def is_expected_retry_plan(
    plan: dict[str, str],
    expected_retry_count: int,
    expected_gap_ms: int,
    expected_cross_request: int | None = None,
    expected_boundary_bisection: int | None = None,
) -> bool:
    if plan.get("retry_insertion") != "1":
        return False
    if int(plan.get("insertion_count", "0")) != expected_retry_count:
        return False
    if int(plan.get("requested_gap_delta_ms", "0")) != expected_gap_ms:
        return False
    if plan.get("keepalive_insertion") != "0":
        return False

    cross_request_value = plan.get("cross_request_resend")
    if expected_cross_request is not None:
        if cross_request_value != str(expected_cross_request):
            return False
    elif expected_retry_count > 1 and expected_gap_ms > 1 and cross_request_value != "1":
        return False

    boundary_value = plan.get("boundary_bisection")
    if expected_boundary_bisection is not None:
        if boundary_value != str(expected_boundary_bisection):
            return False
    elif expected_retry_count > 1 and expected_gap_ms > 1 and boundary_value != "1":
        return False
    return True


def is_expected_keepalive_synthesized_plan(plan: dict[str, str]) -> bool:
    return (
        plan.get("keepalive_insertion") == "1"
        and plan.get("keepalive_synthesized") == "1"
        and plan.get("retry_insertion") == "0"
    )


def is_expected_hybrid_keepalive_retry_plan(
    plan: dict[str, str], expected_retry_count: int, expected_gap_ms: int
) -> bool:
    if plan.get("hybrid_keepalive_retry") != "1":
        return False
    if plan.get("retry_insertion") != "1" or plan.get("keepalive_insertion") != "1":
        return False
    if int(plan.get("requested_gap_delta_ms", "0")) != expected_gap_ms:
        return False
    if int(plan.get("insertion_count", "0")) != expected_retry_count + 1:
        return False

    retry_kinds = 0
    keepalive_kinds = 0
    for index in range(int(plan.get("insertion_count", "0"))):
        kind = plan.get(f"injected_kind[{index}]", "")
        if kind == "retry":
            retry_kinds += 1
        elif kind == "keepalive":
            keepalive_kinds += 1

    if retry_kinds != expected_retry_count or keepalive_kinds != 1:
        return False
    if expected_retry_count > 1 and expected_gap_ms > 1 and plan.get("cross_request_resend") != "1":
        return False
    return True


def is_hybrid_keepalive_retry_plan(plan: dict[str, str]) -> bool:
    if plan.get("hybrid_keepalive_retry") != "1":
        return False
    if plan.get("retry_insertion") != "1" or plan.get("keepalive_insertion") != "1":
        return False

    insertion_count = int(plan.get("insertion_count", "0"))
    if insertion_count < 2:
        return False

    retry_kinds = 0
    keepalive_kinds = 0
    for index in range(insertion_count):
        kind = plan.get(f"injected_kind[{index}]", "")
        if kind == "retry":
            retry_kinds += 1
        elif kind == "keepalive":
            keepalive_kinds += 1

    return retry_kinds > 0 and keepalive_kinds > 0


def build_mock_server(compiler: Path, source: Path, output: Path, cwd: Path) -> None:
    result = run(
        [str(compiler), "-O0", "-g", "-o", str(output), str(source)],
        cwd=cwd,
        timeout=120,
    )
    require(
        result.returncode == 0,
        "mock protocol server build failed:\nSTDOUT:\n"
        f"{result.stdout}\nSTDERR:\n{result.stderr}",
    )


def extract_ssh_request_class_from_message(message: bytes) -> str:
    if message.startswith(b"SSH-"):
        return "identification"
    require(len(message) >= 6, f"SSH message is too short to classify: {message!r}")
    message_code = message[5]
    return {
        1: "disconnect",
        2: "ignore",
        3: "unimplemented",
        4: "debug",
        5: "service_request",
        6: "service_accept",
        20: "kexinit",
        21: "newkeys",
        30: "kexdh_init",
        31: "kexdh_reply",
        50: "userauth_request",
        51: "userauth_failure",
        52: "userauth_success",
        80: "global_request",
        81: "request_success",
        82: "request_failure",
        90: "channel_open",
        91: "channel_open_confirmation",
        94: "channel_data",
        96: "channel_eof",
        97: "channel_close",
    }.get(message_code, "transport")


def split_ssh_seed_messages(data: bytes) -> list[bytes]:
    messages: list[bytes] = []
    offset = 0
    while offset < len(data):
        if data.startswith(b"SSH-", offset):
            newline = data.find(b"\n", offset)
            require(newline != -1, "unterminated SSH identification banner in seed")
            newline += 1
            messages.append(data[offset:newline])
            offset = newline
            continue

        require(offset + 6 <= len(data), "truncated SSH packet header in seed")
        packet_len = int.from_bytes(data[offset : offset + 4], "big")
        total_len = 4 + packet_len
        message_code = data[offset + 5]
        if message_code < 20 or message_code > 49:
            total_len += 8
        require(total_len >= 6, f"invalid SSH packet length {total_len} in seed")
        require(offset + total_len <= len(data), "truncated SSH packet body in seed")
        messages.append(data[offset : offset + total_len])
        offset += total_len

    return messages


def build_ssh_truncated_seed_dir(seed_dir: Path, output_dir: Path, stop_request_class: str) -> Path:
    stop_request_class = stop_request_class.strip().lower()
    require(stop_request_class, "SSH seed truncation requires a non-empty request class")
    shutil.copytree(seed_dir, output_dir)

    transformed_files = 0
    for candidate in sorted(output_dir.iterdir()):
        if not candidate.is_file():
            continue
        data = candidate.read_bytes()
        messages = split_ssh_seed_messages(data)
        truncated: list[bytes] = []
        stop_hit = False
        for message in messages:
            truncated.append(message)
            if extract_ssh_request_class_from_message(message) == stop_request_class:
                stop_hit = True
                break
        if stop_hit:
            candidate.write_bytes(b"".join(truncated))
            transformed_files += 1

    require(
        transformed_files > 0,
        f"SSH seed transform could not find request class {stop_request_class!r} in {seed_dir}",
    )
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an AFLNet live bridge smoke test.")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--monitor", required=True, help="Path to mitppl-monitor")
    parser.add_argument("--afl-fuzz", required=True, help="Path to AFLNet afl-fuzz")
    parser.add_argument("--afl-clang-fast", required=True, help="Path to AFLNet afl-clang-fast")
    parser.add_argument("--server-source", required=True, help="Path to the mock protocol server source")
    parser.add_argument(
        "--protocol",
        default="FTP",
        help="AFLNet protocol selector to pass via -P (for example FTP or RTSP)",
    )
    parser.add_argument(
        "--monitor-mode",
        default="full",
        choices=tuple(MODE_CHANNEL_MASKS.keys()),
        help="Bi-ZoneFuzz++ monitor ablation mode passed into AFLNet -Z",
    )
    parser.add_argument(
        "--network-scheme",
        default="tcp",
        choices=("tcp", "udp"),
        help="Network scheme to pass into AFLNet -N (tcp or udp)",
    )
    parser.add_argument(
        "--seed-dir",
        default="aflnet/tutorials/lightftp/in-ftp",
        help="Seed directory containing replayable FTP sessions",
    )
    parser.add_argument(
        "--formula-text",
        default="",
        help="Override the default generic monitor formula with this MITL text",
    )
    parser.add_argument(
        "--formula-file",
        default="",
        help="Path to a MITL formula file to use instead of the default generic smoke formula",
    )
    parser.add_argument(
        "--property-card-id",
        default="",
        help="Load the monitor formula from this PropertyCard id inside the selected bundle",
    )
    parser.add_argument(
        "--property-card-bundle",
        default="MightyPPL/benchmarks/main_study_property_cards_initial.json",
        help="PropertyCard bundle JSON used with --property-card-id",
    )
    parser.add_argument("--duration-sec", type=int, default=8, help="How long to let afl-fuzz run")
    parser.add_argument("--exec-timeout-ms", type=int, default=2000, help="AFL execution timeout")
    parser.add_argument(
        "--server-wait-ms",
        type=int,
        default=20,
        help="AFLNet server initialization wait passed via -D",
    )
    parser.add_argument(
        "--poll-wait-ms",
        type=int,
        default=20,
        help="AFLNet response polling wait passed via -W",
    )
    parser.add_argument(
        "--force-hints",
        default="retry",
        help="Test-only AFLNet timing hint override (comma separated tokens: retry,keepalive,silence)",
    )
    parser.add_argument(
        "--force-retry-chain",
        type=int,
        default=3,
        help="Forced retry-chain length for test-only override; use 0 to let AFLNet derive it",
    )
    parser.add_argument(
        "--force-gap-ms",
        type=int,
        default=7,
        help="Test-only AFLNet requested gap override used to stabilize retry timing plans",
    )
    parser.add_argument(
        "--disable-test-hint-overrides",
        action="store_true",
        help="Do not inject AFLNET_BIZONE_TEST_HINTS / GAP_MS / RETRY_CHAIN overrides",
    )
    parser.add_argument(
        "--first-pass-only-test-hint-overrides",
        action="store_true",
        help="Apply AFLNET_BIZONE_TEST_HINTS / GAP_MS / RETRY_CHAIN only to replay pass 1, so later replay passes must rely on feedback-derived hints",
    )
    parser.add_argument(
        "--ssh-truncate-after-request-class",
        default="",
        help="For SSH smokes, copy the seed dir into the temp workspace and truncate each seed after the first occurrence of this request class",
    )
    parser.add_argument(
        "--replay-passes",
        type=int,
        default=1,
        help="Replay-only smoke pass count; values >1 exercise multi-exec adaptive feedback reuse",
    )
    parser.add_argument(
        "--disable-replay-only",
        action="store_true",
        help="Run the normal AFLNet loop instead of the deterministic replay-only smoke path",
    )
    parser.add_argument(
        "--persist-exec-history",
        action="store_true",
        help="Ask AFLNet to snapshot per-exec monitor/timing artifacts during the run",
    )
    parser.add_argument(
        "--server-env",
        action="append",
        default=[],
        help="Extra environment variable for the mock server / AFLNet process in KEY=VALUE form; may be repeated",
    )
    parser.add_argument(
        "--max-stage-iters",
        type=int,
        default=0,
        help="Test-only cap for AFLNet havoc stage iterations per queue entry (0 disables the cap)",
    )
    parser.add_argument(
        "--expect-adaptive-feedback-loop",
        action="store_true",
        help="Require replay pass 2 to consume mutation hints produced by replay pass 1",
    )
    parser.add_argument(
        "--expect-exec-history-feedback-origin",
        action="store_true",
        help="Require at least one exec-history timing snapshot to report stage_hint_origin=feedback",
    )
    parser.add_argument(
        "--expect-exec-history-queue-origin",
        action="store_true",
        help="Require at least one exec-history timing snapshot to report stage_hint_origin=queue",
    )
    parser.add_argument(
        "--expect-keepalive-synthesized",
        action="store_true",
        help="Require an active timing plan that used synthesized keepalive insertion",
    )
    parser.add_argument(
        "--expect-keepalive-profile",
        default="",
        help="Require at least one active timing plan to report this keepalive_profile value",
    )
    parser.add_argument(
        "--expect-keepalive-contextual",
        action="store_true",
        help="Require at least one active timing plan to report keepalive_contextual=1",
    )
    parser.add_argument(
        "--expect-keepalive-preferred-class",
        default="",
        help="Require at least one active timing plan to report this keepalive-preferred request class in stage/queue/feedback timing fields",
    )
    parser.add_argument(
        "--expect-request-class",
        default="",
        help="Require at least one request-side trace line to contain req_<class>",
    )
    parser.add_argument(
        "--expect-event-substring",
        action="append",
        default=[],
        help="Require at least one emitted event-trace line to contain this substring",
    )
    parser.add_argument(
        "--expect-event-token",
        action="append",
        default=[],
        help="Require at least one emitted event-trace line to contain this exact CSV token",
    )
    parser.add_argument(
        "--expect-feedback-request-class",
        action="append",
        default=[],
        help="Require at least one feedback record to report this timed_trace_event.request_class",
    )
    parser.add_argument(
        "--expect-feedback-response-class",
        action="append",
        default=[],
        help="Require at least one feedback record to report this timed_trace_event.response_class",
    )
    parser.add_argument(
        "--expect-feedback-close-or-reset",
        choices=("0", "1"),
        default="",
        help="Require at least one feedback record to report this timed_trace_event.close_or_reset_seen bit",
    )
    parser.add_argument(
        "--expect-feedback-request-class-keepalive",
        action="append",
        nargs=2,
        metavar=("CLASS", "BIT"),
        default=[],
        help="Require every feedback record with this timed_trace_event.request_class to report keepalive_hint=<BIT>",
    )
    parser.add_argument(
        "--expect-feedback-response-phase-keepalive",
        action="append",
        nargs=3,
        metavar=("RESPONSE_CLASS", "SESSION_PHASE", "BIT"),
        default=[],
        help="Require every feedback record with this response_class/session_phase pair to report keepalive_hint=<BIT>",
    )
    parser.add_argument(
        "--expect-feedback-response-phase-candidate-absent",
        action="append",
        nargs=3,
        metavar=("RESPONSE_CLASS", "SESSION_PHASE", "CANDIDATE"),
        default=[],
        help="Require every feedback record with this response_class/session_phase pair to omit the normalized candidate_next_event_classes token",
    )
    parser.add_argument(
        "--expect-first-pass-final-session-phase",
        default="",
        help="Require the final property_eval row in pass01.feedback.jsonl to report this timed_trace_event.session_phase",
    )
    parser.add_argument(
        "--expect-first-pass-final-response-class",
        default="",
        help="Require the final property_eval row in pass01.feedback.jsonl to report this timed_trace_event.response_class",
    )
    parser.add_argument(
        "--expect-first-pass-final-keepalive-hint",
        choices=("0", "1"),
        default="",
        help="Require the final property_eval row in pass01.feedback.jsonl to report this keepalive_hint value",
    )
    parser.add_argument(
        "--expect-first-pass-final-candidate-absent",
        action="append",
        default=[],
        help="Require the final property_eval row in pass01.feedback.jsonl to not contain this normalized candidate_next_event_classes token",
    )
    parser.add_argument(
        "--expect-hybrid-keepalive-retry",
        action="store_true",
        help="Require an active timing plan that combined retry insertion with keepalive insertion",
    )
    parser.add_argument(
        "--expect-retry-profile",
        default="",
        help="Require at least one active timing plan to report this retry_profile value",
    )
    parser.add_argument(
        "--expect-retry-preferred-class",
        default="",
        help="Require at least one active timing plan to report this retry-preferred request class",
    )
    parser.add_argument(
        "--expect-retry-contextual",
        action="store_true",
        help="Require at least one active timing plan to report retry_contextual=1",
    )
    parser.add_argument(
        "--expect-retry-insertion-count",
        type=int,
        default=-1,
        help="Require at least one active retry-only plan to use this insertion_count",
    )
    parser.add_argument(
        "--expect-pre-send-delays",
        default="",
        help="Require at least one active timing plan to expose these non-zero pre-send delays, e.g. 1000,2000,4000",
    )
    parser.add_argument(
        "--expect-cross-request-resend",
        choices=("0", "1"),
        default="",
        help="Require at least one active retry-only plan to report this cross_request_resend flag",
    )
    parser.add_argument(
        "--expect-boundary-bisection",
        choices=("0", "1"),
        default="",
        help="Require at least one active retry-only plan to report this boundary_bisection flag",
    )
    parser.add_argument(
        "--expect-channel-mask",
        type=int,
        default=-1,
        help="Require the first property_eval feedback_frame to report this channel_mask; default auto-derives from --monitor-mode",
    )
    parser.add_argument(
        "--allow-no-active-timing-plan",
        action="store_true",
        help="Allow smoke success even when no active timing mutation plan is observed; useful for ablation modes that intentionally disable mutation hints",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    monitor = Path(args.monitor).resolve()
    afl_fuzz = Path(args.afl_fuzz).resolve()
    afl_clang_fast = Path(args.afl_clang_fast).resolve()
    server_source = Path(args.server_source).resolve()
    seed_dir = (workspace / args.seed_dir).resolve()
    formula_file = Path(args.formula_file).resolve() if args.formula_file else None
    property_card_bundle = (workspace / args.property_card_bundle).resolve()

    require(monitor.is_file(), f"monitor binary not found: {monitor}")
    require(afl_fuzz.is_file(), f"afl-fuzz binary not found: {afl_fuzz}")
    require(afl_clang_fast.is_file(), f"afl-clang-fast binary not found: {afl_clang_fast}")
    require(server_source.is_file(), f"mock protocol source not found: {server_source}")
    require(seed_dir.is_dir(), f"seed directory not found: {seed_dir}")
    if formula_file:
        require(formula_file.is_file(), f"formula file not found: {formula_file}")
    if args.property_card_id:
        require(
            property_card_bundle.is_file(),
            f"property-card bundle not found: {property_card_bundle}",
        )
    require(args.replay_passes >= 1, f"replay-passes must be >= 1, got {args.replay_passes}")
    require(args.max_stage_iters >= 0, f"max-stage-iters must be >= 0, got {args.max_stage_iters}")
    if args.ssh_truncate_after_request_class:
        require(
            args.protocol.strip().upper() == "SSH",
            "--ssh-truncate-after-request-class is currently only supported for protocol SSH",
        )
    if args.expect_adaptive_feedback_loop:
        require(
            args.replay_passes >= 2,
            "adaptive feedback loop verification requires --replay-passes >= 2",
        )
        require(
            not args.disable_replay_only,
            "adaptive feedback loop verification currently expects replay-only execution",
        )

    temp_root = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="bizone-aflnet-smoke-", dir=temp_root) as tmp:
        tmpdir = Path(tmp)
        port = find_free_port(args.network_scheme)
        formula = tmpdir / "req_rsp.mitl"
        if formula_file:
            formula.write_text(formula_file.read_text(encoding="utf-8"), encoding="utf-8")
        elif args.formula_text:
            formula.write_text(args.formula_text.rstrip() + "\n", encoding="utf-8")
        elif args.property_card_id:
            formula.write_text(
                load_formula_from_property_card(property_card_bundle, args.property_card_id) + "\n",
                encoding="utf-8",
            )
        else:
            formula.write_text("G(req -> F[0,1000] rsp)\n", encoding="utf-8")

        effective_seed_dir = seed_dir
        if args.ssh_truncate_after_request_class:
            effective_seed_dir = build_ssh_truncated_seed_dir(
                seed_dir,
                tmpdir / "seed-transform",
                args.ssh_truncate_after_request_class,
            )

        server_bin = tmpdir / server_source.stem
        build_mock_server(afl_clang_fast, server_source, server_bin, workspace)

        out_dir = tmpdir / "out"
        env = os.environ.copy()
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFLNET_MONITOR_BIN"] = str(monitor)
        env["AFL_PATH"] = str((workspace / "aflnet").resolve())
        for assignment in args.server_env:
            require("=" in assignment, f"invalid --server-env assignment {assignment!r}; expected KEY=VALUE")
            key, value = assignment.split("=", 1)
            key = key.strip()
            require(key, f"invalid --server-env assignment {assignment!r}; empty key")
            env[key] = value
        if not args.disable_replay_only:
            env["AFLNET_BIZONE_TEST_REPLAY_ONLY"] = "1"
            env["AFLNET_BIZONE_TEST_REPLAY_PASSES"] = str(args.replay_passes)
        if args.persist_exec_history or not args.disable_replay_only:
            # Replay-only smoke can process multiple queue entries, and the
            # later ones overwrite passNN snapshots. Keep exec-history copies
            # so run-level assertions observe the whole execution, not only the
            # final queue item.
            env["AFLNET_BIZONE_TEST_PERSIST_EXEC_HISTORY"] = "1"
        if args.max_stage_iters > 0:
            env["AFLNET_BIZONE_TEST_STAGE_MAX"] = str(args.max_stage_iters)
        if not args.disable_test_hint_overrides:
            if args.force_hints:
                env["AFLNET_BIZONE_TEST_HINTS"] = args.force_hints
            if args.force_retry_chain > 0:
                env["AFLNET_BIZONE_TEST_RETRY_CHAIN"] = str(args.force_retry_chain)
            env["AFLNET_BIZONE_TEST_GAP_MS"] = str(args.force_gap_ms)
            if args.first_pass_only_test_hint_overrides:
                env["AFLNET_BIZONE_TEST_HINT_OVERRIDES_FIRST_PASS_ONLY"] = "1"

        timeout_cmd = [
            "timeout",
            "-k",
            "2s",
            f"{args.duration_sec}s",
            str(afl_fuzz),
            "-d",
            "-t",
            str(args.exec_timeout_ms),
            "-i",
            str(effective_seed_dir),
            "-o",
            str(out_dir),
            "-N",
            f"{args.network_scheme}://127.0.0.1/{port}",
            "-P",
            args.protocol,
            "-D",
            str(args.server_wait_ms),
            "-W",
            str(args.poll_wait_ms),
            "-q",
            "3",
            "-s",
            "3",
            "-E",
            "-K",
            "-Y",
            str(formula),
            "-Z",
            args.monitor_mode,
            "--",
            str(server_bin),
            str(port),
        ]
        fuzz = run(timeout_cmd, cwd=workspace, env=env, timeout=args.duration_sec + 30)
        require(
            fuzz.returncode in {0, 124, 137},
            "afl-fuzz smoke failed unexpectedly:\nSTDOUT:\n"
            f"{fuzz.stdout}\nSTDERR:\n{fuzz.stderr}",
        )

        monitor_dir = out_dir / "queue/.state/bizone-monitor"
        fallback_dir = out_dir / "queue/.state/bizone-feedback"
        # `current.feedback.jsonl` is transient: AFLNet unlinks it before each
        # monitor execution, while `passNN.*` / `execNNNNNN.*` snapshots remain
        # stable across later executions in the same smoke run.
        event_candidates = collect_artifact_candidates(
            monitor_dir / "current.events.txt",
            [
                (monitor_dir, "pass*.events.txt"),
                (monitor_dir, "exec*.events.txt"),
                (fallback_dir, "*.events.txt"),
            ],
        )
        feedback_candidates = collect_artifact_candidates(
            monitor_dir / "current.feedback.jsonl",
            [
                (monitor_dir, "pass*.feedback.jsonl"),
                (monitor_dir, "exec*.feedback.jsonl"),
                (fallback_dir, "*.jsonl"),
            ],
        )
        timing_candidates = collect_artifact_candidates(
            monitor_dir / "current.timing.txt",
            [
                (monitor_dir, "pass*.timing.txt"),
                (monitor_dir, "exec*.timing.txt"),
                (fallback_dir, "*.timing.txt"),
            ],
        )
        events_path = resolve_artifact(event_candidates)
        feedback_path = resolve_artifact(feedback_candidates)
        timing_path = resolve_artifact(timing_candidates)
        require(events_path.is_file(), f"missing event trace across candidates: {event_candidates}")
        require(feedback_path.is_file(), f"missing feedback log across candidates: {feedback_candidates}")
        require(timing_path.is_file(), f"missing timing plan log across candidates: {timing_candidates}")
        exec_history_timing_candidates = sorted(monitor_dir.glob("exec*.timing.txt"))

        events = [line.strip() for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        require(events, "event trace is empty")
        require(any("req" in line for line in events), f"event trace missing request events: {events}")
        require(any("rsp" in line or "silence" in line for line in events), f"event trace missing response-side events: {events}")
        if args.expect_request_class:
            needle = f"req_{args.expect_request_class.lower()}"
            found_request_class = False
            for candidate in event_candidates:
                if not candidate.is_file():
                    continue
                candidate_lines = [
                    line.strip()
                    for line in candidate.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if any(needle in line.lower() for line in candidate_lines):
                    found_request_class = True
                    break
            require(
                found_request_class,
                f"event traces missing expected request class {needle}: {events}",
            )
        for expected_substring in args.expect_event_substring:
            lowered = expected_substring.lower()
            found = False
            for candidate in event_candidates:
                if not candidate.is_file():
                    continue
                candidate_lines = [
                    line.strip()
                    for line in candidate.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if any(lowered in line.lower() for line in candidate_lines):
                    found = True
                    break
            require(found, f"event traces missing expected substring {expected_substring!r}: {events}")
        for expected_token in args.expect_event_token:
            lowered = expected_token.lower()
            found = False
            for candidate in event_candidates:
                if not candidate.is_file():
                    continue
                candidate_lines = [
                    line.strip()
                    for line in candidate.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if any(lowered in event_line_tokens(line) for line in candidate_lines):
                    found = True
                    break
            require(found, f"event traces missing expected token {expected_token!r}: {events}")

        timing_summary = timing_path.read_text(encoding="utf-8")
        require("message_count=" in timing_summary, f"unexpected timing plan payload: {timing_summary}")
        replay_timing_candidates = sorted(monitor_dir.glob("pass*.timing.txt"))
        active_timing_plans = collect_active_timing_plans(timing_candidates)
        if not args.allow_no_active_timing_plan:
            require(active_timing_plans, "no active timing mutation plan was observed")
        insertion_plan_count = 0
        expected_retry_plan_count = 0
        expected_retry_count = (
            args.expect_retry_insertion_count
            if args.expect_retry_insertion_count >= 0
            else (
                0
                if args.disable_test_hint_overrides and args.expect_adaptive_feedback_loop
                else args.force_retry_chain
            )
        )
        expected_cross_request = (
            int(args.expect_cross_request_resend) if args.expect_cross_request_resend else None
        )
        expected_boundary_bisection = (
            int(args.expect_boundary_bisection) if args.expect_boundary_bisection else None
        )
        expected_pre_send_delays = (
            sorted(int(token.strip()) for token in args.expect_pre_send_delays.split(",") if token.strip())
            if args.expect_pre_send_delays
            else []
        )
        expected_pre_send_delay_count = 0
        expected_keepalive_synthesized_count = 0
        expected_keepalive_profile_count = 0
        expected_keepalive_contextual_count = 0
        expected_keepalive_preferred_count = 0
        expected_hybrid_keepalive_retry_count = 0
        expected_retry_profile_count = 0
        expected_retry_preferred_count = 0
        expected_retry_contextual_count = 0
        for candidate, plan in active_timing_plans:
            validate_insertion_plan(candidate, plan)
            if plan.get("retry_insertion") == "1" or plan.get("keepalive_insertion") == "1":
                insertion_plan_count += 1
            if expected_retry_count > 0 and is_expected_retry_plan(
                plan,
                expected_retry_count,
                args.force_gap_ms,
                expected_cross_request,
                expected_boundary_bisection,
            ):
                expected_retry_plan_count += 1
            if expected_pre_send_delays and collect_nonzero_pre_send_delays(plan) == expected_pre_send_delays:
                expected_pre_send_delay_count += 1
            if args.expect_keepalive_synthesized and is_expected_keepalive_synthesized_plan(plan):
                expected_keepalive_synthesized_count += 1
            if args.expect_keepalive_profile and plan.get("keepalive_profile", "") == args.expect_keepalive_profile:
                expected_keepalive_profile_count += 1
            if args.expect_keepalive_contextual and plan.get("keepalive_contextual", "0") == "1":
                expected_keepalive_contextual_count += 1
            if args.expect_keepalive_preferred_class:
                expected_keepalive_preferred = normalize_request_class(
                    args.expect_keepalive_preferred_class
                )
                keepalive_preferred_classes = plan_keepalive_preferred_request_classes(plan)
                if expected_keepalive_preferred in keepalive_preferred_classes.values():
                    expected_keepalive_preferred_count += 1
            if args.expect_hybrid_keepalive_retry:
                if args.disable_test_hint_overrides:
                    if is_hybrid_keepalive_retry_plan(plan):
                        expected_hybrid_keepalive_retry_count += 1
                elif is_expected_hybrid_keepalive_retry_plan(
                    plan, args.force_retry_chain, args.force_gap_ms
                ):
                    expected_hybrid_keepalive_retry_count += 1
            if args.expect_retry_profile and plan.get("retry_profile", "") == args.expect_retry_profile:
                expected_retry_profile_count += 1
            if args.expect_retry_preferred_class:
                expected_retry_preferred = normalize_request_class(args.expect_retry_preferred_class)
                retry_preferred_classes = plan_retry_preferred_request_classes(plan)
                if expected_retry_preferred in retry_preferred_classes.values():
                    expected_retry_preferred_count += 1
            if args.expect_retry_contextual and plan.get("retry_contextual", "0") == "1":
                expected_retry_contextual_count += 1
        aggregated_feedback_records: list[dict] = []
        for candidate in feedback_candidates:
            if candidate.is_file():
                aggregated_feedback_records.extend(load_jsonl(candidate))

        property_records = property_eval_records(aggregated_feedback_records)
        require(property_records, f"feedback log missing property_eval records: {aggregated_feedback_records}")

        first = property_records[0]
        frame = first.get("feedback_frame", {})
        expected_channel_mask = (
            args.expect_channel_mask
            if args.expect_channel_mask >= 0
            else expected_channel_mask_for_mode(args.monitor_mode)
        )
        require(
            int(frame.get("channel_mask", -1)) == expected_channel_mask,
            f"unexpected channel mask for mode {args.monitor_mode!r}: expected {expected_channel_mask}, frame={frame}",
        )
        require_disabled_feedback_channels(frame, expected_channel_mask)
        require(
            first.get("subject") == args.protocol.lower(),
            f"subject did not round-trip as protocol name: {first}",
        )

        semantic_records = [record for record in aggregated_feedback_records if record.get("event_type") == "semantic_state"]
        require(semantic_records, f"feedback log missing semantic_state records: {aggregated_feedback_records}")
        feedback_request_classes: list[str] = []
        feedback_response_classes: list[str] = []
        for candidate in feedback_candidates:
            if not candidate.is_file():
                continue
            candidate_records = load_jsonl(candidate)
            candidate_property_records = property_eval_records(candidate_records)
            feedback_request_classes.extend(
                str(record.get("timed_trace_event", {}).get("request_class", "")).lower()
                for record in candidate_property_records
            )
            feedback_response_classes.extend(
                str(record.get("timed_trace_event", {}).get("response_class", "")).lower()
                for record in candidate_property_records
            )
        for expected_request_class in args.expect_feedback_request_class:
            require(
                expected_request_class.lower() in feedback_request_classes,
                f"feedback records missing request_class {expected_request_class!r}: {feedback_request_classes}",
            )
        for expected_response_class in args.expect_feedback_response_class:
            require(
                expected_response_class.lower() in feedback_response_classes,
                f"feedback records missing response_class {expected_response_class!r}: {feedback_response_classes}",
            )
        if args.expect_feedback_close_or_reset:
            expected_close_reset = bool(int(args.expect_feedback_close_or_reset))
            observed_close_reset_bits = [
                bool(record.get("timed_trace_event", {}).get("close_or_reset_seen", False))
                for record in property_records
            ]
            require(
                expected_close_reset in observed_close_reset_bits,
                "feedback records missing close_or_reset_seen expectation "
                f"{int(expected_close_reset)}: {observed_close_reset_bits}",
            )
        for request_class, expected_keepalive in args.expect_feedback_request_class_keepalive:
            normalized_request_class = normalize_request_class(request_class)
            matching_records = [
                record
                for record in property_records
                if normalize_request_class(
                    record.get("timed_trace_event", {}).get("request_class", "")
                )
                == normalized_request_class
            ]
            require(
                matching_records,
                f"feedback records missing request_class {request_class!r} for keepalive expectation",
            )
            expected_keepalive_bit = int(expected_keepalive)
            for record in matching_records:
                observed_keepalive_bit = 1 if mutation_hint_for_record(record).get("keepalive_hint") else 0
                require(
                    observed_keepalive_bit == expected_keepalive_bit,
                    "feedback record keepalive_hint did not match request_class expectation: "
                    f"class={normalized_request_class!r}, expected={expected_keepalive_bit}, "
                    f"observed={observed_keepalive_bit}, record={record}",
                )
        for response_class, session_phase, expected_keepalive in args.expect_feedback_response_phase_keepalive:
            normalized_response_class = normalize_request_class(response_class)
            normalized_session_phase = str(session_phase).strip().lower()
            matching_records = [
                record
                for record in property_records
                if normalize_request_class(
                    record.get("timed_trace_event", {}).get("response_class", "")
                )
                == normalized_response_class
                and str(record.get("timed_trace_event", {}).get("session_phase", "")).strip().lower()
                == normalized_session_phase
            ]
            require(
                matching_records,
                "feedback records missing response/session pair for keepalive expectation: "
                f"response_class={response_class!r}, session_phase={session_phase!r}",
            )
            expected_keepalive_bit = int(expected_keepalive)
            for record in matching_records:
                observed_keepalive_bit = 1 if mutation_hint_for_record(record).get("keepalive_hint") else 0
                require(
                    observed_keepalive_bit == expected_keepalive_bit,
                    "feedback record keepalive_hint did not match response/session expectation: "
                    f"response_class={normalized_response_class!r}, "
                    f"session_phase={normalized_session_phase!r}, "
                    f"expected={expected_keepalive_bit}, observed={observed_keepalive_bit}, "
                    f"record={record}",
                )
        for response_class, session_phase, forbidden_candidate in args.expect_feedback_response_phase_candidate_absent:
            normalized_response_class = normalize_request_class(response_class)
            normalized_session_phase = str(session_phase).strip().lower()
            normalized_forbidden_candidate = normalize_request_class(forbidden_candidate)
            matching_records = [
                record
                for record in property_records
                if normalize_request_class(
                    record.get("timed_trace_event", {}).get("response_class", "")
                )
                == normalized_response_class
                and str(record.get("timed_trace_event", {}).get("session_phase", "")).strip().lower()
                == normalized_session_phase
            ]
            require(
                matching_records,
                "feedback records missing response/session pair for candidate absence expectation: "
                f"response_class={response_class!r}, session_phase={session_phase!r}",
            )
            for record in matching_records:
                observed_candidates = set(candidate_next_event_classes(record))
                require(
                    normalized_forbidden_candidate not in observed_candidates,
                    "feedback record unexpectedly retained a forbidden candidate for the "
                    "specified response/session pair: "
                    f"response_class={normalized_response_class!r}, "
                    f"session_phase={normalized_session_phase!r}, "
                    f"candidate={normalized_forbidden_candidate!r}, record={record}",
                )

        if args.expect_adaptive_feedback_loop:
            require(
                len(replay_timing_candidates) >= args.replay_passes,
                f"missing replay timing snapshots for {args.replay_passes} pass(es): {replay_timing_candidates}",
            )
            first_timing_path = monitor_dir / "pass01.timing.txt"
            second_timing_path = monitor_dir / "pass02.timing.txt"
            first_feedback_path = monitor_dir / "pass01.feedback.jsonl"
            first_events_path = monitor_dir / "pass01.events.txt"
            require(first_timing_path.is_file(), f"missing first replay timing snapshot: {first_timing_path}")
            require(second_timing_path.is_file(), f"missing second replay timing snapshot: {second_timing_path}")
            require(first_feedback_path.is_file(), f"missing first replay feedback snapshot: {first_feedback_path}")
            require(first_events_path.is_file(), f"missing first replay event snapshot: {first_events_path}")

            first_plan = parse_timing_plan(first_timing_path.read_text(encoding="utf-8"))
            second_plan = parse_timing_plan(second_timing_path.read_text(encoding="utf-8"))
            first_feedback_records = load_jsonl(first_feedback_path)
            first_event_lines = [
                line.strip()
                for line in first_events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            first_feedback_property_records = property_eval_records(first_feedback_records)
            require(
                first_feedback_property_records,
                f"missing property_eval records in first replay feedback snapshot: {first_feedback_records}",
            )

            last_first_feedback = first_feedback_property_records[-1]
            first_mutation_hint = mutation_hint_for_record(last_first_feedback)
            first_feedback_gap = int(first_mutation_hint.get("recommended_gap_delta_ms", 0))
            first_feedback_hint_mask = aggregate_feedback_hint_mask(first_feedback_records)
            first_feedback_preferred_request_class = normalize_request_class(
                first_plan.get("feedback_preferred_request_class", "")
            )
            expected_preferred_request_class = (
                first_feedback_preferred_request_class
                or derive_preferred_request_class_from_feedback(
                    first_feedback_records,
                    first_event_lines,
                    args.protocol,
                )
            )
            first_feedback_retry_preferred = ""
            if first_feedback_hint_mask & 0x1:
                first_feedback_retry_preferred = normalize_request_class(
                    first_plan.get("feedback_retry_preferred_request_class", "")
                )
            first_feedback_keepalive_preferred = ""
            if first_feedback_hint_mask & 0x2:
                first_feedback_keepalive_preferred = normalize_request_class(
                    first_plan.get("feedback_keepalive_preferred_request_class", "")
                )

            require(
                first_feedback_gap != 0 or first_feedback_hint_mask != 0,
                f"first replay pass did not emit reusable mutation hints: {last_first_feedback}",
            )
            require(
                second_plan.get("stage_hint_origin") == "feedback",
                f"second replay pass did not report feedback-derived stage hints: {second_plan}",
            )
            require(
                int(second_plan.get("stage_gap_hint_ms", "0")) == first_feedback_gap,
                "second replay pass did not carry over the first-pass recommended gap "
                f"({first_feedback_gap}) into stage_gap_hint_ms: {second_plan}",
            )
            require(
                int(second_plan.get("stage_hint_mask", "0")) == first_feedback_hint_mask,
                "second replay pass did not carry over the first-pass hint mask "
                f"({first_feedback_hint_mask}) into stage_hint_mask: {second_plan}",
            )
            require(
                second_plan.get("active") == "1",
                f"second replay pass did not activate a timing plan from feedback: {second_plan}",
            )

            if args.expect_first_pass_final_session_phase:
                observed_phase = str(
                    last_first_feedback.get("timed_trace_event", {}).get("session_phase", "")
                ).strip().lower()
                require(
                    observed_phase == args.expect_first_pass_final_session_phase.strip().lower(),
                    "first replay pass final session_phase did not match expectation: "
                    f"expected={args.expect_first_pass_final_session_phase!r}, "
                    f"observed={observed_phase!r}, record={last_first_feedback}",
                )
            if args.expect_first_pass_final_response_class:
                observed_response_class = str(
                    last_first_feedback.get("timed_trace_event", {}).get("response_class", "")
                ).strip().lower()
                require(
                    observed_response_class
                    == args.expect_first_pass_final_response_class.strip().lower(),
                    "first replay pass final response_class did not match expectation: "
                    f"expected={args.expect_first_pass_final_response_class!r}, "
                    f"observed={observed_response_class!r}, record={last_first_feedback}",
                )
            if args.expect_first_pass_final_keepalive_hint:
                observed_keepalive_hint = 1 if first_mutation_hint.get("keepalive_hint") else 0
                require(
                    observed_keepalive_hint == int(args.expect_first_pass_final_keepalive_hint),
                    "first replay pass final keepalive_hint did not match expectation: "
                    f"expected={args.expect_first_pass_final_keepalive_hint!r}, "
                    f"observed={observed_keepalive_hint!r}, record={last_first_feedback}",
                )
            if args.expect_first_pass_final_candidate_absent:
                final_candidates = set(candidate_next_event_classes(last_first_feedback))
                for forbidden_candidate in args.expect_first_pass_final_candidate_absent:
                    normalized_forbidden = normalize_request_class(forbidden_candidate)
                    if not normalized_forbidden:
                        continue
                    require(
                        normalized_forbidden not in final_candidates,
                        "first replay pass final candidate list unexpectedly contained "
                        f"{normalized_forbidden!r}: candidates={sorted(final_candidates)}, "
                        f"record={last_first_feedback}",
                    )

            second_preferred_classes = plan_preferred_request_classes(second_plan)
            second_retry_preferred_classes = plan_retry_preferred_request_classes(second_plan)
            second_keepalive_preferred_classes = plan_keepalive_preferred_request_classes(second_plan)
            validated_retry_preferred = False
            if first_feedback_retry_preferred:
                observed_stage_retry_preferred = second_retry_preferred_classes.get(
                    "stage_retry_preferred_request_class", ""
                )
                require(
                    observed_stage_retry_preferred == first_feedback_retry_preferred,
                    "second replay pass stage retry-preferred request class did not "
                    "match the first-pass retry-preferred class "
                    f"{first_feedback_retry_preferred!r}: "
                    f"observed={observed_stage_retry_preferred!r}, "
                    f"plan={second_plan}, first_plan={first_plan}",
                )
                validated_retry_preferred = True
            validated_keepalive_preferred = False
            if first_feedback_keepalive_preferred:
                observed_stage_keepalive_preferred = second_keepalive_preferred_classes.get(
                    "stage_keepalive_preferred_request_class", ""
                )
                if observed_stage_keepalive_preferred:
                    require(
                        observed_stage_keepalive_preferred == first_feedback_keepalive_preferred,
                        "second replay pass stage keepalive-preferred request class did not "
                        "match the first-pass keepalive-preferred class "
                        f"{first_feedback_keepalive_preferred!r}: "
                        f"observed={observed_stage_keepalive_preferred!r}, "
                        f"plan={second_plan}, first_plan={first_plan}",
                    )
                validated_keepalive_preferred = True
            if expected_preferred_request_class:
                second_keepalive_preferred = second_keepalive_preferred_classes.get(
                    "feedback_keepalive_preferred_request_class", ""
                )
                if (first_feedback_hint_mask & 0x2) and not second_keepalive_preferred:
                    second_preferred_classes = {}
                require(
                    second_preferred_classes or ((first_feedback_hint_mask & 0x2) and not second_keepalive_preferred),
                    "second replay pass did not expose any preferred request class fields "
                    f"while consuming feedback-derived hints: {second_plan}",
                )
                if second_preferred_classes:
                    mismatched_preferred_classes = {
                        field: value
                        for field, value in second_preferred_classes.items()
                        if value != expected_preferred_request_class
                    }
                    require(
                        not mismatched_preferred_classes,
                        "second replay pass preferred request class fields did not match the "
                        "first-pass feedback-derived class "
                        f"{expected_preferred_request_class!r}: {mismatched_preferred_classes}, "
                        f"plan={second_plan}, first_plan={first_plan}",
                    )
            elif not (validated_retry_preferred or validated_keepalive_preferred):
                require(
                    not second_preferred_classes,
                    "second replay pass exposed preferred request class fields even though "
                    "the first-pass feedback did not yield a mappable request class: "
                    f"plan={second_plan}, first_plan={first_plan}, "
                    f"records={first_feedback_property_records}",
                )
            if args.expect_retry_profile:
                require(
                    second_plan.get("retry_profile", "") == args.expect_retry_profile,
                    "second replay pass did not realize the expected feedback-driven retry profile: "
                    f"expected={args.expect_retry_profile!r}, plan={second_plan}, first_plan={first_plan}",
                )
                require(
                    second_plan.get("retry_insertion") == "1",
                    f"second replay pass did not realize feedback-driven retry insertion: {second_plan}",
                )
            if args.expect_retry_contextual:
                require(
                    second_plan.get("retry_contextual", "0") == "1",
                    f"second replay pass did not preserve contextual retry semantics: {second_plan}",
                )
            if args.expect_keepalive_profile:
                require(
                    second_plan.get("keepalive_profile", "") == args.expect_keepalive_profile,
                    "second replay pass did not realize the expected feedback-driven keepalive profile: "
                    f"expected={args.expect_keepalive_profile!r}, plan={second_plan}, first_plan={first_plan}",
                )
                require(
                    second_plan.get("keepalive_insertion") == "1",
                    f"second replay pass did not realize feedback-driven keepalive insertion: {second_plan}",
                )
            if args.expect_keepalive_contextual:
                require(
                    second_plan.get("keepalive_contextual", "0") == "1",
                    f"second replay pass did not preserve contextual keepalive semantics: {second_plan}",
                )
            if not args.expect_retry_profile and not args.expect_keepalive_profile:
                if first_feedback_gap < 0:
                    require(
                        second_plan.get("gap_compression") == "1",
                        f"second replay pass did not realize feedback-driven gap compression: {second_plan}",
                    )
                elif first_feedback_gap > 0:
                    require(
                        second_plan.get("gap_expansion") == "1",
                        f"second replay pass did not realize feedback-driven gap expansion: {second_plan}",
                    )

        if args.expect_exec_history_feedback_origin or args.expect_exec_history_queue_origin:
            require(
                exec_history_timing_candidates,
                "missing exec-history timing snapshots; re-run with --persist-exec-history",
            )
            exec_history_plans = [
                parse_timing_plan(path.read_text(encoding="utf-8"))
                for path in exec_history_timing_candidates
            ]
            if args.expect_exec_history_feedback_origin:
                require(
                    any(plan.get("stage_hint_origin") == "feedback" for plan in exec_history_plans),
                    f"no exec-history timing snapshot reported stage_hint_origin=feedback: {exec_history_timing_candidates}",
                )
            if args.expect_exec_history_queue_origin:
                queue_plans = [
                    plan for plan in exec_history_plans if plan.get("stage_hint_origin") == "queue"
                ]
                require(
                    queue_plans,
                    f"no exec-history timing snapshot reported stage_hint_origin=queue: {exec_history_timing_candidates}",
                )
                require(
                    any(
                        int(plan.get("queue_gap_hint_ms", "0")) == int(plan.get("stage_gap_hint_ms", "0")) and
                        int(plan.get("queue_hint_mask", "0")) == int(plan.get("stage_hint_mask", "0"))
                        for plan in queue_plans
                    ),
                    f"queue-origin exec-history snapshots did not preserve queue hint values: {queue_plans}",
                )

        if expected_retry_count > 0 and not args.expect_hybrid_keepalive_retry:
            require(
                expected_retry_plan_count > 0,
                "expected retry-chain timing plan was not observed in active timing artifacts",
            )
        if expected_pre_send_delays:
            require(
                expected_pre_send_delay_count > 0,
                f"pre-send delay sequence {expected_pre_send_delays!r} was not observed in active timing artifacts",
            )
        if args.expect_keepalive_synthesized:
            require(
                expected_keepalive_synthesized_count > 0,
                "synthesized keepalive timing plan was not observed in active timing artifacts",
            )
        if args.expect_keepalive_profile:
            require(
                expected_keepalive_profile_count > 0,
                f"keepalive profile {args.expect_keepalive_profile!r} was not observed in active timing artifacts",
            )
        if args.expect_keepalive_contextual:
            require(
                expected_keepalive_contextual_count > 0,
                "contextual keepalive synthesis was not observed in active timing artifacts",
            )
        if args.expect_keepalive_preferred_class:
            require(
                expected_keepalive_preferred_count > 0,
                "keepalive-preferred request class "
                f"{args.expect_keepalive_preferred_class!r} was not observed in active timing artifacts",
            )
        if args.expect_hybrid_keepalive_retry:
            require(
                expected_hybrid_keepalive_retry_count > 0,
                "hybrid keepalive+retry timing plan was not observed in active timing artifacts",
            )
        if args.expect_retry_profile:
            require(
                expected_retry_profile_count > 0,
                f"retry profile {args.expect_retry_profile!r} was not observed in active timing artifacts",
            )
        if args.expect_retry_preferred_class:
            retry_preferred_debug = [
                {
                    "path": str(candidate),
                    "stage_retry_preferred_request_class": plan.get(
                        "stage_retry_preferred_request_class", ""
                    ),
                    "queue_retry_preferred_request_class": plan.get(
                        "queue_retry_preferred_request_class", ""
                    ),
                    "feedback_retry_preferred_request_class": plan.get(
                        "feedback_retry_preferred_request_class", ""
                    ),
                    "retry_profile": plan.get("retry_profile", ""),
                    "stage_hint_origin": plan.get("stage_hint_origin", ""),
                }
                for candidate, plan in active_timing_plans
            ]
            require(
                expected_retry_preferred_count > 0,
                "retry-preferred request class "
                f"{args.expect_retry_preferred_class!r} was not observed in active timing artifacts: "
                f"{retry_preferred_debug}",
            )
        if args.expect_retry_contextual:
            require(
                expected_retry_contextual_count > 0,
                "contextual retry insertion was not observed in active timing artifacts",
            )
        if args.expect_adaptive_feedback_loop:
            print("AFLNet Bi-ZoneFuzz++ adaptive feedback replay smoke passed")
            return 0
        if insertion_plan_count:
            print(
                "AFLNet Bi-ZoneFuzz++ smoke passed "
                f"with {insertion_plan_count} insertion timing plan(s)"
            )
            return 0

        print("AFLNet Bi-ZoneFuzz++ smoke passed")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"aflnet bridge smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
