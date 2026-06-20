#!/usr/bin/env python3
"""Validate and exercise Bi-ZoneFuzz++ PropertyCard artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "bizonefuzz.propertycard.v1"
REQUIRED_FIELDS = [
    "property_id",
    "protocol",
    "source_url",
    "section_id",
    "normative_level",
    "original_clause",
    "timer_symbol",
    "timer_binding",
    "AP_definition",
    "trace_mapping",
    "MITL_formula",
    "positive_trace",
    "boundary_negative_trace",
]
VALID_REVIEW_DECISIONS = {"approve", "approve-draft", "request-changes", "abstain"}
VALID_VALIDATION_STATUS = {"passed", "failed", "pending", "not-run"}
PAPER_READY_REVIEW_STATUS = {"paper-ready", "approved-for-publication"}
KNOWN_REVIEW_STATUS = {
    "draft-monitor-checked",
    "draft-reviewed",
    "paper-ready",
    "approved-for-publication",
}


@dataclass
class PropertyCard:
    property_id: str
    protocol: str
    source_url: str
    section_id: str
    normative_level: str
    original_clause: str
    timer_symbol: str
    timer_binding: Any
    AP_definition: Any
    trace_mapping: Any
    MITL_formula: str
    positive_trace: list[str]
    boundary_negative_trace: list[str]
    raw: dict[str, Any]


@dataclass
class BundleArtifact:
    path: Path
    payload: dict[str, Any]
    cards: list[PropertyCard]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def ensure_optional_string(value: Any, context: str) -> None:
    require(isinstance(value, str), f"{context} must be a string")


def ensure_string_list(value: Any, context: str) -> None:
    require(isinstance(value, list), f"{context} must be a list")
    require(all(isinstance(item, str) for item in value), f"{context} must contain only strings")


def validate_review_entry(entry: Any, context: str) -> None:
    require(isinstance(entry, dict), f"{context} must be an object")
    for field in ("reviewer_id", "reviewer_name", "decision", "date"):
        require(field in entry, f"{context} missing required field {field!r}")
        ensure_optional_string(entry[field], f"{context}.{field}")
    decision = entry["decision"].strip().lower()
    require(decision in VALID_REVIEW_DECISIONS, f"{context}.decision has unsupported value {entry['decision']!r}")
    for optional in ("role", "scope", "notes"):
        if optional in entry:
            ensure_optional_string(entry[optional], f"{context}.{optional}")


def review_entry(reviewer_id: str,
                 reviewer_name: str,
                 decision: str,
                 review_date: str,
                 *,
                 role: str = "",
                 notes: str = "") -> dict[str, str]:
    entry = {
        "reviewer_id": reviewer_id,
        "reviewer_name": reviewer_name,
        "decision": decision,
        "date": review_date,
    }
    if role:
        entry["role"] = role
    if notes:
        entry["notes"] = notes
    validate_review_entry(entry, "review entry")
    return entry


def validate_dynamic_validation(metadata: Any, context: str) -> None:
    require(isinstance(metadata, dict), f"{context} must be an object")
    if "status" in metadata:
        ensure_optional_string(metadata["status"], f"{context}.status")
        require(
            metadata["status"].strip().lower() in VALID_VALIDATION_STATUS,
            f"{context}.status has unsupported value {metadata['status']!r}",
        )
    for optional in ("tool", "date", "scope", "method", "evidence"):
        if optional in metadata:
            ensure_optional_string(metadata[optional], f"{context}.{optional}")


def validate_review_metadata_dict(metadata: Any, context: str, *, bundle_scope: bool) -> None:
    require(isinstance(metadata, dict), f"{context} must be an object")
    if "required_approvals" in metadata:
        require(
            isinstance(metadata["required_approvals"], int) and metadata["required_approvals"] >= 1,
            f"{context}.required_approvals must be an integer >= 1",
        )

    approvals_key = "bundle_approvals" if bundle_scope else "approvals"
    if approvals_key in metadata:
        approvals = metadata[approvals_key]
        require(isinstance(approvals, list), f"{context}.{approvals_key} must be a list")
        for index, entry in enumerate(approvals, start=1):
            validate_review_entry(entry, f"{context}.{approvals_key}[{index}]")

    if "dynamic_validation" in metadata:
        validate_dynamic_validation(metadata["dynamic_validation"], f"{context}.dynamic_validation")

    blockers_key = "publication_blockers" if bundle_scope else "blockers"
    if blockers_key in metadata:
        ensure_string_list(metadata[blockers_key], f"{context}.{blockers_key}")

    if not bundle_scope and "publication_ready" in metadata:
        require(isinstance(metadata["publication_ready"], bool), f"{context}.publication_ready must be a boolean")


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(payload, dict), f"{path}: top-level JSON value must be an object")
    schema_version = payload.get("schema_version", SCHEMA_VERSION)
    require(schema_version == SCHEMA_VERSION, f"{path}: unsupported schema_version {schema_version!r}")
    cards_raw = payload.get("cards")
    require(isinstance(cards_raw, list), f"{path}: 'cards' must be a list")

    if "artifact_role" in payload:
        ensure_optional_string(payload["artifact_role"], f"{path}.artifact_role")
    if "bundle_id" in payload:
        ensure_optional_string(payload["bundle_id"], f"{path}.bundle_id")
    if "review_status" in payload:
        ensure_optional_string(payload["review_status"], f"{path}.review_status")
    if "bundle_scope" in payload:
        ensure_string_list(payload["bundle_scope"], f"{path}.bundle_scope")
    if "review_metadata" in payload:
        validate_review_metadata_dict(payload["review_metadata"], f"{path}.review_metadata", bundle_scope=True)

    return payload


def parse_cards(path: Path, payload: dict[str, Any]) -> list[PropertyCard]:
    cards_raw = payload["cards"]
    cards: list[PropertyCard] = []
    for index, raw in enumerate(cards_raw, start=1):
        require(isinstance(raw, dict), f"{path}: cards[{index}] must be an object")
        for field in REQUIRED_FIELDS:
            require(field in raw, f"{path}: cards[{index}] missing required field {field!r}")
        positive_trace = raw["positive_trace"]
        negative_trace = raw["boundary_negative_trace"]
        require(
            isinstance(positive_trace, list) and all(isinstance(item, str) for item in positive_trace),
            f"{path}: cards[{index}].positive_trace must be a list of event lines",
        )
        require(
            isinstance(negative_trace, list) and all(isinstance(item, str) for item in negative_trace),
            f"{path}: cards[{index}].boundary_negative_trace must be a list of event lines",
        )
        if "review_metadata" in raw:
            validate_review_metadata_dict(raw["review_metadata"], f"{path}: cards[{index}].review_metadata", bundle_scope=False)
        cards.append(
            PropertyCard(
                property_id=str(raw["property_id"]),
                protocol=str(raw["protocol"]),
                source_url=str(raw["source_url"]),
                section_id=str(raw["section_id"]),
                normative_level=str(raw["normative_level"]),
                original_clause=str(raw["original_clause"]),
                timer_symbol=str(raw["timer_symbol"]),
                timer_binding=raw["timer_binding"],
                AP_definition=raw["AP_definition"],
                trace_mapping=raw["trace_mapping"],
                MITL_formula=str(raw["MITL_formula"]),
                positive_trace=positive_trace,
                boundary_negative_trace=negative_trace,
                raw=raw,
            )
        )
    return cards


def load_bundle(path: Path) -> BundleArtifact:
    payload = load_payload(path)
    cards = parse_cards(path, payload)
    return BundleArtifact(path=path, payload=payload, cards=cards)


def load_cards(path: Path) -> list[PropertyCard]:
    """Backward-compatible helper for tooling that only needs the card list."""
    return load_bundle(path).cards


def get_required_approvals(metadata: dict[str, Any], default_value: int) -> int:
    value = metadata.get("required_approvals", default_value)
    require(isinstance(value, int) and value >= 1, f"required_approvals must be an integer >= 1, got {value!r}")
    return value


def count_approvals(approvals: list[dict[str, Any]], accepted_decisions: set[str]) -> int:
    dedup: dict[str, dict[str, Any]] = {}
    for entry in approvals:
        reviewer_id = str(entry["reviewer_id"])
        dedup[reviewer_id] = entry
    return sum(1 for entry in dedup.values() if str(entry["decision"]).strip().lower() in accepted_decisions)


def bundle_review_summary(bundle: BundleArtifact, fallback_required_approvals: int) -> dict[str, Any]:
    metadata = bundle.payload.get("review_metadata", {})
    require(isinstance(metadata, dict), f"{bundle.path}: review_metadata must be an object when present")
    required_approvals = get_required_approvals(metadata, fallback_required_approvals)
    approvals = metadata.get("bundle_approvals", [])
    draft_approvals = count_approvals(approvals, {"approve", "approve-draft"})
    final_approvals = count_approvals(approvals, {"approve"})
    dynamic_validation = metadata.get("dynamic_validation", {})
    dynamic_status = ""
    if isinstance(dynamic_validation, dict):
        dynamic_status = str(dynamic_validation.get("status", "")).strip().lower()
    blockers = list(metadata.get("publication_blockers", [])) if isinstance(metadata.get("publication_blockers", []), list) else []
    return {
        "bundle_id": str(bundle.payload.get("bundle_id", "")),
        "review_status": str(bundle.payload.get("review_status", "")),
        "required_approvals": required_approvals,
        "draft_approvals": draft_approvals,
        "final_approvals": final_approvals,
        "dynamic_validation_status": dynamic_status,
        "blockers": blockers,
    }


def card_review_summary(card: PropertyCard, fallback_required_approvals: int) -> dict[str, Any]:
    metadata = card.raw.get("review_metadata", {})
    require(isinstance(metadata, dict), f"{card.property_id}: review_metadata must be an object when present")
    required_approvals = get_required_approvals(metadata, fallback_required_approvals)
    approvals = metadata.get("approvals", [])
    draft_approvals = count_approvals(approvals, {"approve", "approve-draft"})
    final_approvals = count_approvals(approvals, {"approve"})
    dynamic_validation = metadata.get("dynamic_validation", {})
    dynamic_status = ""
    if isinstance(dynamic_validation, dict):
        dynamic_status = str(dynamic_validation.get("status", "")).strip().lower()
    blockers = list(metadata.get("blockers", [])) if isinstance(metadata.get("blockers", []), list) else []
    return {
        "property_id": card.property_id,
        "protocol": card.protocol,
        "required_approvals": required_approvals,
        "draft_approvals": draft_approvals,
        "final_approvals": final_approvals,
        "dynamic_validation_status": dynamic_status,
        "publication_ready": bool(metadata.get("publication_ready", False)),
        "blockers": blockers,
    }


def publication_blockers(summary: dict[str, Any], *, allow_draft: bool, bundle_scope: bool) -> list[str]:
    blockers = list(summary.get("blockers", []))
    approval_count = summary["draft_approvals"] if allow_draft else summary["final_approvals"]
    approval_label = "draft approvals" if allow_draft else "final approvals"
    if approval_count < summary["required_approvals"]:
        blockers.append(
            f"needs {summary['required_approvals']} {approval_label}, found {approval_count}"
        )
    if summary.get("dynamic_validation_status") != "passed":
        blockers.append("dynamic_validation.status != passed")

    if bundle_scope:
        if allow_draft:
            if not summary.get("review_status"):
                blockers.append("review_status missing")
        else:
            if summary.get("review_status") not in PAPER_READY_REVIEW_STATUS:
                blockers.append(f"review_status {summary.get('review_status')!r} is not paper-ready")
    else:
        if not allow_draft and not summary.get("publication_ready"):
            blockers.append("publication_ready=false")

    return blockers


def sync_review_metadata(metadata: dict[str, Any], *, bundle_scope: bool, fallback_required_approvals: int = 2) -> None:
    approvals_key = "bundle_approvals" if bundle_scope else "approvals"
    blockers_key = "publication_blockers" if bundle_scope else "blockers"
    approvals = metadata.get(approvals_key, [])
    if not isinstance(approvals, list):
        return

    required_approvals = get_required_approvals(metadata, fallback_required_approvals)
    draft_approvals = count_approvals(approvals, {"approve", "approve-draft"})
    final_approvals = count_approvals(approvals, {"approve"})

    blockers = metadata.get(blockers_key, [])
    if not isinstance(blockers, list):
        blockers = []
    blockers = [str(item) for item in blockers]
    if draft_approvals >= required_approvals:
        blockers = [item for item in blockers if "Second reviewer approval" not in item]
    metadata[blockers_key] = blockers

    if not bundle_scope:
        dynamic_validation = metadata.get("dynamic_validation", {})
        dynamic_status = ""
        if isinstance(dynamic_validation, dict):
            dynamic_status = str(dynamic_validation.get("status", "")).strip().lower()
        metadata["publication_ready"] = final_approvals >= required_approvals and dynamic_status == "passed"


def stamp_payload_review(payload: dict[str, Any],
                         *,
                         scope: str,
                         review: dict[str, str],
                         card_id: str = "",
                         required_approvals: int = 0) -> None:
    if scope == "bundle":
        metadata = payload.setdefault("review_metadata", {})
        require(isinstance(metadata, dict), "review_metadata must be an object")
        if required_approvals > 0:
            metadata["required_approvals"] = required_approvals
        approvals = metadata.setdefault("bundle_approvals", [])
        require(isinstance(approvals, list), "review_metadata.bundle_approvals must be a list")
        approvals[:] = [candidate for candidate in approvals if str(candidate.get("reviewer_id", "")) != review["reviewer_id"]]
        approvals.append(review)
        sync_review_metadata(metadata, bundle_scope=True)
        return

    require(scope == "card", f"unsupported review scope {scope!r}")
    require(card_id, "card_id is required when stamping a card review")
    cards_raw = payload["cards"]
    target = None
    for raw in cards_raw:
        if str(raw.get("property_id", "")) == card_id:
            target = raw
            break
    require(target is not None, f"no PropertyCard matched card_id {card_id!r}")
    metadata = target.setdefault("review_metadata", {})
    require(isinstance(metadata, dict), f"{card_id}.review_metadata must be an object")
    if required_approvals > 0:
        metadata["required_approvals"] = required_approvals
    approvals = metadata.setdefault("approvals", [])
    require(isinstance(approvals, list), f"{card_id}.review_metadata.approvals must be a list")
    approvals[:] = [candidate for candidate in approvals if str(candidate.get("reviewer_id", "")) != review["reviewer_id"]]
    approvals.append(review)
    sync_review_metadata(metadata, bundle_scope=False)


def parse_bool_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "apply", "x"}


def placeholder_like(value: str) -> bool:
    stripped = value.strip()
    return stripped == "YYYY-MM-DD" or (stripped.startswith("<") and stripped.endswith(">"))


def active_review_queue_row(row: dict[str, Any]) -> bool:
    if parse_bool_text(row.get("apply", "")):
        return True
    for field in ("reviewer_id", "reviewer_name", "decision", "review_date", "notes"):
        if str(row.get(field, "") or "").strip():
            return True
    return False


def apply_review_queue_rows(payload: dict[str, Any],
                            rows: list[dict[str, Any]]) -> tuple[int, int]:
    applied = 0
    skipped = 0

    for index, row in enumerate(rows, start=2):
        if not active_review_queue_row(row):
            skipped += 1
            continue

        scope = str(row.get("scope", "") or "").strip()
        card_id = str(row.get("card_id", "") or "").strip()
        reviewer_id = str(row.get("reviewer_id", "") or "").strip()
        reviewer_name = str(row.get("reviewer_name", "") or "").strip()
        decision = str(row.get("decision", "") or "").strip() or str(row.get("next_decision", "") or "").strip()
        review_date = str(row.get("review_date", "") or "").strip()
        role = str(row.get("role", "") or "").strip()
        notes = str(row.get("notes", "") or "").strip()

        require(scope in {"bundle", "card"}, f"review queue row {index}: unsupported scope {scope!r}")
        if scope == "card":
            require(card_id, f"review queue row {index}: card rows require card_id")

        for field_name, field_value in (
            ("reviewer_id", reviewer_id),
            ("reviewer_name", reviewer_name),
            ("review_date", review_date),
        ):
            require(field_value, f"review queue row {index}: missing {field_name}")
            require(not placeholder_like(field_value), f"review queue row {index}: unresolved placeholder in {field_name}")

        require(decision, f"review queue row {index}: missing decision and next_decision")
        require(decision in VALID_REVIEW_DECISIONS, f"review queue row {index}: unsupported decision {decision!r}")
        if notes:
            require(not placeholder_like(notes), f"review queue row {index}: unresolved placeholder in notes")

        required_approvals_text = str(row.get("required_approvals", "") or "").strip()
        required_approvals = int(required_approvals_text) if required_approvals_text else 0
        review = review_entry(
            reviewer_id,
            reviewer_name,
            decision,
            review_date,
            role=role,
            notes=notes,
        )
        stamp_payload_review(
            payload,
            scope=scope,
            review=review,
            card_id=card_id,
            required_approvals=required_approvals,
        )
        applied += 1

    return applied, skipped


def save_demo(path: Path) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_role": "tooling-demo-only",
        "cards": [
            {
                "property_id": "demo.req_rsp.deadline",
                "protocol": "demo",
                "source_url": "https://example.invalid/spec-demo",
                "section_id": "demo-1",
                "normative_level": "DEMO_ONLY",
                "original_clause": "Whenever req appears, rsp must follow within 5 ms.",
                "timer_symbol": "T_rsp",
                "timer_binding": {"kind": "constant", "unit": "ms", "value": 5},
                "AP_definition": {
                    "req": "request event observed",
                    "rsp": "response event observed",
                },
                "trace_mapping": {
                    "event_stream": "request+response timed trace",
                    "req": "TimedTraceEvent.request_class contains 'req'",
                    "rsp": "TimedTraceEvent.request_class contains 'rsp'",
                },
                "MITL_formula": "G(req -> F[0,5] rsp)",
                "positive_trace": ["@0 req", "@4 rsp"],
                "boundary_negative_trace": ["@0 req", "@6 rsp"],
            }
        ],
    }
    write_json(path, payload)


def run_monitor(monitor: Path, formula: str, events: list[str], timeout: int) -> tuple[int, list[str], str]:
    with tempfile.TemporaryDirectory(prefix="property-card-") as tmp:
        tmpdir = Path(tmp)
        event_path = tmpdir / "events.txt"
        event_path.write_text("".join(f"{line}\n" for line in events), encoding="utf-8")
        result = subprocess.run(
            [str(monitor), "--formula", formula, "--input", str(event_path)],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        verdicts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return result.returncode, verdicts, result.stderr


def command_validate(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    if args.require_structured_review:
        require("review_metadata" in bundle.payload, f"{bundle.path}: top-level review_metadata missing")
        for card in bundle.cards:
            require("review_metadata" in card.raw, f"{bundle.path}: {card.property_id} missing review_metadata")
    print(f"validated {len(bundle.cards)} PropertyCard artifact(s)")
    return 0


def command_init_demo(args: argparse.Namespace) -> int:
    path = Path(args.out)
    save_demo(path)
    print(f"wrote demo PropertyCard artifact to {path}")
    return 0


def command_markdown(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    output = render_bundle_markdown(bundle)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


def render_bundle_markdown(bundle: BundleArtifact) -> str:
    lines = [
        "| property_id | protocol | section_id | normative_level | MITL_formula |",
        "| --- | --- | --- | --- | --- |",
    ]
    for card in bundle.cards:
        lines.append(
            f"| {card.property_id} | {card.protocol} | {card.section_id} | "
            f"{card.normative_level} | `{card.MITL_formula}` |"
        )
    return "\n".join(lines) + "\n"


def export_formulas(bundle: BundleArtifact,
                    out_dir: Path,
                    *,
                    protocol_filter: str = "") -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)

    exported: list[dict[str, Any]] = []
    for card in bundle.cards:
        if protocol_filter and card.protocol.lower() != protocol_filter.lower():
            continue
        target = out_dir / f"{card.property_id}.mitl"
        target.write_text(card.MITL_formula.strip() + "\n", encoding="utf-8")
        exported.append(
            {
                "property_id": card.property_id,
                "protocol": card.protocol,
                "formula_file": target.name,
                "MITL_formula": card.MITL_formula,
                "source_url": card.source_url,
                "section_id": card.section_id,
            }
        )
    return exported


def command_export_formulas(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    out_dir = Path(args.out_dir)
    exported = export_formulas(bundle, out_dir, protocol_filter=args.protocol)

    require(exported, f"{args.cards_json}: no PropertyCards matched export filter")

    if args.manifest_out:
        write_json(Path(args.manifest_out), build_formula_manifest(Path(args.cards_json), exported))

    print(f"exported {len(exported)} MITL formula file(s) to {out_dir}")
    return 0


def command_check_monitor(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    monitor = Path(args.monitor)
    failures: list[str] = []

    for card in bundle.cards:
        pos_rc, pos_verdicts, pos_stderr = run_monitor(monitor, card.MITL_formula, card.positive_trace, args.timeout)
        neg_rc, neg_verdicts, neg_stderr = run_monitor(monitor, card.MITL_formula, card.boundary_negative_trace, args.timeout)

        if pos_rc != 0:
            failures.append(f"{card.property_id}: positive trace run failed: {pos_stderr.strip()}")
        if "NEGATIVE" in pos_verdicts:
            failures.append(f"{card.property_id}: positive trace unexpectedly produced NEGATIVE ({pos_verdicts})")
        if neg_rc != 0:
            failures.append(f"{card.property_id}: boundary negative trace run failed: {neg_stderr.strip()}")
        if "NEGATIVE" not in neg_verdicts:
            failures.append(f"{card.property_id}: boundary negative trace never produced NEGATIVE ({neg_verdicts})")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"monitor-checked {len(bundle.cards)} PropertyCard artifact(s)")
    return 0


def render_review_report_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# PropertyCard Review Report",
        "",
        f"- Bundle ID: `{summary['bundle_id']}`",
        f"- Review Status: `{summary['review_status']}`",
        f"- Required Approvals: `{summary['required_approvals']}`",
        f"- Bundle Draft Approvals: `{summary['draft_approvals']}`",
        f"- Bundle Final Approvals: `{summary['final_approvals']}`",
        f"- Bundle Dynamic Validation: `{summary['dynamic_validation_status'] or 'missing'}`",
        "",
        "## Cards",
        "",
        "| property_id | protocol | draft approvals | final approvals | validation | publication_ready | blockers |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for card in summary["cards"]:
        blockers = "; ".join(card["publication_blockers"]) if card["publication_blockers"] else "none"
        lines.append(
            f"| {card['property_id']} | {card['protocol']} | {card['draft_approvals']}/{card['required_approvals']} | "
            f"{card['final_approvals']}/{card['required_approvals']} | "
            f"{card['dynamic_validation_status'] or 'missing'} | "
            f"{str(card['publication_ready']).lower()} | {blockers} |"
        )

    return "\n".join(lines) + "\n"


def review_report_summary(bundle: BundleArtifact, required_approvals: int) -> dict[str, Any]:
    bundle_summary = bundle_review_summary(bundle, required_approvals)
    cards_summary: list[dict[str, Any]] = []
    for card in bundle.cards:
        summary = card_review_summary(card, required_approvals)
        summary["publication_blockers"] = publication_blockers(summary, allow_draft=False, bundle_scope=False)
        cards_summary.append(summary)

    return {
        "schema_version": "bizonefuzz.propertycard.review-report.v1",
        "cards_json": str(bundle.path),
        "bundle_id": bundle_summary["bundle_id"],
        "review_status": bundle_summary["review_status"],
        "required_approvals": bundle_summary["required_approvals"],
        "draft_approvals": bundle_summary["draft_approvals"],
        "final_approvals": bundle_summary["final_approvals"],
        "dynamic_validation_status": bundle_summary["dynamic_validation_status"],
        "bundle_publication_blockers": publication_blockers(bundle_summary, allow_draft=False, bundle_scope=True),
        "cards": cards_summary,
    }


def review_action_rows(bundle: BundleArtifact,
                       review_summary: dict[str, Any],
                       *,
                       tool_path_hint: str,
                       review_date_template: str) -> list[dict[str, Any]]:
    cards_json_path = str(bundle.path)
    rows: list[dict[str, Any]] = []

    def add_row(*,
                scope: str,
                card_id: str,
                protocol: str,
                review_status: str,
                dynamic_validation_status: str,
                required_approvals: int,
                draft_approvals: int,
                final_approvals: int,
                publication_ready: bool,
                blockers: list[str]) -> None:
        next_decision = ""
        next_gate = ""
        approvals_needed = 0
        if draft_approvals < required_approvals:
            next_decision = "approve-draft"
            next_gate = "draft"
            approvals_needed = required_approvals - draft_approvals
        elif final_approvals < required_approvals:
            next_decision = "approve"
            next_gate = "final"
            approvals_needed = required_approvals - final_approvals
        elif not publication_ready:
            next_decision = "approve"
            next_gate = "final"

        if not next_decision:
            return

        command = [
            "python3",
            tool_path_hint,
            "stamp-review",
            cards_json_path,
            "--scope",
            scope,
        ]
        if scope == "card":
            command.extend(["--card-id", card_id])
        command.extend(
            [
                "--reviewer-id",
                "<reviewer-id>",
                "--reviewer-name",
                "<reviewer-name>",
                "--decision",
                next_decision,
                "--date",
                review_date_template,
                "--role",
                "independent_review",
                "--notes",
                "<notes>",
            ]
        )

        rows.append(
            {
                "scope": scope,
                "card_id": card_id,
                "protocol": protocol,
                "review_status": review_status,
                "dynamic_validation_status": dynamic_validation_status,
                "required_approvals": required_approvals,
                "draft_approvals": draft_approvals,
                "final_approvals": final_approvals,
                "publication_ready": str(publication_ready).lower(),
                "next_gate": next_gate,
                "next_decision": next_decision,
                "approvals_needed": approvals_needed,
                "blockers": "; ".join(blockers) if blockers else "",
                "apply": "",
                "reviewer_id": "",
                "reviewer_name": "",
                "decision": "",
                "review_date": "",
                "role": "independent_review",
                "notes": "",
                "command_template": " ".join(shlex.quote(token) for token in command),
            }
        )

    add_row(
        scope="bundle",
        card_id="",
        protocol="bundle",
        review_status=review_summary["review_status"],
        dynamic_validation_status=review_summary["dynamic_validation_status"],
        required_approvals=review_summary["required_approvals"],
        draft_approvals=review_summary["draft_approvals"],
        final_approvals=review_summary["final_approvals"],
        publication_ready=False,
        blockers=review_summary["bundle_publication_blockers"],
    )

    for card_summary in review_summary["cards"]:
        add_row(
            scope="card",
            card_id=str(card_summary["property_id"]),
            protocol=str(card_summary["protocol"]),
            review_status=str(card_summary.get("review_status", "")),
            dynamic_validation_status=str(card_summary["dynamic_validation_status"]),
            required_approvals=int(card_summary["required_approvals"]),
            draft_approvals=int(card_summary["draft_approvals"]),
            final_approvals=int(card_summary["final_approvals"]),
            publication_ready=bool(card_summary["publication_ready"]),
            blockers=list(card_summary["publication_blockers"]),
        )

    return rows


def render_review_packet_markdown(bundle: BundleArtifact,
                                  review_summary: dict[str, Any],
                                  action_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# PropertyCard Review Packet",
        "",
        f"- Bundle ID: `{review_summary['bundle_id']}`",
        f"- Source Artifact: `{bundle.path}`",
        f"- Review Status: `{review_summary['review_status']}`",
        f"- Required Approvals: `{review_summary['required_approvals']}`",
        f"- Bundle Draft Approvals: `{review_summary['draft_approvals']}`",
        f"- Bundle Final Approvals: `{review_summary['final_approvals']}`",
        f"- Bundle Dynamic Validation: `{review_summary['dynamic_validation_status'] or 'missing'}`",
        "",
        "## Bundle Blockers",
        "",
    ]

    bundle_blockers = review_summary.get("bundle_publication_blockers", [])
    if bundle_blockers:
        for blocker in bundle_blockers:
            lines.append(f"- {blocker}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Pending Reviewer Actions",
            "",
            "| scope | card_id | protocol | next gate | next decision | approvals needed | validation | blockers |",
            "| --- | --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for row in action_rows:
        lines.append(
            f"| {row['scope']} | {row['card_id'] or '-'} | {row['protocol']} | {row['next_gate']} | "
            f"{row['next_decision']} | {row['approvals_needed']} | {row['dynamic_validation_status'] or 'missing'} | "
            f"{row['blockers'] or 'none'} |"
        )

    lines.extend(
        [
            "",
            "## Command Templates",
            "",
        ]
    )
    for row in action_rows:
        target = row["card_id"] or "bundle"
        lines.append(f"- `{target}`")
        lines.append(f"  `{row['command_template']}`")

    return "\n".join(lines) + "\n"


def command_review_report(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    required_approvals = get_required_approvals(
        bundle.payload.get("review_metadata", {}) if isinstance(bundle.payload.get("review_metadata", {}), dict) else {},
        args.required_approvals,
    )
    summary = review_report_summary(bundle, required_approvals)

    if args.format == "json":
        output = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    else:
        output = render_review_report_markdown(summary)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


def command_publication_check(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    require(
        bundle.payload.get("artifact_role") != "tooling-demo-only",
        f"{bundle.path}: demo-only artifacts can never satisfy publication checks",
    )

    required_approvals = args.required_approvals
    bundle_summary = bundle_review_summary(bundle, required_approvals)
    blockers = publication_blockers(bundle_summary, allow_draft=args.allow_draft, bundle_scope=True)

    for card in bundle.cards:
        summary = card_review_summary(card, required_approvals)
        card_blockers = publication_blockers(summary, allow_draft=args.allow_draft, bundle_scope=False)
        if card_blockers:
            blockers.append(f"{card.property_id}: " + "; ".join(card_blockers))

    if blockers:
        for blocker in blockers:
            print(blocker, file=sys.stderr)
        return 1

    stage = "draft gate" if args.allow_draft else "publication gate"
    print(f"{stage} passed for {len(bundle.cards)} PropertyCard artifact(s)")
    return 0


def command_stamp_review(args: argparse.Namespace) -> int:
    path = Path(args.cards_json)
    payload = load_payload(path)
    entry = review_entry(
        args.reviewer_id,
        args.reviewer_name,
        args.decision,
        args.date,
        role=args.role,
        notes=args.notes,
    )
    stamp_payload_review(
        payload,
        scope=args.scope,
        review=entry,
        card_id=args.card_id,
        required_approvals=args.required_approvals,
    )

    target_path = Path(args.out) if args.out else path
    write_json(target_path, payload)
    print(f"stamped review entry into {target_path}")
    return 0


def command_set_review_status(args: argparse.Namespace) -> int:
    path = Path(args.cards_json)
    payload = load_payload(path)
    status = args.review_status.strip()
    require(status, "--review-status must not be empty")
    if args.strict:
        require(
            status in KNOWN_REVIEW_STATUS,
            f"unsupported review_status {status!r}; expected one of {sorted(KNOWN_REVIEW_STATUS)}",
        )
    payload["review_status"] = status
    if args.artifact_role:
        payload["artifact_role"] = args.artifact_role
    target_path = Path(args.out) if args.out else path
    write_json(target_path, payload)
    print(f"updated review_status in {target_path} to {status}")
    return 0


def build_formula_manifest(source_cards: Path, exported: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "bizonefuzz.property-formulas.v1",
        "source_cards": str(source_cards),
        "count": len(exported),
        "entries": exported,
    }


def publication_gate_errors(bundle: BundleArtifact,
                            *,
                            allow_draft: bool,
                            required_approvals: int) -> list[str]:
    bundle_summary = bundle_review_summary(bundle, required_approvals)
    blockers = publication_blockers(bundle_summary, allow_draft=allow_draft, bundle_scope=True)
    for card in bundle.cards:
        summary = card_review_summary(card, required_approvals)
        card_blockers = publication_blockers(summary, allow_draft=allow_draft, bundle_scope=False)
        if card_blockers:
            blockers.append(f"{card.property_id}: " + "; ".join(card_blockers))
    return blockers


def property_index_rows(bundle: BundleArtifact,
                        review_summary: dict[str, Any],
                        formula_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary_by_id = {entry["property_id"]: entry for entry in review_summary["cards"]}
    formula_by_id = {entry["property_id"]: entry for entry in formula_entries}
    rows: list[dict[str, Any]] = []
    for card in bundle.cards:
        summary = summary_by_id[card.property_id]
        formula_entry = formula_by_id.get(card.property_id, {})
        rows.append(
            {
                "property_id": card.property_id,
                "protocol": card.protocol,
                "section_id": card.section_id,
                "normative_level": card.normative_level,
                "timer_symbol": card.timer_symbol,
                "source_url": card.source_url,
                "formula_file": formula_entry.get("formula_file", ""),
                "draft_approvals": summary["draft_approvals"],
                "final_approvals": summary["final_approvals"],
                "publication_ready": str(summary["publication_ready"]).lower(),
            }
        )
    return rows


def citation_index_rows(bundle: BundleArtifact) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for card in bundle.cards:
        rows.append(
            {
                "property_id": card.property_id,
                "protocol": card.protocol,
                "source_url": card.source_url,
                "section_id": card.section_id,
                "normative_level": card.normative_level,
                "original_clause": card.original_clause,
            }
        )
    return rows


def command_publish_bundle(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    require(
        bundle.payload.get("artifact_role") != "tooling-demo-only",
        f"{bundle.path}: demo-only artifacts can never satisfy publication checks",
    )

    required_approvals = get_required_approvals(
        bundle.payload.get("review_metadata", {}) if isinstance(bundle.payload.get("review_metadata", {}), dict) else {},
        args.required_approvals,
    )
    blockers = publication_gate_errors(bundle, allow_draft=args.allow_draft, required_approvals=required_approvals)
    if blockers:
        for blocker in blockers:
            print(blocker, file=sys.stderr)
        return 1

    out_dir = Path(args.out_dir)
    formulas_dir = out_dir / "formulas"
    property_cards_json = out_dir / "property_cards.json"
    property_cards_md = out_dir / "property_cards.md"
    review_report_md = out_dir / "review_report.md"
    review_report_json = out_dir / "review_report.json"
    formulas_manifest_json = out_dir / "formulas_manifest.json"
    property_index_csv = out_dir / "property_index.csv"
    citation_index_csv = out_dir / "citation_index.csv"
    publication_manifest_json = out_dir / "publication_manifest.json"

    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(property_cards_json, bundle.payload)
    property_cards_md.write_text(render_bundle_markdown(bundle), encoding="utf-8")

    review_summary = review_report_summary(bundle, required_approvals)
    review_report_md.write_text(render_review_report_markdown(review_summary), encoding="utf-8")
    write_json(review_report_json, review_summary)

    formula_entries = export_formulas(bundle, formulas_dir)
    write_json(formulas_manifest_json, build_formula_manifest(bundle.path, formula_entries))

    write_csv(
        property_index_csv,
        [
            "property_id",
            "protocol",
            "section_id",
            "normative_level",
            "timer_symbol",
            "source_url",
            "formula_file",
            "draft_approvals",
            "final_approvals",
            "publication_ready",
        ],
        property_index_rows(bundle, review_summary, formula_entries),
    )
    write_csv(
        citation_index_csv,
        [
            "property_id",
            "protocol",
            "source_url",
            "section_id",
            "normative_level",
            "original_clause",
        ],
        citation_index_rows(bundle),
    )

    publication_stage = "draft" if args.allow_draft else "final"
    manifest = {
        "schema_version": "bizonefuzz.propertycard.publication-pack.v1",
        "publication_stage": publication_stage,
        "cards_json": str(bundle.path),
        "bundle_id": str(bundle.payload.get("bundle_id", "")),
        "review_status": str(bundle.payload.get("review_status", "")),
        "required_approvals": required_approvals,
        "cards_count": len(bundle.cards),
        "generated_files": {
            "property_cards_json": str(property_cards_json),
            "property_cards_md": str(property_cards_md),
            "review_report_md": str(review_report_md),
            "review_report_json": str(review_report_json),
            "formulas_dir": str(formulas_dir),
            "formulas_manifest_json": str(formulas_manifest_json),
            "property_index_csv": str(property_index_csv),
            "citation_index_csv": str(citation_index_csv),
            "publication_manifest_json": str(publication_manifest_json),
        },
        "review_summary": {
            "draft_approvals": review_summary["draft_approvals"],
            "final_approvals": review_summary["final_approvals"],
            "dynamic_validation_status": review_summary["dynamic_validation_status"],
            "bundle_publication_blockers": review_summary["bundle_publication_blockers"],
        },
        "cards": [
            {
                "property_id": card.property_id,
                "protocol": card.protocol,
                "source_url": card.source_url,
                "section_id": card.section_id,
                "formula_file": f"{card.property_id}.mitl",
            }
            for card in bundle.cards
        ],
    }
    write_json(publication_manifest_json, manifest)
    print(f"published {publication_stage} PropertyCard pack to {out_dir}")
    return 0


def command_review_packet(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.cards_json))
    required_approvals = get_required_approvals(
        bundle.payload.get("review_metadata", {}) if isinstance(bundle.payload.get("review_metadata", {}), dict) else {},
        args.required_approvals,
    )

    out_dir = Path(args.out_dir)
    formulas_dir = out_dir / "formulas"
    property_cards_json = out_dir / "property_cards.json"
    property_cards_md = out_dir / "property_cards.md"
    review_report_md = out_dir / "review_report.md"
    review_report_json = out_dir / "review_report.json"
    formulas_manifest_json = out_dir / "formulas_manifest.json"
    property_index_csv = out_dir / "property_index.csv"
    citation_index_csv = out_dir / "citation_index.csv"
    review_queue_csv = out_dir / "review_queue.csv"
    review_commands_sh = out_dir / "review_commands.sh"
    review_packet_md = out_dir / "review_packet.md"
    review_packet_manifest_json = out_dir / "review_packet_manifest.json"

    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(property_cards_json, bundle.payload)
    property_cards_md.write_text(render_bundle_markdown(bundle), encoding="utf-8")

    review_summary = review_report_summary(bundle, required_approvals)
    review_report_md.write_text(render_review_report_markdown(review_summary), encoding="utf-8")
    write_json(review_report_json, review_summary)

    formula_entries = export_formulas(bundle, formulas_dir)
    write_json(formulas_manifest_json, build_formula_manifest(bundle.path, formula_entries))
    write_csv(
        property_index_csv,
        [
            "property_id",
            "protocol",
            "section_id",
            "normative_level",
            "timer_symbol",
            "source_url",
            "formula_file",
            "draft_approvals",
            "final_approvals",
            "publication_ready",
        ],
        property_index_rows(bundle, review_summary, formula_entries),
    )
    write_csv(
        citation_index_csv,
        [
            "property_id",
            "protocol",
            "source_url",
            "section_id",
            "normative_level",
            "original_clause",
        ],
        citation_index_rows(bundle),
    )

    action_rows = review_action_rows(
        bundle,
        review_summary,
        tool_path_hint=args.tool_path_hint,
        review_date_template=args.review_date_template,
    )
    write_csv(
        review_queue_csv,
        [
            "scope",
            "card_id",
            "protocol",
            "review_status",
            "dynamic_validation_status",
            "required_approvals",
            "draft_approvals",
            "final_approvals",
            "publication_ready",
            "next_gate",
            "next_decision",
            "approvals_needed",
            "blockers",
            "apply",
            "reviewer_id",
            "reviewer_name",
            "decision",
            "review_date",
            "role",
            "notes",
            "command_template",
        ],
        action_rows,
    )
    review_commands_sh.write_text(
        "#!/bin/sh\nset -eu\n\n" +
        "\n".join(row["command_template"] for row in action_rows) +
        "\n",
        encoding="utf-8",
    )
    review_commands_sh.chmod(0o755)
    review_packet_md.write_text(
        render_review_packet_markdown(bundle, review_summary, action_rows),
        encoding="utf-8",
    )

    manifest = {
        "schema_version": "bizonefuzz.propertycard.review-packet.v1",
        "cards_json": str(bundle.path),
        "bundle_id": review_summary["bundle_id"],
        "review_status": review_summary["review_status"],
        "required_approvals": required_approvals,
        "cards_count": len(bundle.cards),
        "pending_actions": len(action_rows),
        "generated_files": {
            "property_cards_json": str(property_cards_json),
            "property_cards_md": str(property_cards_md),
            "review_report_md": str(review_report_md),
            "review_report_json": str(review_report_json),
            "formulas_dir": str(formulas_dir),
            "formulas_manifest_json": str(formulas_manifest_json),
            "property_index_csv": str(property_index_csv),
            "citation_index_csv": str(citation_index_csv),
            "review_queue_csv": str(review_queue_csv),
            "review_commands_sh": str(review_commands_sh),
            "review_packet_md": str(review_packet_md),
            "review_packet_manifest_json": str(review_packet_manifest_json),
        },
        "bundle_publication_blockers": review_summary["bundle_publication_blockers"],
    }
    write_json(review_packet_manifest_json, manifest)
    print(f"wrote review packet to {out_dir}")
    return 0


def command_apply_review_packet(args: argparse.Namespace) -> int:
    manifest_path = Path(args.review_packet_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(
        manifest.get("schema_version") == "bizonefuzz.propertycard.review-packet.v1",
        f"{manifest_path}: unsupported review packet schema {manifest.get('schema_version')!r}",
    )
    generated_files = manifest.get("generated_files", {})
    require(isinstance(generated_files, dict), f"{manifest_path}: generated_files must be an object")

    source_cards_path = Path(str(args.cards_json or generated_files.get("property_cards_json", ""))).resolve()
    review_queue_path = Path(str(args.review_queue or generated_files.get("review_queue_csv", ""))).resolve()
    require(source_cards_path.is_file(), f"review packet source PropertyCard bundle not found: {source_cards_path}")
    require(review_queue_path.is_file(), f"review packet queue not found: {review_queue_path}")

    payload = load_payload(source_cards_path)
    with review_queue_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    require(rows, f"{review_queue_path}: review queue is empty")
    applied, skipped = apply_review_queue_rows(payload, rows)
    require(applied > 0 or args.allow_zero, f"{review_queue_path}: no review actions were applied")

    target_path = Path(args.out) if args.out else source_cards_path
    write_json(target_path, payload)
    print(f"applied {applied} review action(s) and skipped {skipped} row(s) into {target_path}")
    return 0


def review_gate_result(bundle_path: Path,
                       *,
                       allow_draft: bool,
                       required_approvals_override: int = 0) -> dict[str, Any]:
    bundle = load_bundle(bundle_path)
    required_approvals = get_required_approvals(
        bundle.payload.get("review_metadata", {}) if isinstance(bundle.payload.get("review_metadata", {}), dict) else {},
        required_approvals_override or 2,
    )
    blockers = publication_gate_errors(
        bundle,
        allow_draft=allow_draft,
        required_approvals=required_approvals,
    )
    return {
        "publication_stage": "draft" if allow_draft else "final",
        "required_approvals": required_approvals,
        "passed": not blockers,
        "blockers": blockers,
    }


def command_resolve_review_packet(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = Path(args.review_packet_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(
        manifest.get("schema_version") == "bizonefuzz.propertycard.review-packet.v1",
        f"{manifest_path}: unsupported review packet schema {manifest.get('schema_version')!r}",
    )

    generated_files = manifest.get("generated_files", {})
    require(isinstance(generated_files, dict), f"{manifest_path}: generated_files must be an object")
    source_cards_path = Path(str(args.cards_json or generated_files.get("property_cards_json", ""))).resolve()
    review_queue_path = Path(str(args.review_queue or generated_files.get("review_queue_csv", ""))).resolve()
    require(source_cards_path.is_file(), f"review packet source PropertyCard bundle not found: {source_cards_path}")
    require(review_queue_path.is_file(), f"review packet queue not found: {review_queue_path}")

    payload = load_payload(source_cards_path)
    with review_queue_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    require(rows, f"{review_queue_path}: review queue is empty")
    applied, skipped = apply_review_queue_rows(payload, rows)
    require(applied > 0 or args.allow_zero, f"{review_queue_path}: no review actions were applied")

    if args.review_status:
        status = args.review_status.strip()
        require(status, "--review-status must not be empty when provided")
        if args.strict_review_status:
            require(
                status in KNOWN_REVIEW_STATUS,
                f"unsupported review_status {status!r}; expected one of {sorted(KNOWN_REVIEW_STATUS)}",
            )
        payload["review_status"] = status

    reviewed_bundle_json = out_dir / "reviewed_bundle.json"
    review_report_md = out_dir / "review_report.md"
    review_report_json = out_dir / "review_report.json"
    resolution_manifest_json = out_dir / "review_resolution_manifest.json"

    write_json(reviewed_bundle_json, payload)
    reviewed_bundle = load_bundle(reviewed_bundle_json)
    required_approvals = get_required_approvals(
        reviewed_bundle.payload.get("review_metadata", {}) if isinstance(reviewed_bundle.payload.get("review_metadata", {}), dict) else {},
        args.required_approvals or 2,
    )
    review_summary = review_report_summary(reviewed_bundle, required_approvals)
    review_report_md.write_text(render_review_report_markdown(review_summary), encoding="utf-8")
    write_json(review_report_json, review_summary)

    gate_result = review_gate_result(
        reviewed_bundle_json,
        allow_draft=args.allow_draft,
        required_approvals_override=args.required_approvals,
    )
    resolution_manifest = {
        "schema_version": "bizonefuzz.propertycard.review-resolution.v1",
        "review_packet_manifest": str(manifest_path.resolve()),
        "source_cards_json": str(source_cards_path),
        "review_queue_csv": str(review_queue_path),
        "applied_actions": applied,
        "skipped_rows": skipped,
        "gate_result": gate_result,
        "generated_files": {
            "reviewed_bundle_json": str(reviewed_bundle_json),
            "review_report_md": str(review_report_md),
            "review_report_json": str(review_report_json),
            "review_resolution_manifest_json": str(resolution_manifest_json),
        },
    }
    write_json(resolution_manifest_json, resolution_manifest)

    if args.require_gate_pass and not gate_result["passed"]:
        for blocker in gate_result["blockers"]:
            print(blocker, file=sys.stderr)
        return 1

    print(
        f"resolved review packet into {out_dir} "
        f"(applied={applied}, stage={gate_result['publication_stage']}, gate_passed={gate_result['passed']})"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and smoke-check Bi-ZoneFuzz++ PropertyCard artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a PropertyCard JSON artifact")
    validate.add_argument("cards_json")
    validate.add_argument("--require-structured-review", action="store_true")
    validate.set_defaults(func=command_validate)

    init_demo = subparsers.add_parser("init-demo", help="write a demo-only PropertyCard artifact")
    init_demo.add_argument("--out", required=True)
    init_demo.set_defaults(func=command_init_demo)

    markdown = subparsers.add_parser("markdown", help="render a PropertyCard artifact as a Markdown table")
    markdown.add_argument("cards_json")
    markdown.add_argument("--out", default="")
    markdown.set_defaults(func=command_markdown)

    export_formulas = subparsers.add_parser("export-formulas", help="export MITL formulas from a PropertyCard artifact")
    export_formulas.add_argument("cards_json")
    export_formulas.add_argument("--out-dir", required=True)
    export_formulas.add_argument("--protocol", default="")
    export_formulas.add_argument("--manifest-out", default="")
    export_formulas.set_defaults(func=command_export_formulas)

    check_monitor = subparsers.add_parser("check-monitor", help="run PropertyCard traces against mitppl-monitor")
    check_monitor.add_argument("cards_json")
    check_monitor.add_argument("--monitor", required=True)
    check_monitor.add_argument("--timeout", type=int, default=30)
    check_monitor.set_defaults(func=command_check_monitor)

    review_report = subparsers.add_parser("review-report", help="summarize structured review / publication status")
    review_report.add_argument("cards_json")
    review_report.add_argument("--format", choices=("markdown", "json"), default="markdown")
    review_report.add_argument("--out", default="")
    review_report.add_argument("--required-approvals", type=int, default=2)
    review_report.set_defaults(func=command_review_report)

    publication_check = subparsers.add_parser("publication-check", help="enforce review/publication gates")
    publication_check.add_argument("cards_json")
    publication_check.add_argument("--allow-draft", action="store_true")
    publication_check.add_argument("--required-approvals", type=int, default=2)
    publication_check.set_defaults(func=command_publication_check)

    set_review_status = subparsers.add_parser("set-review-status", help="update the top-level review_status on a PropertyCard bundle")
    set_review_status.add_argument("cards_json")
    set_review_status.add_argument("--review-status", required=True)
    set_review_status.add_argument("--artifact-role", default="")
    set_review_status.add_argument("--strict", action="store_true")
    set_review_status.add_argument("--out", default="")
    set_review_status.set_defaults(func=command_set_review_status)

    stamp_review = subparsers.add_parser("stamp-review", help="append or replace a structured review entry")
    stamp_review.add_argument("cards_json")
    stamp_review.add_argument("--scope", choices=("bundle", "card"), required=True)
    stamp_review.add_argument("--card-id", default="")
    stamp_review.add_argument("--reviewer-id", required=True)
    stamp_review.add_argument("--reviewer-name", required=True)
    stamp_review.add_argument("--decision", choices=sorted(VALID_REVIEW_DECISIONS), required=True)
    stamp_review.add_argument("--date", required=True)
    stamp_review.add_argument("--role", default="")
    stamp_review.add_argument("--notes", default="")
    stamp_review.add_argument("--required-approvals", type=int, default=0)
    stamp_review.add_argument("--out", default="")
    stamp_review.set_defaults(func=command_stamp_review)

    review_packet = subparsers.add_parser("review-packet", help="materialize a pre-approval review packet with pending reviewer actions")
    review_packet.add_argument("cards_json")
    review_packet.add_argument("--out-dir", required=True)
    review_packet.add_argument("--required-approvals", type=int, default=2)
    review_packet.add_argument("--tool-path-hint", default="MightyPPL/scripts/property_card_tools.py")
    review_packet.add_argument("--review-date-template", default="YYYY-MM-DD")
    review_packet.set_defaults(func=command_review_packet)

    apply_review_packet = subparsers.add_parser("apply-review-packet", help="apply reviewer-filled review-packet queue rows to a PropertyCard bundle copy")
    apply_review_packet.add_argument("review_packet_manifest")
    apply_review_packet.add_argument("--review-queue", default="")
    apply_review_packet.add_argument("--cards-json", default="")
    apply_review_packet.add_argument("--out", default="")
    apply_review_packet.add_argument("--allow-zero", action="store_true")
    apply_review_packet.set_defaults(func=command_apply_review_packet)

    resolve_review_packet = subparsers.add_parser("resolve-review-packet", help="apply a filled review packet and materialize a reviewed bundle plus gate-evaluation artifacts")
    resolve_review_packet.add_argument("review_packet_manifest")
    resolve_review_packet.add_argument("--out-dir", required=True)
    resolve_review_packet.add_argument("--review-queue", default="")
    resolve_review_packet.add_argument("--cards-json", default="")
    resolve_review_packet.add_argument("--allow-zero", action="store_true")
    resolve_review_packet.add_argument("--allow-draft", action="store_true")
    resolve_review_packet.add_argument("--review-status", default="")
    resolve_review_packet.add_argument("--strict-review-status", action="store_true")
    resolve_review_packet.add_argument("--required-approvals", type=int, default=0)
    resolve_review_packet.add_argument("--require-gate-pass", action="store_true")
    resolve_review_packet.set_defaults(func=command_resolve_review_packet)

    publish_bundle = subparsers.add_parser("publish-bundle", help="materialize a gated publication pack from a PropertyCard bundle")
    publish_bundle.add_argument("cards_json")
    publish_bundle.add_argument("--out-dir", required=True)
    publish_bundle.add_argument("--allow-draft", action="store_true")
    publish_bundle.add_argument("--required-approvals", type=int, default=2)
    publish_bundle.set_defaults(func=command_publish_bundle)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
