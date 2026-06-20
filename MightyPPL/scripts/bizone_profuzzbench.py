#!/usr/bin/env python3
"""Bi-ZoneFuzz++ experiment automation on top of ProFuzzBench.

This script provides three layers needed by the research prototype:

1. Build an auditable campaign manifest for bring-up or main-study subjects.
2. Run per-replication ProFuzzBench containers while injecting local
   Bi-ZoneFuzz++ AFLNet / monitor assets when requested.
3. Reconstruct RVEM raw logs, tables, and plots from ProFuzzBench-style result
   tarballs.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from property_card_tools import (
    PropertyCard,
    bundle_review_summary,
    card_review_summary,
    get_required_approvals,
    load_bundle,
    load_cards,
    publication_blockers,
)


SCHEMA_VERSION = "bizonefuzz.profuzzbench.v1"
CATALOG_SCHEMA_VERSION = "bizonefuzz.profuzzbench.catalog.v1"
MATRIX_SCHEMA_VERSION = "bizonefuzz.profuzzbench.matrix.v1"
PREFLIGHT_SCHEMA_VERSION = "bizonefuzz.profuzzbench.preflight.v1"
IMAGE_BUILD_SCHEMA_VERSION = "bizonefuzz.profuzzbench.image_build.v1"
RESULT_AUDIT_SCHEMA_VERSION = "bizonefuzz.profuzzbench.result_audit.v1"
FINALIZE_SCHEMA_VERSION = "bizonefuzz.profuzzbench.finalize.v1"
VALID_PUBLICATION_GATES = {"none", "draft", "final"}

DEFAULT_VARIANTS = [
    "aflnet-base",
    "aflnet-patched-base",
    "oracle-only",
    "frontier-only",
    "zone-only",
    "obligation-only",
    "progress-only",
    "frontier+zone",
    "full",
    "aflnwe",
    "stateafl",
]

VARIANT_SPECS = {
    "aflnet-base": {
        "fuzzer": "aflnet",
        "monitor_enabled": False,
        "monitor_mode": "disabled",
        "inject_local_aflnet": False,
    },
    "aflnet-patched-base": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": False,
        "monitor_mode": "disabled",
        "inject_local_aflnet": False,
    },
    "oracle-only": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "oracle-only",
        "inject_local_aflnet": False,
    },
    "frontier-only": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "frontier-only",
        "inject_local_aflnet": False,
    },
    "zone-only": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "zone-only",
        "inject_local_aflnet": False,
    },
    "obligation-only": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "obligation-only",
        "inject_local_aflnet": False,
    },
    "progress-only": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "progress-only",
        "inject_local_aflnet": False,
    },
    "frontier+zone": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "frontier+zone",
        "inject_local_aflnet": False,
    },
    "full": {
        "fuzzer": "bizone-aflnet",
        "monitor_enabled": True,
        "monitor_mode": "full",
        "inject_local_aflnet": False,
    },
    "aflnwe": {
        "fuzzer": "aflnwe",
        "monitor_enabled": False,
        "monitor_mode": "",
        "inject_local_aflnet": False,
    },
    "stateafl": {
        "fuzzer": "stateafl",
        "monitor_enabled": False,
        "monitor_mode": "",
        "inject_local_aflnet": False,
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def split_csv(text: str) -> list[str]:
    return [item.strip() for item in text.split(",") if item.strip()]


def parse_override_map(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if not value:
            continue
        for item in split_csv(value):
            require("=" in item, f"invalid override {item!r}; expected subject=property_id")
            subject, property_id = item.split("=", 1)
            result[subject.strip()] = property_id.strip()
    return result


def load_catalog(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    schema = payload.get("schema_version", "")
    require(schema == CATALOG_SCHEMA_VERSION, f"{path}: unsupported schema_version {schema!r}")
    require(isinstance(payload.get("stages"), list), f"{path}: 'stages' must be a list")
    return payload


def catalog_stage(catalog: dict[str, Any], stage_id: str) -> dict[str, Any]:
    for stage in catalog["stages"]:
        if stage.get("stage_id") == stage_id:
            return stage
    raise ValueError(f"unknown campaign stage {stage_id!r}")


def cards_by_id(cards_json: str) -> dict[str, PropertyCard]:
    cards = load_cards(Path(cards_json))
    return {card.property_id: card for card in cards}


def cards_by_protocol(cards_json: str) -> dict[str, list[PropertyCard]]:
    result: dict[str, list[PropertyCard]] = {}
    for card in load_cards(Path(cards_json)):
        result.setdefault(card.protocol.upper(), []).append(card)
    return result


def sanitize_variant(variant: str) -> str:
    return variant.replace("+", "_plus_")


def variant_family(variant: str) -> str:
    if variant == "aflnet-base":
        return "baseline"
    if variant == "aflnet-patched-base":
        return "patched-baseline"
    if variant in {"aflnwe", "stateafl"}:
        return "comparison"
    return "monitor-ablation"


def unique_strings(items: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        output.append(text)
        seen.add(text)
    return output


def subject_monitor_policy(subject: dict[str, Any]) -> dict[str, Any]:
    payload = subject.get("monitor_policy", {})
    if not isinstance(payload, dict):
        payload = {}

    mode = str(payload.get("mode", "") or "").strip().lower()
    reason = str(payload.get("reason", "") or "").strip()
    raw_allowed = payload.get("allowed_variants", [])
    allowed_variants = unique_strings(raw_allowed) if isinstance(raw_allowed, list) else []

    return {
        "mode": mode,
        "reason": reason,
        "allowed_variants": allowed_variants,
    }


def monitor_policy_allows_variant(policy: dict[str, Any], variant: str) -> bool:
    allowed_variants = set(policy.get("allowed_variants", []))
    if allowed_variants:
        return variant in allowed_variants
    if policy.get("mode") == "baseline-only":
        spec = VARIANT_SPECS.get(variant, {})
        return not bool(spec.get("monitor_enabled"))
    return True


def subject_image(subject: dict[str, Any], fuzzer: str) -> str:
    base = str(subject["docker_image"])
    if fuzzer == "bizone-aflnet":
        return f"{base}-bizone-aflnet"
    if fuzzer == "stateafl":
        return f"{base}-stateafl"
    return base


def subject_options(subject: dict[str, Any], fuzzer: str, test_timeout_ms: int) -> str:
    key = {
        "aflnet": "aflnet_options",
        "bizone-aflnet": "aflnet_options",
        "aflnwe": "aflnwe_options",
        "stateafl": "stateafl_options",
    }[fuzzer]
    template = str(subject.get(key, ""))
    require(template, f"subject {subject['subject_id']} missing {key}")
    return template.replace("{TEST_TIMEOUT}", str(test_timeout_ms))


def select_property_id(subject: dict[str, Any],
                       overrides: dict[str, str],
                       by_id: dict[str, PropertyCard],
                       by_protocol: dict[str, list[PropertyCard]]) -> str:
    subject_id = str(subject["subject_id"])
    if subject_id in overrides:
        return overrides[subject_id]
    recommended = str(subject.get("recommended_property_id", "")).strip()
    if recommended:
        return recommended
    protocol_cards = by_protocol.get(str(subject["protocol"]).upper(), [])
    return protocol_cards[0].property_id if protocol_cards else ""


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_catalog(Path(args.catalog))
    stage = catalog_stage(catalog, args.stage)
    selected_subjects = split_csv(args.subjects) if args.subjects else []
    selected_variants = split_csv(args.variants) if args.variants else list(DEFAULT_VARIANTS)
    require(args.publication_gate in VALID_PUBLICATION_GATES, f"unsupported publication gate {args.publication_gate!r}")
    for variant in selected_variants:
        require(variant in VARIANT_SPECS, f"unknown variant {variant!r}")

    overrides = parse_override_map(args.property_override)
    by_id = cards_by_id(args.cards_json) if args.cards_json else {}
    by_protocol = cards_by_protocol(args.cards_json) if args.cards_json else {}
    review_index, bundle_index = property_review_index(args.cards_json) if args.cards_json else ({}, {})

    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    policy_exclusions: list[dict[str, str]] = []

    for subject in stage["subjects"]:
        subject_id = str(subject["subject_id"])
        if selected_subjects and subject_id not in selected_subjects:
            continue

        monitor_policy = subject_monitor_policy(subject)
        property_id = select_property_id(subject, overrides, by_id, by_protocol)
        card = by_id.get(property_id) if property_id else None

        for variant in selected_variants:
            spec = VARIANT_SPECS[variant]
            monitor_enabled = bool(spec["monitor_enabled"])
            if not monitor_policy_allows_variant(monitor_policy, variant):
                policy_exclusions.append(
                    {
                        "subject_id": subject_id,
                        "protocol": str(subject["protocol"]),
                        "variant": variant,
                        "policy_mode": str(monitor_policy.get("mode", "")),
                        "reason": monitor_policy.get("reason", "") or "variant excluded by monitor policy",
                    }
                )
                continue
            property_state = property_gate_state(property_id, review_index, bundle_index) if monitor_enabled else {
                "property_available": bool(card),
                "property_review_status": "",
                "property_dynamic_validation_status": "",
                "property_required_approvals": "",
                "property_draft_approvals": "",
                "property_final_approvals": "",
                "property_publication_ready": False,
                "draft_ready": True,
                "final_ready": True,
                "draft_blockers": [],
                "final_blockers": [],
            }
            if monitor_enabled and not property_state["property_available"]:
                warnings.append(
                    f"skipped {subject_id}/{variant}: no PropertyCard available for protocol {subject['protocol']}"
                )
                continue
            if monitor_enabled and args.publication_gate != "none" and not gate_ready(property_state, args.publication_gate):
                warnings.append(
                    f"skipped {subject_id}/{variant}: property {property_id} is not {args.publication_gate}-ready: "
                    f"{join_blockers(gate_blockers(property_state, args.publication_gate))}"
                )
                continue

            fuzzer = str(spec["fuzzer"])
            options = subject_options(subject, fuzzer, args.test_timeout_ms)
            formula_file = ""
            container_formula_path = ""
            if monitor_enabled:
                formula_file = f"{property_id}.mitl"
                container_formula_path = f"/home/ubuntu/experiments/{args.formula_subdir}/{formula_file}"
                options = f"{options} -Y {container_formula_path} -Z {spec['monitor_mode']}"

            entry = {
                "stage_id": args.stage,
                "campaign": args.campaign,
                "subject_id": subject_id,
                "protocol": str(subject["protocol"]),
                "profuzzbench_target": str(subject["profuzzbench_target"]),
                "docker_image": subject_image(subject, fuzzer),
                "variant": variant,
                "fuzzer": fuzzer,
                "runs": args.runs,
                "fuzz_timeout_sec": args.fuzz_timeout_sec,
                "skipcount": args.skipcount,
                "test_timeout_ms": args.test_timeout_ms,
                "results_dir": f"results-{subject['profuzzbench_target']}",
                "out_dir": f"out-{subject['profuzzbench_target']}-{sanitize_variant(variant)}",
                "options": options,
                "inject_local_aflnet": bool(spec["inject_local_aflnet"]),
                "monitor_enabled": monitor_enabled,
                "monitor_mode": str(spec["monitor_mode"]),
                "publication_gate": args.publication_gate,
                "property_id": property_id,
                "formula_file": formula_file,
                "container_formula_path": container_formula_path,
                "property_available": int(bool(property_state["property_available"])),
                "property_review_status": property_state["property_review_status"],
                "property_dynamic_validation_status": property_state["property_dynamic_validation_status"],
                "property_required_approvals": property_state["property_required_approvals"],
                "property_draft_approvals": property_state["property_draft_approvals"],
                "property_final_approvals": property_state["property_final_approvals"],
                "property_publication_ready": int(bool(property_state["property_publication_ready"])),
                "property_draft_gate_ready": int(bool(property_state["draft_ready"])),
                "property_final_gate_ready": int(bool(property_state["final_ready"])),
                "property_draft_blockers": list(property_state["draft_blockers"]),
                "property_final_blockers": list(property_state["final_blockers"]),
            }
            if card:
                entry["property_meta"] = {
                    "property_id": card.property_id,
                    "source_url": card.source_url,
                    "section_id": card.section_id,
                    "protocol": card.protocol,
                }
            entries.append(entry)

    require(entries, "no manifest entries were produced")

    return {
        "schema_version": SCHEMA_VERSION,
        "campaign": args.campaign,
        "stage_id": args.stage,
        "catalog": str(Path(args.catalog)),
        "cards_json": str(Path(args.cards_json)) if args.cards_json else "",
        "publication_gate": args.publication_gate,
        "formula_subdir": args.formula_subdir,
        "local_afl_fuzz": str(Path(args.afl_fuzz)) if args.afl_fuzz else "",
        "local_monitor_bin": str(Path(args.monitor_bin)) if args.monitor_bin else "",
        "entries": entries,
        "warnings": warnings,
        "policy_exclusions": policy_exclusions,
    }


def write_manifest(manifest: dict[str, Any], out_path: str) -> None:
    text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == SCHEMA_VERSION, "unsupported manifest schema")
    require(isinstance(manifest.get("entries"), list), "manifest entries must be a list")
    return manifest


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def ratio(numerator: int, denominator: int) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def property_review_index(cards_json: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not cards_json:
        return {}, {}
    bundle = load_bundle(Path(cards_json))
    metadata = bundle.payload.get("review_metadata", {}) if isinstance(bundle.payload.get("review_metadata", {}), dict) else {}
    required_approvals = get_required_approvals(metadata, 2)
    bundle_summary = bundle_review_summary(bundle, required_approvals)
    bundle_index = {
        "bundle_id": bundle_summary["bundle_id"],
        "review_status": bundle_summary["review_status"],
        "required_approvals": bundle_summary["required_approvals"],
        "draft_approvals": bundle_summary["draft_approvals"],
        "final_approvals": bundle_summary["final_approvals"],
        "dynamic_validation_status": bundle_summary["dynamic_validation_status"],
        "draft_blockers": publication_blockers(bundle_summary, allow_draft=True, bundle_scope=True),
        "final_blockers": publication_blockers(bundle_summary, allow_draft=False, bundle_scope=True),
    }

    cards: dict[str, dict[str, Any]] = {}
    for card in bundle.cards:
        summary = card_review_summary(card, required_approvals)
        cards[card.property_id] = {
            "property_id": card.property_id,
            "protocol": card.protocol,
            "source_url": card.source_url,
            "section_id": card.section_id,
            "normative_level": card.normative_level,
            "review_status": bundle_summary["review_status"],
            "required_approvals": summary["required_approvals"],
            "draft_approvals": summary["draft_approvals"],
            "final_approvals": summary["final_approvals"],
            "dynamic_validation_status": summary["dynamic_validation_status"],
            "publication_ready": bool(summary["publication_ready"]),
            "draft_blockers": publication_blockers(summary, allow_draft=True, bundle_scope=False),
            "final_blockers": publication_blockers(summary, allow_draft=False, bundle_scope=False),
        }
    return cards, bundle_index


def join_blockers(items: list[str]) -> str:
    return "; ".join(items) if items else ""


def property_gate_state(property_id: str,
                        review_index: dict[str, dict[str, Any]],
                        bundle_index: dict[str, Any]) -> dict[str, Any]:
    if not property_id:
        return {
            "property_available": False,
            "property_review_status": bundle_index.get("review_status", ""),
            "property_dynamic_validation_status": "",
            "property_required_approvals": "",
            "property_draft_approvals": "",
            "property_final_approvals": "",
            "property_publication_ready": False,
            "draft_ready": False,
            "final_ready": False,
            "draft_blockers": ["PropertyCard unavailable"],
            "final_blockers": ["PropertyCard unavailable"],
        }

    property_info = review_index.get(property_id)
    if not property_info:
        return {
            "property_available": False,
            "property_review_status": bundle_index.get("review_status", ""),
            "property_dynamic_validation_status": "",
            "property_required_approvals": "",
            "property_draft_approvals": "",
            "property_final_approvals": "",
            "property_publication_ready": False,
            "draft_ready": False,
            "final_ready": False,
            "draft_blockers": ["PropertyCard unavailable"],
            "final_blockers": ["PropertyCard unavailable"],
        }

    draft_blockers = unique_strings(
        list(bundle_index.get("draft_blockers", [])) + list(property_info.get("draft_blockers", []))
    )
    final_blockers = unique_strings(
        list(bundle_index.get("final_blockers", [])) + list(property_info.get("final_blockers", []))
    )
    return {
        "property_available": True,
        "property_review_status": property_info.get("review_status", bundle_index.get("review_status", "")),
        "property_dynamic_validation_status": property_info.get("dynamic_validation_status", ""),
        "property_required_approvals": property_info.get("required_approvals", ""),
        "property_draft_approvals": property_info.get("draft_approvals", ""),
        "property_final_approvals": property_info.get("final_approvals", ""),
        "property_publication_ready": bool(property_info.get("publication_ready", False)),
        "draft_ready": not draft_blockers,
        "final_ready": not final_blockers,
        "draft_blockers": draft_blockers,
        "final_blockers": final_blockers,
    }


def gate_ready(state: dict[str, Any], publication_gate: str) -> bool:
    require(publication_gate in VALID_PUBLICATION_GATES, f"unsupported publication gate {publication_gate!r}")
    if publication_gate == "none":
        return True
    if publication_gate == "draft":
        return bool(state.get("draft_ready", False))
    return bool(state.get("final_ready", False))


def gate_blockers(state: dict[str, Any], publication_gate: str) -> list[str]:
    require(publication_gate in VALID_PUBLICATION_GATES, f"unsupported publication gate {publication_gate!r}")
    if publication_gate == "none":
        return []
    if publication_gate == "draft":
        return list(state.get("draft_blockers", []))
    return list(state.get("final_blockers", []))


def select_manifest_entries(manifest: dict[str, Any],
                            subjects_text: str = "",
                            variants_text: str = "") -> list[dict[str, Any]]:
    selected_subjects = set(split_csv(subjects_text)) if subjects_text else set()
    selected_variants = set(split_csv(variants_text)) if variants_text else set()
    entries: list[dict[str, Any]] = []
    for entry in manifest["entries"]:
        if selected_subjects and entry["subject_id"] not in selected_subjects:
            continue
        if selected_variants and entry["variant"] not in selected_variants:
            continue
        entries.append(entry)
    require(entries, "no manifest entries matched the current selection")
    return entries


def resolve_runtime_assets(manifest: dict[str, Any],
                           entries: list[dict[str, Any]],
                           *,
                           afl_fuzz_override: str = "",
                           monitor_bin_override: str = "") -> dict[str, Any]:
    need_local_afl = any(bool(entry.get("inject_local_aflnet")) for entry in entries)
    need_monitor = any(bool(entry.get("monitor_enabled")) for entry in entries)

    afl_text = str(afl_fuzz_override or manifest.get("local_afl_fuzz") or "").strip()
    monitor_text = str(monitor_bin_override or manifest.get("local_monitor_bin") or "").strip()
    afl_path = Path(afl_text).resolve() if afl_text else None
    monitor_path = Path(monitor_text).resolve() if monitor_text else None

    if need_local_afl:
        require(afl_text, "local afl-fuzz binary is required for the selected entries but was not configured")
        require(afl_path is not None and afl_path.is_file(), f"local afl-fuzz binary not found: {afl_path}")
    if need_monitor:
        require(monitor_text, "monitor binary is required for the selected entries but was not configured")
        require(monitor_path is not None and monitor_path.is_file(), f"monitor binary not found: {monitor_path}")

    return {
        "need_local_afl": need_local_afl,
        "need_monitor": need_monitor,
        "local_afl_fuzz": afl_path,
        "local_monitor_bin": monitor_path,
        "local_afl_fuzz_configured": afl_text,
        "local_monitor_bin_configured": monitor_text,
    }


def gate_failures(entries: list[dict[str, Any]],
                  publication_gate: str,
                  review_index: dict[str, dict[str, Any]],
                  bundle_index: dict[str, Any]) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    if publication_gate == "none":
        return failures
    for entry in entries:
        if not entry.get("monitor_enabled"):
            continue
        state = property_gate_state(str(entry.get("property_id", "") or ""), review_index, bundle_index)
        if gate_ready(state, publication_gate):
            continue
        failures.append(
            {
                "subject_id": str(entry["subject_id"]),
                "variant": str(entry["variant"]),
                "property_id": str(entry.get("property_id", "") or ""),
                "reason": join_blockers(gate_blockers(state, publication_gate)),
            }
        )
    return failures


def build_entry_matrix_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    cards_json = str(manifest.get("cards_json", "") or "")
    review_index, bundle_index = property_review_index(cards_json)
    rows: list[dict[str, Any]] = []
    for entry in manifest["entries"]:
        property_id = str(entry.get("property_id", "") or "")
        property_info = review_index.get(property_id, {})
        runs = int(entry.get("runs", 0) or 0)
        fuzz_timeout_sec = int(entry.get("fuzz_timeout_sec", 0) or 0)
        total_fuzz_seconds = runs * fuzz_timeout_sec
        draft_gate_ready = False
        final_gate_ready = False
        draft_blockers: list[str] = []
        final_blockers: list[str] = []
        if property_info:
            draft_blockers = list(bundle_index.get("draft_blockers", [])) + list(property_info.get("draft_blockers", []))
            final_blockers = list(bundle_index.get("final_blockers", [])) + list(property_info.get("final_blockers", []))
            draft_gate_ready = not draft_blockers
            final_gate_ready = not final_blockers
        rows.append(
            {
                "stage_id": manifest.get("stage_id", ""),
                "campaign": manifest.get("campaign", ""),
                "subject_id": entry.get("subject_id", ""),
                "protocol": entry.get("protocol", ""),
                "profuzzbench_target": entry.get("profuzzbench_target", ""),
                "variant": entry.get("variant", ""),
                "variant_family": variant_family(str(entry.get("variant", ""))),
                "fuzzer": entry.get("fuzzer", ""),
                "monitor_enabled": int(bool(entry.get("monitor_enabled"))),
                "monitor_mode": entry.get("monitor_mode", ""),
                "inject_local_aflnet": int(bool(entry.get("inject_local_aflnet"))),
                "runs": runs,
                "fuzz_timeout_sec": fuzz_timeout_sec,
                "total_fuzz_seconds": total_fuzz_seconds,
                "estimated_core_hours": round(total_fuzz_seconds / 3600.0, 4),
                "property_id": property_id,
                "property_required": int(bool(entry.get("monitor_enabled"))),
                "property_available": int(bool(property_info)),
                "property_source_url": property_info.get("source_url", str(entry.get("property_meta", {}).get("source_url", ""))),
                "property_section_id": property_info.get("section_id", str(entry.get("property_meta", {}).get("section_id", ""))),
                "property_normative_level": property_info.get("normative_level", ""),
                "property_review_status": property_info.get("review_status", bundle_index.get("review_status", "")),
                "property_dynamic_validation_status": property_info.get("dynamic_validation_status", ""),
                "property_required_approvals": property_info.get("required_approvals", ""),
                "property_draft_approvals": property_info.get("draft_approvals", ""),
                "property_final_approvals": property_info.get("final_approvals", ""),
                "property_publication_ready": int(bool(property_info.get("publication_ready", False))) if property_info else 0,
                "draft_gate_ready": int(draft_gate_ready),
                "final_gate_ready": int(final_gate_ready),
                "draft_blockers": join_blockers(draft_blockers),
                "final_blockers": join_blockers(final_blockers),
            }
        )
    return rows


def build_subject_readiness_rows(entry_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for row in entry_rows:
        key = (row["stage_id"], row["campaign"], row["subject_id"], row["protocol"])
        groups.setdefault(key, []).append(row)

    output: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        stage_id, campaign, subject_id, protocol = key
        monitor_rows = [row for row in rows if int(row.get("monitor_enabled", 0))]
        comparison_rows = [row for row in rows if row.get("variant_family") == "comparison"]
        property_ids = sorted({str(row.get("property_id", "")) for row in rows if row.get("property_id", "")})
        property_available = all(int(row.get("property_available", 0)) for row in monitor_rows) if monitor_rows else False
        draft_ready_monitor_entries = sum(int(row.get("draft_gate_ready", 0)) for row in monitor_rows)
        final_ready_monitor_entries = sum(int(row.get("final_gate_ready", 0)) for row in monitor_rows)
        missing_property_variants = [row["variant"] for row in monitor_rows if not int(row.get("property_available", 0))]
        draft_blockers = sorted({item for row in monitor_rows for item in split_csv(row.get("draft_blockers", "").replace("; ", ",")) if item})
        final_blockers = sorted({item for row in monitor_rows for item in split_csv(row.get("final_blockers", "").replace("; ", ",")) if item})
        total_fuzz_seconds = sum(int(row.get("total_fuzz_seconds", 0) or 0) for row in rows)
        output.append(
            {
                "stage_id": stage_id,
                "campaign": campaign,
                "subject_id": subject_id,
                "protocol": protocol,
                "profuzzbench_target": rows[0].get("profuzzbench_target", ""),
                "variants": ",".join(sorted(str(row["variant"]) for row in rows)),
                "monitor_variants": ",".join(sorted(str(row["variant"]) for row in monitor_rows)),
                "comparison_variants": ",".join(sorted(str(row["variant"]) for row in comparison_rows)),
                "entry_count": len(rows),
                "monitor_entry_count": len(monitor_rows),
                "runs_total": sum(int(row.get("runs", 0) or 0) for row in rows),
                "total_fuzz_seconds": total_fuzz_seconds,
                "estimated_core_hours": round(total_fuzz_seconds / 3600.0, 4),
                "property_ids": ",".join(property_ids),
                "property_available": int(property_available),
                "property_review_status": rows[0].get("property_review_status", ""),
                "draft_ready_monitor_entries": draft_ready_monitor_entries,
                "final_ready_monitor_entries": final_ready_monitor_entries,
                "draft_ready_subject": int(draft_ready_monitor_entries == len(monitor_rows) and not missing_property_variants) if monitor_rows else 1,
                "final_ready_subject": int(final_ready_monitor_entries == len(monitor_rows) and not missing_property_variants) if monitor_rows else 1,
                "missing_property_variants": ",".join(sorted(missing_property_variants)),
                "monitor_readiness_ratio": round(ratio(draft_ready_monitor_entries, len(monitor_rows)), 4) if monitor_rows else 1.0,
                "draft_blockers": join_blockers(draft_blockers),
                "final_blockers": join_blockers(final_blockers),
            }
        )
    return output


def render_paper_matrix(subject_rows: list[dict[str, Any]], entry_rows: list[dict[str, Any]]) -> str:
    total_entries = len(entry_rows)
    total_subjects = len(subject_rows)
    total_core_hours = sum(float(row.get("estimated_core_hours", 0.0) or 0.0) for row in subject_rows)
    lines = [
        "# Bi-ZoneFuzz++ Experiment Matrix",
        "",
        f"- Subjects: `{total_subjects}`",
        f"- Entries: `{total_entries}`",
        f"- Estimated core-hours: `{total_core_hours:.2f}`",
        "",
        "## Subject Readiness",
        "",
        "| stage | subject | protocol | variants | monitor variants | draft-ready monitor entries | final-ready monitor entries | est. core-hours |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in subject_rows:
        lines.append(
            f"| {row['stage_id']} | {row['subject_id']} | {row['protocol']} | {row['variants']} | {row['monitor_variants'] or 'n/a'} | "
            f"{row['draft_ready_monitor_entries']}/{row['monitor_entry_count']} | "
            f"{row['final_ready_monitor_entries']}/{row['monitor_entry_count']} | {float(row['estimated_core_hours']):.2f} |"
        )

    lines.extend(
        [
            "",
            "## Entry Matrix",
            "",
            "| subject | variant | family | monitor | runs | timeout (s) | property | draft gate | final gate |",
            "| --- | --- | --- | ---: | ---: | ---: | --- | ---: | ---: |",
        ]
    )
    for row in entry_rows:
        lines.append(
            f"| {row['subject_id']} | {row['variant']} | {row['variant_family']} | {row['monitor_enabled']} | "
            f"{row['runs']} | {row['fuzz_timeout_sec']} | {row['property_id'] or 'n/a'} | "
            f"{row['draft_gate_ready']} | {row['final_gate_ready']} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_campaign_summary(manifest: dict[str, Any],
                           entry_rows: list[dict[str, Any]],
                           subject_rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_fuzz_seconds = sum(int(row.get("total_fuzz_seconds", 0) or 0) for row in entry_rows)
    return {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "stage_id": manifest.get("stage_id", ""),
        "campaign": manifest.get("campaign", ""),
        "publication_gate": manifest.get("publication_gate", "none"),
        "manifest_entries": len(entry_rows),
        "subjects": len(subject_rows),
        "monitor_entries": sum(int(row.get("monitor_enabled", 0)) for row in entry_rows),
        "comparison_entries": sum(1 for row in entry_rows if row.get("variant_family") == "comparison"),
        "total_runs": sum(int(row.get("runs", 0) or 0) for row in entry_rows),
        "total_fuzz_seconds": total_fuzz_seconds,
        "estimated_core_hours": round(total_fuzz_seconds / 3600.0, 4),
        "draft_ready_subjects": sum(int(row.get("draft_ready_subject", 0)) for row in subject_rows),
        "final_ready_subjects": sum(int(row.get("final_ready_subject", 0)) for row in subject_rows),
        "warnings": list(manifest.get("warnings", [])),
        "policy_exclusions": list(manifest.get("policy_exclusions", [])),
    }


def command_matrix(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == SCHEMA_VERSION, "unsupported manifest schema")
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    entry_rows = build_entry_matrix_rows(manifest)
    subject_rows = build_subject_readiness_rows(entry_rows)
    summary = build_campaign_summary(manifest, entry_rows, subject_rows)

    entry_matrix_csv = out_dir / "entry_matrix.csv"
    subject_readiness_csv = out_dir / "subject_readiness.csv"
    paper_matrix_md = out_dir / "paper_matrix.md"
    campaign_summary_json = out_dir / "campaign_summary.json"
    matrix_manifest_json = out_dir / "matrix_manifest.json"

    write_csv(
        entry_matrix_csv,
        [
            "stage_id",
            "campaign",
            "subject_id",
            "protocol",
            "profuzzbench_target",
            "variant",
            "variant_family",
            "fuzzer",
            "monitor_enabled",
            "monitor_mode",
            "inject_local_aflnet",
            "runs",
            "fuzz_timeout_sec",
            "total_fuzz_seconds",
            "estimated_core_hours",
            "property_id",
            "property_required",
            "property_available",
            "property_source_url",
            "property_section_id",
            "property_normative_level",
            "property_review_status",
            "property_dynamic_validation_status",
            "property_required_approvals",
            "property_draft_approvals",
            "property_final_approvals",
            "property_publication_ready",
            "draft_gate_ready",
            "final_gate_ready",
            "draft_blockers",
            "final_blockers",
        ],
        entry_rows,
    )
    write_csv(
        subject_readiness_csv,
        [
            "stage_id",
            "campaign",
            "subject_id",
            "protocol",
            "profuzzbench_target",
            "variants",
            "monitor_variants",
            "comparison_variants",
            "entry_count",
            "monitor_entry_count",
            "runs_total",
            "total_fuzz_seconds",
            "estimated_core_hours",
            "property_ids",
            "property_available",
            "property_review_status",
            "draft_ready_monitor_entries",
            "final_ready_monitor_entries",
            "draft_ready_subject",
            "final_ready_subject",
            "missing_property_variants",
            "monitor_readiness_ratio",
            "draft_blockers",
            "final_blockers",
        ],
        subject_rows,
    )
    paper_matrix_md.write_text(render_paper_matrix(subject_rows, entry_rows), encoding="utf-8")
    campaign_summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    matrix_manifest = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "manifest": str(Path(args.manifest).resolve()),
        "generated_files": {
            "entry_matrix_csv": str(entry_matrix_csv),
            "subject_readiness_csv": str(subject_readiness_csv),
            "paper_matrix_md": str(paper_matrix_md),
            "campaign_summary_json": str(campaign_summary_json),
            "matrix_manifest_json": str(matrix_manifest_json),
        },
        "entry_count": len(entry_rows),
        "subject_count": len(subject_rows),
        "warning_count": len(summary["warnings"]),
        "policy_exclusion_count": len(summary.get("policy_exclusions", [])),
    }
    matrix_manifest_json.write_text(json.dumps(matrix_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote experiment matrix to {out_dir}")
    return 0


def export_required_formulas(manifest: dict[str, Any],
                             out_dir: Path,
                             entries: list[dict[str, Any]] | None = None) -> dict[str, Path]:
    selected_entries = manifest["entries"] if entries is None else entries
    required_property_ids = unique_strings(
        [
            str(entry.get("property_id", "") or "")
            for entry in selected_entries
            if entry.get("monitor_enabled") and entry.get("property_id")
        ]
    )
    if not required_property_ids:
        return {}

    cards_json = manifest.get("cards_json", "")
    require(cards_json, "manifest is missing cards_json; cannot export formulas")
    by_id = cards_by_id(cards_json)
    out_dir.mkdir(parents=True, exist_ok=True)
    exported: dict[str, Path] = {}
    for property_id in required_property_ids:
        card = by_id.get(property_id)
        require(card is not None, f"manifest references unknown PropertyCard {property_id!r}")
        target = out_dir / f"{property_id}.mitl"
        target.write_text(card.MITL_formula.strip() + "\n", encoding="utf-8")
        exported[property_id] = target
    return exported


def run_subprocess(cmd: list[str],
                   *,
                   cwd: Path | None = None,
                   capture: bool = False,
                   timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=False,
        timeout=timeout,
    )


def probe_docker_environment(docker_bin: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "docker_bin": docker_bin,
        "cli_available": False,
        "cli_version_text": "",
        "cli_error": "",
        "daemon_available": False,
        "daemon_version": "",
        "daemon_error": "",
    }

    try:
        client = run_subprocess([docker_bin, "--version"], capture=True)
    except OSError as exc:
        report["cli_error"] = str(exc)
        return report

    report["cli_version_text"] = client.stdout.strip()
    report["cli_available"] = client.returncode == 0
    if client.returncode != 0:
        report["cli_error"] = (client.stderr or client.stdout).strip()
        return report

    daemon = run_subprocess([docker_bin, "info", "--format", "{{.ServerVersion}}"], capture=True)
    if daemon.returncode == 0:
        report["daemon_available"] = True
        report["daemon_version"] = daemon.stdout.strip()
    else:
        report["daemon_error"] = (daemon.stderr or daemon.stdout).strip()
    return report


def inspect_docker_images(docker_bin: str,
                          entries: list[dict[str, Any]],
                          *,
                          daemon_available: bool) -> dict[str, Any]:
    required_images = unique_strings([str(entry.get("docker_image", "") or "") for entry in entries])
    image_rows: list[dict[str, Any]] = []
    if not daemon_available:
        for image in required_images:
            image_rows.append(
                {
                    "image": image,
                    "present": False,
                    "checked": False,
                    "image_id": "",
                    "error": "docker daemon unavailable; image presence not checked",
                }
            )
        return {
            "checked": False,
            "required_count": len(required_images),
            "present_count": 0,
            "missing_count": len(required_images),
            "all_present": False if required_images else True,
            "images": image_rows,
        }

    for image in required_images:
        inspected = run_subprocess(
            [docker_bin, "image", "inspect", image, "--format", "{{.Id}}"],
            capture=True,
        )
        image_rows.append(
            {
                "image": image,
                "present": inspected.returncode == 0,
                "checked": True,
                "image_id": inspected.stdout.strip() if inspected.returncode == 0 else "",
                "error": "" if inspected.returncode == 0 else (inspected.stderr or inspected.stdout).strip(),
            }
        )

    present_count = sum(1 for row in image_rows if bool(row["present"]))
    return {
        "checked": True,
        "required_count": len(required_images),
        "present_count": present_count,
        "missing_count": len(required_images) - present_count,
        "all_present": present_count == len(required_images),
        "images": image_rows,
    }


def require_docker_images_available(image_report: dict[str, Any]) -> None:
    if bool(image_report.get("all_present", False)):
        return
    missing = [
        str(row.get("image", ""))
        for row in image_report.get("images", [])
        if isinstance(row, dict) and not bool(row.get("present", False))
    ]
    suffix = f": {', '.join(missing)}" if missing else ""
    raise RuntimeError(f"required ProFuzzBench Docker images are missing{suffix}")


def profuzzbench_context_index(workspace: Path) -> dict[str, Path]:
    subjects_root = workspace / "profuzzbench" / "subjects"
    contexts: dict[str, Path] = {}
    if not subjects_root.is_dir():
        return contexts
    for dockerfile in subjects_root.glob("*/*/Dockerfile"):
        context = dockerfile.parent.resolve()
        contexts.setdefault(context.name.lower(), context)
    return contexts


def image_build_targets(manifest: dict[str, Any],
                        entries: list[dict[str, Any]],
                        workspace: Path) -> list[dict[str, Any]]:
    contexts = profuzzbench_context_index(workspace)
    grouped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        image = str(entry.get("docker_image", "") or "")
        if not image:
            continue
        target = grouped.setdefault(
            image,
            {
                "image": image,
                "context": "",
                "dockerfile": "",
                "context_found": False,
                "dockerfile_found": False,
                "subjects": set(),
                "variants": set(),
                "protocols": set(),
                "profuzzbench_targets": set(),
            },
        )
        target["subjects"].add(str(entry.get("subject_id", "") or ""))
        target["variants"].add(str(entry.get("variant", "") or ""))
        target["protocols"].add(str(entry.get("protocol", "") or ""))
        target["profuzzbench_targets"].add(str(entry.get("profuzzbench_target", "") or ""))

    for image, target in grouped.items():
        candidates = [image.lower()]
        candidates.extend(str(item).lower() for item in target["profuzzbench_targets"])
        context = next((contexts[key] for key in candidates if key in contexts), None)
        if context is not None:
            if image.endswith("-bizone-aflnet"):
                dockerfile_name = "Dockerfile-bizone-aflnet"
            elif image.endswith("-stateafl"):
                dockerfile_name = "Dockerfile-stateafl"
            else:
                dockerfile_name = "Dockerfile"
            dockerfile = context / dockerfile_name
            target["context"] = str(context)
            target["dockerfile"] = str(dockerfile)
            target["context_found"] = context.is_dir()
            target["dockerfile_found"] = dockerfile.is_file()
        for key in ("subjects", "variants", "protocols", "profuzzbench_targets"):
            target[key] = unique_strings([str(item) for item in target[key] if str(item)])

    return [grouped[key] for key in sorted(grouped)]


def inspect_one_docker_image(docker_bin: str, image: str, daemon_available: bool) -> dict[str, Any]:
    report = inspect_docker_images(
        docker_bin,
        [{"docker_image": image}],
        daemon_available=daemon_available,
    )
    rows = report.get("images", [])
    if isinstance(rows, list) and rows:
        return dict(rows[0])
    return {
        "image": image,
        "present": False,
        "checked": bool(daemon_available),
        "image_id": "",
        "error": "image inspect produced no rows",
    }


def write_image_build_report(out_dir: Path, report: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "image_build_manifest.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def materialize_bizone_aflnet_source(workspace: Path, context: Path) -> dict[str, Any]:
    source = workspace / "aflnet"
    target = context / "bizone-aflnet-src"
    require((source / "Makefile").is_file(), f"local AFLNet source missing Makefile: {source}")
    if target.exists():
        shutil.rmtree(target)
    ignore = shutil.ignore_patterns(
        "*.o",
        "afl-fuzz",
        "afl-gcc",
        "afl-g++",
        "afl-clang",
        "afl-clang++",
        "afl-replay",
        "aflnet-replay",
        "afl-showmap",
        "afl-tmin",
        "afl-gotcpu",
        "afl-analyze",
        "afl-as",
        "as",
        ".test*",
        "test-instr",
        "core",
        "core.*",
    )
    shutil.copytree(source, target, ignore=ignore)
    return {
        "source": str(source),
        "target": str(target),
        "mode": "copied-before-docker-build",
    }


def docker_exec(docker_bin: str,
                container_id: str,
                command: str,
                *,
                capture: bool = False,
                user: str = "",
                timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [docker_bin, "exec"]
    if user:
        cmd.extend(["-u", user])
    cmd.extend([container_id, "/bin/bash", "-lc", command])
    return run_subprocess(cmd, capture=capture, timeout=timeout)


def require_ok(result: subprocess.CompletedProcess[str], context: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{context} failed\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")


def docker_cp(docker_bin: str, local_path: Path, target: str) -> None:
    result = run_subprocess([docker_bin, "cp", str(local_path), target], capture=True)
    if result.returncode != 0:
        raise RuntimeError(f"docker cp failed: {' '.join(result.args)}\nSTDERR:\n{result.stderr}")


def host_shared_library_map(binary: Path) -> dict[str, Path]:
    result = run_subprocess(["ldd", str(binary)], capture=True)
    if result.returncode != 0:
        raise RuntimeError(f"ldd failed for {binary}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    libs: dict[str, Path] = {}
    for line in result.stdout.splitlines():
        match = re.search(r"^\s*(\S+)\s+=>\s+(/\S+)", line)
        if match:
            libs[match.group(1)] = Path(match.group(2)).resolve()
    return libs


def missing_container_libraries(docker_bin: str,
                                container_id: str,
                                binary: str,
                                *,
                                env_prefix: str = "") -> list[str]:
    result = docker_exec(docker_bin, container_id, f"{env_prefix}ldd {binary}", capture=True)
    if result.returncode != 0:
        raise RuntimeError(f"container ldd failed for {binary}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    missing: list[str] = []
    for line in result.stdout.splitlines():
        match = re.search(r"^\s*(\S+)\s+=>\s+not found", line)
        if match:
            missing.append(match.group(1))
    return unique_strings(missing)


def inject_missing_shared_libraries(docker_bin: str,
                                    container_id: str,
                                    local_binary: Path,
                                    container_binary: str) -> str:
    missing = missing_container_libraries(docker_bin, container_id, container_binary)
    if not missing:
        return ""

    host_libs = host_shared_library_map(local_binary)
    lib_dir = "/home/ubuntu/bizone/lib"
    require_ok(
        docker_exec(docker_bin, container_id, f"mkdir -p {lib_dir}", capture=True),
        "prepare injected shared-library directory",
    )
    for lib_name in missing:
        host_path = host_libs.get(lib_name)
        require(host_path is not None and host_path.is_file(), f"missing host shared library for {lib_name}")
        docker_cp(docker_bin, host_path, f"{container_id}:{lib_dir}/{lib_name}")
    remaining = missing_container_libraries(
        docker_bin,
        container_id,
        container_binary,
        env_prefix=f"LD_LIBRARY_PATH={lib_dir}:$LD_LIBRARY_PATH ",
    )
    require(not remaining, f"injected AFLNet binary still has missing shared libraries: {remaining}")
    return f"LD_LIBRARY_PATH={lib_dir}:$LD_LIBRARY_PATH "


def inject_local_aflnet_from_source(docker_bin: str,
                                    container_id: str,
                                    local_aflnet_dir: Path,
                                    *,
                                    make_opt: str = "-j2") -> None:
    require((local_aflnet_dir / "Makefile").is_file(), f"local AFLNet source missing Makefile: {local_aflnet_dir}")
    source_dst = "/tmp/bizone-aflnet-src"
    require_ok(
        docker_exec(docker_bin, container_id, f"rm -rf {source_dst}", capture=True, user="root"),
        "clear previous injected AFLNet source",
    )
    docker_cp(docker_bin, local_aflnet_dir, f"{container_id}:{source_dst}")
    build_cmd = f"cd {source_dst} && make clean >/dev/null 2>&1 || true && make all {make_opt}"
    require_ok(
        docker_exec(docker_bin, container_id, build_cmd, capture=True, user="root"),
        "build injected AFLNet source inside container",
    )
    require_ok(
        docker_exec(
            docker_bin,
            container_id,
            f"cp {source_dst}/afl-fuzz /home/ubuntu/aflnet/afl-fuzz && chmod +x /home/ubuntu/aflnet/afl-fuzz",
            capture=True,
            user="root",
        ),
        "install container-built AFLNet binary",
    )
    remaining = missing_container_libraries(docker_bin, container_id, "/home/ubuntu/aflnet/afl-fuzz")
    require(not remaining, f"container-built AFLNet binary has missing shared libraries: {remaining}")


def container_timeout_diagnostics(docker_bin: str,
                                  container_id: str,
                                  entry: dict[str, Any]) -> str:
    ps = docker_exec(
        docker_bin,
        container_id,
        "ps -eo pid,ppid,stat,etime,cmd | head -80",
        capture=True,
    )
    outdir = docker_exec(
        docker_bin,
        container_id,
        (
            "find /home/ubuntu/experiments -maxdepth 5 "
            f"\\( -name '{entry['out_dir']}' -o -name '{entry['out_dir']}.tar.gz' \\) "
            "-print 2>/dev/null"
        ),
        capture=True,
    )
    return (
        "container watchdog timed out\n"
        f"PS_STDOUT:\n{ps.stdout}\nPS_STDERR:\n{ps.stderr}\n"
        f"OUTPUT_STDOUT:\n{outdir.stdout}\nOUTPUT_STDERR:\n{outdir.stderr}"
    )


def execute_entry(entry: dict[str, Any],
                  results_root: Path,
                  docker_bin: str,
                  local_afl_fuzz: Path,
                  local_monitor_bin: Path,
                  exported_formulas: dict[str, Path],
                  delete_container: bool,
                  dry_run: bool,
                  container_timeout_margin_sec: int) -> None:
    results_dir = results_root / entry["results_dir"]
    results_dir.mkdir(parents=True, exist_ok=True)

    for run_index in range(1, int(entry["runs"]) + 1):
        tar_name = f"{entry['out_dir']}_{run_index}.tar.gz"
        save_path = results_dir / tar_name
        docker_cmd = [docker_bin, "run", "--cpus=1", "-d", "-it", entry["docker_image"], "/bin/bash", "-lc", "sleep infinity"]
        if dry_run:
            print(
                json.dumps(
                    {
                        "action": "run",
                        "variant": entry["variant"],
                        "subject": entry["subject_id"],
                        "run_index": run_index,
                        "docker_run": docker_cmd,
                        "save_to": str(save_path),
                    },
                    ensure_ascii=False,
                )
            )
            continue

        launched = run_subprocess(docker_cmd, capture=True)
        if launched.returncode != 0:
            raise RuntimeError(f"docker run failed:\nSTDERR:\n{launched.stderr}")
        container_id = launched.stdout.strip()[:12]
        run_completed = False

        try:
            env_prefix = ""
            if entry["inject_local_aflnet"]:
                inject_local_aflnet_from_source(
                    docker_bin,
                    container_id,
                    local_afl_fuzz.parent,
                )

            if entry["monitor_enabled"]:
                require(local_monitor_bin.is_file(), f"monitor binary not found: {local_monitor_bin}")
                require_ok(
                    docker_exec(
                        docker_bin,
                        container_id,
                        "mkdir -p /home/ubuntu/mightyppl /home/ubuntu/experiments/bizone/formulas",
                        capture=True,
                    ),
                    "prepare monitor directories",
                )
                docker_cp(docker_bin, local_monitor_bin, f"{container_id}:/home/ubuntu/mightyppl/mitppl-monitor")
                require_ok(
                    docker_exec(docker_bin, container_id, "chmod +x /home/ubuntu/mightyppl/mitppl-monitor", capture=True),
                    "chmod injected monitor binary",
                )
                formula_path = exported_formulas[entry["property_id"]]
                docker_cp(docker_bin, formula_path, f"{container_id}:{entry['container_formula_path']}")
                env_prefix = (
                    f"AFLNET_MONITOR_BIN=/home/ubuntu/mightyppl/mitppl-monitor "
                    f"AFLNET_CAMPAIGN={entry['campaign']} "
                    f"AFLNET_SUBJECT={entry['subject_id']} "
                    f"AFLNET_FUZZER_NAME={entry['fuzzer']} "
                )

            command = (
                f"cd /home/ubuntu/experiments && "
                f"{env_prefix}run {entry['fuzzer']} {entry['out_dir']} "
                f"'{entry['options']}' {entry['fuzz_timeout_sec']} {entry['skipcount']}"
            )
            watchdog_timeout = max(1, int(entry["fuzz_timeout_sec"]) + int(container_timeout_margin_sec))
            try:
                executed = docker_exec(docker_bin, container_id, command, capture=True, timeout=watchdog_timeout)
            except subprocess.TimeoutExpired as exc:
                diagnostics = container_timeout_diagnostics(docker_bin, container_id, entry)
                raise RuntimeError(
                    f"container run timed out for {entry['subject_id']}/{entry['variant']} #{run_index} "
                    f"after {watchdog_timeout}s\n{diagnostics}"
                ) from exc
            if executed.returncode != 0:
                raise RuntimeError(
                    f"container run failed for {entry['subject_id']}/{entry['variant']} #{run_index}\n"
                    f"STDOUT:\n{executed.stdout}\nSTDERR:\n{executed.stderr}"
                )
            run_completed = True
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"failed during container execution for {entry['subject_id']}/{entry['variant']} #{run_index}: {exc}"
            ) from exc
        finally:
            if not dry_run and run_completed:
                copied = run_subprocess(
                    [docker_bin, "cp", f"{container_id}:/home/ubuntu/experiments/{entry['out_dir']}.tar.gz", str(save_path)],
                    capture=True,
                )
                if copied.returncode != 0 and save_path.exists():
                    pass
                elif copied.returncode != 0:
                    raise RuntimeError(
                        f"failed to collect result tarball from {container_id}\nSTDERR:\n{copied.stderr}"
                    )
            if not dry_run and delete_container:
                run_subprocess([docker_bin, "rm", "-f", container_id], capture=True)


def normalize_cov_rows(input_handle: Any,
                       *,
                       campaign: str,
                       subject: str,
                       fuzzer: str,
                       variant: str,
                       run_id: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.TextIOWrapper(input_handle, encoding="utf-8"))
    rows = list(reader)
    if not rows:
        return []

    def numeric(name: str, row: dict[str, str]) -> float:
        value = row.get(name, "") or "0"
        return float(value)

    base_time = numeric("time", rows[0]) if "time" in rows[0] else 0.0
    output: list[dict[str, Any]] = []
    for row in rows:
        time_value = numeric("time", row) if "time" in row else 0.0
        elapsed_sec = max(0.0, time_value - base_time)
        line_abs = int(float(row.get("l_abs", row.get("lines", "0")) or "0"))
        branch_abs = int(float(row.get("b_abs", row.get("branches", "0")) or "0"))
        output.append(
            {
                "schema_version": "rvem.raw.v1",
                "event_type": "campaign_snapshot",
                "campaign": campaign,
                "subject": subject,
                "fuzzer": fuzzer,
                "variant": variant,
                "run_id": run_id,
                "elapsed_sec": elapsed_sec,
                "coverage_edges": branch_abs,
                "coverage_blocks": line_abs,
                "coverage_paths": 0,
            }
        )
    return output


def read_jsonl_from_tar(handle: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    text = handle.read().decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def archive_stem(path: Path) -> str:
    name = path.name
    for suffix in (".tar.gz", ".tgz", ".tar"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def artifact_label_from_member(name: str, suffixes: tuple[str, ...]) -> str:
    base = Path(name).name
    for suffix in suffixes:
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def is_saved_seed_feedback_member(name: str) -> bool:
    return "/queue/.state/bizone-feedback/" in name and name.endswith(".jsonl")


def is_current_feedback_member(name: str) -> bool:
    return name.endswith("/queue/.state/bizone-monitor/current.feedback.jsonl")


def is_replay_feedback_member(name: str) -> bool:
    return bool(re.search(r"/queue/\.state/bizone-monitor/pass\d+\.feedback\.jsonl$", name))


def is_exec_feedback_member(name: str) -> bool:
    return bool(re.search(r"/queue/\.state/bizone-monitor/exec\d+\.feedback\.jsonl$", name))


def is_timing_member(name: str) -> bool:
    return (
        ("/queue/.state/bizone-feedback/" in name and name.endswith(".timing.txt"))
        or name.endswith("/queue/.state/bizone-monitor/current.timing.txt")
        or bool(re.search(r"/queue/\.state/bizone-monitor/pass\d+\.timing\.txt$", name))
        or bool(re.search(r"/queue/\.state/bizone-monitor/exec\d+\.timing\.txt$", name))
    )


def classify_timing_member(name: str) -> tuple[str, str, int]:
    label = artifact_label_from_member(name, (".timing.txt",))
    if "/queue/.state/bizone-feedback/" in name:
        match = re.search(r"id:(\d+)", label)
        return ("saved-seed", label, int(match.group(1)) if match else 0)
    if label == "current":
        return ("current-monitor", label, 0)
    match = re.fullmatch(r"pass(\d+)", label)
    if match:
        return ("replay-pass", label, int(match.group(1)))
    match = re.fullmatch(r"exec(\d+)", label)
    if match:
        return ("exec-history", label, int(match.group(1)))
    return ("unknown", label, 0)


def numeric_or_text(value: str) -> int | str:
    stripped = value.strip()
    if stripped and re.fullmatch(r"-?\d+", stripped):
        return int(stripped)
    return stripped


def parse_timing_plan_text(text: str) -> dict[str, Any]:
    scalar_fields: dict[str, Any] = {}
    pre_send_delay_ms: dict[int, int] = {}
    injected_fields: dict[int, dict[str, Any]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        match = re.fullmatch(r"([A-Za-z0-9_]+)\[(\d+)\]", key)
        if not match:
            scalar_fields[key] = numeric_or_text(value)
            continue

        field_name = match.group(1)
        index = int(match.group(2))
        parsed_value = numeric_or_text(value)
        if field_name == "pre_send_delay_ms":
            pre_send_delay_ms[index] = int(parsed_value)
            continue

        if field_name.startswith("injected_"):
            entry = injected_fields.setdefault(index, {})
            entry[field_name[len("injected_"):]] = parsed_value

    plan = dict(scalar_fields)
    message_count = int(plan.get("message_count", 0) or 0)
    if pre_send_delay_ms:
        width = max(message_count, max(pre_send_delay_ms) + 1)
        plan["pre_send_delay_ms"] = [pre_send_delay_ms.get(index, 0) for index in range(width)]
    else:
        plan["pre_send_delay_ms"] = []

    injected_plan: list[dict[str, Any]] = []
    for index in sorted(injected_fields):
        payload = injected_fields[index]
        injected_plan.append(
            {
                "index": index,
                "kind": str(payload.get("kind", "")),
                "base_message_count": int(payload.get("base_message_count", 0) or 0),
                "source_index": int(payload.get("source_index", 0) or 0),
                "after_index": int(payload.get("after_index", 0) or 0),
                "slot_index": int(payload.get("slot_index", 0) or 0),
            }
        )
    plan["injected_plan"] = injected_plan
    return plan


def feedback_metadata(payloads: list[dict[str, Any]], default_property_id: str) -> dict[str, Any]:
    if not payloads:
        return {"elapsed_sec": 0.0, "property_id": default_property_id, "monitor_exec_id": ""}

    last = payloads[-1]
    try:
        elapsed_sec = float(last.get("elapsed_sec", 0.0) or 0.0)
    except (TypeError, ValueError):
        elapsed_sec = 0.0
    return {
        "elapsed_sec": max(0.0, elapsed_sec),
        "property_id": str(last.get("property_id", "") or default_property_id),
        "monitor_exec_id": str(last.get("run_id", "") or ""),
    }


def collect_from_tar(entry: dict[str, Any], tar_path: Path, raw_out: Path) -> int:
    run_index_text = archive_stem(tar_path).rsplit("_", 1)[-1]
    run_id = f"{entry['variant']}-rep-{run_index_text}"
    records: list[dict[str, Any]] = []
    monitor_records = 0

    with tarfile.open(tar_path, "r:*") as archive:
        members = archive.getmembers()
        coverage_member = next((m for m in members if m.name.endswith("/cov_over_time.csv")), None)
        if coverage_member:
            handle = archive.extractfile(coverage_member)
            if handle:
                records.extend(
                    normalize_cov_rows(
                        handle,
                        campaign=entry["campaign"],
                        subject=entry["subject_id"],
                        fuzzer=entry["fuzzer"],
                        variant=entry["variant"],
                        run_id=run_id,
                    )
                )

        saved_seed_feedback = [member for member in members if is_saved_seed_feedback_member(member.name)]
        current_feedback = [member for member in members if is_current_feedback_member(member.name)]
        replay_feedback = [member for member in members if is_replay_feedback_member(member.name)]
        exec_feedback = [member for member in members if is_exec_feedback_member(member.name)]
        preferred = saved_seed_feedback or current_feedback or replay_feedback or exec_feedback

        feedback_index: dict[str, dict[str, Any]] = {}
        all_feedback_members = [*saved_seed_feedback, *current_feedback, *replay_feedback, *exec_feedback]
        for member in all_feedback_members:
            handle = archive.extractfile(member)
            if not handle:
                continue
            payloads = read_jsonl_from_tar(handle)
            label = artifact_label_from_member(member.name, (".feedback.jsonl", ".jsonl"))
            feedback_index[label] = feedback_metadata(payloads, str(entry.get("property_id", "")))
            if member not in preferred:
                continue
            for payload in payloads:
                original_run_id = str(payload.get("run_id", ""))
                if original_run_id:
                    payload["monitor_exec_id"] = original_run_id
                payload["campaign"] = entry["campaign"]
                payload["subject"] = entry["subject_id"]
                payload["fuzzer"] = entry["fuzzer"]
                payload["variant"] = entry["variant"]
                payload["mode"] = entry["variant"]
                payload["run_id"] = run_id
                if not payload.get("property_id"):
                    payload["property_id"] = entry.get("property_id", "")
            records.extend(payloads)
            monitor_records += len(payloads)

        for member in members:
            if not is_timing_member(member.name):
                continue
            handle = archive.extractfile(member)
            if not handle:
                continue
            scope, label, order = classify_timing_member(member.name)
            plan = parse_timing_plan_text(handle.read().decode("utf-8", errors="replace"))
            meta = feedback_index.get(label, {})
            timing_record = {
                "schema_version": "rvem.raw.v1",
                "event_type": "timing_audit",
                "campaign": entry["campaign"],
                "subject": entry["subject_id"],
                "fuzzer": entry["fuzzer"],
                "variant": entry["variant"],
                "mode": entry["variant"],
                "run_id": run_id,
                "elapsed_sec": float(meta.get("elapsed_sec", 0.0) or 0.0),
                "property_id": str(meta.get("property_id", "") or entry.get("property_id", "")),
                "artifact_scope": scope,
                "artifact_label": label,
                "artifact_order": order,
                "timing_plan": plan,
            }
            monitor_exec_id = str(meta.get("monitor_exec_id", "") or "")
            if monitor_exec_id:
                timing_record["monitor_exec_id"] = monitor_exec_id
            records.append(timing_record)

    raw_out.parent.mkdir(parents=True, exist_ok=True)
    with raw_out.open("w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return monitor_records


def expected_result_tarball(entry: dict[str, Any], results_root: Path, run_index: int) -> Path:
    return results_root / str(entry["results_dir"]) / f"{entry['out_dir']}_{run_index}.tar.gz"


def inspect_result_tarball(entry: dict[str, Any], tar_path: Path, run_index: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        "campaign": entry.get("campaign", ""),
        "stage_id": entry.get("stage_id", ""),
        "subject_id": entry.get("subject_id", ""),
        "protocol": entry.get("protocol", ""),
        "variant": entry.get("variant", ""),
        "fuzzer": entry.get("fuzzer", ""),
        "run_index": run_index,
        "monitor_enabled": int(bool(entry.get("monitor_enabled"))),
        "property_id": entry.get("property_id", ""),
        "results_dir": entry.get("results_dir", ""),
        "out_dir": entry.get("out_dir", ""),
        "tarball_path": str(tar_path),
        "tarball_exists": int(tar_path.is_file()),
        "tarball_valid": 0,
        "tarball_size_bytes": tar_path.stat().st_size if tar_path.is_file() else 0,
        "coverage_member_count": 0,
        "saved_seed_feedback_count": 0,
        "current_feedback_count": 0,
        "replay_feedback_count": 0,
        "exec_feedback_count": 0,
        "feedback_member_count": 0,
        "timing_member_count": 0,
        "has_coverage": 0,
        "has_feedback": 0,
        "has_timing": 0,
        "member_count": 0,
        "error": "",
    }
    if not tar_path.is_file():
        row["error"] = "missing tarball"
        return row

    try:
        with tarfile.open(tar_path, "r:*") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
    except (tarfile.TarError, OSError) as exc:
        row["error"] = f"invalid tarball: {exc}"
        return row

    saved_seed_feedback = [name for name in names if is_saved_seed_feedback_member(name)]
    current_feedback = [name for name in names if is_current_feedback_member(name)]
    replay_feedback = [name for name in names if is_replay_feedback_member(name)]
    exec_feedback = [name for name in names if is_exec_feedback_member(name)]
    timing_members = [name for name in names if is_timing_member(name)]
    coverage_members = [name for name in names if name.endswith("/cov_over_time.csv")]

    row.update(
        {
            "tarball_valid": 1,
            "member_count": len(names),
            "coverage_member_count": len(coverage_members),
            "saved_seed_feedback_count": len(saved_seed_feedback),
            "current_feedback_count": len(current_feedback),
            "replay_feedback_count": len(replay_feedback),
            "exec_feedback_count": len(exec_feedback),
            "feedback_member_count": len(saved_seed_feedback) + len(current_feedback) + len(replay_feedback) + len(exec_feedback),
            "timing_member_count": len(timing_members),
            "has_coverage": int(bool(coverage_members)),
            "has_feedback": int(bool(saved_seed_feedback or current_feedback or replay_feedback or exec_feedback)),
            "has_timing": int(bool(timing_members)),
        }
    )
    return row


def build_result_audit(manifest: dict[str, Any],
                       results_root: Path,
                       selected_entries: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for entry in selected_entries:
        for run_index in range(1, int(entry.get("runs", 0) or 0) + 1):
            tar_path = expected_result_tarball(entry, results_root, run_index)
            rows.append(inspect_result_tarball(entry, tar_path, run_index))

    expected_runs = len(rows)
    completed_runs = sum(1 for row in rows if int(row["tarball_exists"]) and int(row["tarball_valid"]))
    missing_runs = sum(1 for row in rows if not int(row["tarball_exists"]))
    invalid_tarballs = sum(1 for row in rows if int(row["tarball_exists"]) and not int(row["tarball_valid"]))
    coverage_present_runs = sum(1 for row in rows if int(row["tarball_valid"]) and int(row["has_coverage"]))
    coverage_missing_runs = sum(1 for row in rows if int(row["tarball_valid"]) and not int(row["has_coverage"]))
    coverage_unproven_runs = expected_runs - coverage_present_runs
    monitor_rows = [row for row in rows if int(row["monitor_enabled"])]
    monitor_feedback_present_runs = sum(
        1 for row in monitor_rows if int(row["tarball_valid"]) and int(row["has_feedback"])
    )
    monitor_timing_present_runs = sum(
        1 for row in monitor_rows if int(row["tarball_valid"]) and int(row["has_timing"])
    )
    monitor_feedback_missing_runs = sum(
        1 for row in monitor_rows if int(row["tarball_valid"]) and not int(row["has_feedback"])
    )
    monitor_timing_missing_runs = sum(
        1 for row in monitor_rows if int(row["tarball_valid"]) and not int(row["has_timing"])
    )
    monitor_feedback_unproven_runs = len(monitor_rows) - monitor_feedback_present_runs
    monitor_timing_unproven_runs = len(monitor_rows) - monitor_timing_present_runs

    by_subject_variant: list[dict[str, Any]] = []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((str(row["subject_id"]), str(row["variant"])), []).append(row)
    for (subject_id, variant), items in sorted(groups.items()):
        valid_items = [row for row in items if int(row["tarball_exists"]) and int(row["tarball_valid"])]
        by_subject_variant.append(
            {
                "subject_id": subject_id,
                "variant": variant,
                "expected_runs": len(items),
                "completed_runs": len(valid_items),
                "missing_runs": sum(1 for row in items if not int(row["tarball_exists"])),
                "invalid_tarballs": sum(1 for row in items if int(row["tarball_exists"]) and not int(row["tarball_valid"])),
                "coverage_runs": sum(1 for row in valid_items if int(row["has_coverage"])),
                "feedback_runs": sum(1 for row in valid_items if int(row["has_feedback"])),
                "timing_runs": sum(1 for row in valid_items if int(row["has_timing"])),
                "monitor_enabled": int(any(int(row["monitor_enabled"]) for row in items)),
            }
        )

    complete = (
        expected_runs > 0
        and completed_runs == expected_runs
        and invalid_tarballs == 0
        and coverage_missing_runs == 0
        and monitor_feedback_missing_runs == 0
        and monitor_timing_missing_runs == 0
    )
    return {
        "schema_version": RESULT_AUDIT_SCHEMA_VERSION,
        "manifest_campaign": manifest.get("campaign", ""),
        "manifest_stage_id": manifest.get("stage_id", ""),
        "results_root": str(results_root),
        "selected_entry_count": len(selected_entries),
        "expected_runs": expected_runs,
        "completed_runs": completed_runs,
        "missing_runs": missing_runs,
        "invalid_tarballs": invalid_tarballs,
        "coverage_present_runs": coverage_present_runs,
        "coverage_missing_runs": coverage_missing_runs,
        "coverage_unproven_runs": coverage_unproven_runs,
        "monitor_expected_runs": len(monitor_rows),
        "monitor_feedback_present_runs": monitor_feedback_present_runs,
        "monitor_feedback_missing_runs": monitor_feedback_missing_runs,
        "monitor_feedback_unproven_runs": monitor_feedback_unproven_runs,
        "monitor_timing_present_runs": monitor_timing_present_runs,
        "monitor_timing_missing_runs": monitor_timing_missing_runs,
        "monitor_timing_unproven_runs": monitor_timing_unproven_runs,
        "complete": complete,
        "by_subject_variant": by_subject_variant,
        "runs": rows,
    }


RESULT_AUDIT_CSV_FIELDS = [
    "campaign",
    "stage_id",
    "subject_id",
    "protocol",
    "variant",
    "fuzzer",
    "run_index",
    "monitor_enabled",
    "property_id",
    "results_dir",
    "out_dir",
    "tarball_path",
    "tarball_exists",
    "tarball_valid",
    "tarball_size_bytes",
    "coverage_member_count",
    "saved_seed_feedback_count",
    "current_feedback_count",
    "replay_feedback_count",
    "exec_feedback_count",
    "feedback_member_count",
    "timing_member_count",
    "has_coverage",
    "has_feedback",
    "has_timing",
    "member_count",
    "error",
]


def result_audit_gate_problems(audit: dict[str, Any], args: argparse.Namespace) -> list[str]:
    problems: list[str] = []
    expected_runs = int(audit.get("expected_runs", 0) or 0)
    if args.require_complete:
        if expected_runs <= 0:
            problems.append("no expected runs were selected")
        if int(audit.get("missing_runs", 0) or 0):
            problems.append(f"missing result tarballs: {audit['missing_runs']}")
        if int(audit.get("invalid_tarballs", 0) or 0):
            problems.append(f"invalid result tarballs: {audit['invalid_tarballs']}")
    if args.require_coverage:
        if int(audit.get("coverage_unproven_runs", 0) or 0):
            problems.append(f"runs without proven coverage artifacts: {audit['coverage_unproven_runs']}")
    if args.require_monitor_artifacts:
        if int(audit.get("monitor_feedback_unproven_runs", 0) or 0):
            problems.append(
                "monitor-enabled runs without proven feedback artifacts: "
                f"{audit['monitor_feedback_unproven_runs']}"
            )
        if int(audit.get("monitor_timing_unproven_runs", 0) or 0):
            problems.append(
                "monitor-enabled runs without proven timing artifacts: "
                f"{audit['monitor_timing_unproven_runs']}"
            )
    return problems


def command_audit_results(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    selected_entries = select_manifest_entries(manifest, args.subjects, args.variants)
    results_root = Path(args.results_root).resolve()
    audit = build_result_audit(manifest, results_root, selected_entries)
    gate_problems = result_audit_gate_problems(audit, args)
    audit["gate_requirements"] = {
        "require_complete": bool(args.require_complete),
        "require_coverage": bool(args.require_coverage),
        "require_monitor_artifacts": bool(args.require_monitor_artifacts),
    }
    audit["gate_passed"] = not gate_problems
    audit["gate_problems"] = gate_problems

    text = json.dumps(audit, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.csv_out:
        write_csv(Path(args.csv_out), RESULT_AUDIT_CSV_FIELDS, audit["runs"])
    sys.stdout.write(text)

    return 0 if not gate_problems else 1


def command_plan(args: argparse.Namespace) -> int:
    manifest = build_manifest(args)
    write_manifest(manifest, args.out)
    for warning in manifest["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    for exclusion in manifest.get("policy_exclusions", []):
        print(
            "policy-exclusion: "
            f"{exclusion.get('subject_id', '')}/{exclusion.get('variant', '')}: {exclusion.get('reason', '')}",
            file=sys.stderr,
        )
    return 0


def command_preflight(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    selected_entries = select_manifest_entries(manifest, args.subjects, args.variants)
    publication_gate = args.enforce_publication_gate or str(manifest.get("publication_gate", "none") or "none")
    require(publication_gate in VALID_PUBLICATION_GATES, f"unsupported publication gate {publication_gate!r}")

    review_index, bundle_index = property_review_index(str(manifest.get("cards_json", "") or "")) if publication_gate != "none" else ({}, {})
    gate_errors = gate_failures(selected_entries, publication_gate, review_index, bundle_index)

    try:
        assets = resolve_runtime_assets(
            manifest,
            selected_entries,
            afl_fuzz_override=args.afl_fuzz,
            monitor_bin_override=args.monitor_bin,
        )
        asset_error = ""
    except (RuntimeError, ValueError) as exc:
        assets = {
            "need_local_afl": any(bool(entry.get("inject_local_aflnet")) for entry in selected_entries),
            "need_monitor": any(bool(entry.get("monitor_enabled")) for entry in selected_entries),
            "local_afl_fuzz": None,
            "local_monitor_bin": None,
            "local_afl_fuzz_configured": str(args.afl_fuzz or manifest.get("local_afl_fuzz") or "").strip(),
            "local_monitor_bin_configured": str(args.monitor_bin or manifest.get("local_monitor_bin") or "").strip(),
        }
        asset_error = str(exc)

    try:
        with tempfile.TemporaryDirectory(prefix="bizone-profuzzbench-preflight-") as tmp:
            exported = export_required_formulas(manifest, Path(tmp), selected_entries)
        formula_export = {
            "ok": True,
            "error": "",
            "property_ids": sorted(exported),
            "count": len(exported),
        }
    except (RuntimeError, ValueError) as exc:
        formula_export = {
            "ok": False,
            "error": str(exc),
            "property_ids": [],
            "count": 0,
        }

    docker_report = probe_docker_environment(args.docker_bin)
    image_report = inspect_docker_images(
        args.docker_bin,
        selected_entries,
        daemon_available=bool(docker_report["daemon_available"]),
    )

    results_root = Path(args.results_root).resolve()
    try:
        results_root.mkdir(parents=True, exist_ok=True)
        results_root_status = {"path": str(results_root), "writable": True, "error": ""}
    except OSError as exc:
        results_root_status = {"path": str(results_root), "writable": False, "error": str(exc)}

    ready_for_dry_run = (
        not asset_error
        and formula_export["ok"]
        and not gate_errors
        and results_root_status["writable"]
        and docker_report["cli_available"]
    )
    ready_for_real_run = ready_for_dry_run and docker_report["daemon_available"] and image_report["all_present"]

    report = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "manifest": str(Path(args.manifest).resolve()),
        "publication_gate": publication_gate,
        "selected_entry_count": len(selected_entries),
        "selected_subjects": unique_strings([str(entry["subject_id"]) for entry in selected_entries]),
        "selected_variants": unique_strings([str(entry["variant"]) for entry in selected_entries]),
        "monitor_entry_count": sum(1 for entry in selected_entries if entry.get("monitor_enabled")),
        "comparison_entry_count": sum(1 for entry in selected_entries if not entry.get("monitor_enabled")),
        "assets": {
            "need_local_afl": bool(assets["need_local_afl"]),
            "need_monitor": bool(assets["need_monitor"]),
            "local_afl_fuzz": str(assets["local_afl_fuzz"]) if assets["local_afl_fuzz"] else "",
            "local_monitor_bin": str(assets["local_monitor_bin"]) if assets["local_monitor_bin"] else "",
            "configured_afl_fuzz": assets["local_afl_fuzz_configured"],
            "configured_monitor_bin": assets["local_monitor_bin_configured"],
            "error": asset_error,
        },
        "formula_export": formula_export,
        "docker": docker_report,
        "docker_images": image_report,
        "results_root": results_root_status,
        "gate_failures": gate_errors,
        "ready_for_dry_run": ready_for_dry_run,
        "ready_for_real_run": ready_for_real_run,
    }

    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    sys.stdout.write(text)

    if args.require_daemon and not ready_for_real_run:
        return 1
    return 0 if ready_for_dry_run else 1


def command_build_images(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    selected_entries = select_manifest_entries(manifest, args.subjects, args.variants)
    workspace = Path(args.workspace).resolve()
    out_dir = Path(args.out_dir).resolve()
    log_dir = out_dir / "image-build-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    targets = image_build_targets(manifest, selected_entries, workspace)
    docker_report = probe_docker_environment(args.docker_bin)
    report: dict[str, Any] = {
        "schema_version": IMAGE_BUILD_SCHEMA_VERSION,
        "manifest": str(Path(args.manifest).resolve()),
        "workspace": str(workspace),
        "selected_subjects": unique_strings([str(entry["subject_id"]) for entry in selected_entries]),
        "selected_variants": unique_strings([str(entry["variant"]) for entry in selected_entries]),
        "dry_run": bool(args.dry_run),
        "force": bool(args.force),
        "docker": docker_report,
        "build_config": {
            "network": args.network,
            "make_opt": args.make_opt,
            "build_args": list(args.build_arg or []),
            "retries": int(args.retries),
            "retry_delay_sec": float(args.retry_delay_sec),
        },
        "targets": [],
        "summary": {},
    }

    if not docker_report["cli_available"] and not args.dry_run:
        report["summary"] = {
            "target_count": len(targets),
            "context_missing_count": 0,
            "build_attempted_count": 0,
            "final_present_count": 0,
            "failed_count": len(targets),
            "gate_passed": False,
            "error": f"docker CLI unavailable: {docker_report['cli_error'] or args.docker_bin}",
        }
        write_image_build_report(out_dir, report)
        return 1

    if not docker_report["daemon_available"] and not args.dry_run:
        report["summary"] = {
            "target_count": len(targets),
            "context_missing_count": 0,
            "build_attempted_count": 0,
            "final_present_count": 0,
            "failed_count": len(targets),
            "gate_passed": False,
            "error": f"docker daemon unavailable: {docker_report['daemon_error']}",
        }
        write_image_build_report(out_dir, report)
        return 1

    for target in targets:
        image = str(target["image"])
        row = dict(target)
        row.update(
            {
                "present_before": False,
                "present_after": False,
                "image_id_before": "",
                "image_id_after": "",
                "build_attempted": False,
                "build_skipped_reason": "",
                "attempts": [],
                "materialized_sources": [],
                "final_error": "",
            }
        )

        if not row["context_found"]:
            row["final_error"] = f"no Dockerfile context found for image {image!r}"
            report["targets"].append(row)
            write_image_build_report(out_dir, report)
            continue
        if not row["dockerfile_found"]:
            row["final_error"] = f"Dockerfile not found for image {image!r}: {row['dockerfile']}"
            report["targets"].append(row)
            write_image_build_report(out_dir, report)
            continue
        if image.endswith("-bizone-aflnet"):
            row["materialized_sources"].append(
                materialize_bizone_aflnet_source(workspace, Path(str(row["context"])))
            )

        before = inspect_one_docker_image(args.docker_bin, image, bool(docker_report["daemon_available"]))
        row["present_before"] = bool(before.get("present", False))
        row["image_id_before"] = str(before.get("image_id", "") or "")
        if args.dry_run:
            row["build_skipped_reason"] = "dry-run"
            row["present_after"] = row["present_before"]
            row["image_id_after"] = row["image_id_before"]
            report["targets"].append(row)
            write_image_build_report(out_dir, report)
            continue
        if row["present_before"] and not args.force:
            row["build_skipped_reason"] = "already-present"
            row["present_after"] = True
            row["image_id_after"] = row["image_id_before"]
            report["targets"].append(row)
            write_image_build_report(out_dir, report)
            continue

        row["build_attempted"] = True
        for attempt_index in range(1, max(1, int(args.retries)) + 1):
            log_path = log_dir / f"{sanitize_variant(image)}.attempt{attempt_index}.log"
            context_path = Path(str(row["context"]))
            dockerfile_path = Path(str(row["dockerfile"]))
            cmd = [args.docker_bin, "build", "."]
            if args.network:
                cmd.extend(["--network", args.network])
            if dockerfile_path.name != "Dockerfile":
                cmd.extend(["-f", dockerfile_path.name])
            cmd.extend(["-t", image])
            if args.make_opt:
                cmd.extend(["--build-arg", f"MAKE_OPT={args.make_opt}"])
            for build_arg in args.build_arg or []:
                cmd.extend(["--build-arg", build_arg])
            result = run_subprocess(cmd, cwd=context_path, capture=True)
            log_path.write_text(
                "$ " + " ".join(cmd) + "\n\n"
                "## STDOUT\n"
                + (result.stdout or "")
                + "\n## STDERR\n"
                + (result.stderr or ""),
                encoding="utf-8",
            )
            row["attempts"].append(
                {
                    "attempt": attempt_index,
                    "command": cmd,
                    "returncode": result.returncode,
                    "log": str(log_path),
                }
            )
            if result.returncode == 0:
                break
            if attempt_index < int(args.retries) and float(args.retry_delay_sec) > 0:
                time.sleep(float(args.retry_delay_sec))

        after = inspect_one_docker_image(args.docker_bin, image, bool(docker_report["daemon_available"]))
        row["present_after"] = bool(after.get("present", False))
        row["image_id_after"] = str(after.get("image_id", "") or "")
        if not row["present_after"]:
            last_attempt = row["attempts"][-1] if row["attempts"] else {}
            row["final_error"] = (
                f"image {image!r} is still unavailable after build attempts; "
                f"last_returncode={last_attempt.get('returncode', 'n/a')}"
            )
        report["targets"].append(row)
        write_image_build_report(out_dir, report)

    context_missing_count = sum(1 for row in report["targets"] if not bool(row.get("context_found", False)))
    dockerfile_missing_count = sum(
        1
        for row in report["targets"]
        if bool(row.get("context_found", False)) and not bool(row.get("dockerfile_found", False))
    )
    build_attempted_count = sum(1 for row in report["targets"] if bool(row.get("build_attempted", False)))
    final_present_count = sum(1 for row in report["targets"] if bool(row.get("present_after", False)))
    failed_count = sum(1 for row in report["targets"] if not bool(row.get("present_after", False)))
    gate_passed = (
        len(report["targets"]) > 0
        and context_missing_count == 0
        and dockerfile_missing_count == 0
        and (args.dry_run or failed_count == 0)
    )
    report["summary"] = {
        "target_count": len(report["targets"]),
        "context_missing_count": context_missing_count,
        "dockerfile_missing_count": dockerfile_missing_count,
        "build_attempted_count": build_attempted_count,
        "final_present_count": final_present_count,
        "failed_count": failed_count,
        "gate_passed": gate_passed,
        "error": "" if gate_passed else "one or more Docker images are unavailable",
    }
    write_image_build_report(out_dir, report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if gate_passed else 1


def command_run(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    publication_gate = args.enforce_publication_gate or str(manifest.get("publication_gate", "none") or "none")
    require(publication_gate in VALID_PUBLICATION_GATES, f"unsupported publication gate {publication_gate!r}")
    selected_entries = select_manifest_entries(manifest, args.subjects, args.variants)
    assets = resolve_runtime_assets(
        manifest,
        selected_entries,
        afl_fuzz_override=args.afl_fuzz,
        monitor_bin_override=args.monitor_bin,
    )
    results_root = Path(args.results_root).resolve()
    review_index, bundle_index = property_review_index(str(manifest.get("cards_json", "") or "")) if publication_gate != "none" else ({}, {})
    docker_report = probe_docker_environment(args.docker_bin)
    require(docker_report["cli_available"], f"docker CLI unavailable: {docker_report['cli_error'] or args.docker_bin}")
    image_report = inspect_docker_images(
        args.docker_bin,
        selected_entries,
        daemon_available=bool(docker_report["daemon_available"]),
    )
    if args.dry_run and not docker_report["daemon_available"]:
        print(
            "warning: docker daemon unavailable; dry-run validated host assets and manifest semantics only",
            file=sys.stderr,
        )
    if not args.dry_run:
        require(docker_report["daemon_available"], f"docker daemon unavailable: {docker_report['daemon_error']}")
        require_docker_images_available(image_report)

    with tempfile.TemporaryDirectory(prefix="bizone-profuzzbench-formulas-") as tmp:
        exported_formulas = export_required_formulas(manifest, Path(tmp), selected_entries)
        for entry in selected_entries:
            if publication_gate != "none" and entry.get("monitor_enabled"):
                state = property_gate_state(str(entry.get("property_id", "") or ""), review_index, bundle_index)
                require(
                    gate_ready(state, publication_gate),
                    f"refusing to run {entry['subject_id']}/{entry['variant']}: property "
                    f"{entry.get('property_id', '')!r} is not {publication_gate}-ready: "
                    f"{join_blockers(gate_blockers(state, publication_gate))}",
                )
            execute_entry(
                entry,
                results_root,
                args.docker_bin,
                assets["local_afl_fuzz"],
                assets["local_monitor_bin"],
                exported_formulas,
                args.delete_containers,
                args.dry_run,
                args.container_timeout_margin_sec,
            )
    return 0


def command_collect_rvem(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == SCHEMA_VERSION, "unsupported manifest schema")
    results_root = Path(args.results_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    combined_paths: list[Path] = []
    missing: list[str] = []

    selected_subjects = set(split_csv(args.subjects)) if args.subjects else set()
    selected_variants = set(split_csv(args.variants)) if args.variants else set()

    for entry in manifest["entries"]:
        if selected_subjects and entry["subject_id"] not in selected_subjects:
            continue
        if selected_variants and entry["variant"] not in selected_variants:
            continue

        results_dir = results_root / entry["results_dir"]
        for run_index in range(1, int(entry["runs"]) + 1):
            tar_path = results_dir / f"{entry['out_dir']}_{run_index}.tar.gz"
            if not tar_path.is_file():
                missing.append(str(tar_path))
                continue
            raw_path = raw_dir / f"{entry['subject_id']}.{sanitize_variant(entry['variant'])}.rep{run_index}.jsonl"
            collect_from_tar(entry, tar_path, raw_path)
            combined_paths.append(raw_path)

    if args.require_complete and missing:
        raise RuntimeError("missing result tarballs:\n" + "\n".join(missing))
    require(combined_paths, "no RVEM raw fragments were collected")

    combined_path = out_dir / "campaign.raw.jsonl"
    with combined_path.open("w", encoding="utf-8") as output:
        for path in combined_paths:
            output.write(path.read_text(encoding="utf-8"))

    workspace = Path(args.workspace).resolve()
    rvem_tool = Path(args.rvem_tool).resolve()
    validate = run_subprocess([sys.executable, str(rvem_tool), "validate", str(combined_path)], cwd=workspace, capture=True)
    if validate.returncode != 0:
        raise RuntimeError(f"rvem validate failed:\nSTDOUT:\n{validate.stdout}\nSTDERR:\n{validate.stderr}")

    table_dir = out_dir / "tables"
    aggregate = run_subprocess(
        [sys.executable, str(rvem_tool), "aggregate", str(combined_path), "--out-dir", str(table_dir)],
        cwd=workspace,
        capture=True,
    )
    if aggregate.returncode != 0:
        raise RuntimeError(f"rvem aggregate failed:\nSTDOUT:\n{aggregate.stdout}\nSTDERR:\n{aggregate.stderr}")

    plot_dir = out_dir / "plots"
    plot = run_subprocess(
        [sys.executable, str(rvem_tool), "plot", "--table-dir", str(table_dir), "--out-dir", str(plot_dir)],
        cwd=workspace,
        capture=True,
    )
    if plot.returncode != 0:
        raise RuntimeError(f"rvem plot failed:\nSTDOUT:\n{plot.stdout}\nSTDERR:\n{plot.stderr}")

    dashboard_path = out_dir / "dashboard.html"
    dashboard = run_subprocess(
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
        capture=True,
    )
    if dashboard.returncode != 0:
        raise RuntimeError(f"rvem dashboard failed:\nSTDOUT:\n{dashboard.stdout}\nSTDERR:\n{dashboard.stderr}")

    report_dir = out_dir / "reports"
    report = run_subprocess(
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
        capture=True,
    )
    if report.returncode != 0:
        raise RuntimeError(f"rvem report failed:\nSTDOUT:\n{report.stdout}\nSTDERR:\n{report.stderr}")

    if missing:
        print("warning: missing tarballs were skipped", file=sys.stderr)
        for item in missing:
            print(f"warning: {item}", file=sys.stderr)

    print(f"collected {len(combined_paths)} RVEM raw fragment(s) to {combined_path}")
    print(f"wrote tables to {table_dir}")
    print(f"wrote plots to {plot_dir}")
    print(f"wrote dashboard to {dashboard_path}")
    print(f"wrote reports to {report_dir}")
    return 0


def short_tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_finalize_stage(finalize_manifest: dict[str, Any],
                       manifest_path: Path,
                       name: str,
                       cmd: list[str],
                       *,
                       cwd: Path,
                       final_manifest_path: Path) -> subprocess.CompletedProcess[str]:
    result = run_subprocess(cmd, cwd=cwd, capture=True)
    stage = {
        "name": name,
        "command": cmd,
        "returncode": result.returncode,
        "stdout_tail": short_tail(result.stdout or ""),
        "stderr_tail": short_tail(result.stderr or ""),
        "passed": result.returncode == 0,
    }
    finalize_manifest.setdefault("stages", []).append(stage)
    if result.returncode != 0:
        finalize_manifest["gate_passed"] = False
        finalize_manifest["failed_stage"] = name
        final_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        final_manifest_path.write_text(
            json.dumps(finalize_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        raise RuntimeError(
            f"finalize-artifacts stage {name!r} failed with exit code {result.returncode}; "
            f"see {final_manifest_path}"
        )
    return result


def command_finalize_artifacts(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    selected_entries = select_manifest_entries(manifest, args.subjects, args.variants)
    require(selected_entries, "no manifest entries selected for finalization")

    workspace = Path(args.workspace).resolve()
    rvem_tool = Path(args.rvem_tool).resolve()
    results_root = Path(args.results_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    audit_dir = out_dir / "audits"
    rvem_dir = out_dir / "rvem"
    package_dir = out_dir / "artifact-package"
    final_manifest_path = out_dir / "finalization_manifest.json"
    result_audit_path = audit_dir / "result_audit.json"
    result_audit_csv = audit_dir / "result_audit_runs.csv"
    rvem_audit_path = audit_dir / "rvem_artifact_audit.json"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)

    finalize_manifest: dict[str, Any] = {
        "schema_version": FINALIZE_SCHEMA_VERSION,
        "gate_passed": False,
        "failed_stage": "",
        "manifest": str(manifest_path),
        "results_root": str(results_root),
        "out_dir": str(out_dir),
        "selected_entry_count": len(selected_entries),
        "selected_subjects": unique_strings([str(entry["subject_id"]) for entry in selected_entries]),
        "selected_variants": unique_strings([str(entry["variant"]) for entry in selected_entries]),
        "strict_requirements": {
            "result_tarballs_complete": True,
            "coverage_artifacts_present": True,
            "monitor_feedback_and_timing_present": True,
            "rvem_artifacts_complete": True,
            "rvem_evidence_tables_nonempty": True,
            "artifact_package_complete": True,
        },
        "outputs": {
            "result_audit_json": str(result_audit_path),
            "result_audit_csv": str(result_audit_csv),
            "rvem_dir": str(rvem_dir),
            "rvem_artifact_audit_json": str(rvem_audit_path),
            "artifact_package_dir": str(package_dir),
            "finalization_manifest": str(final_manifest_path),
        },
        "stages": [],
    }

    selector_args: list[str] = []
    if args.subjects:
        selector_args.extend(["--subjects", args.subjects])
    if args.variants:
        selector_args.extend(["--variants", args.variants])

    self_tool = Path(__file__).resolve()
    run_finalize_stage(
        finalize_manifest,
        manifest_path,
        "audit-results",
        [
            sys.executable,
            str(self_tool),
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
            *selector_args,
        ],
        cwd=workspace,
        final_manifest_path=final_manifest_path,
    )

    run_finalize_stage(
        finalize_manifest,
        manifest_path,
        "collect-rvem",
        [
            sys.executable,
            str(self_tool),
            "collect-rvem",
            str(manifest_path),
            "--results-root",
            str(results_root),
            "--out-dir",
            str(rvem_dir),
            "--workspace",
            str(workspace),
            "--rvem-tool",
            str(rvem_tool),
            "--require-complete",
            *selector_args,
        ],
        cwd=workspace,
        final_manifest_path=final_manifest_path,
    )

    run_finalize_stage(
        finalize_manifest,
        manifest_path,
        "audit-rvem-artifacts",
        [
            sys.executable,
            str(rvem_tool),
            "audit-artifacts",
            "--table-dir",
            str(rvem_dir / "tables"),
            "--plot-dir",
            str(rvem_dir / "plots"),
            "--report-dir",
            str(rvem_dir / "reports"),
            "--dashboard-html",
            str(rvem_dir / "dashboard.html"),
            "--out",
            str(rvem_audit_path),
            "--require-complete",
            "--require-data",
        ],
        cwd=workspace,
        final_manifest_path=final_manifest_path,
    )

    package_cmd = [
        sys.executable,
        str(rvem_tool),
        "package-artifacts",
        "--out-dir",
        str(package_dir),
        "--table-dir",
        str(rvem_dir / "tables"),
        "--plot-dir",
        str(rvem_dir / "plots"),
        "--report-dir",
        str(rvem_dir / "reports"),
        "--dashboard-html",
        str(rvem_dir / "dashboard.html"),
        "--rvem-audit-json",
        str(rvem_audit_path),
        "--result-audit-json",
        str(result_audit_path),
        "--result-audit-csv",
        str(result_audit_csv),
        "--raw-jsonl",
        str(rvem_dir / "campaign.raw.jsonl"),
        "--manifest",
        str(manifest_path),
        "--note",
        "generated by bizone_profuzzbench.py finalize-artifacts after strict result/RVEM/package gates",
        "--require-core",
        "--require-rvem-audit-complete",
        "--require-result-audit-gate",
        "--require-complete",
    ]
    for review_packet_dir in args.review_packet_dir or []:
        package_cmd.extend(["--review-packet-dir", review_packet_dir])
    for stage_audit_dir in args.stage_audit_dir or []:
        package_cmd.extend(["--stage-audit-dir", stage_audit_dir])
    run_finalize_stage(
        finalize_manifest,
        manifest_path,
        "package-artifacts",
        package_cmd,
        cwd=workspace,
        final_manifest_path=final_manifest_path,
    )

    finalize_manifest["gate_passed"] = True
    final_manifest_path.write_text(
        json.dumps(finalize_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(finalize_manifest, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="ProFuzzBench overlay automation for Bi-ZoneFuzz++.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="build a Bi-ZoneFuzz++ ProFuzzBench campaign manifest")
    plan.add_argument("--catalog", default=str(root / "benchmarks/profuzzbench_campaigns.json"))
    plan.add_argument("--cards-json", default=str(root / "benchmarks/main_study_property_cards_initial.json"))
    plan.add_argument("--stage", choices=["bring-up", "main-study"], required=True)
    plan.add_argument("--campaign", default="")
    plan.add_argument("--subjects", default="")
    plan.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
    plan.add_argument("--property-override", action="append", default=[])
    plan.add_argument("--runs", type=int, default=20)
    plan.add_argument("--fuzz-timeout-sec", type=int, default=24 * 3600)
    plan.add_argument("--skipcount", type=int, default=5)
    plan.add_argument("--test-timeout-ms", type=int, default=5000)
    plan.add_argument("--publication-gate", choices=sorted(VALID_PUBLICATION_GATES), default="none")
    plan.add_argument("--formula-subdir", default="bizone/formulas")
    plan.add_argument("--afl-fuzz", default=str(Path(__file__).resolve().parents[2] / "aflnet/afl-fuzz"))
    plan.add_argument("--monitor-bin", default=str(root / "build/mitppl-monitor"))
    plan.add_argument("--out", default="")
    plan.set_defaults(func=command_plan)

    preflight = subparsers.add_parser(
        "preflight",
        help="validate selected manifest entries, host assets, and Docker readiness without launching containers",
    )
    preflight.add_argument("manifest")
    preflight.add_argument("--results-root", required=True)
    preflight.add_argument("--afl-fuzz", default="")
    preflight.add_argument("--monitor-bin", default="")
    preflight.add_argument("--subjects", default="")
    preflight.add_argument("--variants", default="")
    preflight.add_argument("--enforce-publication-gate", choices=sorted(VALID_PUBLICATION_GATES), default="")
    preflight.add_argument("--docker-bin", default="docker")
    preflight.add_argument("--require-daemon", action="store_true")
    preflight.add_argument("--out", default="")
    preflight.set_defaults(func=command_preflight)

    build_images = subparsers.add_parser(
        "build-images",
        help="resolve and optionally build selected ProFuzzBench Docker images with auditable logs",
    )
    build_images.add_argument("manifest")
    build_images.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    build_images.add_argument("--subjects", default="")
    build_images.add_argument("--variants", default="")
    build_images.add_argument("--docker-bin", default="docker")
    build_images.add_argument("--out-dir", required=True)
    build_images.add_argument("--network", default="host")
    build_images.add_argument("--make-opt", default="-j2")
    build_images.add_argument("--build-arg", action="append", default=[])
    build_images.add_argument("--retries", type=int, default=1)
    build_images.add_argument("--retry-delay-sec", type=float, default=0.0)
    build_images.add_argument("--force", action="store_true")
    build_images.add_argument("--dry-run", action="store_true")
    build_images.set_defaults(func=command_build_images)

    run_cmd = subparsers.add_parser("run", help="run a manifest against ProFuzzBench-style Docker images")
    run_cmd.add_argument("manifest")
    run_cmd.add_argument("--results-root", required=True)
    run_cmd.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    run_cmd.add_argument("--afl-fuzz", default="")
    run_cmd.add_argument("--monitor-bin", default="")
    run_cmd.add_argument("--subjects", default="")
    run_cmd.add_argument("--variants", default="")
    run_cmd.add_argument("--enforce-publication-gate", choices=sorted(VALID_PUBLICATION_GATES), default="")
    run_cmd.add_argument("--docker-bin", default="docker")
    run_cmd.add_argument("--delete-containers", action="store_true")
    run_cmd.add_argument("--dry-run", action="store_true")
    run_cmd.add_argument("--container-timeout-margin-sec", type=int, default=300)
    run_cmd.set_defaults(func=command_run)

    matrix = subparsers.add_parser("matrix", help="materialize a paper-facing experiment matrix and readiness summary from a manifest")
    matrix.add_argument("manifest")
    matrix.add_argument("--out-dir", required=True)
    matrix.set_defaults(func=command_matrix)

    audit_results = subparsers.add_parser(
        "audit-results",
        help="audit ProFuzzBench result tarball completeness before RVEM reconstruction",
    )
    audit_results.add_argument("manifest")
    audit_results.add_argument("--results-root", required=True)
    audit_results.add_argument("--subjects", default="")
    audit_results.add_argument("--variants", default="")
    audit_results.add_argument("--out", default="")
    audit_results.add_argument("--csv-out", default="")
    audit_results.add_argument("--require-complete", action="store_true")
    audit_results.add_argument("--require-coverage", action="store_true")
    audit_results.add_argument("--require-monitor-artifacts", action="store_true")
    audit_results.set_defaults(func=command_audit_results)

    collect = subparsers.add_parser("collect-rvem", help="reconstruct RVEM raw logs/tables/plots from result tarballs")
    collect.add_argument("manifest")
    collect.add_argument("--results-root", required=True)
    collect.add_argument("--out-dir", required=True)
    collect.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    collect.add_argument("--rvem-tool", default=str(root / "scripts/rvem_tools.py"))
    collect.add_argument("--subjects", default="")
    collect.add_argument("--variants", default="")
    collect.add_argument("--require-complete", action="store_true")
    collect.set_defaults(func=command_collect_rvem)

    finalize = subparsers.add_parser(
        "finalize-artifacts",
        help="strictly audit result tarballs, reconstruct RVEM, audit RVEM artifacts, and package evidence",
    )
    finalize.add_argument("manifest")
    finalize.add_argument("--results-root", required=True)
    finalize.add_argument("--out-dir", required=True)
    finalize.add_argument("--workspace", default=str(Path(__file__).resolve().parents[2]))
    finalize.add_argument("--rvem-tool", default=str(root / "scripts/rvem_tools.py"))
    finalize.add_argument("--subjects", default="")
    finalize.add_argument("--variants", default="")
    finalize.add_argument("--review-packet-dir", action="append", default=[], help="optional review packet directory to include in the final package")
    finalize.add_argument("--stage-audit-dir", action="append", default=[], help="optional stage-audit output directory to include in the final package")
    finalize.set_defaults(func=command_finalize_artifacts)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "campaign") and not args.campaign:
        args.campaign = getattr(args, "stage", "bizonefuzz")
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"bizone_profuzzbench.py: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
