#!/usr/bin/env python3
"""Benchmark MightyPPL runtime verification backends on runtime-only cases."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from run_monitaal_benchmark_correctness import TestCase, build_cases, repo_paths, write_events


@dataclass(frozen=True)
class BenchRun:
    case_name: str
    backend: str
    metrics: dict


def build_synthetic_large_alphabet_cases() -> list[TestCase]:
    cases: list[TestCase] = []
    for pair_count in (2, 3):
        clauses: list[str] = []
        events: list[tuple[int, tuple[str, ...]]] = []
        time = 0
        for index in range(pair_count):
            trigger = f"p{index}"
            response = f"q{index}"
            clauses.append(f"G({trigger} -> F[0,20] {response})")
            events.append((time, (trigger,)))
            events.append((time + 5, ()))
            events.append((time + 10, (response,)))
            time += 25
        cases.append(
            TestCase(
                name=f"synthetic_large_alphabet_{pair_count * 2}",
                formula=" && ".join(clauses),
                events=events,
                expect_no_negative=True,
            )
        )
    return cases


def run_bench(bench_bin: Path, case: TestCase, backend: str, workdir: Path) -> BenchRun:
    input_path = workdir / f"{case.name}.{backend}.events.txt"
    write_events(input_path, case.events)
    completed = subprocess.run(
        [
            str(bench_bin),
            "--case-name",
            case.name,
            "--formula",
            case.formula,
            "--input",
            str(input_path),
            "--monitor-backend",
            backend,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    stdout_lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not stdout_lines:
        raise RuntimeError(
            f"benchmark command produced no JSON output for {case.name}/{backend}\n"
            f"stderr:\n{completed.stderr}"
        )
    metrics = json.loads(stdout_lines[-1])
    return BenchRun(case.name, backend, metrics)


def markdown_report(rows: Iterable[dict]) -> str:
    lines = [
        "| case | backend | compile_setup_ms | accepting_space_precompute_ms | total_replay_ms | avg_per_event_ms | max_per_event_ms | max_active_states | first_decisive_verdict_index | final_verdict | verdict_trace_equivalent |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {case_name} | {backend} | {compile_setup_ms:.6f} | {accepting_space_precompute_ms:.6f} | "
            "{total_replay_ms:.6f} | {avg_per_event_ms:.6f} | {max_per_event_ms:.6f} | {max_active_states} | "
            "{first_decisive_verdict_index} | {final_verdict} | {verdict_trace_equivalent} |".format(**row)
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    workspace_root, mighty_root = repo_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, default=mighty_root / "build" / "mitppl-monitor-bench")
    parser.add_argument("--gear-input", type=Path, default=workspace_root / "MoniTAal" / "benchmark" / "gear-control-input.txt")
    parser.add_argument("--gear-test-header", type=Path, default=workspace_root / "MoniTAal" / "benchmark" / "gear_controller_test.h")
    parser.add_argument("--workdir", type=Path, default=mighty_root / "build" / "native-bdd-runtime-benchmark")
    parser.add_argument("--gear-limit", type=int, default=0)
    parser.add_argument("--include-gear-test", action="store_true")
    args = parser.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)

    cases = [
        case
        for case in build_cases(args.gear_input, args.gear_test_header, args.gear_limit, args.include_gear_test)
        if case.expected_returncode == 0
    ]
    cases.extend(build_synthetic_large_alphabet_cases())

    results: dict[tuple[str, str], BenchRun] = {}
    report_rows: list[dict] = []

    for case in cases:
        concrete = run_bench(args.bench, case, "concrete", args.workdir)
        bdd = run_bench(args.bench, case, "bdd", args.workdir)
        results[(case.name, "concrete")] = concrete
        results[(case.name, "bdd")] = bdd

        equivalent = concrete.metrics["verdict_trace"] == bdd.metrics["verdict_trace"]
        for run in (concrete, bdd):
            row = dict(run.metrics)
            row["verdict_trace_equivalent"] = "yes" if equivalent else "no"
            row["first_decisive_verdict_index"] = (
                row["first_decisive_verdict_index"] if row["first_decisive_verdict_index"] is not None else "-"
            )
            report_rows.append(row)

    out_json = args.workdir / "runtime_benchmark_results.json"
    out_md = args.workdir / "runtime_benchmark_results.md"
    out_json.write_text(json.dumps(report_rows, indent=2), encoding="utf-8")
    out_md.write_text(markdown_report(report_rows), encoding="utf-8")

    failures = [row for row in report_rows if row["verdict_trace_equivalent"] == "no"]
    print(f"Wrote {out_json}")
    print(f"Wrote {out_md}")
    if failures:
        print(f"{len(failures) // 2} case(s) had verdict-trace mismatches between concrete and bdd.")
        return 1

    print(f"All {len(cases)} runtime benchmark cases matched between concrete and bdd.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
