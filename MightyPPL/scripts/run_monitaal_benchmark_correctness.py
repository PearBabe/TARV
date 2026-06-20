#!/usr/bin/env python3
"""Run translated MoniTAal benchmark correctness checks against mitppl-monitor."""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


VERDICTS = {"POSITIVE", "NEGATIVE", "INCONCLUSIVE"}


@dataclass
class MonitorRun:
    case_name: str
    formula: str
    input_path: Path
    event_count: int
    returncode: int
    stdout: str
    stderr: str

    @property
    def verdicts(self) -> list[str]:
        return [line.strip() for line in self.stdout.splitlines() if line.strip() in VERDICTS]

    @property
    def final_verdict(self) -> str:
        return self.verdicts[-1] if self.verdicts else "-"

    def first_index(self, verdict: str) -> str:
        for index, value in enumerate(self.verdicts, start=1):
            if value == verdict:
                return str(index)
        return "-"


@dataclass
class TestCase:
    name: str
    formula: str
    events: list[tuple[int, tuple[str, ...]]]
    expected_returncode: int = 0
    expect_final: str | None = None
    expect_no_negative: bool = False
    expect_any_negative: bool = False
    expect_stdout_empty: bool = False
    expect_stderr_contains: str | None = None


@dataclass(frozen=True)
class ResponseProperty:
    name: str
    trigger_original: str
    response_original: str
    trigger: str
    response: str
    deadline: int

    @property
    def formula(self) -> str:
        return f"G({self.trigger} -> F[0,{self.deadline}] {self.response})"

    @property
    def label_map(self) -> dict[str, str]:
        return {
            self.trigger_original: self.trigger,
            self.response_original: self.response,
        }


GEAR_XML_RESPONSE_PROPERTIES = [
    ResponseProperty("closeclutch", "CloseClutch", "ClutchIsClosed", "closeclutch", "clutchisclosed", 150),
    ResponseProperty("openclutch", "OpenClutch", "ClutchIsOpen", "openclutch", "clutchisopen", 150),
    ResponseProperty("reqset", "ReqSet", "GearSet", "reqset", "gearset", 300),
    ResponseProperty("reqneu", "ReqNeu", "GearNeu", "reqneu", "gearneu", 200),
    ResponseProperty("speedset", "SpeedSet", "ReqTorque", "speedset", "reqtorque", 500),
    ResponseProperty("test1", "test1", "ReqTorque", "test1", "reqtorque", 900),
]


def repo_paths() -> tuple[Path, Path]:
    mighty_root = Path(__file__).resolve().parents[1]
    workspace_root = mighty_root.parent
    return workspace_root, mighty_root


def parse_monitaal_event_line(line: str, source: Path, line_number: int) -> tuple[int, str]:
    text = line.strip()
    if not text:
        raise ValueError(f"{source}:{line_number}: empty line")
    if not text.startswith("@"):
        raise ValueError(f"{source}:{line_number}: expected '@'")

    payload = text[1:]
    time_text, _, label = payload.partition(" ")
    if not time_text.isdigit():
        raise ValueError(f"{source}:{line_number}: expected integer timestamp")
    return int(time_text), label.strip()


def normalize_monitaal_events(
    path: Path,
    label_map: dict[str, str] | None = None,
    limit: int | None = None,
) -> list[tuple[int, tuple[str, ...]]]:
    grouped: list[tuple[int, list[str]]] = []
    current_time: int | None = None
    current_labels: list[str] = []

    def flush() -> None:
        nonlocal current_time, current_labels
        if current_time is None:
            return
        grouped.append((current_time, sorted(set(current_labels))))
        current_time = None
        current_labels = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            time, label = parse_monitaal_event_line(line, path, line_number)
            if current_time is not None and time != current_time:
                flush()
                if limit is not None and len(grouped) >= limit:
                    break
            if current_time is None:
                current_time = time

            if label:
                if label_map is None:
                    current_labels.append(label.lower())
                elif label in label_map:
                    current_labels.append(label_map[label])

    if limit is None or len(grouped) < limit:
        flush()
    return grouped[:limit] if limit is not None else grouped


def write_events(path: Path, events: Iterable[tuple[int, tuple[str, ...]]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for time, labels in events:
            count += 1
            label_text = ",".join(labels) if labels else "-"
            handle.write(f"@{time} {label_text}\n")
    return count


def add_or_merge_event(events: list[tuple[int, tuple[str, ...]]], time: int, label: str) -> list[tuple[int, tuple[str, ...]]]:
    merged: dict[int, set[str]] = {event_time: set(labels) for event_time, labels in events}
    merged.setdefault(time, set()).add(label)
    return [(event_time, tuple(sorted(labels))) for event_time, labels in sorted(merged.items())]


def mutate_first_response_deadline(
    events: list[tuple[int, tuple[str, ...]]],
    trigger: str,
    response: str,
    deadline: int,
) -> list[tuple[int, tuple[str, ...]]]:
    request_time = None
    for time, labels in events:
        if trigger in labels:
            request_time = time
            break
    if request_time is None:
        raise RuntimeError(f"benchmark trace did not contain trigger {trigger!r}")

    mutated: list[tuple[int, tuple[str, ...]]] = []
    deadline_time = request_time + deadline
    for time, labels in events:
        label_set = set(labels)
        if request_time <= time <= deadline_time:
            label_set.discard(response)
        mutated.append((time, tuple(sorted(label_set))))

    return add_or_merge_event(mutated, deadline_time + 1, response)


def mutate_first_req_newgear_deadline(events: list[tuple[int, tuple[str, ...]]], deadline: int) -> list[tuple[int, tuple[str, ...]]]:
    return mutate_first_response_deadline(events, "reqnewgear", "newgear", deadline)


def extract_c_string(header: Path, symbol: str) -> str:
    text = header.read_text(encoding="utf-8")
    match = re.search(rf"const char\*\s+{re.escape(symbol)}\s*=\s*(\".*?\");", text, re.DOTALL)
    if not match:
        raise RuntimeError(f"could not find C string {symbol!r} in {header}")
    return ast.literal_eval(match.group(1))


def normalize_monitaal_event_text(
    text: str,
    label_map: dict[str, str],
    source_name: str,
    limit: int | None = None,
) -> list[tuple[int, tuple[str, ...]]]:
    grouped: list[tuple[int, list[str]]] = []
    current_time: int | None = None
    current_labels: list[str] = []
    source = Path(source_name)

    def flush() -> None:
        nonlocal current_time, current_labels
        if current_time is None:
            return
        grouped.append((current_time, sorted(set(current_labels))))
        current_time = None
        current_labels = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        time, label = parse_monitaal_event_line(line, source, line_number)
        if current_time is not None and time != current_time:
            flush()
            if limit is not None and len(grouped) >= limit:
                break
        if current_time is None:
            current_time = time
        if label in label_map:
            current_labels.append(label_map[label])

    if limit is None or len(grouped) < limit:
        flush()
    return grouped[:limit] if limit is not None else grouped


def run_monitor(monitor: Path, workdir: Path, case: TestCase, timeout: int) -> MonitorRun:
    return run_monitor_with_backend(monitor, workdir, case, timeout, "concrete")


def run_monitor_with_backend(
    monitor: Path,
    workdir: Path,
    case: TestCase,
    timeout: int,
    backend: str,
) -> MonitorRun:
    input_path = workdir / f"{case.name}.events.txt"
    event_count = write_events(input_path, case.events)
    result = subprocess.run(
        [
            str(monitor),
            "--formula",
            case.formula,
            "--monitor-backend",
            backend,
            "--input",
            str(input_path),
        ],
        cwd=monitor.parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return MonitorRun(
        case_name=case.name,
        formula=case.formula,
        input_path=input_path,
        event_count=event_count,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def evaluate(case: TestCase, run: MonitorRun) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if run.returncode != case.expected_returncode:
        failures.append(f"expected rc {case.expected_returncode}, got {run.returncode}")
    if case.expect_final is not None and run.final_verdict != case.expect_final:
        failures.append(f"expected final verdict {case.expect_final}, got {run.final_verdict}")
    if case.expect_no_negative and "NEGATIVE" in run.verdicts:
        failures.append(f"expected no NEGATIVE verdict, first at line {run.first_index('NEGATIVE')}")
    if case.expect_any_negative and "NEGATIVE" not in run.verdicts:
        failures.append("expected at least one NEGATIVE verdict")
    if case.expect_stdout_empty and run.stdout:
        failures.append("expected empty stdout")
    if case.expect_stderr_contains and case.expect_stderr_contains not in run.stderr:
        failures.append(f"expected stderr to contain {case.expect_stderr_contains!r}")
    return not failures, failures


def print_result(case: TestCase, run: MonitorRun, ok: bool, failures: list[str]) -> None:
    status = "PASS" if ok else "FAIL"
    print(
        f"{status} {case.name}: formula={case.formula!r} events={run.event_count} "
        f"rc={run.returncode} final={run.final_verdict} "
        f"first_positive={run.first_index('POSITIVE')} first_negative={run.first_index('NEGATIVE')}",
        flush=True,
    )
    if ok:
        return

    print(f"  input: {run.input_path}")
    for failure in failures:
        print(f"  - {failure}", flush=True)
    if run.stdout:
        print("  stdout:", flush=True)
        print("\n".join(f"    {line}" for line in run.stdout.splitlines()[:12]), flush=True)
    if run.stderr:
        print("  stderr:", flush=True)
        print("\n".join(f"    {line}" for line in run.stderr.splitlines()[:12]), flush=True)


def build_cases(gear_input: Path, gear_test_header: Path, gear_limit: int, include_gear_test: bool) -> list[TestCase]:
    limit = None if gear_limit == 0 else gear_limit
    b_freq_events = [(time, ("a",)) for time in range(10)]
    b_freq_events.append((35, ("b",)))

    gear_events = normalize_monitaal_events(gear_input, label_map={"ReqNewGear": "reqnewgear", "NewGear": "newgear"}, limit=limit)
    mutated_gear_events = mutate_first_req_newgear_deadline(gear_events, 1300)

    cases = [
        TestCase(
            name="b_eventually_positive",
            formula="(F[1,infty) b) || (a && (!a))",
            events=b_freq_events,
            expect_final="POSITIVE",
        ),
        TestCase(
            name="b_response_negative",
            formula="G(a -> F[1,20] b)",
            events=b_freq_events,
            expect_any_negative=True,
        ),
        TestCase(
            name="gear_response_nominal",
            formula="G(reqnewgear -> F[0,1300] newgear)",
            events=gear_events,
            expect_no_negative=True,
        ),
        TestCase(
            name="gear_response_mutated_negative",
            formula="G(reqnewgear -> F[0,1300] newgear)",
            events=mutated_gear_events,
            expect_any_negative=True,
        ),
        TestCase(
            name="sat_precheck_unsat_on_benchmark_vocab",
            formula="F[0,0] reqnewgear && G[0,0] (!reqnewgear)",
            events=gear_events[:5],
            expected_returncode=2,
            expect_stdout_empty=True,
            expect_stderr_contains="UNSATISFIABLE",
        ),
    ]

    for prop in GEAR_XML_RESPONSE_PROPERTIES:
        events = normalize_monitaal_events(gear_input, label_map=prop.label_map, limit=limit)
        mutated_events = mutate_first_response_deadline(events, prop.trigger, prop.response, prop.deadline)
        cases.extend(
            [
                TestCase(
                    name=f"gear_xml_{prop.name}_nominal",
                    formula=prop.formula,
                    events=events,
                    expect_no_negative=True,
                ),
                TestCase(
                    name=f"gear_xml_{prop.name}_mutated_negative",
                    formula=prop.formula,
                    events=mutated_events,
                    expect_any_negative=True,
                ),
            ]
        )

    if include_gear_test:
        gear_test_input = extract_c_string(gear_test_header, "gear_controller_test_input")
        gear_test_events = normalize_monitaal_event_text(
            gear_test_input,
            {"ReqNewGear": "reqnewgear", "NewGear": "newgear"},
            str(gear_test_header),
            limit=limit,
        )
        gear_test_formula = "G(reqnewgear -> ((!newgear) U[150,1205] newgear))"
        cases.extend(
            [
                TestCase(
                    name="gear_controller_test_nominal",
                    formula=gear_test_formula,
                    events=gear_test_events,
                    expect_no_negative=True,
                ),
                TestCase(
                    name="gear_controller_test_mutated_negative",
                    formula=gear_test_formula,
                    events=mutate_first_response_deadline(gear_test_events, "reqnewgear", "newgear", 1205),
                    expect_any_negative=True,
                ),
            ]
        )

    return cases


def parse_args() -> argparse.Namespace:
    workspace_root, mighty_root = repo_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=Path, default=mighty_root / "build" / "mitppl-monitor")
    parser.add_argument("--gear-input", type=Path, default=workspace_root / "MoniTAal" / "benchmark" / "gear-control-input.txt")
    parser.add_argument("--gear-test-header", type=Path, default=workspace_root / "MoniTAal" / "benchmark" / "gear_controller_test.h")
    parser.add_argument("--workdir", type=Path, default=mighty_root / "build" / "monitaal-benchmark-correctness")
    parser.add_argument("--gear-limit", type=int, default=0, help="Grouped gear events to use; 0 means the full benchmark trace")
    parser.add_argument("--backend", choices=("concrete", "bdd"), default="concrete")
    parser.add_argument(
        "--include-gear-test",
        action="store_true",
        help="Also run the embedded gear_controller_test.h model translation; this is slower in the current MightyPPL frontend",
    )
    parser.add_argument("--timeout", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    monitor = args.monitor.resolve()
    gear_input = args.gear_input.resolve()
    gear_test_header = args.gear_test_header.resolve()
    workdir = args.workdir.resolve()

    if not monitor.exists():
        print(f"error: mitppl-monitor not found: {monitor}", file=sys.stderr)
        return 2
    if not gear_input.exists():
        print(f"error: MoniTAal gear input not found: {gear_input}", file=sys.stderr)
        return 2
    if not gear_test_header.exists():
        print(f"error: MoniTAal gear controller test header not found: {gear_test_header}", file=sys.stderr)
        return 2
    if args.gear_limit < 0:
        print("error: --gear-limit must be non-negative", file=sys.stderr)
        return 2

    workdir.mkdir(parents=True, exist_ok=True)
    cases = build_cases(gear_input, gear_test_header, args.gear_limit, args.include_gear_test)

    failed = 0
    for case in cases:
        print(f"RUN  {case.name}: formula={case.formula!r} events={len(case.events)}", flush=True)
        run = run_monitor_with_backend(monitor, workdir, case, args.timeout, args.backend)
        ok, failures = evaluate(case, run)
        print_result(case, run, ok, failures)
        failed += 0 if ok else 1

    if failed:
        print(f"\n{failed} case(s) failed. Inputs are preserved under {workdir}")
        return 1

    print(f"\nAll {len(cases)} MoniTAal benchmark correctness cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
