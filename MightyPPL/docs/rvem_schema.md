# RVEM Foundation for Bi-ZoneFuzz++

RVEM, the Runtime Verification Evaluation Metrics layer, records raw fuzzing and
monitoring telemetry as JSONL and aggregates it into analysis tables. The schema
keeps ProFuzzBench-style campaign coordinates (`campaign`, `subject`, `fuzzer`,
`run_id`, `elapsed_sec`) while adding runtime-verification fields for MITL
properties, semantic monitor states, deadline slack, and monitoring overhead.

## Raw JSONL Schema

Each line is a JSON object with `schema_version: "rvem.raw.v1"`.

Common required fields:

| field | type | meaning |
| --- | --- | --- |
| `event_type` | string | one of `run_start`, `campaign_snapshot`, `property_eval`, `semantic_state`, `case_result`, `monitor_overhead`, `ablation_result`, `timing_audit` |
| `campaign` | string | campaign or experiment suite name |
| `subject` | string | target protocol, model, or benchmark subject |
| `fuzzer` | string | fuzzer name, compatible with ProFuzzBench-style reports |
| `variant` | string | Bi-ZoneFuzz++ variant or ablation label |
| `run_id` | string | unique replicate/run identifier |
| `elapsed_sec` | number | seconds since this run started |

Optional common fields include `timestamp`, `seed`, `execs_total`,
`cases_total`, `bugs_total`, `violations_total`, `yield_total`, `execs_per_sec`,
and coverage counters either as top-level fields (`coverage_edges`,
`coverage_blocks`, `coverage_paths`) or nested under `coverage`.

Runtime-verification event fields:

| event type | fields |
| --- | --- |
| `property_eval` | `property_id`, `case_id`, `verdict`, `slack_ms`, `deadline_ms` |
| `semantic_state` | `semantic_state.state_id`, `semantic_state.region`, `semantic_state.monitor_state_count`, `semantic_state.frontier_width`, `verdict` |
| `case_result` | `case_id`, `start_sec`, `end_sec`, `outcome`, `property_id`, `slack_ms` |
| `monitor_overhead` | `monitor_ms`, `target_ms`, `total_ms`, `execs_per_sec`, `yield_total` |
| `ablation_result` | `ablation`, plus final coverage/yield/overhead counters |
| `timing_audit` | top-level `artifact_scope`, `artifact_label`, `artifact_order`, plus nested `timing_plan` reconstructed from AFLNet `*.timing.txt` artifacts |

When logs are produced by `MightyPPL/build/mitppl-monitor --feedback-jsonl`, each
`property_eval`, `semantic_state`, and `case_result` record also keeps:

- `timed_trace_event`
- `feedback_frame`

This preserves the original `TimedTraceEvent + FeedbackFrame` pair required by
Bi-ZoneFuzz++ while still staying compatible with the flat RVEM aggregation
pipeline.

For AFLNet timing-plan reconstruction, the nested `timing_plan` may also carry
planner-facing request-class provenance such as:

- generic preferred classes:
  `stage_preferred_request_class`,
  `queue_preferred_request_class`,
  `feedback_preferred_request_class`
- retry-specific preferred classes:
  `stage_retry_preferred_request_class`,
  `queue_retry_preferred_request_class`,
  `feedback_retry_preferred_request_class`
- keepalive-specific preferred classes:
  `stage_keepalive_preferred_request_class`,
  `queue_keepalive_preferred_request_class`,
  `feedback_keepalive_preferred_request_class`
- mutation explainability anchors:
  `retry_source_request_class`,
  `keepalive_anchor_request_class`,
  `feedback_request_class`,
  `feedback_response_class`,
  `feedback_session_phase`

These fields let RVEM distinguish generic next-request guidance from
retry-specific source reuse and keepalive-specific reuse/synthesis when
reconstructing timing audits for adaptive fuzzing runs.

Example:

```json
{"schema_version":"rvem.raw.v1","event_type":"campaign_snapshot","campaign":"profuzzbench-style-can","subject":"gear-controller","fuzzer":"bizonefuzz","variant":"rvem","run_id":"r0","elapsed_sec":600,"coverage":{"edges":145,"blocks":72,"paths":2},"execs_total":2900,"cases_total":42,"yield_total":5,"monitor_ms":12,"target_ms":128,"execs_per_sec":91}
{"schema_version":"rvem.raw.v1","event_type":"property_eval","campaign":"profuzzbench-style-can","subject":"gear-controller","fuzzer":"bizonefuzz","variant":"rvem","run_id":"r0","elapsed_sec":720,"property_id":"reqnewgear_deadline","case_id":"c17","verdict":"NEGATIVE","slack_ms":-18,"deadline_ms":1300}
{"schema_version":"rvem.raw.v1","event_type":"semantic_state","campaign":"profuzzbench-style-can","subject":"gear-controller","fuzzer":"bizonefuzz","variant":"rvem","run_id":"r0","elapsed_sec":720,"semantic_state":{"state_id":"q7","region":"gear","monitor_state_count":18,"frontier_width":5},"verdict":"INCONCLUSIVE"}
```

Direct monitor logging example:

```sh
MightyPPL/build/mitppl-monitor \
  --formula 'G(req -> F[0,50] rsp)' \
  --input events.txt \
  --feedback-jsonl feedback.jsonl \
  --campaign bring-up \
  --subject live555 \
  --fuzzer-name bizonefuzz \
  --mode full \
  --run-id run-0 \
  --property-set-id rtsp.req_rsp
```

## Aggregated Tables

`MightyPPL/scripts/rvem_tools.py aggregate raw.jsonl --out-dir tables` writes
CSV files with stable column order. The CSVs are Parquet-ready: `--parquet`
writes matching `.parquet` files when pandas and a Parquet engine are installed.

| table | purpose |
| --- | --- |
| `time_series.csv` | coverage, execution, violation, yield, and overhead counters over elapsed time |
| `property_summary.csv` | per-property positive/negative/inconclusive counts and slack summary |
| `semantic_state_series.csv` | monitor semantic state/frontier size over time |
| `slack_distribution.csv` | per-evaluation slack samples for ECDF and violin plots |
| `ablation_summary.csv` | final counters grouped by fuzzer/variant/ablation |
| `overhead_yield.csv` | monitor overhead and yield samples for tradeoff analysis |
| `case_timeline.csv` | per-case intervals with outcome and property annotations |
| `frontier_obligation_series.csv` | per-evaluation frontier, zone, obligation, and protocol-semantic snapshots |
| `property_progress_series.csv` | per-evaluation progress vectors / bins / coverage deltas for property-centric views |
| `trace_replay.csv` | replay-oriented timed-event, mutation-hint, and explainability rows for case inspection |
| `timing_audit_series.csv` | timing-plan provenance and mutation-audit rows reconstructed from `current/pass/exec/seed` timing artifacts |

`frontier_obligation_series.csv` preserves `zone_hash`, `min_slack_ms`,
`boundary_class`, guard counters, and `slack_exact`. In the current BFZK
implementation, `zone_hash` is a compact scheduler-facing fingerprint of the
timing region: concrete monitor valuations are encoded as point-zone
pairwise-difference matrices, while interval/symbolic monitor states fall back
to MoniTAal federation DBM bound matrices. This keeps RVEM and AFLNet from
depending on heavyweight DBM objects while still making the feedback tied to the
monitor's timed state rather than to response-code states alone.

## Plot Outputs

`MightyPPL/scripts/rvem_tools.py plot --table-dir tables --out-dir plots`
produces SVGs without requiring matplotlib:

- `coverage_over_time.svg`
- `time_to_first_violation.svg`
- `property_heatmap.svg`
- `semantic_state_over_time.svg`
- `slack_ecdf.svg`
- `slack_violin.svg`
- `progress_coverage_bar.svg`
- `ablation_bar.svg`
- `overhead_vs_yield.svg`
- `case_timeline.svg`
- `obligation_lifecycle.svg`
- `timing_hint_origin.svg`

For a complete smoke dataset:

```sh
python3 MightyPPL/scripts/rvem_tools.py demo --out-dir /tmp/rvem_demo
```

To inspect the code-level schema:

```sh
python3 MightyPPL/scripts/rvem_tools.py schema
```

To reuse a flat ProFuzzBench-style campaign CSV, convert it first:

```sh
python3 MightyPPL/scripts/rvem_tools.py import-profuzzbench-csv results.csv rvem.raw.jsonl \
  --campaign can-fuzzing --subject gear-controller
```

The importer recognizes common aliases such as `time`, `elapsed_sec`, `hour`,
`fuzzer`, `target`, `program`, `edges`, `coverage_edges`, `crashes`,
`unique_bugs`, `queue_size`, and `interesting`.

## Interactive Dashboard

`MightyPPL/scripts/rvem_tools.py dashboard --table-dir tables --plot-dir plots --out-html dashboard.html`
builds a self-contained HTML dashboard with five views:

- `Overview`
- `Protocol Drill-down`
- `Property Explorer`
- `Frontier & Obligation Evolution`
- `Trace Replay with Explanation`

The dashboard consumes the aggregated CSV tables directly, embeds the SVG plots
when `--plot-dir` is provided, and keeps the new multi-feedback tables
(`frontier_obligation_series.csv`, `property_progress_series.csv`,
`trace_replay.csv`, `timing_audit_series.csv`) in the same artifact bundle so
protocol-level review no longer drops frontier / obligation / explainability /
timing-plan provenance evidence after raw logging.

The current paper-facing figure bundle now includes:

- coverage growth
- time-to-first-violation survival
- semantic-state expansion
- slack boundary distributions
- property-progress coverage
- obligation lifecycle evolution
- timing-hint provenance

## Paper-Ready Reports

`MightyPPL/scripts/rvem_tools.py report --table-dir tables --plot-dir plots --out-dir reports`
builds a lightweight report bundle on top of aggregated tables:

- `variant_overview.csv`
- `survival_table.csv`
- `progress_obligation_summary.csv`
- `subject_variant_summary.csv`
- `subject_metric_matrix.csv`
- `pooled_variant_summary.csv`
- `monitor_ablation_summary.csv`
- `pairwise_variant_comparison.csv`
- `timing_provenance_summary.csv`
- `figure_manifest.json`
- `paper_summary.md`
- `paper_tables.md`
- `paper_tables.tex`
- `report_manifest.json`

This layer is meant for experiment write-up rather than raw ingestion. It keeps
the derived per-variant summaries, survival rows, and figure inventory in one
place so 24-hour campaign batches can regenerate both plots and paper-facing
tables without hand editing.

The subject-level outputs are the paper-facing table/matrix layer. The
`subject_variant_summary.csv` file keeps one normalized row per
`campaign` / `subject` / `fuzzer` / `variant`, including Wilson event-rate
intervals, bootstrap confidence intervals for coverage / semantic-state /
overhead means, first-violation timing, progress coverage, boundary-hit rate,
and timing-provenance counts. The `subject_metric_matrix.csv` file pivots the
same subject rows into a wide subject-by-variant matrix with stable dynamic
columns such as `aflnet/full__event_fraction` and
`aflnet/full__mean_final_coverage`, which is intended for spreadsheet checks
and paper table assembly. `paper_tables.md` and `paper_tables.tex` render the
same subject-level content as Markdown tables and LaTeX `longtable`s.

`monitor_ablation_summary.csv` is the ablation-facing companion table: it keeps
only monitor-enabled ablation variants (`oracle-only`, `frontier-only`,
`zone-only`, `obligation-only`, `progress-only`, `frontier+zone`, `full`) and
adds subject-level plus pooled deltas relative to the `full` configuration for
event fraction, coverage, semantic states, progress bins, boundary-hit rate,
overhead, and timing-provenance counts.

The pairwise comparison table now also carries:

- bootstrap confidence intervals for `delta_mean`
- Mann-Whitney U statistics with two-sided asymptotic `p` values
- Cliff's delta and `A12`
- a compact significance tier (`***`, `**`, `*`, `ns`)

The `report` command also accepts:

- `--reference-label` for explicit pairwise-comparison baselines
- `--bootstrap-samples`
- `--bootstrap-seed`

## Artifact Audit

`MightyPPL/scripts/rvem_tools.py audit-artifacts --table-dir tables --plot-dir plots --report-dir reports --dashboard-html dashboard.html`
checks that the RVEM bundle contains the paper-facing tables, the required SVG
figure set, the report manifests, and the five dashboard views. The command
prints a machine-readable `rvem.artifact_audit.v1` JSON document with
`problems`, `warnings`, row counts, figure availability, and dashboard view
coverage.

Use `--require-complete` to make missing or malformed artifacts fail the
command. Use `--require-data` when a campaign should already contain real
multi-feedback evidence rows in the core tables (`time_series`,
`frontier_obligation_series`, `property_progress_series`, `trace_replay`, and
`timing_audit_series`). This audit only checks artifact completeness; it does
not claim that a long-running experimental campaign has been executed.

For Bi-ZoneFuzz++ campaign tarballs produced via the ProFuzzBench overlay, use
the higher-level collector instead:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py collect-rvem manifest.json \
  --results-root /path/to/results --out-dir /path/to/rvem
```

That wrapper imports `cov_over_time.csv`, normalizes monitor-log campaign
coordinates back to the manifest, reconstructs `timing_audit` rows from
`queue/.state/bizone-feedback/*.timing.txt` and
`queue/.state/bizone-monitor/{current,passNN,execNNNNNN}.timing.txt`, and then
calls `rvem_tools.py validate/aggregate/plot/dashboard/report` automatically.

## Reproducibility Package

`MightyPPL/scripts/rvem_tools.py package-artifacts` builds a final
checksum-backed package after `audit-artifacts` and the ProFuzzBench
`audit-results` gate have run. The command emits
`rvem.repro_package.v1` as `artifact_package_manifest.json`, plus
`checksums.sha256`, `README.md`, and copied evidence under `payload/`.

The package can include:

- RVEM `tables/`, `plots/`, `reports/`, `dashboard.html`, and raw JSONL logs
- `rvem.artifact_audit.v1` JSON from `audit-artifacts`
- `bizonefuzz.profuzzbench.result_audit.v1` JSON and optional run-level CSV
- campaign manifests, stage-audit directories, and PropertyCard review packets

Strict packaging should use:

```sh
python3 MightyPPL/scripts/rvem_tools.py package-artifacts \
  --out-dir artifact-package \
  --table-dir rvem/tables \
  --plot-dir rvem/plots \
  --report-dir rvem/reports \
  --dashboard-html rvem/dashboard.html \
  --rvem-audit-json rvem/reports/artifact_audit.json \
  --result-audit-json result_audit.json \
  --result-audit-csv result_audit_runs.csv \
  --raw-jsonl rvem/campaign.raw.jsonl \
  --manifest campaign.manifest.json \
  --require-core \
  --require-rvem-audit-complete \
  --require-result-audit-gate \
  --require-complete
```

`--require-rvem-audit-complete` requires a complete
`rvem.artifact_audit.v1` input. `--require-result-audit-gate` requires a
passing ProFuzzBench result-audit gate. The package is deliberately not a
statistical proof by itself: it preserves evidence and checksums, while the
included audits remain the authority for run completeness, coverage evidence,
monitor feedback artifacts, and timing-artifact availability.

When the inputs come from the ProFuzzBench overlay, prefer
`bizone_profuzzbench.py finalize-artifacts`. That command runs result auditing,
RVEM reconstruction, RVEM artifact auditing, and `package-artifacts` in one
strict sequence and writes `bizonefuzz.profuzzbench.finalize.v1`. A failed
finalization keeps the failing stage in `finalization_manifest.json`, so missing
tarballs, missing monitor feedback, empty evidence tables, or package problems
remain visible instead of being hidden by a later packaging step.
