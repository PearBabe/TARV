# ProFuzzBench Overlay for Bi-ZoneFuzz++

This repository now includes an experiment-automation layer that sits on top of
the local `profuzzbench/` clone instead of replacing it. The overlay has three
jobs:

1. turn `PropertyCard` artifacts into runnable `.mitl` formula files
2. build an auditable campaign manifest for bring-up or main-study runs
3. audit ProFuzzBench result tarballs before analysis
4. reconstruct RVEM raw logs, tables, and plots from ProFuzzBench result
   tarballs

The implementation files are:

- [`MightyPPL/benchmarks/profuzzbench_campaigns.json`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/benchmarks/profuzzbench_campaigns.json)
- [`MightyPPL/scripts/bizone_profuzzbench.py`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/scripts/bizone_profuzzbench.py)
- [`MightyPPL/scripts/run_profuzzbench_overlay_smoke.py`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/scripts/run_profuzzbench_overlay_smoke.py)

## Campaign Catalog

`profuzzbench_campaigns.json` records the current experiment design in a stable,
machine-readable form.

- `bring-up`: `lightftp`, `exim`, `live555`
- `main-study`: `kamailio`, `tinydtls`, `live555`, `dcmtk`, `openssh`
- each subject keeps:
  - protocol
  - ProFuzzBench target/image id
  - AFLNet baseline options
  - AFLnwe comparison options
  - StateAFL comparison options
  - the currently recommended timing property when one has already been
    extracted as a `PropertyCard`

The current catalog now binds `exim` to the official SMTP timeout card
`smtp.mail.reply_within_minimum_timeout`. `lightftp` is now modeled
explicitly as a `baseline-only` bring-up subject in the catalog rather than as
an accidental missing-property warning. The reason is recorded in
`monitor_policy`: RFC 1123 gives only a `>= 5 minute` FTP idle-timeout lower
bound, while the checked-in LightFTP target configuration/source at commit
`5980ea1` does not expose a shorter implementation-default control timeout that
would be defensible for the repository's current short-horizon timed fuzzing
budget.

## Manifest Planning

Build a manifest for the main-study RTSP subject:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py plan \
  --stage main-study \
  --campaign main-study-quick \
  --subjects live555 \
  --variants aflnet-base,aflnet-patched-base,oracle-only,frontier-only,zone-only,obligation-only,progress-only,frontier+zone,full \
  --runs 2 \
  --fuzz-timeout-sec 21600 \
  --out live555.manifest.json
```

The manifest stores:

- `subject_id`, `protocol`, `docker_image`
- `variant`, `fuzzer`, `out_dir`, `results_dir`
- fully rendered AFLNet and monitor-ablation option strings
- whether local Bi-ZoneFuzz++ AFLNet injection is required
- the selected `property_id` and formula filename for monitor-enabled modes
- optional publication-gate filtering / metadata for monitor-enabled entries
- optional `policy_exclusions` when a subject is intentionally restricted to a
  subset of variants such as `baseline-only`

If you want planning to exclude monitor-enabled variants whose `PropertyCard`
artifacts are not yet ready for a draft or final paper workflow, add:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py plan \
  --stage main-study \
  --campaign main-study-draft-ready \
  --subjects live555 \
  --variants aflnet-base,aflnet-patched-base,oracle-only,frontier-only,zone-only,obligation-only,progress-only,frontier+zone,full \
  --publication-gate draft \
  --out live555.draft.json
```

With the current repository's draft-only bundle, this keeps the non-monitor
baselines (`aflnet-base` and `aflnet-patched-base`) and skips the
monitor-enabled ablation variants, while recording the readiness warnings in
the manifest.

To turn that manifest into a paper-facing experiment matrix and readiness
summary without launching Docker yet:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py matrix live555.manifest.json \
  --out-dir live555.matrix
```

The matrix bundle contains:

- `entry_matrix.csv`
- `subject_readiness.csv`
- `paper_matrix.md`
- `campaign_summary.json`
- `matrix_manifest.json`

`campaign_summary.json` now also distinguishes:

- `warnings`: unexpected readiness blockers such as publication-gate failures
- `policy_exclusions`: intentional catalog-level exclusions such as
  `lightftp` being baseline-only until an official short-horizon timed FTP
  property route exists

This layer is meant for experiment design review before spending cluster time.
It makes the planned variants, monitor-enabled subsets, selected properties,
draft/final publication gates, and estimated core-hour budget auditable from
the same manifest that later drives the real run.

The overlay smoke follows the same monitor-ablation shape: it plans and
reconstructs `aflnet-base`, `oracle-only`, `frontier-only`, `zone-only`,
`obligation-only`, `progress-only`, `frontier+zone`, and `full`, then checks
that the report bundle includes the ablation summary relative to `full`.

## Host Preflight

Before launching real containers, run a host-side readiness audit against the
selected manifest slice:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py preflight live555.manifest.json \
  --results-root /data/bizone-profuzzbench \
  --out live555.preflight.json
```

The preflight report checks:

- selected manifest entries and publication-gate filtering
- whether the selected slice actually requires local `afl-fuzz` injection
- whether monitor-enabled entries can see the local `mitppl-monitor`
- whether required `.mitl` formulas can be exported from the current
  `PropertyCard` bundle
- whether the chosen results root is writable
- whether the Docker CLI is present, and whether the Docker daemon is reachable
- whether each selected ProFuzzBench Docker image already exists locally

This command does not launch containers. In the current workspace shape, that
means it can still produce a truthful report even when the Docker daemon is not
running. If the daemon is reachable, preflight also runs `docker image inspect`
for every selected image and folds missing images into `ready_for_real_run`.
If you want the command itself to fail until real container execution becomes
possible, add `--require-daemon`; if the daemon is available but images are
missing, the JSON will still report `ready_for_real_run=false` through the
`docker_images` section.

When images are missing, use the checked manifest itself to build or audit the
required Docker contexts:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py build-images bringup.manifest.json \
  --workspace /home/lqq/download/fuzz_monitor_PPL_MoniTAal \
  --subjects lightftp,exim,live555 \
  --variants aflnet-base \
  --out-dir /tmp/bizone-image-build \
  --network host \
  --make-opt -j2 \
  --retries 2
```

`build-images` resolves each selected image back to a local
`profuzzbench/subjects/*/*/Dockerfile` context, checks whether the image already
exists, runs `docker build . ...` from the subject directory only when needed
unless `--force` is set, and writes `image_build_manifest.json` plus
per-attempt logs under `image-build-logs/`. For `stateafl` variants it follows
the ProFuzzBench convention of using `Dockerfile-stateafl` and the
`<image>-stateafl` tag. It is deliberately separate from `run`: build failures
such as apt mirror EOFs remain auditable image-availability blockers instead of
being mixed into fuzzing results. Use `--dry-run` to validate context and
Dockerfile resolution without requiring a Docker daemon.

If you want the same readiness flow across whole experiment stages instead of a
single manifest, the repository now also includes a stage-level audit wrapper:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench_stage_audit.py \
  --out-dir /tmp/bizone-stage-audit
```

That wrapper materializes `plan + matrix + preflight` for `bring-up` and
`main-study`, then writes:

- `stage_summary.json`
- `stage_summary.csv`
- `stage_summary.md`
- per-stage `manifest.json`
- per-stage `matrix/`
- per-stage `preflight.json`

When the audit runs with `--publication-gate draft` or
`--publication-gate final`, it also materializes a root-level
`review-packet/` directory for the currently selected `PropertyCard` bundle.
That packet contains:

- `review_queue.csv` with pending reviewer actions
- `review_commands.sh` with copy-ready `stamp-review` command templates
- `review_packet.md` and `review_packet_manifest.json`
- the exported `.mitl` formulas, review report, and citation/property indexes

This keeps the stage audit truthful: it still removes monitor-enabled entries
that are not publication-ready, but it no longer stops at reporting the
blocker. The same audit artifact now also points directly at the structured
approval work needed to unblock draft/final campaigns. The stage table also
surfaces Docker image presence counts, so a reachable Docker daemon is not
mistaken for proof that campaign containers can actually launch.

The audit now also separates intentional catalog policy from accidental
readiness failures. For example, `lightftp` contributes `7`
`policy exclusions` in bring-up because its monitor-enabled variants are
explicitly disabled by policy, not because the tooling silently failed to find
assets.

By default the stage audit is a reporting command: it writes the readiness
artifacts even when the host is not ready for real Docker campaigns or when a
publication gate filters out monitor-enabled entries. For a CI or
paper-campaign launch gate, add explicit requirements:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench_stage_audit.py \
  --out-dir /tmp/bizone-stage-audit-strict \
  --require-dry-run-ready \
  --require-real-run-ready \
  --require-no-warnings \
  --require-monitor-entries
```

Available strict gates are:

- `--require-dry-run-ready`
- `--require-real-run-ready`
- `--require-no-warnings`
- `--require-no-policy-exclusions`
- `--require-monitor-entries`

When one of these gates fails, the command still writes `stage_summary.json`,
`stage_summary.csv`, and `stage_summary.md`; the JSON contains a `gate` object
with `passed=false` and concrete `problems`. This is intentional: missing
Docker daemon access, missing Docker images, publication blockers,
baseline-only policy exclusions, or zero monitor-enabled entries should remain
inspectable rather than being hidden by a nonzero exit code.

The current repository snapshot derived from that workflow is summarized in:

- [`MightyPPL/docs/stage_readiness_snapshot.md`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/docs/stage_readiness_snapshot.md)

## Execution Model

`bizone_profuzzbench.py run` executes one ProFuzzBench container per
replication, using the subject's existing `run.sh` inside the image.
`aflnet-base` is the official ProFuzzBench AFLNet baseline and deliberately
uses the AFLNet binary already present in the image. `aflnet-patched-base` and
the monitor-enabled Bi-ZoneFuzz++ AFLNet variants inject local assets before
launching the run:

- local `aflnet/` source, rebuilt inside the container to avoid host/container
  ABI drift
- local `MightyPPL/build/mitppl-monitor`
- exported `.mitl` formula file

This keeps the official baseline clean, while `aflnet-patched-base` provides a
fair engineering baseline for the patched AFLNet code with monitor feedback
disabled. It also avoids requiring an immediate fork of every upstream
ProFuzzBench Dockerfile while still keeping the runtime path compatible with
the benchmark's subject scripts.

Example dry run:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py run live555.manifest.json \
  --results-root /tmp/profuzzbench-results --dry-run
```

`run --dry-run` now performs a truthful host-side check before printing the
planned container launches:

- it validates local `afl-fuzz` only when the selected entries actually inject
  local AFLNet
- it validates local `mitppl-monitor` for monitor-enabled entries
- it validates Docker CLI discovery
- it reports daemon unreachability as a warning rather than silently pretending
  the environment is ready for a real launch

Example real run:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py run live555.manifest.json \
  --results-root /data/bizone-profuzzbench --delete-containers
```

You can also enforce a publication gate at run time even when the manifest was
planned without one:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py run live555.manifest.json \
  --results-root /data/bizone-profuzzbench \
  --dry-run \
  --enforce-publication-gate draft
```

This causes the wrapper to refuse monitor-enabled entries whose current
PropertyCard bundle is not ready for the selected gate.

## RVEM Reconstruction

Once result tarballs should exist, audit the ProFuzzBench result bundle before
reconstructing RVEM artifacts:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py audit-results live555.manifest.json \
  --results-root /data/bizone-profuzzbench \
  --out /data/bizone-profuzzbench/result_audit.json \
  --csv-out /data/bizone-profuzzbench/result_audit_runs.csv \
  --require-complete \
  --require-coverage \
  --require-monitor-artifacts
```

The result audit checks every selected manifest entry and run for:

- the expected `results-*/out-*_N.tar.gz` tarball
- tarball readability
- `cov_over_time.csv` evidence for coverage-aligned ProFuzzBench plots
- monitor feedback JSONL artifacts for monitor-enabled variants
- timing-plan artifacts for monitor-enabled variants

The command is deliberately non-failing by default so partial campaigns can be
inspected during long runs. Add the `--require-*` gates when a batch should be
complete. Missing tarballs are treated as unproven coverage/monitor evidence,
not as success.

After that gate passes, reconstruct RVEM artifacts directly:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py collect-rvem live555.manifest.json \
  --results-root /data/bizone-profuzzbench \
  --out-dir /data/bizone-profuzzbench/rvem
```

The collector does two things:

- imports `cov_over_time.csv` from each tarball into RVEM `campaign_snapshot`
  records so coverage-over-time plots stay aligned with ProFuzzBench
- harvests Bi-Zone monitor logs from:
  - `queue/.state/bizone-feedback/*.jsonl`
  - `queue/.state/bizone-monitor/current.feedback.jsonl`
  - `queue/.state/bizone-monitor/passNN.feedback.jsonl`
  - `queue/.state/bizone-monitor/execNNNNNN.feedback.jsonl`
- reconstructs `timing_audit` RVEM rows from:
  - `queue/.state/bizone-feedback/*.timing.txt`
  - `queue/.state/bizone-monitor/current.timing.txt`
  - `queue/.state/bizone-monitor/passNN.timing.txt`
  - `queue/.state/bizone-monitor/execNNNNNN.timing.txt`

The output tree is:

- `campaign.raw.jsonl`
- `raw/*.jsonl`
- `tables/*.csv`
- `plots/*.svg`
- `dashboard.html`
- `reports/variant_overview.csv`
- `reports/survival_table.csv`
- `reports/progress_obligation_summary.csv`
- `reports/pooled_variant_summary.csv`
- `reports/monitor_ablation_summary.csv`
- `reports/pairwise_variant_comparison.csv`
- `reports/timing_provenance_summary.csv`
- `reports/figure_manifest.json`
- `reports/paper_summary.md`
- `reports/paper_tables.md`
- `reports/paper_tables.tex`

The default RVEM plot bundle now includes paper-facing figures such as:

- `time_to_first_violation.svg`
- `progress_coverage_bar.svg`
- `obligation_lifecycle.svg`
- `timing_hint_origin.svg`

The paper-facing report bundle now also keeps a dedicated
`monitor_ablation_summary.csv`, which normalizes subject-level and pooled
monitor-ablation deltas relative to `full` so channel-ablation write-up does
not have to reconstruct those comparisons manually from the wider variant
tables.

To gate the regenerated bundle before paper-table or dashboard review, run:

```sh
python3 MightyPPL/scripts/rvem_tools.py audit-artifacts \
  --table-dir /data/bizone-profuzzbench/rvem/tables \
  --plot-dir /data/bizone-profuzzbench/rvem/plots \
  --report-dir /data/bizone-profuzzbench/rvem/reports \
  --dashboard-html /data/bizone-profuzzbench/rvem/dashboard.html \
  --require-complete
```

Add `--require-data` for smoke datasets or completed campaign batches where
the core multi-feedback evidence tables should already contain rows. This is
an artifact-completeness gate, not a substitute for the formal `24h x 20 runs`
campaign evidence.

Finally, freeze the audited RVEM/result bundle into a checksum-backed artifact
package:

```sh
python3 MightyPPL/scripts/rvem_tools.py package-artifacts \
  --out-dir /data/bizone-profuzzbench/artifact-package \
  --table-dir /data/bizone-profuzzbench/rvem/tables \
  --plot-dir /data/bizone-profuzzbench/rvem/plots \
  --report-dir /data/bizone-profuzzbench/rvem/reports \
  --dashboard-html /data/bizone-profuzzbench/rvem/dashboard.html \
  --rvem-audit-json /data/bizone-profuzzbench/rvem/reports/artifact_audit.json \
  --result-audit-json /data/bizone-profuzzbench/result_audit.json \
  --result-audit-csv /data/bizone-profuzzbench/result_audit_runs.csv \
  --raw-jsonl /data/bizone-profuzzbench/rvem/campaign.raw.jsonl \
  --manifest live555.manifest.json \
  --require-core \
  --require-rvem-audit-complete \
  --require-result-audit-gate \
  --require-complete
```

The package writes `artifact_package_manifest.json`, `checksums.sha256`, a
truthfulness-oriented `README.md`, and copied evidence under `payload/`. The
package gate preserves the upstream audit results: it fails if the RVEM audit
is incomplete or if the ProFuzzBench result audit gate did not pass. It does
not turn a smoke run into paper-scale evidence; the manifest records run-count
limitations when the included result audit covers fewer than the planned
campaign runs.

For a completed batch, the preferred strict workflow is the overlay-level
finalizer. It runs the same gates in order and writes a
`bizonefuzz.profuzzbench.finalize.v1` manifest with each stage command,
return code, and output location:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench.py finalize-artifacts live555.manifest.json \
  --results-root /data/bizone-profuzzbench \
  --out-dir /data/bizone-profuzzbench/finalized \
  --rvem-tool MightyPPL/scripts/rvem_tools.py
```

`finalize-artifacts` performs:

- `audit-results --require-complete --require-coverage --require-monitor-artifacts`
- `collect-rvem --require-complete`
- `rvem_tools.py audit-artifacts --require-complete --require-data`
- `rvem_tools.py package-artifacts --require-core --require-rvem-audit-complete --require-result-audit-gate --require-complete`

If any stage fails, `finalization_manifest.json` is still written with
`gate_passed=false` and `failed_stage` set to the real failing step. This is the
recommended paper-artifact handoff because it keeps result completeness, RVEM
evidence, visualization artifacts, and checksums connected by one auditable
manifest.

## Current Caveats

- The run wrapper is implemented, but this turn only smoke-tested the planning
  and result-reconstruction path, not a full real Docker campaign.
- The collector normalizes monitor log coordinates back to the manifest's
  `campaign / subject / fuzzer / variant / run_id`, because the current AFLNet
  runtime logger still emits generic runtime labels.
- Persisted monitor logs are currently interesting-seed-oriented rather than a
  full per-exec campaign trace; the overlay reconstructs what is available in
  the saved tarballs.
