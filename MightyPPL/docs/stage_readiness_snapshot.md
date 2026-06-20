# Stage Readiness Snapshot

Snapshot date: `2026-06-18`

This document summarizes the current stage-level readiness of the
Bi-ZoneFuzz++ ProFuzzBench workflow using the new
`bizone_profuzzbench_stage_audit.py` wrapper over:

- `plan`
- `matrix`
- `preflight`

The snapshot was generated from the current repository state with the paper-like
defaults already encoded by the audit wrapper:

- `bring-up` + `main-study`
- `20` runs per subject/variant
- `24h` fuzz timeout per run
- full variant set:
  `aflnet-base`, `oracle-only`, `frontier-only`, `zone-only`,
  `obligation-only`, `progress-only`, `frontier+zone`, `full`, `aflnwe`,
  `stateafl`

Regeneration commands:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench_stage_audit.py \
  --workspace /home/lqq/download/fuzz_monitor_PPL_MoniTAal \
  --out-dir /tmp/bizone-stage-audit-default

python3 MightyPPL/scripts/bizone_profuzzbench_stage_audit.py \
  --workspace /home/lqq/download/fuzz_monitor_PPL_MoniTAal \
  --publication-gate draft \
  --out-dir /tmp/bizone-stage-audit-draft
```

Under `publication_gate=draft` or `publication_gate=final`, the audit now also
produces a sibling `review-packet/` directory containing the pending reviewer
action queue and command templates for the current `PropertyCard` bundle.

The audit has two modes:

- Reporting mode is the default. It writes the readiness artifacts and returns
  success when `plan + matrix + preflight` can be generated, even if the report
  says `real-run ready = no`.
- Strict gate mode adds one or more `--require-*` flags and returns nonzero
  after writing the same artifacts when a requirement is not satisfied.

Strict launch-gate example:

```sh
python3 MightyPPL/scripts/bizone_profuzzbench_stage_audit.py \
  --workspace /home/lqq/download/fuzz_monitor_PPL_MoniTAal \
  --out-dir /tmp/bizone-stage-audit-launch-gate \
  --require-dry-run-ready \
  --require-real-run-ready \
  --require-no-warnings \
  --require-monitor-entries
```

In the current environment, `--require-real-run-ready` is expected to fail if
any selected ProFuzzBench Docker image is not already present locally. Docker
daemon access alone is no longer enough to pass the real-run gate. Under
`publication_gate=draft`, `--require-monitor-entries` is also expected to fail
until the second-reviewer approval path is completed and monitor-enabled
entries survive the gate.

## Default Gate (`publication_gate=none`)

| Stage | Subjects | Entries | Monitor Entries | Warnings | Policy Exclusions | Dry-Run Ready | Real-Run Ready | Draft-Ready Subjects | Final-Ready Subjects | Est. Core-Hours |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: |
| `bring-up` | 3 | 23 | 14 | 0 | 7 | yes | no | 1 | 1 | 11040 |
| `main-study` | 5 | 50 | 35 | 0 | 0 | yes | no | 0 | 0 | 24000 |

Interpretation:

- `bring-up` is technically dry-run ready, and monitor-enabled runs now exist
  for both `live555` and `exim`.
- `lightftp` is no longer counted as a warning-producing missing-property
  subject. Instead, it is explicitly modeled as a baseline-only bring-up
  target, so its seven monitor-ablation variants appear as catalog policy
  exclusions rather than accidental readiness failures.
- `main-study` is fully formed from a manifest perspective:
  all five protocols have monitor-enabled entries, exported formulas, and no
  missing-property warnings.
- Neither stage is real-run ready until the selected ProFuzzBench Docker images
  have been built or otherwise loaded locally; the audit now checks image
  presence explicitly after confirming daemon access.
- A strict `--require-real-run-ready` gate therefore fails truthfully while
  still leaving `stage_summary.json` with `gate.passed=false`.

## Draft Gate (`publication_gate=draft`)

| Stage | Subjects | Entries | Monitor Entries | Warnings | Policy Exclusions | Dry-Run Ready | Real-Run Ready | Draft-Ready Subjects | Final-Ready Subjects | Est. Core-Hours |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: |
| `bring-up` | 3 | 9 | 0 | 14 | 7 | yes | no | 3 | 3 | 4320 |
| `main-study` | 5 | 15 | 0 | 35 | 0 | yes | no | 5 | 5 | 7200 |

Interpretation:

- Under the current publication gate, every monitor-enabled variant is removed
  from both stages.
- `lightftp` still contributes seven bring-up policy exclusions, but they are
  no longer mixed into the warning count; the remaining `14` bring-up warnings
  come from the publication-gate blockers on `exim` and `live555`.
- `bring-up` loses monitor-enabled `live555` entries not because the RTSP card
  is missing, but because the current review state still lacks the second
  reviewer approval required for draft publication.
- `main-study` drops from `35` monitor-enabled entries to `0`; only the three
  comparison/baseline variants per subject remain:
  `aflnet-base`, `aflnwe`, `stateafl`.
- The same draft audit now exports a root `review-packet/` bundle. In the
  current repository snapshot, that packet reports `10` pending reviewer
  actions across the bundle/card scopes, which turns the review bottleneck into
  a concrete artifact instead of only a stage-level warning count.
- A strict `--require-monitor-entries` gate under `publication_gate=draft`
  therefore fails until those review actions are resolved against the checked
  bundle.

## Concrete Gaps

### 1. Environment / image gap

- Docker CLI: available
- Docker daemon: available in the latest local check
- ProFuzzBench images: not yet proven available for the selected campaign
  slices

Effect:

- host-side preflight passes
- real ProFuzzBench container campaigns remain blocked until the required
  images pass `docker image inspect`

Recent local observation:

- `docker info` succeeds from WSL.
- Attempting to build the `lightftp` ProFuzzBench image reached package
  download/install but failed on transient apt HTTP EOF errors for packages
  including `gdb` and `llvm-10-dev`; this is recorded as an image availability
  blocker, not hidden as a successful real-run readiness state.

### 2. Bring-up FTP policy gap

Current explicit catalog policy:

- `lightftp` / `FTP` is baseline-only

Effect under `publication_gate=none`:

- `7` bring-up monitor-ablation entries are intentionally excluded by policy

Additional context:

- TSIM now emits explicit `conn_timeout` / `conn_close` propositions for FTP,
  so the instrumentation side is no longer the blocker.
- The remaining blocker is property selection quality: the most defensible
  official FTP timeout rule is still the RFC 1123 minimum idle-timeout
  guidance (`>= 5 minutes`), and that bound does not match the repository's
  current short per-exec fuzz budgets well enough to make `lightftp`
  immediately paper-ready as a monitor-guided bring-up subject.
- The checked-in LightFTP target configuration/source at commit `5980ea1`
  does not expose a shorter implementation-default control timeout, so the
  repository now records this as an explicit policy exclusion instead of an
  unresolved missing-property warning.

### 3. Publication-readiness gap

All current monitor-enabled draft/publication paths are still blocked by the
same review bottleneck:

- bundle-level second reviewer approval still missing
- per-card draft approvals currently `1/2`

Affected subjects:

- `exim`
- `live555`
- `kamailio`
- `tinydtls`
- `dcmtk`
- `openssh`

Effect:

- `14` bring-up monitor-enabled entries disappear under `publication_gate=draft`
- `35` main-study monitor-enabled entries disappear under `publication_gate=draft`

## What This Means For The Paper Path

Today the repository is already strong enough for:

- host-side experiment planning
- manifest generation
- matrix generation
- preflight auditing
- smoke/regression evidence for adaptive monitor-guided fuzzing behavior

But it is not yet strong enough for the full paper campaign because three
independent readiness barriers remain:

1. required Docker images must be built or loaded before long-running container campaigns
2. `FTP/lightftp` still needs a defensible official short-horizon timed
   `PropertyCard` route if it is to re-enter the monitor-enabled bring-up path;
   until then it remains an explicit baseline-only policy subject
3. the current six-protocol initial property bundle still needs the second
   reviewer approval required by the repository's own draft/publication gate

## Recommended Next Actions

1. Keep `lightftp` baseline-only unless a stronger official FTP timing route
   is found than RFC 1123's `>= 5 minute` idle-timeout lower bound or the
   LightFTP implementation gains a documented shorter timeout default.
2. Complete the second-reviewer approval path for the six current bundled
   protocols so `draft` no longer collapses all monitor-enabled entries.
3. Re-run the stage audit after the required Docker images are built or loaded;
   `--require-real-run-ready` will then separate image availability from the
   remaining publication and policy readiness gaps.
