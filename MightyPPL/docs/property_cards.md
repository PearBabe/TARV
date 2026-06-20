# PropertyCard Workflow for Bi-ZoneFuzz++

`PropertyCard` is the artifact unit for the property-extraction module. It keeps
the normative source, timer binding, AP mapping, MITL formula, and replayable
positive/boundary-negative traces together so every paper claim can be audited.

## Main-study rule

Formal experiment cards for `SIP`, `DTLS`, `RTSP`, `DICOM`, and `SSH` must come
from:

- RFC text
- protocol standards
- official implementation manuals or default configuration references

The repository also includes a `demo` card path only for tool regression. Demo
cards are not valid paper artifacts.

Current non-demo artifact bundle:

- [`MightyPPL/benchmarks/main_study_property_cards_initial.json`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/benchmarks/main_study_property_cards_initial.json)
  - scope: initial main-study draft for `SIP`, `DTLS`, `RTSP`, `DICOM`, and `SSH`
  - status: schema-validated, `mitppl-monitor` replay-checked, and structured review metadata validated
  - caveat: still marked draft until two-reviewer approval is completed and final publication approvals are added

Generated summary table:

- [`MightyPPL/docs/main_study_property_cards_initial.md`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/docs/main_study_property_cards_initial.md)

Generated structured review report:

- [`MightyPPL/docs/main_study_property_cards_review.md`](/home/lqq/download/fuzz_monitor_PPL_MoniTAal/MightyPPL/docs/main_study_property_cards_review.md)

## Required fields

Every card must contain:

- `property_id`
- `protocol`
- `source_url`
- `section_id`
- `normative_level`
- `original_clause`
- `timer_symbol`
- `timer_binding`
- `AP_definition`
- `trace_mapping`
- `MITL_formula`
- `positive_trace`
- `boundary_negative_trace`

These fields match the plan requirement:

`property_id, protocol, source_url, section_id, normative_level, original_clause, timer_symbol, timer_binding, AP_definition, trace_mapping, MITL_formula, positive_trace, boundary_negative_trace`

Formal main-study bundles also carry structured review metadata:

- top-level `review_metadata`
- per-card `review_metadata`

The review metadata records required approval count, individual review entries,
dynamic validation status, publication blockers, and the current
`publication_ready` state for each card.

## Tooling

Validate a card artifact:

```sh
python3 MightyPPL/scripts/property_card_tools.py validate cards.json
```

Enforce that structured review metadata is present and well-formed:

```sh
python3 MightyPPL/scripts/property_card_tools.py validate cards.json \
  --require-structured-review
```

Render a paper-ready Markdown summary:

```sh
python3 MightyPPL/scripts/property_card_tools.py markdown cards.json --out cards.md
```

Export per-property `.mitl` files for AFLNet / ProFuzzBench experiment wiring:

```sh
python3 MightyPPL/scripts/property_card_tools.py export-formulas cards.json \
  --out-dir formulas --manifest-out formulas.json
```

Check the positive and boundary-negative traces against `mitppl-monitor`:

```sh
python3 MightyPPL/scripts/property_card_tools.py check-monitor cards.json \
  --monitor MightyPPL/build/mitppl-monitor
```

Summarize structured review and publication status:

```sh
python3 MightyPPL/scripts/property_card_tools.py review-report cards.json \
  --format markdown --out cards_review.md
```

Materialize a pre-approval review packet for the second-review workflow:

```sh
python3 MightyPPL/scripts/property_card_tools.py review-packet cards.json \
  --out-dir review-packet
```

The review packet is intentionally allowed before publication gates pass. It
packages:

- the current bundle JSON and Markdown export
- the structured review report
- exported `.mitl` formulas and a formulas manifest
- `review_queue.csv` with pending reviewer actions
- `review_commands.sh` with `stamp-review` command templates
- `review_packet.md` and `review_packet_manifest.json` for handoff / audit

`review_queue.csv` is now a real round-trip artifact rather than a passive
report. In addition to the planning fields (`scope`, `card_id`, `next_gate`,
`next_decision`, ...), it includes reviewer-fillable columns such as:

- `apply`
- `reviewer_id`
- `reviewer_name`
- `decision`
- `review_date`
- `role`
- `notes`

Once those fields are completed, apply the queue back to a bundle copy with:

```sh
python3 MightyPPL/scripts/property_card_tools.py apply-review-packet \
  review-packet/review_packet_manifest.json \
  --out reviewed_bundle.json
```

This command reads the packet's `review_queue.csv`, validates the filled
reviewer metadata, and stamps the resulting approvals into the target bundle.

If you want a higher-level artifact instead of just the updated JSON, use:

```sh
python3 MightyPPL/scripts/property_card_tools.py resolve-review-packet \
  review-packet/review_packet_manifest.json \
  --out-dir reviewed-draft \
  --allow-draft \
  --require-gate-pass
```

This orchestration command applies the filled queue, writes
`reviewed_bundle.json`, regenerates `review_report.{md,json}`, and emits a
`review_resolution_manifest.json` recording the applied action count plus the
result of the selected draft/final publication gate.

Check whether a bundle is ready for draft or final publication:

```sh
python3 MightyPPL/scripts/property_card_tools.py publication-check cards.json \
  --allow-draft
```

Append or update a reviewer decision for the bundle or a specific card:

```sh
python3 MightyPPL/scripts/property_card_tools.py stamp-review cards.json \
  --scope card \
  --card-id sip.invite.response_within_timer_b \
  --reviewer-id reviewer_two \
  --reviewer-name "Second Reviewer" \
  --decision approve-draft \
  --date 2026-06-17 \
  --role independent_review \
  --notes "Confirms the RFC clause binding and boundary trace."
```

Update the bundle-level `review_status` explicitly when a reviewed bundle moves
from draft to paper-ready or publication-ready:

```sh
python3 MightyPPL/scripts/property_card_tools.py set-review-status cards.json \
  --review-status approved-for-publication \
  --strict
```

Materialize a gated publication pack once the draft gate or final publication
gate is satisfied:

```sh
python3 MightyPPL/scripts/property_card_tools.py publish-bundle cards.json \
  --out-dir published-pack \
  --allow-draft
```

For a final publication pack, omit `--allow-draft`. The final gate requires:

- bundle-level final approvals
- per-card final approvals
- passed dynamic validation
- top-level `review_status` in `paper-ready` or `approved-for-publication`

Create a demo-only card for smoke testing:

```sh
python3 MightyPPL/scripts/property_card_tools.py init-demo \
  --out MightyPPL/benchmarks/demo_property_cards.json
```

## Review workflow

Follow the planned extraction sequence:

1. `spec snapshot`
2. `clause mining`
3. `template binding`
4. `AP mapping`
5. `parameter binding`
6. `two-reviewer approval`
7. `dynamic validation`
8. `artifact publication`

For the current repository state, steps 6-8 are supported by:

- the JSON schema validator
- structured `review_metadata`
- the replay-based `check-monitor` command
- the `review-report` command
- the `review-packet` command
- the `apply-review-packet` round-trip helper
- the `resolve-review-packet` orchestration helper
- the `publication-check` gate
- the `stamp-review` helper
- the Markdown export command

The current six-protocol initial bundle is intentionally still a draft:

- one draft approval is recorded for the bundle and for each card
- dynamic validation is recorded as passed
- publication blockers remain until an independent second reviewer approves the
  bundle and each card
- final publication still requires final-approval entries in addition to the
  draft gate

The `publish-bundle` command is the concrete implementation of step 8
`artifact publication`. A successful publication pack contains:

- `property_cards.json`
- `property_cards.md`
- `review_report.md`
- `review_report.json`
- `formulas/*.mitl`
- `formulas_manifest.json`
- `property_index.csv`
- `citation_index.csv`
- `publication_manifest.json`

This makes the property-extraction module auditable without asking a later
experiment script to rediscover formulas, source URLs, approval state, or the
paper-facing property index from scratch.

Regression coverage for this workflow now includes:

- `mightyppl_property_card_initial_bundle`
- `mightyppl_property_card_review_smoke`
