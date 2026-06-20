# Bi-ZoneFuzz++ Implementation Notes

This repository now contains the first executable slice of the Bi-ZoneFuzz++
architecture. The implementation is split across MightyPPL, MoniTAal, RVEM,
and AFLNet-facing timing hooks.

## Module mapping

- `TSIM`
  - `aflnet/aflnet.c`
  - `aflnet/afl-fuzz.c`
  - `MightyPPL/mitppl-monitor.cpp`
- `MFCB`
  - `MightyPPL/MightyPPLMonitor.{h,cpp}`
- `BFZK`
  - `MightyPPL/MightyPPLMonitor.{h,cpp}`
  - `MoniTAal/src/monitaal/*` read-only summary helpers
- `RVEM`
  - `MightyPPL/scripts/rvem_tools.py`
  - `MightyPPL/docs/rvem_schema.md`
- `ProFuzzBench overlay`
  - `MightyPPL/benchmarks/profuzzbench_campaigns.json`
  - `MightyPPL/scripts/bizone_profuzzbench.py`
  - `MightyPPL/docs/profuzzbench_overlay.md`
- `Property extraction`
  - `MightyPPL/scripts/property_card_tools.py`
  - `MightyPPL/docs/property_cards.md`

## What is implemented now

- Embedded `MonitorSession` API for MightyPPL + MoniTAal.
- `FeedbackFrame` with seven feedback channels:
  - frontier
  - zone
  - obligation
  - property progress
  - protocol semantic
  - mutation hint
  - explainability
- BFZK zone feedback now fingerprints timing regions from MoniTAal state data:
  - when concrete monitoring is available, each valuation is encoded as a
    point-zone pairwise-difference matrix before hashing
  - otherwise, the symbolic positive/negative frontier federations are encoded
    by DBM dimension and bound matrix before hashing
  - the public `FeedbackFrame` schema stays stable: schedulers consume
    `zone_hash`, `min_slack_ms`, `slack_exact`, `boundary_class`,
    `violated_guard_count`, and `near_deadline_count`
- `mitppl-monitor --feedback-jsonl` that emits RVEM-compatible raw logs with
  nested `timed_trace_event` and `feedback_frame`.
- Automated smoke/regression coverage through `ctest`.
- RVEM now also lifts multi-feedback fields into dashboard-ready tables:
  - `frontier_obligation_series.csv`
  - `property_progress_series.csv`
  - `trace_replay.csv`
  - paper-facing static figures including:
    - `time_to_first_violation.svg`
    - `progress_coverage_bar.svg`
    - `obligation_lifecycle.svg`
    - `timing_hint_origin.svg`
  - paper-ready report artifacts including:
    - `variant_overview.csv`
    - `survival_table.csv`
    - `progress_obligation_summary.csv`
    - `pooled_variant_summary.csv`
    - `pairwise_variant_comparison.csv`
    - `timing_provenance_summary.csv`
    - `figure_manifest.json`
    - `paper_summary.md`
  - a self-contained `dashboard.html` with `Overview`, `Protocol Drill-down`,
    `Property Explorer`, `Frontier & Obligation Evolution`, and
    `Trace Replay with Explanation`
- AFLNet network-timing telemetry hooks:
  - request send completion
  - response first byte
  - response completion
  - inter-request gap
- AFLNet live monitor bridge and multi-channel seed guidance:
  - runtime timed-trace export into `current.events.txt`
  - `mitppl-monitor` invocation with ablation-aware feedback channels
  - semantic-state / boundary / obligation / progress signals folded into
    interestingness and scheduling score updates
- First timing-aware mutation slice driven by `IMutationHintFeedback`:
  - gap compression
  - gap expansion
  - silence-window insertion
  - keepalive-biased delay placement
  - boundary-bisection timing plans
  - execution-scoped timed retry insertion
  - bounded multi-insertion retry chains
  - cross-request delay-resend retry layouts
  - hybrid keepalive+retry schedules within one execution, with per-insertion
    audit metadata in the timing-plan artifact
  - DTLS-aware retransmission scheduling that prefers `ClientHello` retry
    sources and exposes contextual retry profiles in timing artifacts
  - protocol-aware keepalive synthesis for text and simple binary protocols
  - contextual RTSP keepalive synthesis that reuses live request URI / `CSeq`
    / `Session` information instead of only falling back to a static template
  - contextual SIP keepalive synthesis that reuses live request URI / `Via` /
    `From` / `To` / `Call-ID` / `CSeq` information instead of only falling
    back to a static template
  - transaction-aware SIP timed-trace export that derives a stable helper key
    from `Via` branch / `Call-ID` / `CSeq`, labels the first `INVITE` as
    `invite`, later same-transaction replays as `rtx`, and correlated SIP
    responses as `invite_rsp`
  - contextual DTLS probe synthesis that reuses live `ClientHello` /
    `Heartbeat` records when possible and otherwise falls back to a static
    DTLS 1.2 heartbeat template
  - replay-aligned DTLS AP binding that labels the first `ClientHello` as
    `ch`, later local retries as generic `rtx`, and ordinal retries such as
    `rtx1` / `rtx2` when later retries are materialized in the timed trace
  - replay-aligned DICOM AP binding that labels association requests as
    `assoc_req` and correlated ACSE responses as `acse_rsp`
  - replay-aligned RTSP AP binding that labels successful session-establishing
    `SETUP` responses as `session_open` and later matching session-scoped
    requests as `session_activity`, keyed by `rtsp_sess_<hash>`
  - replay-aligned FTP/SMTP reply binding that preserves raw text-protocol
    reply-code labels such as `rsp_220`, `rsp_250`, and correlated terminal
    request helpers such as `noop_rsp` / `mail_rsp` instead of exposing only
    AFLNet's internal `state_N` mapping
  - explicit TSIM connection-outcome propositions such as `conn_timeout`,
    `conn_close`, plus paired `rsp_timeout` / `rsp_close` helpers derived from
    socket poll / EOF outcomes
  - replay-aligned SSH AP binding that labels the first outbound
    identification event as `conn_open` and correlated terminal
    authentication responses as `auth_done`
  - execution-scoped keepalive duplication / insertion
- Main-study protocol smoke now extends beyond FTP:
  - `aflnet/tutorials/mockftp/mock_ftp_server.c`
  - `run_aflnet_bizone_smoke.py --force-hints keepalive --force-retry-chain 0`
  - validates raw FTP response-code labels `rsp_220` / `rsp_331` / `rsp_200`,
    correlated `noop_rsp`, explicit close outcome labels
    `rsp_close` / `conn_close`, and feedback-side `response_class`
    preservation of the raw reply codes instead of only `state_N`
  - `run_aflnet_bizone_smoke.py --seed-dir aflnet/tutorials/mockftp/in-ftp-timeout --force-hints= --force-retry-chain 0 --allow-no-active-timing-plan`
  - validates explicit timeout outcome labels `rsp_timeout` / `conn_timeout`
    and feedback-side timeout classification on a no-response FTP control path
  - `aflnet/tutorials/mockrtsp/mock_rtsp_server.c`
  - `run_aflnet_bizone_smoke.py --protocol RTSP --seed-dir aflnet/tutorials/live555/in-rtsp`
  - validates `keepalive_synthesized`, `keepalive_contextual`,
    `keepalive_profile=rtsp-options-contextual`, `session_open`,
    `session_activity`, and injected `OPTIONS` requests in the event trace
  - `run_aflnet_bizone_smoke.py --protocol RTSP --seed-dir aflnet/tutorials/live555/in-rtsp --disable-test-hint-overrides --force-retry-chain 0 --replay-passes 2`
  - validates adaptive RTSP keepalive reuse from first-pass feedback:
    replay pass 2 now preserves `keepalive_profile=rtsp-options-contextual`,
    `keepalive_contextual=1`, preferred class `options`, and
    `session_open -> session_activity` guidance when it reuses an existing
    RTSP `OPTIONS` keepalive instead of relying on test-only overrides
  - `aflnet/tutorials/mocksip/mock_sip_server.c`
  - `run_aflnet_bizone_smoke.py --protocol SIP --seed-dir aflnet/tutorials/mocksip/in-sip`
  - validates `keepalive_synthesized`, `keepalive_contextual`,
    `keepalive_profile=sip-options-contextual`, and injected `OPTIONS`
    requests in the event trace even for LF-ended SIP seeds
  - `run_aflnet_bizone_smoke.py --protocol SIP --force-hints retry --force-retry-chain 1 --force-gap-ms 1000`
  - validates `retry_profile=sip-invite-retransmission`, transaction-aware
    `invite` / `rtx` / `invite_rsp` SIP trace labels, and `sip_tx_<hash>`
    helpers in both event traces and monitor feedback
  - `aflnet/tutorials/mockdtls/mock_dtls12_server.c`
  - `run_aflnet_bizone_smoke.py --protocol DTLS12 --network-scheme udp --seed-dir aflnet/tutorials/mockdtls/in-dtls`
  - validates `keepalive_synthesized`, `keepalive_contextual`,
    `keepalive_profile=dtls12-clienthello-contextual`, and binary
    `req_clienthello` event traces over UDP
  - `run_aflnet_bizone_smoke.py --protocol DTLS12 --network-scheme udp --force-hints retry --force-retry-chain 1 --force-gap-ms 1000`
  - validates `retry_profile=dtls12-clienthello-retransmission`,
    `retry_contextual=1`, and the DTLS initial-retransmission scheduling path
  - `run_aflnet_bizone_smoke.py --protocol DTLS12 --network-scheme udp --exec-timeout-ms 8000 --force-hints retry --force-retry-chain 0 --force-gap-ms 1000 --expect-retry-insertion-count 3 --expect-pre-send-delays 1000,2000,4000`
  - validates the DTLS multi-step backoff / boundary-bisection path:
    auto-derived three-step retry insertion, canonical `1s/2s/4s`
    pre-send delays, `cross_request_resend=0`, contextual retry metadata, and
    the first ordinal retransmission label `rtx1`
  - `aflnet/tutorials/mockdicom/mock_dicom_server.c`
  - `run_aflnet_bizone_smoke.py --protocol DICOM --seed-dir aflnet/tutorials/dcmqrscp/in-dicom --force-hints keepalive --force-retry-chain 0`
  - validates contextual DICOM association-activity guidance by reusing live
    `P-DATA-TF` context, exposing `keepalive_profile=dicom-pdata_tf-contextual`,
    `keepalive_contextual=1`, and binary `req_pdata_tf` event traces
  - `run_aflnet_bizone_smoke.py --protocol DICOM --seed-dir aflnet/tutorials/dcmqrscp/in-dicom --disable-test-hint-overrides --force-retry-chain 0 --replay-passes 2`
  - validates adaptive DICOM keepalive reuse from first-pass feedback:
    replay pass 2 consumes feedback-derived hints, preserves
    `keepalive_profile=dicom-pdata_tf-contextual`,
    `keepalive_contextual=1`, preferred class `pdata_tf`, and
    `acse_rsp -> pdata_tf` guidance instead of relying on test-only overrides
  - `run_aflnet_bizone_smoke.py --protocol DICOM --seed-dir aflnet/tutorials/dcmqrscp/in-dicom --force-hints retry --force-retry-chain 1 --force-gap-ms 1000`
  - validates contextual DICOM ACSE retry guidance by preferring
    `A-ASSOCIATE-RQ` as the retry source and exposing
    `retry_profile=dicom-associate_rq-retransmission`,
    `retry_contextual=1`, and binary `req_associate_rq` traces
  - `aflnet/tutorials/mockssh/mock_ssh_server.c`
  - `run_aflnet_bizone_smoke.py --protocol SSH --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh --force-hints keepalive --force-retry-chain 0`
  - validates contextual SSH pre-auth guidance by reusing live `KEXINIT`
    context, exposing `keepalive_profile=ssh-kexinit-contextual`,
    `keepalive_contextual=1`, binary `req_kexinit` event traces, plus
    replay-aligned `conn_open` / `auth_done` labels on the stock SSH replay
  - `run_aflnet_bizone_smoke.py --protocol SSH --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh --disable-test-hint-overrides --force-retry-chain 0 --replay-passes 2`
  - validates adaptive SSH post-auth keepalive reuse from first-pass feedback:
    replay pass 2 preserves `keepalive_profile=ssh-global_request-contextual`,
    `keepalive_contextual=1`, preferred class `global_request`, and positive
    `auth_done -> global_request` evidence while the first-pass final
    `auth_done/completed` row still truthfully omits authenticated keepalive
    candidates until the replay-derived adaptive handoff is applied
  - `run_aflnet_bizone_smoke.py --protocol SSH --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh --disable-test-hint-overrides --ssh-truncate-after-request-class service_request --force-retry-chain 0 --replay-passes 2`
  - validates the synthesized SSH fallback path separately:
    replay pass 2 preserves `keepalive_profile=ssh-ignore-contextual`,
    `keepalive_contextual=1`, preferred class `ignore`, positive
    `auth_done/authenticated -> ignore` keepalive evidence, and the absence of
    unrelated `disconnect` candidates on the authenticated `auth_done` row
  - `run_aflnet_bizone_smoke.py --protocol SSH --seed-dir profuzzbench/subjects/SSH/OpenSSH/in-ssh --force-hints retry --force-retry-chain 1 --force-gap-ms 1000`
  - validates SSH handshake retry guidance by preferring `KEXINIT` as the
    retry source and exposing `retry_profile=ssh-kexinit-retransmission`,
    `retry_contextual=1`, and binary `req_kexinit` traces
- Initial official-source-backed PropertyCard bundle for:
  - `SIP`
  - `DTLS`
  - `RTSP`
  - `DICOM`
  - `SSH`

## Current boundary

The repository now supports the M1 monitor/feedback/logging milestone and the
first executable M2 slice inside AFLNet. Live multi-channel feedback is already
consumed during fuzzing, and the first timing-aware mutation operators are
implemented and smoke-tested.

That means:

- feedback production is implemented
- logging and visualization are implemented
- multi-feedback frontier / obligation / progress / explainability evidence now
  survives raw-log aggregation into dashboard-ready artifacts
- PropertyCard validation/replay is implemented
- AFLNet timed-trace capture is implemented
- AFLNet multi-channel seed scheduling is implemented
- the first hint-driven timing mutation schedule is implemented

The remaining boundary is now narrower:

- broader protocol coverage for keepalive synthesis and richer cross-request
  timing hybrids are still pending beyond the current retry-chain /
  delay-resend / keepalive-retry hybrid slice, although RTSP, SIP, DTLS,
  DICOM, and now SSH have contextual guidance paths and DTLS now has a
  verified multi-step retransmission/backoff slice
- the RVEM dashboard plus the first paper-facing figure bundle are now
  concrete, but the full target figure set in the research plan is still not
  exhausted
- the main-study PropertyCard bundle is only an initial draft artifact and still
  needs the remaining extraction/review/publication workflow steps for a
  paper-final release
- larger ProFuzzBench campaign automation and full ablation runs are still
  pending

## Recommended next integration points

1. Extend timing mutation from the current retry-chain / delay-resend /
   keepalive-retry hybrid operators to broader protocol coverage and richer
   cross-request timing hybrids, using the RTSP/SIP/DTLS/DICOM/SSH contextual
   guidance path as the reference template; the next natural step is denser
   paper-ready property coverage plus authenticated-phase protocol guidance.
2. Persist quick-look campaign metadata (`mode`, `subject`, `property_set_id`)
   in ProFuzzBench wrappers so RVEM plots regenerate automatically.
3. Automate the main-study protocol/property bundle and ablation runs for the
   24-hour campaign matrix.
