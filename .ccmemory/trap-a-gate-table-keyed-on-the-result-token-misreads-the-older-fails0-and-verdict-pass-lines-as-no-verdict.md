---
name: trap-a-gate-table-keyed-on-the-result-token-misreads-the-older-fails0-and-verdict-pass-lines-as-no-verdict
description: TRAP (s73, capture gate table): 17 of 59 healthy laps print "=== harness label: fails=0 wall=Ns ===" or "VERDICT PASS", not "RESULT: PASS"; a RESULT-…
metadata:
  type: feedback
---

# A gate table keyed on the RESULT token misreads the older verdict lines as "no verdict"

**What happened (s73, D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT closure table).** A miner built the per-entry table of the capture gate's latest healthy lap from the 150 `*_capture_gate_*` dirs, classifying each `<harness>_ok.log` by its `RESULT:` line. It reported 19 entries with "a healthy log but no RESULT line". A second sweep that printed each log's tail showed 17 of them are PASSING laps in the older verdict format:

- `=== <harness> <label>: fails=0 wall=50s out=... ===` (tcp_stale_resend, dlm_wait_signal, transport_conformance, d0287_2node_death_rejoin, tcp_lockreq_blackhole, live_holder_wait, d0947_nomagic_repick, d0946_recycle_platter_assert, d0963_sf_lagging_flush, depart_takeover_unmount, join_during_takeover, d_intents_2tcp_open_efi, f2_iclus_refusal)
- `VERDICT PASS: ...` / `=== VERDICT PASS label=... ===` (d512_t1_reuse, d512_t2_pause, d512_race_verify, intents_classless_attribute)

Only 2 of the 19 (d0977_open_unlink_tcp, d0531_stale_slice_recovery) genuinely had no healthy lap.

**Two more things the same job taught.** (1) 25 of the 150 gate dirs are chunk runs (`..._capture_gate_s58g-c01`) whose directory name does not contain the harness name; matching a harness to its dir by the name suffix silently drops most of the fault-lap evidence. Match on the `<harness>_fault.log` / `<harness>_ok.log` filenames the gate writes (tests/capture_fault_gate.sh header). (2) The gate itself only reads `^RESULT` (`res=$(grep -a '^RESULT' ...)`), so the gate's own summary of an older-format lap is also "no RESULT" — the ok.log's last lines are the evidence, not the gate's one-line summary.

**The rule.** When tabulating harness verdicts, classify by ALL the verdict shapes in the tree — `RESULT: <STATUS>`, `RESULT <STATUS> <label>:`, `=== ... fails=<n> ...===`, `VERDICT PASS|FAIL` — and treat "no line matched" as "read the tail", never as a category. A miner's "none" bucket is a selection wearing evidence's clothes until the tails have been read.
