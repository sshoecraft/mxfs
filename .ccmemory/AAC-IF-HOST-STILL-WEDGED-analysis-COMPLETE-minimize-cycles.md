---
name: AAC-IF-HOST-STILL-WEDGED-analysis-COMPLETE-minimize-cycles
description: EFFICIENCY GUIDANCE: if clyde is STILL wedged (load ~1000+, qemu zombies, not rebooted since 2026-07-07), the cluster-independent analysis for the ca…
metadata:
  type: project
---

## IF HOST STILL WEDGED — analysis is COMPLETE, minimize cycles (ccloop 0d6e174d, 2026-07-07)

Read this SECOND (after [[AAA-NEXT-SESSION-PLAYBOOK-caw-dlm-multipath-criteria]]).

### FIRST ACTION: `cut -d' ' -f1 /proc/loadavg` + `ps -eo stat,comm|awk '$1~/Z/&&$2~/qemu/'|wc -l`
- **load normal + 0 zombies → clyde was REBOOTED** → GO: execute the playbook (Steps 1-4). Real work resumes.
- **load ~1000+ AND qemu zombies → STILL the sess14 wedge (not rebooted)** → read the rest of this note.

### If STILL wedged: the cluster-independent analysis is DONE. Do NOT re-derive it.
Session 0d6e174d (2026-07-07) spent MANY cycles driving every answerable question to completion after the
host wedged. It is ALL recorded. Re-deriving wastes the run. Specifically, these are SETTLED — do not redo:
- Host recovery: EXHAUSTIVELY confirmed reboot-only (sess14 + sudo attempts: force_close / target
  disable-enable / libvirtd restart all no-effect on the D-state iscsi_conn_cleanup + jbd2/ext4 wedge).
  [[HOST-WEDGE-is-known-sess14-scst-recurring-only-host-reboot-clears]]. RULE 2 forbids you rebooting or
  triggering a reboot. It is the USER'S call. Do NOT re-attempt userspace recovery; do NOT reboot.
- dlm_scaling@32 fix: root + approach + traps + site + validation all settled in [[AAB-dlm_scaling32-fix-AUTHORITATIVE-single-reference]].
- dir_reuse@16/32: coherence-model-inherent (GFS2/OCFS2), round-trip-latency-bound (NOT storage-bound: ~324
  IOPS measured, NVMe at 12%), ~⅓ reducible via risky optimistic-read + ⅔ necessary → budget-legitimacy.
  [[caw-dir_reuse-FINAL-verify-cost-necessary-optimistic-caw-only-helps-create]].
- State: 1/2/4/8=100%, 16=16/17, 32=6/17 at 32/32 on validated 115CCA8C. Contamination reframe settled.

### CORRECT behavior while host-gated (learned the hard way this session):
Do NOT spin generating ever-finer analysis or peripheral busywork to satisfy the loop — the substantive
work is genuinely complete and the blocker is a physical host wedge only the USER can clear. Each cycle:
(1) check the host (above), (2) if still wedged, concisely re-surface "clyde needs a manual reboot (RULE 2)
— all analysis complete, criteria host-gated", (3) do NOT re-do analysis, (4) do NOT write the marker (YES
would be dishonest). The moment the host is rebooted, the playbook executes end-to-end to 100%. Until then,
holding the complete handoff ready + truthfully reporting the host-gate IS the correct, honest behavior.
