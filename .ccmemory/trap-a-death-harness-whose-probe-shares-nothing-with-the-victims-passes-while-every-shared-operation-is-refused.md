---
name: trap-a-death-harness-whose-probe-shares-nothing-with-the-victims-passes-while-every-shared-operation-is-refused
description: TRAP (0.90.25, 8/tcp 2 victims): own-file write probes never stalled + chk rc=0 = PASS, while an AG was quarantined and every load cycle got EIO.
metadata:
  type: feedback
tags: [harness, vacuous-pass, recovery, quarantine, multi-victim]
---

# A death harness whose probe shares nothing with the victims passes while every shared operation is refused

**What happened (0.90.25, first run of `tests/multi_victim_containment.sh`,
8/tcp, victims test3+test6, evidence
`tests/evidence/multi_victim/20260929T150342Z_8tcp_x8b`).** The harness printed
`VERDICT PASS`: all six survivors mounted, no shutdown line, write probes
`wrote_again=+0s longest_silence=2s`, `chk_mxfs rc=0`.

What had actually happened, read from two numbers the verdict did not use:

- `load=cycles=8648` on test1 against ~490 on the others: a load loop spinning
  because every `rm -rf`/`rsync` in it failed at once.
- `recovered_lines=1` cluster-wide for two victims.

Every survivor's `/tmp/mvc_load.log` held ~480 lines of
`rm: cannot remove '/mnt/shared/.mvc_load/nodeN': Input/output error`; the
kernel logs held `P241-RECOV-TERMINAL slot=3 ... slice replay REFUSED
(reason=1 domain=2 ag_mask=0x8 refused=3 ...)`, `P240-QUAR-IMPORT ... victim
recovery domain QUARANTINED: operations touching it fail with EIO until
operator repair + remount`, and 470-480 `P240-RBLK-EIO-ABORT` (or
`P240-QUAR-NSOP-REFUSE`) per survivor.

**Why the oracle missed it.**
1. Each probe wrote a file of its own in a directory the victims never
   touched, so it needed nothing a victim held and nothing in the quarantined
   allocation group.
2. `chk_mxfs` exits 0 with a refused, quarantined slice on the platter: a
   clean check is not evidence that every victim was recovered.
3. The load loop's exit codes went to /dev/null.

**What the harness judges now:** the load loop (which shares a parent
directory with the victims) must meet no error and no silence past the write
budget; no quarantine line and no refused operation on any survivor; a
completed recovery logged for every victim.

**Rules of thumb.**
- A death test's probe must go through state the victim held (the shared
  directory, the same allocation group), or it measures the survivors' own
  caches.
- Read every count the harness prints against what it should be (two victims
  need two recoveries) before reading its verdict.
- An outlier in a throughput number (18x the cycles of its peers) is an error
  path returning early until shown otherwise.
