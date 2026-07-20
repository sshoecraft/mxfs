---
name: AAA-ccloopa864-sess6-HANDOFF-diagrun-live-r5-clean-watch-outcome
description: sess6 HANDOFF: dir_reuse@32/caw run (v0.10.53 C98E4152) reached r8 (PAST baseline wedge!) — wedge#2a FIXED (override fired). Now relabort climbing (w…
metadata:
  type: project
---

## sess6 (ccloop a864) HANDOFF — wedge#2a FIXED (reached r8, furthest ever); wedge#3 now the risk

### CRITERIA: sole gap = dir_reuse_coherency@32/caw (all other 1/2/4/8/16/32 caw cells PASS; zero FAIL). PASS that cell → criteria met.

### BIG WIN: wedge#2a is FIXED. The sync_wait completion-routing fix works.
Run of **v0.10.53 / C98E41521CB5C45CFF49804** reached **r8** (baseline wedged r3, v0.10.52-run r1 — this is the FURTHEST EVER). `iowait_stuck=0` throughout; `P-SYNCWAIT-OVERRIDE` FIRED (override=1) = the fix actively caught the XBF_ASYNC-flip lost-wakeup race and rerouted to complete(&b_iowait). **KEEP the v0.10.52 fix — it is correct and proven.**

### NEW RISK at r8: wedge#3 (release-abort livelock) — relabort climbing
At r8: **relabort=1811 and climbing** (was ~300 at r1-r6). This is the sess5 wedge#3 = P15-REL-ABORT release-abort livelock on the hot shared dir ino=131 (local re-acquire beats the pending peer BAST during the release drain → handoff never completes → peers starve). The run is STILL ADVANCING through r8 (not frozen), so it's grinding, not dead — but the danger is **PACE DEGRADATION → RULE-0 timeout** (budget 4480s / ~75min; r8 hit at ~16min = ~2min/round; if later rounds slow, won't reach r24).

### LIVE — DO NOT KILL. Terminal waiter **blcke0chk** fires ONCE on run-exit (PASS/FAIL + criteria.json status) or sustained wedge (iowait_stuck>=30 + captured diag line). Per-round monitor was stopped to save context.
- **FIRST ACTION next session:** read blcke0chk.output (+ scratchpad/diag_run.log tail, `pgrep -f 'run.sh 32 caw'`).
  - **PASS 24 rounds nodes_pass=32/32** → verify criteria.json dir_reuse@32/caw=PASS, spot-check 8/16-caw dir_reuse no-regression → `echo YES > /src/mxfs/.ccloop/runs/a8642ea1-81eb-4fcd-beea-b99f4f52db31/criteria-met`.
  - **TIMEOUT or wedge on relabort/starvation (P138-WAIT climb, round frozen, iowait_stuck stays 0)** → implement WEDGE#3 fix (below).

### WEDGE#3 FIX (if needed) — design from sess5 memories [[AAA-ccloopa864-sess5-WEDGE3-release-abort-livelock-ino131]] + [[AAA-ccloopa864-sess5-HEAD-diagnostic-run-and-pathB-plan]]:
1. Make **`mxfs_caw_fair_handoff=1` DEFAULT** (dlm/dlm_caw.c:88 `int mxfs_caw_fair_handoff = 1;`) — currently 0. Makes a fresh local CAW acquirer DEFER to a pending peer yield-ticket so the release completes + hands off. sess5 measured it PARTIAL alone (r8→r11).
2. **Fix the release-abort livelock at the abort site xfs_mxfs_dlm.c:12056** (`if (gen_moved || pin_only || orphan_live) {...abort...}`): make it STARVATION-AWARE — when a peer BAST has starved past a threshold, PROCEED with the handoff instead of aborting; OR gate the DIR fast-path re-acquire (xfs_mxfs_dlm.c ~19247, the dir-strict gate) so a fresh local EX acquirer (ex_holders==0 && pr_holders==0 && pin==0) DEFERS to slow-path when i_dlm_bast_pending is set → the pending release completes → peer served. (BAST-priority over local re-acquire.) Instrument first per RULE 4 (P15-REL-ABORT already fires — that IS the instrumentation).
3. Config defaults: inode_mht_ms=300, dir_ex_tenure_floor=1, dir_ex_batch_grace_ms=25, caw_orphan_force_ms=3000.

### ROOT wedge#2a (fixed, reference): lost b_iowait wakeup on durable_signal sync xfs_bwrite (owner_scan dir3_leafn / bmbt_scan xfs_bmbt) — completion routed to XBF_ASYNC relse branch not complete(). Fix = b_mxfs_sync_wait snapshot (xfs/xfs_buf.h) at xfs_buf_submit, routed in xfs_buf_ioend + xfs_buf_bio_end_io. Diag fields sync_wait/ioend_seen/relse_seen in P-IOWAIT-STUCK probe.

### Mechanics: MXFS_DEV=/dev/mapper/mpatha. SSH `bash tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass '<cmd>'`. NEVER rebuild while a run active. `pgrep -f 'make modules'` self-matches waiter shells → `pgrep -x make`. run.sh prep re-mkfs's+power-cycles all 32+asserts srcversion.
</body>
