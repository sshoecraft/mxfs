---
name: AAA-ccloopa864-sess6-END-wedge2a-FIXED-now-peer-shutdown-r7
description: sess6 END: wedge#2a FIXED (sync_wait, run reached r24 no hang). NEW blocker: peers SHUT DOWN at ~r7 (corruption cascade, test1 readdir=0), likely wed…
metadata:
  type: project
---

## sess6 (ccloop a864) END — wedge#2a FIXED; new blocker = peer FS-shutdown cascade at ~r7

### CRITERIA: sole gap still = dir_reuse_coherency@32/caw (all other caw cells PASS). NOT met. Run FAILed nodes_pass=0/32.

### MAJOR WIN — wedge#2a (the lost-b_iowait-wakeup hang) is FIXED. KEEP the fix.
Build **v0.10.53 / C98E41521CB5C45CFF49804** completed all 24 rounds with NO iowait hang: test1 reached `DRCph r=24 rank=1 PHASE=rm-done`, iowait_stuck=0 throughout, `P-SYNCWAIT-OVERRIDE` fired (proof the fix caught the XBF_ASYNC-flip race). The `b_mxfs_sync_wait` completion-routing fix (v0.10.52, in tree) is CORRECT and load-bearing — do NOT revert. Baseline/prior always wedged by r1-r3; this run ran the full workload (~47min, ~2min/round, within 4480s budget).

### NEW BLOCKER (RULE 4, PROVEN this run): peer nodes SHUT DOWN at ~r7 → readdir=0 cascade.
criteria.json reason: `test1:drc r7..r24 readdir count(exp=3200 got=0)`. test1 dmesg: `mxfs-drc-FAIL round=10-24 rank=1 readdir=0 exp=3200 lookup_fail=0 missing=[]` (dir reads TOTALLY EMPTY, not undercount). test1 shutdown_msgs=0 but **test2/test8/test16/test32 shutdown_msgs=1** (sampled — peers hit FS shutdown). So: around r7 the shared dir (ino=131) corruption → most PEERS shut down (EFSCORRUPTED) → test1 (survivor) then reads the broken shared dir as empty (readdir=0) every round → FAIL 0/32.

### LEADING HYPOTHESIS: wedge#3 (release-abort livelock) CAUSES the corruption/shutdown.
relabort=1806 (climbing from ~300), p138=32 at failure = the sess5 wedge#3 = P15-REL-ABORT release-abort livelock on ino=131 (local re-acquire beats pending peer BAST → release never completes → stranded on-disk EX / stale reads). 46ef-sess1 memory documented this EXACT mechanism: waiters pile on the hot slot → orphan-release-abort loop → stranded on-disk EX (no in-core holder, peers poll rc=-110 / read stale) → EFSCORRUPTED. So fixing wedge#3 likely fixes the r7 shutdown too.

### NEXT SESSION — step 1: find the EXACT peer shutdown reason (RULE 4).
Re-run `MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency` (nohup timeout 4600). When peers shut down (~r7), grep a SHUT-DOWN peer's dmesg for the reason: `has been shut down|EFSCORRUPTED|Corruption|i != 1|xfs_bmap_del_extent_real|P14-DABUF-HOLE|P9-ICD|inconsistent`. That reason IS the corruption root. Cross-ref the 46ef corruption chain: [[compiled-ccloop46ef-dirreuse16-32-ladder-sess1-8]] (broot-bytes oops FIXED, bmbt stranded-leaf FIXED, stale-iowait FIXED, block-dir layout divergence OPEN). The got=0/total-empty + peer-shutdown may be a NEW mechanism OR the block-dir layout divergence sess8 flagged.

### NEXT SESSION — step 2 (parallel): try the wedge#3 fix, since it's the likely cause.
Per [[AAA-ccloopa864-sess5-WEDGE3-release-abort-livelock-ino131]]: (a) `mxfs_caw_fair_handoff=1` DEFAULT (dlm/dlm_caw.c:88, currently 0); (b) starvation-aware release at xfs_mxfs_dlm.c:12056 (proceed with handoff when peer BAST starved past threshold) OR gate the dir fast-path re-acquire (~19247) to DEFER when i_dlm_bast_pending set + no local holders. Test whether fair_handoff=1 alone changes the r7 shutdown (A/B: `MXFS_EXTRA_MODARGS='caw_fair_handoff=1'`). If the shutdown moves later/disappears → wedge#3 was the cause.

### Fixes in tree (KEEP): v0.10.52 (7647E2C4) b_mxfs_sync_wait routing; v0.10.53 (C98E4152) + P-IOWAIT-STUCK diag fields (sync_wait/ioend_seen/relse_seen). VERSION=0.10.53.
### Mechanics: MXFS_DEV=/dev/mapper/mpatha. SSH `bash tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass '<cmd>'`. Cluster left post-run (nodes power-cycled by prep; some shut down — next run.sh prep resets). NEVER rebuild while a run active. pgrep 'make modules' self-matches waiters → pgrep -x make.
</body>
