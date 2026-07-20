---
name: sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0
description: sess28(ccloop) DECISIVE on a CLEAN cluster: dir_reuse 8/tcp loss is WRITE-SIDE (read fully coherent: diff1=0 over 300 samples, p28c=0, rdmiss=1). Rea…
metadata:
  type: project
---

## sess28 — CORRECTED & DECISIVE: the dir_reuse 8/tcp loss is WRITE-SIDE (read is coherent)

### The clean experiment (build 52EED814, dir_addname_coherent=1, DRC_ROUNDS=24, NO concurrent driver)
`drc_one.sh 1 24` → RESULT FAIL, all 8 nodes: **p28e=300 diff1=0 p28c=0 rdmiss=1 corrupt=0**.
- p28e=300 = the addname coherence helper REACHED the FUA platter read 300+ times (capped) — it IS being called for the storm dir (ino<=256).
- **diff1=0** = in 300 sampled first-clean-add platter checks, the in-core dir DATA block NEVER diverged from the platter. The read base is ALWAYS coherent at addname.
- **p28c=0** = the read-side fix (mxfs_dir_addname_coherent_refresh) detected ZERO stale bases this entire failing run.
- **rdmiss=1, corrupt=0** = a clean single-dirent durable loss, NO shutdown.

### CONCLUSION: read is coherent → the loss is WRITE-SIDE. The read-side fix is a DEAD END for this loss.
The dirent is added onto a COHERENT base (diff=0), then VANISHES durably afterward — a stale dir-block DESTAGE reverts the committed entry. This CONFIRMS the sess27 write-side verdict (P28-PLATTER 76 MATCH / 0 DIFFER = in-core==platter) and the sess22/sess11 "logged-then-vanishes" finding.

### IMPORTANT correction to earlier sess28 (do NOT be misled):
[[sess28-PROVEN-readside-staleness-targeted-platter-guard]] claimed READ-SIDE (P28W-CLOBBER REAL: platter had node5_f1.md5 at our slot). That was almost certainly a CONTAMINATION ARTIFACT: a surviving background driver (`drc_diag.sh 8 1`, pid 1378265) ran run.sh CONCURRENTLY with my drc_platter/drc_one runs for ~43 min — TWO drivers mkfs'ing+writing the SAME shared LUN = genuine cross-run divergence that looked like a peer's durable entry at our slot. On a verified-single-driver run, diff1=0 (no read divergence). **LESSON: ALWAYS `ps -eo cmd|grep run.sh` to confirm NO surviving background driver before trusting an 8-node result — pkill -f on the driver name repeatedly FAILED to kill it; kill the driver PID explicitly and verify.**

### NEXT SESSION — target the WRITE side (sess22 GPT-L2 / sess40 ABA):
The committed dirent is reverted by a STALE dir-DATA-block writeback. Candidates: (a) a NON-EX-holder's xfsaild destaging an OLD cached copy of the block (cached before the entry was added) over the platter; (b) an EX-holder destaging a stale RMW base (but diff=0 says the base is coherent at addname, so (a) is more likely). FIX direction: enforce "no dir-DATA-block writeback by a node that does not currently hold the dir EX" (the GFS2/OCFS2 invariant — only the lock holder writes the locked domain's metadata). Instrument the dir-data bio write chokepoint (pal/linux/xfs_buf.c, where mxfs_buf_xfsaild_skip_dir_write / P16-DIRBLK-SUBMIT live) with a CONTENT-superset check: is the block being written MISSING an on-disk inumber that the platter has? (same-incarnation). If so, SUPPRESS the write (like P126 AG-meta / P60 bmbt writeback suppression). See [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]] (incarn-based, for DEAD-incarnation ABA — this is SAME-incarnation, needs a content/owner-EX check), [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]] (L2 demote invariant), [[sess27-DEFINITIVE-read-coherent-platter-MATCH-loss-is-stale-write-revert]].

### Keeper build 52EED814: dir_addname_coherent DEFAULT 0 (read-side fix off — proven not to fix; kept as A/B lever). All sess28 changes gated off at default -> behaviorally == prior keeper 164A6D5D. The only ungated change: inert b_mxfs_coherent_gen field on xfs_buf. Cluster clean, 8 nodes up. Tooling: tests/tcp/drc_one.sh (single instrumented run), drc_diag.sh (multi-run shut/rdmiss/p28c capture). CRITERIA NOT MET.
