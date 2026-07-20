---
name: sess53-residual-durable-dirent-resurrection-stale-dir-flush
description: sess53: plain defaults+P52 = 4/5; sole residual = DURABLE dirent resurrection (stale dir flush, NOT sf-merge). sf_merge=0 REFUTED (still leaks + regr…
metadata:
  type: project
---

## sess53 — the ONLY residual on plain defaults is durable dirent resurrection (stale dir flush)

### Reliability measured (PLAIN `./run.sh 2 tcp`, build B9258412 = D67776EC + P53 diag, default sf_merge=1, dir_pr_release_fast=1):
**d1,d2,d3,d4 = PASS 17/17; d5 = FAIL** (tcp_dlm_scaling `tds shared dir drained got=1`,
TDS-LEFTOVER n2_r120). = **4/5**. Sole failure face = durable dirent leak. ~540s/run healthy.

### THE RESIDUAL = durable dirent RESURRECTION via STALE DIR FLUSH (NOT the sf-merge)
d5 forensics (cluster live, drop_caches): leftover `n2_r120` visible on BOTH nodes after
drop_caches → DURABLE (on-disk), shortform dir (fmt=1). At node1's reload: P62-RELOAD-FORK-SHRINK
`incore_size=21 disk_size=21 incore_gen==disk_gen`, P-SFMERGE count=1 → **disk ALREADY had n2_r120
at reload time**. So resurrection happened on DISK before the reload. Mechanism: node2 removes
n2_r120 (mv n2_rN→.done); node1 still holds a STALE in-core dir (missed node2's removal — the
EVICT-RING-DIRMOD DIR_MODIFY signal is asymmetric/lossy, GPT memory: node1 gets ~0 DIR_MODIFY);
node1 acquires EX, modifies (adds n1_rX), and FLUSHES THE WHOLE SHORTFORM DINODE → writes n2_r120
back to disk (resurrection). This is the [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]
problem: a stale in-core dir fork reaching the on-disk dinode. The reload-on-acquire did NOT fire
(or loaded the already-resurrected disk) because the trigger (evict-ring gen bump) was missed.

### REFUTED this session
- **sf_merge=0 (adopt-disk on reload)**: e1 PASS, **e2 FAIL 15/17** (STILL leaked n2_r60 + REGRESSED
  fence_during_write 1/2). Disabling the 3-way SF merge does NOT fix the leak (proves the merge is
  not the resurrection vector — adopt-disk still sees the resurrected disk image) and is strictly
  worse. **KEEP sf_merge=1 (code default; no change needed).** Do NOT pursue sf_merge=0.
- option B (dir_pr_release_fast=2): unreliable (iunlink/trans_cancel shutdowns + leak). Do NOT use.
  Plain defaults (dir_pr_release_fast=1) is better. See [[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]].

### NEXT (the real fix): make dir reload-on-ACQUIRE reliable (GPT Step 2/4)
node1 must reload the dir from the canonical disk image on EX/PR acquire WHENEVER a peer modified it
since node1's last load — using a RELIABLE signal (DLM grant epoch / shared on-disk dir epoch), NOT
the lossy evict-ring. Then node1 never flushes a stale fork. OR Step 4: fence the dir-inode fork
flush (xfs_iflush_cluster / mxfs_iflush_cluster_merge_dirs flushing-slot branch) to refuse writing a
dir dinode whose fork wasn't validated under the current epoch. Investigate i_dlm_dir_gen bump sites +
the acquire-reload decision (is it gated on the lossy ring gen?). Fast repro is hard (intermittent
~1/5 full suite; warm-FS repeat driver INVALID — node2 trans_cancel:1061 crash cascades). 
Marker NOT written (4/5, not 100%).
