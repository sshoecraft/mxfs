---
name: sess46-dirwr-confirms-writeside-leaf-clobber-and-fix-plan
description: sess46 dirwr=1 run CONFIRMS write-side leaf CLOBBER is real (P-LEAFWRITE fires). Refined fix: content-based subset-check clobber suppression at leaf-…
metadata:
  type: project
---

## sess46 — dirwr=1 diagnostic findings + REFINED FIX PLAN for dir_reuse leaf-hash

### dirwr=1 run (full suite) findings:
- **P-LEAFWRITE tag=CLOBBER FIRES** (count=2, in rsync_paired before dir_reuse) — node1 IS about to write a leaf block that drops the peer's committed hashvals. **Write-side clobber is REAL**, not just read-side staleness. So node1's stale-base leaf, when it destages (the test's `sync` forces it while node1 holds EX → skip_dir_write doesn't suppress EX-held), CLOBBERS node2's entries on the LUN.
- **dirwr=1 PERTURBS badly**: test1 SHUT DOWN on crash_consistency with `!(flags & XFS_DABUF_MAP_HOLE_OK)` at xfs_da_btree.c:2814 → xfs_create → xfs_trans_cancel → Corruption(0x8) shutdown. This is the dir EXTENT-MAP hole (stale in-core extent map, peer allocated a block node1's map doesn't have). Same dir-coherency family, MORE severe. dirwr's heavy FUA reads change timing → surfaces it. **dirwr is NOT a clean repro vehicle** (it shuts down + makes rsync_paired/crash_consistency fail on timing). Use normal runs + the always-on DIR-STALE-SKIP probe.
- rsync_paired FAIL under dirwr = timing artifact (90s window blown by FUA reads), NOT a real regression (passes normally).

### REFINED FIX (next session — implement carefully, false-positive guards are CRITICAL = sess23 corruptor class):
**Content-based leaf-write CLOBBER suppression at the bio-submit chokepoint** (pal/linux/xfs_buf.c, near the P-LEAFWRITE detector ~line 2309, and the call site that emulates clean ioend ~2008). Promote P-LEAFWRITE from detector to SUPPRESSOR:
 1. GATE (perf, RULE 0): only when multi-node AND leaf buffer (xfs_dir3_leaf1/leafn_buf_ops) AND `bp->b_mxfs_dir_gen < owner_dir->i_dlm_dir_gen` (peer modified since this buf was stamped). This limits the FUA read to suspected-stale leaf writes.
 2. FUA-read the disk leaf (p56_tmp already does this).
 3. PRECISE clobber check (NOT the current sum+xor fingerprint — too broad, flags legit SUPERSET writes): sorted-merge the hashvals; suppress ONLY if **disk has a hashval the buffer LACKS** (disk ⊄ buf). A legit superset write (buf ⊇ disk) must NOT be suppressed.
 4. INCARNATION GUARD (avoid sess23 fresh-block corruptor): only suppress if the disk block is the SAME incarnation (xfs_dir3_blk_hdr.owner == this dir's ino AND not a reused-daddr prior incarnation). A fresh/first leaf write over a prior-incarnation/empty disk block must NOT be suppressed.
 5. On suppress: emulate clean ioend (like mxfs_buf_xfsaild_skip_dir_write call site) → removes the buf's log item from AIL CLEANLY (no unsafe in-AIL BLI abort) → buffer becomes clean → consumer_refresh/drop_caches re-reads the disk SUPERSET → lookup OK.
 - WHY this is the safe vector: protects the LUN (no clobber), avoids the unsafe in-AIL abort (emulated ioend is the safe completion), content-precise (not gen-based). RISK: false-positive suppression of a legit write = corruption — the subset + incarnation guards prevent it; TEST that node1's OWN new entries still lookup-able (they should be in node2's superset via the merged data-block, readdir=200).
 - CAVEAT: if node1's last entries were NOT in node2's superset (mutual divergence), suppression loses them → lookup fails for node1's files instead. If TEST shows this, the real fix is UPSTREAM (re-read disk leaf before RMW) — but that needs safe in-AIL eviction (the harder path).

VALIDATE: clean virsh reboot, full `./run.sh 2 tcp` ×3 for 17/17 + no shutdown + perf within budget (tcp_dlm_scaling/rsync_paired). [[sess46-PROVEN-dir_reuse-leaf-hole-is-async-evictring-lag-stale-leaf-RMW]] [[sess46-dir_reuse-fix-vectors-and-hazards-map]]</body>
