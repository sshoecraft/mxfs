---
name: sess89_lessons
description: "sess89 — bnobt cross-node lost-update ROOT identified (Gemini RULE-5): post-release xfsaild clobber via CIL→AIL race in bast_work_fn handoff. Probe-A built (0BC933EE), NOT yet deployed/proven."
metadata:
  node_type: memory
  type: project
  originSessionId: 29df431e-loop-sess89
---

# sess89 (2026-06-05, ccloop) — bnobt lost-update ROOT (Gemini): post-release xfsaild clobber

## DECISIVE FAILURE CHARACTERIZATION (fresh repro, build A18B3029, instr=0)
cache_coherency FAIL passed=0 failed=4 (cascade from a test1 SHUTDOWN). The shutdown:
`Internal error "ltbno+ltlen>bno" xfs_alloc.c:2244` in `xfs_free_ag_extent` ← `xfs_inactive_truncate`
← `xfs_defer_finish_noroll`. Freeing `bno=10 len=1 agno=1` but bnobt left-neighbor `ltbno=10 ltlen=6`
→ block 10 ALREADY FREE → DOUBLE-FREE. `P47-INACT inact_ino=2097287 incore_gen=disk_di_gen=2070108664
disk_di_mode=0100644 verdict=DISK-LIVE-same-gen=>A-lost-removal` = inode 2097287 is LIVE, same-gen
(NOT stale/reused — sess47 fix N/A), legitimately owns block 10, but bnobt lists it free → block 10
was DOUBLE-ALLOCATED (also owned by 2097282). The bnobt "remove block 10" update was LOST.
`agf_freeblks==pagf_freeblks` (pagf NOT stale → my pagf_bno_level-staleness theory REFUTED). The
disagreement is bnobt(free-space) vs inode-extent-map (allocated), two separate on-disk structures.

## WHAT I PROVED THIS SESSION (RULE 4)
- test1 acquired agno=1 FRESH exactly ONCE, held CONTINUOUSLY (only REL-UNMOUNT, no peer release
  during run). pag_gen=1 = SINGLE-EPOCH (EXPECTED, **NOT a frozen-gen bug** — kills the sess46/52/80
  "frozen pag_dlm_meta_gen" framing). So test1 did NOT create the inconsistency — it INHERITED an
  already-corrupt on-disk state (block 10 free in bnobt + owned by live inode) when it fresh-FUA-read
  agno=1 at acquire. The prior holder (test4) released agno=1 via REL-INLINE-V = bast_work_fn (the
  FULL-drain path). So the corruption survives the full-drain release path.
- The deferred-iodone release path (mxfs_dlm_ag_meta_iodone L7114 / mxfs_dlm_ag_release_work_fn L7078)
  is effectively DEAD CODE: `pag_dlm_release_pending` is only ever set to FALSE, NEVER true (grep
  confirmed). So the ONLY active cross-node on-disk release is bast_work_fn (L6095), which does
  log_force(SYNC) + bounded xfs_ail_push_ag_sync + drain_meta_buffers(xfs_bwrite) + blkdev_flush before
  mxfs_v5_dlm_ag_unlock (L6470). Counter-undercount-in-meta_track hypothesis = MOOT.

## GEMINI RULE-5 ROOT DIAGNOSIS (notes inline; the paradox: full-drain release yet removal lost)
**Post-release xfsaild clobber via CIL→AIL pipeline race in the bast_work_fn handoff.** Timeline:
1. Node B truncate uses rolling txns (xfs_defer_finish_noroll/EFI-EFD); a roll commits the bnobt
   "free/alloc block" change into the **CIL**. `demoting=true` blocks NEW acquires but does NOT wait
   for in-flight local deferred-op rolls.
2. bast_work_fn: log_force(SYNC). But CIL→AIL insertion happens in xlog_cil_committed on a workqueue;
   xfs_log_force(SYNC) can RETURN BEFORE the item lands in the AIL. So drain_meta_buffers sees the
   buffer NOT-in-AIL/clean (or its bli moved) and SKIPS it (or bwrites but iodone can't strip a
   not-yet-in-AIL item from the AIL).
3. ag_unlock. Peer (test1) acquires, FUA-reads disk (block 10 free), allocates it to a 2nd inode.
4. **Node B's background CIL push finally inserts the bnobt item into Node B's AIL; xfsaild wakes and
   writes Node B's STALE in-core bnobt buffer to its home location → ERASES the peer's allocation =
   the lost removal.** Then re-acquire's invalidate_ag_meta sees buffer IN_AIL → skips XBF_DONE clear
   → poisoned cache → eventual double-free.

## IN FLIGHT — NOT YET DONE (next session START HERE)
- **Probe-A BUILT (srcversion `0BC933EE7D4AF59BEF0DFE1`), NOT deployed/proven.** Added to
  `xfs_buf_submit` (pal/linux/xfs_buf.c, right after the verify_write check ~L1660): for any
  agf/agfl/agi/bnobt/cntbt/inobt/finobt WRITE in multi-node, if `!(cached||holders>0||demoting||
  release_pending)` → `pr_warn_ratelimited("PROBE-A AG-META-WRITE-NOT-HELD ... comm=%s")` + one-shot
  dump_stack. **comm=="xfsaild/*" == 100% confirmation of Gemini's mechanism.**
- NEXT: reset4.sh 4 (deploy 0BC933EE via NFS /mnt/mxfs-src), clear dmesg, instr=0, run
  `tests/criteria/cache_coherency.sh --nodes 4`, grep all nodes dmesg for `PROBE-A`. If it fires from
  xfsaild post-release → PROVEN → implement Gemini's FIX.
- **Gemini's FIX (apply after proof):** in bast_work_fn, BEFORE drain_meta_buffers: (1) wait for
  in-flight local txns/deferred-op rolls on this AG to drain (active refcount on pag carried across
  xfs_trans_roll — invasive), AND/OR (2) after log_force(SYNC), `flush_workqueue(mp->m_log->l_cilp->
  xc_commit_wq)` to GUARANTEE CIL→AIL insertion completes so drain's xfs_bwrite iodone actually strips
  items from the AIL and xfsaild never touches them post-release. Constraints: no single-node perf
  regress, no xfsaild/CAW-poll deadlock (release ctx holds no ILOCK/AGF/AGI). Start with the
  workqueue-flush (simpler, less invasive); add the refcount-wait if clobber persists.
- ALT defensive fix if the above is hard: in xfs_buf_submit, BLOCK (or re-queue) an AG-meta WRITE when
  `!held` (the Probe-A condition) — refuse to let xfsaild clobber an AG we don't own; force the buffer
  to wait for re-acquire. Risk: could wedge xfsaild; treat as fallback.

## INFRA
- Build: `make modules` → mxfs.ko. Deploy: all node kernels 6.8.0-101; reset4.sh 4 remounts from NFS
  /mnt/mxfs-src (=192.168.120.1:/src/mxfs). Shutdown wedges node (refcount leak) → recovers on its own
  reboot OR `virsh destroy/start` (LIBVIRT_DEFAULT_URI=qemu:///system). All 4 VMs left RUNNING, mxfs
  UNLOADED/unmounted at session end — next session: reset4.sh 4 first.
- `timeout 560 ...cache_coherency.sh` auto-backgrounds (>10min foreground cap); poll output file.
