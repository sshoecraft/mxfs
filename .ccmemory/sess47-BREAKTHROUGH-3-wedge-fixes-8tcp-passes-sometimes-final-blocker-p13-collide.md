---
name: sess47-BREAKTHROUGH-3-wedge-fixes-8tcp-passes-sometimes-final-blocker-p13-collide
description: sess47(ccloop) BREAKTHROUGH: 3 wedge fixes (build 05BC5765) -> 8/tcp dir_reuse PASSES 8/8 clean (run1). 2/4 tcp PASS. Final blocker=intermittent P13-…
metadata:
  type: project
---

## sess47 (ccloop 4cb2d0a2) BREAKTHROUGH — build 05BC576518CA5792B2CB287

### THREE wedge fixes (all KEEP) eliminated every 8/tcp dir_reuse WEDGE/deadlock:
1. relsafe lock @xfs_mxfs_dlm.c~8676 (lock-free iext walk -> garbage daddr WARN flood).
2. ilock_end defer-to-bast-wq @~15300 (inline-flush self-deadlock vs readdir buffer).
3. **conversion-admit @ilock_begin ~14622**: bast_process releasing a written reg file
   does filemap_write_and_wait (reg-durable, ~9966) AFTER clearing i_dlm_mode=NL (~9266);
   the xfs_end_io unwritten-extent conversion (needs EX) then can't fast-path (mode!=EX)
   and blocks on the DEMOTING wait -> PageWriteback never clears -> bast deadlocks
   (PROVEN: bast in filemap_write_and_wait + xfs-conv kworker in ilock_begin, both
   D-state; P47 mode=0 state=3). FIX: admit a non-dir op when state==DEMOTING &&
   MXFS_IF_DLM_RELFLUSH set (on-disk grant still held, set ~9222..10137, unlock ~10312)
   — same safety as the existing mode==EX file fast-path (13954), covers the
   pre-cleared-NL sub-window. Dirs excluded (strict coherency gate).

### RESULTS (pristine reset each, contamination-controlled per sess29):
- 2/tcp dir_reuse: PASS 2/2. 4/tcp dir_reuse: PASS 4/4 (clean).
- **8/tcp dir_reuse: PASS 8/8 CLEAN (run1, shut=0 hole=0 hung=0)** — first clean 8-node pass!
- But INTERMITTENT: run2 (same build) FAIL; run3 (+dir_tenure_evict=1) FAIL.

### CRITICAL META-LESSON: most earlier "DABUF hole / shutdown" 8-node failures were
CONTAMINATION from killed/timed-out runs (sess29 hazard). PROOF: 4/tcp FAILED 0/4 right
after an 8-node run but PASSED 4/4 after a clean `rm /root/drc_failrounds.txt /root/drc_*.dmesg;
dmesg -C` + full virsh reset + `mosquitto_sub --remove-retained 'mxfs/#'`. ALWAYS fully
sanitize between runs; never trust a result that followed a killed run.

### FINAL BLOCKER (intermittent ~50% at 8 nodes): P13-COLLIDE AG/extent double-alloc.
test4 shutdown: `P13-COLLIDE ino=131 daddr=102568048 off=64 our=[node4_f28] comm=dd
dirty=1 done=1 bufgen=0 dirgen=51 ourdir=0 downer=<different-inode> dmagic=0x8f85d55a
— placing onto a DIFFERENT durable dirent (stale-base free-slot double-alloc)` ->
xfs_create -> xfs_trans_cancel:1060 -> Corruption(0x8) -> shutdown. ourdir=0 + downer=
different inode = the dir's in-core EXTENT MAP points to a freed-and-REALLOCATED daddr
now owned by ANOTHER inode (rm-rf+recreate reuse churn). The node RMWs that block,
clobbering the other owner. bufgen=0 = the stale base was never gen-refreshed. NOT fixed
by dir_tenure_evict (that's leaf-side). This is the deep cross-node dir-extent / AG
free-space coherence family (sess39-47 bnobt). test5 also goes readdir=0 with repeated
`DLM inode lock failed ino=131 mode=5 rc=-35` (expected B5 inactivation guard, high vol).

### NEXT (RULE 4): the dir EXTENT MAP must be reloaded on dir-inode REUSE before a modify
RMWs a stale daddr. Investigate why mxfs_dlm_dir_modify_refresh / evict's incarnation
detection (P106-MR-SKIP) lets a reused dir keep a stale extent map pointing at a
reallocated daddr. Repro fast at 4-node too? (4 passed clean — maybe 8-node only). Keep
build 05BC5765 (P47 instrument harmless). See [[sess47-FINAL-state-fixes-heal-and-decoded-release-wedge-data]].
</body>
