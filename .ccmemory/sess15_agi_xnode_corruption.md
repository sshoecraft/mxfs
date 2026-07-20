---
name: sess15_agi_xnode_corruption
description: sess15 (ccloop s15) — 1853FF8F drain-wedge GONE; rename/unlink/cwr FAIL via cross-node AGI unlinked-list corruption→shutdown under inode reuse.
metadata:
  type: project
---

## sess15 (ccloop 4eef1f39, build 1853FF8F)

### GOOD NEWS: session-14's 1853FF8F is STABLE — drain-wedge eliminated
On a CLEAN power-cycled 4-node cluster: P113-DRAIN-WEDGE=0 on all nodes, NO hung_task, mounts
stable, no SIGKILL. The sess115 rewrite of `mxfs_inode_cluster_durable` (native delwri submit /
AG-drain instead of manual xfs_bwrite) DID fix the leak. KEEP 1853FF8F as base.

### cache_coherency on clean 1853FF8F = passed=1 failed=3 (cross_visibility PASS; rename, unlink, cross_write_read FAIL)
NOT a regression of the wedge — a DIFFERENT, deeper failure now dominates: **forced FS SHUTDOWN
from AGI unlinked-list corruption.**

### PROVEN ROOT (RULE 4): cross-node AGI unlinked-list read-coherency corruption under inode REUSE
rename_visibility: rename_visibility dir = ino=135 (block fmt, all nodes agree, NO dir-inode
divergence). node{2,4}_after_* durably missing on ALL nodes because **test4 SHUT DOWN** at t=317s:
```
xfs_iunlink_remove_inode line 632 (xfs_inactive_ifree) — agi_unlinked[bucket=21] garbage
P71-INSTR agno=5 bucket=21 head_agino=0xffffffff disk_head=0x95 agi_disk_differs=1 pag_gen=1
```
In-core AGI bucket[21]=NULLAGINO (empty) but FUA disk read=0x95 (valid head). test4's in-core AGI
is STALE → xfs_verify_agino(0xffffffff) fails → XFS_CORRUPTION_ERROR → shutdown.

### The cross-node lifecycle of the corrupting inode 10485909 (agino 0x95, AG5) — decisive
- t=70.43 test4: P90-PICK + P-CRNAME creates **node4_before_20** = ino 10485909.
- t=72.18 **test3**: `P82-ADD ino=10485909 agno=5 agino=0x95 bucket=21` — test3 unlinks it (adds to
  AG5 unlinked list, commits → disk_head becomes 0x95).
- t=193.24 test4: `P103-RELOAD-REUSE-ADOPT ino=10485909 disk_gen 279186378→622545939` (inode FREED
  + REUSED by a peer), then P-CRNAME add=[node4_after_20] cino=10485909 — test4 re-adopts same ino#.
- t=317 test4: inactivates 10485909 → reads STALE AG5 AGI (NULLAGINO, never saw test3's t=72 add)
  → corruption → shutdown.
So **test3 ADDs, test4 REMOVEs the same AG5 unlinked inode**; test4's cached AG5 AGI never
reflected test3's committed add.

### AG-DLM EXCLUSION is violated for AG5 (the real mechanism)
test4 held AG5 from ACQ-FRESH t=69.29 → REL t=402 (REL-INLINE-V55, "Phase-3 meta_pending=3 timeout").
test3 ALSO did ACQ-FRESH AG5 at t=69.88 and modified it at t=72. So BOTH nodes operated on AG5
concurrently. `P88-CLOBBER-PRODUCER agno=5 writing pristine bnobt while NOT holding AG DLM (ag_held=0)`
fired on test4 at t=87 — test4's xfsaild writes AG5 metadata when test4 does not hold AG5's DLM.
pag_dlm_meta_gen for AG5 stuck at 1 the whole run (gen never bumped → mxfs_ag_meta_invalidate_stale
no-op branch, AGI never re-invalidated after t=69).

### Gemini consult this session = WRONG PREMISE (do not trust its Hypothesis A)
I consulted Gemini under the (false) assumption "only test4 touched AG5, single-node revert". It
returned Hypothesis A (stale FUA re-read reverts committed-but-undestaged AGI) + fix = extend
`mxfs_buf_is_undestaged()` guard to AGI/AGF. BUT static analysis refutes single-node revert:
`_XBF_FUA_FRESH` is cleared ONLY by xfs_buf_stale (pal/linux/xfs_buf.c:90), and the AG5 AGI was
staled only ONCE (t=69, P14 verdict=STALED) → never re-read after → cannot self-revert. The REAL
cause is CROSS-NODE (test3 add unseen by test4) + AG-DLM exclusion failure. Existing guards already
cover single-node: FUA path P91-FUA-SKIP-LOGGED (xfs_buf.c:1708, checks pin/b_li_list/b_log_item),
bio path P110-BIO-OVER-LOGGED (xfs_buf.c:2499, mxfs_buf_has_uncheckpointed_mods). Helpers
`mxfs_buf_has_uncheckpointed_mods` (5073) + `mxfs_buf_is_undestaged` (5149, already reads agi_lsn).

### NEXT SESSION — re-consult Gemini/GPT with CORRECT premise, then fix
The question is NOT single-node revert. It is: **why do test3 and test4 both hold/modify AG5 (EX)
concurrently, and why is test4's iunlink_remove reading a stale AGI?** Candidate fixes:
1. FUA-refresh the AGI buffer at the START of xfs_iunlink_remove_inode/insert (multi-node) when it
   carries no uncheckpointed mods — directly fixes the read-staleness at the corruption site
   (xfs/libxfs/xfs_inode_util.c:612). disk_head=0x95 is already correct; just adopt it.
2. Fix the AG-DLM exclusion: ensure test4's xfsaild AG-meta writes are drained/blocked when test4
   does not hold AG5 (P88-CLOBBER-PRODUCER ag_held=0). Invariant #1 (drain before release) is being
   violated — xfsaild writes AG5 bufs after release/while peer holds.
3. Bump pag_dlm_meta_gen on EVERY fresh AG acquire so cached AGI is force-invalidated (it stayed at 1).

### METHOD (works; recurring teardown wedge)
- Clean reboot REQUIRED before trusting results: `for h in test1..4; sudo virsh -c qemu:///system
  destroy/start`. Module wedges "in use" after interrupted repros → power-cycle, not rmmod.
- Then `bash tests/reset4.sh 4` (RESET_OK). Verify srcversion on all 4 via /sys/module/mxfs/srcversion.
- Fast repro: `bash tests/repro_double_alloc.sh 25` (instr=0) — LOW-RATE (failed iter8 once, 30/30
  clean next). Better signal: run rename_visibility alone:
  `MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16 ./tests/run_tests.sh --nodes 4 --phase cluster
  --test test_rename_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`
  (~250s, reliably fails+shuts-down test4). MUST set MXFS_TESTS_DIR (nodes have /src NFS, not /mnt/mxfs-src).
- Harvest: `dmesg | grep P71-INSTR` (agi_disk_differs), `P82-ADD` (which node unlinked), `P88-CLOBBER-
  PRODUCER`, ACQ-FRESH per agno, `P103-RELOAD-REUSE-ADOPT`. Marker NOT written.
</body>
