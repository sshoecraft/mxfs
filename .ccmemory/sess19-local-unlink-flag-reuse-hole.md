---
name: sess19-local-unlink-flag-reuse-hole
description: sess19 (ccloop 4eef1f39): bnobt double-free = test1 inactivates a PEER's live inode via torn-reload of a reused inode#. Added MXFS_IF_LOCAL_UNLINK fl…
metadata:
  type: project
---

# sess19 (ccloop run 4eef1f39) — local-unlink flag + the reuse hole

## Build `57B046347E1A23B0825822A` (deployed all 4, NOT a full fix — still shuts down)

## Where cache_coherency stands NOW (build E9963FFA last full run)
4 subtests: cross_visibility PASS, rename_visibility PASS, **unlink_visibility FAIL**
(31/122, slow 369s), **cross_write_read FAIL** (empty `.md5` sidecar content,
expected=''). BUT all downstream failures are likely **secondary to the bnobt
double-free SHUTDOWN** that takes a node out mid-run (test1 errored → peers wedge).
Fixing the shutdown is the gate.

## DECISIVE ROOT (RULE-4, clean reset+reproduce on 57B04634)
rename_visibility PASSes functionally but **test1 SHUTS DOWN** (bnobt
`ltbno+ltlen>bno` xfs_alloc.c:2244, agno=2 bno=27). Cross-node trace:
- inode 4194443 = **node3's file** `node3_before_10`→`node3_after_10`. node3
  created+owns it (P90-PICK + P-CRNAME on test3; P-IRESURRECT on test3 is its
  LEGIT first-flush: disk_mode=0 disk_gen=555073053 < incore_gen=1083402091).
- **test1 inactivates node3's LIVE file**: `P47-INACT inact_ino=4194443
  incore_gen=1083402091 disk_di_mode=0100644 disk_di_gen=1083402091
  verdict=DISK-LIVE-same-gen=>A-lost-removal`; `P81-DEXT disk_claims_freed=1`.
- At failure leaf `P28 disk_differs=0`, `P33 nr=2 rec0=(9,6) recN=(24,260891)` —
  bnobt is COHERENT (in-core==disk) and genuinely shows blk27 free, while the
  on-disk inode owns it = **durable inode-vs-bnobt double-state**.
- **No INACT-SKIP-STALE for 4194443** → my B3 guard did NOT skip because the
  `local_unlink` flag was SET.

## The HOLE in this session's fix
test1's in-core inode 4194443 = a **torn in-place reload of a reused inode#**:
the SAME inode number was test1's own file earlier; test1 unlinked it (→ set
`MXFS_IF_LOCAL_UNLINK` via xfs_droplink, nlink=0); then node3 reused 4194443 and
test1 RELOADED it in place (adopted node3's gen=1083402091/mode) **without
clearing the flag** (XFS_IRECLAIM_RESET_FLAGS only clears on iget-RECYCLE, not on
a DLM in-place reload). So the stale flag makes B3 wrongly PROCEED → frees node3's
block → double-free.

## Changes landed this session (build 57B04634) — KEEP, but incomplete
1. `xfs/xfs_inode.h`: `#define MXFS_IF_LOCAL_UNLINK (1U<<19)`; added to
   `XFS_IRECLAIM_RESET_FLAGS`.
2. `xfs/libxfs/xfs_inode_util.c` xfs_droplink: set flag at nlink→0 transition.
3. `xfs/xfs_inode.c`: set flag in both O_TMPFILE/orphan xfs_iunlink callers
   (~1284, ~1615) so legit tmpfile frees aren't false-skipped.
4. `xfs/xfs_inode.c` xfs_inactive guard: **B3** — skip destructive inactivation
   when `!local_unlink && coh_nlink>0` (coh_nlink via new
   `mxfs_dbg_disk_di_nlink_coherent` PLAIN-bio read, xfs_mxfs_dlm.c — di_nlink
   @0x10; FUA would read stale platter per sess111). Logs
   `INACT-SKIP-STALE ... coh_nlink=%d local_unlink=%d reason={disk-free|
   gen-mismatch|torn-live-no-local-unlink}`. B1(disk-free) skips fired fine.

## NEXT STEP (high-confidence, one edit) — CLOSE THE HOLE
Clear the flag whenever the inode adopts a (possibly new) incarnation on reload:
add `xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK);` at the TOP of
**`mxfs_dlm_reload_inode`** (xfs/xfs_mxfs_dlm.c ~line 2678; the fn that calls
`xfs_inode_from_disk` ~2811+ to adopt the peer's incarnation). Safe: a LEGIT
local unlink→inactivation holds the inode and does NOT go through a DLM reload;
only peer-contended inodes reload. Once cleared on reload, B3 as written becomes
correct (torn reload → flag clear → coh_nlink>0 → skip; node3's live file saved).
Then: `virsh -c qemu:///system destroy+start` ALL 4 → `bash tests/reset4.sh 4` →
confirm build → run rename_visibility (cmd below) → expect NO shutdown +
`INACT-SKIP-STALE ... reason=torn-live-no-local-unlink local_unlink=0` for the
peer-owned inode. Then unlink_visibility + cross_write_read + full
cache_coherency.sh + verify_ship.sh.

## Run rename alone
`MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh
--nodes 4 --phase cluster --test test_rename_visibility --pass-file
/tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`
(run_tests aborts "node N not mounted" if a node's FS is shut down — `mountpoint
-q` fails on an errored mxfs mount. ALWAYS power-cycle+reset4 first.)

## Still-open deeper root (separate from the inactivation guard)
P122 write-side interlock WORKS (suppressed 2 agno=0 P93-REVERT-CLOBBER writes
this run). But `pag_dlm_meta_gen` is STILL frozen at 1 (P74/P88 show
buf_gen=0 pag_gen=1, `cnt-modify-on-STALE-buf ... pin=1`), so stale PINNED in_ail
bnobt/cntbt buffers get USED for alloc/free in-tenure (cold-read discard skips
pinned). The agno=2 durable double-state likely originated from an earlier
revert/double-alloc that P122 didn't catch. sess80 Gemini's **shared on-disk AGF
epoch** (replace frozen local gen) remains the unimplemented architectural fix
for the read-side. The B3+reload-clear fix prevents the INACTIVATION from
tripping over it; whether that alone makes cache_coherency green needs the rerun.
Related: [[sess121-bnobt-clobber-writeside-fix]] [[sess111_reframe_bnobt_red_herring]]
[[sess114_lessons]] (torn reload) [[sess80_lessons]] (AGF epoch).
