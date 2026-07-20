---
name: sess106_lessons
description: sess106 — ROOT PROVEN: rename_visibility loss = concurrent same-name mkdir → 2 nodes modify parent dir inode (131) with DIVERGENT bases → divergent c…
metadata:
  type: project
---

# sess106 (2026-06-06, ccloop run 29df431e) — builds `07665752`→`6BBE18ED`→`44EF4535` (probes; KEEP src)

Continues sess105. `3911B884` was STALE (xfs_inode.c P105-CREATE-PARENT never compiled). Current
deployed build `44EF4535` (probes P106-MKDIR + P106-MR-SKIP/EVICT + P106-EXGRANT/EXREL).

## ROOT CAUSE — PROVEN (RULE 4): concurrent same-name mkdir → mutual-exclusion VIOLATION via stale-cached-EX
rename_visibility loss = all 4 nodes concurrently `mkdir -p .mxfs_test/rename_visibility` (test line 14,
NO barrier; harness pre-create run_tests.sh:258 uses DIFFERENT name `test_rename_visibility` so it does
NOT pre-create the path). `.mxfs_test`=ino 131 (shortform fmt=1). Two nodes BOTH create the same name,
each allocating a DISTINCT child inode → parent block lost-update → loser keeps stale dentry→orphaned
child → its files invisible cluster-wide.

DECISIVE evidence (build 44EF4535, clean pair-1 fail):
- P106-MKDIR `parent=131 name="rename_visibility"`: node3 lookup_rc=-2 new_ino=12583041 @realns 626888;
  node1 lookup_rc=-2 new_ino=135 @realns 626991 (~104ms LATER, did NOT see node3's entry).
- P106-EXGRANT/EXREL(131) merged timeline: node3 EXGRANT@626888, EXREL@627038. **node1 created child
  135 into ino 131 @626991 — INSIDE node3's EX-held window** — via FAST-PATH (cached i_dlm_mode==EX,
  no fresh grant logged near it; node1's own EXREL@628127).
- node1 took fast path: `if (ip->i_dlm_mode==EX || (PR&&PR)) {cache hit; return;}` (xfs_mxfs_dlm.c
  ~3254 and ~3874) — trusts in-memory mode, does NO on-disk CAW, NO ownership re-check.
- RULED OUT (dmesg of failing run): NO reclaim / NO heartbeat-expiry / NO epoch-change / NO
  GRANT-WAIT-TIMEOUT / NO caw exclusion-violation. CAW timeout path does NOT steal (it shuts down).
  is_compatible(EX) requires no other holder + caw_check_exclusion ran clean ⇒ node1's holders_ex bit
  was ALREADY CLEAR when node3 granted. So node1 released the ON-DISK slot cleanly but left
  i_dlm_mode==EX STALE in memory (consistent w/ sess52 ex_pop=1: CAS is exclusive; bug is in-memory
  state divergence). UNKNOWN which release path clears holders_ex without setting i_dlm_mode=NL
  (bast_process DOES set NL at xfs_mxfs_dlm.c:1573 — so it's a DIFFERENT path: yield? AG-side? a CAW
  internal demote?). Next: instrument every i_dlm_mode→NL / on-disk release site OR (better) the fix-probe below.

## GEMINI (RULE 5) DESIGN — lease + cheap-read epoch verify (full design in transcript)
Time-bound in-memory lease (jiffies, ~1s): fast-path trusts cached EX only while lease valid; on expiry
do a CHEAP uncached slot read to confirm owner==self & generation==expected (renew or fall to slow).
Peer steal sets requested_by + waits lease+skew then bumps generation. On acquire-from-peer:
invalidate_inode_pages2 + drop dcache to consume publish-before-notify. Needs CAW slot
generation+owner+requested_by (slot ALREADY has `generation` + `holders_ex` bitmap → maybe no format
change needed).

## TARGETED FIX PLAN (lower risk than full lease; do this next)
The proven hole = fast-path cached-EX trusts memory without verifying on-disk ownership.
Primitive EXISTS: `mxfs_dlm_caw_held(ctx,resource)` (dlm_caw.c:1857) returns 1 if this node holds the
resource on-disk (reads slot). v5 wrapper exists for AG: `mxfs_v5_dlm_ag_held` (v5_mount.c:1157) —
ADD a mirror `mxfs_v5_dlm_inode_held(ctx, ino)` (build resource_id MXFS_LTYPE_INODE, call caw_held).
STEP 1 (PROVE, RULE 4): at the dir-EX fast-path cache-hit (xfs_mxfs_dlm.c ~3254/3490 and ~3874), when
S_ISDIR && i_dlm_mode==EX, call inode_held; if it returns 0 → log `P106-STALE-EX ino=...` . A hit on
node1's create-135 proves stale-cached-EX definitively.
STEP 2 (FIX): if inode_held==0 on the fast-path for a dir, DON'T trust cache — fall through to
slow-path re-acquire (which reloads fresh + sess64 evict). Bound the per-op disk-read cost with a
short jiffies lease (Gemini) so only ~1 cheap read/sec/inode, not every op. Then reproduce: divergence
should vanish (later creator re-acquires, sees peer's durable dirent, EEXIST→converge).

## SEPARATE BUG (open): AGI/iunlink corruption shutdown on `rm -rf` (xfs_iunlink+0x283 xfs_agi) — seen on
07665752 LOOPED run (test1). Own RULE-4 loop later; contaminates looped repros.

## METHODOLOGY
- Repro: virsh destroy+start ALL 4 → reset4.sh 4 → dmesg -C → run cross_visibility then
  rename_visibility (fails clean pair 1-2). Loser varies (whoever's child gets orphaned).
- ALWAYS `strings mxfs.ko | grep <probe>` after build — incremental left xfs_inode.c probe out of 3911B884.
Marker NOT written (criterion 3/4).
