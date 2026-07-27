---
name: ccloop4dd7-sess1-C-inobt-divergence-root-lead
description: ccloop-4dd7 sess1 final lead: P150 proves divergent per-node inobt record content across AG handoffs; suspects = in-AIL keep guard vs Invariant-1 dra…
metadata:
  type: project
---

# ccloop-4dd7 sess1 part C — the remaining flavor-1 root lead (STOP-POINT)

## Where the RULE-4 loop stands on the LAST unfixed corruption flavor
v0.11.46 round 1: both nodes died again on the inobt double-free flavor (P-DIFREE-DBL
agno=1 agino=138 off=10 freecount=54 → xfs_inobt_check_irec → -117 both nodes).
**P150 gave the decisive evidence** (tests/logs/vmrig_dialloc_20260724_10*/):

- test2 (10:41:51, tenures 60-61): last op on off=10 = FREE, post mask=0xfffffffffffb8400
  freecount=49.
- test1 (10:41:52, tenure 63): FREE on off=10 with pre=0xffffffffffff94d0/54 — bit
  ALREADY SET, content matching NEITHER of test2's recent states.
⇒ **Each node maintains its own divergent copy of the record across AG handoffs**
(divergent RMW braid), not a single lost bit. btenure==tenure on every P150 line;
bgen (b_mxfs_ag_gen) == 0 ALWAYS ⇒ these buffers NEVER took the FUA-read path that
stamps gen (pal/linux/xfs_buf.c:6458) — cold re-reads are nearly absent.

## P144 rates (same round): inobt WR=1404/1937 per node vs cold RD=125/120
Writes flow constantly (AIL destage works) but COLD RE-READS are ~1 per 12-15 writes —
consistent with cached buffers surviving handoffs. The offline join per (agno,daddr)
crc (P144-WR from writer vs next P144-RD on reader) can now directly show whether a
reader's first image after a handoff matches the writer's last write — DO THIS JOIN
FIRST next session (script it; realns-ordered merge of both nodes' P144 lines for
daddr=2093248/2093256 = AG1 inobt/finobt leaves).

## Root-candidate ranking (from mxfs_ag_meta_invalidate_stale reading, xfs_mxfs_dlm.c
~25525):
1. The sess103 **in-AIL keep guard** (25598: discard requires !dirty && !in_ail &&
   !pinned && !delwri): under relentless RMW churn the inobt leaf is nearly ALWAYS
   in_ail at the peer's acquire-time invalidation ⇒ kept stale ⇒ RMW on own copy.
   The guard's soundness ASSUMES Invariant-1's release drain destages AG-meta before
   unlock (leaving buffers NOT in_ail at the peer's acquire). Under TCP with the
   deferred-release machinery (pag_dlm_meta_pending / release_pending) the drain may
   complete asynchronously AFTER the peer acquires — breaking the assumption WITHOUT
   breaking the write-side (writes do land, later).  Verify: correlate P5U-AGUNLOCK
   relgen times vs P144-WR times for the same AG — if WRs land AFTER the peer's next
   acquire, that's the hole.  Also the sess19b arm (25641+) handles in_ail&&!dirty
   with !mxfs_buf_is_undestaged() — check why it didn't catch these (undestaged=true
   likely, i.e. genuinely not-yet-written work at acquire time on the OTHER node...
   but then whose work — reader's own prior tenure or writer's?).
2. Where is mxfs_ag_meta_invalidate_stale CALLED for inobt reads — confirm the btree
   read path actually invokes it (grep callers; if only agf/agi callers exist, inobt
   leaves are never invalidated at all — matching bgen=0).
3. The read path serving cache-hits without any freshness check (XBF_DONE short-
   circuit in xfs_buf_read_map → "Buffer already read; all we need to do is check").

## Immediate next actions (in order)
1. Script the P144 WR/RD cross-node join for the failing daddr (2093248) — one shot,
   decides reader-stale vs writer-late definitively.
2. grep callers of mxfs_ag_meta_invalidate_stale — is the inobt/finobt btree-leaf READ
   path covered?
3. Fix per verdict: likely = make AG release truly drain-before-unlock for AG-meta under
   TCP (or make the acquire-side wait on peer's release_pending), OR extend invalidation
   to force cold-read of in_ail-but-destaged leaves (the sess19b arm) for the inobt.
4. Then resume verification rounds (target ≥5 consecutive clean 180s churns), then
   deadshell_repro 8/8, then full ./run.sh 2 tcp suite.

## Cluster state at stop
test1 FS shut down (this round's -117); test2 followed. VMs healthy (rebooted at 10:37
with iSCSI fix — boots clean now). Next session: MXFS_FORCE_PREP=1 ./run.sh 2 tcp
prep_cluster then continue. Build on nodes = 13ABFACB (v0.11.46). All fixes uncommitted
in the tree (user has not directed a commit).
