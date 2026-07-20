---
name: sess99_lessons
description: sess99 — release-side xfs_buf_stale FIXED block-format dir lost-update (0 reverts). unlink_visibility PASSES isolated (D6AD04FE). Acquire-side stale…
metadata:
  type: project
---

# sess99 (ccloop run 29df431e) — release-side dir publish-and-discard WORKS

## CURRENT BUILD: D6AD04FEFAE22AC82C4D71D (deployed test1-4, KEEP)
= dir release-side stale (KEEP) + acquire-side reverted to clear-DONE + AG-meta
bnobt/cntbt release-side stale (INERT, fires 0× — see below). Earlier builds this session:
BA0A5E6D (dir release-stale only = 1 survivor), 18848E6D (acquire-side stale = REGRESSION).

## FIX 1 (KEEP, PROVEN): release-side xfs_buf_stale on dir DATA blocks
New fn `mxfs_dir_stale_data_blocks` (xfs/xfs_mxfs_dlm.c ~L450, after
mxfs_dir_evict_data_blocks). Wired at bast_process dir-release (~L1581) REPLACING
mxfs_dir_evict_data_blocks. On dir EX BAST release, for each DURABLE (clean/!in_ail/
!pinned/!delwri/DONE) dir block: `xfs_buf_stale(dbp); dbp->b_flags&=~(XBF_DONE|
_XBF_FUA_FRESH); b_mxfs_dir_gen=0`. MUST force-clear DONE after stale (xfs_buf_stale
doesn't — v0.3.99). MUST NOT stale in-AIL (discards committed update — P79-INSTR).
RESULT (build BA0A5E6D): P-DIRWR write trace MONOTONIC, **ZERO reverts** (sess98
oscillated). The block-format dir durable lost-update — the PRIMARY proven sess98 root —
is FIXED. P99-DIR-STALE fires 12-35×/node, P99-STALE-SKIP=0.

## FIX 2 (KEEP, but INERT): AG-meta bnobt/cntbt release-side stale
In mxfs_dlm_ag_drain_meta_buffers (~L5710), after successful xfs_bwrite of a
bnobt/cntbt buf: xfs_buf_stale + clear DONE + P99-AGMETA-STALE log. INTENT: stop the
P93-REVERT-CLOBBER bnobt run-killer (same mechanism as dir). **But P99-AGMETA-STALE
fires 0×** — the drain only bwrites in_ail/pinned bufs; xfsaild flushes the stale bnobt
buf ASYNC *before* the release drain, so the drain finds it clean+skips. The revert is
async, OUTSIDE the release window. So FIX 2 is currently a no-op (harmless, KEEP for now).

## RESULT: unlink_visibility PASSES in ISOLATION (D6AD04FE, MXFS_NODE_OFFSET=0 test1-4)
0 survivors. (BA0A5E6D was 1 survivor = borderline; the shortform-collapse survivor.)
Full cache_coherency criterion (test1-4, all 4 subtests) was RUNNING at relay boundary:
PASSED cross_visibility + rename_visibility with NO bnobt shutdown (better than the
earlier full run which shut down node1 on `ltbno+ltlen>bno` during cross_visibility),
slow on unlink (~3min, the L1372 whole-AG push — sess98 flagged for removal). Result
pending. Check: /tmp/claude-1000/-src-mxfs/e02c1682-*/tasks/bf4j3km3x.output and
`tests/criteria/cache_coherency.sh` → /tmp/cache_coherency.*.log.

## REGRESSION (RULE-4 2a, REVERTED): acquire-side xfs_buf_stale
Converting mxfs_dir_drain_evict_data_blocks clean-branch from clear-DONE to xfs_buf_stale
made unlink WORSE (all 4 nodes 6/1/1/1). CONFIRMS sess96: aggressive acquire-side COLD
re-read under fua_disable=1 returns stale/racing SCST-target content. ⇒ GPT "release+
acquire PAIR" is WRONG here: release-side stale correct, acquire-side cold-read harmful.
DO NOT retry acquire-side cold-read/stale for dirs.

## REMAINING BLOCKER: bnobt P93-REVERT-CLOBBER (intermittent run-killer)
Still fires 4-12×/node every unlink run; intermittently escalates to `ltbno+ltlen>bno`
shutdown (killed the earlier full run during cross_visibility cleanup). Detector is at
pal/linux/xfs_buf.c ~L1911 in xfs_buf_submit (fires when bnobt write nr < disk_nr =
reverting a durable split). A WRITE-SUPPRESS there (skip write + stale if disk_nr>nr) is
tempting BUT cannot distinguish stale-base revert from a LEGIT record-count reduction
(merge) without the buffer's load-epoch — and buf_gen/pag_gen are FROZEN at 1 (sess46/80).
bnobt class = deep multi-session blocker, 2 GPT consults already (sess92). Real fix likely
the on-disk per-AG coherence EPOCH (sess98_gpt_fix_design optional arch) or fixing
pag_dlm_meta_gen to actually track peer mods. Don't patch speculatively.

## NEXT SESSION
1. Read the full cache_coherency result (bf4j3km3x.output). If PASS → run
   `tests/criteria/verify_ship.sh` end-to-end (the ship gate). If unlink slow trips a
   timing threshold, drop the L1372 whole-AG `xfs_ail_push_ag_sync(d_agno)` (sess98 said
   targeted mxfs_dir_flush_data_blocks suffices now that release-stale handles coherency).
2. If FAIL on bnobt shutdown: tackle P93 via AG-meta epoch / pag_dlm_meta_gen fix, or
   RULE-5 GPT consult with the new evidence (release-side stale fixed dirs; AG-meta async
   xfsaild revert is the residual). Read [[sess92_lessons]] (prior bnobt GPT consults).
Related: [[sess98_lessons]] [[sess98_gpt_fix_design]] [[sess96_lessons]] [[sess90_lessons]].
