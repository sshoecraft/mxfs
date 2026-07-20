---
name: AAA-ccloopa864-sess2-END-fable-design-and-evict-formation-site
description: sess2 END: Fable consult on CAW-orphan fix (claim-protocol, invalidate-not-flush, reclaim-time release is root). Formation site suspect = mxfs_dlm_ev…
metadata:
  type: project
---

# sess2 END — Fable design for the CAW-orphan fix + formation site found

## STATE: dir_reuse@32/caw is the ONLY criteria gap. Root = orphaned on-disk dir-EX holder bit at reuse boundary (see AAA-ccloopa864-sess2-DEEPROOT-*). Cluster killed, /tmp/mxfs_run.lock FREE. Build in tree = v0.10.45 srcver 4E1FA7B6 (acq self-EDEADLK + P72 stale-DEMOTING re-queue + probes P-ACQ-STUCK/P-SELF-STALE-EDEADLK/P72-STALE-REQUEUE + B2-B5 fairness changes). Runs B7/B8 both reached r4 (vs B2-B6 r2/r3) then wedged on an idle stuck EX holder (B8=test27 slot36627 hex=0x4000000). P72-STALE-REQUEUE fires 100s-1000s/node but does NOT clear — because bast_process's release is skipped for a CAW incore-NL orphan (orphan_live is TCP-only, p_rel_gen always 0 on CAW).

## FABLE CONSULT (claude-fable-5) — key guidance, VALIDATED design:
1. **My "release when mode==NL && state!=ACQUIRING && caw_held" predicate has a TOCTOU double-EX hole** unless serialized. Killer interleave: checker reads (NL,NONE) → acquirer sets ACQUIRING→CAS bit→CACHED → checker clears the now-LEGIT bit → double-EX. FIX = **claim protocol**: under i_dlm_lock CAS state NONE→DEMOTING, RE-VALIDATE mode==NL inside the claim, THEN read slot + CAS-clear. With the claim, no strike-escalation needed on CAW (the ACQUIRING window is structurally excluded).
2. **PREREQUISITE**: verify the acquire path BLOCKS while state==DEMOTING. If it doesn't, the existing demote worker AND this fix are both unsound (ABA). CHECK THIS FIRST (ilock_begin wait-on-DEMOTING).
3. **Fix layer = (b) dedicated minimal clear, NOT the full bast_process drain block.** That block FLUSHES; for a stale orphan the incore may hold PRIOR-INCARNATION cache → must INVALIDATE (invalidate_inode_pages2 / mapping invalidation), never flush. Flushing prior-incarnation metadata into the reused inode = corruption worse than the hang.
4. **ROOT FIX (prevent formation) = reclaim-time release.** Orphan forms on holder node K's OWN reclaim path: inode eviction under MEMORY PRESSURE (WHY 32 repro & 16 doesn't = inode/dentry cache pressure) resets i_dlm_mode→NL WITHOUT releasing the disk bit. Make EVERY i_dlm_mode→NL reset site (evict/invalidate/unmount) go through RELEASE, not reset.
5. Also cover holders_pr orphans (stranded PR bit blocks EX too). Also: store inode-gen in the slot so a bit with gen < current inode-gen is provably stale (cheap mitigation, future).
6. Do BOTH: reclaim-time prevention + minimal BAST/acquire-time clear (recovery net for crashed/missed paths). Acquire-time self-check is cheapest but only helps the B6 variant (holder RE-acquires); the B7/B8 idle-holder needs BAST-time clear or reclaim-time prevention.

## FORMATION SITE FOUND (next session start here):
`mxfs_dlm_evict` (xfs_mxfs_dlm.c:21934) resets i_dlm_mode=NL at:
- **21953 UNPUBLISH FAST-PATH**: `if (mxfs_dlm_unpublish_drop(ip)) { mode=NL; epoch++; state=NONE; ex/pr_holders=0; return; }` — resets WITHOUT any disk release (comment: "unpublished inode holds EX locally but NO on-disk slot ... skip disk release"). **SUSPECT: if a genuinely-PUBLISHED dir ino131 (real on-disk EX bit) is wrongly on the unpublished list, this orphans the bit.** VERIFY: does the shared dir take this path? add a probe logging mxfs_dlm_unpublish_drop=1 + caw_held at evict for ino<=256.
- 21966+: normal release path (cancel_work_sync bast_work, then release). Under 32-node memory pressure, is this path skipped/failing? cancel_work_sync CANCELS a pending demote → could that drop a demote that was mid-release, leaving the bit? (relates to the P72 stale-DEMOTING: evict cancels the bast_work → work_busy=0 → stale DEMOTING).

## NEXT-SESSION PLAN (RULE 4):
1. VERIFY acquire blocks on state==DEMOTING (grep ilock_begin wait loop).
2. Instrument mxfs_dlm_evict: probe P-EVICT ino state mode caw_held unpublish_drop — confirm the shared dir orphans HERE (mode=NL reset while caw_held=1).
3. If confirmed: add reclaim-time release — in mxfs_dlm_evict, before resetting mode=NL, if caw_held(disk)==1, do a synchronous release (claim + invalidate + caw_unlock). Watch the cancel_work_sync interaction (don't reset without releasing).
4. Add the BAST/acquire-time minimal-clear recovery net (claim protocol, invalidate-not-flush) per Fable.
5. Rerun B9 32/caw dir_reuse; expect past r4 → 24 rounds. Reproduce 2x for confidence.

## Run mechanics: `nohup timeout 5200 env MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS='dirwr=1 dirland=1 close_release=0 caw_inode_fastpoll=1 caw_fair_handoff=1' ./run.sh 32 caw dir_reuse_coherency`. Prep power-cycles shut-down nodes (convergence FLAKES on 3-consec-stable — just relaunch). Recover SSH-slow nodes: virsh destroy+start (~12-18s). After kill: leftover mxfs_sshpass cleanup subshells hold the lock — `for p in $(fuser /tmp/mxfs_run.lock); do kill -9 $p; done`. Monitor caps: keep bash internal deadline < tool timeout minus one sleep.
