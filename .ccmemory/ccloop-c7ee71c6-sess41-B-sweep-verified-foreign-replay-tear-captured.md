---
name: ccloop-c7ee71c6-sess41-B-sweep-verified-foreign-replay-tear-captured
description: sess41-B: C8 sweep+adopted-authority VERIFIED (P89 free on 347); 3 leak roots fixed; FOREIGN-REPLAY TEAR captured live w/ deterministic repro
metadata:
  type: project
---

# sess41 part B — C8 verified through 3 proven leak roots; foreign-replay tear captured

## C8 survivor sweep: VERIFIED END-TO-END on 0.11.347
Successful trace (unlinker_death, ino=132): P97-SWEEP walks bucket → ADOPTED reap entry →
worker waits while fd open (retry) → A closes (P91 eager clear) → next cadence: coherence
ilock pulls nlink=0 → MXFS_IF_ADOPTED_UNLINK + bucket restore → prune → irele → inactivation
**will_skip=0** → **P89-REAP-DONE** (freed ~27s after close). Data intact through B's death.

## Three leak roots found + fixed getting there (RULE 4 each time)
1. **345**: opener's dentry pins the zombie after last close (cross-node unlink never
   d_deletes opener's alias; nothing re-looks-up) → retire-only reap entries
   (MXFS_REAP_RETIRE): worker d_prune_aliases (P92-REAP-RETIRE). Freer entries prune too.
2. **346**: sweep's in-core LOCAL_UNLINK restore was STRIPPED by any reload (sess19
   clear-on-reload) before the inactivation → B4 skip. Authority must be re-derived per
   attempt → sweep enqueues MXFS_REAP_ADOPTED; worker restores per retry under gen check.
   NEW MXFS_IF_ADOPTED_UNLINK (bit 28): grants B3/B4 authority, NEVER P2L-OWNFREE (adopted
   freer can race a new slot-claimant → double-free). Cleared with LOCAL_UNLINK everywhere.
3. **347**: sweep/worker trusted CACHED nlink — stale-high when survivor==opener never saw
   dead peer's droplink → skipped enqueue → leak. Sweep enqueues EVERY chained inode
   (chain = on-disk truth); worker takes coherence ilock (SHARED, ride the acquire reload)
   BEFORE gen/nlink checks and BEFORE authority restore.

## Test-harness lessons (tests/openunlink_deaths.sh now embodies them)
- ino-reuse probing is UNSOUND as a free detector (XFS alloc cursor won't revisit the chunk).
  P89-REAP-DONE is the authoritative signal.
- dd of /proc/PID/fd/N ADVANCES the shared file-description offset — a second read hits EOF
  (looked like data loss; wasn't).
- Rebooted VMs lose /src (NFS not in fstab) AND iSCSI sessions; restart_node now mirrors
  run.sh's restore recipe (discovery both portals + login + rescan + multipath) then
  prep_node.sh rejoin. WORKS (test2 rejoined clean).
- P19/P2L prints cap at 300/boot — never assert on them after a busy uptime.

## FOREIGN-REPLAY TEAR — live damage captured (D-FOREIGN-REPLAY-UNGATED-IMAGES)
Same test, next run: B died ~5s after rm. Replay of B's slice APPLIED the inode item
(nlink->0 durable) but SKIPPED the two untagged BUFFER images (P223-FR-UNTAGGED-SKIP,
type 0x123c ×2 = dirent-removal block + AGI bucket insert). Torn recovery state that never
existed anywhere: dirent PRESENT → nlink-0 zombie on NO bucket (sweep found bucket empty;
`ls` shows `d????????? .oud_...` on test1). foreign_replay_untagged_apply=0 (default skip)
IS the tear mechanism when mixed with applied inode items of the same transaction.
**tests/openunlink_deaths.sh unlinker_death is now a deterministic ~2min reproducer.**
Both defect arms live: false-skip tear (this) and false-apply revert (LSN-incomparable).
Next: GPT consult on atomic-transaction foreign replay vs commit-time tagging of ALL images.

## State: 0.11.347 (232CFE303F69AAF453A0C8E) deployed 32/caw; board NOT yet re-run on 347
(343 board was all-green; 344-347 changes are reap/sweep + death-harness only, but board
re-run required before any closure claims). opener_death case not yet run. 9 OPEN defects
(8 original + trunc FIXED-VERIFIED... = 7 original OPEN + trunc closed → total open 8:
recount: FOREIGN-REPLAY, MATRIX, SHARED-DIR-PACE, INODE-CLUSTER-PUBLISH, READDIR-PACE,
DIRVIEW, AGI (sweep done, needs gate+matrix), OPEN-UNLINK (needs C7/C9/matrix arms)).
