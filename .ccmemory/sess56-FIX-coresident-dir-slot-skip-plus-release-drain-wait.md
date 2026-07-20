---
name: sess56-FIX-coresident-dir-slot-skip-plus-release-drain-wait
description: sess56 TWO fixes got 2/tcp 17/17 (s5, build 5EA07421): (1) release-drain wait-until-clean on handoff; (2) partial-write SKIPs any not-logged DIR slot…
metadata:
  type: project
---

## sess56 — 2/tcp reached 17/17 (run s5, build 5EA07421509FFB83866E338). Criterion = reliable 17/17; reliability NOT yet confirmed (need ~6-8 consecutive clean-reboot PLAIN passes). Prior baseline ~50%.

Two independent, load-bearing fixes (RULE-4 proven each step; supersedes the sess55 ICLUSTER-lock plan — NOT needed):

### FIX 1 — release-drain wait-until-clean (xfs/xfs_mxfs_dlm.c `mxfs_inode_cluster_durable` ~1684)
ROOT (PROVEN d11, build 2C60CCE9): the 25×(~50ms) drain budget gave up when the dir's ILOCK was held by node1's own in-flight workload op (xfs_iflush_cluster trylock-SKIPs it → P55D), releasing the dir EX to the peer with a committed dirent change still in_ail → peer FUA-reads stale platter → RESURRECTION, then own P34D-RELOAD adopts stale disk → revert. Violates Architectural Invariant #1.
FIX: when this drain runs as part of a RELEASE (`i_dlm_state == DEMOTING/BAST`), new local dir ops are already diverted (ilock_begin dir gate: state!=CACHED) so the dir is quiescing — wait up to 1500 tries (~3s, well under peer ACQUIRE_WAIT=6000ms) for ip to leave the AIL instead of releasing stale. `icd_releasing`/`icd_max_try`; log_force only when pinned (no CIL storm). Op-side proactive durable (state==CACHED) keeps the short 25 budget. Verified: P9-ICD-FAIL → 0; eliminated the d11 give-up; suite went 50%→16/17 (only the read/RMW-side leak remained).

### FIX 2 — partial-write skips ANY not-logged DIR slot (pal/linux/xfs_buf.c `mxfs_submit_partial_inode_write` ~1727)
ROOT (PROVEN s3/s4, sess54-class): the shared hot dir D co-resides in a 4KB inode cluster with churned child FILE inodes (n*_rX files created IN D). A co-resident file flush rewrites the WHOLE cluster incl D's dinode slot. Old code wrote any HELD (PR/EX) slot unconditionally AND any slot where the flushing node didn't have D in-core (ip==NULL) → wrote D's STALE cached-buffer image (round-57 shortform still holding n2_r57) → durable dirent RESURRECTION. P56-RELOAD-MERGE proved reloads were CLEAN-adopting correctly (merged=0, post==disk) — the disk ITSELF was stale, written by these co-resident flushes.
FIX: skip EVERY slot whose buffer dinode is a DIR (`(be16_to_cpu(d->di_mode)&S_IFMT)==S_IFDIR`) and is NOT logged|bli_dirty this round — regardless of in-core/held state. A dir's authoritative on-disk image is written ONLY by its EX holder's LOGGED flush; every other cluster flush leaves the dir slot untouched. Per-inode v5 CRCs make isolated-run writes valid. (First attempt gated on `ip && held` only fired 30/10× but MISSED the ip==NULL case → still leaked s4; broadening to all not-logged dir slots → s5 17/17.)

### Probes added (always-on ratelimited, KEEP for now): P55D/P9-ICD-FAIL enriched (rel/state/exh/prh/comm); P56-RELOAD-MERGE (reload merged/clean/post_cnt/disk_cnt/resurrect); P56-CORESIDENT-DIR-SKIP (the skipped writes).

### DEAD-END this session (reverted): re-enabling the fast-path `mxfs_dir_sf_refresh_if_disk_differs` on every clean acquire (s2) — regressed dlm_fairness to a stall (got=4/50) and never adopted (P9-SFREFRESH=0); the leak was disk-stale not cache-stale, so a read-side refresh is the wrong layer. The dormant Edit-1 (dirty-gate the fast-path merge) is harmless (mxfs_sf_fastpath_adopt=0).

### NEXT: run ~6-8 consecutive clean-reboot `PLAIN=1 NOREBOOT=1 bash tests/tcp/fg_one_run.sh sN` for reliability. If solid, consider removing/quieting the probes, then write criteria-met. Watch dir_reuse_coherency perf (~285s, RULE-0) AFTER reliability. Repro/marker path unchanged.
