---
name: sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock
description: sess25 PROVEN via dataclobber=1 detect: dir_reuse 8/tcp readdir=799 clobber is ALWAYS a background (in_txn=0) destage of a stale in-core dir DATA blo…
metadata:
  type: project
---

## sess25 (ccloop 4cb2d0a2) — DECISIVE dir_reuse 8/tcp diagnosis

CURRENT STATE: build 8A437A71 (keeper). 1/2/4 tcp = 17/17. 8/tcp = 16/17, LONE blocker = dir_reuse_coherency. The other 3 (cache_coherency, zero_silent_loss, fault_netpartition) were CASCADE victims of a contaminated full-suite run — ALL PASS clean-standalone 8/8 (verified this session). So fixing dir_reuse → full 8/tcp.

### Failure: durable single-entry lost-update (readdir=799/800, lookup_fail=0). Round 15 keeper lost node7_f14.md5 (LOOKUP_ENOENT, REREAD_MISS = durable). dirino=131 IDENTICAL on all nodes → intra-inode dir-block lost-update (NOT dentry/iget reuse).

### REFUTED this session:
- **tenure_evict=1 + dir_evict_prior_tenure=1**: still FAILS. The acquire/modify-path evict is NOT the issue.
- **P68-EVDECIDE evidence (keeper r15)**: ZERO `undurable=1 done=1` for ino=131 → the evict NEVER keeps a stale DONE base; it always evicts/invalidates. So "stale RMW base kept by evict" theory is WRONG.

### PROVEN via `dataclobber=1` (detect-only) run + per-node dmesg:
- The clobbering WRITE is ALWAYS `in_txn=0` (0 clobbers with in_txn=1 across all 8 nodes). NOTE: in_txn=0 is NOT a discriminator — XFS writes ALL metadata outside transactions (log→CIL→AIL→xfsaild destage). So every dir-block write is in_txn=0.
- The clobber is the EX HOLDER's own background destage: `mode=5 real_mode=5` (real DLM grant = EX), `in_ail=1`, `bdirty=0 pin=0`, comm=dd/bash (AIL-push in app ctx, NOT release-drain which is kworker).
- **stale=0** (bufgen==dirgen) on the lost-update writes → gen/epoch guards are BLIND (matches CLAUDE.md sess22 "count guards blind"). The dangerous face is `kind=data` EQUAL-count, DIFFERENT-fingerprint (two nodes filled the same free slot from divergent bases → one entry replaces the other → global -1).
- ex_write_guard (default ON) only suppresses NON-EX writes (dir_not_held_ex); the clobber is EX-held so it slips through. dir_stale_incarn_skip requires dc_stale (bufgen<dirgen) → blind to stale=0. Both useless here.

### ROOT (feedback loop): EX holder's in-core dir block becomes stale (loses a peer's entry) → background AIL-push destages that stale block over the peer's fuller disk → disk now stale → next acquirer's evict+reread fetches the (now-stale) disk → stale RMW base → repeats.

### FIX DIRECTION (the GFS2 invariant): a multi-node dir DATA/LEAF block's on-disk image must change ONLY via the EX holder's synchronous release-drain (Inv-1 handoff fence) — NEVER via background xfsaild/AIL-push destage. Then between an EX holder's acquire(read coherent disk)→release, disk is FROZEN, so the holder's view = acquire-disk + own-mods = coherent superset; release-drain lands it; next node reads coherent. Handles ADD and REMOVE correctly (release-drain writes current in-core, post-remove) → NO legit-remove resurrection (the trap that made dir_stale_incarn_skip catastrophic sess22, and write-suppression a corruptor sess23). IMPLEMENT: in pal/linux/xfs_buf.c submit hook, DEFER (keep in AIL, don't write) a background destage of a multi-node dir DATA/LEAF block when this node holds it; ALLOW only (a) the release-drain write (mark it via a per-buffer/per-task flag) and (b) sync flush under AIL/log pressure. Edge: long EX hold with no BAST → AIL fills → need a pressure safety-valve that does a COHERENT sync flush, not a raw background write.

[[sess24-PATCH5-fixes-corruption-passes-8of8-once-but-intermittent-reread-wedge-remains]] [[sess22-readdir799-is-content-divergent-clobber-count-guards-blind]]
