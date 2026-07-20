---
name: sess10run2-r8-forensics-t3-stale-serve-conversion-fork
description: sess10(a9a03929) r8 round-13 FORENSICS (recovered /root snapshots): 59 dirents durably lost from block0 daddr=7872; t3 stale-serve (P5D) + conversion…
metadata:
  type: project
---

# sess10 (run a9a03929) — r8 round-13 mass-loss forensics

## Evidence source
Test's own `/root/drc_fail_r13_rank*.dmesg` snapshots (line 151 of dir_reuse_coherency.sh) survived the reboots — journald boots from before 17:18Z were LOST (virsh destroy skips journal flush), so these /root snapshots are the ONLY forensic channel. Pulled to session scratchpad `r8_r13_t*.dmesg` + `tl_7872.txt` merged timeline.

## Corrected failure model (vs sess9 memory)
- Round-13 storm dir = **ino 2529** (>256!) → the ENTIRE storm probe family (P49-STALEBASE, P13-COLLIDE, P9-LFREE, P13-LADD, P11-DATALOG) was **scope-blind in-suite**. That's why nothing fired — not because no clobber happened.
- The 59 missing names were **LOOKUP_ENOENT + REREAD_MISS** on ALL 4 nodes (drc-CLASS) — genuine durable dirent loss in ONE data block (block0, daddr **7872**, a low reused daddr; blocks 1/2 = 2096976/2097440, leaf = 2096520). The test's `lookup_fail=0` only covered names readdir listed.
- Missing set = everything placed into block0 after a cut: node1 f4+, node2 f9+, node3 f11+, node4 f10+; all md5s (later, blocks 1/2) survived.

## Cross-node block0 timeline (round 13, uptimes ±72ms aligned)
- 341.95–342.56: create storm; t1 places f1–f50 in block0 (block format), P5-UNDEST-SALVAGE ×10 on t1 (keeps its undestaged base); t1 block-format writes at 342.373 + **342.561** (P-BLKWR = write verifier = real submission; content should carry f1–f50).
- t3: P36-EVICT-RECOVERED (drop stale base pre-RMW) 341.98 ×2 + **342.928**; then t3 logs the FIRST leaf1 buffer at **343.066** = t3 performed block→leaf CONVERSION.
- t3 **P5D-STALE-SERVED**: leaf 2096520 at 343.161, block0 7872 at **343.257** (+P34-TRYLOCK-STALE rc=-11) — deferred-stale invalidation couldn't apply within the bounded 50ms honor-wait (block busy in the write storm) → **stale image knowingly served, consumer likely an addname RMW**.
- Peers destage block0 repeatedly 343.6–343.8 (P64-N1F1 kworker writes, all present=1 for canary f1). **LAST write of block0 = t3 at 343.810**. NOTHING writes 7872 after.
- Verify at 347.74: t1 block0 NOT cached (P-RDPATH in_cache=0) → fresh platter read → 59 entries gone. All nodes identical.

## Prime hypothesis (S2, needs content-level proof)
t3's EX-grant reload flagged its cached block0 stale (`b_mxfs_stale_pending`); the xfs_da_read_buf honor-wait (25×2ms) expired while the buffer stayed busy → served the stale base to a MODIFYING path (P5D at 343.257); t3 batch-added onto that stale base; t3's later destages (last word 343.810) durably erased the coherent lineage's 59 dirents. Alternative S1: t3's 342.928 platter re-read predated visibility of t1's 342.56 write (write-in-flight) → stale conversion base. Both are "RMW proceeds on non-cluster-latest base + last-writer-wins".
P5D sites: xfs_da_btree.c ~3262 (LOCKED) & ~3320 (busy) inside xfs_da_read_buf; comment admits "on exhaustion serve stale as before".

## Build 48BCA7DF (deployed next) — instrumentation for the decisive repro
- `mxfs_ino_watched()` helper (xfs_mxfs_dlm.h) reusing PRE-EXISTING `mxfs.watch_ino` ullong modparam (xfs_mxfs_dlm.c ~22367): 0=legacy ino<=256, N=only N. Rescoped: P9-LFREE, P13-LADD, P11-DATALOG (also fires when watch>1 armed), P2-EPOCHPLACE, P13-COLLIDE+P49-STALEBASE, P28E, P10-RDBLK, P-DIRWR (uncapped when watched + leaf owner extraction).
- NEW P10-RDBLK (xfs_dir2_leaf_getdents): per data block consumed by watched-dir readdir → active count + b_ep/valid_ep/b_gen/dir_gen/flags/dirty/pin.
- NEW mxfs_dirdump() (xfs_dir2_readdir.c) + magic-name trigger `.mxfs_dirdump*` at top of xfs_lookup (returns ENOENT, zero coherency side effects): per block in-core vs platter active counts + pmagic/powner + buffer state.
- P5D prints now carry trans=%d comm realns.
- dir_reuse_coherency.sh: arms watch_ino per round (stat %i), fires .mxfs_dirdump1 at RDMISS + .mxfs_dirdump2 after CLASS loop.
- run.sh: on FAIL pulls per-node `journalctl -k -b 0` into the artifact dir (kernlog_*).

## Repro plan
Full 4/tcp suite with MXFS_EXTRA_MODARGS='watch_ino=1' (sentinel keeps probes quiet until dir_reuse arms real ino). Flake rate ~1/4 suite runs (r8 had it in rounds 6 AND 13). On FAIL: read P-DIRWR crc/active timeline for block0 + P11-DATALOG placements + P10-RDBLK + DIRDUMP to pin S1 vs S2, then fix (candidate: at EX grant, stale_pending set must resolve before modifications are allowed; or fail-and-retry the RMW read instead of serving stale).

## Fix candidates (do NOT implement before proof)
- Grant-time resolution: after mxfs_dlm_reload_inode flags stale_pending, do not return the EX grant to the caller until every flagged dir block is invalidated (wait is pre-trans → deadlock-safe vs read-time wait).
- Read-time: on honor-wait exhaustion for tp!=NULL (modifying) consumers, return -EAGAIN and restart the op instead of serving stale (needs caller retry plumbing).
