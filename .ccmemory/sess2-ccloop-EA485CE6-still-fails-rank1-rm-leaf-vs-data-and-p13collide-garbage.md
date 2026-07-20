---
name: sess2-ccloop-EA485CE6-still-fails-rank1-rm-leaf-vs-data-and-p13collide-garbage
description: sess2(ccloop relay): EA485CE6 STILL fails 8/tcp 0/8 (prev "corruption eliminated" was run-variance). Two faces: durable readdir=700/800 loss + DABUF_…
metadata:
  type: project
---

## sess2 (ccloop relay run 6614aa96) — fresh evidence on current build EA485CE6

### Baseline re-measure: EA485CE6 FAILS 8/tcp dir_reuse 0/8 (drc_reliab_iter.sh 8)
Prev session's "ALL corruption eliminated" claim = RUN VARIANCE / false. This clean-reboot run reproduced BOTH faces. So EA485CE6 is NOT corruption-free.

### Failure anatomy (always-on probes, NO dirwr perturbation):
1. **PRIMARY durable loss**: readdir=700/800 (sometimes 799, 719) — exactly **one node's worth (100 = 50 files+50 md5)** missing, persists every round from ~r7. lookup_fail=0 (listed names all lookup-able).
2. **SECONDARY shutdown**: DABUF_MAP_HOLE (xfs_da_btree.c:2885, !HOLE_OK) → later DLM ino=131 mode=5 rc=-110 timeout → "Corruption of in-memory data" shutdown.

### KEY LOCALIZATION (decisive): corruption is rank1-ONLY
test1 (rank1, the dir-lifecycle owner doing mkdir+rm-rf): IFLUSH-GAP=90, DABUF-HOLE=12, shutdown=1. **All 7 peers: IFLUSH-GAP=0, DABUF-HOLE=0, shutdown=0.** rank1's rm FLUSHES a gapped data-fork map (P-IFLUSH-GAP-DETECT, comm=rm) at t=206 — 106s BEFORE the read-hole at t=312. So rank1's rm is the corruption PRODUCER (write-side).

### Mechanism chain (leaf-vs-DATA divergence):
- The 100 lost entries' DATA is gone from rank1's data blocks (readdir walks data → 700/800) but their LEAF hash entries survive → rm walks leaf → maps a freed/garbage block → DABUF_MAP_HOLE. **Fix the create-time dirent loss → both faces vanish.**
- P-HOLE-DISK at the hole: disk map=[0,5]+leaf nx=3, di_size=24576(6blk), leaf refs blocks 1-4 = DISK-TORN durable. Sparse map [0,5] is LEGIT XFS (shrink_inode middle-block free); corruption = stale LEAF referencing the freed blocks.

### P13-COLLIDE = SMOKING GUN but AMBIGUOUS (resolve next):
test2/4/6 hit P13-COLLIDE: a dir addname places its dirent at a daddr whose ON-DISK content is **non-dir GARBAGE** (dmagic=0x59f6a212/0x9ac4c6a9 random, garbage downer, **ourdir=0**), buffer dirty=1 done=1 **bufgen=0 cohgen=0** (FRESH buffer). Two readings:
  (a) **Physical block DOUBLE-ALLOC** — dir data block overlaps a file's urandom data block (AG free-space coherence failure / bnobt double-alloc family, sess42/43/81). Durable loss.
  (b) **Benign fresh-block disk-lag** — freshly-allocated dir block, in-core correct (dirty=1), disk still holds prior-tenant garbage not yet overwritten (the CLAUDE.md "mkfs O_SYNC zero not durable on LIO" / stale-disk-garbage class). P13 = false positive.
bufgen=0/cohgen=0/dirty=1 LEANS toward (b). MUST disambiguate: after a fresh fail, FUA-read the missing entries' expected daddrs from multiple nodes — physically present (reader-stale) vs absent/garbage (durable double-alloc/clobber).

### Refuted-this-session: P54-KEEPGUARD-STALE=0 everywhere (the addname epoch-refresh keep-guard is NOT blocking; epoch refresh P28-ADDNAME-EPOCHSTALE fires 1-5×/node and works). So the residual loss is NOT the keep-guard-stale path.

### Build state: EA485CE6 deployed (local /src/mxfs/mxfs.ko, loads via NFS on nodes). Harness: tests/tcp/drc_reliab_iter.sh 8 (reboots 8 VMs + run.sh 8 tcp dir_reuse_coherency, ~7min). dirwr=1 HIDES the race (sess52) — use always-on probes only.

### NEXT (RULE 4): disambiguate P13-COLLIDE (a) vs (b). If (a) double-alloc → AG free-space coherence (per-AG DLM reload, b_mxfs_ag_gen). If (b) → the durable 100-loss is elsewhere (stale-base RMW slipping past epoch refresh, OR cross-node dir-data create lost-update). Then fix producer, not rank1-rm consumer.
See [[sess49b-FINAL-corruption-fixed-remaining-node6-write-durability]] [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]] [[sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents]]
