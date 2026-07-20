---
name: compiled-dirreuse-4tcp-xfsaild-reflush-stale-buffer
description: Compiled sess69: 4/tcp dir_reuse single-dirent loss = xfsaild reflush of in-AIL clean stale dir buffer, poisoned by cross-node stale read-cache hit.
metadata:
  type: project
tags: [compiled, sess69, dir_reuse_coherency, tcp, xfsaild, read-coherency, cache-invalidation, cache_coherency]
---

# 4/tcp dir_reuse single-dirent loss — xfsaild reflush of a stale in-AIL dir buffer, poisoned by a cross-node stale read-cache hit

All of sess69, ccloop. Central finding: the `dir_reuse_coherency` criterion fails only at 4 nodes over TCP DLM as an intermittent single-dirent durable lost-update, and after refuting the entire 68-session DLM/coherency-detector apparatus, the true root was proven to be a **read-side** stale cross-node cache hit that poisons the RMW base, later flushed to disk by xfsaild — indistinguishable at every write-side chokepoint from a legitimate `rm`. No marker written; criterion NOT met. Baseline builds: `A81DB821`, `1B683F47` (= baseline + P-WRACT cap to 2M), `A6D2BC7B`, `DE3A7E21` (baseline + dirwr-gated probes, inert at production). All probes ship inert at `dataclobber=0 dirwr=0`.

## The two failures ([[sess69-PROVEN-4tcp-dirreuse-two-failures-handoff-underfires]])
Criterion = 1/2/4/8-node TCP DLM at 100%. 2✅ (sess58), **4❌**, 8 untested.
1. **Intermittent single-dirent durable lost-update.** Caught red-handed: round 17 lost `node3_f23` (kept its `.md5`); another run lost `node3_f2.md5`. `readdir=399/400`, `lookup_fail=0`, LOOKUP_ENOENT + REREAD_MISS on ALL 4 nodes including the creator ⇒ durable on-disk loss, not a local-cache miss. Always a peer's just-committed entry. dir ino reused every round (131/132).
2. **24-round TIMEOUT (RULE 0 failure).** `TEST_TIMEOUT=300s` (run.sh:49). 24 rounds reaches only ~round 21 (~13-16s/round) → NORESULT → FAIL. 14 rounds passes in budget; **20 rounds (~280s) fits AND still reproduces the loss** — the standard repro. Per-round cost: verify ~6s (drop_caches + 400 cold FUA lookups), rm ~4s, create ~2s + barriers. Work scales with node count (4n=400 entries) but budget is fixed ⇒ 4n overflows. Separate per-round-cost fix owed.

## Every DLM/coherency detector reports SUCCESS — the loss is invisible to all of them ([[sess69-DECISIVE-loss-invisible-to-detectors-double-grant-remaster]], [[sess69-REFUTATIONS-and-gpt-design-dirreuse-4tcp]])
Ran with full kernel-log **streaming to file** (`DRC_STREAM=1` → `dmesg --follow > /root/drc_stream_rankN.log`) because always-on probes (P25-INSTR, P82-ADD, P64-N1F1, P62-DWR-N1F1, P-DIRIFLUSH, P103-RELOAD-REUSE-ADOPT @3628×) overflow the 256KB ring within ONE round. Refuted with direct counts on the failing dir ino:
- `P-TDS-RMW`: every dir-EX-modify serve = `held=1 mode=EX stale_base=0`; **stale_base=1 count = 0** — no RMW ever runs on a detectably-stale base.
- `P-DOUBLEGRANT = 0`, `P-STALEMASTER-GRANT = 0`, `P106-STALE-EX = 0` (local mirror always holds EX at serve).
- `P-DE-BLK disp=SKIP = 0` (reacquire `mxfs_dir_drain_evict_data_blocks` evicts EVERY block it visits; `P-DE-ENTER nd` reaches 4 = data + leaf covered).
- `P-SF-DURABLE-FAIL = 0`, `P97-RELFENCE-WEDGE = 0` (sess97 release fence always bwrites dir blocks durable before handoff).
- `P116-RELOAD-SELFCLOBBER-SKIP ino=dir = 0` (reload not skipped). `MAPDIVERGE = 0` (sess68, extent maps agree at modify).

Caveat noted then: `P106` checks only local `mxfs_v5_dlm_inode_held`, not global exclusivity, so a true cross-node double-grant would not trip it — flagged as not-fully-refuted at that point (later closed out: EX is genuinely exclusive). Conclusion: EX is genuinely exclusive, every RMW holds EX with a fully-reloaded fresh base, release is fully durable — yet a dirent is durably lost. The 68-session "detect stale base + reload/evict/grant_gen/handoff" effort attacked the WRONG layer. Handoff-refresh also *under-fires* (dir BAST'd 155–218×/node vs ~50×/node slow `P63-HANDOFF` + ~0-1× fast `P63-FASTEX-HANDOFF`), because all fast-path refresh triggers depend on the **lossy async DIR_MODIFY eviction-ring** (`mxfs_dlm_note_evicted` at xfs_mxfs_dlm.c:14078 → bumps `i_dlm_dir_gen` + sets `MXFS_IF_DIR_RELOAD`), which drops messages on TCP. grant_gen (sess10/61) is implemented and refined (sess63, `mxfs_v5_dlm_inode_grant_handoff` / dg_shadow) but now UNDER-fires.

## Write-side suppression is HARMFUL and refuted twice ([[sess69-REFUTED-dataclobber-enforce-makes-it-catastrophic]])
`mxfs.dataclobber=2` (enforce sess41's write-side guard: plain-read on-disk block, skip xfsaild write if disk has strictly MORE live dirents + `dc_stale` prior-tenure): round 2 → **readdir=0/400 EMPTY dir on ALL nodes** — catastrophic vs baseline's single-dirent loss at round 8-19. Matches the project's repeated lesson (sess23 P122/P93 suppression became the corruptor; `mxfs.dirskip` enforce "refuted sess17" per xfs_mxfs_dlm.c:15430). **DO NOT retry `dataclobber>=2` or `dirskip=1`.** Implication: the writes are individually legitimate (each node holds EX, fresh base, `stale_base=0`, `P-DOUBLEGRANT=0`) — there is no single bad operation to catch. Reverted to defaults 0.

## Localizing the clobber: xfsaild reflush of a buffer one-entry-behind disk ([[sess69-ROOT-xfsaild-reflush-stale-dir-buffer-behind-disk]])
`dataclobber=1` (detect-only; compares each multinode dir data/leaf write vs current on-disk content — covers leaf-format, unlike block-0-only P-WRACT). `P-DATACLOBBER-SKIP` fired 280× / 20 rounds, categorized by comm/kind/stale/delta:
- **`xfsaild/sda kind=data stale=0 delta=1` (13×)** ← THE clobber. xfsaild background-flushes a dir DATA buffer ONE entry behind the durable on-disk block, reverting disk and dropping a peer's entry = the readdir=399/400 loss. `stale=0` (bufgen==dirgen, CURRENT-tenure stamp) ⇒ sess41's `dc_stale` bufgen<dirgen gate MISSES it, which is why enforce didn't fix it.
- `rm kind=data stale=0 delta=1` (177×) ← LEGIT rm-rf removals (buffer=disk-1 is correct).
- `*/leaf stale=0 delta=0` (75×) ← leaf rewrites (mostly legit reorg).
- `dd/bash kind=leaf stale=1 delta=275-281` (4×) ← fresh (bufgen=0) leaf-hash-hole clobbers; enforce DOES catch these via `dc_stale`.

The count signal `disk_cnt > buf_cnt` is fundamentally AMBIGUOUS: a legit rm buffer is `disk − {name this txn removes}`; the stale clobber is `disk − {a peer's entry this node never touched}`. Clearing XBF_DONE on acquire-evict only forces the next READ to re-fetch — it does NOT stop xfsaild from flushing the lingering BLI's stale `b_addr`. `dataclobber=1` detect is the right diagnostic; NEVER enforce.

## Refuting non-owner flush: the clobber holds REAL exclusive EX ([[sess69-FINAL-clobber-indistinguishable-from-rm-real-held-ex]])
Using the MODE-AWARE `mxfs_v5_dlm_inode_held_rawmode` (not the mode-blind `mxfs_v5_dlm_inode_held`) in the detector (build `A6D2BC7B`): at the single-entry clobber, `comm=xfsaild real_mode=5(EX)` ×4 vs `comm=rm real_mode=5(EX)` ×146. **Non-owner-stray-flush REFUTED** — the flushing node genuinely holds exclusive EX; owner-fence (skip held<EX) would not fire. The paradox: under exclusive EX only this node can advance disk, so this node itself put 159 on disk, yet a buffer with 158 for the same daddr, same incarnation, still exists and xfsaild flushes it. ⇒ two divergent content versions for one reused daddr = a stale lingering/duplicate `xfs_buf`. Suspected daddr free+realloc within a round (block↔leaf conversion / coalesce / split) leaving an old BLI in the AIL.

## Confirming the clobber buffer state: in-AIL, clean, superseded ([[sess69-CONFIRMED-clobber-is-inail-clean-superseded-buffer-reflush]])
Full state at the clobber (6 consistent samples, build `DE3A7E21`, dataclobber=1):
```
kind=data owner=131 daddr=120 buf_cnt=154 disk_cnt=155 bufgen=8 dirgen=8
mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 bflags=0x32
incarn==bincarn stale=0 comm=xfsaild/sda
```
Decisive: `real_mode=5(EX)`, `in_ail=1` but `bdirty=0 pin=0` (a LINGERING committed/destaged buffer, NOT un-checkpointed work), `buf_cnt = disk_cnt − 1`, `bufgen==dirgen`, same incarnation. daddr=120 = dir block 0 (reused every round). xfsaild flushes a CLEAN in-AIL block-0 buffer whose `b_addr` (154) is a SUPERSEDED earlier version while disk already advanced to 155. Because the buffer is clean (not dirty/pinned), the acquire-evict undurable-keep guards do NOT protect it from being flushed. Every prior guard missed it: count-suppression can't distinguish rm; tenure/gen/incarnation all pass it as current; owner-fence sees EX; stale-base-reload sees no read-time stale base.

## No write-side fix is possible — the buffer content REVERTED ([[sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted]])
Final discriminator (build `DE3A7E21`, `kind=data delta=1`): `comm=rm in_ail=1 bdirty=0 pin=0` ×184 (legit) vs `comm=xfsaild in_ail=1 bdirty=0 pin=0` ×6 (clobber) — **byte-identical buffer state** across every available signal (count, hash, dirty, pin, in_ail, tenure, gen, incarnation, real grant mode, txn context). ⇒ **No write-side suppression/skip can work** — anything that suppresses the clobber also suppresses legit removals (= the enforce=2 empty-dir catastrophe). STOP pursuing write-side chokepoint fixes (dataclobber/dirskip/owner-fence — all dead ends). What it proves about the root: a CLEAN in-AIL buffer at 154 while durable disk is 155 under exclusive same-incarnation EX means the buffer's `b_addr` content went BACKWARD (was 155 when disk was written, then reverted to 154). Under exclusive EX the only way is (1) a stale READ re-populated daddr 120 after it destaged at 155 — a re-read returned content older than durable disk = read-coherency bug — or (2) daddr-120 aliasing under reuse. Session refutation tally (do NOT retry): phantom-EX, double-grant, split-master, reacquire-evict-incomplete, release-not-durable, reload-skipped, detectable-stale-base, extent-map-divergence, non-owner-flush, write-side count-suppression, bdirty/pin/in_ail discrimination.

## TRUE ROOT (proven): a cross-node STALE READ-CACHE HIT poisons the RMW base ([[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]])
Reconstructed the full read/write content timeline of dir block 0 (daddr=120) by merging always-on `P-DIRRD` (read crc+fua) and `P-DIRWR` (write crc+count) across all 4 nodes by realns, mapping read crcs to write entry-counts, via `dirwr=2` (dirwr=1 = P-DIRWR only; P-DIRRD needs ≥2). **18 STALE READS detected on daddr=120, ALL 18 are `fua=0` (non-FUA) AND cross-node** (reader ≠ the node that wrote the latest version) — a read returned FEWER entries than a strictly-earlier peer write.

Fully-connected mechanism (every link evidenced):
1. A PEER acquires dir EX and durably advances dir block 0 to N entries on the shared target.
2. THIS node has daddr=120 cached as a STALE XBF_DONE buffer (N−k entries). The local-cache invalidation that should drop it is driven by the **lossy async DIR_MODIFY eviction-ring** (`mxfs_dlm_note_evicted` → `i_dlm_dir_gen`/`MXFS_IF_DIR_RELOAD`), which drops messages on TCP → buffer never invalidated.
3. This node does a non-FUA READ (`comm=bash`: md5sum/ls, or a create's read) → **CACHE HIT on the stale buffer**. FUA is irrelevant — a cache hit never issues a disk read, so `fua_disable`/FUA-passthrough cannot fix it; the buffer must be INVALIDATED to force a miss.
4. The stale read re-validates the buffer XBF_DONE, **poisoning the base**. A later fast-path (cached-EX, no reacquire-evict) create RMW reads this poisoned buffer, adds its entry, and durably writes back — DROPPING the peer's entries. That is the xfsaild-reflush clobber seen above: the write looks legit (real_mode=EX, stale_base=0, clean buffer, indistinguishable from rm) precisely BECAUSE the staleness was injected on the READ side earlier; the write just flushes the poisoned base. `P-TDS-RMW stale_base=0` because the lossy dir_gen signal never fired. The reacquire-evict (`P-DE-BLK SKIP=0`) IS complete — but these poisoning reads happen on paths that DON'T reacquire-evict (consumer_refresh fast-path / fast-path create) and rely on the lossy ring. This unifies every prior sess69 finding.

## THE FIX and its caveats (next session) ([[sess69-FIX-caveat-evict-on-release-refuted-thread-the-needle]])
Direction (GPT-5.5 design + this evidence, the GFS2/OCFS2 "invalidate on demote" model): make cross-node dir-buffer invalidation RELIABLE, driven by LOCAL writer-exclusion state, not the lossy ring/dg_shadow. When THIS node drops the dir below writer-exclusion (EX/PR → NL, i.e. a peer is taking it), AFTER the durability flush, invalidate all cached dir DATA/leaf buffers for that inode so any later read misses and re-fetches the peer's durable image. Wire it at the EX/PR→NL release/BAST path (xfs_mxfs_dlm.c release sites + bast_process), NOT `mxfs_dlm_note_evicted`. Keep continuous ≥PR holders on the fast path (RULE 0 timing). Alternative: a master-authoritative LVB-carried `dir_change_seq` in the grant response, consulted on the read/fast-path.

**CAVEAT 1 — naive evict-on-release was already REFUTED.** xfs_mxfs_dlm.c release path (~6059) comment: "the sess96 force-evict-on-release was REFUTED" — clearing DONE on a buffer with un-checkpointed work causes durable RESURRECTION (re-read loses our work / re-adds removed entries). The release path FLUSHES (in-core→platter), does NOT evict. So do NOT simply call `mxfs_dir_evict_data_blocks` at release. Thread the needle: invalidation runs AFTER the durability flush (`mxfs_dlm_dir_inode_durable` / `mxfs_dir_flush_data_blocks`) and ONLY on CLEAN/destaged buffers; prefer a per-buffer/per-inode "validated-under-grant epoch" flag the read path checks over clearing DONE. Regression-test 2/tcp `unlink_visibility`/`rename_visibility` for resurrection on ANY such change.

**CAVEAT 2 — the harder half: NL reads re-populate the cache stale.** A node at NL that READS the dir (md5sum/ls/lookup) re-populates the buffer XBF_DONE from disk; if a peer THEN advances the block, the next non-FUA read cache-hits the now-stale buffer (the proven stale reads were `comm=bash` at `fua=0`). So a non-grant-holder's read path must either (a) revalidate via a RELIABLE cross-node signal (a DLM-grant-carried `dir_change_seq`, not the lossy ring — the `mxfs_dlm_dir_consumer_refresh` path is meant to do this but is gated on the lossy `i_dlm_dir_gen`), (b) hold ≥PR while reading so the cached block stays valid, or (c) force FUA/uncached re-read of multinode dir blocks when the holder is below PR.

VALIDATE: `dirwr=2` RD/WR trace must show ZERO stale cross-node reads on daddr=120; then 4/tcp `dir_reuse` PASS; then full 2/tcp 17/17 ×3 (no resurrection regression) + 1/4/8.

## Repro / tooling (KEEP)
- Decisive trace+repro: `MXFS_EXTRA_MODARGS='dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency`, then merge P-DIRRD/P-DIRWR by realns and map read-crc→write-count (python in scratchpad).
- `dataclobber=1` = detect-only diagnostic (covers leaf-format); `dirwr=1` = P-DIRWR only, `dirwr=2` adds P-DIRRD. NEVER `dataclobber>=2` / `dirskip=1` (over-suppresses → empty dir).
- `tests/suite/dir_reuse_coherency.sh`: persistent `/root/drc_failrounds.txt` marker + per-round failverify snapshot + `DRC_STREAM=1` full-log streaming (always-on probes overflow the 256KB ring within one round — MUST stream to file).

## Infra hazards
- test2/test3 each wedged a D-state kworker (`mxfs-ino-bast` / `flush-8:0`) mid-session → recover ONLY via `virsh -c qemu:///system destroy/start <node>`.
- A node still holding the LUN (mxfs loaded) breaks node1's mkfs (`zero_region verify FAIL`) — ensure ALL nodes rmmod before prep.
