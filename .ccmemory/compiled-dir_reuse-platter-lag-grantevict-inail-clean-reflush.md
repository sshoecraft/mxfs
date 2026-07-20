---
name: compiled-dir_reuse-platter-lag-grantevict-inail-clean-reflush
description: sess36-38 dir_reuse endgame: platter-lag target-flush PASS, grant-evict/ail-defer combos, decisive gen-blind in-AIL clean-subset reflush clobber.
metadata:
  type: project
tags: [compiled, dir_reuse, cache_coherency, platter-lag, grant-evict, zombie-bli, xfsaild, tcp-dlm]
---

## dir_reuse_coherency endgame (sess36-37): the readdir=799 single-dirent durable loss

Central topic: the ship-blocking `dir_reuse_coherency` criterion (8/tcp) fails with a
durable single-directory-entry loss (readdir=799/800, then propagated to ALL nodes) on
REUSED daddrs/inodes across rm-rf rounds. sess36 found a platter-lag mechanism and a
config that PASSED once; sess37 re-instrumented and REFUTED the simple readside/zombie
framings, converging on a gen-blind, in-AIL, clean, content-divergent EX-holder reflush
of a stale subset. 1/2/4 tcp pass keeper-equiv throughout; only 8/tcp fails.

### Build progression
- `4703FA18` — the "keeper" baseline (sess33 head).
- `64544CAD` — keeper + `dir_grant_evict=1` (default ON) + `dir_conv_genbump=0`. See
  [[sess36-FIX-grant-gen-modify-evict-keepguard]] [[sess36-grant-evict-insufficient-loss-is-platter-lag-reread]].
- `CF57F8AB` — keeper-equiv; grant_evict + dir_conv_genbump BOTH default 0. Safe, no
  regression. sess36 disk head. [[sess36-HEAD-handoff]] [[sess36-PROMISING-grant_evict-plus-ail_defer-combo]].
- `C949F3C3` — sess37 instrumentation build (P28-PLATTER compare; master_self field).
  [[sess37-REFUTED-release-retire-bli-and-readside-coherent]] [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]].
- `24946150` — sess37 dataclobber=1 detect-only ground-truth build. [[sess37-FRESH-clobber-groundtruth-bgen0-rmw-on-stale-base]].
- `DFAEAF39` — sess37 disk head, keeper-equiv at default; all sess37 levers default 0.
  [[sess37-HEAD-handoff]].

### sess36: grant-evict fix, then the platter-lag breakthrough
`dir_grant_evict` ([[sess36-FIX-grant-gen-modify-evict-keepguard]]) wires grant_gen into the
modify-EVICT keep-guard in `mxfs_dir_evict_data_blocks` (xfs/xfs_mxfs_dlm.c ~3829): force-
evict a clean in-AIL DONE block whose `b_mxfs_grant_gen != ip->i_dlm_cached_grant_gen`
(both nonzero). grant_gen is the acked-TCP authoritative "lock changed hands" token
(dlm.c dlm_next_gen); epoch/dir_gen under-fire on TCP. It also retires the evicted block's
lingering BLI (P34-NEWTENURE-RETIRE) to avoid the sess26/33 zombie-reflush → readdir=0
trap. New probe P36-GRANTEVICT (gated dirwr/instr).

Result ([[sess36-grant-evict-insufficient-loss-is-platter-lag-reread]]): grant-evict is
SAFE (0 shutdowns, fires correctly) but INSUFFICIENT — readdir=799 loss persists on all 8
nodes. Evicted blocks are `in_ail=0 undestaged=0 undurable=0` = already refreshed base, so
a FRESH RMW base still loses an entry. This REFUTES the stale-base-RMW-at-modify theory as
sole root. Lost entry traced: `node2_f49` (node2's own file), added to daddr=14654480
off=1552, then durably LOOKUP_ENOENT + REREAD_MISS on ranks 1,4,5,6,7,8.

New lead → FUA-platter-lag: node2 adds f49, releases EX (drain); a peer acquires EX,
grant-evict clears XBF_DONE + FUA-re-reads — but the FUA read hits the PLATTER, which LAGS
the LIO target write-cache where node2's drained f49 still sits (CLAUDE.md: "LIO drops SCSI
FUA bit"; "pwrite-O_SYNC zero not durable on LIO"). Peer's "fresh" reread is MISSING f49 →
RMWs its own files onto that base → release-drain writes the block WITHOUT f49 → durable
loss everywhere. This explains why EVERY base-refresh fix (acquire-evict / dir_gen / epoch /
grant_gen) failed: the problem is downstream of the cache — the durable medium the FUA read
targets lags the writer's drain.

BREAKTHROUGH ([[sess36-BREAKTHROUGH-platter-lag-target-flush-PASS]]): `dir_modify_target_flush=1`
(xfs/xfs_mxfs_dlm.c ~5487, issue SYNCHRONIZE CACHE to the shared target after the modify-
evict, BEFORE the post-evict FUA reread) → `./run.sh 8 tcp dir_reuse_coherency` = **PASS 8/8**
(1 clean-reboot run, ~6min). Note: explicit SCSI SYNCHRONIZE CACHE / SCSI WRITE(16)+FUA
commands WORK on LIO even though bio REQ_FUA is dropped (same mechanism as the read-FUA
workaround). Optimization direction: move the flush from per-reader-modify to the WRITER's
release-drain (once per EX release) — `dir_release_fua_write` (xfs_mxfs_dlm.c:3539) re-issues
each drained dir block as an explicit SCSI WRITE(16)+FUA before DLM unlock, stronger than
the flaky bio-level blkdev_flush that LIO drops. A single `dir_release_fua_write=1` capture
was left in flight at sess36 handoff (scratchpad/cap_fw.log).

sess36 proven diagnosis via dataclobber=1 + grant_evict capture ([[sess36-HEAD-handoff]]):
the clobber signature P-DATACLOBBER-SKIP = `real_mode=5(EX), in_txn=0, in_ail=1, bdirty=0,
stale=0 (bufgen==dirgen, GEN-BLIND), SAME incarnation, comm=dd/rm`; leaf clobbers are count-
preserving hash-divergent (371==371, different hashes), data clobbers off-by-one during rm.
Mechanism = PLATTER-LAG feedback loop: stale async write → stale disk → stale acquire-reread
→ stale RMW → stale async write. Lost files: node2_f49, node8_f40.md5, node5_f3 — all on
reused daddrs/inodes.

grant_evict + `dir_ail_defer` combo ([[sess36-PROMISING-grant_evict-plus-ail_defer-combo]]):
ail_defer encodes the GFS2 invariant (only the release-drain writes contended dir blocks;
impl xfs_mxfs_dlm.c:18544 returns XFS_ITEM_LOCKED in the buf_item push). Combo = 2 PASS /
1 FAIL+SHUTDOWN → DISQUALIFIED: ail_defer's deferred BLIs pin the AIL tail → log fills → DLM
acquire blocks → 184s starvation shutdown (test1 unreachable). Even the passes broke the
loop only by luck. The wall: any write under pressure must be COHERENT, but in-core content
is sometimes stale-by-content despite grant_evict (the freshness stamps LIE: stale=0 over
stale content), so you cannot just "allow the destage." Needs a liveness valve that never
starves the log tail.

### sess36 refuted levers (do NOT retry)
- `dir_conv_genbump` (bump i_dlm_dir_gen in xfs_dir2_block_to_leaf) — readdir=796, sess35
  conversion-gen theory refuted.
- `dir_drain_merge` — CATASTROPHIC: readdir=471, duplicate names, shutdown (DATA-graft over-
  grafts). Confirms sess34 leaf-desync wall.
- `dir_grant_evict` ALONE — safe, fresh base, loss persists.
- `dir_modify_target_flush` per-modify — flaky as bio blkdev_flush (LIO-dropped); the WORKING
  form uses explicit SCSI SYNCHRONIZE CACHE.
- `dir_ail_defer` — 184s starvation shutdown.
- `dir_zombie_retire` — !DONE-gated; the loss-write block is DONE=1.
- dir_tenure_evict / dir_evict_prior_tenure (sess30/32), conv_genbump — all refuted.

### sess37: reads are coherent; the loss is a stale DESTAGE
sess37 re-instrumented ([[sess37-REFUTED-release-retire-bli-and-readside-coherent]]): P28-
PLATTER FUA-read-vs-in-core compare at addname (build C949F3C3) = **7152 MATCH vs 48 DIFFER**,
and ALL 48 DIFFER are dirty=our-own-uncommitted-work. A CLEAN in-core dir block ALWAYS
equals the platter → the RMW base at addname is coherent → the loss is NOT a stale read/RMW
base. It is a stale DESTAGE of a block that was correct at addname but reflushed later in a
peer-superseded form. (This partially walks back the sess36 platter-lag reread framing: the
readside was measured coherent under the sess37 stack.)

BLI-retirement code facts ([[sess37-CORRECTION-bwrite-retires-bli-zombie-theory-refuted]]):
`__xfs_buf_ioend` (pal/linux/xfs_buf.c) line ~1387 calls `xfs_buf_item_done` on the write-
completion branch, which does `xfs_trans_ail_delete` + `xfs_buf_item_relse` (AIL delete +
BLI free). `xfs_bwrite` = submit + iowait, so by the time the release-drain bwrite returns
the BLI is ALREADY retired+freed. This REFUTES the sess32 "xfs_bwrite does NOT retire the
BLI" claim and the "zombie BLI survives the release path" theory. Corollary: the delwri-
submit refactor lead is MOOT — xfs_buf_delwri_submit shares xfs_buf_submit + the same
__xfs_buf_ioend completion, so it retires BLIs identically, no improvement.
(NOTE: this DIRECTLY contradicts the sess37-HEAD-handoff "NEXT = delwri-submit" proposal,
which was written before this correction; the delwri path is dead.)

`dir_release_retire_bli` (manual `xfs_buf_item_done` after the release-drain xfs_bwrite,
mxfs_dir_flush_one_daddr ~line 1978) = CORRUPTION: `XFS (sda): Metadata I/O Error (0x1) at
xfs_trans_read_buf_map` → FS SHUTDOWN all nodes, round 1. It was a DOUBLE xfs_buf_item_done
(ioend already called it) → use-after-free. Manual BLI retire after bwrite is categorically
a corruptor. `mxfs_dir_release_invalidate`'s `xfs_buf_stale` (xfs_mxfs_dlm.c:4374/2046,
default on) marks XBF_STALE but does NOT remove the BLI from the AIL.

### sess37 decisive characterization of the clobber
master_self measurement ([[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]]):
genuine-EX (real_mode=5) clobbers = master_self=0 → 166, master_self=1 → 11. CONFOUND: the
dir inode (131) is mastered by ONE node so 7/8 are non-master by population (166/177=94% ≈
87.5% population) → master_self=0 dominance does NOT prove stale-local-DLM. What IS proven:
the 11 master_self=1 clobbers occur on the AUTHORITATIVE master where mxfs_dlm_audit_double_grant
fires 0× (no double-grant), yet a genuine-EX clobber still happens → NOT a DLM grant error;
it is an INTRA-NODE stale-cached-buffer reflush. Signature (build C949F3C3): bufgen=0 stale=1
in_ail=1 bdirty=0 in_txn=0; kinds data+leaf; leaf daddr=6279744 buf_cnt=117 vs disk_cnt=379.

Fresh ground-truth split ([[sess37-FRESH-clobber-groundtruth-bgen0-rmw-on-stale-base]], build
24946150, dataclobber=1 detect-only, 299 events): the clobbers are TWO classes —
- CLASS 1 FALSE POSITIVES (majority, daddr=120 block-0): rm-rf teardown removing entries
  one-by-one; buf_cnt decreasing (154,153,152...), disk_cnt = buf_cnt+1, stale=0. disk_cnt>
  buf_cnt is EXPECTED. This is why enforcing dataclobber>=2 was CATASTROPHIC (lookup_fail=150
  — it skipped legit rm removals).
- CLASS 2 THE REAL LOSS (data/leaf, comm=dd/bash/xfsaild): **bufgen=0 (stale=1)**, dirgen=35/42.
  e.g. leaf daddr=4186520 buf_cnt=117 disk_cnt=379 → a stale PARTIAL leaf about to overwrite
  the peer's full 379-entry leaf, dropping ~262 (sess12 leaf-clobber family). KEY CORRECTION
  over sess36: the REAL loss has bufgen=0, NOT bgen==dir_gen. bgen=0 = the buffer was NEVER
  coherently re-read (evicted-not-reread, OR obtained via `xfs_da_get_buf` fresh-without-read),
  carries un-landed local content (logged_seq!=written_seq, UNdestaged) so it CANNOT be
  safely dropped. This is an RMW/REBUILD-ON-STALE-BASE: a leaf rebuilt via xfs_dir2 get_buf
  during block→leaf conversion or leaf split, on a base never coherently read → drops peer
  entries on durable write. Candidate sites: xfs_dir2_leaf.c / xfs_dir2_node.c / xfs_dir2_block.c
  get_buf paths; `mxfs_dir_rebuild_leaf_from_data` (xfs/libxfs/xfs_dir2_leaf.c, sess22) may
  rebuild the leaf-hash index from a stale/partial data scan. Fix direction: force a coherent
  FUA re-read of the base BEFORE any RMW/rebuild at a get_buf site whose block is bgen<dir_gen.

Residual face with best read-side stack ON ([[sess37-residual-is-equal-count-content-divergence-xfsaild-leaf]],
config dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1
dir_addname_platter_guard=2): the DOMINANT clobber is a GENUINE EX holder — mode=5 real_mode=5
(via mxfs_v5_dlm_inode_held_rawmode) = **1890 events**; stale-cached EX (real_mode=0) = only
**2**. So dir_ex_write_guard (gates on cached i_dlm_mode) using real_mode would catch only the
2 rare ones, NOT the fix. Residual signature: kind=leaf/data daddr=6279744, buf_cnt==disk_cnt
(EQUAL, e.g. 374/374), bufgen==dirgen (stale=0), in_ail=1, bdirty=0, pin=0, comm=xfsaild/dd —
a background reflush by a node genuinely holding EX of a buffer whose content DIVERGES from
disk at EQUAL entry count. Lost entry: node4_f2 (`P26-DSCAN-MISS ndb=6 scanned=801` genuinely
absent; `P33-DSCAN-ONDISK incore==disk fmt2 nx10 sameincarn=1` — inode agrees, only DATA-block
content lost the entry).

THE PARADOX: under continuous genuine EX no peer can write disk, yet the holder's freshly-read
(bgen==dirgen) buffer diverges from disk. Two candidate explanations, both sound to pursue:
1. Cross-master double-grant the auditor misses — mxfs_dlm_audit_double_grant scans only THIS
   master's table; if dir-inode mastership is distributed, a conflicting EX grant on a DIFFERENT
   master is invisible (sess49's proven gap: mxfs_v5_dlm_inode_held is a NO-OP on TCP; a
   dropped/deferred TCP BAST leaves a peer modifying under our nominal EX).
2. Read-served-stale on acquire — FUA re-read on EX acquire returns a stale platter image (LIO
   read-cache lag) so bgen==dirgen but content is behind disk.
All count/gen/incarn/cached-mode guards are BLIND to this (equal count, current gen, same
incarn, cached EX). Cheap decisive next diagnostic: at P-DATACLOBBER detect, when real_mode=5
and content diverges, dump whether a PEER currently holds EX/PR on this dir (cross-node holder
dump) → settles double-grant vs read-served-stale.

### Two contradictory but coexisting sub-mechanisms (reconcile carefully)
- CLASS-2 bgen=0 / stale=1 RMW-on-stale-base at get_buf rebuild sites (sess37 fresh ground-
  truth) — an UNdestaged buffer never coherently read.
- The 1890-event bgen==dirgen / stale=0 / EQUAL-count content-divergent EX-holder reflush
  (residual face with the read-side stack ON) — a clean, gen-current buffer that still diverges.
The sess36 gen-blind (stale=0) signature matches the second; the sess37 fresh detect matches
the first. Both are real; the read-side stack shifts the surviving population from the first to
the second. Any fix must handle the EQUAL-count, current-gen, clean case that all stamp-based
guards miss.

### Categorical standing negatives (proven repeatedly, do NOT retry)
- Write-side DROP/suppress of dir DATA at ANY chokepoint = corruptor (~5×, sess23/33/37).
- Manual `xfs_buf_item_done` / BLI retire after a manual release xfs_bwrite = Metadata-IO-Error
  shutdown (double-done use-after-free).
- Content-compare enforcement → ghost/duplicate wall; dataclobber>=2 enforce = lookup_fail=150.
- delwri-submit release refactor = moot (same __xfs_buf_ioend completion).
- Read-side stack + zombie retires ceiling ≈ 50% of 24-round runs.

### Best known config (sess37, ~50%, NOT 100%)
`dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1 dir_addname_platter_guard=2
dir_zombie_retire=1 dir_zombie_push=1` — all SAFE (read-refresh + !DONE-gated BLI retire).
Fails ~round 1 OR ~round 24. The ONLY sess36 config that hit PASS 8/8 was
`dir_modify_target_flush=1` (SYNCHRONIZE CACHE before post-evict FUA reread), single run,
never batch-confirmed.

### The two remaining sound directions
1. DLM serialization fix (sess49/sess10 "not converged"): make TCP dir-EX truly exclusive —
   synchronous demote-before-grant (a TCP BAST must demote i_dlm_mode→NL + drain + invalidate
   BEFORE the master grants a peer EX), and make the double-grant auditor cross-master-aware to
   prove/disprove cross-master double-grant. Add a real_mode-vs-cached-mode assertion at the
   dir-write chokepoint.
2. Owner-checkpoint (GPT design): route ALL dir-metadata writeback through the EX owner (defer
   xfsaild, land via a bounded owner-checkpoint + liveness valve + per-dir registry). Holds the
   invariant even under a brief double-grant window because only one node's release-drain writes.
   This also subsumes the flush/target-durability angle (dir_modify_target_flush / dir_release_fua_write).

### Harness
scratchpad/{cap.sh,batch.sh} "\<MODARGS\>" [N=24] = reboot + run drc 8/tcp + dmesg capture
(cap ≈ 6-7 min). Stream logs at tests/tcp/drc_cap/stream_rank*.log (OVERWRITTEN each run — mine
immediately after a FAIL: grep RDMISS for the lost name, P11-DATALOG for its daddr,
P-DATACLOBBER-SKIP / P-RELFLUSH for the clobber, P28-PLATTER for read coherence). After
`make clean` ALWAYS `make tools`. dataclobber=1 = detect-only (logs, still writes).
