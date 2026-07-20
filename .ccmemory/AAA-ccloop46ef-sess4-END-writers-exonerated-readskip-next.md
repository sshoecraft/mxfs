---
name: AAA-ccloop46ef-sess4-END-writers-exonerated-readskip-next
description: sess4 END: P70 audits ALL CLEAN (writers/platter exonerated; PLATTER-TORN was decoder artifact). Next: instrument read-time dir-buf invalidation skip…
metadata:
  type: project
---

# sess4 END — state for sess5

## Where the investigation stands (all RULE-4 evidence-cited)
1. **Writers + platter fully EXONERATED**: build 91A7D62B (v0.10.16) run 082443Z — P70-REL-AUDIT (post-wire-unlock raw FUA readback of dinode+bmbt child+leaves, da3-magic-aware decoder) = **refs_into_holes=0 on ALL 36 audits**. Data holes (db 1,2,4,10,11,12,22,33…) are LEGAL sparse blocks from rename-phase shrink.
2. **Earlier "PLATTER-TORN" verdicts were DECODER ARTIFACTS**: the scan misdecoded the dir's da3 interior NODE block (lives in the leaf dablk region) as a leaf — its 2 child pointers decoded as ghost refs (constant ghost_db=16384,16384, refs_into_holes=2 across all eras). Both decoders (P70 + P-HOLE-DISK PLATTER-SCAN) now check XFS_DIR3_LEAF1/LEAFN magic.
3. **Remaining failure**: cache_coherency@32 still 0/32 (P14-DABUF-HOLE storms, e.g. want_bno=1 at iversion=1232 under dlm_mode=3/PR, comm=bash; 82-fail rv-content family or mass-P14 wedge/timeout). Walker follows a leaf entry to a legally-FREED data block with a FRESH map → the LEAF VIEW is stale. Since the platter leaf is clean at every release, the stale leaf is the READER'S CACHED BUFFER.
4. **Last unaudited layer = read-time dir-buffer invalidation** (xfs_da_btree.c ~3776: `cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen` branch): per the sess12 comment in pal/linux/xfs_buf.c:4044, the read-time invalidation is SKIPPED for dirty/pinned/in-AIL buffers (XBF_TRYLOCK + dirty guards) — the write-side clobber got the sess12 guard, but the LOCAL READ still serves the stale image → P14. NEXT STEP: add P72-READSKIP-STALE (always-on capped) at every skip arm of that branch (print owner, daddr, bgen vs dir_gen, buf flags, comm); correlate with same-node P14s (same daddr, ms before). Read the code around xfs_da_btree.c:3400-3810 first (P5R/pbp/cbp arms).

## Also queued (structural, low-risk, do after/with the probe)
- **Grant-meta invalidate-at-unlock** (dlm_caw.c mxfs_dlm_caw_unlock_gen `out:`): on rc==0 && ours → valid=false. Kills the ghost-seq problem (grant_gen() returns stale seqs forever → P15H orphan signature fired on ghosts; p_rel_gen==0 currently means bucket-evicted not no-tenure). Makes P15H/P6Z/P6ZC semantics sound.
- Colliding stores still WIPE live non-releasing buckets (store_unless_releasing claims them) — with 32768 buckets rare; invalidate-at-unlock shrinks the live-meta population further.

## sess4 fixes landed (all in tree, v0.10.9→0.10.16, build 91A7D62BEE7805AE254062D deployed via run.sh)
- P15H strand-reap threshold 4→280 (~7s) — reap storm 45→0 (run 065143Z+).
- CAW p_rel_gen==0 release: release-if-no-tenure-now (P6ZC print), in-loop-guarded; never blind-unconditional, never skip-leak.
- grant_meta no-wipe hardening (store/prebump/release_mark wait out foreign mid-release buckets) + GRANTMETA_SIZE 4096→32768.
- P-HOLE-DISK probe: m_bsize(=8 BB!)→sb_blocksize byte fix (probe was silent ALL of sess3/4 because reads EINVAL'd), FUA fallback, BTREE DISK_MAPS_WANT verdict, btree_enter/read-fail prints.
- mxfs_dir_evict_bmbt_by_root (walk-miss-proof child evict at reload) — evidence: owner-scan works (89 evicts), 273 ROOT-KEEPs all DONE=0 (already-evicted, benign).
- Vacuous-durable bail closed (BTREE+need_iread releases now consult owner-scans; 126/run, all durable=1).
- P67-STALE-BASE-RMW laundering detector (1 benign fire — laundering REFUTED), P63-LEAFWR straggler fields (0 stragglers — REFUTED), P70-REL-AUDIT.

## Watchouts
- kill stale ccloop predecessor sessions at start (this sess killed sess3's PID 1963297).
- Window ALL kernlog greps to the run's start; check `prep OK … build <srcv>`.
- runs: background+poll; artifacts /tmp/run_cache_coherency_<ID>/kernlog_test*.
- P-DIRDW chg-chain gaps are benign publish-batching (floor); chain contiguity at tenure boundaries is the health signal.
- chk_mxfs post-fail from a node (umount first) = platter truth; sess3 showed consistent-at-rest.

## Ladder after cache_coherency@32 green ×2
trio (crash_consistency@32 floor ON, dlm_scaling@32), dir_reuse@16/@32, then ./run.sh N caw for N=1,2,4,8,16,32 → all green → echo YES > /src/mxfs/.ccloop/runs/46efd8b6-3dd3-477c-b004-14362c80d8e8/criteria-met
