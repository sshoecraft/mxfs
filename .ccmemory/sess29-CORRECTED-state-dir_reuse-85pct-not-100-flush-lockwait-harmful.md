---
name: sess29-CORRECTED-state-dir_reuse-85pct-not-100-flush-lockwait-harmful
description: sess29(ccloop) CORRECTED: dir_release_invalidate+relinval_clean gets dir_reuse 8/tcp to ~85% (6/7), NOT 100% (4/4 was a lucky streak; residual 799 TO…
metadata:
  type: project
---

## sess29 — CORRECTED end-state (criteria 1/2/4/8 tcp 100% NOT met)

### dir_reuse_coherency 8/tcp pass rate = ~85%, NOT 100%
Winning config `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`:
- build D1DD1926: standalone PASS + drc_passrate2 4/4 (5 pass)
- build 23FE6715 (adds gated dir_flush_lockwait, default 0 = behaviorally identical): drc_passrate2 1 PASS / 1 FAIL (round1 readdir=799/800)
- **Combined 6 PASS / 1 FAIL ≈ 85%.** The earlier "4/4" was a lucky streak (0.85^4≈0.52). Big improvement over the keeper (~0% dir_reuse) but NOT 100%.

### The two NEW levers (KEEP, default 0) — genuine progress, partial fix
- **dir_release_invalidate=1** (existing): stale dir leaf/data buffers at release → lookup_fail→0 AND eliminates the DABUF_HOLE + xfs_defer shutdowns (they were stale-leaf/extent artifacts). Alone = 1/4.
- **dir_relinval_clean=1** (NEW, xfs/xfs_mxfs_dlm.c mxfs_dir_flush_data_blocks `!needs_flush` branch): also xfs_buf_stale CLEAN cached dir blocks at release. Lifts ~25%→~85%. Residual ~15% = single-dirent 799 loss.

### RESIDUAL (the last ~15%): the IN-TENURE xfsaild destage TOCTOU
relinval_clean fixes the HANDOFF (release→reacquire cold-read fresh). It does NOT catch an xfsaild destage of OUR dirty dir block on a base that went stale DURING our tenure (peer added durably after our last refresh, before our async destage). That is the write-side TOCTOU. Read-side invalidation fundamentally cannot close it (peer can always add after our last read).

### REFUTED HARD this session (do NOT repeat)
- **dir_flush_lockwait>0** (bounded trylock-bail in the release flush to break the crash_consistency ABBA): CATASTROPHIC — bailing a release flush violates Invariant 1 (releases stale) → cache_coherency/strong_consistency/posix_multi 0/8. Code KEPT but DEFAULT 0 (inert); NEVER set it >0. The ABBA must be fixed structurally (snapshot daddrs under i_lock, flush WITHOUT holding i_lock — like mxfs_dir_drain_evict_data_blocks does), NOT by bailing.
- **dir_write_merge** (chokepoint 3-way data graft): cross-block DUPLICATE names (+1/+2 over-count); can't verify global name-uniqueness from one block. FUA→plain read didn't help. Default 0, abandoned.
- **dir_postread_reread=1**: all nodes shut down round 1 (FUA leaf re-read tears).

### crash_consistency IN-SUITE HANG (separate pre-existing wall, blocks full `./run.sh 8 tcp`)
Full suite = 11/17 PASS then crash_consistency HANG (NOT my fix — passes STANDALONE 30s 8/8 with same modargs). ABBA: mxfs_dir_flush_data_blocks blocking xfs_buf_incore(...,0,...) at xfs_mxfs_dlm.c:1600 runs holding dp->i_lock(read); a recovery/peer context holds the dir buffer + needs i_lock(write). NEXT (RULE 4): reproduce (full suite) + capture the HOLDER (b_lock_ip field on xfs_buf + all D-state stacks across nodes) to PROVE it, then fix structurally (drop i_lock across the buffer get).

### CONTAMINATION CAUTION (cost ~30min this session)
After killing a mid-run suite, the NEXT full `./run.sh 8 tcp` can FAIL early tests (cache_coherency 0/8) from leftover state even though full8.sh virsh-resets — the killed run's broken on-disk/cluster state contaminates. ALWAYS verify a clean baseline (drc_passrate2 dir_reuse PASS) before trusting a full-suite result. Build 23FE6715 confirmed GOOD via dir_reuse PASS after the contaminated full8c.

### NEXT SESSION
1. Close the residual ~15% 799 TOCTOU: needs a write-side catch WITHOUT the merge's cross-block-dup bug. Ideas: suppress the specific xfsaild destage that would revert (in-AIL dir block whose disk image gained entries since logged) by RE-LOGGING via a transaction (not bailing); OR a per-dir-block "peer modified since logged" gen check at the bio chokepoint that forces a transactional re-apply.
2. Fix crash_consistency ABBA structurally (i_lock not held across release-flush buffer get).
3. THEN: full 8/tcp suite reliability + 1/2/4 tcp + make levers defaults.
Tools: tests/tcp/drc_passrate2.sh N "MODARGS" (dir_reuse reliability), tests/tcp/full8.sh N "MODARGS" (full suite). See [[sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean]] [[sess29-full8tcp-11of17-crashconsist-insuite-hang-is-last-wall]] [[sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall]].
