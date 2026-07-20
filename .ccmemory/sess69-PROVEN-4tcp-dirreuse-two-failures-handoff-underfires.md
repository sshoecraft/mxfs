---
name: sess69-PROVEN-4tcp-dirreuse-two-failures-handoff-underfires
description: sess69 PROVEN: 4/tcp dir_reuse_coherency has TWO failures — (1) intermittent single-dirent durable lost-update, (2) 24-round TIMEOUT. Handoff-refresh…
metadata:
  type: project
---

## sess69 — 4/tcp dir_reuse_coherency: PROVEN diagnosis (build A81DB821 baseline)

Criterion = 1/2/4/8 node tcp dlm test 100%. 2✅ (sess58). **4❌**. 8 untested.

### TWO distinct failure modes at 4 nodes (both must be fixed)
1. **Intermittent single-dirent DURABLE lost-update.** Caught red-handed:
   - run @ NFILES=50: round 17 lost `node3_f23` (kept its `.md5`); another run round 16 lost `node3_f2.md5`. readdir=399/400, lookup_fail=0, LOOKUP_ENOENT + REREAD_MISS on **ALL 4 nodes incl. the creator** → durable on-disk loss. Always a peer's (node3's) just-committed entry; a peer RMW'd the data block off a STALE base lacking it.
2. **24-round TIMEOUT (RULE 0 failure).** TEST_TIMEOUT=300s (run.sh:49). 24 rounds reaches only ~round 21 in 300s (~13-16s/round) → killed → NORESULT → FAIL. **14 rounds PASSES in budget**; 20 rounds fits (~280s) and catches the content loss. Per-round cost: verify ~6s (drop_caches + 400 cold FUA lookups), rm ~4s, create ~2s, + barriers. Work scales with node count (4n=400 entries vs 2n=200) but budget is fixed → 4n overflows.

### ROOT of the content loss (instrumented, kernel-log STREAMED to beat ring rotation)
The dir-EX **fast-path serve / re-acquire uses a STALE dir base** because every staleness signal under-fires under heavy 4-node contention:
- The dir is BAST'd **155–218×/node** but handoff-refresh fires only **~50×/node (slow P63-HANDOFF)** + **~1×/node (fast P63-FASTEX-HANDOFF=0,0,1,1)**. So many cross-node re-acquires serve a stale base with NO reload → clobber.
- All fast-path refresh triggers depend on the **LOSSY async eviction-ring** (`mxfs_dlm_note_evicted` MXFS_EVICT_TYPE_DIR_MODIFY at xfs_mxfs_dlm.c:14078 → bumps i_dlm_dir_gen + sets MXFS_IF_DIR_RELOAD). On TCP this drops messages → receiving node doesn't refresh → stale fast-path serve. (sess61 case-A confirmed.)
- The grant_gen fix (sess10/61 plan) IS implemented (mxfs_dlm_grant_gen, mxfs_v5_dlm_inode_grant_gen, i_dlm_cached_grant_gen) and refined (sess63) to use `mxfs_v5_dlm_inode_grant_handoff` (dg_shadow: a DIFFERENT node held EX since) to avoid over-fire — but it now **UNDER-fires** (FASTEX-HANDOFF ≈ 0).
- Fast-path serve site: xfs_mxfs_dlm.c ~10484 (P-DIRFASTEX) refresh gate at ~10534: `(dir_gen>loaded_gen && !self_created) || (i_flags & MXFS_IF_DIR_RELOAD)`; handoff gate ~10583-10613. `dir_ex_verify_held` (~10554) checks real grant AFTER serve (too late for the clobbering RMW).

### Architectural tension (why 68 sessions of point-fixes failed)
Any staleness-detect-and-reload must fire on EVERY real cross-node EX handoff (else lose a dirent) but NOT on same-node continuous-hold/PR→EX-upgrade (else resurrect deletes — sess50/63 — or starve → timeout). The lossy eviction-ring + lossy dg_shadow handoff don't achieve this on TCP.

### CANDIDATE FIX (not yet tried in this form): local-release-set reload flag
Set MXFS_IF_DIR_RELOAD when THIS node actually relinquishes the dir EX grant (BAST drain/unlock to NL), NOT via the lossy ring. Can't miss a handoff (we set it on our own release; a peer can only modify after we release). Won't resurrect (Invariant 1 drains our work at release → disk ⊇ our work on reload). Caveat: need the grant-release point even when i_dlm_mode is kept cached (phantom/deferred-BAST) — that's the gap to confirm.

### Tooling added this session (KEEP)
- tests/suite/dir_reuse_coherency.sh: persistent `/root/drc_failrounds.txt` marker + per-round failverify snapshot (survives ring rotation); `DRC_STREAM=1` → `dmesg --follow > /root/drc_stream_rankN.log` (FULL log, beats the always-on probe flood that overflows the 256KB ring within ONE round).
- Repro: `MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency` (fails ~round 16-19, fits budget).
- NOTE: always-on debug probes (P25-INSTR, P82-ADD, P64-N1F1, P62-DWR-N1F1, P-DIRIFLUSH, P103-RELOAD-REUSE-ADOPT @3628×) flood dmesg even with instr=0/dirwr=0 — one round overflows the ring; MUST stream to file for clean signal.

Build A81DB821 = baseline (my P69 probes were net-zero, removed). Related: [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].</body>
