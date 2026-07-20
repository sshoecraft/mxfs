---
name: sess44-FINAL-epoch-unreliable-half-EX-grants-carry-zero-need-reliable-signal
description: sess44 FINAL: P44-GRANTDIREPOCH proves ~half the storm-dir EX grants carry dir_epoch=0 (best_mode=5 epoch=0 in ~9/19 EX samples) — NOT shadow-table o…
metadata:
  type: project
---

## sess44 FINAL — the dir_epoch coherency signal is structurally unreliable (~50% zero)

### Decisive (P44-GRANTDIREPOCH probe in mxfs_dlm_grant_dir_epoch, dlm.c:2448, build EC24B20897): for the storm dir ino=131 the LOCAL granted lock carries:
- best_mode=5(EX) epoch=15  — ~10 samples (good)
- best_mode=5(EX) epoch=0   — ~9 samples (THE BUG: holds EX but dir_epoch=0)
- best_mode=3(PR) epoch=0   — PR grants don't carry dir_epoch (expected)
So roughly HALF of EX grants carry dir_epoch=0 → mxfs_v5_dlm_inode_dir_epoch=0 → cur_mep=0 (P68-EVDECIDE 9842×0 vs 2158×15) → ALL acquire-side stale-base eviction (newtenure/prior-tenure/epoch_adopt fast-path, all gated on epoch>0) is INERT for those grants → stale-base RMW → intra-block offset double-alloc.

### NOT shadow-table overflow: enlarging DG_SHADOW_N 512→8192 did NOT fix it (still FAIL, cur_mep still 0-dominant). So the dir's slot isn't being evicted.

### ROOT (design): dg_grant_ex (dlm.c:2583) — the per-resource epoch ADVANCES only on a cross-node OWNER CHANGE (`handoff = last_owner!=0 && last_owner!=owner`, epoch++ at 2667) and is set to 0 on a fresh/recycled slot (2701/2708). For an EXISTING slot it returns the current epoch (2674). So epoch=0 on an EX grant means EITHER (a) the slot was freshly created with epoch=0 and granted before any cross-node handoff advanced it (the FIRST node to grab a fresh-each-round rm-rf'd dir), OR (b) the slot was recycled. AND fast-path MHT serves never call dg_grant_ex at all, so a node holding cached EX across peer handoffs reads its own STALE lk->dir_epoch. The 1842 fix (sess44, kept) closed one propagation hole but the epoch is still 0 ~half the time by this design.

### CONCLUSION: the 40-session failure is structural — the acquire-side coherency machinery (sophisticated: P63-FASTEX-HANDOFF edge-trigger + P-FASTEX-EPOCH level-trigger + P68 newtenure/prior-tenure evict) is ALL gated on epoch/grant_gen signals that are unreliable (0 ~half the time) for a fast-path-served, rm-rf-reused shared dir. Need a RELIABLE per-dir "changed since I last coherently read it" signal that: (1) is non-zero from the first grant, (2) advances on EVERY cross-node EX transfer incl fast-path, (3) survives inode rm-rf reuse, (4) does NOT over-fire within a continuous same-node tenure (else sess35 readdir=0 / resurrection). Candidate: a master-authoritative monotonic per-(ino) grant counter delivered on every grant AND queryable cross-node (not just the local cached lock) at fast-path-serve time — OR drop the dir's cached EX entirely between create-wave handoffs so every modify re-acquires slow-path (perf cost; but correctness-first).

### NEXT: RULE-5 GPT-5.5 consult #2 justified (first consult was on the release-side, now REFUTED; this is a NEW, fully-instrumented architectural question about the coherency signal). Provide: epoch 0 ~half of EX grants, all consumers gated on it, fast-path MHT serve + inode reuse, the dg_shadow design. Ask for the minimal reliable cross-node dir-staleness signal + where to query it at fast-path serve. THEN implement + validate 1/2/4/8.

### STATE: build EC24B20897 = EBBC5A82 (kept 1842 epoch-propagation fix, 2/tcp dir_reuse PASS) + DG_SHADOW_N 8192 (harmless) + P44-GRANTDIREPOCH probe (ratelimited, ino=131 only). The 1842 fix is the validated keeper; the shadow-size + probe need 1/2/4 re-verify (low risk). 8/tcp still ~33% fail. Criterion NOT met. [[sess44-KEPT-fix-1842-dir-epoch-propagation-partial-next-is-fastpath-serve]] [[sess44-ROOT-epoch-and-grantgen-both-zero-for-reused-dir-inode-coherency-signal-dead]]
