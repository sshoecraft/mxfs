---
name: sess35-dir_reuse-two-residual-faces-round1-and-799
description: sess35: build 2EAA0090 dir_reuse 8/tcp = 4/5 PASS. Two residual faces: round-1 format-transition 10-loss (all-nodes-coherent) + steady 799 1-loss. Ep…
metadata:
  type: project
---

## sess35 — dir_reuse 8/tcp residual is TWO faces (build 2EAA0090 = 4/5 PASS).

### Repro result (`drc_repro_loop.sh 8 "" 24`, build 2EAA0090, default-on)
- iters 1-4 PASS 8/8 (NO loss across ~115 steady rounds — the per-block fix DID eliminate the common steady-state loss). iter5 FAIL (0/8).
- iter5 had TWO failing rounds (from drc_failrounds.txt across nodes):
  - **round 1: readdir=790/800 (10 lost), ALL 8 nodes coherent**, missing=[node3_f1, node6_f28/29/39/40/48/49, node8_f7/8/16] — all LOOKUP_ENOENT + REREAD_MISS (durable). This is the FRESH-DIR format-transition (shortform→block→leaf→node) concurrent-create loss. P78-FMT-TORN-FIX fired 1248× on ino=131 at round1 start.
  - **round 17: readdir=799/800 (1 lost), SOME nodes only** (test7/8, not test1) — sess34's steady-state single-entry residual, still present but rare.

### Decisive instrumentation (iter5 round1 window, NFS stream tests/tcp/drc_cap/stream_rank*.log)
- NO `P36-EVICT-LOCKED` and NO `EVDECIDE undurable=1` flagged as prior-tenure → read-side evict kept no OBVIOUS stale base. BUT EVDECIDE didn't log b_epoch/cur_mep so couldn't confirm.
- **P64-MASTER-HANDOFF fired only 7× in round1** despite thousands of creates / 29133 KEPT(undurable=1) EVDECIDE on ino=131. So the dir epoch (dg_shadow[].epoch, dlm/dlm.c:2602, bumps only when last_owner!=owner) advances ~7×/round — one node does ~57 creates per tenure then hands off. Refresh-on-handoff SHOULD suffice yet 10 lost.

### Epoch machinery (dlm/dlm.c)
- dg_grant_ex (dlm.c:2521) computes dir_epoch: bumps dg_shadow[mine].epoch ONLY on cross-node handoff (last_owner!=owner, line 2593-2602). Grantee level-triggered compares vs valid_epoch.
- BOTH cur_mep (xfs_mxfs_dlm.c:3601) AND i_dlm_dir_valid_epoch (set on acquire line 11563 from dir_grant_epoch) derive from the SAME dg_shadow epoch. If epoch doesn't advance on a handoff, BOTH the per-block fix (P26/P34, default-on) AND P16/P23 (both DEFAULT-OFF) fail identically.

### NEXT (sess35 in progress): build 6FE8A391 = EVDECIDE + staleprt/b_epoch/cur_mep/valid_epoch fields (instrumentation-only). Focused round-1 repro `drc_repro_loop.sh 15 "" 2` running. Looking for: undurable=1 with staleprt=1 (KEPT stale prior-tenure base = READ-side clobber) vs none (→ WRITE-side ABA reflush, sess33/sess40 family — fix at RELEASE-side BLI retire not just acquire-side).
See [[sess35-progress-2EAA0090-dir_reuse-4of4-pass]] [[sess34-WIN-newtenure-evict-plus-bli-retire-passes]].
</body>
