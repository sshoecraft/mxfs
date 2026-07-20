---
name: sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis
description: sess49 COMPLETE diagnosis of the residual (tcp_dlm_scaling/dlm_fairness drain-fail): TCP BAST-not-demoting → stale cached i_dlm_mode==EX double-grant…
metadata:
  type: project
---

## sess49 — residual blocker FULLY traced (after cache_coherency FIXED). Build DBA88871.

### CRITERION STATUS: full `./run.sh 2 tcp` = 17/17 ONCE, then 16/17, 16/17 (3 clean runs).
cache_coherency FIXED+reliable (P43 EX-gate, [[sess49-ROOT-cache_coherency-uv-is-P43-fmtrevert-guard-misfire]]).
RESIDUAL (flaky, ~1/3 clean): **tcp_dlm_scaling** + **dlm_fairness** drain-fail (shared dir not drained,
got>=1) AND tcp_dlm_scaling corruption-shutdown (xfs_trans_cancel:1060, xfs_remove dirtied-then-cancel).
BOTH pass STANDALONE (fresh prep), fail IN-SUITE = CONTAMINATION (cumulative churn state).

### FAST REPRO (reliable, ~1 min): `bash tests/tcp/repro_rename_drain.sh 150 8` — concurrent
create+rename+rm churn in a SHARED dir over iters on ONE mount; fails within a few iters with a
durable leftover dirent (nlink=0, BOTH nodes see it). NOT read-side (drop_caches doesn't fix; both
nodes agree) = DURABLE write-side RESURRECTION of a peer's removed dirent.

### COMPLETE ROOT CHAIN (RULE 4, this session + sess10/sess17):
1. The churn dir stays SHORTFORM (tiny, ~0-2 live entries). So the resurrection is in the inode
   shortform fork, NOT data blocks (P35F data-block flush-exhaust = 0 confirmed; release drains clean).
2. There IS already a reliable read-side fix: `mxfs_dir_sf_refresh_if_disk_differs` (xfs_mxfs_dlm.c:8176)
   does a COHERENT plain-bdev disk-compare + `mxfs_dir_sf_3way_merge` (keeps own undestaged delta,
   adopts peer's). It runs UNCONDITIONALLY (sf_disk_check, line 8777, NOT gen-gated) on the cached-EX
   fast path for any shared non-self-created shortform dir. So staleness DETECTION is covered.
3. Yet resurrection survives ⇒ the failing node RMWs concurrently with the peer = **DOUBLE-GRANT**:
   its in-memory `i_dlm_mode==EX` is STALE (the TCP DLM granted the peer EX via a BAST that did NOT
   demote this node). sess106/107 PROVED this on CAW (on-disk holders_ex bit already clear during the
   fast-path RMW). On **TCP** the verification is IMPOSSIBLE: `mxfs_v5_dlm_inode_held` is a NO-OP
   (returns 1) — sess10-SYNTHESIS. So a dropped/un-honored TCP BAST leaves a stale cached EX that the
   fast path trusts → both nodes modify → one durably resurrects the other's removed dirent. The
   3-way merge can't save it when the peer's removal isn't yet DESTAGED to the LUN at compare time
   (peer also holding stale-EX, no clean release/drain).

### THE FIX (sess10 GPT verdict [[sess10-gpt-verdict-serialize-tenure-not-epoch]], NOT converged):
strict dir-EX tenure serialization — no double-grant (real DLM EX that BASTs peers, not cached-both-
sides) + reload-on-reacquire + MHT batching (anti-starvation). The TCP-specific gap: ensure every TCP
BAST reliably demotes i_dlm_mode→NL BEFORE the master grants the peer EX (synchronous demote-before-
grant). Investigate dlm/dlm.c grant/BAST handshake + the XFS-layer bast_notify/MHT-defer dwork
(xfs_mxfs_dlm.c:5633 bast_dwork_fn, 5758 bast_notify) for where a TCP BAST can be dropped/deferred so
i_dlm_mode stays EX. sess10-SYNTHESIS #2: MHT-defer dwork "already consumed" early-out / cancel-by-
reacquire could drop the demote.

### REFUTED (do NOT repeat): force-evict (starvation got=7/50), drop-clean-gate (revert-own),
HB-interval reduction (500ms WEDGES, 1000ms no better — [[sess-tcp-heartbeat-reduction-insufficient]]),
di_changecount (unsound, per-node i_version not a shared seq), sf flush-before-evict (rename_visibility
2→24 worse), CAW shared-epoch (detection not RMW-exclusion). mode enum 0=NL 3=PR 5=EX.
Related: [[sess17-CONFIRMED-staleflush-clobber-P17]] [[sess10-SYNTHESIS-handoff-and-final-target]]
