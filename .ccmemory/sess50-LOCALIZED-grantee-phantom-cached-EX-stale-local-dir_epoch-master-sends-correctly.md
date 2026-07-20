---
name: sess50-LOCALIZED-grantee-phantom-cached-EX-stale-local-dir_epoch-master-sends-correctly
description: sess50(ccloop) LOCALIZED: master sends dir_epoch correctly (662); grantees' local lk->dir_epoch lags (max 57-189, many 0) = phantom cached-EX after u…
metadata:
  type: project
---

## sess50 (ccloop) — LOCALIZED: grantee phantom cached-EX with stale local dir_epoch (master propagation is CORRECT)

### DECISIVE DATA (build C69E3475, P51-SENDGRANT + P44-GRANTDIREPOCH + P64-MASTER-HANDOFF, ino 131, clean 8/tcp FAIL):
- **test3 masters ino 131.** It computes the monotonic handoff epoch correctly (P64 epoch up to 662) and **SENDS it correctly** on EX grants (P51 dir_epoch_sent up to 662; only 2 zero-sends).
- **EVERY grantee (test1-8) stores a STALE local lk->dir_epoch**: P44 max epoch only 57/189/175/179/166/177/184/174 — FAR below the master's 662 — and each has 10-48 reads where the local epoch is **0**.
- ⇒ The master's monotonic epoch is propagated/computed correctly. The loss is at the GRANTEE: its local `lk->dir_epoch` (what mxfs_dlm_grant_dir_epoch / the fast-path would consume) LAGS the master by hundreds of epochs.

### ROOT (refined, evidence-backed): PHANTOM CACHED-EX after an unprocessed revoke.
A node serves a dir-EX FAST-PATH (cached i_dlm_mode=EX, local lk GRANTED with an OLD dir_epoch) while the master has since advanced the epoch by granting OTHER nodes EX (epoch→662). For the master to grant peers, it revoked this node's grant — but this node's LOCAL state (i_dlm_mode=EX, lk GRANTED, lk->dir_epoch frozen at its last real grant ~50-189) was NOT downgraded (lost/unprocessed BAST on TCP, or MHT held through it). The node then RMWs the dir under this PHANTOM grant on a base stale by the missed epochs → count-preserving single-dirent clobber. Consistent with ALL prior evidence: master never double-grants (MX-DOUBLEGRANT 0×, it correctly serializes by revoking first); reads are "coherent" and base "not stale" by LOCAL counters precisely because the local epoch is itself stale (frozen); P51-HANDOFF-UNDERFIRE fires (grant_gen jumps, ho false).

### THE FIX (two viable directions; implement+test, RULE 4):
**(A) Reliable revoke/downgrade** — when the master grants a dir resource to a new EX holder, the PRIOR holder's local i_dlm_mode + lk MUST be downgraded to NL before/as the new grant commits. Find why the BAST/revoke to the prior holder is lost or not processed on TCP for the contended storm dir (the holder keeps serving cached EX). Likely in the master's grant-to-peer path (it must BAST + await release, not just grant) and/or the holder's BAST processing under the MHT/fast-path (xfs_mxfs_dlm.c bast_notify / MHT dwork — does a re-acquire during the MHT window clobber the BAST-owed state?). Reliable revoke ⇒ holder releases ⇒ next access slow-path re-acquires with the CURRENT epoch + acquire-evict refreshes the base.
**(B) Grantee-side ownership validation** — before each modify of a SHARED dir (or on the fast-path serve), the holder validates with the master that it STILL holds the grant at the current epoch (a cheap epoch/ownership query RPC, cached per-epoch). If the master's epoch > our local lk->dir_epoch, our cached EX is phantom/stale → force slow-path re-acquire + base refresh. More RPCs but bulletproof; gate to shared (dir_gen>0) dirs to bound cost (RULE 0).

### Probes now in build C69E3475 (all in-tree, ino-131-gated/ratelimited, pure instrument): P51-SENDGRANT (master epoch sent), P44-GRANTDIREPOCH (grantee stored epoch, pre-existing), P64-MASTER-HANDOFF (master dg_shadow.epoch), P51-HANDOFF-UNDERFIRE (fast-path grant_gen-advanced-but-ho-false), P50-RD/WR/B + relepoch (dormant). Baseline-equivalent functionally (relepoch gates OFF). Cluster healthy. Marker NOT written.

### NEXT: pick (A) — instrument the prior-holder downgrade on a peer EX grant: when test3 (master) grants ino-131 EX to node X, does node Y (prior holder) receive+process a revoke/BAST that sets its i_dlm_mode=NL before X modifies? Add a probe at the master's grant-to-peer (does it BAST the prior holder?) and at the holder's BAST recv/process. If the prior holder isn't reliably downgraded → that's the serialization break to fix. This is the v6 of the master-epoch work left incomplete in [[sess16run-INPROGRESS-master-epoch-check-done-stamps-remain]].
See [[sess50-NEXT-fix-dir_epoch-propagation-some-grant-path-delivers-0]] [[sess50-ROOT-handoff-underfire-last_owner-immediate-prior-only-use-dg_shadow-epoch]] [[sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole]].</body>
