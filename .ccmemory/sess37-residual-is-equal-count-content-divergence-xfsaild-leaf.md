---
name: sess37-residual-is-equal-count-content-divergence-xfsaild-leaf
description: sess37: residual = GENUINE-EX-holder (real_mode=5, 1890/1892) equal-count content-divergent background reflush. Stale-cached-EX rare (2). Points to D…
metadata:
  type: project
---

## sess37 — the RESIDUAL face (best read-side stack ON) decisively characterized.

### Config: dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1 dir_addname_platter_guard=2 (+ dataclobber=1 dirwr=1 detect). dirwr=1 perturbs → round-1 fail (clean residual ~round20). Lost entry: node4_f2.

### node4_f2 evidence: `P26-DSCAN-MISS ndb=6 scanned=801` (genuinely ABSENT from all 6 data blocks on a coherent datascan); `P33-DSCAN-ONDISK ... incore==disk (fmt2 nx10 size24576 gen892472424 sameincarn=1)` — the dir INODE agrees in-core vs disk; only the DATA-block CONTENT lost the entry. Reader holds PR, stale=0.

### ★ THE DOMINANT CLOBBER = GENUINE EX HOLDER (decisive count):
- `mode=5 real_mode=5` (genuine EX, verified via mxfs_v5_dlm_inode_held_rawmode): **1890** events.
- `mode=5 real_mode=0` (STALE-cached EX, master says NOT EX): only **2** (1 data). RARE.
So the clobber is NOT primarily stale-cached-EX. dir_ex_write_guard (which gates on cached i_dlm_mode) using real_mode instead would only catch the 2 rare ones — NOT the fix.

### Residual clobber signature (the 1890): `kind=leaf/data daddr=6279744 buf_cnt==disk_cnt (EQUAL, e.g. 374/374) ... bufgen==dirgen (stale=0) mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 comm=xfsaild/dd`. = a background xfsaild/dd reflush by a node GENUINELY HOLDING EX, of a buffer whose content DIVERGES from disk at EQUAL entry count (detector flags ds!=bs).

### THE PARADOX → the deep root: under GENUINE continuous EX no peer can write disk (peer can't get EX), yet the holder's freshly-read (bgen==dirgen) buffer diverges from disk. The only explanations:
1. **Cross-master double-grant** the auditor misses: mxfs_dlm_audit_double_grant scans only THIS master's table; if dir-inode mastership is distributed, a conflicting EX grant on a DIFFERENT master is invisible (MX-DOUBLEGRANT fires 0x because it can't see cross-master). This is sess49's PROVEN gap: mxfs_v5_dlm_inode_held is a NO-OP on TCP; a dropped/deferred TCP BAST leaves a peer modifying under our nominal EX.
2. **Read-served-stale on acquire**: the FUA re-read on EX acquire returns a stale platter image (LIO read-cache lag) so bgen==dirgen but content is behind disk.

### ALL count/gen/incarn/cached-mode guards are blind to this (equal count, current gen, same incarn, cached EX). Write-side DROP is categorically the corruptor (sess23/33/37). 

### THE TWO REMAINING SOUND DIRECTIONS (next sessions):
1. **DLM serialization fix (sess49/sess10 "not converged")**: make TCP dir-EX truly exclusive — synchronous demote-before-grant (a TCP BAST must demote i_dlm_mode→NL + drain+invalidate BEFORE the master grants the peer EX), AND make the double-grant auditor cross-master-aware to PROVE/DISPROVE cross-master double-grant. Add a real_mode-vs-cached-mode assertion at the dir-write chokepoint (if real_mode!=EX but cached==EX → log loudly; if a PEER holds EX while we write → that's the smoking gun).
2. **Owner-checkpoint (GPT design)**: route ALL dir-metadata writeback through the EX owner (defer xfsaild, land via bounded owner-checkpoint + liveness valve + per-dir registry). This makes the invariant hold even if the DLM has a brief double-grant window, because only one node's release-drain writes.

### FIRST cheap diagnostic next session: at the P-DATACLOBBER detect, when real_mode=5 and content diverges, ALSO query+log whether a PEER currently holds EX/PR on this dir (cross-node holder dump) — settles double-grant vs read-served-stale decisively. See [[sess37-HEAD-handoff]] [[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]] [[sess37-FRESH-clobber-groundtruth-bgen0-rmw-on-stale-base]].
