---
name: sess42-ELIM-fua-write-plus-grantevict-fail-broken-path-bypasses-release-flush
description: sess42(ccloop) ELIMINATION: dir_release_fua_write=1 + dir_grant_evict=1 BOTH ON still fail 8/tcp → the broken path NEVER reaches the release flush →…
metadata:
  type: project
---

## sess42 (ccloop) — final elimination of the session. Chain: [[sess42-CONFIRMED-stale-WRITE-not-base-grantevict-plus-wseq-both-insufficient]] → this.

### A/B (build 7E1EFD90): `dir_release_fua_write=1` (creator SCSI-FUA-writes each released dir block to the PLATTER, bypassing the LIO/SCST write-back cache) + `dir_grant_evict=1` (reader FUA-re-reads the platter at acquire) — BOTH ON — STILL FAILS 8/tcp dir_reuse (iter 2/6, multi-entry loss). 

### Cumulative elimination this session (every release/durability/base lever ON, still loses):
- written_seq-at-completion (`dir_wseq_at_completion=1`): no
- grant-evict fresh read base (`dir_grant_evict=1`): no (sess36 re-confirmed)
- force-flush all DONE dir data blocks at release (`dir_release_flush_all_done=1`): no
- FUA-write released dir blocks to platter (`dir_release_fua_write=1`): no
- write-merge graft disk-only names (`dir_write_merge=1`): inert (dko=0)

### CONCLUSION: the broken path NEVER reaches the release-flush / release-durability machinery. No amount of release-side or read-base tuning helps because the creator's just-added dirent is DISCARDED FROM IN-CORE (cached-EX demote → reload-adopt) WITHOUT EVER BEING WRITTEN. This is the cached-EX / master-grant-mirror DIVERGENCE: node holds `i_dlm_mode==EX` (cached) and modifies the dir, but the DLM master/mirror has already moved the grant to a PEER (so `mxfs_v5_dlm_inode_held()==0`). The two nodes RMW the same dir block divergently; the creator's add is on the losing side and is discarded on the next reload-adopt. MX-DOUBLEGRANT is SILENT (the master never has two GRANTED EX simultaneously), so the divergence is: creator's grant was RELEASED at the master, but creator's in-core i_dlm_mode stayed EX (or re-cached EX) → it kept modifying. Detected reactively by `P-TCPEX-REACQ` (xfs_mxfs_dlm.c:13507) but only AFTER the divergent modifications, and the holders==0 gate skips the check mid-MHT-batch (creates f0..f24 under one cached-EX tenure → if the grant is lost mid-batch, the rest modify under a stale grant).

### NEXT (RULE 4) — instrument the DIVERGENCE CAUSE, not the symptom:
1. Add an always-on (storm-dir ino<=256, ratelimited) tracer that, at EVERY dir-EX fast-path SERVE (xfs_mxfs_dlm.c ~13684 where i_dlm_ex_holders++ before serving cached EX), queries `mxfs_v5_dlm_inode_held()` / `mxfs_v5_dlm_inode_grant_gen()` and logs when `i_dlm_mode==EX && mirror_held==0` (serving a cached EX whose grant is GONE) — i.e. catch the modify-under-stale-grant at the moment it serves, including mid-batch (holders>0). This names exactly which creates run under a dead grant.
2. Then PREVENT it: at that serve, if mirror !held (or grant_gen advanced), DIVERT to slow-path re-acquire (real EX grant + drain + reload) BEFORE serving — even mid-batch. Risk: RULE-0 timeout (~800 handoffs × slow re-acquire; sess43 hit >180s on per-handoff FUA-refresh). Mitigate: only divert when mirror actually !held (rare), not every op.
3. Deeper: find WHERE node's grant is released at the master while its in-core i_dlm_mode stays EX. Candidates: bast_process sets i_dlm_mode=NL @8848 then a fast-path re-cache; OR master `mxfs_dlm_purge_stale_for_resource` (dlm.c:2020) promotes a waiter to EX after purging this node as a "stale remote holder" (master-change/flap) without notifying it; OR the acquire-timeout-retry "wins" path (dlm.c:548-559). Trace with `MXFS_EXTRA_MODARGS='dirwr=1'` (enables P-DIR-SEQ REL/FASTEX/ACQUIRE + P106-EXREL/EXGRANT timeline) — correlate node-A's modify-under-stale-EX realns vs node-B's grant realns. Watch: dirwr overhead may slow the race (use lightest probe).

### Build 7E1EFD90 = keeper FUNCTIONALLY (all fix params default OFF). Cluster clean. Criterion NOT met.</body>
