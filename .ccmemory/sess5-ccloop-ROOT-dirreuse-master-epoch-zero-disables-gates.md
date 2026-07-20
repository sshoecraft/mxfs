---
name: sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates
description: sess5(run6614) PROVEN ROOT of dir_reuse lost-update: master dir_epoch mxfs_v5_dlm_inode_dir_epoch(131) intermittently returns 0 (stale/dup local lock…
metadata:
  type: project
---

## sess5 (run 6614) — dir_reuse lost-update ROOT PROVEN (live-failure probes, no masking)

### The chain (measured on a live 4/tcp dir_reuse failure, build E101D113):
- readdir=300/exp=400, lookup_fail=0 = 100 dirents durably clobbered (node-addname stale-base RMW).
- **P29-DATAWRITE CLOBBER = 0** on all nodes → NOT a stale-write; it's a stale-READ base.
- **P2-EPOCHPLACE: 314× on test1, ALL `unestablished=1` (master_ep=0)**, zero stale_base — placements happen with the authoritative master epoch = 0 (local valid_ep=186).
- **P44-GRANTDIREPOCH (ino=131): local lock dir_epoch = 0 / 8 / 22** (test1), 2/9/17/25/32 (test2) — LOW and sometimes 0.
- **P51-SENDGRANT (master test1): dir_epoch_sent up to 190, sent=0 NEVER** — the master COMPUTES + SENDS the correct monotonic epoch.

### ROOT: `mxfs_v5_dlm_inode_dir_epoch()` (dlm/v5_mount.c:1420 → mxfs_dlm_grant_dir_epoch dlm/dlm.c:2509) returns the LOCAL granted lock's `lk->dir_epoch`, which is STALE/ZERO relative to the master's sent epoch. A zero master-epoch DISABLES every epoch-gated dir coherence guard — prior_tenure evict, tenure_stale/epoch_stale read gate, newtenure evict ALL require `master_ep != 0` / `cur_mep != 0`. So the stale-base RMW protection is INERT → the clobber. Send-side is correct; the LOCAL store/query of dir_epoch is the bug (rapid fast-path re-grants leave a stale/duplicate local mirror; advance-only store at dlm.c:3317 updates only the first match; the query picked the last highest-mode mirror = often stale/0).

### FIX APPLIED (build 9762C6C6, TESTING): mxfs_dlm_grant_dir_epoch now returns the **MAX dir_epoch across ALL local granted mirrors** of the resource (epoch is monotonic → max = most-current), instead of the last-iterated highest-mode one. Re-enables the epoch gates whenever any mirror carries a nonzero epoch. Low-risk (read-only query change).

### If query-max is insufficient (local mirrors genuinely all stale/low): the STORE side must be fixed — refresh lk->dir_epoch on EVERY grant/re-grant/fast-path-adopt (not advance-only-first-match), OR switch the dir coherence gates to the RELIABLE LOCAL signal i_dlm_epoch/b_mxfs_relepoch (sess50, "immune to grant handoff-underfire") instead of the fragile master dir_epoch. That is the robust architectural fix.

### KEPT fixes still in tree: undestaged cold-read salvage (2/tcp=17/17), deferred-stale (b_mxfs_stale_pending), soak dump_stack gate.
See [[sess5-ccloop-dirreuse-lostupdate-acquire-reload-locked-skip-gap]] [[sess5-ccloop-HANDOFF-state-fixes-and-next]] [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]]
