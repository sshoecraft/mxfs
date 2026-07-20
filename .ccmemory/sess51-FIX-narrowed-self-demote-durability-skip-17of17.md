---
name: sess51-FIX-narrowed-self-demote-durability-skip-17of17
description: sess51 STATE: tcp_dlm_scaling root=symmetric PR→EX dir-upgrade livelock. KEEP=self-demote durability-skip (build D50912EB, dir_reuse/rsync solid, tcp…
metadata:
  type: project
---

## sess51 — tcp_dlm_scaling root FOUND+mostly fixed; full 100% NOT yet met

### KEEP (build D50912EB5DD534BBE064EA6, both nodes via NFS): self-demote durability-skip.
`mxfs_dir_pr_release_fast` (0=off,1=DEFAULT self-demote-only,2=broad all-clean). In
`mxfs_dlm_bast_process`, skip `mxfs_dlm_dir_inode_durable` on a clean release (p_held_mode!=EX &&
xfs_inode_clean && !in_ail && pin==0) that is a SELF-demote (P109 EDEADLK upgrade recovery, ~9472
sets `i_dlm_self_demote`; read+cleared at bast_process entry; init in mxfs_dlm_inode_init). xfs_inode.h
has the new flag. P51-REL log (always-on): ino/held_mode/selfdemote/sf/clean_skip/drain_ms.

### tcp_dlm_scaling ROOT (PROVEN, live dmesg): symmetric PR->EX directory-inode UPGRADE livelock.
bash open(O_CREAT) = lookup(dir PR) then create(dir EX-upgrade). Both nodes cache PR + want EX; master
CONVBLK-DENYs both (-EDEADLK, dlm.c:2574, no bast to conflicting holder); both self-demote PR->NL
through the bast_process drain (log_force SYNC ~2s under cross-node contention) and re-collide. The
~2s clean-release drain is the amplifier. See [[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]].

### EMPIRICAL RESULTS (full ./run.sh 2 tcp, clean reboots):
- BROAD skip (FFC0DA1D): tcp_dlm_scaling 4/4 PASS, but EXPOSED dir_reuse_coherency + rsync_paired
  ~17% fail each (the clean-release log_force is an INCIDENTAL coherency-masking barrier; removing it
  on peer handoffs un-masks the sess37/40 stale-block-RMW family on BLOCK/LEAF dirs).
- SELF-demote-only (358133566 / D50912EB): dir_reuse/rsync SOLID, tcp_dlm_scaling INTERMITTENT
  (~1 fail/3 runs: rel run1 17/17, run2 tcp_dlm 1/2; single full run 17/17). Peer-handoff clean-PR
  drains still occasionally stall tcp_dlm_scaling. BEST BASE.
- REFUTED shortform-gate (3FCCA8B7, skip clean release when dir if_format==LOCAL): BROKE dir_reuse
  0/2 — dir_reuse's vulnerable phase IS the shortform sf->block growth/conversion. Reverted.
- REFUTED msleep tiebreak (0C21541E, node-slot backoff in EDEADLK recovery): CASCADE 12/17
  (dir_reuse 0/2 + fence/fault/soak/tcp_dlm) — msleep in the DLM acquire path is too disruptive.
  Reverted (orphaned comment ~3879 left; param gone).

### CORE TENSION (next session): tcp_dlm_scaling needs clean-PR PEER-handoff releases CHEAP;
dir_reuse needs them DRAINED (masking). SAME code path. The masking dir_reuse needs is for pending
DIR-DATA-BLOCK writeback (xfs_inode_clean checks only the INODE, NOT data blocks) — a proper "no
pending dir-data-block writeback" check (not if_format) might let the BROAD skip be safe. OR fix the
livelock at the MASTER (dlm.c CONVBLK-DENY: proper conversion FIFO / deterministic winner) — non-
disruptive, unlike the requester msleep. OR fix the stale-block-RMW root (sess37 acquire-evict
LOCKED-skip / sess40 writeback-skip owner-gone gap) so masking isn't needed. force_block stays 0
(sess44). MARKER NOT written. Related: [[sess51-dir-reuse-exposed-by-durability-skip-stale-block-race]]
