---
name: sess63-handoff-signal-works-1of24-residual-writeside-block0
description: sess63 (build 5E78DEE0): master prior-EX-owner HANDOFF signal implemented + drives reload disk-superset adopt. VALIDATED 1/tcp 16/16, 2/tcp 17/17 (NO…
metadata:
  type: project
---

## sess63 — master-exposed prior-EX-owner HANDOFF signal: IMPLEMENTED, VALIDATED, 1-2/24 residual

### Build 5E78DEE0 (= 503078E1 handoff impl + SF2BLK name-dump probe). On disk.
### VALIDATED (clean virsh reboot before each):
- **1/tcp = 16/16 PASS**. **2/tcp = 17/17 PASS** — the DLM grant-protocol change does NOT regress 2/tcp (was sess58 17/17). Handoff infra is SAFE + load-bearing.
- **4/tcp dir_reuse_coherency**: ~17-24/24 rounds failing -> **1-2/24** (24x improvement). Still FAIL (needs 0). 8/tcp not yet run.

### WHAT WAS BUILT (sess61/62 FIXDESIGN, end-to-end) — the reliable "a DIFFERENT node held EX since I last did" signal
grant_gen alone over-fires (bumps on same-node re-grants -> resurrection). Sourced instead from the DLM master's dg_shadow:
- **dlm/dlm.c**: `dg_shadow_ent` += `last_owner` (RETAINED across dg_release) + `used`. `dg_grant_ex()` RETURNS handoff = (last_owner!=0 && last_owner!=owner); sets granted `lk->handoff`; delivered to remote grantee via `mxfs_dlm_lock_resp.handoff` (was pad[0], wire size unchanged) at all send_grant GRANT sites (DENY sites pass 0); grantee stores it in process_remote_grant. New query `mxfs_dlm_grant_was_handoff(ctx,res,*gen_out)`.
- **dlm/v5_mount.{c,h}**: `mxfs_v5_dlm_inode_grant_handoff(ctx,ino,*gen_out)` (CAW->false). **xfs_inode.h**: `i_dlm_handoff_acted_gen` (consume once/episode, reset in inode-init).
- **xfs_mxfs_dlm.c mxfs_dlm_reload_inode**: compute `genuine_handoff` at top (handoff && gg!=acted_gen) + P63-HANDOFF detector; fold into `peer_modified_since_load`; bypass P33 dir-grow-revert + P43/P43B fmt-revert keep-stale guards (`&& !genuine_handoff`); set acted_gen at the actual adopt (before xfs_idestroy_fork). Fast-path EX serve (~9854): replaced DISABLED sess61 grant_gen check with handoff trigger -> dir_ex_stale_refresh (P63-FASTEX-HANDOFF).
- **xfs/libxfs/xfs_dir2_block.c**: P62-SF2BLK-CALLED now dumps shortform NAMES.

### EVIDENCE IT WORKS (RULE 4)
P63-HANDOFF fires 23-24x/node cross-node post_release=1. P56-RELOAD-MERGE shows clean disk-superset adopt: `clean=1 disk=[node1_f1..node1_f8]`. Read-side staleness FIXED.

### RESIDUAL (1-2/24) — see [[sess63-residual-root-crossnode-gen-divergence-reused-dir]]
DECISIVE: each failure loses exactly ONE entry (node1_f1 / node4_f31.md5 / etc), only peers (not rank1 the dir creator). SF2BLK name-dump PROVES cross-node INCARNATION divergence: same reused dir ino, DIFFERENT di_gen, DISJOINT same-node-only shortforms each converting sf->block independently. Reused-dir dentry/iget coherence (d_revalidate is DISABLED sess38), NOT the within-incarnation block0 split. The handoff reload (acquire/read side) can't make a peer abandon a stale CACHED incarnation. NEXT: reused-dir incarnation coherence (reliable inode-free fencing via DLM, or gen-change detect at dir lookup/create dropping stale child dentries). KEEP handoff infra. Marker NOT written.</body>
