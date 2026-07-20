---
name: sess52-PHANTOM-desync-dlm-revoke-not-propagated-to-xfs-mode
description: sess52(ccloop) phantom-EX refined: P51-PHANTOM stacks are plain xfs_create→addname (no recursion, demoter_self=0). Many have state=CACHED+held=0 = DL…
metadata:
  type: project
---

## sess52 — phantom-EX origin refined (build 6DC1DD93, P51-PHANTOM probe + dump_stack)

### P51-PHANTOM (held=0 && master=0 dir modify) stacks are ALL plain:
`xfs_dir2_data_log_entry ← xfs_dir2_node_addname / xfs_dir2_leaf_addname ← xfs_dir_createname_args ← xfs_dir_createname ← xfs_dir_create_child ← xfs_create ← xfs_generic_create ← xfs_vn_create ← do_filp_open` (comm=dd/bash). **demoter_self=0 for ALL** (not the belt-and-suspenders/demoter recursion). So a NORMAL create commits a dir-block modify while held=0.

### Two phantom sub-cases (mht=0 run, many phantoms across nodes 2,3,4,5):
- **state=0 (CACHED) + held=0**: the inode is in ISTATE_CACHED (dir fast-path serves cached EX, i_dlm_mode=EX) but the DLM grant is NOT held. ⇒ **the DLM grant was REVOKED (master moved EX to a peer) WITHOUT the XFS layer demoting i_dlm_mode/state.** The fast-path keeps serving phantom EX. (e.g. `name=[node2_f8] state=0 held=0 bastacq=0`, `name=[node5_f4.md5] state=0`).
- **state=1 (ACQUIRING) + held=0**: a modify runs while state=ACQUIRING (slow-path acquire in flight) and the grant isn't held yet. (e.g. `name=[node2_f25.md5] state=1`).
Both ⇒ the create commits without a real exclusive grant.

### THE DESYNC (root): mxfs_v5_dlm_inode_held() (local replicated grant, reflects master revoke) == 0, but ip->i_dlm_mode==EX and ip->i_dlm_state==CACHED. The DLM-level revoke did NOT propagate to the XFS-level cached-lock state. The dir fast-path serve gates on (mode==EX && state==CACHED) — NOT on held — so it serves a revoked grant. (master_self comment v5_mount.c:1680 already warns: "local DLM table can go stale if a master revocation didn't demote it" — that stale state IS being used to modify.)

### FIX (next session, precise):
Option A (source-of-truth gate, narrow): in ilock_begin dir-EX path, before serving the cached fast-path for a published peer-reachable storm dir, verify mxfs_v5_dlm_inode_held()==1; if 0, the grant was revoked → set i_dlm_mode=NL + slow-path re-acquire. NOTE dir_ex_revalidate (force slow-path, no held-check) was REFUTED because the slow path ALSO yields held=0 (state=1 case) — so a plain divert is insufficient; the held-check must gate the actual SERVE and the slow-path must not publish EX unless held==1.
Option B (fix revoke→demote propagation, root): find where the TCP DLM master revokes a holder's EX to grant a peer, and ensure the revoked node's i_dlm_mode/state are demoted (BAST delivered + processed) BEFORE the peer is granted (GPT#2 handshake: revoke→holder demotes+ACKs→master grants). The state=CACHED+held=0 phantom means a revoke happened with NO BAST processed on the holder.
Validate: P51-PHANTOM count == 0 AND dir_reuse 8/tcp PASS, watching perf (RULE 0; mht=0 was 260-410s but more phantoms — keep MHT for perf, fix correctness orthogonally).

Build 6DC1DD93 = baseline + gated P51-MOD/P51-PHANTOM probes (dirwr off = baseline-equiv). Marker NOT written. Supersedes detail in [[sess52-ROOT-PROVEN-phantom-EX-bast-during-acq-modify-without-grant]].
