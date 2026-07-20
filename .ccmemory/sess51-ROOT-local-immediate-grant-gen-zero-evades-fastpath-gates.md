---
name: sess51-ROOT-local-immediate-grant-gen-zero-evades-fastpath-gates
description: sess51(ccloop) ROOT+FIX(build B3957326): master's local-immediate EX self-grant (dlm.c:1346) left grant_gen=0; fast-path staleness gates guard hgg!=0…
metadata:
  type: project
---

## sess51 (ccloop) — ROOT CAUSE + FIX for 8/tcp dir_reuse single-dirent loss

### Fresh decisive evidence (build C69E3475, clean 8/tcp dir_reuse, DRC_STREAM):
- **Round 1 (FRESH dir, NO inode reuse) lost 4 entries**, all 8 nodes AGREE missing = `node2_f40.md5 node2_f41.md5 node2_f49.md5 node2_f50.md5` (test2's TAIL .md5 sidecars). Durable on-disk loss, lookup_fail=0 (data-block shortfall, not leaf-hash). ⇒ the loss is NOT about rm-rf/inode reuse (sess50 phantom-across-reuse framing was wrong for the primary mechanism); it's a concurrent-create lost-update.
- **test3 masters ino 131** (P64-MASTER-HANDOFF 265× round1). test3 fired **P-DOUBLEGRANT 3×**, each with `gen_new=0`; P48-DG-CHAIN shows the GRANTED EX holder with **grant_gen=0**.

### ROOT (code-proven): local-immediate EX self-grant leaves grant_gen=0.
`mxfs_dlm_lock` compat-grant path (dlm.c:1321-1368) does `newlk = lock_alloc(...GRANTED...)` (lock_alloc zeroes grant_gen at dlm.c:271) then calls `dg_grant_ex(ctx, resource, ctx->local_node, newlk->grant_gen, ...)` **without ever assigning dlm_next_gen** — UNLIKE every sibling grant path: remote-immediate (3141), remote-reaffirm (2947), remote-upgrade (3015), promote_waiters (707) all do `grant_gen = dlm_next_gen(ctx)` first. So the master's OWN EX grants carry grant_gen=0.
Consequence: the fast-path dir-EX staleness gates ALL guard with `hgg != 0` (P63-FASTEX-HANDOFF xfs_mxfs_dlm.c:14391 `if (ho && hgg != 0 && hgg != acted)`; P51 under-fire detector excludes hgg==0). A master holding a gen-0 grant **SKIPS the handoff refresh even when a peer genuinely held EX since** (ho=true) → RMWs a STALE dir base → drops the peer's tail dirents. test3 (master) clobbers test2's tail .md5.

### FIX (build B3957326): dlm.c:1346 — stamp `newlk->grant_gen = dlm_next_gen(ctx);` before dg_grant_ex, matching remote-immediate. Makes the master's own grants visible to the same staleness machinery that already protects remote grantees.

### SECONDARY ANOMALY (not yet fixed, may be separate): P-DOUBLEGRANT owner ids (1741934843, 4139768876, …) appear NOWHERE else in dmesg (not membership, not grant traffic) and pair with grant_gen=0 → look like garbage/stale owners. Could be lock-table corruption or pre-convergence formation-ramp residue. Watch if loss persists after the gen fix.

### INFRA: every run leaves 1-2 nodes wedged on teardown (D-state [mxfs-worker] pins module refcount=1, won't rmmod) → next prep ABORTs. Recover: `virsh -c qemu:///system destroy testN; start testN`. Did a full clean 8-node reboot before the verification run.

### STATUS: build B3957326 deployed; repro4 running for verification. Marker NOT written. Need multiple clean 8/tcp dir_reuse PASS (bug was ~1/4) + then full ./run.sh {1,2,4,8} tcp.
See [[sess50-NEXT-fix-dir_epoch-propagation-some-grant-path-delivers-0]] [[sess50-LOCALIZED-grantee-phantom-cached-EX-stale-local-dir_epoch-master-sends-correctly]].
