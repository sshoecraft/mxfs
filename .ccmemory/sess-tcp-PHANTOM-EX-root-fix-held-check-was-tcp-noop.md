---
name: sess-tcp-PHANTOM-EX-root-fix-held-check-was-tcp-noop
description: dir_reuse 2/tcp ROOT = phantom-EX (cached EX, DLM grant gone). mxfs_v5_dlm_inode_held returned 1 ALWAYS on TCP→all phantom-EX probes/fixes inert. Fix…
metadata:
  type: project
---

## dir_reuse_coherency 2/tcp — PHANTOM-EX confirmed + partially fixed (RULE 4)

### THE decisive infra bug (root of why 90+ sessions missed this on TCP):
`mxfs_v5_dlm_inode_held()` (dlm/v5_mount.c:1350) returned **1 (held) UNCONDITIONALLY for TCP**
(`if (!ctx->dlm_caw) return 1`). TCP keeps grants in the dlm.c local mirror, NOT the CAW slot
table. So EVERY phantom-EX probe/fix built on it (sess107 P106/P108-REACQUIRE, the sess8 "not
lost-slot, it's double-grant" conclusion) was **INERT on TCP** — the exact transport the criterion
tests. sess8's "P108 fired ZERO times" was because held always==1, not because the slot was held.

### FIX 1 (landed): real TCP held-check.
- dlm/dlm.c: new `mxfs_dlm_held_mode(ctx, resource)` — highest mode this node holds in its local
  mirror (GRANTED/CONVERTING entry owned by local_node), else MXFS_LOCK_NL. Read-only, cheap.
- dlm/dlm.h: declared. dlm/v5_mount.c: `mxfs_v5_dlm_inode_held` now uses it for the TCP path
  (`ctx->dlm`): returns held_mode>=EX.

### PROVEN with the working check: broadened P106 probe (xfs_mxfs_dlm.c ~8567, dropped the
self_created+1000ms-throttle gates) → **P106-STALE-EX fired 45× on test1 (node1)** for the shared
dir ino=131: `cached_mode=EX on_disk_held=0 unpub=1 pin=0`. Phantom-EX: node1 RMWs the dir under a
locally-granted UNPUBLISHED EX (invisible to the DLM) while node2 acquires the empty slot cleanly →
both modify → durable lost-update. (Matches drain_evict==empty[-ENOENT], release-fence sound, both
nodes durably agree on contiguous lost ranges = concurrent divergent RMW, NOT stale cache.)

### FIX 2 (landed): broadened sess107 unpublished-EX backstop (xfs_mxfs_dlm.c ~8309) — divert
EVERY unpublished dir EX-modify (pin==0) to the slow-path real acquire, dropping the
`(reused_create || !self_created)` gate (an unpublished inode gets NO BAST → self_created never
clears → old gate never fired). **Result: P106-STALE-EX → 0 on both nodes. Phantom-EX eliminated.**

### RESIDUAL (still FAIL, build 972D4319): loss persists (round 11 readdir=187, data-loss face).
P108-REACQUIRE now fires 80-104×/run (the working held-check catches lost-slot grants and
re-acquires) but the loss survives. P108 is **throttled 1/sec AND gated `!self_created`** (skips
node1's self-created shared dir) → sub-second lost-slot window uncovered. Likely residual = either
(a) published-EX lost-slot in the throttle/self_created gap, or (b) a TRUE double-grant (both
mirrors GRANTED). NEXT: make the held-check at ilock_begin un-throttled + cover self_created for
TCP (cheap local lookup), re-acquire on held<EX; if loss still survives, add a GRANTED-entry-removal
trace for ino 131 in dlm.c (find what removes a holder's master/mirror entry without a legit
release — the memory's Bug-51/membership-purge/dup-release audit). Build base: 972D4319.
Test loop: `MXFS_EXTRA_MODARGS='inode_mht_ms=300' bash tests/drc_cap2.sh` (clear dmesg -C first).
mht=300 still NOT the code default (needed for timing) — make it default before the criterion run.
See [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]] [[sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit]].
