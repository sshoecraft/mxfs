---
name: sess3-ccloop-UNIFIED-root-divergent-extentmap-and-forceblock-conflict
description: sess3(ccloop): build 5240351B REGRESSED cache_coherency (forceblock=1 default). Unified root=divergent dir data-fork extent map. Fix locus=reload_ino…
metadata:
  type: project
---

## sess3 (ccloop) — MAJOR reframe. Criterion NOT met; marker NOT written.

### Criterion = full `./run.sh {1,2,4,8} tcp` suite (criteria.json). Gap computed = 17 tcp combos (16× tests never run at 2/tcp + dir_reuse 8/tcp). BUT criteria.json's recorded 4/8 PASSes are STALE (older builds) — the CURRENT build 5240351B does NOT reproduce them (see below). So real scope is bigger.

### KEY FINDING 1 — build 5240351B REGRESSED cache_coherency:
- `cache_coherency` FAILS deterministically 0/2 AND 0/4 with current build 5240351B (recorded PASS at 4/tcp+8/tcp on 2026-06-27 was an OLDER build).
- Symptom: CRC error on ROOT dir block (block-format), `xfs_dir3_block_read_verify` → deterministic shutdown early in the test.
- Disabling `dir_addname_epoch_refresh=0` does NOT fix it → the session-2 epoch REFRESH gate is not the cause.

### KEY FINDING 2 — `dir_force_block=1` (compiled DEFAULT, sess67, xfs_mxfs_dlm.c:6560) is the trigger:
- `MXFS_EXTRA_MODARGS='dir_force_block=0'` → **cache_coherency 2/tcp PASSES 2/2**.
- But `dir_force_block=0` → **dir_reuse 4/tcp FAILS 0/4** (sess67 set force_block=1 specifically to fix dir_reuse sf→block conversion divergence).
- CONFLICT: cache_coherency needs force_block=0, dir_reuse needs force_block=1. `mxfs_dir_should_force_block()` (xfs_mxfs_dlm.c:6577) can't distinguish them (both are fresh shared shortform dirs). force_block is GLOBAL → just shifts WHICH test fails.

### KEY FINDING 3 — UNIFIED ROOT CAUSE (both tests, same bug):
Both cache_coherency (block fmt) and dir_reuse (leaf fmt, force_block=0) fail with the SAME signatures:
- `P13-COLLIDE ... placing onto a DIFFERENT durable dirent (stale-base free-slot double-alloc)` — in-core dir-data buffer for a daddr holds a DIFFERENT incarnation's content (garbage dmagic, different downer, ourdir=0).
- `P-IFLUSH-GAP-DETECT ino=NNN — in-core dir data fork has a HOLE between data blocks (divergent-grow torn map; DABUF_MAP_HOLE source)`.
- `P49-STALEBASE ... whole-block writeback will clobber durable peer dirents`.
→ **The dir's DATA-FORK EXTENT MAP diverges across nodes** when two nodes grow the same shared dir. Per-block epoch/gen coherence is insufficient — confirms GPT-5.5 gap #4 (coherence unit must be WHOLE inode incl. extent map + bmbt fork, not one dir block). For freshly-mkdir'd inodes the epoch gate is inert (master_ep=0).

### FIX LOCUS — `mxfs_dlm_reload_inode` adopt-vs-keep (sess49 tension, xfs_mxfs_dlm.c:5328 `mxfs_dir_epoch_adopt`, DEFAULT 0):
- epoch_adopt=1 → reload runs xfs_idestroy_fork+xfs_inode_from_disk = ADOPT disk dinode/extent-map. But adopts STALE-SMALLER disk when OUR grow isn't destaged → shrinks fork → leaf block→hole → AG double-free SHUTDOWN (sess49 measured 8/tcp 0/8).
- epoch_adopt=0 (current) → KEEP in-core when dirty/grant_held. Correct for OUR uncommitted grow; WRONG when a PEER durably grew the dir (we keep stale-smaller map → RMW wrong physical blocks → P13-COLLIDE/divergent map).
- THE FIX: make adopt-vs-keep EPOCH-GATED — adopt disk (reread WHOLE extent map) when peer's master handoff epoch is AHEAD of our last-commit epoch; keep in-core only for our own uncommitted-under-current-epoch work. = GPT's ACK-based whole-inode handoff [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]].

### INFRA built this session: `scripts/ccloop_reset.sh <N>` — robust teardown that virsh-reboots a VM when post-shutdown umount wedges in D-state (the recurring "device is busy" mkfs-fail cause). USE IT between runs.

### Build identity: 5240351B deployed on /src/mxfs/mxfs.ko. Nodes test1-8 (192.168.120.186=test1, .182=test2). prep_node.sh insmods /src/mxfs/mxfs.ko via NFS /src from 192.168.1.4. Pass `MXFS_EXTRA_MODARGS='k=v'` to set module params per run.
See [[sess2-ccloop-FINAL-epoch-fixes-banked-corruption-gone-residual-is-writeside]] [[sess2-ccloop-BEST-CONFIG-epoch-fixes-plus-mht1500-3of3]]
