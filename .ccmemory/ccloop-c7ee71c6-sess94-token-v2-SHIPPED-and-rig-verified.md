---
name: ccloop-c7ee71c6-sess94-token-v2-SHIPPED-and-rig-verified
description: sess94: step 5.2 (authority token v2) SHIPPED 0.11.427 and RIG-VERIFIED through a real node death — v=2, nonzero victim incarnation, status field dis…
metadata:
  type: reference
tags: [sess94, foreign-replay, authority-token, token-v2, step5.2, D-FOREIGN-REPLAY-UNGATED-IMAGES, rig-verified]
---

# step 5.2 — token v2 — SHIPPED (0.11.427) and RIG-VERIFIED

Executes the sess83 RULE-5 ruling + the sess91 edit inventory. Still **report-only**:
v2 changes what is RECORDED, not what is DECIDED. The ATOMIC-SKIP taint scan and the
P223 gate are byte-identical, so the `foreign_replay_ab.sh` arms stay comparable.

## What landed

**Wire** (`xfs/libxfs/xfs_log_format.h`) — `struct mxfs_blf_authority_v2`, 40B BE,
naturally aligned, `_Static_assert`ed at 24 (v1) and 40 (v2):
`be16 version; be16 class; be32 flags; be64 resource; be64 grant_epoch;
be64 owner_epoch; be32 owner_slot; be32 owner_node`. fs_gen omitted (already bound by
log/slice/descriptor/HB). Plus the status enum (ruling item (a)), the
`MXFS_AUTH_FLAG_{STATUS,RESERVED}_MASK` split, `mxfs_blf_authority_size(version)`,
the normalized `struct mxfs_auth_view`, and `enum mxfs_auth_parse`.

**The size-macro trap, handled as the inventory demanded:** `MXFS_BLF_AUTHORITY_SIZE`
was REDEFINED to `sizeof(v2)` (one macro, both sides — size estimate + emission), and
the local `lbuf` struct moved to the v2 type in the same edit. No second emit-size
macro. The PARSER never uses that macro — it reads the version field out of the record
first, then sizes from `mxfs_blf_authority_size()`.

**Producer** (`pal/linux/xfs_buf_item.c`) — the sess82 classification ladder now fills
`mba_status` from the branch it already took instead of throwing it into a counter.
Two new counters: `unknown` (neither AG-authorized nor holding an AG grant — the
inode-authority population) and `incomplete` (capture failure).

**Identity, all-or-nothing** — `mxfs_disklock_mount_identity()` (disklock.c) and its
forwarder `mxfs_v5_dlm_mount_identity()` (v5_mount.c) return {slot, node_id,
incarnation} or false with all three zeroed. TRAP AVOIDED: do NOT read
`ctx->node_slot` in v5_mount for this — it is 0 in a fresh context and 0 is also a
legitimate claimed slot (the MDS), so it cannot distinguish unclaimed from slot 0.
The disklock's `local_slot` is -1 until the claim succeeds and therefore can.
**Capture failure DOMINATES classification**: if identity is unavailable the token is
forced to class NONE / status INCOMPLETE with all identity fields zeroed — a record
that cannot be bound to an emitting incarnation must not carry a class that looks
like proof.

**Parser/reporter** (`xfs/xfs_log_recover.c`) — `mxfs_blf_parse_authority()` no longer
returns a pointer-or-NULL. It returns NOT_BUF / UNTAGGED / MALFORMED / OK and fills a
normalized view. v1's NULL conflated the last three, so report-only mode could not
measure any of them. **v1 normalizes to status UNSET, never VALID** — v1 must never
gate an apply/skip decision no matter how good its producer gets.

## The measurement (real node death, victim test9, 32/caw)

`tests/foreign_replay_ab.sh 32 9` — test9 destroyed, live foreign replay of slot 24 on
test1 at t+114s, visibility 40/40 dirs + 40/40 files + 40/40 sizes.

    P227-TOKEN blkno=50237378 len=1 v=2 class=1 st=1 res=24 gepoch=1
               oepoch=7618068144501195325 slot=24 node=801578990 (n=1)
    P227-TOKEN blkno=50237448 len=8 v=2 class=0 st=4 res=0 gepoch=0
               oepoch=7618068144501195325 slot=24 node=801578990 (n=4)
    P227-TOKENSUM buf_items=4 tokened=4 v1=0 v2=4 ag=3 sb=0 classless=1
                  untagged=0 malformed=0 st: s1=3 s4=1

- `v=2` on every token, `v1=0`, `malformed=0`, `untagged=0`.
- `oepoch` is a real nonzero mount incarnation — **the field v1 could not have**, and
  the thing D-MOUNT-INCARNATION-CONSTANT-ZERO had to close before 5.2 could exist.
- `slot=24` matches the dead slot the replayer independently named, and `node=` is a
  real node_id: the slot<->node consistency check has both halves.
- `st=1` (VALID) on AG-classed images, `st=4` (MISLABELLED) on the classless one —
  the status field DISCRIMINATES, which is exactly what class==NONE could not do.

Producer side on a live node, after driving 16384 tokens:

    P228-TOKCLASS n=16384 ag=11613 sb=1 mislabel=4770 noepoch=0 unknown=0 incomplete=0
                  mis_blft: t10=106 t11=1675 t12=1299 t13=376 t14=1309 t15=5

**`incomplete=0` over 16384 tokens** = the mount-identity capture never failed, so
every emitted token carries a real {slot, node, incarnation}.

## The finding step 5.3 should start from

`unknown=0` while `mislabel=4770` (29% of all tokens). The inode-authority population
— dir data blocks, da-nodes, attr blocks, symlinks, bmbt — is NOT reaching the
"holds no AG grant" branch. It reaches **MISLABELLED**: the emitter *does* hold the
containing AG's EX grant (ge != 0) at format time while the buffer's real authority is
the inode's grant. So step 5.3's capture problem is not "find the missing authority",
it is "stop the AG grant from shadowing the inode grant" — and `mis_blft` names the
population precisely (t10/t12/t14 dominate).

## proto_gen — decided, NOT bumped

Both mixed-version directions are safe by construction, so no bump was spent:
- v2 record read by a v1 parser: `iov_len = base+40 >= base+24` passes the length
  check, then `version != 1` → NULL → no authority → fail closed.
- v1 record read by the v2 parser: version=1 → size 24 → decodes, status UNSET.
The ruling's "reserved bits must be zero or future enforcement rejects the token"
forces a bump **at enforcement (5.4)**, not now.

## Still owed on this defect (unchanged by 5.2)

Ruling items (b) capture at the DIRTY/JOIN seam, (c) MERGE not last-writer-wins, and
(d) provenance SNAPSHOT with the CIL image. The wire is a clean prerequisite for all
three: they change WHERE and HOW the fields are filled, not what the fields ARE.
The dir-image false-SKIP that makes this defect critical does not close until 5.4.
