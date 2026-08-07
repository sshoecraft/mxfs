---
name: ccloop-c7ee71c6-sess91-step5.2-token-v2-edit-inventory
description: sess91: step 5.2 (token v2) is UNBLOCKED — the line-verified edit inventory for the wire+producer half, with the size-macro trap and the status enum.
metadata:
  type: reference
tags: [sess91, foreign-replay, authority-token, step5.2, token-v2, edit-inventory, D-FOREIGN-REPLAY-UNGATED-IMAGES, unblocked]
---

# step 5.2 — token v2 — UNBLOCKED, and the exact places it lands

`D-FOREIGN-REPLAY-UNGATED-IMAGES` step 5.2 was blocked on
`D-MOUNT-INCARNATION-CONSTANT-ZERO` because v2 must bind the token to the victim
**incarnation** and that identifier was a measured constant 0. That defect is
CLOSED (sess91, FIXED AND VERIFIED) — the incarnation is now a real random
nonzero 64-bit value per mount, rig-verified. **5.2 is unblocked.** Nothing
below is written yet; this is the recon so the next session does not re-derive it.

## Why v1 cannot be promoted (already documented in-tree)

`xfs/libxfs/xfs_log_format.h:545-557` states it: `mba_resource` is a `__be32`
agno so it cannot name an inode; `mba_owner_boot` is memset 0 and never filled
so a record cannot be bound to a victim incarnation; and a 32-bit resource
cannot be widened without a wire change. **V1 IS REPORT-ONLY AND MUST NEVER GATE
AN APPLY/SKIP DECISION.**

## The v2 wire (from the sess83 RULE-5 ruling, 40B packed BE)

    be16 version; be16 class; be32 flags; be64 resource;
    be64 grant_epoch; be64 owner_epoch; be32 owner_slot; be32 owner_node

2+2+4+8+8+8+4+4 = 40. Keeps `owner_node` as an independent slot↔node consistency
check; **omits fs_gen** (already bound by the outer log/slice/descriptor/HB).
`owner_epoch` is the emitting mount's incarnation — the field the closure
unblocked.

## The status field — the ruling's mandatory addition (a)

Today `class == NONE` overloads *six* different meanings, and the emission site
proves it: `pal/linux/xfs_buf_item.c:496-508` distinguishes `!auth && ge`
(mislabelled) from `auth && !ge` (no epoch) **only by bumping a counter** — the
token still goes out as NONE either way. v2 must carry the reason in `mba_flags`
as an explicit status, with reserved bits required to be zero so future
enforcement can reject an unknown token:

    VALID        provenance complete, single-sourced
    NOT_REQUIRED no authority is needed for this image
    UNPROVEN     authority applies but we could not prove the grant (auth && !ge)
    MISLABELLED  a grant was held but is not this buffer's authority (!auth && ge)
    MIXED        two or more differing provenances merged into this image
    INCOMPLETE   a capture attempt failed
    WRITE_AUTH   authority is the write-tenure kind, not a lock grant
    UNSUPPORTED / MALFORMED

Report-only mode must count MALFORMED / MIXED / INCOMPLETE **separately** and
never normalize them to NONE.

## Edit sites — line-verified against 0.11.421

1. **`xfs/libxfs/xfs_log_format.h:537-559`** — add `struct
   mxfs_blf_authority_v2` and `MXFS_BLF_AUTHORITY_V2 2`, plus the status enum.
   Keep the v1 struct: an upgraded node may replay a log written by a v1 node.

2. **THE SIZE-MACRO TRAP — read this before touching anything.** Presence of the
   trailer must be size-stable or the CIL shadow buffer overruns (silent
   corruption class, documented at `xfs_buf_item.c:429-441`). Today that is
   guaranteed by ONE macro used on both sides:
   - size side: `pal/linux/xfs_buf_item.c:257-258`
     `if (mxfs_buf_item_wants_authority(bip)) *nbytes += MXFS_BLF_AUTHORITY_SIZE;`
   - format side: `pal/linux/xfs_buf_item.c:515-517` emits
     `base_size + MXFS_BLF_AUTHORITY_SIZE`.

   So **redefine the single existing macro to `sizeof(struct
   mxfs_blf_authority_v2)` and change the local `lbuf` struct at
   `xfs_buf_item.c:443-446` to the v2 type in the same edit.** Do NOT add a
   second emit-size macro. The PARSER is the only place that needs per-version
   sizes — give it `mxfs_blf_authority_size(version)` and use that for its
   length check, never the emit macro.

3. **`pal/linux/xfs_buf_item.c:427-518`** — the emission body. The classification
   ladder (SB → AG-authorized → mislabelled → no-epoch) already computes exactly
   the distinctions the status enum needs; it currently throws them away into
   counters. Fill `mba_status` from the branch that is already taken, and fill
   `mba_owner_epoch` / `mba_owner_node` from the new accessors below.
   `mxfs_buf_item_wants_authority` (`:128-136`) stays exactly as-is — it depends
   only on (multi-node && buffer class) and **must never** depend on the pag
   epoch or on anything resolved at format time.

4. **New accessors, both O(1) lock-free reads of mount-lifetime constants** —
   model them on `mxfs_v5_dlm_get_node_slot` (`dlm/v5_mount.c:4502-4507`), which
   is a three-line read of `ctx->node_slot`:
   - `mxfs_v5_dlm_get_node_id(ctx)` → `ctx->node_id` (the field already exists;
     it is used at `v5_mount.c:4497`)
   - `mxfs_v5_dlm_mount_incarnation(ctx)` → a new
     `mxfs_disklock_local_epoch(dl)` returning `ctx->epoch`
   Declare them beside the existing `extern`s at `xfs_buf_item.c:124-126`.
   The slot and the incarnation are both fixed for the life of a mount (a node
   claims its slot at mount and holds it; sess89 measured that nodes migrate
   slots *across* mounts, never within one), so no caching layer is needed and
   no lock is taken on the format path.

5. **`xfs/xfs_log_recover.c:2034-2065`** — `mxfs_blf_parse_authority`. Keep the
   ordering exactly as sess49 established (`ri_cnt<1 || !ri_buf` →
   `xfs_buf_log_check_iovec` → `ITEM_TYPE()==XFS_LI_BUF` → flag →
   `blf_map_size <= XFS_BLF_DATAMAP_SIZE` → **recompute** `base` from
   `blf_map_size`, never a stored offset → length → version). Extend the version
   test to accept 1 and 2 and return a tagged union or a normalized struct.
   NULL still means "no authority", fail closed.

6. **`xfs/xfs_log_recover.c:2108`** — the P227-TOKEN reporter. Print the status
   and the new fields, and count MALFORMED / MIXED / INCOMPLETE separately.

## Still report-only after 5.2

v2 changes what is RECORDED, not what is DECIDED. The ATOMIC-SKIP taint scan and
the P223 gate stay byte-identical so `tests/foreign_replay_ab.sh` arms remain
comparable. Enforcement is 5.4+; the dir-image false-SKIP that makes this defect
critical does not close until then.

## The three ruling items 5.2 does NOT cover — do not let the wire hide them

(b) capture provenance at **DIRTY/JOIN** time (the `xfs_trans_dirty_buf` seam),
with format time only SERIALIZING it — today capture is at format time
(`xfs_buf_item.c:438-441`, justified by the step-2b `log_force(SYNC)` barrier
audit). (c) **LAST-WRITER-WINS IS WRONG** — merge instead: no provenance yet ⇒
install; identical complete provenance ⇒ retain; differing resource / owner
incarnation / slot / class-mode / grant epoch ⇒ permanently MIXED; any capture
failure ⇒ permanently INCOMPLETE. (d) provenance must be SNAPSHOT with the CIL
image so relogging into a later checkpoint cannot mutate provenance attached to
an earlier pending checkpoint — audit CIL insertion+relogging, shadow item
alloc/copy, transaction cancellation, BLI reuse, buffer invalidation/stale, and
I/O completion + checkpoint retirement.

The wire is a clean prerequisite for all three: (b)/(c)/(d) change WHERE and HOW
the fields are filled, not what the fields ARE, so landing v2 first does not
have to be redone.

## Open decision — proto_gen

A gen-3 parser meeting a v2 token is already safe by construction: it recomputes
`base`, passes the `>= base+24` length check, reads `mba_version == 2 != 1`, and
returns NULL = no authority = fail closed. So safety does not force a bump. The
ruling's "reserved bits must be zero or future enforcement rejects the token"
does force one **at enforcement**. Decide deliberately whether to spend the bump
now (one re-mkfs + board, and the rig re-preps constantly anyway) or at 5.4.
