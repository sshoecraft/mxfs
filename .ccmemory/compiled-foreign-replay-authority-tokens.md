---
name: compiled-foreign-replay-authority-tokens
description: Compiled: D-FOREIGN-REPLAY-UNGATED-IMAGES end-to-end — both defect arms, P223/adopted containment, GPT token spec, steps 1-3a shipped, 3b resume poin…
metadata:
  type: project
tags: [compiled, foreign-replay, dlm, recovery, authority-token, grant-epoch, D-FOREIGN-REPLAY]
---

# D-FOREIGN-REPLAY-UNGATED-IMAGES — the authority-token campaign

Critical, OPEN since sess32. The longest-running open defect and the campaign
sess48 died mid-flight in. Resume at **step 3b**.

## The defect

MXFS gives every node its own journal slice. Per-node slices number LSN
cycle/block independently, so any cross-slice LSN comparison is meaningless.
Upstream XFS gates BUFFER (and dquot/icreate) image replay on exactly that:
`lsn && XFS_LSN_CMP(lsn, current_lsn) >= 0 -> skip`
(`pal/linux/xfs_buf_item_recover.c:1061`, `xfs_dquot_item_recover.c:145`).
MXFS's own sb-LSN check already skips this comparison with a comment admitting
incomparability — the same incomparability applies to every buffer record.
Two arms, both real:

- **false-APPLY** — replay silently reverts survivor-written dir blocks / AG state.
- **false-SKIP** — the dead node's fsync-ACKED changes are dropped.

INODE records are correctly gated and stay applied: `di_changecount` is
node-independent ([[ccloop-c7ee71c6-sess32-GPT-ruling-A-D-foreign-replay-stop-ship]]).

Three exposure paths: live foreign replay by the elected survivor; mount-time
claim of a dirty slice hours later; late intent processing against a moved-on
filesystem.

## Containment (shipped 0.11.273-274) and why it is not the fix

`mxfs.foreign_replay_untagged_apply=0` — live foreign replay skips untagged
buf/dquot/quotaoff/icreate images (P223-FR-UNTAGGED-SKIP). `mxfs.stale_stage_unlanded_shutdown=1`
fails P222's unlanded arm closed. A/B on victims test9/test10: 11 skips vs 0,
both arms 40/40 acked visibility — the refused records were redundant because
the destage kick lands metadata within ~ms of commit
([[ccloop-c7ee71c6-sess32-P223-foreign-replay-containment-AB]]).

Mount-time arm: pass-1 (own ACTIVE stamp reclaim, full recovery safe) vs pass-2
(fresh claim = `slice_adopted`) → `XLOG_MXFS_ADOPTED_SLICE` → predicate
`xlog_is_mxfs_untrusted_replay = foreign || adopted` suppresses untagged images
and intents. Verified live on test11 (7 images suppressed, clean rejoin) and
test12 (knob=1, no suppression)
([[ccloop-c7ee71c6-sess32-adopted-slice-suppression-shipped]]).

**Residual keeping it OPEN**: acked buffer-image changes that never destaged are
now applied by NOBODY — a bounded durability gap. Adopted-intent skip leaks
incomplete extent-frees.

## The skip is itself a tear mechanism (sess41, live damage)

Replay APPLIED the inode item (nlink→0 durable) but SKIPPED the two untagged
BUFFER images of the *same transaction* (dirent-removal block + AGI bucket
insert). Result: a state that existed nowhere — dirent PRESENT, nlink-0 zombie
on NO bucket, `ls` showing `d????????? .oud_...`. Per-item skipping manufactures
torn states; **the transaction is the atomicity unit**.
`tests/openunlink_deaths.sh unlinker_death` is a deterministic ~2min reproducer
([[ccloop-c7ee71c6-sess41-B-sweep-verified-foreign-replay-tear-captured]]).

This drove the ATOMIC-SKIP taint scan: any BUF/DQUOT/QUOTAOFF/ICREATE item taints
the whole transaction.

## GPT design ruling (sess48) — the binding spec

Full spec in [[ccloop-c7ee71c6-sess48-GPT-ruling-foreign-replay-token-design]].

- **Transport: per-buffer tokens in a v2 buffer log format.** Transaction-level
  authority records REJECTED — CIL aggregation coalesces items across
  transactions/relogs, so recovery's transaction hash cannot preserve per-buffer
  attribution; multi-AG transactions prove only "some grant existed". Checkpoint
  summaries share the flaw.
- **Content**: `{version, resource_class, resource_id/agno, grant_epoch, owner_slot,
  owner_boot_epoch}`. `{agno, grant_epoch}` suffices **iff** grant_epoch is durable,
  non-reused, per-acquisition, and persisted **before** the grantee may modify AG
  metadata. A separate tenure_id is redundant.
- **Apply rule**: exact match (class, id, epoch) vs manifest → apply in forward
  same-slice order. No cross-slice LSN comparison, ever. SB/global buffers get
  their own class and epoch and **never inherit authority from co-transaction AG
  items**.
- **Ordering**: fence(PR) → freeze grants/slots → durable manifest+descriptor
  BEFORE any purge → replay under token gate → make output durable → write
  IMAGE_REPLAY_DONE (outside the purged slice, checksummed) → only then purge and
  resume. 7 before 8, never reversed. Mount-time: matching DONE → suppress;
  no DONE → recover then DONE; mismatched → fail closed.
- **FORBIDDEN simplification — the grant-release/CIL boundary.** Before releasing
  an AG grant, all CIL/log items authorized by it must be formatted and stable.
  Without this a G1-dirtied buffer relogged under G2 misattributes and *no*
  tagging scheme is sound.
- **Critical release invariant**: exact-held-at-death does NOT recover acked writes
  of a grant released before death — release must guarantee acked state durably
  destaged.

## What shipped

**Step 1 — 0.11.395.** `uint64_t ex_grant_epoch` in `struct mxfs_caw_lock_slot`
(8 of reserved[352], 512B assert intact). Stamped in `dlm/dlm_caw.c
caw_grant_epoch_update` (~945) = `s->ex_grant_epoch = s->generation` when mode is
EX/PW — the one helper every grant path already calls after its generation bump
(initial acquire ~4268, waiter-promote ~2826, convert-upgrade ~5928, batch ~7195/~7223,
claim-recycle ~3503). Downgrades correctly do not stamp. **0 = no-authority
sentinel**: fresh pre-grant, tombstoned, and REPAIRED slots — repair deliberately
does not carry it forward, because unknown EX history must fail closed
([[ccloop-c7ee71c6-sess48-STEP1-design-ex-grant-epoch-in-caw-slot]]).

Recon that seeded it: `struct mxfs_disklock_record` is exactly 512B; its existing
`epoch` field is the **node-instance** epoch (new per mount/rejoin) = the ruling's
`owner_boot_epoch`, already persisted and CRC-covered. The missing piece was only
the per-acquisition epoch. `granted_at_ms` is per-node boottime — never compare
cross-node ([[ccloop-c7ee71c6-sess48-disklock-record-recon-epoch-exists]]).

**Step 2a — 0.11.396.** `mxfs_dlm_caw_read_ex_grant_epoch` (dlm_caw.c) + wrapper
`mxfs_v5_dlm_ag_grant_epoch` (v5_mount.c, CAW only; TCP -ENODEV = fail closed) →
`pag->pag_mxfs_grant_epoch` (xfs_ag.h), populated in the fresh-grant success path
of the AG acquire (`xfs_mxfs_dlm.c` ~34572, the sess19b post-grant slot-read block,
slot-stable/pre-`pag_dlm_lock` window). Read failure ⇒ 0 ⇒ fail closed
([[ccloop-c7ee71c6-sess48-STEP2a-SHIPPED-pag-grant-epoch]]).

**Step 2b — AUDIT PASS, no code.** The ruling's non-negotiable barrier already
exists in `bast_work_fn` Phase 2 (~38955-39000): `xfs_log_force(SYNC)` → `msleep(3)`
→ second `xfs_log_force(SYNC)` → `drain_meta_buffers` → `blkdev_flush`, plus a
force at ~38833. Every G1 item is formatted and log-stable before unlock;
`demoting=true` blocks concurrent acquires and release proceeds only at
holders==0. The G1→G2 relog hazard is excluded: an item relogged after reacquire
formats while the node actually holds G2, which is correct attribution.
**Directive that fell out: capture the token at CIL FORMAT time, not at
`xfs_trans_log_buf` time** — an item can be relogged across tenures, so format
time is when the emitted image is fixed
([[ccloop-c7ee71c6-sess48-STEP2b-AUDIT-PASS-cil-barrier-exists]]).

**Step 3a — 0.11.397, SHIPPED + VERIFIED.** Layout: `XFS_BLF_MXFS_AUTHORITY (1<<5)`
(blf bits 5-10 were free; 11-15 are BLFT), 24-byte big-endian `struct
mxfs_blf_authority` appended after `blf_data_map` in the *same* format iovec
([[ccloop-c7ee71c6-sess48-STEP3-layout-blf-bit5-token-after-map]]).

Emission mechanics: build a local `[blf base_size][24B token]` and emit ONE
`xlog_format_copy` of `base_size+24`; keep the returned pointer for the `blf_size++`
mutations. A separate iovec region would shift the `ri_buf` chunk indexing recovery
walks. **HAZARD (silent corruption class):** `xfs_buf_item_size_segment` must add
the same 24 bytes under the same condition — hence the shared pure predicate
`mxfs_buf_item_wants_authority`, which depends only on (multi-node && buffer class)
and **never** on the pag epoch, so presence is size-stable. Underestimating
overruns the CIL shadow buffer
([[ccloop-c7ee71c6-sess48-STEP3a-emission-mechanics]]).

Fill: `xfs_sb_buf_ops` → class SB; `agno<agcount` → `perag_get` →
`READ_ONCE(pag_mxfs_grant_epoch)`, nonzero → class AG; else NONE (fail closed at
the future gate). Stale/cancel segments stay untokenized. `owner_boot` is 0 for
now — fill when the descriptor work lands. Verified: matrix 9/9, rsync lap 32/32,
**crash_consistency 204/204** (real dirty-log replay of tokened records)
([[ccloop-c7ee71c6-sess48-STEP3a-SHIPPED-token-in-log]]).

Passive by construction: recovery's only check on the region is
`xfs_buf_log_check_iovec` (bitmap-bounds), and upstream pass2 copies
`min(i_len, sizeof(xfs_buf_log_format))`, so trailing bytes are ignored by
un-aware readers. That is why 3a is safe to soak before 3b exists and why the
log-incompat flag can wait for enforcement (step 5).

## RESUME HERE — step 3b (report-only parser)

Two gates, both in the pass2 item-recover function of `xfs/xfs_log_recover.c`
(~2030-2145) ([[ccloop-c7ee71c6-sess48-STEP3b-insertion-points]]):

1. **ATOMIC-SKIP taint scan (~2049)** — under `xlog_is_mxfs_untrusted_replay(log)
   && !mxfs_foreign_replay_untagged_apply`, a pre-pass taints the whole transaction
   if ANY item is BUF/DQUOT/QUOTAOFF/ICREATE → P227-FR-ATOMIC-SKIP.
2. **Per-item P223 skip (~2128)** — same condition per item, reached only when
   apply-knob=1. P226 intent skip sits above it.

Plan: helper `mxfs_blf_parse_authority(item)` → `const struct mxfs_blf_authority*`
or NULL. Item type `XFS_LI_BUF`; `blfp = ri_buf[0].i_addr`; check
`blf_flags & XFS_BLF_MXFS_AUTHORITY`; **recompute** `base = offsetof(blf_data_map)
+ blf_map_size*4` — never trust a stored offset; require `i_len >= base+24`;
version be16 == 1. In the taint scan, parse and `xfs_notice` a count-capped
P227-TOKEN decode. **Decode only — the taint decision is unchanged in this build.**
Verify via `tests/foreign_replay_ab.sh` that victims' records arrive with class=AG,
sane agno, nonzero epoch.

## Then

- **Step 4** — recovery descriptor + IMAGE_REPLAY_DONE + victim-slot freeze;
  `mxfs_dlm_caw_purge_node` (`v5_mount.c:1197/1274`) must not clear victim EX bits
  pre-DONE. Rework of the P163-RECOVERY-COMPLETE flow.
- **Step 5** — gate swap: exact-match {agno, epoch} vs the fenced slot's
  `ex_grant_epoch` replaces the P223 untagged skip. Transaction applies iff ALL its
  images are authorized (keep the sess41 atomicity principle). Class NONE /
  SB-unmatched / mismatch → tainted as today. DQUOT/QUOTAOFF/ICREATE stay
  untokenized → tainted (noquota moots dquot; icreate needs its own class).
  A/B via `foreign_replay_ab.sh` + fault injection at the 5 sess32 points.

Campaign entry and the containment code map: [[ccloop-c7ee71c6-sess48-HANDOFF-foreign-replay-campaign-entry]].

## Recurring lessons

- **No criterion drove this machinery.** crash_consistency is guest-side only and
  fence_during_write leaves no dirty slice — measured zero foreign-replay lines
  across both criteria on all 32 nodes. The board looked green over an entirely
  unexercised code path. `tests/foreign_replay_ab.sh` exists because of this.
- **Per-item skipping tears; transactions are atomic.**
- **Fail closed on unknown authority** — epoch 0, repaired slots, TCP transport,
  read failure all resolve to "no authority".
- **Size/format predicates must be pure and shared**, or the CIL shadow buffer
  overruns silently.
- **Rig**: a freshly booted test VM has no /src (NFS not in fstab) and no iSCSI
  session — restore before `prep_node.sh`. After every mkfs/prep all nodes read
  pass-2 ADOPTED with clean slices; that is expected and a no-op.
