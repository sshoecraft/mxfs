---
name: compiled-p53-fossil-next-unlinked-campaign
description: Compiled: the P53 fossil di_next_unlinked campaign 0.11.377-394 — arms eliminated, A-prime store v1-v5, two proven roots, FIXED AND VERIFIED.
metadata:
  type: project
tags: [compiled, P53, iunlink, fossil, di_next_unlinked, A-prime, iunl-store, D-RSYNC-RENAME-361, xfs_buf]
---

# P53 fossil `di_next_unlinked` — the full campaign (0.11.377 → 394)

**Disposition: FIXED AND VERIFIED on 0.11.394** — 8 consecutive clean soak cycles
(5@32, 3@8) + matrix 9/9 ×3, against a pre-fix cadence of ~1 fatal per 2 cycles.
This is the fossil arm of D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361; the
rename/dirent-erasure arm is a different mechanism and remains OPEN
([[ccloop-c7ee71c6-sess48-FOSSIL-ARM-VERIFIED-8-clean-cycles]]).

## Symptom

`P53-IUNLINK-MISMATCH ino=… old_ptr=<stale agino> expected=NULLAGINO next=…`
→ `xfs_inode_verifier_error` → `Corruption of in-memory data (0x8) at
__xfs_trans_commit` → withdrawal. The on-disk `di_next_unlinked` (offset 0x60 in
the v3 dinode) holds a **fossil**: a pre-remove chain value that a committed
NULL-clear should have erased. `dip_gen == i_gen` every time — later inode-item
flushes rewrite the core and launder the fossil under a current generation,
because **`di_next_unlinked` is not in the logged core**
([[ccloop-c7ee71c6-sess47-rsync-rename-producer-fossil-nextunlinked]]).

Two shapes: `old_ptr == next_agino` → absorbed by the P53-IUNLINK-IDEMPOTENT
carve-out; otherwise fatal. **Every absorbed pair means the producer is still
alive** — the carve-out is a mask, not a fix, and must not be removed while it is
the only thing between the producer and mass shutdowns
([[ccloop-c7ee71c6-sess47-FALSIFIER-P53-with-fence-on]]).

## Arms eliminated, in order (the expensive part)

Each of these cost a build/deploy/soak cycle and is worth never re-deriving:

- **Target write-cache time-travel, closable by flush** — REFUTED twice. During a
  wave, 60× `P-INOCL-COLDREAD fence=1` on the same daddr interleaved *between*
  fossil observations: the fence executed and issued device flushes and fossils
  kept coming. A flush cannot help if the clear was never submitted
  ([[ccloop-c7ee71c6-sess47-ADDENDUM-fence-ran-and-failed]],
  [[ccloop-c7ee71c6-sess47-TAIL6-cycle6-arms-eliminated]]).
- **Delwri-window re-read** — P-PINNED-REREAD extended to cover `_XBF_DELWRI_Q`,
  then ZERO through a fatal.
- **Authority/AGI arms** — `P-B-MODE-DIVERGE` (the `xfs_inactive` guard reading raw
  `mxfs_dbg_disk_di_mode` while nlink used the coherent variant) and
  `P-IFR-AGI-STALE` both stayed at zero
  ([[ccloop-c7ee71c6-sess47-TAIL4-findingB-seed]],
  [[ccloop-c7ee71c6-sess47-TAIL5-381-findingB-armed]]).
- **Buffer-scoped gating** — the 0.11.382 non-destructive gate
  (`DELWRI || pinned || bli-dirty || uncheckpointed`) recurred with
  **refused=0**: at install time the buffer had no local unhomed markers at all.
  **Lesson: a defense scoped to the buffer cannot close a bug whose path crosses
  a full buffer teardown. Only MOUNT-level state survives**
  ([[ccloop-c7ee71c6-sess47-TAIL8-382-gate-shipped-gpt-ruling]],
  [[ccloop-c7ee71c6-sess47-TAIL9-382-gate-insufficient-ledger-term-missing]]).
- **Install-site chasing** — three hooks in, still ~1 fatal/2 cycles. The chase was
  not converging; the discriminator experiment was what broke it
  ([[ccloop-c7ee71c6-sess47-TAIL16-385-unhooked-fill-audit]],
  [[ccloop-c7ee71c6-sess47-TAIL18-386c2-media-vs-transit]]).

## The A-prime store, v1→v5 (each version's hole)

A mount-level typed ledger of committed-but-not-home iunlink values. **P220's
pend/dur/flush could NOT be reused** — those are `ip->i_mxfs_pub_*_seq`,
per-`xfs_inode`, destroyed at reclaim, and every victim is a reclaimed zombie
([[ccloop-c7ee71c6-sess47-TAIL11-aprime-needs-new-mount-store]]).

| ver | build | change | hole that killed it |
|---|---|---|---|
| v1 | 383 | record@precommit, retire@write-completion, overlay@2 installs | completion ≠ durability on LIO; retired records + stale platter → 0 overlays at the fatal |
| v2 | 384 | two-phase retire: stamp `wr_epoch` at completion, drop only after flush-epoch advances | drop-on-gen-mismatch destroyed live coverage — `rec_gen=img_gen+1` means the *platter* is pre-reuse stale, and ordering is undecidable with randomized `di_gen` |
| v3 | 385 | GENDROP → **GENSKEW keep-and-skip**: never graft cross-incarnation, never drop | ≥1 install path still unhooked (readahead/reverify branch) |
| v4 | 389-390 | **install site 4 = WRITE side** (overlay outgoing payload in `xfs_buf_submit` before `xfs_buf_verify_write`) + payload-verified retire | gen-mismatch-stamps-retire rule was wrong for `nu` (see root #2) |
| v5 | 392 | AG-**tenure**-scoped records (`purge_ag` before all 4 `mxfs_v5_dlm_ag_unlock` sites) + LIVESKEW refusal via RCU peek of `pag_ici_root` | — |

GPT's binding constraints throughout: typed records carrying
{ino, gen, ownership epoch, committed value} retained until HOME completion;
overlay = 4-byte graft **+ `xfs_dinode_calc_crc` + full verify**, gen-equal only;
counts alone (`pend>flush`) may only REFUSE, never graft; `(ino,gen)` is unsound
cross-tenure because `nu` has no ordering and gen is not an nu-version; grafting
against a disagreeing live in-core edge is itself a corruption vector
([[ccloop-c7ee71c6-sess47-TAIL12-383-aprime-shipped]],
[[ccloop-c7ee71c6-sess47-TAIL13-two-phase-retire]],
[[ccloop-c7ee71c6-sess47-TAIL15-385-v3-genskew-keep]],
[[ccloop-c7ee71c6-sess48-v5-tenure-scope-and-c2-392-open]]).

**The machinery was proven sound early**: 0.11.384 cycle 1 produced 13
`P-IUNLSTORE-OVERLAY` corrections fleet-wide with P53=0 — specimen
`img_next=0xf4 committed=0xffffffff`, the exact fossil shape of all four prior
fatals, intercepted before install. What remained was coverage, not concept
([[ccloop-c7ee71c6-sess47-TAIL14-384-overlay-proven-live]]).

## The five install sites

1. `read_map` cold-fill completion (`pal/linux/xfs_buf.c` ~1516, the
   `P-INOCL-COLDREAD` site) — pinned as the first install vector by a
   COLDREAD 120ms before the P53 on the same AG chunk
   ([[ccloop-c7ee71c6-sess47-TAIL10-install-site-coldfill]]).
2. `mxfs_buf_coherent_reread_verify` pre-install.
3. `read_map`'s "already read" **reverify** branch — readahead-filled buffers whose
   bio completes with no ops and never passes the cold-fill hook
   ([[ccloop-c7ee71c6-sess47-TAIL17-386-site3-cycle1]]).
4. **Write side** — `xfs_buf_submit` before `xfs_buf_verify_write`.
5. After the `mxfs_iflush_cluster_merge_dirs` merge loop (root #1's fix).

## Root #1 — the in-core fossil reverter (fixed 0.11.391)

`xfs_inode.c mxfs_iflush_cluster_merge_dirs`, running from xfsaild under the
buffer lock, had two `memcpy(dbuf, ddisk, inodesize)` arms (DEADINCARN + restore)
that installed the coherent-disk image wholesale and restored the buffer's `nu`
**only `if (bli_dirty)`**. `bli_dirty` is buffer-level: after checkpoint the BLI
detaches, so `bli_dirty==0`, so the platter's pre-write `nu` was installed in-core
and xfsaild then destaged the fossil. This matches the `P-IUNLSTORE-WRSITE`
specimens exactly (`pin=0 delwri=0 bli=0 in_ail=0 comm=xfsaild`).

Two latent defects in the same lines: the restore did **no CRC recompute** — and
`nu` **IS** inside the `di_crc` region (the old sess44 comment saying otherwise is
wrong; upstream `xfs_iunlink_update_dinode` recomputes every time) — and a
buffer-level flag could restore OUR stale `nu` over a FOREIGN slot's fresher
value. Fix: both save/restores removed, replaced by install site 5
([[ccloop-c7ee71c6-sess48-CLMERGE-ROOT-PROVEN-site5]]).

Predicted at the shape level a session earlier: the per-slot merge preserves only
slots with **attached inode log items**, and an iunlink `nu` write is a
*buffer-log* change on a slot whose in-core inode was reclaimed — so the merge
preserved nothing for it ([[ccloop-c7ee71c6-sess47-TAIL7-ROOT-SHAPE-merge-misses-iunlink]]).

## Root #2 — the reuse-carried fossil (fixed 0.11.394)

`P-IUNLSTORE-QUERY` at P53 time reported **NO-RECORD, store count=0** — the store
was empty, so overlay had nothing to graft. Mechanism:

1. A prior incarnation's remove committed; its home write was lost.
2. The ino was freed and **reused**; create → iflush stamps a new `di_gen` around
   the slot — **iflush never writes `di_next_unlinked`**.
3. The fossil chain value now sits under a *current* gen, and **every gen-keyed
   defense goes blind**. v4's "gen-mismatch ⇒ hazard extinguished ⇒ retire" rule
   was actively wrong: **`nu` is SLOT state that rides across the gen bump**, not
   incarnation state.
4. Next unlink of the reused ino: INSERT expects NULLAGINO, finds fossil → fatal.

Fix: `P-CREATE-NUFIX` in `xfs_inode_init` (`libxfs/xfs_inode_util.c`, multi-node
only). A just-allocated ino provably cannot be on any unlinked list, so a non-NULL
`nu` is a fossil **by proof** — clear it + `xfs_dinode_calc_crc` +
`xfs_trans_inode_buf` + 4-byte `xfs_trans_log_buf` inside the create transaction.
Kills the whole family regardless of which write was lost. O_TMPFILE-safe
([[ccloop-c7ee71c6-sess48-REUSE-FOSSIL-ROOT-createfix]]).

## The experiment that broke the deadlock

Rather than add a fourth install hook, an in-kernel discriminator
(`mxfs_iunl_discrim`) A/B-read the cluster sectors at first overlay mismatch —
PLAIN bio (target-cache view) vs SCSI FUA (media view) — and printed both plus
`wr_epoch`/`flush_epoch`. All 10 specimens: **WRITE-NOWHERE-IN-TARGET**, committed
value absent from cache *and* media, with `wr_epoch` **STAMPED**. So a covering
write had completed and **carried the fossil itself**. That killed the
transit/FUA-read theory outright (candidate fix F would have done nothing), killed
target-loss, and named retire-on-mere-completion as the reason 386 was failing
every other cycle ([[ccloop-c7ee71c6-sess48-DISCRIM-verdict-and-v4]]).

**Method lesson: when hook-adding stops converging, build the discriminator.**

## Durable lessons

- Mount-level state is the only thing that survives buffer teardown and inode
  reclaim. Design defenses at that scope from the start.
- `di_next_unlinked` is slot state, not incarnation state — no gen-keyed scheme
  can protect it across reuse.
- Completion ≠ durability on this LIO stack; and a completed write can be the
  *carrier* of the corruption, not just a victim of losing it.
- Inode clusters are **shared-grain** (32 dinodes, peers update siblings). Refusing
  a disk read the way P61 does for bmbt was proven harmful for AGI in sess122 and
  is not the right shape here. Per-slot merge or ledger-scoped overlay only.
- An idempotent carve-out that absorbs a corruption is a masking device. Count
  every absorbed event; post-fix they become the regression detector.
- The overlay∘pipeline composition produces a benign *inverse* P53
  (`old_ptr=NULL, next=NULL`) when the overlay installs the latest committed value
  while an earlier in-flight item expects an intermediate one. Tolerated and
  instrumented; revisit only if it ever appears non-absorbable.

## Tooling and soak protocol

`tests/iunl_soak_sweep.sh <mark> [n]` — single awk pass per node, counts
P53/OVERLAY/WRSITE/FOSSILWR/RELLEAK/AGPURGE/LIVESKEW. Stamp
`echo 'MXFS-SOAK-MARK <m>' > /dev/kmsg` per node each cycle; the kmsg ring rotates
marks out in hours, so sweep promptly.

Cycle = `run.sh 32 caw rsync_paired` → idle 250s → lap again → sweep → matrix
(`tests/openunlink_matrix.sh`) every ~2 cycles + reap-repro guard at deploy.

Standing alarms, any of which is a regression: same-gen `FOSSILWR`, `WRSITE`
(another reverter exists), `LIVESKEW`, mid-run `RELLEAK`, `P53` fatal shape.
`AGPURGE-ALIVE` absent ⇒ releases are bypassing the four purge hooks.

Discrim's FUA leg is gated off under `mxfs_fua_disable` (fleet default): site 5
runs in xfsaild under the buffer lock, which is the sess113 forced-FUA drain-wedge
vector. Plain-only verdicts there.
