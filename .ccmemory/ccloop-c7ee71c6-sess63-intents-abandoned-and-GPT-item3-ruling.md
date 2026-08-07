---
name: ccloop-c7ee71c6-sess63-intents-abandoned-and-GPT-item3-ruling
description: sess63: PROVED a dead node's journal intents + iunlink obligations are processed by NOBODY (adopted-slice mount skips them too) + GPT's binding desig…
metadata:
  type: reference
tags: [foreign-replay, recovery, intents, item3, gpt-ruling, defect, step4, in-progress]
---

# sess63 — GPT item 3 is a hard defect, and GPT ruled the whole protocol

No build this session (tree stays **0.11.407**, srcversion `C72F20487083A2CA52AC43C`).
This was a proof + design session. **STILL DO NOT BOARD.**

## The proof (line-verified, do not re-derive)

`mxfs_xlog_recover_foreign_slice()`'s header comment justifies skipping intents
with "the slice is left dirty, so the next mount-time claimer performs full
replay including intents". **That premise is false.**

- `xfs/xfs_log.c:628-632` — a PASS-2 (fresh) disklock claim sets
  `m_mxfs_slice_adopted` → `XLOG_MXFS_ADOPTED_SLICE`. A slot that was
  published-recovered is in EXACTLY that state (`mxfs_disklock_purge_node`
  zeroed its stamp), so **the next claimer is ALWAYS an adopted-slice mount.**
- `xfs/xfs_log_priv.h:526-531` — `xlog_is_mxfs_untrusted_replay = FOREIGN ||
  ADOPTED`; both share every skip.
- `xfs/xfs_log_recover.c:2224-2244` — EFI/EFD and RUI..CUD_RT `continue`
  (P226-UNTRUSTED-INTENT-SKIP) under that predicate.
- `xfs/xfs_log_recover.c:3679-3682` — foreign replay returns before
  `xlog_recover_finish()` ever runs; `xfs/xfs_log.c:797-802` `kfree`s the
  shadow AIL undrained.

⇒ **Nobody ever processes a dead node's intents or its AGI unlinked bucket**,
and the slot is still published as consumable. Ledger entry
**D-FOREIGN-SLICE-INTENTS-ABANDONED** (critical, OPEN) written with the full
evidence chain. Ledger: 42 entries, **14 open**.

Second measured fact: the TRANSACTION-ATOMIC SKIP (`xfs_log_recover.c:2181`,
default knob `foreign_replay_untagged_apply=0`) taints on ANY
BUF/DQUOT/QUOTAOFF/ICREATE item — i.e. essentially every metadata transaction.
**Foreign/adopted replay today applies almost nothing but pure-inode
transactions.** That is why the board is green over this path.

Third: `mkfs_mxfs.c:789-792` sets ro_compat = FINOBT only ⇒ **reflink and
rmapbt are OFF** on MXFS-formatted volumes. GPT still refused to let that
excuse ignoring BUI (see below).

## GPT RULE-5 ruling (binding; full text in the sess63 transcript)

- **Milestone state machine, not a stage byte**: `ACTIVE → GUARD{FENCED,
  IMAGES_REPLAYED, OBLIGATIONS_DONE, GRANTS_RELEASED} → CONSUMABLE(zeroed)`,
  carrying victim slot + victim incarnation + fs_gen + recovery generation +
  recovery-owner slot/boot epoch + slice identity + stage + version/crc.
  **Never overwrite victim identity with the recovery holder's.**
- **Ordering is fixed and my D2 was wrong**: CAS `ACTIVE→GUARD(FENCED)` must be
  durable BEFORE any CAW purge. Purging first is a crash hole — HB still reads
  ACTIVE while half the recovery evidence is gone.
- **The peer broadcast predicate must split.** "Slot no longer ACTIVE" today
  means both "victim fenced" and "victim grants released"; the first GUARD
  transition would otherwise tell peers to drop deliberately-frozen grants.
- **A stale GUARD may be taken as a RECOVERY LEASE but never as a member slot**
  — no ACTIVE, no fresh journal over the victim slice, no mounting on it, until
  CONSUMABLE. Strictly stronger than the sess43 AGI-sweep GUARD.
- **Intent policy = option (b)** (complete directly from the recovery context),
  **NOT (c)** (re-log as our own). HB stage and the live log are separate
  durable domains with no atomic commit between them: crash after logging the
  replacement EFI but before recording adoption ⇒ double free; reverse order ⇒
  lost obligation. `xfs_free_extent_later()` is not sufficient (no
  deduplicatable source-intent identity; defer may execute during commit/roll).
- **My intent/done matching rule was ruled UNSOUND.** Correct table:
  intent admitted + done admitted → cancel; admitted + done absent → recover;
  intent rejected → quarantine; **admitted + done REJECTED → AMBIGUOUS,
  quarantine, never guess** (honouring it suppresses unreplayed work; ignoring
  it double-frees metadata that did reach home).
- **Late completion is EFI-only.** RUI/CUI do not inherit the parked-extent
  argument (later alloc/unshare/COW/free consume that state); BUI definitely
  not. Support BUI or quarantine the slice — "reflink is off" is not a reason.
- **AGI sweep**: `nlink==0` does NOT prove no peer has the inode open. Needs
  distributed inode authority + remote-open state + AGI/bucket authority; a
  local `iget` is not a proof. (Links to D-CROSSNODE-OPEN-UNLINK-DATA-LOSS.)
- **Purge-then-reacquire of victim AG grants is forbidden**: needs atomic CAS
  transfer to the recovery owner with no unowned interval, an adoption mode, or
  a cluster metadata freeze.
- **D5 (item 4) ruled directionally correct**: move `settle_own_slot` after
  `xfs_log_mount_finish` — but that alone does NOT prove absence of the 6A
  deadlock class. Crash-retained locks are an arbitrary prefix of the dead
  incarnation's acquisition order, so `peer holds B waits for our retained A` /
  `we hold A wait for B` is still reachable. Needs a lock-order proof, a cohort
  freeze, or controlled ordered release. Also: `settle_own_slot` must not
  destroy the manifest own/adopted replay validation needs.
- **SEQUENCING (important)**: intent recovery is nearly a no-op until step 5
  (exact-match token gate) — but shipping step 5 FIRST with today's early
  publication is strictly WORSE (more admitted transactions ⇒ more real pending
  obligations ⇒ still finished by nobody ⇒ still published). Order: descriptor
  + freeze → quarantine terminal state → report-only admission + intent/done
  inventory → authority transfer → intent completion → gate swap → final
  release. Step 5 and intent completion must go live in the SAME version-gated
  compatibility epoch.
- Extra defects named: the CAW table is both lock table and authority manifest
  (victim entries must be frozen against purge/repair/reuse/epoch-reset until
  token validation completes); a successor must RESUME from the recorded stage,
  never re-run old images after peers advanced; `mount_cohort_complete`'s
  in-memory `replayed` bitmap cannot be the authoritative resume record —
  per-slot durable progress is required; refresh vs stage-CAS vs takeover vs
  final-zero must be serialized with mandatory reread after CAS failure.

## Next session

Start at step 1 of the sequencing list: the versioned durable recovery
descriptor + victim-manifest freeze in the HB record, with the split broadcast
predicate. Do NOT touch the step-5 gate until it exists.
