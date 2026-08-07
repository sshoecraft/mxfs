---
name: ccloop-c7ee71c6-sess65-recovery-descriptor-c-side-landed
description: sess65: the durable recovery descriptor is LIVE (0.11.409) — begin/advance/refresh/read/takeover + all four freeze sites + the split broadcast predic…
metadata:
  type: reference
tags: [foreign-replay, recovery, descriptor, disklock, step1, in-progress, do-not-board]
---

# sess65 — recovery descriptor .c side landed (0.11.409)

Tree **0.11.409**, srcversion `F696294F7C2ECCE699E08C3` (was 0.11.408 /
`50D0591F24309A58B91BFE4`).  **STILL DO NOT BOARD** — no rig cycle since
0.11.401 and this changes a live death/recovery path.

Both builds clean: kernel `make modules` (only the two PRE-EXISTING
frame-size warnings in `join_gate` / `confirm_dead_mask`, neither touched)
and the user-mode `_Static_assert` branch of `disklock.h`.

## What shipped — step 1 of the sess63 sequencing list, second half

### Parsing layer (`disklock.c`, just above `fs_identity_changed`)

Three predicates, deliberately different in strictness.  **Use the right
one — this distinction is the whole safety argument:**

- `recov_desc_of(hb)` — STRICT.  GUARD flag + descriptor magic + version we
  speak + crc validating against the record's identity triple.  Everything
  that INTERPRETS (stage tests, owner tests, takeover) uses this.
- `recov_lease_covers(hb, node, epoch)` — CONSERVATIVE.  True for any sector
  that even *claims* a descriptor: torn, or a future protocol generation.
  Everything that would DESTROY or REUSE the slot uses this.  A descriptor we
  cannot read freezes the slot rather than being guessed at.
- `recov_desc_names(hb, node, epoch)` — strict identity ("whose slot is
  this?").  A torn descriptor names nobody.

`recov_desc_crc()` copies the `hb_feature_crc` pattern: chains
`crc32c(bytes 0..75)` then the packed `{fs_gen, node_id, epoch}` of the
record header — i.e. the VICTIM's identity, so a descriptor spliced next to
a different victim's header never validates.  The struct is naturally
aligned end to end (asserted in the header), so bytes 0..75 cover no padding.

### The five ops (`disklock.c`, before `set_expire_cb`)

`recovery_begin` / `advance` / `refresh` / `read` / `takeover`, all going
through `recov_cas_durable()` — CAS from the exact observed image,
`-EOPNOTSUPP` → FUA write + cache-piercing readback that memcmp's the
80-byte descriptor, then `mxfs_pal_bdev_flush()`.  A lost CAS is `-EAGAIN`
and is NEVER retried inside: the caller must re-read and re-decide.

`begin` preserves the victim record **byte for byte** (node_id, fs_gen,
epoch, its last timestamp, lock_count, the §7.C mepoch record, the
version-gate feature block); only `flags` changes and the dead evict-ring
bytes become the descriptor.  That is rule 2, and it is also why the feature
block still validates and why the monitor's identity match still fires.

**Design decision worth keeping:** the `victim_epoch` argument to `begin()`
is a CROSS-CHECK ONLY, not a precondition.  The sector is the authority for
which incarnation last owned the slice; `pending_epoch[]` is one survivor's
observation.  Making the observation a precondition would have introduced a
brand-new way for recovery publication to fail permanently.  A disagreement
logs `P234-RECOV-EPOCH-DRIFT` and records the sector's value.

`recov_stamp_after(prev)` guarantees the owner stamp strictly increases —
a stalled or backwards clock must not read as a live owner.

### The four freeze sites (this is the actual defect surface)

1. **Split broadcast predicate** — `hb_still_dead_stamp()` replaces the
   inline test in the monitor at both the first read AND the re-read confirm.
   GUARD-naming-this-victim ⇒ still dead ⇒ deferred purge stays armed.  Only
   the zeroed sector releases it.
2. **`purge_node` phase-0 gate** — the HB scan now runs BEFORE the 65536
   lock-record loop.  Old order destroyed the authority manifest and only
   then discovered it was not allowed to.  Refuses on unreadable descriptor
   (`-EPROTO`), QUARANTINED (`-EPERM`), stage < GRANTS_RELEASED (`-EBUSY`),
   or not-our-descriptor (`-EBUSY`), logging `P234-PURGE-FROZEN`.  The HB
   zeroing arm also matches a GUARD naming the victim — that zero IS the
   CONSUMABLE transition.
3. **`guard_slot` + `slot_unclaimed`** — a descriptor-bearing guard is a
   RECOVERY LEASE, never takeable by the sess43 sweep, *even when abandoned*.
   Both tests are placed BEFORE `hb_guard_abandoned()` deliberately.
4. **`find_node_slot` disk-scan arm** — now matches GUARD-with-descriptor.
   Without it a peer that never witnessed the death resolves slot = -1 and
   falls into `v5_lease_expire_cb`'s "owns no slice → purge immediately" arm.

### Wiring (`v5_mount.c` `mxfs_v5_dlm_recovery_complete`)

`begin(FENCED)` → `advance(IMAGES_REPLAYED)` → CAW purge → flush →
`advance(GRANTS_RELEASED)` → in-memory bookkeeping → `purge_node` (the zero).
`begin() == -ENOENT` (sector already zeroed by another survivor) clears the
pending marker and returns 0 — `P234-COMPLETE-ALREADY`.  Every other
negative return publishes NOTHING and leaves the marker set.
`advance(IMAGES_REPLAYED)` is honest: **both** callers of
`recovery_complete` (`xfs_mxfs_dlm.c:42150` and `mount_cohort_complete`)
run only after a durable slice replay — verified, not assumed.

New plumb: `mxfs_v5_dlm_opts.log_node_count` ← `mp->m_mxfs_log_node_count`
(`xfs_super.c`, set from the envelope at line ~2690, well before the DLM
init at ~3025).  `slice_idx = dead_slot % log_node_count`, matching
`xfs_log.c:769`.  Also added `mxfs_disklock_pending_epoch()`.

## Honest gaps — start here next session

1. **`begin()` runs at recovery-COMPLETE time, not at FENCE time.**  The
   descriptor therefore covers the purge/publish window but NOT the replay
   window: a survivor that dies mid-replay still leaves no durable record.
   Moving `begin()` into `v5_start_slice_recovery` / `v5_defer_slice_recovery`
   is the next increment.  It adds a durable CAS + flush to the heartbeat
   monitor thread's death path — a latency change in a hot path that wants a
   RULE-5 consult before it lands.
2. **`recovery_refresh` and `recovery_takeover` have no in-tree callers yet.**
   They are the abandonment path, which only becomes reachable once (1) is
   done — a recovery that only spans the purge window has no window to be
   abandoned in.  Land them together with (1); do not leave them uncalled for
   another session.
3. No quarantine SETTER exists (only the refusal).  Deliberate: nothing can
   yet detect an undischargeable obligation.  It arrives with the
   report-only admission + intent inventory step.
4. Concurrency note for (1): once two survivors can both be elected, the
   loser's `recovery_complete` gets `-EBUSY` from `begin()` and keeps its
   pending marker until its monitor sees the zeroed sector (≤2s).  That is
   correct but new — watch for `P234-RECOV-OWNED` in rig logs.

Sequencing unchanged after that: quarantine terminal state → report-only
admission + intent/done inventory → authority transfer → intent completion →
step-5 gate swap.  Step 5 must NOT ship before intent completion.
