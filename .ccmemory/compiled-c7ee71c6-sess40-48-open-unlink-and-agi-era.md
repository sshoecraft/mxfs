---
name: compiled-c7ee71c6-sess40-48-open-unlink-and-agi-era
description: Compiled: c7ee71c6 sess40-48 (0.11.331-394) — AGI per-slot buckets, open-tracking/deferred reap, the 512B slot regression, version gate, P195 closure…
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , a, g, i, -, u, n, l, i, n, k, e, d, ,,  , o, p, e, n, -, t, r, a, c, k, i, n, g, ,,  , o, p, e, n, -, u, n, l, i, n, k, ,,  , c, a, w, -, s, l, o, t, ,,  , v, e, r, s, i, o, n, -, g, a, t, e, ,,  , P, 1, 9, 5, ,,  , f, l, a, k, e, -, f, o, r, e, n, s, i, c, s, ,,  , r, e, a, p, -, i, f, r, e, e]
---

# c7ee71c6 sess40-48 — the open-unlink / AGI era (0.11.331 → 394)

## 1. D-AGI-UNLINKED — root proven, then fixed structurally

**The session tool that made it tractable:** `tests/agi_bucket_repro.sh` — pair/chain phases,
two nodes, ~40s. Held-open unlinked fds become persistent zombies; **congruent inos (same AG,
`ino ≡ mod 64`) force cross-node bucket adjacency on demand**.

A discovery en route that reframes the whole class: **mxfs shards inode ALLOCATION per node
across AGs**, so cohabitation never comes from concurrent creates — it comes from **unlinking
peer-created files** (any shared-tree `rm`). The pool must be created by ONE node to reproduce.

**Root (design-level):** `i_prev_unlinked` is **in-core-only state mirroring a cluster-shared
on-disk list**, and the peer that mutates the list updates it only in ITS icache. Both upstream
premises — "all members are in-core" and "not-in-core ⇒ abandoned orphan to free" — are false
cross-node. Failure shape: B's insert faults A's live zombie in and BASTs A off its own
open-unlinked EX; A's close then hits a head-mismatch with a stale self-view
(`prev=NULLAGINO`, "I am head") → `xfs_iunlink_lookup(NULLAGINO)=NULL` → -EFSCORRUPTED →
shutdown ([[ccloop-c7ee71c6-sess40-AGI-root-proven-slot-buckets-shipped]]).

**Fix: per-slot AGI buckets** (`mxfs.iunlink_slot_buckets`, cluster-uniform only) — each node
owns its own bucket, so mount recovery scopes to it. **Key collapse: slice index == disklock
slot, so an adopted slice's dead-owner bucket IS the claimant's own bucket** and is already
swept. Same-build A/B: knob=1 pair+chain CLEAN, knob=0 reproduces -117 + withdrawal.
Also shipped: `MXFS_IF_FREE_COMMITTED`, set only at *committed* ifree, because **"inactivation
skipped ≠ inode freed"** (GPT).

## 2. Open-tracking and deferred reap (D-CROSSNODE-OPEN-UNLINK-DATA-LOSS)

A peer's unlink was truncating and freeing a file another node held open — a live fd read 20
bytes of zeros. The design as built, with **two measured redesigns that must not be regressed**
([[ccloop-c7ee71c6-sess40-END-open-tracking-shipped-and-claim-exhaustion-found]]):

- `open_holders` uint64 bitmap inside the CAW slot's reserved area. Tombstones preserve it,
  same-resource claims inherit it, fencing strips dead nodes' bits, slots with open bits never
  tombstone.
- **PUBLISH ON THE BAST-RELEASE CAS, NOT PER `open()`.** Per-open CASes bumped generations on
  hot slots and starved real acquires — 32 nodes × ~20k opens → `ea_claim=100` → rc=-110 →
  `SHUTDOWN_CORRUPT_INCORE`, 234/644 checks lost. BAST release is the only moment a peer's
  destructive path can be imminent, so publishing there is both sufficient and rare.
- **CLEARS MUST BE GATED on `i_mxfs_open_pub`.** Ungated, evict and unlinked-exit ran a full
  slot probe (SCSI reads) for *every* inode → 440/644. With the gate: 644/644.
- **Reap entries must carry the defer-time authority snapshot** and restore it after the
  generation match — a fresh iget has neither, and the no-authority guard then blocks the
  owner's own reap forever (measured: retried at 30s cadence indefinitely).

**GPT's audit found two holes the in-house G1-G6 audit missed** — chiefly **OPEN-AT-NL**:
`open()` can complete from dcache with the inode at NL, so no grant exists, the peer's EX draws
no BAST from us, nothing publishes, and the file is freed under our live fd. *"Open implies
grant history" is not "open implies current grant or bit."* Fixed by C3 (`mxfs_dlm_open_protect`
in `xfs_file_open`, fail-closed) plus C1/C2/C4/C5/C10
([[ccloop-c7ee71c6-sess41-gpt-openunlink-audit-ruling]],
[[ccloop-c7ee71c6-sess41-343-safety-set-shipped-trunc-defect-fixed]]).

Three leak roots were burned down to make the death cases pass — dentry pin, flag-strip-by-
reload, stale cached nlink — plus an `opener_death` root where the purge skip predicates missed
`open_holders & dead_mask`, so a dead opener's bit was never stripped and the defer was eternal
([[ccloop-c7ee71c6-sess41-END-349-deaths-pass-multiopener-eio-open]]).
For TCP, GPT ruled **hybrid**: keep the bits in the CAW disk slots (they exist regardless of
transport) and replace the atomic release-CAS with strict **ordering**
([[ccloop-c7ee71c6-sess44-C9-tcp-open-tracking-gpt-design]]). The ICLUSTER port later reached
matrix 9/9 at both knob settings ([[ccloop-c7ee71c6-sess46-routed-opentrack-matrix-9of9]]).

## 3. THE LESSON OF THE ERA — a 4-byte pad took the cluster down

`uint64_t open_holders` was added to `struct mxfs_caw_lock_slot` **after a uint32 field**. The
compiler inserted 4 bytes of alignment padding and the struct **grew past its 512-byte ON-DISK
size**. `find_slot` reads up to 16 slots at once and indexes that buffer as an array of the
struct, so every slot past the first decoded from the wrong offset →
unrecognised magic → `slot_appears_corrupt()` returns false for non-LIVE magic so nothing
re-read it → find_slot classified it "truly empty" and **terminated the probe chain** → the
same image became the claim CAS compare → retry exhaustion → -110 → cascade of 10-32 node
shutdowns.

**The reasoning error, recorded so it is not repeated:** a same-build A/B with
`mxfs.open_tracking=0` failed identically, and that was read as "the defect predates this work."
**A knob A/B can only exonerate code the knob actually disables.** `open_tracking` gates
*behaviour*; it cannot gate *struct layout*, so both arms carried the broken 520-byte slot.

**Why it shipped silently:** the size check's kernel arm was a macro that **nothing ever
invoked** (grep: zero call sites). Now an unconditional `_Static_assert` at the point of
definition. **RULE FOR THIS TREE: `struct mxfs_caw_lock_slot` is an on-disk sector image —
never add a field without an explicit pad keeping natural alignment AND total size 512**
([[ccloop-c7ee71c6-sess40-END2-slot-struct-regression-and-full-green-board]]).

## 4. "Last week green, now half the tests DON'T WORK" — answered with evidence

User question, sess43. **Answer: the filesystem did not regress.** The board ran ~11× in one
day (vs occasionally before), a flake-HISTORY display had just been added, and **that display
counted RIG failures as test flakes**. 9 of 14 "FLAKY" rows were rig; 5 were genuine and each
got attributed ([[ccloop-c7ee71c6-sess43-flake-forensics-and-harness-truth-fixes]]).

**Three harness truth-bugs were manufacturing or hiding flakes**, the worst being: `run.sh`'s
history push **dropped the `reason` field**, so the moment the next run overwrote a cell the
evidence vanished — *that* is why D-DIR-REUSE sat "UNROOTED: which check failed is not yet
captured" for whole sessions. Also: the reconvergence gate demanded a lease beacon
`active_count==N`, but a dead identity lingers in the lease for 10 minutes, so a healthy
cluster read as "did not reconverge."

**User directives from that exchange, now standing policy:** FLAKY must STAY for genuine
test-detected failures — never relabel to PASS; infra-caused history exclusions are fine;
**"flaky and production don't mix"** — every flake needs a ledger defect and a root-cause fix,
and **aging out is not closure** ([[ccloop-c7ee71c6-sess43-353-orphan-closure-and-flake-rulings]]).

## 5. Defects closed in this era

- **D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER**: `xfs_shutdown_devices()` ends with an
  unconditional `blkdev_issue_flush()` (inherited upstream, for bdev-pagecache coherency) and
  it ran AFTER the deferred SCSI-PR unregister — so **every clean unmount of a PR-protected LUN
  ended in a failed Synchronize Cache**. Fixed by moving the unregister after
  `xfs_shutdown_devices` (which flushes and invalidates but does not release the buftargs, so
  `bt_bdev` is still valid) ([[ccloop-c7ee71c6-sess43-354-prflush-closed-gate-fixed]]).
- **C7 version gate** — three independent enforcement layers (XFS sb INCOMPAT bit, envelope
  flag + `cluster_proto_gen`, and a heartbeat feature block whose CRC binds fs_gen+node_id+epoch)
  with an offline `chk_mxfs --upgrade-protogate` path, all six arms verified
  ([[ccloop-c7ee71c6-sess42-END-c7-shipped-orphan-defect-found]]).
- **D-DESTAGE-TEAR-BUCKETLESS-ORPHAN** (358) — closed against a GPT gap-review that demanded
  boards on the final build, stale-holder fencing, deferred-open liveness, ABA review and
  crash-of-repair treatment; four live race arms at 32 nodes
  ([[ccloop-c7ee71c6-sess44-DESTAGE-TEAR-CLOSED-358-boards-green]]).
- **D-REAP-WORK-UAF-PANIC** and **D-OUTAGE-REMOUNT-MUTUAL-IFREE-SKIP-STRAND**
  ([[ccloop-c7ee71c6-sess44-END-reap-uaf-panic-found-13-open]]).
- **D-DIRENT-PUBLISH-STALE-BASE-P195** — closed with GPT's Option B (adopt-at-EX-acquire,
  explicit `i_dlm_base_valid` with acquire/release ordering). 24 aged loops predicted ~3 hits
  and got 0 ([[ccloop-c7ee71c6-sess45-P195-CLOSED-361-option-b-shipped]]).
- **D-CACHE-COHERENCY-UV-COUNT-MISS — DISPROVED**, by an accident: three deliberate attempts to
  land a mid-body mount drop failed, then a watcher believed dead fired its 180s `umount -l`
  with *perfect* incident ordering, reproducing the `uv exp=128 got=124` signature exactly from
  one degraded member ([[ccloop-c7ee71c6-sess45-UV-COUNT-MISS-DISPROVED-degraded-member]]).
- **D-REAP-IFREE-EFSCORRUPTED-372** — root proven by a 40s deterministic repro: zombies parked
  on a slot bucket → memory pressure reclaims the shells, destroying
  `i_prev_unlinked/i_next_unlinked/i_unlinked_bucket` → the reap worker igets fresh shells
  (prev=0) and reaps in **defer order = insertion order = chain TAIL** → mid-list branch →
  `xfs_iunlink_lookup(prev=0)=NULL` → **silent -EFSCORRUPTED, the only printless exit** (now
  named P-UNLREM-NOPREV). The authority flag is stripped again by the inactive-side reload, so
  **the fix must key off the bucket**, which survives
  ([[ccloop-c7ee71c6-sess47-REAP-IFREE-117-ROOT-PROVEN]], [[ccloop-c7ee71c6-sess46-REPRO-117-ring-captured]],
  [[ccloop-c7ee71c6-sess47-fence-shipped-soak-running]], [[ccloop-c7ee71c6-sess47-END-372-closed-fence-shipped]]).
  A **variant** decoded separately: a pre-ifree revalidation TOCTOU reading a **stale in-core
  AGI** (`agi_disk_differs=1` at failure) → later coherent read saw empty → P71 → -117. Fixed
  by deciding on the disk-side AGI when the images diverge (379), then refined (380) to
  **discriminate divergence direction** — dirty/pinned/DELWRI means *we* own the delta so trust
  in-core; clean-but-divergent means prior-tenure fossil so trust disk. Fire rate went
  584 → 0 new through a full matrix, proving the earlier storm was entirely the dirty case
  ([[ccloop-c7ee71c6-sess47-TAIL-372-variant-gate-miss]], [[ccloop-c7ee71c6-sess47-TAIL2-379-deployed]],
  [[ccloop-c7ee71c6-sess47-TAIL3-379-direction-refinement]]).

**Found and contained, not closed:** D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN — 17 of 32 nodes
hit an *independent* dirty `xfs_trans_cancel` in `xfs_rename` under rsync within ~20 seconds
(identical first-error lines; **not** a cascade), on a build that had passed rsync_paired 3×
earlier the same day ([[ccloop-c7ee71c6-sess45-rsync-rename-shutdown-362-containment]],
[[ccloop-c7ee71c6-sess45-END-two-closed-one-opened-362-lapping]]).

## 6. Self-caught bugs (both before any closure was claimed)

- **The guard clock bug.** The recovery GUARD's staleness test compared `mxfs_pal_time_ms()`
  (each node's own **uptime**) against the record's timestamp. Across nodes with different
  uptimes — the normal case — a FRESH guard computes a delta of hours and reads as stale, so
  peers would claim a guarded slot mid-sweep: **the cluster-visible exclusion GPT ruled
  mandatory was not actually in force.** Exactly the trap `tests/hb_live_count.sh` documents
  (HB timestamps are comparable only to themselves) — written hours earlier by the same session
  and not applied to its own kernel code ([[ccloop-c7ee71c6-sess43-END-355-guard-clock-bug-selfcaught]]).
- A B-side EIO was hunted across 5 faithful replays and **not reproduced**; two theories
  (zapped-fork, open_protect fail-closed) were eliminated by code+rig evidence rather than
  assumed away, and a P-LKERR tripwire was shipped instead of a guess
  ([[ccloop-c7ee71c6-sess42-lkerr-tripwire-350-eio-hunt]]).

## 7. Pace and measurement discipline

Round decomposition via `tests/drc_phase_census.py` (all 32 nodes' DRCph markers, not 2 logs):
round wall median 9.16s — creates+barrier ≈ 68%, write-barrier skew wait 25%, 64 dir-EX turns
per round. The grace lever was **REFUTED**, and **host load was proven to modulate pace**
([[ccloop-c7ee71c6-sess43-pace-decomposition-and-hostload-confounder]]).

**The arithmetic trap that cost half a session:** `dir_reuse_coherency` checks are
`3/round + ~27-30 FIXED checks`. "58 checks" is **eight rounds** (floor is ≥8, i.e. ZERO
margin) — not 58/3=19. Misreading it produced a phantom "3× regression" that was mostly load
noise on a zero-margin row ([[ccloop-c7ee71c6-sess46-knob1-pace-recalibration]],
[[ccloop-c7ee71c6-sess46-END-matrix-green-both-configs-new-117-defect]]).

**Rig mechanics that look like filesystem defects** — `run.sh` runs a **SEQUENTIAL 32×15s mount
preflight** before any test output, so under load the preflight alone takes 100-480s. An outer
timeout below **580s** kills run.sh mid-preflight → no cleanup → leftover processes → the next
lap is slower → spiral. Clyde is co-tenanted (Wow.exe ~390% CPU, worldserver, other Claude
sessions); load waves of 80-190 recur every 10-20 minutes and starve all 32 guests —
`NO_TERMINAL_RECORD=32 at hostload=178` is **environmental, not an mxfs defect**. Gate each lap
on load<45. Never kill the co-tenant processes
([[ccloop-c7ee71c6-sess48-rig-lap-budget-and-cotenant-waves]]).

**Standing rule from this era:** on any shutdown, `dmesg > /root/<tag>.dmesg` **before**
recovery. And because dmesg persists across module reloads and inode numbers are reused, every
detection must be **count-growth**, never line-exists.
