---
name: ccloop-c7ee71c6-sess40-END2-slot-struct-regression-and-full-green-board
description: sess40 END2: cluster shutdowns root-caused to MY OWN 333 struct-padding regression (on-disk slot grew past 512); fixed in 341 + unconditional size as…
metadata:
  type: project
---

# sess40 END2 — the cascading shutdowns were MY regression. 0.11.341, full board green.

## THE LESSON OF THE SESSION (read this before anything else)
I added `uint64_t open_holders` to `struct mxfs_caw_lock_slot` in 0.11.333 **after a uint32 field**. The compiler inserted 4 bytes of alignment padding and the struct grew past its **512-byte ON-DISK** size. `find_slot` reads up to 16 slots at once and indexes that buffer **as an array of that struct**, so every slot past the first in a window decoded from the wrong byte offset.

Consequences, all of which I initially misattributed:
- shifted image → unrecognised magic → `slot_appears_corrupt()` returns false for any non-LIVE magic, so **nothing re-read it**;
- find_slot classified it "truly empty" → **terminated the probe chain**, hiding live slots (this is why census showed `slot LIVE hex!=0 waiters=0` while every requester was in claim-empty);
- and that same image became the **claim CAS compare** → could never match → retry exhaustion → `-110` → `SHUTDOWN_CORRUPT_INCORE` → 10-32 nodes cascade.

**MY REASONING ERROR, RECORDED SO IT ISN'T REPEATED:** I ran a same-build A/B with `mxfs.open_tracking=0`, saw the control arm fail identically, and concluded the defect "predates this work". **A knob A/B can only exonerate code the knob actually disables.** `open_tracking` gates *behaviour*; it cannot gate *struct layout*, so both arms carried the broken 520-byte slot. I filed a wrong "ruled_out" line in the ledger on that basis; it is now retracted in place.

**WHY IT SHIPPED SILENTLY:** the size check's kernel arm was a macro, `MXFS_BUILD_CHECK_CAW_SLOT()`, that **nothing ever invoked** (grep: zero call sites). Kernel builds had no size assertion at all. Now an **unconditional `_Static_assert`** at the point of definition — no call site needed, fires in every build. Any future field that breaks the on-disk size fails the build.

**RULE FOR THIS TREE:** `struct mxfs_caw_lock_slot` is an on-disk sector image. Never add a field without an explicit pad keeping natural alignment AND total size 512 (`uint32_t pad4` now sits before `open_holders`, `reserved[352]`).

## What actually found it
P94-SPAN-DISAGREE's byte dump: `span16=d4ec3a45acfcd7e69407a00200000000` vs `fresh16=4c44584d02000000d4ec3a45acfcd7e6` — same index, microseconds apart. `fresh[8..] == span[0..]`: shifted by exactly 8. Chain of diagnostics that got there: P91-CLAIMEXH (base/insertion point/target content/bounded re-probe) → P92-CLAIMCAS (byte-diff of the CAS compare buffer vs a fresh read: `cmp[magic=b4bc1b3d] disk[magic=4d584357] first_diff=0 fresh_read_skipped=1`) → P93/P94. **kzalloc zeroes the buffer, so garbage bytes could not be uninitialised memory — that ruled out a short read and pointed at decode offset.** All four probes retained and armed.

## Hardening kept (correct independently of the root)
- 336: claim-race **wall-clock deadline** instead of a bare 100-count (the unlock path's shipped pattern).
- 337: **always read the claim target fresh** before the CAS (the `last_read_idx == empty_idx` skip could feed a span artifact to the compare); **only a ZERO magic terminates the probe** — any other unrecognised magic is re-read per-slot, and if still unrecognised is recyclable but never a chain terminator (P93).
- These contained the damage while the true root was being found, and make the paths robust to any future unreadable image instead of turning it into a filesystem shutdown.
- Still-open hardening idea: `mxfs_dlm_ilock_begin` escalating a transient acquire timeout to `SHUTDOWN_CORRUPT_INCORE` is a blunt response; a claim timeout should surface as an error, not a cluster-wide shutdown.

## Board state — 0.11.341, 32/caw, fresh prep: ALL 22 CRITERIA PASS
precond_readiness, fio_perf, cache_coherency 654/654, strong_consistency, zero_silent_loss 644/644, scaling_curve, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, dlm_scaling, dirent_durability (30r loss=0), dirent_publish_integrity, crash_consistency 22s/90s, fence_during_write, fault_netpartition, soak, node_responsive, kernel_health, ag_strand_repair, sustained_load, dlm_lock_correctness, dirent_type_integrity, **dir_reuse_coherency 58/58 104s**. Plus tests/openunlink_probe.sh PASS and tests/agi_bucket_repro.sh no-corruption.
Zero P94/P93/unrecoverable events fleet-wide after the fix (41-91 span disagreements per node per run before it).

## Harness note (do not misread)
`agi_bucket_repro.sh` may print `REPRO=RELOAD-ONLY`. Since per-slot buckets (332) a node only walks its OWN bucket, so an **owner-local** P83 reload is expected and benign — it re-stitches a zombie of its own that was evicted from cache. Deferred-reap zombies (333+, P87-OPEN-DEFER) live in the owner's bucket while a peer keeps the file open, making owner-local reloads *more* likely. The defect signature is a reload whose `node_slot` does **not** own the bucket, or any corruption count. The harness now prints this explanation itself.

## 8 OPEN
D-FOREIGN-REPLAY-UNGATED-IMAGES, D-MATRIX-UNMEASURED, D-32NODE-SHARED-DIR-CREATE-PACE, D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-READDIR-PEER-CACHED-DIR-PACE, D-DIRVIEW-NONCONVERGE-SESS25, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (runtime+mount arms fixed; open-tracking coordinator shipped; GPT's 10 invariants + survivor sweep remain), D-CROSSNODE-OPEN-UNLINK-DATA-LOSS (fix shipped+verified; closure needs GPT's 9-case matrix incl. owner death, opener death, mmap, O_TMPFILE/linkat, slot reuse).
