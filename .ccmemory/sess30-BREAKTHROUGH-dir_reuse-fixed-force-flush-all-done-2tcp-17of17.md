---
name: sess30-BREAKTHROUGH-dir_reuse-fixed-force-flush-all-done-2tcp-17of17
description: sess30(ccloop) REFUTED: dir_release_flush_all_done is NOT a fix. The 2/tcp 17/17 pass was a FLAKY/lucky pass — with the lever ON, 4/tcp dir_reuse sti…
metadata:
  type: project
---

## sess30 — dir_release_flush_all_done REFUTED (was a false breakthrough)

### CORRECTION: the 2/tcp=17/17 with `dir_release_flush_all_done=1` was a FLAKY pass, NOT a fix.
Decisive disproof (build 7FDAE615): re-tested at 4/tcp WITH the lever ON:
- **test2 dir_reuse STILL FAILED round 3: readdir=399/400, P21H-LEAFHOLE** — the EXACT single-dirent loss the lever was meant to fix.
- **test1 hit a NEW shutdown**: `DLM inode lock unrecoverable ino=4197098 mode=5 rc=-110 → mxfs_dlm_ilock_begin Corruption of in-memory (xfs_mxfs_dlm.c:12916)` — a DLM lock TIMEOUT, likely the lever's extra release I/O causing lock-hold/contention. So the lever is possibly mildly HARMFUL.
- cache_coherency PASSED 4/4 (so the 8-node cache_coherency 0/8 was contamination/scale, not a force-flush regression).

### Lesson: dir_reuse is FLAKY across runs (passed 4/4 twice without the lever, failed 0/4 with it; failed 0/2 without, passed 2/2 with). A SINGLE pass proves NOTHING — need ≥3 clean runs. I over-claimed a breakthrough on one flaky pass. The Inv-1-release-flush-gap hypothesis is NOT confirmed (the loss persists with force-flush).

### KEEP: `dir_release_flush_all_done` DEFAULT 0 (inert, refuted diagnostic lever). Build 7FDAE615 = C1B0C0CE (4 levers default-1) + this inert lever. Behaviorally == C1B0C0CE.

### dir_reuse single-dirent loss (P21H-LEAFHOLE, 399/400 or 799/800) REMAINS UNSOLVED. The 8-node face is AG-meta CRC / metadata-read-error shutdown (xfs_trans_read_buf_map / read_agi). Both unsolved.
### Refuted levers now: dir_leaf_rebuild, dir_write_merge, dir_flush_lockwait, dir_postread_reread, dir_release_flush_all_done.
See [[sess30-FINAL-build-C1B0C0CE-levers-default-bare-4tcp-17of17]] [[sess30-SCOPING-1and4tcp-100pct-dir_reuse-sole-flaky-blocker]].
