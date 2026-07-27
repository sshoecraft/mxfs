---
name: pve-fio-odirect-write-eagain-after-dropcaches
description: PROVEN: on mxfs N>=2, an O_DIRECT write to an inode just evicted by drop_caches returns spurious -EAGAIN (offset 0), zeroing fio_perf seqW/randW. Nat…
metadata:
  type: project
tags: [fio_perf, eagain, o_direct, drop_caches, proxmox, 6.17, tcp, RULE4, RULE5, open-front, write-path]
---

# fio_perf seqW=0/randW=0 on Proxmox 2/tcp = spurious -EAGAIN on O_DIRECT write after drop_caches

Found 2026-07-20, Proxmox rig (pve1=192.168.1.80 / pve2=192.168.1.81, kernel
6.17.2-1-pve, build `CA76C3FF2BAD7C39813BE5C`), first 2-node TCP run on 6.17.

## Symptom

`fio_perf` records **seqW=0 MiB/s AND randW=0 iops** (both writes zero), reads
fine (seqR ~56, randR ~15678). Only at N>=2. The native-XFS N=1 baseline of the
IDENTICAL test passed at seqW=99 MiB/s, so this is **mxfs-specific**, not a rig
or fio-version artifact.

`fio_perf_vs_xfs` then "PASS (1s)" is VACUOUS — it compared against zero writes.

## RULE-4 evidence (all proven, not guessed)

The test's `run()` (tests/suite/fio_perf.sh) runs each workload TWICE to the same
file (isolate steady-state from first-touch), reports only pass 2, with
`sync; echo 3 > /proc/sys/vm/drop_caches` before each pass;
`--ioengine=libaio --direct=1 --iodepth=32`.

- Standalone single fio O_DIRECT write to the mount: **works**, 102 MiB/s,
  error=0, full write. O_DIRECT writes are not fundamentally broken.
- Replaying the double-pass: **pass 1 writes the full file fine** (57 MiB/s,
  error=0, ~19s); **pass 2 fails instantly** (0.6s):
  `fio: io_u error ... Resource temporarily unavailable: write offset=0,
  buflen=1048576` = **-EAGAIN on the first block of the rewrite**.
- Discriminators:
  * V1 two O_DIRECT passes, NO drop_caches between  -> pass 2 **succeeds**
  * V2 two passes WITH drop_caches (test behavior)   -> pass 2 **EAGAIN**
  * V3 drop_caches then FIRST write to a fresh file  -> **succeeds**
  * V5 drop_caches then O_DIRECT rewrite, iodepth=1   -> **EAGAIN** (not async/batch)
- **Trigger = `echo 3 > drop_caches`** (inode + pagecache eviction). The next
  O_DIRECT WRITE to a just-evicted inode returns -EAGAIN. Fresh-file first write
  after drop_caches is fine. iodepth-independent.

## Code paths traced (upstream XFS 6.19 semantics; mxfs is a fork)

- 1M @ offset 0 is aligned -> `xfs_file_dio_write_aligned` (pal/linux/xfs_file.c
  ~722). Takes IOLOCK_SHARED, calls stock `xfs_file_write_checks` (~481, no mxfs
  hook, no non-NOWAIT EAGAIN), then `iomap_dio_rw` with **dio_flags=0** — NO
  IOMAP_DIO_OVERWRITE_ONLY, NO IOMAP_NOWAIT.
- The **unaligned** path (`xfs_file_dio_write_unaligned` ~876) is the one with
  the OVERWRITE_ONLY -> -EAGAIN -> `retry_exclusive` dance (line ~939). The
  **aligned path has NO such retry**.
- `xfs_direct_write_iomap_begin` (pal/linux/xfs_iomap.c ~867) is stock: every
  -EAGAIN site gates on `flags & (IOMAP_NOWAIT | IOMAP_OVERWRITE_ONLY)` (lines
  ~985, 997, 1011) — neither set here. Stock code should NOT EAGAIN.
- mxfs overlay has ~7 `if (PTR_ERR(bp) == -EAGAIN)` buffer-read sites in
  xfs_mxfs_dlm.c + a documented "transient torn-read coherency retry" for
  multi-node metadata buffers.

## Hypothesis (under GPT review — RULE 5 consult sent, task ktw6q985u)

drop_caches evicts the inode -> data-fork bmbt extent map gone -> next write's
`xfs_bmapi_read` inside iomap_begin must reload bmbt blocks -> mxfs coherent/DLM
buffer read returns -EAGAIN transiently (grant not ready / torn-read) -> aligned
direct-write path has no EAGAIN->retry wrapper -> -EAGAIN propagates through
iomap_dio_rw to the fio io_u. Native XFS reads bmbt with no DLM step -> never
EAGAINs.

Upstream contract: -EAGAIN from the write path is legal ONLY when
RWF_NOWAIT/IOCB_NOWAIT was set. A spurious EAGAIN to a blocking O_DIRECT write is
a real bug — a database doing O_DIRECT after memory pressure evicts its inode
would hit it. NOT just a test artifact.

## Candidate fixes (do NOT patch before GPT + instrumented proof)

(a) make the mxfs coherent buffer-read / DLM reload BLOCK (wait/retry
internally) instead of returning -EAGAIN when the caller did not pass
NOWAIT/nonblocking; (b) add an EAGAIN->retry wrapper to the aligned direct-write
path mirroring the unaligned one; (c) something deeper. Constraint: mxfs
invariant that a peer must never read stale metadata — the fix must not become a
stale-read hole, and must avoid i_lock/IOLOCK/AIL-drain reentrancy deadlock in
the iomap_begin context.

## GPT consult result (task ktw6q985u, gpt-5.6-sol) + two decisive FREE tests

GPT qualified the bmbt hypothesis: a 64MB/1GB sequential file is likely
FMT_EXTENTS (extents copied inline at iget) so `xfs_bmapi_read` needs NO external
btree read — ranked **lazy inode DLM grant reacquisition after inode eviction**
as at-least-as-likely, noting the fresh-file-works result supports it (a created
inode already holds the grant; a reclaimed+re-iget'd one must reacquire).

Two RULE-4 discriminators run at ZERO build cost confirmed GPT's #1:

1. **`filefrag` -> `1 extent found`** = FMT_EXTENTS. **bmbt-reload hypothesis
   REFUTED** (no external btree block to read).
2. **drop_caches level** (rewrite after each): `=1` pagecache-only, inode
   SURVIVES -> **no EAGAIN**; `=2` inode/dentry evict, pagecache kept ->
   **EAGAIN**; `=3` both -> **EAGAIN**. So **inode EVICTION is the trigger, not
   pagecache/buffer.**

Combined with "open succeeds, first WRITE fails at offset 0": iget re-instantiates
the inode on pass 2 with `i_dlm_stale` set; the first write triggers the
stale-reload / write-grant reacquire, and a coherent read in that path returns
-EAGAIN. NOTE: `mxfs_dlm_ilock_begin` (xfs_mxfs_dlm.c:20845) is **void** (called
bare from xfs_ilock at xfs_inode.c:235) so it does NOT propagate EAGAIN up — the
EAGAIN escapes via a different return (coherent buffer read in the stale-reload,
the `PTR_ERR(bp)==-EAGAIN` family), NOT the grant-acquire return itself.

## GPT fix philosophy (do NOT copy the unaligned XFS retry dance)

MXFS should carry an explicit blocking/NOWAIT policy down to the grant/coherent-
read op: for a BLOCKING caller wait/retry internally (or unwind to a lock-safe
restart point); return -EAGAIN ONLY for actual NOWAIT callers. If it's a grant
acquire, pre-acquire at a lock-order-safe higher layer BEFORE taking XFS
IOLOCK/ILOCK. An aligned-DIO EAGAIN->retry wrapper is a BACKSTOP at best (masks
this symptom, not other blocking paths; can spin; doesn't fix lock order).
Deadlock traps to respect: DLM grant -> IOLOCK -> ILOCK -> buffer locks ordering;
AST/BAST must not need locks held by waiters; per-AG DLM before local AG metadata;
no unbounded DLM wait from AIL/reclaim/writeback; obtain DLM mode THEN lock+
validate buffer (not buffer-lock-then-wait-grant); coherency must survive retry;
handle partial DIO.

## ROOT CAUSE PROVEN + FIX VERIFIED (then it exposed a SECOND bug — read on)

Instrumented the write path (probes at xfs_file_dio_write_aligned /
write_checks / write_iter, all gated to comm=fio, DKMS-rebuilt on the nodes).
The -EAGAIN comes from **`kiocb_modified(iocb)` inside `xfs_file_write_checks`**
→ `file_modified_flags` → `__file_update_time` → **`xfs_vn_update_time`**
(pal/linux/xfs_iops.c). That function had:

```c
	} else {   /* non-SB_LAZYTIME */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		if (flags & IOCB_NOWAIT)   /* WRONG for the 2-arg S_* form */
			return -EAGAIN;
#endif
	}
```

The 3-arg `->update_time(inode, enum fs_update_time type, unsigned int flags)`
form (where `flags` genuinely carries IOCB_*) was introduced upstream by commit
**761475268fa8 "fs: refactor ->update_time handling", first released in v7.0-rc1**
(confirmed via `git describe --contains` in /src/linux). On 6.17.2 (all kernels
<7.0) `->update_time` is the 2-arg `int flags` form carrying **S_*** bits, and
**S_VERSION == 8 == IOCB_NOWAIT (0x8)** (verified against 6.17.2-1-pve's real
headers). A version-bumping write passes `flags = S_MTIME|S_CTIME|S_VERSION =
0xE`, so `flags & IOCB_NOWAIT` is true → **spurious -EAGAIN to a blocking write**.
`ki_flags=0x860000` = IOCB_DIRECT|IOCB_WRITE|(aio bit), NO IOCB_NOWAIT — proven
blocking. Invisible on 6.8 (< 6.15 → compiled out), which is where the whole
matrix was validated. drop_caches triggers it because eviction makes
`inode_needs_update_time` return non-zero so `->update_time` actually runs; the
VFS `file_modified_flags` already returns -EAGAIN for genuine IOCB_NOWAIT BEFORE
calling `->update_time`, so the pre-7.0 form must not repeat the check.

**FIX**: gate the check `>= KERNEL_VERSION(6, 90, 0)` (matches the sibling
3-arg-signature gates already in the function). **VERIFIED**: fio_perf seqW
0 → 110 MiB/s / randW 0 → 28390 iops (2/2 nodes); the drop_caches repro passes.

## A SUSPECTED dir_reuse regression — INVESTIGATED, then REFUTED (confounded A/B)

Initially it looked like the fix regressed `dir_reuse_coherency` (buggy PASS ×2 /
fixed FAIL ×2). That A/B was **CONFOUNDED by rig load** and the conclusion was
WRONG — see [[pve-timestamp-update-ex-iflush-breaks-create-visibility]] for the
full correction. Short version: on the buggy build fio_perf writes nothing
(seqW=0 → idle rig), on the fixed build it writes 110-154 MiB/s (loaded rig), so
the A/B wasn't isolating the timestamp mechanism. Controlled re-test on the FIXED
build: **dir_reuse PASS 11/11** (idle, cold-prep, after heavy fio_perf, probe
build). Also a Heisenbug — a non-executing probe flipped FAIL→PASS. The 2 early
fails were the known, rare, pre-existing dir_reuse create-visibility flaky class
(P-IGET-ENOENT dead-shell), NOT a deterministic consequence of this fix.

**The fio_perf fix has NO reproducible regression and should ship.** dir_reuse's
create-visibility flakiness is a separate pre-existing issue for its own focused
investigation (with deliberate race-amplification).

Deployed state at handoff: nodes on the FIXED build `C7287111` (fio_perf fix,
no probe); source tree matches (6.90.0 gate). VERSION bumped 0.11.39 → 0.11.40.
Fast iteration: `scripts/pve_dkms_rebuild.sh` (runs on a node from NFS /src).

## Related

[[compiled-tcp32-dlm-correctness-campaign]] (mxfs write-path / grant-lifecycle
context), [[pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead]] (the OTHER
open Proxmox bug, from fence_during_write), [[runsh-ssh-node-pipeline-swallows-remote-exit-status]].
