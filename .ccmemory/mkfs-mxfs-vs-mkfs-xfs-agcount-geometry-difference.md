---
name: mkfs-mxfs-vs-mkfs-xfs-agcount-geometry-difference
description: CLOSED (documented open question): mxfs-vs-xfs single-node fio gap traced to first-touch/steady-state mismatch; root of mxfs's smaller first-touch pe…
metadata:
  type: reference
---

## FINAL STATE (2026-07-14, same session): root cause identified as a TEST
## METHODOLOGY bug, not an mxfs performance bug or benchmark artifact of the
## kind originally suspected. One sub-question remains a documented open item.

**The original "mxfs is 2.5x faster than XFS" observation was a test bug**:
every single-shot fio comparison that session (via `fio_perf`/`fio_perf_vs_xfs`)
used a FRESH file each time, so it was unknowingly comparing FIRST-TOUCH
(never-before-written extents) performance on both sides. First-touch and
steady-state (already-written) throughput differ dramatically and by
DIFFERENT amounts per filesystem:

| | first-touch (fresh file) | steady-state (same file, 2nd write) | ratio |
|---|---|---|---|
| stock XFS | 15,645 iops | 44,582 iops | 2.85x |
| mxfs | 36,674 iops | 53,238 iops | 1.45x |

At steady state mxfs is only ~93-99% of XFS (near parity, as expected for the
same fork + thin overlay) — see `fio_perf_vs_xfs` runs after the fix. The
apparent "2.5x mxfs advantage" was almost entirely the MISMATCH between
mxfs's smaller first-touch penalty and XFS's larger one, not mxfs being
faster in any steady-state sense.

**FIX APPLIED**: `tests/suite/fio_perf.sh`'s `run()` now executes each fio
workload TWICE against the same persistent file and reports only the second
(steady-state) pass — eliminates the mismatch structurally for all future
runs, both the `1/xfs` baseline capture and the `fio_perf_vs_xfs` comparison.
`tests/tooling/fio_vs_xfs_baseline.sh` was deliberately left UNCHANGED (user
decision): it reformats fresh every round by design, so it consistently
measures first-touch-vs-first-touch (a fair, different, complementary facet —
already properly rigorous via position-balanced rounds + trimmed mean, unlike
the ad-hoc test below).

**OPEN QUESTION (documented, not resolved, user has explicitly decided to
leave it open rather than investigate further right now)**: WHY does mxfs
show a smaller first-touch penalty than stock XFS (1.45x vs 2.85x), given a
full source trace found the actual code identical?
- Traced `xfs_direct_write_iomap_begin`/`imap_needs_alloc`/
  `xfs_iomap_write_direct`/`xfs_iomap_write_unwritten`/`xfs_dio_write_end_io`
  in `/src/mxfs/pal/linux/xfs_iomap.c` + `xfs_file.c` against upstream
  `~/src/linux` 6.19-rc0 — BYTE-FOR-BYTE IDENTICAL. Confirmed: first write to
  a hole costs 2 transactions upstream (alloc-as-unwritten, then a second
  transaction at DIO completion to convert unwritten->written + log i_size);
  a rewrite of an already-written extent costs 0 transactions (pure
  `xfs_bmapi_read`). This upstream double-transaction cost is identical in
  mxfs's fork.
- The one mxfs-specific lock hook (`mxfs_dlm_ilock_begin()` in `xfs_ilock()`,
  `/src/mxfs/xfs/xfs_inode.c:~200-235`) hits a single-node bypass
  (`xfs_mxfs_dlm.c:~19997-20008`) uniformly on EVERY ILOCK/IOLOCK acquisition
  (both first- and second-touch) — cannot explain an asymmetric effect.
- mkfs_mxfs's log-size difference (4-slice, 64MB/slice minimum) washes out to
  the SAME effective per-node log size as stock XFS at N=1 — not the cause.
- **Known confound flagged by the trace agent, NOT controlled for**: the
  first/second-touch measurement above was a single-shot, non-position-
  balanced test (run1-then-run2, sequential, no alternation, no repeats) —
  exactly the methodology `fio_vs_xfs_baseline.sh`'s own header comment warns
  is unreliable on this specific host/LUN (documented 46-210% single-shot
  swings). So the 2.85x vs 1.45x MAGNITUDE, and possibly the asymmetry
  itself, may not be fully real — it has not been validated with
  position-balancing/repetition.
- **Verdict if it DOES turn out to be real** (per user, 2026-07-14): not a
  bug and not benchmark cheating — durability-skipping (`fua_disable`) and
  data-caching (`cache_mem_max_mb`/`pct`) mechanisms were both already ruled
  out as explanations, so a confirmed smaller first-touch penalty would be a
  genuine, legitimate architectural advantage worth documenting/highlighting,
  not something to "fix."

**Next step if ever resumed**: redo the first/second-touch comparison with
position-balancing (alternate which filesystem/pass goes first, repeat N
rounds, trimmed mean) before trusting the magnitude; only escalate to
block-layer instrumentation (blktrace) if the effect survives that.

---

## Background facts from the investigation (still true, kept for reference)

- `mkfs_mxfs` targets ~262144 blocks (~1GB) per AG (`tools/mkfs_mxfs.c`
  ~1111-1122), giving agcount=50 on a 50GB LUN vs stock `mkfs.xfs`'s
  agcount=4 (~12.5GB/AG) on the same device. Real, intentional-looking
  (comment: "Target ~262144 blocks per AG (~1GB)"), plausibly for cluster
  per-node AG affinity — but PROVEN NOT to affect single-node fio randwrite
  throughput (reformatting XFS with `-d agcount=50` to match changed nothing:
  15,716 iops / 2.01ms, statistically identical to XFS's agcount=4 baseline).
- Also ruled out this session: host page cache (this LUN's SCST vdisk_fileio
  device uses `o_direct=1`, confirmed via `scripts/scst_setup.sh` + live
  `/sys/kernel/scst_tgt/devices/mxfs/filename`; both fio legs showed real
  millisecond-scale device latencies, not RAM-speed, ruling out a fake/
  buffered-I/O explanation too); sparse-file allocation (image fully
  allocated, `du -h` == apparent size).
- Verify AG geometry via `chk_mxfs -v /dev/sda` vs `mkfs.xfs -N -f /dev/sda`
  (dry-run, must unmount first).
