---
name: ccloop-c7ee71c6-sess43-354-prflush-closed-gate-fixed
description: sess43 part4: 0.11.354 closes D-UNMOUNT-RELEASE-FLUSH (24 clean unmounts, 0 failed I/O); policy gate over-count fixed; board green; 11 OPEN
metadata:
  type: project
---

# sess43 part 4 — a defect actually CLOSED, and the readiness gate made truthful

## DEFECT CLOSED: D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER (0.11.354)
**Root (code + timestamps, not guessed):** `xfs_shutdown_devices()` ends with an
unconditional `blkdev_issue_flush()` on the data device (inherited upstream, for
bdev-pagecache coherency with udev/blkid) and it ran AFTER the deferred SCSI-PR
unregister in `xfs_fs_put_super`. So every clean unmount of a PR-protected LUN
ended in a FAILED Synchronize Cache:
`reservation conflict error, dev dm-1, sector 0 op 0x1:(WRITE) flags 0x800 phys_seg 0`.

**Fix:** move the late unregister to AFTER `xfs_shutdown_devices(mp)`. That
function only flushes + invalidates — it does NOT release the buftargs — so
`bt_bdev` is still valid at the new call site. v0.11.74 had already moved the
unregister after `xfs_unmountfs` (so the unmount record could not bounce EBADE on
a WE-RO target); this completes the ordering so NO device I/O can outlive our own
registration.

**Verified:** `tests/unmount_flush_clean.sh 8 3` = 24 clean unmount/mount cycles,
**ZERO** failed-I/O lines, all nodes remounted. Pre-fix the same path emitted the
failure on essentially every unmount (353: test8 x2, test5 x1, test32 during a
board unmount). DISCRIMINATOR the arm encodes: bare `sd N:0:0:0: reservation
conflict` notices (50 of them in the passing run) are the NORMAL PR-probe artifact
at every mount on every healthy node — only `reservation conflict error, dev ...`
is a rejected command.

## POLICY GATE WAS OVER-COUNTING (tests/suite/open_defects.sh)
It counted `status != "RESOLVED"` as open, so every entry legitimately closed as
"FIXED AND VERIFIED" or "DISPROVED" was still counted: it reported **open=26 of=31**
while the ledger held 11 OPEN. Direction was fail-SAFE (can never manufacture a
false green) but the readiness number was meaningless. Fixed in BOTH branches
(python + the no-python grep fallback) with a normalising comparison against
{RESOLVED, FIXEDANDVERIFIED, FIXEDVERIFIED, DISPROVED}; **any unrecognised status
— including a typo — still counts as OPEN**, so nothing can be closed by accident.
Both branches now agree.

## NEW DEFECT REGISTERED: D-CRASH-CONSISTENCY-32-NOTERMINAL-354 (major, OPEN)
crash_consistency at 32/caw burned its full 90s budget with NO_TERMINAL_RECORD on
ALL 32 nodes (hostload=20.71) where it normally finishes in 22-42s. NOT reproduced
in 3 immediate re-runs — two of which ran at DOUBLE the host load (43-44) and still
passed, so simple load correlation is excluded. P15-REL-ABORT storm EXCLUDED as
cause by measurement (40/134/189 aborts per node with escapes firing, vs the
historical 4480/run and 5993-in-126s storms). Live hypothesis: residual load from
the preceding test (rsync_paired) — the harness only kills leftovers AFTER a
timeout. next_step is instrumentation (per-phase markers + wchan capture at kill).

## P15-REL-ABORT loop: measured, bounded on this build — AND A READING TRAP
40/134/189 aborts per node per session; P15-ORPH-PROCEED fires ~2 per 150; the
two P15H timeouts fire 0. One inode (61352960) showed bursty orphan-shape aborts
(12 over 369s on test1, 22 on test19), not a continuous storm.
**TRAP recorded in the ledger:** `age_orph_ms`/`age_starve_ms` in the
P15-REL-ABORT print are the PER-INODE clocks, which the code documents as
diagnostic-only and known to be reset by icache eviction. `age=0` there does NOT
mean the resource-scoped escape clocks are defeated — judge the loop by
escape-print counts. (I nearly mis-rooted this; checking which value the print
actually reports is what caught it.)

## PACE: load correlation now STAMPED and monotonic
With `hostload=` recorded on every result: load 19.69 -> 9 rounds (PASS);
load 24.24 -> 6 rounds (FAIL). Plus morning data load 11-17 -> 8-10 rounds and the
high-load block load 28-30 -> 5-7 rounds (including after a full re-prep, which
rules out mount-degradation-with-use). ~15 runs across two builds, monotonic.
Margin over DRC_MIN_ROUNDS=8 is ~1 round; hypervisor contention moves it 3-4.

## BOARD: 0.11.354 (srcversion 2DDE66BFEB1DC5B3D3B6042) 32/caw ALL GREEN
22 PASS + 5 FLAKY(current-PASS) + 1 POLICY, 0 FAIL. Also 8/caw all green.
Ledger: 32 entries, **11 OPEN** (was 11 — closed the PR-flush one, registered the
crash_consistency one).

## STATE / NEXT
- Rig: 32/caw on 0.11.354, all mounted, dir_ex_batch_grace_ms restored to default 10.
- NEXT: (1) crash_consistency phase markers + wchan-at-kill instrumentation;
  (2) pace per-turn cost — 32/tcp historically reaches 11 rounds vs caw 8-9, so
  compare transports directly on a quiet host; (3) D-CACHE-COHERENCY-UV-COUNT-MISS
  reproduction with the now-working reason[]/faildist[] capture;
  (4) D-DESTAGE-TEAR needs repeated torn-shape runs to reach FIXED AND VERIFIED.
