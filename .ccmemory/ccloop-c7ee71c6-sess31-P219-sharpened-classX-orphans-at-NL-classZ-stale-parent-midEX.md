---
name: ccloop-c7ee71c6-sess31-P219-sharpened-classX-orphans-at-NL-classZ-stale-parent-midEX
description: 0.11.270 P219 data: class X = ORPHAN (nl=0,mode kept) images really written at NL (bflags=0x32, no XBF_STALE); class Z = shared parent submitted mid-…
metadata:
  type: project
---

# sess31 — 0.11.270 sharpened P219: the three classes, and what to do

## Data (one PASSING dirent_durability lap, 32/caw, build A07AD5868B46CB6D6A82A7D)
- Class X (REAL, the hole): `dlm_mode=0 stage_mode=5 stale=1 img_mode=100600
  img_nl=0 img_cc=2..3 bflags=0x32` — bflags decode: WRITE|ASYNC|DONE, **no
  XBF_STALE** → real home write. img semantics: nlink=0 with mode retained =
  **ORPHAN** (unlinked-while-open / pending inactivation; a truly freed XFS
  inode has di_mode=0). xfsaild publishes the orphan image AT NL after the
  staging tenure died (epsrc=14516 grant-lost). New counter `stale_nl` in
  P219-LOGGED-AUTHORITY-TOTAL counts exactly this shape.
- Class Y (mostly noise): stage_mode=0 events persist AFTER the torn-read fix
  (epoch double-read stamp, xfs_inode.c ~7297) → xfs_iflush at NL genuinely
  happens (xfsaild flushing re-dirtied inodes post-release). The COPY at NL is
  itself part of the same hole (copying without authority), not just a stamp
  race.
- Class Z (NEW): the SHARED PARENT DIR (ino=25165965) submitted by comm=mkdir
  UNDER EX with stage_epoch 2-4 behind now_epoch (220→222, 178→182);
  img_nl=1840 on test14 vs 3191 on test18 — multi-epoch-old parent inode-core
  images going to the wire MID-TENURE. Run passed ⇒ presumably the current
  tenure's release drain rewrites fresh bytes before handoff (Architectural
  Invariant 1); benign IFF the drain always covers it. If any path unlocks
  without the drain (that is D-RELEASE-BARRIER-OPEN's whole premise), a peer
  inherits an nlink/size-reverted parent — a live candidate mechanism for
  D-SILENT-MKDIR-LOSS.

## Fix design (NOT implemented — consult GPT with these specifics first)
GPT ranking from this session: D (tenure cannot end with obligations; for
INVOLUNTARY loss → fencing, never late publish) > C (reacquire+reload/adopt+
restage) > B (fresh iflush only as C's tail) > A (quarantine fail-closed).
Class-X-specific question for the consult: if the release drain flushed the
orphan's nl=0 state before the tenure ended, home ALREADY has it and skipping
the late NL rewrite loses nothing; if the inode was re-logged after the drain,
the orphan is on the unlinked list and log recovery owns it anyway — so is a
knob-gated SKIP of stale_nl slots (leave buffer dirty, requeue) safe as
containment? Needs: proof the drain covered it (compare drain-flush seq vs
ili re-log), and the AIL-pileup hazard bounded.
epsrc=14516 is the grant-lost bump (xfs_mxfs_dlm.c) — option D there means
making the grant-lost path honor the same obligation the BAST tails honor, or
refusing to end the tenure while `staged-not-republished` items exist.

## Producer + harvest
dirent_durability@32/caw yields ~13 events/lap even when PASSing. Harvest:
`echo 1 > /sys/module/mxfs/parameters/release_barrier_dump` then dmesg grep
P219-LOGGED-AUTHORITY-TOTAL (has stale_nl since 0.11.270) + the
P219-LOGGED-NO-AUTHORITY lines (bflags= field marks 270+ lines).
