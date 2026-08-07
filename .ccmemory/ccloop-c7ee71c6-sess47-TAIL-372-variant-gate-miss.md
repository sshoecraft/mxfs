---
name: ccloop-c7ee71c6-sess47-TAIL-372-variant-gate-miss
description: sess47 tail CORRECTED: test32 -117 = P71 EMPTY-BUCKET exit on a FOREIGN zombie; revalidation read STALE in-core AGI (agi_disk_differs=1) → proceeded;…
metadata:
  type: project
---

# -372 VARIANT DECODED (0.11.378, test32) — CORRECTED; supersedes the gate-miss hypothesis

Ring: test32:/root/ifree_t32_1785712978.dmesg. Sequence (t=20454.009-.018):
1. `P9-NLEDGE from_disk ino=52962484 old=1 new=0` (kworker/u9:16) — FOREIGN zombie: nlink=0 adopted from disk (a peer unlinked it; entry was on the PEER's slot bucket, or already consumed by the peer's completed free).
2. `P-UNLREM-INCOMPLETE ub=-1 prev=0 lu=0 au=0` — local destructive inactivation proceeded with no membership (fallback bucket 52 = agino%64).
3. **`P71-INSTR agi-unlinked-garbage bucket=52 head_agino=NULLAGINO disk_head=NULLAGINO agi_disk_differs=1`** → XFS_CORRUPTION_ERROR → -117 → shutdown. NOT the silent NOPREV exit; NOT a preflight-gate miss per se (preflight would only have -EAGAIN'd on ub=-1 anyway — wait, it DIDN'T RUN: unlinked_incomplete gate false at gate time because nlink went 0 only at step 1, microseconds before, on a different worker).

## The real defect chain (two findings)
A. **Pre-ifree revalidation TOCTOU on a STALE in-core AGI**: the empty-bucket skip (xfs_inode.c ~3743) read an AGI image where bucket 52 looked NON-empty (or head==agino somewhere) → proceeded; the remove's later AGI read was coherent → empty → P71. `agi_disk_differs=1` at P71 proves in-core vs disk divergence AT failure time. Same stale-buffer class as the fossil di_next_unlinked (AGI arm this time). Under held AG EX a peer cannot be mutating — the staleness predates the acquire's coherency refresh ⇒ the revalidation ran against a prior-tenure AGI image.
B. **Foreign-zombie authority**: lu=0/au=0/ub=-1 local inactivation of a peer-freed inode should have been stopped by B1-B4 authority guards before ANY of this — check why they passed (the disk-mode read that gates them may have used the same stale path).

## Fix targets (RULE-4 order)
1. Instrument the revalidation: print the AGI's b_mxfs_ag_gen/tenure + head values it ACTS on, plus a disk-differs check (mxfs_ag_buf_disk_differs already exists — used in P71) — if differs, FORCE coherent re-read before deciding.
2. Then the authority-guard path for foreign zombies with from_disk late nlink adoption.
3. Preflight NOBUCKET arm is still correct but never reached; after fix 1, the empty-bucket skip handles this shape (as designed).

Rig: 0.11.378 fleet, test32 withdrawn (ring saved), widened P-PINNED-REREAD live (0 false positives). All other sess47 memories remain valid.
