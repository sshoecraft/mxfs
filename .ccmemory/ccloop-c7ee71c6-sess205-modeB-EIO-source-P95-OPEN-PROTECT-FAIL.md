---
name: ccloop-c7ee71c6-sess205-modeB-EIO-source-P95-OPEN-PROTECT-FAIL
description: sess205: #18 Mode B EIO source = P95-OPEN-PROTECT-FAIL (xfs_mxfs_dlm.c:36886, mode==NL after ilock, fail-closed -EIO); EDEADLK bursts REFUTED as caus…
metadata:
  type: project
---

# sess205 — Mode B (rsync_paired test19 EIO) source found

Run analyzed: /tmp/run_rsync_paired_20260810T135045Z (0.11.472, sv 9EF804271D01AA283D14131).

## Refuted (RULE 4)
sess204 correlated the mkstemp EIO with `DLM inode lock failed rc=-35`
bursts. WRONG: the failing rsync on test19 ran 13:52:40→13:52:59
(elapsed=18.7s), the EDEADLK bursts (13:49:49 inos 56625770-89 ×3 each;
13:51:42 ino=39848700) are outside that window (cp/mv/rm phase) and
every one resolved via the P109 void-loop (each followed by P6H-ADOPT
mode=5 success — the ×3-per-ino signature is the ilock_begin retry loop).

Why no probe accompanied rc=-35: **P109-CAW-EDEADLK print is gated on
caw_instr_on()** (dlm_caw.c:8049) — silent with instrumentation off.
Not ratelimit. And `DLM inode lock failed` (v5_mount.c:4754-57) prints
for ANY nonzero rc including handled -EDEADLK — pure noise.

## The actual EIO
kernlog_test19 13:52:49: `P95-OPEN-PROTECT-FAIL ino=56623363 — no DLM
grant after ilock; failing the open (fail closed)` → returns -EIO at
xfs_mxfs_dlm.c:36886 (C3 open-protect hook). The check reads
i_dlm_mode under i_dlm_lock while still holding ILOCK_SHARED
(:36861-63), so it is not a post-iunlock race. mkstemp's open(O_CREAT)
had already published the dirent durably → EIO to rsync → leftover
.file29.eA4RCi → files=401/400 + content-sum mismatch. One event
explains all three failed checks.

ino=56623363 is in the previous lap's ino range (created 13:28) ⇒
likely reused ino from the overwrite lap's frees. The
P95-OPEN-STALE-INCARNATION arm (S_IFMT==0 → -ESTALE) did NOT fire:
i_mode nonzero, dlm_mode NL.

## Open question (next session)
Why does the ilock ride exit with i_dlm_mode==NL on a live inode?
Read the hook entry above xfs_mxfs_dlm.c:36820 and ilock_begin's exit
paths; instrument the !ok arm (log i_dlm_state, routed_iclus, open_n,
self_created, i_mode); count P95-OPEN-PROTECT-FAIL fleet-wide in the
run dir. RULE-5 consult before changing the fail-closed -EIO semantics.
