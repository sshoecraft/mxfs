---
name: ccloop-c7ee71c6-sess235-GPT-ruling-open-protect-demote-race-fix-shape
description: sess235 RULE-5 ruling: open_protect live-NL = cold-open restart (shape a), NO synthetic -ESTALE, release-gen serialization + admission gate; 9 invari…
metadata:
  type: project
---

# sess235 RULE-5 ruling (gpt-5.6-sol) — D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO fix shape

Defect: mxfs_dlm_open_protect (xfs/xfs_mxfs_dlm.c:37531-37654) returns -EIO
when the post-ride re-read sees mode==NL. PROVEN benign race (0.11.482
cache_coherency FAIL test23): BAST worker's terminal release store
(:16355) landed 16us before the re-read on a live published file
(nl_line=16355 nl_om=5 nl_age_us=16 stamp).

## Ruling
- **Shape (a)** — treat live-NL as a COLD OPEN: restart the acquisition/
  admission protocol. NOT a recursive acquire while holding ILOCK_SHARED.
- **NO synthetic -ESTALE** for live-NL (keep it ONLY for the tombstone arm).
  O_CREAT|O_EXCL/mkstemp hazard: first attempt durably publishes dirent,
  -ESTALE re-walk finds the file, O_EXCL -> -EEXIST + leftover file.
- Conservative loop: snapshot release generation; drop spinlock + ILOCK;
  wait for the OLD release epoch to fully complete (a stale terminal store
  must never overwrite a newer acquire's mode — needs release/acquire
  generation check); routed cluster acquire via its normal lock protocol;
  retake ILOCK_SHARED; re-run ENTIRE admission (tombstone, route/iclus,
  publication, release-gen) from scratch; loop.
- Livelock bound: few plain restarts, then a short per-inode ADMISSION GATE
  the release worker honors — BAST marks pending, only terminal demotion is
  delayed through the admission critical section. Never convert contention
  into -EIO/-ESTALE; return only REAL hard errors (shutdown/fence/timeout).
- open_n visibility is necessary but NOT sufficient: the release that
  produced NL may predate the count publication — hence the epoch wait.

## Key invariants (assert/instrument)
1. Covered inode admits only with current routed iclus grant.
2. Tombstone re-check AFTER every acquire and at admission linearization.
3. Release worker may terminal-store NL only if its release gen still owns
   the installed grant gen.
4. Admission cannot commit while a pre-open_n release can finish without
   acknowledging the open.
5. Admission checks (mode/state/gen/route/publication) atomic under
   i_dlm_lock; pending BAST cannot invalidate a committing admission.
6. Post-admission demote is safe (open publication protects incarnation).
7. Acquire success != admission; full re-validation follows.
8. Error fidelity: NL/contention never -EIO; tombstone -ESTALE; real
   failures return their real errno.
9. No synthetic stale-retry after irreversible O_CREAT side effects.

## Question answered
Live mode==NL is NEVER inherently unsafe to acquire — danger lives in
surrounding state (tombstone, teardown, unpublished, un-routed, old
release epoch still able to store), each of which must be tested
explicitly, not inferred from NL.
