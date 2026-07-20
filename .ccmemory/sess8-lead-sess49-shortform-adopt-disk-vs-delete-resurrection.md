---
name: sess8-lead-sess49-shortform-adopt-disk-vs-delete-resurrection
description: sess8 code-level lead: the sess49 "shortform dirs always adopt disk superset (skip-the-skip)" reload logic (xfs_mxfs_dlm.c ~4825) may RESURRECT an in…
metadata:
  type: project
---

## Concrete code-level lead for the serialized-handoff coherence gap
([[sess8-DECISIVE-not-doublegrant-not-splitbrain-serialized-coherence-gap]]).

The slow-path EX-acquire reload (mxfs_dlm_reload_inode, xfs_mxfs_dlm.c ~4753, called post_release=true
from ilock_begin ~7079) has a sess36 SELF-SKIP: if this inode's own log item is still dirty/in-AIL/
pinned, skip the reload (our in-core is freshest). sess49 then added a SCOPE FIX (~4825-4846):
"skip-the-skip" for LOCAL-format (shortform) DIRECTORIES — i.e. a shortform dir ALWAYS adopts the
on-disk dinode even when our own log item is in-flight, on the rationale that "the disk dinode is a
strict SUPERSET (our drained entry + peer's), so adopting it cannot lose our own entry."

## THE FLAW (hypothesis matching the n1_r7 RESURRECTION symptom):
"strict superset" holds for cross-node ADDS, but NOT for DELETES. If THIS node's in-flight committed-
not-checkpointed op is a DELETE (rm/rename-away of n1_r7), and the reload adopts a disk image that
still CONTAINS n1_r7 (either stale-LUN or our delete not yet on the read coherence point), then
adopting disk RESURRECTS the entry we just deleted in-core. The skip-the-skip forces adoption exactly
when our in-core (with the delete applied) is the truth and disk may lag. dlm_fairness does
create→rename→rm of per-node files, so DELETE/rename-away is the dominant op — consistent with the
durable resurrected-`.done`/`n1_rK` leftovers.

## WHY this is the prime lead now: double-grant + split-brain are REFUTED (P-DOUBLEGRANT=0,
P-STALEMASTER-GRANT=0 at failures), and EX is serialized with a reload on every acquire — so the bug
is in WHAT the reload adopts, not in lock exclusion. The sess49 skip-the-skip is the one place that
deliberately adopts disk over in-core for shortform dirs while our own mods are in-flight.

## NEXT SESSION — resolve + fix:
1. CONFIRM via one correlated handoff trace (low-volume; gate to the test dir ino): does node B's
   adopted shortform count/contents contain an entry that node A durably DELETED? And was A's delete
   on the read coherence point (plain-bio) at B's reload?
2. If the skip-the-skip resurrects in-flight deletes: the fix is to make the shortform "superset"
   adoption a true MERGE-aware decision — do NOT adopt a disk entry that THIS node has a
   committed-not-checkpointed REMOVAL for (track via ili_fields / a removed-set), or gate the
   skip-the-skip to ADD-only situations. Careful: must still adopt the peer's adds (the sess49
   regression it was built to fix — cross_write_read dirent loss). The correct invariant: adopt the
   UNION of (peer durable entries) and (our committed-not-yet-durable entries), respecting our
   committed deletes. This is the shortform-dir merge the codebase has never fully done.
3. Validate 30+ dlm_fairness iters + full suite ×3. Watch for regressing cross_write_read /
   unlink_visibility / zero_silent_loss (the sess49/sess60 shortform cases).

## STABLE STATE: 15/16, no cascade. Build 174E2CD5 (rename guard + detectors). Marker NOT written.
See [[sess8-DECISIVE-not-doublegrant-not-splitbrain-serialized-coherence-gap]] for the detector build
+ the write-vs-read correlated-trace plan; [[sess49_lessons]] for the original skip-the-skip rationale.
</body>
