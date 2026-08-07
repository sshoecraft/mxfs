---
name: ccloop-c7ee71c6-sess47-TAIL2-379-deployed
description: sess47 final: 0.11.379 deployed fleet-wide — ifree revalidation now decides on DISK-side AGI when in-core diverges (P-IFR-AGI-STALE); repro CLEAN + m…
metadata:
  type: project
---

# 0.11.379 (982534B67B8B6A3FC659A8F) — fleet-deployed at sess47 end

Change: xfs_inactive_ifree revalidation block — when mxfs_ag_buf_disk_differs(ck_agibp), BOTH the empty-bucket check AND the 64-head scan now read mxfs_agi_disk_bucket_head (disk-side, cluster-coherent under held AG EX) instead of the possibly prior-tenure in-core image; P-IFR-AGI-STALE prints each divergence (incore vs disk head + ag_gen). Closes the test32 variant's proven TOCTOU arm (revalidation proceeded on stale non-empty in-core; remove saw coherent empty → P71 → -117).

Verified on deploy: reap_midlist_repro CLEAN (both scenarios), openunlink_matrix 9/9. NOT yet re-exposed to the variant's natural trigger (foreign zombie + matrix reuse churn) — relay should run aged cycles incl. matrix and watch: P-IFR-AGI-STALE (mechanism firing = arm confirmed live and now handled), P71-INSTR (should go quiet for the empty-bucket-foreign shape), P-PINNED-REREAD (delwri tripwire), P53 pairs.

STILL OPEN from the variant decode (finding B): why B1-B4 authority guards allowed a lu=0/au=0/ub=-1 foreign zombie into destructive inactivation at all — the disk-mode read gating them may share the stale-read path. And the fossil-producer delwri-window hunt continues (memory ...-ADDENDUM-fence-ran-and-failed).
