<!-- sess430 RULE-5 ruling: D-0351 dialloc containment must be TWO-PHASE (Option B) — no platter I/O under AGI/cursor nesting; dedicated non-expiring per-… -->
# sess430 — dialloc containment ruling (D-0351 item "platter-live validation before the inobt modification")

Asked: Option A (plain lock-free LUN read inside mxfs_dialloc_pick_in_rec, next to the existing DLM try-reserve) vs Option B (true two-phase). Ruling:
- Option A REFUSED under the sess427 item-6 ruling: synchronous I/O under the AGI/btree cursor nesting is not grandfathered by the DLM probe already there.
- Option B: collect candidates without modifying the trees; drop cursors/AGI (and any ialloc locks I/O completion could depend on); consult the local pubob store; authoritative plain reads; quarantine bad candidates; restart and REVALIDATE the selected free bit before xfs_dialloc_ag_update_inobt; transaction stays clean across validation; release reservations of rejected/unused candidates; bounded restart count + per-attempt visited set.
- Quarantine set: NOT the 8-entry timed cooldown. Exact per-AG agino membership, no expiry, no eviction during the mount, capacity for every observed DISK-LIVE (bitmap/xarray); if it cannot record another entry -> fail the allocation cleanly; clear only after coordinated repair + authoritative verification (platter mode 0 AND metadata still agrees).
- Error policy: one loud rate-controlled P-line per DISK-LIVE candidate, quarantine, release reservation, continue; never fail an otherwise satisfiable create. All candidates quarantined -> distinct clean failure (EIO/EUCLEAN, not ENOSPC), no dirty cancel, no shutdown.
- Pubob exception: same-node chain allowed only when the store entry matches exact ino + gen/tenure + expected unpublished state; never flush inline.
- Release audit: queue the observation {agino, gen/tenure, platter evidence, reservation/owner identity} into the async release/audit path; notify the VERIFIED owner to publish/repair; do not infer ownership from a possibly stale dinode; do not clear quarantine on request, only after post-repair verification.
Status: NOT BUILT (sess430). Build after the 0.39.1 chain verification completes.
