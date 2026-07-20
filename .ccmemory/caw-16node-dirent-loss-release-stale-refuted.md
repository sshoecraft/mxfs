---
name: caw-16node-dirent-loss-release-stale-refuted
description: 3rd refuted fix (ccloop 26c41354 sess1): dir_release_stale=1 alone still leaks (node8_file22 dangling, 15/16) but NO timeout (218s, lightweight). Dem…
metadata:
  type: project
---

## dir_release_stale=1 REFUTED (Case B narrowing) — ccloop 26c41354 sess1

Continues [[caw-16node-dirent-loss-CASE-B-PROVEN]]. Tested `MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 dir_release_stale=1"` (GFS2 invalidate-on-demote: the demoting node clears XBF_DONE|_XBF_FUA_FRESH on its dir buffers at EX release) on cache_coherency at 16.
- Result: FAIL 15/16, `test1: uv gone node8_file22 uv none remain got=1` — dangling dirent STILL leaks. Completed in 218s (NOT a timeout — invalidation is cheap, unlike relverify's per-release FUA reads).
- **Conclusion**: the reintroducing async write is NOT the demoting node's own stale buffer (invalidating it changed nothing) → it's a **PEER's** stale cached dir buffer being xfsaild-destaged, OR a path release_stale's invalidation doesn't cover. Also note 15/16 (not all-16) = the reintroduced dirent is visible to only SOME nodes = per-node cache divergence.

### Refuted-fix tally (RULE 5: ≥3 distinct approaches refuted with evidence)
1. inode_mht_ms=600/dir_sf_mht_ms=120 → coherency WORSE (posix_multi 0/16).
2. dir_relverify=1+dir_release_stale=1+dir_wr_barrier=1 → cache_coherency TIMEOUT 0/16 (RULE-0).
3. dir_release_stale=1 alone → still leaks 15/16 (but lightweight, no timeout).

### NEXT (unchanged, RULE 4): write-side probe to name the PEER reintroducer
Rebuild + instrument the xfsaild dir-block destage (pal/linux/xfs_buf.c, dir DATA/LEAF bio submit / mxfs_buf_xfsaild_skip_dir_write ~3327): for owner==shared test dir, raw-FUA read current disk; if in-core buf about to be written has an inum the fresh disk LACKS (reintroduction), log writer comm/daddr/owner/i_dlm_mode(is this node even holding EX? probably NL/PR — a peer)/b_mxfs_dir_gen vs i_dlm_dir_gen/b_mxfs_dir_incarn vs i_generation/IN_AIL. Loop cache_coherency at 16 (baseline modargs) until dangling-dirent fail. Expected: a node at NL/PR (not EX) destaging a stale dir buf whose _XBF_FUA_FRESH/dir_gen was never invalidated when a peer modified the dir. Fix = skip that destage (a node must NOT destage a dir DATA/LEAF buf it does not hold EX for — the sess12 dir_ex_write_guard idea, but that arm is default-OFF and was tuned out; re-validate it for THIS reintroduce case, or a targeted "peer-held-buffer never destages dir blocks" rule). Beware: xfsaild legitimately destages metadata; the skip must be dir-DATA/LEAF + not-EX-held + disk-proven-reintroduction, else it wedges the AIL.

### Infra state: 16-node CONVERGENCE is ALSO flaky (ITER 2 here: "did NOT converge to 16 within 170s") — separate membership-stability issue (disklock slot-table read undercount, see [[caw-multipath-16node-instability-diagnosis-sess1]]); contributes to run PREP FAILs. Build still 591A76FB (no kernel edits yet; only run.sh + new scripts/caw_preflight.sh). criteria.json 1/2/4/8 PASS intact. Marker NOT written.
