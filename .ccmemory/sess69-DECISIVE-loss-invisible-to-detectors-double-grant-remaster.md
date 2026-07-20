---
name: sess69-DECISIVE-loss-invisible-to-detectors-double-grant-remaster
description: sess69 DECISIVE: 4/tcp dir_reuse loss is INVISIBLE to ALL coherency detectors (P-TDS-RMW stale_base=0, P-DOUBLEGRANT=0, P-STALEMASTER=0). EX is exclu…
metadata:
  type: project
---

## sess69 DECISIVE — the loss is invisible to EVERY DLM/coherency detector; root is WRITE-SIDE

4/tcp dir_reuse_coherency, dirwr=1 + full kernel-log streaming. Round 8 lost `node4_f7.md5`; other runs lost node3_f23, node3_f2.md5 — NOT node-specific, it's a racing writer's entry. readdir=399/400, durable, all nodes incl creator. dir ino reused each round (131/132).

### EVERYTHING in the EX-coherency layer is REFUTED with direct always-on probe evidence (streamed):
- `P-TDS-RMW`: every dir-EX-modify serve = `held=1 mode=EX stale_base=0`. **stale_base=1 count = 0 all nodes** — no RMW ever runs on a base any detector flags stale.
- `P-DOUBLEGRANT = 0` (master never granted EX while a different node held active EX).
- `P-STALEMASTER-GRANT = 0` (no split-brain mastership / no two-master).
- `P106-STALE-EX = 0` (local mirror always holds EX at serve).
- `P-DE-BLK disp=SKIP = 0` (reacquire drain_evict leaves NO block stale; visits data+leaf, nd up to 4).
- `P-SF-DURABLE-FAIL = 0`, `P97-RELFENCE-WEDGE = 0` (release fence always makes dir blocks durable before handoff).
- `P116-RELOAD-SELFCLOBBER-SKIP ino=dir = 0` (reload not skipped).
- MAPDIVERGE=0 (sess68, extent maps agree at modify).

**Conclusion: EX is genuinely exclusive (one owner, master-confirmed), every RMW holds EX with a fully-reloaded fresh base, release is fully durable — yet a dirent is durably lost.** The bug is NOT in DLM grant exclusivity, NOT in stale-base reload, NOT in release durability. The entire 68-session "detect stale base + reload/evict/grant_gen/handoff" effort has been attacking the WRONG layer.

### LEADING ROOT (next session): WRITE-SIDE stray/non-owner writeback of a stale cached dir DATA block
After node X durably writes dir block @ daddr D (with the entry) and releases, a LATER xfsaild/CIL writeback — on SOME node — of a STALE cached copy of daddr D (a prior-incarnation ABA copy, since the dir inode + block daddrs are REUSED every round, or a copy held at NL by a non-owner) writes back to the shared target, REVERTING D to a version lacking the entry. The DLM layer never sees it because no lock op is involved — it's a raw buffer flush. This is dir_reuse-specific because only this test reuses dir-block daddrs (crash_consistency doesn't reuse → passes).
- Supporting: prior leads sess40 (`dir-block ABA writeback skip`, build B9F9326E, UNVERIFIED), sess67 (`dir_iflush_owner_fence` — only EX owner may flush a dir inode; reverted as "inert" but that was for the INODE, maybe not the DATA blocks). Architectural Invariant #1 covers releasing-node flush ordering but NOT a non-owner node's xfsaild flushing a stale cached dir DATA block it holds at NL.

### NEXT SESSION — confirm write-side stray flush
Add an always-on probe at the dir DATA-block bio WRITE submission (pal/linux/xfs_buf.c write path, or xfs_dir2_data.c) logging: daddr + writing-node dlm_mode for the owning dir inode + a content fingerprint (dir entry count, or hdr->bestfree). Then catch a WRITE of a dir block by a node whose dlm_mode for that inode is NL/PR (NOT EX) — that is a non-owner stray flush = the corruptor. FIX candidate: fence dir DATA-block writeback so ONLY the current EX owner (or the release drain) may write a multinode dir data block; a non-owner's stale cached copy must be invalidated, never flushed (extend sess67 dir_iflush_owner_fence from the inode to the data/leaf blocks — see [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]] which is EXACTLY this lead). Note P62-DWR-N1F1 (xfs_dir2_data.c:524) already fingerprints dir writes for "node1_f1" — generalize it.

### Also: 24-round TIMEOUT (RULE 0), ~13-16s/round×24 > 300s. Separate per-round-cost fix needed.

Cluster healthy (test1-4 mounted), build A81DB821 baseline. Marker NOT written — criterion not met. See [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]], [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]], [[sess69-REFUTATIONS-and-gpt-design-dirreuse-4tcp]].</body>
