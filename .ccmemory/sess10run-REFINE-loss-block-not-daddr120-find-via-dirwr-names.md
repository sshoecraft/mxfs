---
name: sess10run-REFINE-loss-block-not-daddr120-find-via-dirwr-names
description: sess10(ccloop) refine: by mid/late rounds the lost dir entry is NOT in block0 (daddr=120) — dir spans 3+ extents; find the lost entry's daddr via P35…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — refinement for the release→grant timing experiment

Attempted the release→grant timing comparison on the surviving befva0857 trace (round 14, lost node1_f33.md5). Restricting to daddr=120 (dir block 0) captured ONLY P106-EXREL events (43 of them) — **NO P-DIRRD reads or P35E-DIRWR writes to daddr=120 in round 14**. Meaning: by round 14 the shared dir spans 3 data extents (P21H showed nextents=3) and the lost sidecar (node1_f33.md5) lives in a HIGHER data block, not block 0. Early rounds (sess69) lost block-0 entries (daddr=120); later rounds lose higher-block entries.

### So the timing experiment must target the lost entry's ACTUAL daddr
1. From `mxfs-drc-RDMISS round=N` get the lost name.
2. Find its data block daddr: grep P35E-DIRWR lines whose `names=[...]` list contains (the block just before/after) the lost name — P35E-DIRWR logs `daddr=... nent=N names=[. .. f1 f2 ...]`. The block whose name-range brackets the lost name's position is its daddr. (Or add a one-line probe at xfs_dir2_data add logging name→daddr.)
3. THEN merge P106-EXREL (release-done realns), P-DIRRD (cold-read realns+crc+fua), P35E-DIRWR (write realns+crc+nent) for THAT daddr across all 4 nodes by realns (wall-clock comparable) and check: does the clobbering owner's cold-read of that daddr precede a peer's P106-EXREL (Rank1 ordering) or follow it but still read short (Rank2 drain hole)?

### Observed EX-handoff cadence (round 14, block-0 EXREL waves): ~300ms-1.6s between release waves across the 4 nodes — heavy ping-pong, consistent with the 4-node contention amplifying the race.

### Reminder: per-run virsh reset REQUIRED (a FAIL wedges a node → next mkfs fails). See [[sess10run-REFUTED-fua_disable0-and-test-harness-wedge]] [[sess10run-HANDOFF-do-release-grant-timing-probe-next]].

### Status: criterion NOT met. Tree DE3A7E21 baseline, cluster clean+healthy (test1-4), test1-8 up.
