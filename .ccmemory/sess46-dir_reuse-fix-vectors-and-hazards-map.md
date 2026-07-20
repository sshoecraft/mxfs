---
name: sess46-dir_reuse-fix-vectors-and-hazards-map
description: sess46 fix-vector map for dir_reuse leaf-hash hole: every direct intervention has a known hazard (clobber/unsafe-abort/corruptor-class). The safe fix…
metadata:
  type: project
---

## sess46 — dir_reuse_coherency leaf-hash hole: FIX VECTORS + their HAZARDS (so next session doesn't re-loop)

Root: [[sess46-PROVEN-dir_reuse-leaf-hole-is-async-evictring-lag-stale-leaf-RMW]]. node1's dir LEAF buffer ends up **in-AIL/pinned AND stale** (buf_gen=0 < inode_gen, missing node2's last ~15 entries). Reader-path `mxfs_dlm_dir_consumer_refresh` (xfs_mxfs_dlm.c:2470) → `mxfs_dir_evict_data_blocks` **deliberately SKIPS in-AIL/pinned blocks** (line 2540-2544: "leave evicted_gen behind so next read retries once durable") — but node1's leaf never becomes durable-and-droppable, so it's served stale forever. Verify lookup is **lock_flags=0** so it SKIPS the slow-path acquire (no gen-bump, no eager drain-evict) — sess43 comment xfs_mxfs_dlm.c:5096.

### EVERY DIRECT INTERVENTION HAS A KNOWN HAZARD (all mapped, all dead-ends as-is):
1. **Destage node1's in-AIL stale leaf** (force AIL push / log force / direct write): CLOBBERS node2 — writes node1's version (missing f36-50.md5) over node2's superset on the LUN. The whole P34/relflush machinery AVOIDS this.
2. **Discard node1's in-AIL leaf** (xfs_buf_stale + abort BLI, re-read LUN): UNSAFE — sess26 GPT consult: "never manually abort a DIRTY/in-AIL BLI." Risk log/AIL corruption → shutdown. (sess26 fix only stales CLEAN ABA buffers.)
3. **Write-side suppress stale leaf write** (extend mxfs_buf_xfsaild_skip_dir_write gen-arm): KNOWN CORRUPTOR CLASS — the tenure-mismatch arm (xfs_mxfs_dlm.c:15778-15793) is DETECTOR-ONLY because buf_gen=0/unstamped on a LEGIT fresh leaf write → suppressing drops the whole leaf (sess23 "suppression-was-corruptor"). The existing safe arms: NL-released + ABA(b_mxfs_dir_incarn != live gen). My case is CURRENT-incarnation, EX-held → neither fires.
4. **force_block=1**: fixes dir_reuse but BREAKS dlm_fairness+cache_coherency (shutdown). REFUTED sess44. User forbids flag-flip.

### THE REAL FIX IS UPSTREAM (prevent the stale-base RMW), per sess43/44:
node1's create-wave RMW built the leaf on a base missing node2's f36-50.md5 (durability race: node1 re-read node2's leaf before node2's write hit the platter; OR node1 fast-path acquired without eager-evict). To fix: node1's dir-insert RMW must use node2's CURRENT DURABLE leaf. Candidates (instrument, don't blind-patch):
 (a) Confirm Invariant #1 is VIOLATED for the leaf at the LATER release (P34-LEAF-DRAIN was clean at an EARLY release, but the leaf is in-AIL at verify → a later release didn't destage it). If so, fix the release-side leaf destage for that path.
 (b) sess43 conclusion: dir WRITES must be platter-durable (FUA-write/per-op flush) BEFORE release so the acquirer's FUA-reread sees them — NOT a refresh mechanism. ANY refresh misses own target-cached writes (the dual constraint).
 (c) Make the lock_flags=0 verify lookup/readdir take a real coordinated acquire so it eager-drain-evicts (but that still skips in-AIL → needs (a)).

### MISSING DATUM (get FIRST next session): is the LUN leaf CORRECT (read-side staleness → node1 just needs to re-read) or CORRUPTED (write-side clobber → node1 wrote stale over node2)? Run with `MXFS_EXTRA_MODARGS='dirwr=1'` → P-LEAFWRITE tag=CLOBBER (buf_cnt<disk_cnt) fires on a clobbering write; P-RELFLUSH shows release-flush; P56. sess46 launched this (bg task, /tmp/full_run_dirwr_*.log + /tmp/dfollow.log). If CLOBBER fires → write-side; if only read-side stale (no CLOBBER, LUN correct) → the fix is getting node1 to re-read (vector a/c + handle in-AIL safely).

### REPRO: dir_reuse FAILS only CUMULATIVELY (passes standalone clean-prep). Need full `./run.sh 2 tcp` (no args) after clean virsh reboot. Fails round 1 (fresh dir) due to a stale cached block at a daddr reused from a PRIOR test. 3/3 full runs fail. Capture: `systemd-run --unit=dmesgcap --collect bash -c 'dmesg --follow > /tmp/dfollow.log'`. KEEP sess45 partial-iwrite fix; build EF006296 unchanged this session.</body>
