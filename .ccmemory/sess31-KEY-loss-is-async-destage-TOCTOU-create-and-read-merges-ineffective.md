---
name: sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective
description: sess31 KEY: dir_reuse loss is an async-xfsaild-destage TOCTOU. dir_merge=1 AND addname_coherent BOTH ineffective (snapshot stales before destage). wr…
metadata:
  type: project
---

## sess31 — narrowing the dir_reuse single-dirent loss (tested against the reliable round-1 repro)

### Confirmed mechanism (fresh P-WMERGE, dir ino=131)
`P-WMERGE disk_extra=1 incore_extra=1 held_mode=EX in_ail=1 bgen=0 kind=data MERGE-NEEDED` — an EX-holder (test5) async-destages an in-AIL dir-DATA block whose stale base (bgen=0) is missing a peer's durable add (node1_f4.md5) → reverts it. P25-RELVERIFY-MISMATCH=0 (every EX *release* is coherent) → the block goes stale AFTER release / during the reacquired tenure, and xfsaild destages it later.

### TESTED INEFFECTIVE this session (against the round-1 repro, params confirmed applied)
- **`dir_merge=1 dir_force_block=0`** (mxfs_dir_merge_peer_into_tp — the transactional union-merge that re-adds missing peer dirents via xfs_dir_createname, handles leaf/freeindex/freespace): STILL loses node1_f4.md5 at round 1 (799/800). No shutdown. wall=499s (slow — reads all dir blocks per create). → a CREATE-TIME merge cannot close the window: the peer's add lands durably AFTER our merge snapshot but BEFORE our async destage.
- **`dir_addname_coherent=1`** (read-side FUA reread at addname): sess28 already showed ineffective; it's CLEAN-only (skips the in-AIL block which IS our failure case).

### TESTED HARMFUL
- **`dir_write_merge=1`** (destage-time data-only graft): bnobt double-free SHUTDOWN (ltbno+ltlen>bno). Closes the TOCTOU window but corrupts free-space btree (no transactional leaf/freeindex update at the bio chokepoint).

### THE ARCHITECTURAL CONCLUSION
The clobber is an **async xfsaild destage TOCTOU**. Read-side and create-time merges snapshot too early; destage-time graft can't be transactionally consistent. So neither merge approach can fix it. The fix must be one of:
1. **Never async-destage a multi-node dir DATA block** — dir DATA blocks may only be written SYNCHRONOUSLY at EX release (where we hold EX, coherent), and their in-AIL items must be fully drained at release, NOT lazily by xfsaild in a later reacquired tenure. (Closest to GFS2/OCFS2 glock-release semantics. Biggest, most-correct change.)
2. At the xfsaild destage chokepoint, if disk_extra>0 (FUA read shows we'd revert a peer), DEFER the destage and force a coherent reacquire+transactional re-apply of our delta (incore_extra) onto the fresh disk base — i.e., move the union-merge to fire AT destage TOCTOU instead of at create. Needs a transaction, so the destage must bounce to a worker that holds EX and re-applies.

### Reliable repro (for next session)
Reboot 8 nodes, then: `MXFS_EXTRA_MODARGS="<modargs>" MXFS_TEST_ENV="DRC_ROUNDS=8" timeout 520 ./run.sh 8 tcp dir_reuse_coherency`. Loss = round 1, node1_f4.md5, 799/800, ~1 in 2 runs. Capture clobber with `dir_writeprobe=1` → P-WMERGE in `/root/drc_create_r1_rank<N>.dmesg` (CREATE-phase snapshot). run.sh reuses the mount → MUST reboot to apply insmod modargs (no `mxfs.` prefix).

### Standing: 1/2/4 tcp = 100%; 8/tcp = 2/3 (only this loss). [[sess31-DECISIVE-round1-standalone-repro-confirms-sess28-mechanism]] [[sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness]]
</body>
