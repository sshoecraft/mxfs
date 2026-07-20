---
name: sess-tcp-posix-multi-root-ifree-drain-wedge-holds-AG
description: ROOT (proven, per-create timing): posix_multi 2-node TCP stall = inode INACTIVATION (ifree of rm-rf'd recycled inodes) wedges 62s in mxfs_ail_drain_i…
metadata:
  type: project
---

## PROVEN root (build B77AD901, fresh format, RULE 4) — supersedes ping-pong theory
tests/repro_burst_timed.sh (per-create latency, concurrent same-dir 100/node):
- test1: ALL 100 creates fast (max 3ms, total 589ms).
- test2: **create #1 = 62028ms**, then 99 fast (total 62638ms). i.e. ONE create blocks 62s.
=> NOT per-create ping-pong; a ONE-TIME ~60s stall on a single lock acquire, then fine.

## The 62s is an inode-FREE drain holding the AG DLM lock
dmesg at the stall:
- test1: `P137-IFREE-TIME ino=2097382 force_us=137 drain_us=62569 flush_us=4` — the inode
  inactivation/free drain (`mxfs_ail_drain_inode_sync`, called from xfs_ifree path
  xfs/xfs_inode.c:2446, BETWEEN xfs_trans_commit and `out_unlock_ag: mxfs_ag_dlm_unlock`)
  took **62.5 seconds**. The log_force was fast (137us); the AIL drain (wait for the freed
  inode's cluster buffer to be written home) wedged 62s.
- test2: `DLM inode lock failed: ino=256 mode=5 rc=-110` — test2's allocation of a new inode
  (in the AG test1's ifree holds) timed out at the 60s MXFS_LOCK_WAIT_TIMEOUT_MS.
=> test1's inodegc inactivation holds the AG DLM lock across a 62s drain → starves test2's
   xfs_dialloc in that AG → -110 → create #1 blocks 62s → barrier desync → posix_multi FAIL.

## Why the drain wedges 62s
The freed inode's cluster buffer is orphaned in the AIL (IFLUSHING set / delwri-queued but
not written home). xfsaild does not destage it promptly — it is busy churning the contended
shared DIR inode (repeated `P78-FMT-TORN-FIX ino=<dir> comm=xfsaild/sda` every create + dir
buffer re-pinned each create => `DIR-STALE-SKIP pin=1` spam). The P136-DRAIN-RESCUE in
mxfs_ail_drain_inode_sync (xfs_mxfs_dlm.c:1271, fires iter>=512 ~0.19s) does NOT resolve it
(guards skip when the buf is on a delwri list / locked / not cleanly IFLUSHING), so it loops
~62s until the logjam clears. Same family as [[sess128-ailstuck-single-node-many-files-wedge]]
and [[sess43-dirdata-pin-rootcause]] P136, but here it is HOLDING THE AG DLM LOCK = cross-node
starvation, not just local slowness.

## TRIGGER
posix_multi (+cache_coherency) start with `rm -rf $D` → frees ~200 inodes → async inodegc
inactivation → recycled by the new create burst → inactivation drain collides with the burst.
30-file tests (zero_silent_loss) don't pile enough inactivations to wedge. Refutes
[[sess-tcp-dir-lostupdate-is-multiblock]] (dir converges fine) and the pure-deadlock idea
(at hang-freeze NO test task is kernel-blocked — the holder is mid-drain/inodegc, peer S-waits).

## NOT fixed by inode_mht_ms (REFUTED): raising 50->3000 still FAILs (iter1 138s). Reset to 50.

## FIX DIRECTIONS (next)
1. Don't hold the AG DLM lock across the 62s wait: the freed dinode (mode=0) durability for a
   peer realloc is the invariant — but it could be satisfied by ACTIVELY destaging THIS inode's
   cluster buffer (bounded, process ctx, NOT BAST kworker so sess113 hazard differs) instead of
   passively waiting for xfsaild. Make the ifree drain submit the delwri-queued cluster buffer
   itself (or fire P136 rescue earlier + handle the delwri-queued case) so it completes in ms.
2. OR ensure xfsaild isn't starved by the dir-inode churn (the P78 re-flush loop).
3. Verify with tests/repro_burst_timed.sh: test2 create#1 should drop from 62s to <1s.
Tooling: repro_burst_timed.sh (per-create ms), catch_hang.sh, repro_pm_timed.sh, repro_pm_loop.sh.
Reset cluster: tests/setup/reset2_tcp.sh (a wedge can leave umount D-state in xfs_buftarg_drain
→ virsh destroy+start, [[reference-node-power-control]]).
</body>
