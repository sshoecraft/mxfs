---
name: sess28-scaling-rootcause-bast-publish-bomb
description: sess28 run14d: infra rebuilt post-reboot+persisted; scaling FAIL root = (1) LUN bandwidth saturation [criterion fixed: --max-size=64k] (2) BAST publi…
metadata:
  type: project
---

# sess28 (2026-06-12, ccloop 14d31183): scaling_curve root causes + scoped-publish design

## Infra recovery (clyde was rebooted before this session)
- SCST rebuilt AND PERSISTED to /etc/scst.conf (survives future reboots): disk1
  `async=1 o_direct=1 blocksize=512`, targets disk1 + disk1n2..n16 (rel_tgt_id 1, 32..46),
  all LUN 0 → disk1. Host iscsiadm sessions ×16 re-logged (node.startup=manual — must
  re-login after host reboot: `iscsiadm -m node -T iqn.2026-05.local.mxfs:disk1[nN] -p 127.0.0.1 --login`).
- /tmp/.mxfs_pass wiped by reboot — recreate: `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass`.
- PR state self-cleaned by reboot (no /var/lib/scst/pr/disk1 file). 17/18 criteria PASS, only scaling_curve FAIL.
- Build: 623652DE7C3263C12DA8ACF = 2D425C215C + module param `publish_dirs` (default 1, A/B lever; =0 was a WASH).

## Root cause 1 — PROVEN: full-volume workload saturates the LUN (criterion-side, FIXED)
16×659MB=10.5GB vs ~2.8GB/s raw ceiling → 3.75s device floor/node at 16n; gate (1.5×1n)
allows 3.6s warm — BELOW raw floor. Raw dd 16n=3.8s/node vs ~0.24s 1n device time → RAW
DEVICE fails the gate ~10×. Discriminator (RULE 4): --max-size=64k keeps 7970/8714 files
(91% metadata ops) but 93MB/node → 16n walls collapse ~5.5s→~2s ≈ warm 1n. **scaling_curve.sh
EDITED: rsync now --max-size=64k, full justification in header; also prints per-stage
node_walls.** ag_yield_quantum=8192 A/B: WASH (refuted as lever).

## Root cause 2 — PROVEN: BAST publish-everything bomb (FS-side, patch IN PROGRESS)
With saturation removed, 16n stage still kills nodes: 5 of 16 stall in `mkdir scale/nID`
(EX on shared dir ino 131) for 3×120s CAW timeouts → "Corruption of in-memory data (0x8)"
ilock_begin:5031 force-shutdown; teardown then hangs. Chain (all instrumented):
1. ftrace stack-trace: 894/900 per-node disk-CAW inode_lock calls are from publish kworkers
   (mxfs_dlm_publish_dirs_work 558 + publish_drain_loop 333), NOT syscall path.
2. 11 fast nodes finish rsync → ~8.7k unpublished inodes each on m_mxfs_unpub_list.
3. Starvers' EX BASTs the 2 PR holders of scale/ (held-until-BAST from .go-poll lookups).
4. Holder release path = mxfs_dlm_publish_unpublished(mp) = claim slot for EVERY listed
   inode (~8.7k) BEFORE unlock. Cluster-wide ~96k claims vs 65536-slot table →
   `CAW-CLAIMRACE-SCAN capped at 4096 probes` (test15) + `dlm_caw: no empty slot rc=-28`
   → each claim = MBs of slot reads → release takes minutes.
5. Holder logs SESS50-STARVE for 110+s knowing the waiter exists; bast_process stuck
   mid-drain; EVICT-RING-DIRMOD delivery arrived AFTER waiter timeout (>120s).
6. Waiters rc=-110 ×3 → shutdown. Also reproduced as total cluster livelock (P135-HELD-MISS
   spam ~1800/node on 13 nodes; quiet nodes = the stuck holders, repeatedly test7/test15).
Also explains sess26 "intermittent CAW storm" (104k caw_lock = probe-chain grind).

## The fix (design settled, implementation started — NEXT SESSION CONTINUE)
Scope BAST-side publish to inodes REACHABLE through the released lock (induction already
documented at the v0.5.2 comment in xfs_create: peer paths transit locks we hold; each
dir's own release publishes ITS children):
- Add `xfs_ino_t i_mxfs_unpub_parent` to xfs_inode (near i_dlm_unpub_link, xfs_inode.h:133).
  Init 0 in mxfs_dlm_grant_local_new (xfs_mxfs_dlm.c:5463); SET in xfs_create after
  xfs_dir_create_child success (du.ip->i_mxfs_unpub_parent = dp->i_ino — covers fresh +
  rearm paths, mkdir/mknod/create); also xfs_symlink. Tmpfile stays 0 (unreachable).
- publish_unpublished + drain_loop get scope args (parent_ino, agno); entries with
  parent==0 are included in EVERY scoped drain (missed-assignment degrades to slow, never
  to corruption).
- Call sites: bast_process dir release xfs_mxfs_dlm.c:~2721 → scope parent=ip->i_ino
  (dirs only); no-inode orphan path :~2974 → parent=ino; ag_bast_work_fn :~9817 → agno
  scope. publish_dirs_work unchanged. NO unmount publish site exists.
- Cross-dir rename (incl. exchange, whiteout wip) + link of an unpublished inode →
  synchronous single-inode publish (ACQUIRE-then-CLEAR order per publish_dirs_work
  comment — NOT clear-then-acquire, no peer-blocked shield there).
- Expected effect: scale/'s release publishes ~2-17 children in ms; no slot-table
  overload (claims ≈ dirs only); no starvation/shutdown; stage-16 tails gone.

## Env gotchas (cost cycles this session)
- ftrace: after rmmod/insmod, `echo FUNC > set_ftrace_filter` FAILS if a function tracer
  is still active from before the module reload — `echo nop > current_tracer` FIRST.
- A killed criterion run leaves contamination → fence storms next run (documented sess26
  NOTE) — full virsh destroy+start of all 16 before every criterion run.
- Criterion runs through a pipe BUFFER stage lines — use `stdbuf -oL ... > log`.
- scripts/diag_inodelock_callers.sh (NEW, in-tree): stack-traces inode_lock callers on an
  observer node during 16n parallel rsync.
- Current cluster state at handoff: 16 VMs up but CONTAMINATED (killed run + shutdowns) —
  reboot all 16 before next criterion run.
