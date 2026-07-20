---
name: sess26-storage-infra-pernode-sessions
description: sess26 run14d: SCST infra rebuilt — disk1 dev (async+o_direct), 16 per-node iSCSI sessions/targets, PR fencing now REAL. scaling 569%→171%.
metadata:
  type: project
---

# sess26 (2026-06-11, ccloop run 14d31183): storage infra rebuild + scaling_curve truth

## What changed on clyde (HOST config — persists, but know how it was built)
1. **disk1b is DEAD — cluster now runs on SCST device `disk1`** (same backing file
   /home/steve/disk-1.img, now fully fallocated 20G). disk1b had a stale PR
   (key 0x43356bc, WERO) from a dead host-nexus ISID that NO initiator could clear,
   plus 46 zombie iscsi-scst sessions stuck in `closing` with undrained commands
   (cleanup threads in D-state msleep loop in close_conn). Those zombies are STILL
   THERE until clyde reboots (user's call, RULE 2). Do not log into disk1b.
2. **disk1 recreated with `async=1; o_direct=1`** (vdisk_fileio, write_through=0).
   Root cause proven: buffered pwrite to one backing file serializes ALL nodes on
   the file inode's i_rwsem → aggregate ceiling ~930MB/s. With async+o_direct:
   ~2.8GB/s (NVMe-bound). Raw 16-node parallel dd: 10.5s → 3.8s per node.
   o_direct is a CREATE-TIME param (sysfs attr read-only): del_device/add_device
   `echo "add_device disk1 filename=...; async=1; o_direct=1" > /sys/kernel/scst_tgt/handlers/vdisk_fileio/mgmt`.
3. **16 per-node iSCSI sessions**: targets `iqn.2026-05.local.mxfs:disk1` (test1)
   + `disk1n2..disk1n16` (test2-16), all LUN 0 → device disk1. Host (clyde) logs
   into all 16; each VM XML's shared LUN points at its own by-path device.
   Previously ALL 16 VMs shared ONE host session → one I_T nexus, one QD-32 queue,
   one 8-thread SCST pool → no real per-node PR fencing, serialized queue.
   **NOTE: /etc/scst.conf NOT updated** — runtime config only. After a clyde reboot
   the disk1n2..16 targets + LUN mappings + async/o_direct flags must be re-created
   (or scst.conf updated). iscsiadm node records exist (auto/manual login on boot
   varies). VM XMLs ARE persistent (virsh define'd).
4. **multipath**: /etc/multipath.conf now blacklists vendor SCST_FIO (mpatha was
   assembling all 16 paths; nothing used it).
5. **PR fencing is now REAL**: each node = distinct nexus, registers its own key
   (key=node_id), WERO reservation enforced. With the old shared nexus this was
   theater. Consequence: stale-epoch nodes (e.g. after a mid-run script kill +
   re-mkfs without reboot) get legitimately fenced → `heartbeat write failed: -52`
   (EBADE) → shutdown. ALWAYS full virsh destroy/start of all 16 before criterion
   runs after any aborted run.
6. Workload tree /root/open-gpu-kernel-modules (659M, 8714 files) **staged on
   test5-16** (was only on test1-4 — all prior "16n" numbers had 12 no-op writers).

## scaling_curve truth (build 2D425C215C v0.5.5)
- Honest 16-writer baseline pre-infra-fix: 1n=2470 2n=3671 4n=4304 8n=8435 16n=14072 (569%).
- Post infra fix: 1n=4037 2n=4259 4n=4378 8n=4380 16n=6928 (171%, gate ≤150%).
  Curve FLAT 1→8n; failure isolated to 8→16 + outliers. 1n regressed 2470→4037
  (o_direct per-op latency; paired ratios stay fair since xfs+mxfs share the LUN).
- Profile (16 real writers): per node ~850 mxfs_v5_dlm_inode_lock disk-CAW acquires
  (≈ one per created dir; files use unpublished fast path), avg 2-5ms each
  (≈1×caw_slot 0.7-2.4ms + ~3×read_slot ~0.5ms). caw_wait_for_grant rare (1-4/node)
  but 34-735ms each — peer-handoff latency = wall variance.
- **Intermittent CAW storm**: one node hit 104k caw_lock calls / 110k FUA reads /
  22.2s wall (vs ~850/5.2s normal); avg 200µs/call = NOQUEUE-style single-read
  failures in a hot loop. Storm NOT from inode_lock (count normal). Suspect
  ag_lock_nb trylock loop or similar. NOT yet root-caused.
- Stack sampling: rsync blocks in xfs_trans_commit → mxfs_trans_drain_ag_unlocks →
  mxfs_ag_dlm_unlock → sync xfs_log_force (xlog_wait_on_iclog / CIL flush) +
  drain_alloc_buflist iowait — the yield-quantum EAGER SYNC DRAIN every 512 trans
  fires with zero peer contention, in syscall context. A/B pending:
  module param `ag_yield_quantum` (NOT mxfs_ag_yield_quantum) = 8192.
- Host CPU peak 18% during 16n → CPU oversubscription REFUTED. agcount=20, dirs+files
  both node-affine (slot%maxagi) → AG-sharing-by-geometry REFUTED.

## Gotchas
- diag_vnop_profile.sh / diag_stacksample.sh: MXFS_SET_PARAMS uses /sys/module/mxfs/parameters/<name> — use PARAM names (ag_yield_quantum), not C symbol names.
- showstat criteria count = 19 (posix_semantics runs twice: _single + _multi16).
- A killed criterion/profile run leaves the cluster contaminated → next fresh_cluster_mount may fence stale nodes (see 5). Reboot first.
