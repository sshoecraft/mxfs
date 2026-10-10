---
name: compiled-drbd-concurrent-writes-oracle-fence-handler-resume-io-ftrace-timing-and-lun-pool
description: DRBD 8.4 dual-primary diagnostics: concurrent-writes oracle, fence-handler resume-io RCU fix, private ftrace timing, clyde LUN pool sizing
metadata:
  type: project
tags: [compiled, drbd, ftrace, lun-pool, fencing, diagnostics]
---

Shared topic: instruments and rig facts for MXFS on DRBD 8.4 dual-primary (nested PVE pairs, physical PVE hosts) and the clyde test-LUN pool. The first three are DRBD-pair diagnostics; the last is a clyde rig reference.

## Concurrent-writes oracle
Source: [[technique-drbd-concurrent-writes-detected-names-two-hosts-writing-one-sector-map-it-with-chk-mxfs-geometry]]

- DRBD 8.4 two-primaries logs `Concurrent writes detected: local=<s>s +<len>, remote=<s>s +<len>` on both hosts when peer and local writes overlap in flight. Sectors are 512-byte sectors of /dev/drbd0, lengths in bytes. For a correctly coordinated cluster FS it must never appear: a holder's write must complete before the grant moves. One line proves a host published bytes without write tenure. Zero cost, no MXFS instrument.
- It is also a stability defect: on the 0.90.92 nested pair, four conflicts in 5 s were followed by `ASSERTION req->rq_state & RQ_NET_PENDING FAILED in __req_mod`, `BAD! BarrierAck`, Connected -> ProtocolError, and a tie-break loss that restarted a participant. Defect record D-DRBD-BOTH-HOSTS-WRITE-ONE-DINODE-AT-ONCE-AND-DRBD-DROPS-THE-LINK.
- Mapping a sector: `chk_mxfs --geometry /dev/drbd0` (safe on a mounted host) gives xfs_data_offset, agblocks, agblklog, inopblog, blocksize, inodesize. daddr = sector - xfs_data_offset/512; fsblock = daddr/(blocksize/512); agno = fsb/agblocks; agbno = fsb%agblocks; for a dinode agino = (agbno << inopblog) + offset in block, ino = (agno << (agblklog+inopblog)) | agino. Confirm with `dd ... iflag=direct | od`: MXFS dinodes start `4d 4e`. Use MXFS tools, never xfs_db.
- Counting: `journalctl -k -b <n> | grep -c 'Concurrent writes detected'` per boot per host; zero is baseline (physical pve2: zero in 70 boots through 0.90.92).
- It appeared under shared-directory churn (tests/pve_churn_fairness.sh) with the ftrace function profiler (tests/pve_pair_profile.sh) running; the same churn unprofiled logged none. Timing perturbation widens the race; a race only timing hides is still the defect.

## Fence handler must resume I/O itself
Source: [[technique-drbd-84-fence-handler-resumes-io-itself-to-avoid-the-rcu-sleep-warning]]

- With `fencing resource-and-stonith`, a Primary that loses its link freezes I/O (susp_fen=1, NEW_CUR_UUID). If the fence-peer handler exits 4 or 7, DRBD 8.4 after_conn_state_ch calls drbd_uuid_new_current() inside rcu_read_lock(); the metadata write sleeps -> `Voluntary context switch within RCU read-side critical section!` (WARN_ONCE per boot) and RCU grace periods stall on the md write. Seen on Proxmox 6.17 (drbd 8.4.11) and Ubuntu 6.8. Exit 3 and 5 set pdsk <= Outdated too, so no exit code avoids it.
- Fix (0.90.89, tools/mxfs_drbd_fence_self.py resume_frozen_io): after the peer is excluded, run `drbdadm resume-io <res>` from the handler BEFORE exiting 7. It does the same rotation under adm_mutex without RCU, clears susp/susp_fen; the exit code then only records pdsk Outdated. Verified on the nested pair: susp 1 -> 0 8 ms after the decision, no warning, peer resynced as SyncTarget.
- Only safe on the lost-link path: that handler runs on DRBD's own `drbd_async_h` kthread. A promotion runs the handler synchronously inside `drbdadm primary` under adm_mutex; resume-io there deadlocks. Never call it for a node that is not Primary. Bound the child wait with Popen+poll; subprocess.run(timeout) kills then waits and can hang on a kernel-stuck child.
- Test on a fresh boot: WARN_ONCE means a host that already printed it proves nothing. Restart the excluding host first (tests/pve_fence_rcu_check.sh).

## Timing a module function on a live host
Source: [[technique-time-a-module-function-on-a-live-host-with-a-private-ftrace-instance]]

- Private ftrace instance, no kernel-log lines, global tracer untouched: mkdir `/sys/kernel/tracing/instances/<name>`; write the filter; `buffer_size_kb`; set `current_tracer` to function_graph FIRST; only then `funcgraph-tail` (funcgraph-* options do not exist until function_graph is current -> Invalid argument); toggle tracing_on; read `trace`; reset to nop and rmdir. Durations in us on the closing `}` line or on leaf lines. Needs PVE 9's 6.17; clyde's 6.8 is not known to support instance function_graph. tests/pve_pair_write_bound.sh prints p50/p90/p99/max on both hosts. Idle nested pair: one cas_emulate swap 10-12 ms.
- Long workloads, many functions: tests/pve_pair_profile.sh (function profiler, trace_stat/function<cpu>, plus slow calls via tracing_thresh). Traps:
  - Writing NAMES to set_ftrace_filter costs ~7 s per name on pve1 (29 names = 196 s, overran the ssh timeout). Write LINE NUMBERS from `available_filter_functions` instead (`awk ... {print NR}`); milliseconds.
  - The profile table hides functions whose mean is below `tracing_thresh` at read time; zero the threshold while reading.
  - A local `timeout` on ssh ends only the client; the remote setup kept running and left pve1 tracing. Give the remote command its own `timeout`.

## Clyde test-LUN pool
Source: [[reference-test-luns-come-from-the-pool-tools-lun-pool-sh]]

- Since 2026-10-01 every clyde test LUN is borrowed from tools/lun_pool.sh (fixed disk.img / disk-grp / disk-plat LUNs and scripts/rig_groups.sh, scst_platform_targets.sh were deleted). Images ~/disks/pool/lunNN.img, SCST device mxfspoolNN, LUN 0 in ini_group `alloc`. Allocations are pid-owned, kept bound after the owner exits, and adopted by the next alloc of exactly that node set; released when a new alloc overlaps its nodes or oldest-first when none is free. Subcommands: `up` after host reboot, `snapshot <id> <label>`, `create <count> <size>`.
- Pool size: 8 was too few (6 board groups + 4 platform sets + yardstick; debian13 got "no pool LUN for its verification set"); 12 x 20G from 2026-10-01; 11 since 2026-10-02 because / reached the preflight's 88% gate and every release board aborted. When short, `create` more within the 120 GB free / 88% floor; do not route around the pool.
- run.sh borrows a LUN after taking locks and exports MXFS_LUN_WWID / MXFS_HOST_IMAGE_PATH / MXFS_POOL_LUN. MXFS_LOG_SLICES defaults to 2N (<=8 nodes, 20G), 32 on 80G (<=16), 32 on 144G beyond. Measured: 20G at -n 32 = 9 AGs; at -n 16 = 19; the AG cap comes from the log slice count, not AG size.
- Groups g2/g4/g8 + g2b/g4b/g8b (test15-28); tests/full_verify.sh and tests/board_4node_chain.sh run side by side on them. mpath/pass attachments have no LUN; data/rigs.json scst-fio has "pool": true and no lun_wwid.
