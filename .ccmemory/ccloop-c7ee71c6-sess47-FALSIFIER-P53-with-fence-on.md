---
name: ccloop-c7ee71c6-sess47-FALSIFIER-P53-with-fence-on
description: sess47 tail: P53 FIRED WITH FENCE ON (cycle-7 lap-1 wave, 23 nodes, all idempotent-absorbed, 0 shutdowns) — fence arm incomplete; leads: unfenced coh…
metadata:
  type: project
---

# FALSIFIER RESULT — inocl_fence did NOT stop the fossil producer (0.11.377)

## Event (sess47 tail, ~23:04 host time)
Soak cycle 7 lap 1 (hostload burst 40): P53-IUNLINK-MISMATCH wave across many nodes (test10=10 pairs, test9=8, ~23 nodes with hits), **fence=1 active**. ALL absorbed by P53-IUNLINK-IDEMPOTENT (old_ptr==next_agino alignment) — ZERO shutdowns, zero -117. Same fossil signature: old_ptr = agino-1 serial-churn value, expected NULLAGINO. Lap 2 (post-260s-idle) then FAILED 24/32 (8 nodes × 3/6 checks) with P5N-AG-ORPHAN-NAK stranded-AG on test1 + massive "heartbeat received from unknown node 2116408489" spam (test1=321 lines; test1 was crash_consistency's victim ~22:45, up 1h13m at check).

## Rings banked BEFORE recovery
test9:/root/cycle7_test9_*.dmesg, test10:/root/cycle7_test10_*.dmesg (+ earlier test2:/root/transcommit_incore_1785706689.dmesg for the fatal form).

## Verdict + leads (next session's RULE-4 targets, in order)
1. **Unfenced read path**: the coherent re-read machinery — mxfs_buf_is_multinode_dir_meta (pal/linux/xfs_buf.c ~1130) INCLUDES xfs_inode_buf_ops; its raw medium re-read (CRC-retry path, "straight from the shared medium") and the P34D-RELOAD src=plain dinode reads BYPASS xfs_buf_read_map where the fence lives. If those paths DMA a stale image over b_addr, the fence never runs. Instrument: stamp-check + P-INOCL-COLDREAD sibling in the raw re-read path.
2. **Crash/rejoin correlation**: wave nodes were 5h-up peers; test1's crash_consistency death+rejoin (+321 unknown-node lines, P5N stranded AG) preceded the wave by ~17min. FOREIGN-REPLAY-UNGATED-IMAGES (open critical) could regress cluster images during slice replay — elevated as producer arm. Check test9/test10 rings: any replay/fence/rejoin events between crash (t≈uptime-35min) and the t≈18341 wave.
3. The idempotent carve-out is currently the ONLY thing between this producer and mass shutdowns (all 10+8+... events absorbed). sess53's masking warning is now operationally live — do NOT remove the carve-out, but every absorbed pair = producer still alive.
4. rsync-paired lap-2 8-node failure likely membership/stranded-AG collateral (P5N), not data loss — but verify from the run log leftovers before re-prep (leftovers at /tmp/mxfs_run_* on clyde or run.sh's fail detail).

## Rig state at handoff
0.11.377 ship config; 32/32 mounted BUT test1 has stranded-AG NAK spam + cluster has rejoin churn — re-prep before precision testing (rings already saved). inocl_fence stays 1 (harmless, may cover a real minor arm). D-RSYNC-RENAME-361: OPEN, arm INCOMPLETE — do not promote.
