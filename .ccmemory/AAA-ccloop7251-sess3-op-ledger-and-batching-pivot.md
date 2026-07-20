---
name: AAA-ccloop7251-sess3-op-ledger-and-batching-pivot
description: sess3 KEY: per-file DLM op ledger measured (kprobes); 5 shave-fixes landed 0.11.12-15 all flat; budget math forces batching pivot; GPT consult sent
metadata:
  type: project
tags: [perf, dlm, dir_reuse, kprobes, architecture]
---

# ccloop 72513a13 sess3 — the op-count wall (dir_reuse perf campaign)

## Methodology that finally worked (REUSE THIS)
kprobes on PAL I/O primitives, cluster-wide, windowed by the DRCph phase markers:
```
echo "p:k_read mxfs_pal_bdev_read_prio" >> kprobe_events   # every slot read is FUA via this
echo "p:k_fua mxfs_pal_scsi_read_fua_bdev" >> kprobe_events
echo "p:k_caw mxfs_pal_bdev_compare_and_write" >> kprobe_events
echo "p:k_sleep mxfs_pal_sleep_ms ms=%di:u32" >> kprobe_events  # arg capture!
echo "stacktrace" > events/kprobes/k_read/trigger   # caller attribution
```
ftrace *function tracer* does NOT work on mxfs.ko (no fentry) — kprobes DO.
mxfs_pal_bdev_read_prio == SCSI READ(16)+FUA passthrough always (block trace shows rwbs 'N' zero-sector — passthrough, NOT flushes).

## Measured ledger (8/cawd, 800 entries/round)
- create 6-9s: 100 creates on a node = ~1763 FUA reads (was; now ~1/3), 4.6s/6s was acquire-poll sleep → fixed by UDP grant nudge, phase UNCHANGED (it's tenure-rotation queueing on dir EX, 56 rotations × (batch + 5-50ms release drain)).
- verify 4-13s: per foreign cold stat = PR claim CAW + ~3 FUA reads + PR release CAW. Cluster ~27k cmds.
- rm 6-9s: per unlink ~11 FUA + 2 CAW (find, grant-wait, p87 verify readback, second acquire in xfs_inactive (fixed: demote suppressed for nlink==0), unlock/tombstone) + cross-node PR revoke per file.
- gap 3.1s/round: post-rm sync (AIL of 800 frees) + mkdir + MQTT barriers (barriers are fast).
- idle node: ~80-130 SCSI cmd/s = bast_poll (256 slots individually/sweep, relax was 1000ms → now 4000) + heartbeat + worker.
- LUN cmd ≈ 0.25-0.5ms. Round ≈ 60k cmds at 8 nodes — DEVICE-OP-AGGREGATE BOUND.

## Landed 0.11.12→0.11.15 (all correct, all ~flat on round time)
1. span probe reads in find_slot_skip (16 slots/1 FUA read) — dlm_caw.c.
2. P125-AG-DIVERGE assertion behind knob p125_ag_diverge (was 5.3 FUA/create via xfsaild).
3. dir-EX serve held-verify: CAW-only 100ms throttle + ONE shared rawmode snapshot (sess6 counters + p42 + sess107 enforce reuse it) — restored throttle a TCP session dropped.
4. i_dlm_heldchk_j stamped AT GRANT → p108/dir-verify/cluster_durable auto-skip fresh grants (fresh-inode one-shots were paying ~2 walks each).
5. UDP GRANT NUDGE: MXFS_GRANT_MAGIC on bast mcast socket; senders = unlock_gen success with waiters + self-grant with remaining waiters; receivers bump nudge_seq + cond_broadcast; caw_acquire_poll_sleep → caw_nudge_prepare/caw_nudge_wait (PAL condvar; signal-pending guard). Poll sleeps 4.6s→~6ms proven.
6. close-demote suppressed for i_nlink==0 (0.11.11 demote made rm SLOWER — inactive re-acquired from scratch).
7. p87 grant-persist readback: INODE sampled 1/64, AG always.
8. BAST_POLL_RELAX 1000→4000ms.
9. pr_idle_release_ms=400 A/B'd at runtime: rm barely moved (revoke wasn't rm's floor). Left at 0 default.

## THE WALL (why shaves don't matter)
Budget: 32 nodes, 24 rounds ≤120s → 5s/round → ~16k device cmds/round TOTAL → ≤1.5 ops per file-touch. Floors today: claim CAW + release CAW + cluster FUA read = 3 ops minimum per touched file per phase. GRANULARITY MUST CHANGE (batching):
- Option A: per-INODE-CLUSTER (ino>>5) on-disk resources (matches existing invalidation granularity = cluster buffer!) → create/verify/rm claim ~25 locks not 800.
- Option B: dir-covered lock-less reads + child-EX summary count in dir slot → verify = 0 CAWs + ~25 cluster FUA reads.
- GPT consult (RULE 5) sent with full evidence — task k1ud3n6hg. Check the answer, design, implement.

## Watch-outs
- 0.11.11 write-once demote (ex_close_release_ms=250) helps cross-node stat (6.1→4.4ms) but invalidates creator cache + costs 52ms drain/file under load; NO net dir_reuse win. Reconsider defaults after batching.
- rm ALSO pays: peers' 800×7 PR demote storms when reaper off; with cluster-granularity these become 25×7.
- Solo create ~5-7ms/file (native ~0.3): even zero-contention path needs the batching.
- dir_ex_verify per-serve on CAW was ~4.8 FUA/create before throttle (sess-tcp had dropped the throttle for TCP-cheapness reasons).
- clyde load: kill stray ugrep/etc from prior sessions (found one at 1201% CPU grepping /proc).
