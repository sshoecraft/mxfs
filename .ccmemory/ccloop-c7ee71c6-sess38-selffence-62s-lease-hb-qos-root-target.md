---
name: ccloop-c7ee71c6-sess38-selffence-62s-lease-hb-qos-root-target
description: sess38 last: self-fence reframed — hb failed to land for FULL 62s lease (default; param=0); root target = hb FUA write / shared ctx->lock stalling un…
metadata:
  type: project
---

# D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE — sharpened root target (sess38 close)

## Established by code read + deployment check
- Deployed lease_timeout_ms=0 → compile default **62s** (disklock.h MXFS_DISKLOCK_DEAD_THRESHOLD=31 × 2s; xfs_super.c:2010 comment says test rigs "set e.g. 15000" — OURS DOESN'T).
- So test21's hb was failing to land for ~62s (from ~57111, spanning most of rsync_paired) — the P15-REL-ABORT loop (57169+) was a LATE CO-SYMPTOM, not the cause. Fence was CORRECT behavior.
- hb thread (dlm/disklock.c:264 disklock_hb_fn): per 2s cycle does write_sector_fua of own slot UNDER ctx->lock (342-343) + monitor scan reading ALL peer hb sectors under the SAME ctx->lock (374+). One cycle at 32 nodes = 1 FUA write + 32 reads through the one saturated LUN, no I/O priority.
- Candidate mechanisms for a 62s outage: (a) single hb FUA write stuck in device queue (LIO under storm; SCSI timeouts/retries can be 30-60s); (b) ctx->lock held by a stuck monitor READ (same queue) blocking the writer; (c) hb thread starved of CPU (unlikely — kthread).

## Next loop (RULE 4)
1. Instrument hb cycle: log when a cycle's write latency > 2s (write_ms, monitor_ms, cycles_missed) — unconditional, rare by definition. Also stamp last-successful-write age into the P-existing fence path so a self-fence names its own outage duration.
2. Reproduce: board-load mix while watching the new cycle-latency probe (no knobs needed).
3. Fix shapes (GPT first): move monitor reads OUT of ctx->lock (they don't need the write mutex); hb write with REQ_PRIO / front-of-queue; consider lease_timeout_ms=15000 for the rig (per the code comment) — but the PRODUCT defect is hb QoS under saturation, not the lease length.
4. Board-watch: the P83-UNL-RELOAD canary (AGI defect) is also standing in 323.
