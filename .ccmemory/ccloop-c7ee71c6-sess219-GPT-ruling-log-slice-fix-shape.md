---
name: ccloop-c7ee71c6-sess219-GPT-ruling-log-slice-fix-shape
description: sess219 RULE-5 ruling (gpt-5.6-sol) for D-LOG-SLICE-SHARED-MULTIWRITER: dual-layer guard, REMOVE modulo (identity+checked helper), mkfs error-not-cla…
metadata:
  type: project
---

# sess219 GPT ruling — log-slice sharing fix shape

Defect: D-LOG-SLICE-SHARED-MULTIWRITER (sess218 root: mkfs default -n 4, 32 nodes, slice = slot % 4 ⇒ 8 writers/slice).

## Ruling (gpt-5.6-sol)
1. **Dual-layer guard**: (a) disklock slot ADMISSION constrained to slots [0, log_node_count) — slots are per-LUN so allocator may only consider first N slots; never remap. (b) kernel re-checks slot < log_node_count at slice selection AND foreign replay — protects vs stale userspace/mixed versions/corrupt metadata. Late-guard mount failure must release the claimed slot on every failure path.
2. **Remove `%` entirely** from all log-addressing paths — one checked helper `slice = slot` after `if (slot >= log_node_count) return -EINVAL`. Callers: own mount (xfs_mount.c:1040), foreign replay (xfs_log.c:811), fence intent (v5_mount.c:1072), stale clearing, unmount, debug.
3. **Validate geometry in kernel** too: count==0, >64, >max_nodes, slice min size, overlap/overflow — don't trust mkfs alone.
4. **mkfs**: required_logblocks = count*16384 (+overhead); build geometry to satisfy or FAIL with required-vs-available numbers; never shrink after sizing; audit/remove the 65536 aggregate clamp; check log AG can hold contiguous region. Unify semantics: effective admission max = slice count (max_nodes vs log_node_count must not diverge confusingly).
5. **Foreign replay ordering**: fence → recovery ownership → READ-ONLY scan/validate → replay → stale-clear. NEVER xlog_clear_stale_blocks after find_tail corruption/-EIO — preserve the slice as evidence. Slot-reuse race: replacement node must not log while old incarnation's recovery in progress (slot incarnation/lease gen).
6. **Legacy FS**: 32-on-4 filesystems corrupt-by-construction in ALL slices; reformat is the only defensible disposition; prior crash_consistency results invalid for them. Future: persist highest-slot-ever-admitted / unsafe-aliasing flag durable BEFORE first journal use.
7. **Mixed-version gate**: old kernel can still modulo-map — needs incompat bit / proto capability. (Note: count==max_nodes makes modulo==identity for all valid slots, which de-fangs old kernels on NEW FSes; gate still owed for small-count FSes.)
8. **Bounded retry/escalation** for unreplayable slice = independent defect (474): bounded transient retries, no mutation between attempts, structural find_tail fail = poisoned slice, publish state so other nodes don't storm, preserve first error.
9. **Test plan**: after reformat re-run with slots 0 / count-1 / count / 63, sparse slots, admission exhaustion, mount-fail slot release, survivor crash mid-replay, injected find_tail EIO, malformed counts, verify every log I/O stays in-slice.

## Central invariant
"A filesystem slot has exactly one identically numbered log slice, and no node may participate unless that slice exists."
