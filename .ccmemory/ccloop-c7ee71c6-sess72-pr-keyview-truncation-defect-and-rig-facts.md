---
name: ccloop-c7ee71c6-sess72-pr-keyview-truncation-defect-and-rig-facts
description: sess72: found+fixed a NEW critical defect — PR key view sized by MXFS_MAX_NODES truncates on a multipath rig and freezes HEALTHY nodes. Plus rig PR f…
metadata:
  type: reference
tags: [scsipr, fencing, critical, defect, rig-facts, 0.11.414]
---

# sess72 — PR key-view truncation defect (NEW, critical) + rig PR ground truth

Build **0.11.414**, srcversion `DEA067313AD0A51C8558066`. Builds clean
(scsipr.o + kern.o zero warnings), tools + user-mode PAL clean.
**DEPLOYED to all 32 nodes** (`prep_cluster` 69s, all 32 active).

## 1. sess71's two OPEN rig risks are both CLOSED — with direct evidence

- **`dm_pr_read_reservation` EXISTS in 6.8.** `grep /proc/kallsyms` on test1
  shows `dm_pr_{clear,ops,preempt,read_keys,read_reservation,register,release,
  reserve}` and the sd layer has the matching `sd_pr_read_reservation`. The
  feared `-EOPNOTSUPP`-on-every-fence does NOT happen on this fleet.
- **A WE-RO reservation IS held.** `sg_persist --in --read-reservation
  /dev/mapper/mpatha` → `Key=0x2d7fac00, type: Write Exclusive, registrants
  only`. So the new `NO_RESERVATION` refusal will not fire spuriously.

**GPT sess71 item 7 (READ FULL STATUS audit) is DISCHARGED.**
`sg_persist --in --read-full-status` shows, per node, **2 descriptors carrying
the SAME key**, one per iSCSI session (`i,0x100003d0200` / `i,0x200003d0200`),
`all_tg_pt` CLEAR, relative port 0x1. That empirically confirms GPT item 6:
one 0x05 with SARK=victim key removes BOTH multipath registrations.

## 2. THE NEW DEFECT (this is the session's real find)

**Registrations are per-I_T NEXUS, not per node.** The rig holds **64
descriptors for 32 nodes**. Every consumer in `dlm/scsipr.c` was declaring
`uint64_t keys[MXFS_MAX_NODES]` and passing `max_keys = MXFS_MAX_NODES`, and
`MXFS_MAX_NODES == 64` (`include/mxfs/mxfs_common.h:29`).

So the fleet sat **EXACTLY at capacity, zero headroom**, and both PAL backends
truncate **silently** (`*count = min(num_keys, max_keys)`; user.c clamps
`addl_len/8` the same way) with no way for the caller to know.

Why that is severe, not cosmetic — **every consumer decides from key ABSENCE**:
- `mxfs_scsipr_self_check()`: `own_present == false` → `-ESTALE` →
  `v5_mount.c:985` `P-PR-SELFFENCE` → `fence_notify_fn()` → **node freezes.**
  Its topology escape hatch is `count >= live_members`, and a *saturated*
  count satisfies that maximally — so the guard cannot catch truncation.
  **A truncated view freezes a HEALTHY node.**
- `mxfs_scsipr_fence_node()`: same signature → `SELF_PREEMPTED`; and
  `victim_present == false` → `KEY_ABSENT_UNPROVEN`, so a fence silently
  stops preempting.

**Reachability is not theoretical:** one stale descriptor from a node that
died without unregistering, a third path, or a 33rd node pushes past 64. A
crash+rejoin is exactly the workload under test.

### Fix shipped in 0.11.414
- `scsipr.h`: `MXFS_PR_MAX_PATHS_PER_NODE 8`, `MXFS_PR_MAX_KEYS
  (MXFS_MAX_NODES * 8)` = 512. Sized by NEXUSES, not nodes.
- `pal.h`/`kern.c`/`user.c`: `mxfs_pal_scsi_pr_read_keys()` gained
  `int *total` = descriptors the TARGET reports (kernel: `pr_keys_buf->num_keys`
  after the call; user: `addl_len/8`). Truncation is now DETECTABLE.
- `dlm/scsipr.c`: new static `mxfs_scsipr_probe_keys()` — the single snapshot
  helper all four consumers use. Heap-allocates (512×8 = 4KB is far past
  kernel-stack budget, and self_check runs on the HB thread). Returns
  **`-EOVERFLOW`** when `total > count` and logs `P-PR-VIEW-TRUNC`.
- New `MXFS_FENCE_KIND_VIEW_TRUNCATED = 9` (on-disk numbering, appended).
- All four consumers converted: fence(classify), fence(post-preempt verify),
  self_check, probe. **`self_check` explicitly returns 0 on a truncated view
  — never self-fence on a view that cannot see itself.**

## 3. Other rig facts worth not re-deriving

- **`local_key` is per-INCARNATION, not a slot.** `ctx->local_key =
  (uint64_t)node_id` and observed keys are `0x2d7fac00`, `0x9c9c9d2b`,
  `0x72907e1e` — they CHANGE across remounts of the same node. So
  `victim_key = (uint64_t)victim_node` in `fence_node()` is only correct if
  the caller passes the victim's *current incarnation* id.
- `P-PR-PROBE` reports "2 key(s) registered" because it runs at mount time
  before peers register — it is NOT a contradiction of the 64 on the wire.
- Node IPs are **dnsmasq leases and NOT sequential** (test5=.164,
  test17=.185, test19=.149). Resolve by hostname; never compute an IP.

## 4. NEXT STEPS

1. **Debug `tests/pr_fence_evidence.sh`** (new, RULE 3). It exited with no
   output before reaching the `virsh destroy` — rig was left INTACT (32/32 up,
   test17 never killed), so nothing is contaminated. Run it under `bash -x`.
   It measures, across a real node death: the descriptor-count evolution
   (does it exceed 64? → proves the old buffer truncated in practice) and the
   `P236-FENCEKIND` outcome distribution (1 winner / N losers).
2. That run is the **RULE-4 verification for D-PR-FENCE-PREEMPT-WITHOUT-ABORT**
   — target: a real fence of a live registered victim reports
   `PREEMPT_ABORT_DONE proves_excl=1`.
3. Then sess71's steps 1-4 (descriptor v2, `recovery_begin()` to fence time,
   evidence publish/consume, only THEN gate the two replay-dispatch sites).
   **Do NOT gate the dispatch sites before the evidence channel exists** —
   fence winner and replayer (`lowest_live_slot`) are different nodes, so
   gating early stalls recovery outright.
