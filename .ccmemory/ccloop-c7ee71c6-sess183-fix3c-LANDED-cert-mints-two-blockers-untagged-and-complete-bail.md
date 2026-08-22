---
name: ccloop-c7ee71c6-sess183-fix3c-LANDED-cert-mints-two-blockers-untagged-and-complete-bail
description: sess183: Fix 3c LANDED+measured (sv 8C2D7B86): kind-17 cert mints, lease+replay run; remount still FAILS — single-node emits NO trailers (untagged=7…
metadata:
  type: project
---

# sess183 — Fix 3c landed and rig-measured; two downstream blockers

Build: tree 0.11.464 + Fix 3c, sv 8C2D7B86E87E21D5489BC77, loaded on test32.

## What landed (all in tree, builds clean)
- scsipr.h: `MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE = 17` (on-disk enum, "proved" section); `mxfs_fence_kind_proves_exclusion` accepts 16|17. scsipr.c name case.
- disklock.c: BOTH `resv_type == WR_EX_RO` checks (certify writer ~3750, validator `mxfs_recov_cert_proves_exclusion` ~3500) now apply only when kind==PREEMPT_ABORT_DONE — kind 17 has no resv supporting fact.
- v5_mount.{h,c}: `single_node_exclusive` opt/ctx field; `v5_single_node_fence_gate` = module param AND `mxfs_v5_dlm_is_single_node`; `v5_fence_kind_contradicts_single_node` refuses mint over RACE_LOST / ADVISORY_TOPOLOGY / VIEW_TRUNCATED / SELF_PREEMPTED (affirmative evidence of another initiator). `v5_pr_fence_prove`: !scsipr leg falls through to fence_intent when gated then synthesizes kind 17 (P238-FENCE-SINGLENODE leg=nopr); P&A-unproven leg upgrades observed kind→17 (leg=unproven — the leg the loop rig takes, observed=UNSUPPORTED).
- xfs_super.c: `module_param_named(single_node_exclusive, ...)` 0644 default 0 beside legacy_rw, plumbed into dlm_opts (read at mount/fill_super time).
- tests/dirty_slice_release_repro.sh remount arm: sysfs param 1 before mount, 0 after.

## Measured (repro all, test32 loop7)
race PASS, delay PASS. Remount: full new chain fired — P274-CLAIM-WITHDRAWN-SKIP → P163-WITHDRAW-SEEN → P236-FENCE-INTENT → P236-FENCEKIND UNSUPPORTED(2) → **P238-FENCE-SINGLENODE leg=unproven** → **P236-FENCE-CERTIFIED kind=SINGLE_NODE_EXCLUSIVE** → P238-RECOV-LEASE stage=2 → foreign replay of slot 0 runs. STILL FAIL on:

1. **Untagged slice**: P227-TOKENSUM untagged=7 → P227-FR-ATOMIC-SKIP → marker txn not applied. ROOT: `mxfs_buf_item_wants_authority` (pal/linux/xfs_buf_item.c:151) returns false for single-node mounts — they emit NO authority trailer, and xfs_mxfs_dlm.c single-node early-outs skip DLM locking entirely, so no cert exists to bind anyway. A single-node victim's slice is structurally 100% untagged; the #1 containment gate skips all of it.
2. **Publication fails**: `P163-COMPLETE-BAIL slot=0 ctx=0 disklock=0` → "slice replayed but publication FAILED". Completion callback got NULL ctx — undiagnosed, likely mechanical threading bug.

## Blocker-1 needs a RULE-5 consult before coding
Tension: sess180 ruling item 2 LIMIT says fence+completion is NOT lineage authority for untagged images ("inherits #1 status; do not expand"); item 5 allows single-node no-fence recovery under HARD exclusivity + explicit flag. Question: may a kind-17 certificate authorize a SCOPED per-replay apply of that victim's untagged images (sole node held ALL authority), or must single-node mounts emit trailers (what class?)? Global knob `mxfs_foreign_replay_untagged_apply` is defect #1 itself — not usable. sess175 lineage constraints stand.
