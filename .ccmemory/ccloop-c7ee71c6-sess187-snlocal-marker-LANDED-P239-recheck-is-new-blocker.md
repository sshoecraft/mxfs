---
name: ccloop-c7ee71c6-sess187-snlocal-marker-LANDED-P239-recheck-is-new-blocker
description: sess187: snlocal marker fully landed+built (sv 0A24EA59), repro race+delay PASS; remount now blocked by P239-EXCL-LAPSED — recheck lacks kind-17 leg
metadata:
  type: project
tags: [ccloop-c7ee71c6, dirty-slice, snlocal, kind-17, P239]
---

# sess187 — snlocal write-time marker landed; P239 recheck is the new blocker

## Landed + built (sv 0A24EA596743E1FC8E70ACD, tree = 0.11.464 + Fix 3c + 2a/2b + this)
All 6 edits of the sess186 plan for sess184-ruling blocker 1:
- disklock.h: ctx `bool snlocal` + set_snlocal decl (pre-claim only).
- disklock.c: hb_feature_fill(ctx, hb) stamps MXFS_HB_FEAT_SNLOCAL (5 sites);
  hb_victim_snlocal() (state==OK && flag, fail-closed); VICTIM_SNLOCAL OR'd
  into desc flags at BOTH creators (~2990 recovery_begin, ~3685 fence_intent);
  set_snlocal refuses once local_slot>=0 (uses MXFS_LOG_ERR — MXFS_LOG_ERROR
  does not exist).
- v5_mount.c: set_snlocal(disklock, ctx->single_node_exclusive) before BOTH
  claim sites; new API mxfs_v5_dlm_victim_untagged_authority (~5614; decl
  v5_mount.h ~433): cert_sn_excl = stage>=FENCED && kind==17, victim_snlocal
  = flags&0x4, fail closed on any error.
- xfs_log_priv.h: l_mxfs_untagged_authorized / l_mxfs_cert_single_node /
  l_mxfs_untagged_skips. xfs_log.c foreign_slice fn: evaluates authority at
  shadow-log creation (P227-SNLOCAL-DIVERGE warn on cert&&!marker);
  post-replay cert && !authorized && skips>0 → P227-SNLOCAL-TORN alert +
  -EFSCORRUPTED (slice stays unpublished). Adopted path never authorizes.
- xfs_log_recover.c: ATOMIC-SKIP gate gets authorized branch →
  P227-SNLOCAL-ACCEPT (separate counter per ruling item 8) and applies;
  per-item P223 gate adds !authorized; both skip sites bump untagged_skips.

## Repro result (tests/dirty_slice_release_repro.sh test32 all)
race PASS, delay PASS. remount FAIL at a NEW point (past sess183's):
P238-FENCE-SINGLENODE mints kind-17 → P236-FENCE-CERTIFIED →
P236-RECOV-CLAIMED stage=2 → **P239-EXCL-LAPSED site=claim
kind=NO_RESERVATION(8) rc=-1** → replay refused → marker lost.
ROOT: v5_exclusion_recheck (v5_mount.c:2760) calls
mxfs_scsipr_exclusion_holds unconditionally; kind-17 has NO PR reservation by
definition. Per the sess184 predicate split, kind-17's "exclusion holds NOW"
leg = v5_single_node_fence_gate (:993), not PR state. Call sites: 2830
reacquire / 2851 claim / 2897 / 3188 complete. Fix needs cert fence_kind
(desc read or ctx->recov_auth[slot], struct at :429) to branch. RULE-5
consult next before implementing (fence-path change).

## Harness lessons (paid in blood)
- `make clean` DELETES tools/ binaries — always `make tools` after, or the
  repro's mkfs fails and (pre-fix) the GOINGDOWN ioctl hit the node's ROOT FS
  through the unmounted mountpoint and killed test32 (virsh destroy/start +
  remount /src NFS recovered). Script now aborts the arm if mount_rc != 0.
- Repro's victim mount now sets single_node_exclusive=1 (write-time marker
  requirement) and resets it after umount.
