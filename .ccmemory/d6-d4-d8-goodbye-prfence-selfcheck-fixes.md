---
name: d6-d4-d8-goodbye-prfence-selfcheck-fixes
description: v0.11.79 D6 goodbye (survivor 38s→10ms); v0.11.80 D4 PR fence w/ READ-KEYS+topology classify + D8 probe/self-check. Shared-nexus VM rig: per-node PR…
metadata:
  type: project
tags: [d6, d4, d8, goodbye, pr-fence, self-check, shared-nexus, ccloop-c7ee71c6]
---

# D6/D4/D8 fixes (ccloop c7ee71c6 sess1, v0.11.79-80)

## D6 (v0.11.79) FIXED AND VERIFIED — clean-umount goodbye
Repro'd on VMs: after peer's clean umount, survivor's next EX **blocked 38s** (20s settle-freeze + retries to departed master until 40s grace) with 280 retry-spam lines. Fix (3 legs):
- Sender: `mxfs_v5_dlm_shutdown` broadcasts `MXFS_MSG_NODE_LEAVE` after release_all+journal-slot release, before peer_shutdown, gated `!ctx->withdrawn` (fenced nodes never claim clean departure).
- RX (v5_mount.c NODE_LEAVE): clears tcp_suspect entry + purge + lease unregister + `v5_refresh_active_nodes` (was missing — membership never updated!) + P-GOODBYE-RX log.
- Disconnect cb: `!mxfs_lease_has_node` → expected close of departed node → skip suspect+EX-freeze ("no death grace"). Straggler-beacon resurrection impossible: process_renewal does NOT auto-register unknown nodes.
VERIFIED: goodbye→active_count=1 same-ms; survivor touch 38000ms→10ms; 0 retry lines; fence/netpartition/membership/crash suite green (real-death grace intact).

## D4 (v0.11.80) — PR fencing was MISSING in v5 + hygiene
Legacy dlm/mount.c blind preempts are USER-MODE only (not in Kbuild). Kernel v5 dead-node paths (v5_lease_expire_cb + v5_tcp_declare_dead) never PR-preempted at all → TCP-dead-but-disk-alive peer could keep writing. Fix: `mxfs_scsipr_fence_node(ctx, victim, live_members)` called FIRST in both paths (fence before purge/remaster/slice-replay):
- READ KEYS classify; preempt only a PRESENT victim key (blind preempt of absent key = SPC conflict).
- **Topology guard**: count<live_members ⇒ P-PR-ADVISORY, no preempt/self-fence (D1 EBADE + lease/disklock fence instead).
- Own-key-gone: ESTALE→self-fence ONLY when unambiguous (count>=live && live>=2). Sole-survivor = ambiguous → log only.
- `registered` flag on scsipr ctx kills the unregister-then-destroy double-PROUT.
CRITICAL RIG FACT (measured): on the tcm_loop VM rig ALL VMs share ONE host I_T nexus → each node's REGISTER **overwrites** the previous one's; READ KEYS always shows 1 key (the LAST registrant's). Per-node PR is architecturally impossible there; first fence attempt (pre-guard) FALSE-SELF-FENCED the survivor. Guarded version verified: kill n2 → "sole survivor — ambiguous; relying on reactive D1" + survivor touch 8ms.

## D8 (v0.11.80) — probe + periodic self-check
- `mxfs_scsipr_probe` after register+reserve (both TCP+CAW branches): logs P-PR-PROBE own-key-visible/absent (advisory detect at mount).
- Periodic self-check: TCP death-worker every 60×500ms ticks calls `mxfs_scsipr_self_check(live)` — same classification; ESTALE→P-PR-SELFFENCE+fence_notify. Advisory latched once per episode (advisory_logged). read_keys failures logged (first 8). P-D8-TICK forensic (first 20 ticks) in-tree.
VERIFIED: clobbered node advises on first tick ("own key gone, 1 key(s) for 2 live"); clean node silent; no false fence.

## PENDING verification legs (sane-nexus rig = cawd/QNAP; folded into CAW-rig task)
- Positive preempt (victim key present) → P-PR-FENCE preempted + sg_persist confirms.
- Unambiguous ESTALE self-fence execution.
- QNAP re-validation of the whole PR program (D1a/D2/D3/D4/D8 interact there).

## Watch
- P125-EVICT-SUSPECT ino=128 at umount seen on current build (evict with non-quiescent mxfs bookkeeping; DLM already shut down at that point). Also on old builds. Investigate before sign-off.
- fio_vs_xfs_baseline WATCH (task #7): 68/70/70% under loadavg 30; re-baseline quiet.
