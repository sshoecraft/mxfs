---
name: sess53-HANDOFF-gpt-design-reliable-epoch-plus-safe-writeset-refresh
description: sess53 HANDOFF build 9473C7AD: dir_reuse root=handoff-bit UNDER-FIRE (P42=0). GPT-5.5 design: exact owner_epoch + per-buffer write-set refresh (NOT d…
metadata:
  type: project
---

## sess53 HANDOFF — 8/tcp dir_reuse: root re-proven + GPT-5.5 fix design + plan

### BUILD 9473C7AD = baseline + P-DGEX probes (my failed fix REVERTED).
- Reverted `dir_ex_grantgen_refresh` (arm dir_ex_stale_refresh on grant_gen advance):
  DELAYED loss (round 11->19) but REGRESSED to DABUF_MAP_HOLE flood (readdir=0). CAUSE: it
  bumped XFS dir_gen -> read-path re-reads LEAF blocks while reload(post_release=false) KEPT
  the stale extent map -> refreshed-leaf + stale-map = leaf refs a HOLE -> !HOLE_OK shutdown.
  LESSON: refresh must NOT bump XFS dir_gen / disturb leaf+extent-map under churn.
- Added probes in dlm.c dg_grant_ex (RULE-4): **P-DGEX** (ino=131 EX grant: owner,last_owner,
  active_b4,handoff,epoch) + **P-DGEX-NEWSLOT** (mine<0 -> handoff forced FALSE = eviction
  under-fire). DIAGNOSIS dgex_diag.sh was RUNNING at relay boundary — re-run it:
  `bash tests/tcp/drc_phantom_diag.sh ""` then read the per-node P-DGEX counts (handoff=1 vs
  handoff=0, active_b4=1, NEWSLOT) on the MASTER node for ino=131. That pins WHICH under-fire.

### ROOT (RULE-4 PROVEN, see [[sess53-ROOT-PROVEN-dirreuse-is-handoff-bit-underfire-not-phantom]]):
NOT a phantom (P42-STALEEX-SERVE=0). It is READ-staleness: master handoff BIT under-fires
(`handoff=(last_owner!=0 && last_owner!=owner)`, dg_shadow evictable 8192-slot), so a fast-path
EX serve whose grant_gen advanced (lock changed hands) skips the base refresh and RMWs a STALE
dir DATA block -> durable single .md5-sidecar clobber on all 8 nodes.

### GPT-5.5 DESIGN (RULE-5 consult, full text in transcript / was scratchpad/gpt_design.md):
1. **Exact owner_epoch** (replace lossy last_owner): master advances a per-resource epoch ONLY
   on cross-node EX owner change; same-node release+reacquire (peer WAITING, never granted) =>
   UNCHANGED; A->B->A => +2. Grant reply carries owner_epoch + resource_incarnation. Client
   handoff = (grant.owner_epoch != ip.owner_epoch_seen). **On slot eviction/state-loss FAIL
   CLOSED = force refresh, NEVER "no handoff"** (the current NEWSLOT->false is the unsafe bug).
   Key DLM resource by fs_uuid+ino+**GENERATION**+class (ino reused every round).
2. **Safe refresh** = SEPARATE MXFS coherency epoch (NOT XFS dir_gen — that caused my hole) +
   per-buffer validated_epoch. Before RMW of a dir buffer, if bp.validated<ip.remote_epoch ->
   LOCKED coherent reread of THAT daddr (no fork adopt, no global evict). Apply to the op
   WRITE SET (data+leaf+free+dabtree), not data-only (stale leaf/free also clobber) and not
   whole-fork. KEEP-GUARD non-negotiable (never reread dirty/in-AIL -> flush/wait/slowpath, else
   DUPLICATES). Recompute dup-check/freeindex after reread. Extent-map HOLE -> return
   -EAGAIN_SLOWPATH (do NOT let xfs_dabuf_map shutdown); slow path = grow-only extent merge.
3. Trigger on owner_epoch (NOT grant_gen) => cost O(handoffs) not O(creates); MHT preserved.

### NEXT-SESSION PLAN (tasks #1-3): (1) read P-DGEX to pin the under-fire (eviction vs
missed-dg_release active_b4=1 vs stale last_owner). (2) Make dg_shadow epoch exact+fail-closed
so i_dlm_dir_valid_epoch (already plumbed from dg_shadow.epoch) becomes reliable. (3) Enable the
EXISTING structurally-safe data-block-only refresh `dir_addname_epoch_refresh` (node.c:2034 —
rereads ONLY the selected data block, NO dir_gen bump, NO leaf) once the epoch is reliable; test
8/tcp for 0 loss AND 0 DABUF_HOLE; extend to leaf/free write-set if a residual clobber remains.
Marker NOT written. Other criteria (1/2/4 tcp + non-dir_reuse 8/tcp tests) believed passing.</body>
