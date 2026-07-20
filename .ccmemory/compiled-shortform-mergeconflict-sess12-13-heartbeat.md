---
name: compiled-shortform-mergeconflict-sess12-13-heartbeat
description: sess12-13 MODE-B shortform concurrent-modify merge conflict: double-grant refuted, write-side laggy-heartbeat root, 3-way SF merge fix required.
metadata:
  type: project
tags: [compiled, mode-b, shortform-dir, tcp-dlm, merge-conflict, lost-update, cache-coherency, sess12, sess13]
---

# MODE-B shortform shared-dir merge conflict (sess12-13)

Central topic: the residual `./run.sh 2 tcp` failure (criterion = 100%/16 validated x3 clean-reboot, NOT met at sess13 end, marker NOT written). Root is a **shortform shared-directory concurrent-modify lost-update / merge conflict** ("MODE-B"), driven by a laggy/bursty DIR_MODIFY heartbeat, on the TCP-DLM 2-node cluster. A TCP double-grant was chased and definitively **refuted**; one genuine double-grant (CONVBLK) was found and fixed separately.

## The test and its two failure modes
`tcp_dlm_scaling` (also implicates `dlm_fairness`, `crash_consistency`, `fence_during_write`): each node does create+rename+rm of its OWN `n{R}_*` entries in a SHARED dir; rank1 asserts the dir is empty at the end. Flaky ~1/3 → ~1/10 per clean-rebooted run, residual rotates across {tcp_dlm_scaling, dlm_fairness, crash_consistency}. Two distinct roots ([[sess13-two-failure-modes-and-p91-falsepos-resurrection]]):

- **MODE A (rarer)** — AG↔dir cross-node distributed deadlock → FS SHUTDOWN (nodes_pass=0/2). A node's `rm` holds shared-dir inode EX inside a DIRTIED remove txn, then blocks ~60s acquiring AG0's DLM grant → `DLM AG lock failed: ag=0 rc=-110` → `xfs_remove`→`xfs_droplink -110`→`xfs_trans_cancel` on a DIRTY trans → "Corruption of in-memory data" → SHUTDOWN (xfs/xfs_trans.c:1060). Peer holds AG0 + re-requests dir EX every 6.14s (`MXFS_LOCK_ACQUIRE_WAIT_MS=6s` retry). Classic ABBA; cycle exists because AG DLM locks are CACHED across ops. GPT verdict for MODE-A: keep [inode,AG] order but PRE-ACQUIRE all needed AG DLMs BEFORE dirtying the trans — no blocking DLM acquire after `xfs_trans_log_*`, no inode-DLM acquire while holding AG-DLM; OR take the AG lock in `xfs_remove` before the trans dirties so -110 cancels a CLEAN trans (no shutdown).
- **MODE B (dominant)** — shortform stale-base RESURRECTION → leftover dirent (nodes_pass=1/2). Leftover is the node's OWN file, e.g. `n1_r1`/`n1_r6` nlink=1 (a create→rename→rm reverted).

## What was REFUTED

- **TCP dir-EX double-grant is NOT the cause** ([[sess13-doublegrant-REFUTED-serialized-stale]], decisive, RULE-4, build B65625E2). Method: `tcp_dlm_scaling` with `MXFS_EXTRA_MODARGS='lockwr=1'` (tests/tcp_lkt_doublegrant.sh), clean reboot, foreground; on a leftover failure read the ALWAYS-ON master-side detectors from `dg_grant_ex` (dlm/dlm.c:2142). Result both nodes: **P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0** (not instr-gated). Grants strictly serialize PR/EX through the master ring — only one node holds dir-EX at a time. This REFUTES the sess12 "find the 2nd double-grant path" lead — there is none.
- **Release durability is NOT the gap.** `bast_process` release barrier (xfs_mxfs_dlm.c ~3638-3748) loops until `!in_ail && !pinned && data_durable` before `mxfs_v5_dlm_inode_unlock`. `mxfs_dir_data_durable` (987) returns TRUE vacuously for FMT_LOCAL (shortform has no data blocks) BUT the `in_ail` wait on `ip->i_itemp` DOES cover the shortform DINODE (item leaves AIL only when the inode cluster buffer is iflushed AND written). `mxfs_inode_cluster_durable` (1514) synchronously delwri_submit+blkdev_flush's the dir cluster on release. So the shortform dinode IS durable on the shared target before unlock. DO NOT re-investigate release-barrier durability.
- **Not (always) a stale-READ.** At a failure `P34D-RELOAD-FRESHSRC ino=2097280` showed the coherent plain-bio on-disk read (fua_disable=1 ⇒ reads = SCST cache = coherent) EQUALS the cached buffer, and `P58-STALE-BASE-ADD` fired 0× that run ([[sess13-modeB-writeside-laggy-heartbeat-not-stale-read]]). So the base was NOT stale-on-read; yet the leftover survives ON DISK ⇒ it's WRITE-side.
- Refuted fix attempts (do NOT repeat): `mxfs_dlm_yield_basted_cached_ags()` for MODE-A is DEAD CODE — `P13-INODE-YIELD-AG` fires 0× (eligibility needs holders==0 but the deadlock has ACTIVE holders on both sides). The MODE-B prelock-reload `mxfs_dlm_dir_modify_reload_prelock()` is INSUFFICIENT — still ~1/16. "no MHT-defer for dirs" (build 00F4C5E1, sess12) still failed, REVERTED. Force-slow-path on i_dlm_stale → STARVATION (dlm_fairness got=7); dropping the IN_AIL gate → destage-race reverts own removal.

## The proven MODE-B mechanism
([[sess13-modeB-MECHANISM-shortform-merge-conflict]], build CF359E6C, dir-filtered P-LKT via tests/tcp_lkt_dirtrace.sh + tcp_dlm_scaling lkt_ino/dump hooks; dir ino=2097280.)

The shortform dir is ONE dinode (whole dirent set inline). Under serialized-but-STALE modify, a node legitimately holds dir-EX and RMWs a shortform base missing a durable change:
- Grants SERIALIZED (master ring alternates PR/EX cleanly — DLM exclusion correct).
- The modifying node RMWs from a STALE base: `P58-STALE-BASE-ADD add=[n1_r1.done] fmt=0 loaded_gen=3 dir_gen=11`; loaded_gen always LAGS dir_gen.
- Master reloads fresh: `P34D-RELOAD-FRESHSRC ... size=19 → fresh size=32 — adopting coherent on-disk`.
- **DECISIVE — `P62-RELOAD-FORK-SHRINK ino=2097280 incore_size=51 disk_size=32 in_ail=0 pin=0`**: in-core shortform is LARGER than disk but NOT dirty/pinned; the reload SHRINKS it to disk.

Interpretation: in-core = {node's own n1_* entries} + {STALE n2_* the peer already removed}; disk = {node's durable n1_*} + {peer's CURRENT n2_*}. **NEITHER is a superset of the other.** The reload's "adopt disk if peer_modified" heuristic shrinks to disk and drops the node's not-yet-durable n1_*; the subsequent `P58` add RMWs the stale base and durably reverts the node's own rename+rm → leftover `n1_r1,n1_r2`. Reload CANNOT distinguish "disk is NEWER, adopt+shrink" from "disk was REVERTED by a peer's stale-base RMW, do NOT adopt" — identical clean flags (in_ail=0/pin=0), opposite correct actions. This is the irreducible shortform merge conflict: whole dirent set in ONE dinode, two writers.

## Root driver: laggy/bursty heartbeat, not the DLM
([[sess13-modeB-writeside-laggy-heartbeat-not-stale-read]].) SMOKING GUN: the EVICT-RING-DIRMOD heartbeat is LAGGY/BURSTY — test1 logged `gen->17,18,19,20,21,22` (6 gens) ALL within 10 microseconds (t=147.271982→147.271992): it was unaware of 6 peer dir modifications, then got all 6 notifications in one burst. Confirms sess10: dir cross-node coherency RELIES ON THE LOSSY/LAGGY DISKLOCK HEARTBEAT (`note_dir_modified`→`i_dlm_dir_gen` / `MXFS_IF_DIR_RELOAD`) instead of the reliable DLM. The modify-path reload is gated on this laggy `dir_gen`, so a node modifies in the lag window from a stale base.

sess12 framing ([[sess12-churn-resurrection-root-and-gpt-fix-A]]): the receiver `mxfs_dlm_evict_inode_cb` (xfs_mxfs_dlm.c:10057) only does `dir_gen++; set MXFS_IF_DIR_RELOAD`; both nodes hold `i_dlm_mode=EX` cached and mutate via fast path (no DLM round-trip/BAST). When a node tries to consume `MXFS_IF_DIR_RELOAD` to adopt a peer removal, reload is BLOCKED by `P91-RELOAD-PROTECT` (xfs_mxfs_dlm.c:5057) → keeps stale base → checkpoint durably resurrects the peer's removed dirent. Detector `P58-STALE-BASE-ADD` (xfs/libxfs/xfs_dir2.c:447) fired 126×/run. sess12 UNRESOLVED sub-question was "why cached-EX-on-BOTH still happens" — hypothesizing a 2nd missed-demote beyond CONVBLK; sess13 later proved grants ARE serialized, so the true gap is the stale-base merge, not a second double-grant.

## The P91 false-positive
`P91` = `mxfs_buf_has_uncheckpointed_mods` (xfs_mxfs_dlm.c:8591) is a WHOLE-CLUSTER-BUFFER over-approximation (`if (bip) { … return true; }`). It cannot distinguish: (A) the dir's own mods already ON DISK but BLI lingering in AIL until next log-tail checkpoint [SAFE to reload]; (B) a CO-RESIDENT inode (same 4KB/16-inode cluster) with un-destaged mods [keep]; (C) genuine un-destaged dir mod [keep]. Captured buffer flags=0x20 (XBF_DONE only, NOT dirty/DELWRI) ⇒ case-A false-positive that wrongly keeps the stale base ([[sess13-two-failure-modes-and-p91-falsepos-resurrection]]). Same contradiction the AG-meta path solved with the li_lsn-vs-payload_lsn discriminator (`mxfs_ag_meta_payload_lsn` 8645, sess120) — but dinodes have NO on-disk LSN field stamped at write time, so that trick doesn't port.

## REQUIRED FIX = 3-way shortform merge
Both cheaper fixes are PROVEN insufficient ([[sess13-FIX-REQUIRED-3way-sf-merge]]):
- **adopt-disk wrong**: `mxfs_dir_sf_refresh_if_disk_differs` (xfs_mxfs_dlm.c:6293, on cached-EX fast path via sf_disk_check @6802) only adopts when in-core is CLEAN (returns if pincount>0 || ili_fields || IN_AIL). When the node has its own committed-not-checkpointed SF mods (ili_fields set) it SKIPS → RMWs stale base → P58. Relaxing the clean gate would DROP the node's own uncommitted entries.
- **flush-then-adopt wrong**: flushing in-core to disk overwrites disk with the node's stale peer-view → REVERTS the peer's current changes (the resurrection).

Fix (GPT-endorsed Option B, exact for the disjoint-name churn of tcp_dlm_scaling/dlm_fairness/crash_consistency):
1. **base snapshot**: when the SF fork is loaded/reloaded (loaded_gen set — end of `mxfs_dlm_reload_inode` and at iget), store a copy of the SF dirent set (name→ino) as a new per-inode field `i_dlm_dir_sf_base` (+ gen stamp); free on evict/reload.
2. **at a shortform-dir modify** (in `mxfs_dir_sf_refresh_if_disk_differs` or a new pre-RMW hook): coherent-read disk SF (theirs); if theirs != ours, MERGE over (base ∪ ours ∪ theirs): if ours differs from base for a name (we added/removed/changed it) → take OURS; else → take THEIRS. Rebuild in-core SF fork from MERGE; RMW proceeds on merged base; commit; release-barrier flushes durable (already sound).
3. Refresh base to post-merge state after install.
4. Disjoint names ⇒ exact, no conflicts. Same-name general case = documented last-writer-per-name (criterion tests are disjoint).

The release barrier (bast_process 3638-3748) already guarantees the durable handoff; the missing half is the ACQUIRE/modify-side MERGE instead of adopt-or-skip. Alternative Option A (strict dir-EX tenure): a shortform mutation reloads the current on-disk dinode synchronously right before the RMW (NOT heartbeat-gated), applies delta, makes durable BEFORE releasing EX — combined with the existing release barrier, disk is always a strict superset at the next acquire. GPT (sess10/12) endorsed either.

## The one genuine double-grant that WAS fixed: CONVBLK
([[sess12-convblk-doublegrant-fix]], build **F967E0F587960FC0EC155CB** / F967E0F5.) PROVEN root (RULE-4): TCP DLM blocked-upgrade double-grant. In `dlm/dlm.c` `process_remote_request` (~2383) and local `mxfs_dlm_lock` (~1056), on a BLOCKED upgrade (sender GRANTED PR, requests EX, conflicts) the OLD code REMOVED the sender's GRANTED entry and re-queued it WAITING — but the sender still LOCALLY held the lower grant, so removal made it INVISIBLE to other nodes' compat scans (which skip non-GRANTED). A peer then got a conflicting mode → two nodes hold incompatible grants → stale-read/dir lost-update. Proven: `P-CONVBLK-REMOVE sender=… type=1(INODE) held_mode=PR req_mode=EX` on test2 (master) during a crash_consistency FAILURE.

Fix (3 edits, scoped to INODE; AG keeps legacy remove+requeue): (1) include/mxfs/mxfs_common.h new enum `MXFS_ERR_UPGRADE_CONFLICT`; (2) dlm.c sender return map (~936) `MXFS_ERR_UPGRADE_CONFLICT → -EDEADLK`; (3) both blocked-upgrade sites: for `resource->type==MXFS_LTYPE_INODE` KEEP the grant visible + deny with the new code (P-CONVBLK-DENY). The XFS ilock P109 path (xfs_mxfs_dlm.c ~7182) then drops the lower grant through the BAST drain pipeline in-sync and re-acquires FRESH via clean FIFO — no double-grant, no conversion deadlock. Result: P-CONVBLK-REMOVE=0, P-CONVBLK-DENY active (2-7/run), crash_consistency PASSES 3/3, no dlm_fairness starvation regression. KEEP (correct but not decisive alone).

## Build progression
- **5EC1F0BF** — pre-CONVBLK baseline (sess12).
- **F967E0F5** (= F967E0F587960FC0EC155CB) — CONVBLK double-grant fix only; best sess12 build; KEEP.
- **00F4C5E1** — sess12 "no MHT-defer for dirs" experiment; still failed; REVERTED.
- **5642A8E1** — F967E0F5 + sess13 dead-code yield.
- **B65625E2** — F967E0F5 + MODE-A yield (dead) + MODE-B prelock-reload; double-grant refuted here; MODE-B prelock insufficient (~1/16).
- **CF359E6C** (= F967E0F5/CONVBLK + sess13) — DEPLOYED + validated both nodes; full suite observed 15/16 and 14/16 (residual rotates {crash_consistency, tcp_dlm_scaling, dlm_fairness}); the `lkt_ino` P-LKT filter param add is inert unless set, no regression. Contents: xfs_mxfs_dlm.c/.h `mxfs_dlm_yield_basted_cached_ags` (MODE-A, dead code) + `mxfs_dlm_dir_modify_reload_prelock` (MODE-B pre-ILOCK shortform reload, insufficient) + `lkt_ino` filter; xfs_inode.c prelock-reload calls in xfs_remove/create/rename before xfs_trans_alloc*; dlm.c lkt_ino guard in `mxfs_lkt_record`; tests/tcp_scaling_capture.sh, tests/tcp_lkt_doublegrant.sh. **Build base for the next-session 3-way merge is CF359E6C** ([[sess13-HEAD-status]]).

## Tooling / harness state and gaps
- Repro: **tests/tcp_scaling_capture.sh N** (clears dmesg per iter, dumps detectors + sysrq-w blocked-tasks on FAIL). **tests/tcp_lkt_doublegrant.sh** (foreground, lockwr=1). P-LKT ring (`mxfs.lockwr=1`, `lktdump` param) works but is FLOODED by child-inode GRANT-LOCAL noise (n1_rN, owner=local) which evicts dir events — filter via the `lkt_ino` param (`mxfs_lkt_record`, dlm/dlm.c:117) or enlarge `MXFS_LKT_RING_SZ`.
- **tests/tcp_lkt_dirtrace.sh gaps to fix before the next decisive trace** ([[sess13-lkt-dirtrace-harness-gaps]]): (1) the `lkt_ino` watcher never fired (at failure `lkt_ino=0`, still recording all) — the inline `ssh nohup ... stat -c %i > lkt_ino` nested-quote/timing broke; FIX = a persistent node-side script (tests/ + NFS) that logs to dmesg when it sets lkt_ino. (2) dir unmounted before failure-capture — post-run.sh `stat -c %i /mnt/shared/.tcp_dlm_scaling` returned EMPTY; FIX = capture dir ino + trigger lktdump + read leftovers from INSIDE the test (e.g. on tcp_dlm_scaling's rank1 drain-fail branch `echo $(stat -c %i "$D") > /sys/module/mxfs/parameters/lktdump` + dump leftover names to dmesg). Partial trace confirmed child grants ARE routed through the master and serialized cleanly (GRANT-REMOTE+REMOTE-RELEASE on master, GRANT-LOCAL+UNLOCK-GRANTED on creator) — consistent with the double-grant refutation.

## Operational lessons (carry forward)
- **NEVER run_in_background + wait/until-loop/poll**: orphaned `*.output` files make the ccloop Stop hook (keepgoing.py) fire "Background command still running" forever. FOREGROUND everything; if a setter must run mid-test, background it ON THE NODE via `ssh node 'sleep 2; echo … &'` (returns immediately, no clyde orphan). [[feedback-never-background-wait-poll]]
- **ALWAYS `virsh destroy+start` BOTH nodes before a run** — contaminated cluster → mkfs rc=1 / module-not-loaded = FALSE FAILs, not real. test1=DHCP .114, test2 .182 (harness uses DNS names). NFS /src from 192.168.1.4.
- Criterion for this line of work = full `./run.sh 2 tcp` 100% (all 16), validated x3 clean-reboot. At sess13 end: NOT met, marker NOT written.

## Next session
Implement the 3-way SF merge (Option B). Files: xfs_mxfs_dlm.c (`mxfs_dir_sf_refresh_if_disk_differs` + base snapshot in reload + new `i_dlm_dir_sf_base` field in the xfs_inode mxfs section, include/mxfs or xfs_inode.h). Touchpoints: reload self-skip/P91 4944-5070; P9-SFREFRESH 6225-6331; reload repopulate after invalidate 5070+; sf refresh+CLEAN-gate ~6240/6267; bast_process visibility barrier ~2840. Validate full run.sh 2 tcp x3 after clean reboot; watch dlm_fairness/tcp_dlm_scaling/crash_consistency (rotating residual), no regression on cache_coherency/zero_silent_loss, and RULE-0 timing. Build base = CF359E6C.
