---
name: sess13-modeB-writeside-laggy-heartbeat-not-stale-read
description: sess13 UPDATE: MODE-B resurrection is NOT a stale-READ (P34D fresh==cached, P58=0); it's write-side + LAGGY/BURSTY heartbeat (6 gens in 10us). Preloc…
metadata:
  type: project
---

## Criterion NOT met. Build B65625E2 = F967E0F5 + sess13 MODE-A yield (dead code) + sess13 MODE-B prelock-reload (INSUFFICIENT — still fails ~1/16, e.g. iter5 leftover n1_r1 nlink=1).

## sess13 CHANGES IN TREE (keep; sound but not a complete fix):
1. `mxfs_dlm_yield_basted_cached_ags()` (xfs_mxfs_dlm.c before mxfs_dlm_ilock_begin) + call in inode-acquire loop ~7170. For MODE-A AG<->dir deadlock. **DEAD CODE: P13-INODE-YIELD-AG fires 0× — eligibility holders==0 but deadlock has active holders.**
2. `mxfs_dlm_dir_modify_reload_prelock()` (xfs_mxfs_dlm.c after consumer_refresh; decl xfs_mxfs_dlm.h) — consumes MXFS_IF_DIR_RELOAD + reloads dinode BEFORE ILOCK_EXCL (post_release=false). Called in xfs_remove (before xfs_trans_alloc_dir), xfs_create (before xfs_trans_alloc_icreate), xfs_rename (before retry:). Rationale: mxfs_dlm_dir_modify_refresh only evicts DATA blocks (no-op for shortform); modify paths hold ILOCK_EXCL so can't call reload (needs i_lock EXCL). **Did NOT fix the test.**

## WHY MODE-B prelock-reload FAILED — NEW PROVEN EVIDENCE (RULE 4):
- At failure: `P34D-RELOAD-FRESHSRC ino=2097280 buf[size=32 nx=0] fresh[size=32 nx=0] src=plain` — the COHERENT plain-bio on-disk read (fua_disable=1, so reads SCST cache = coherent) EQUALS the cached buffer. So our base is NOT stale; on-disk dir already == our image. **P58-STALE-BASE-ADD fired 0× this run.** So MODE-B is NOT (always) a stale-READ.
- Yet leftover n1_r1 (test1's own create+rename+rm, nlink=1) survives ON DISK (size=32 includes it). ⇒ a WRITE-side lost update: test1's removal of n1_r1 is not the durable on-disk state, OR a peer durably wrote a base containing n1_r1 over test1's removal.
- **SMOKING GUN: EVICT-RING-DIRMOD heartbeat is LAGGY/BURSTY.** test1 logged `gen->17,18,19,20,21,22` ALL within 10 MICROSECONDS (t=147.271982→147.271992). i.e. test1 was unaware of 6 of test2's dir modifications, then received all 6 notifications in one burst. This is exactly sess10's proven root: dir cross-node coherency RELIES ON THE LOSSY/LAGGY DISKLOCK HEARTBEAT (note_dir_modified→i_dlm_dir_gen) instead of the reliable DLM. fua_disable=1 (reads coherent — NOT a read-coherency issue).

## THEREFORE the real root (confirms sess10-SYNTHESIS + sess10-CORRECTION): the DLM EX HANDOFF is not reliably enforcing drain-before-release + reload-on-reacquire for the shortform shared dir. If it were, the bursty heartbeat would be irrelevant. Either (a) TCP double-grant (both nodes hold dir-EX, peer's mods stay in its cache, never durable when we read — consistent with P34D fresh==cached==our-stale), or (b) a release path that hands EX to the peer WITHOUT draining the shortform dinode to disk (Invariant #1 violation). NOTE first MODE-A capture also showed `P13-SFPARENT-DURABLE-FAIL ino=131 — shortform parent cluster not destaged` (durability give-up under churn) — a candidate for (b).

## NEXT SESSION — sharpest leads (do NOT repeat reload-tweaks; they're exhausted):
1. PROVE drain-on-release: instrument the dir-EX release/bast_process to confirm the shortform dinode is xfs_iflush'd + delwri-submitted + on disk BEFORE mxfs_v5_dlm_inode_unlock. Cross-node realns timeline: does peer acquire EX + read disk BEFORE our release's destage completes? (the handoff race).
2. PROVE/REFUTE TCP double-grant of the dir inode under churn: add a cross-node EX-overlap detector for the shared dir ino on TCP (mxfs_v5_dlm_inode_held is a NO-OP on TCP per sess10 — must add a real TCP grant-state query against ctx->dlm lock table). If both hold EX overlapping → DLM mutual-exclusion bug (CONVBLK/gen-token still has a hole).
3. The architectural fix (GPT Option A, converged sess10/sess12/sess13): dir mutation = real serialized EX tenure; on BAST bounded-quantum then close-admission+visibility-barrier(destage shortform dinode)+demote; reload-on-reacquire; heartbeat = hint only. See [[sess12-churn-resurrection-root-and-gpt-fix-A]] [[sess10-SYNTHESIS-handoff-and-final-target]] [[sess10-CORRECTION-local-grantgen-insufficient]].
4. MODE-A (AG<->dir deadlock→shutdown, rarer): GPT verdict = keep [inode,AG] order but PRE-ACQUIRE all needed AG DLMs BEFORE dirtying the trans (no blocking DLM acquire after xfs_trans_log_*; no inode-DLM acquire while holding AG-DLM). See [[sess13-two-failure-modes-and-p91-falsepos-resurrection]].

## Repro: tests/tcp_scaling_capture.sh N (clears dmesg per iter, dumps detectors+sysrq-w blocked-tasks on FAIL). ALWAYS virsh destroy+start BOTH nodes before trusting a run (contaminated cluster → mkfs rc=1/module-not-loaded false FAILs). test1=DHCP .114 test2 .182, harness uses DNS names.
