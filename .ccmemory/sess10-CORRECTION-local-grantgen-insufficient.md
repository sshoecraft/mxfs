---
name: sess10-CORRECTION-local-grantgen-insufficient
description: sess10 CORRECTION to the fix plan: a LOCAL grant_gen lookup is insufficient (non-master node's entry is stale exactly when needed). Reliable signal n…
metadata:
  type: project
---

## Correction to [[sess10-FIX-PLAN-use-dlm-grant-gen-not-lossy-evictring]] — caught a flaw BEFORE implementing (don't pursue the dead-end).

## The flaw in "cheap local grant_gen check":
The proposed mxfs_dlm_local_grant_gen would walk THIS node's lock table for its GRANTED entry's grant_gen. But the failing scenario is node B fast-pathing a dir-EX MODIFY at the XFS layer WITHOUT touching the DLM. In that case node B's local DLM entry is UNCHANGED (gen == cached gen) -> "match" -> no reload — i.e. the local gen is exactly as STALE as i_dlm_mode. The local table only changes when node B itself goes through a real DLM grant/release. So a local-gen compare cannot detect "a PEER got the lock since I cached it."

## Why: the authoritative "who holds this now / current grant_gen" lives on the RESOURCE MASTER. The dir inode is mastered by ONE node. If node B is NOT the master, it must do a network round-trip to learn the current holder — which is a real reacquire (the thing the fast path avoids). There is no cheap, reliable, purely-local signal.

## Consequence: the fix IS inherently GPT's design (no shortcut): a node must do a REAL DLM reacquire (round-trip) when the tenure may have changed, bounded by MHT (so it's per-TENURE, not per-op). The reliable "tenure may have changed" trigger is: a BAST was RECEIVED for this dir (reliable, acked TCP). The existing flow ALREADY does this IF the BAST is honored: BAST -> (defer MHT) -> release+drain -> next access is a slow-path reacquire -> reload (which is reliable, proven). 

## So the REAL bug narrows to ONE of:
(a) node B keeps fast-path-serving EX MODIFYs DURING the MHT-defer window (state stays CACHED), RMW'ing on a base that a peer is about to/has invalidated — fix: do NOT serve EX-modify while a BAST is pending for a CONTENDED dir (only serve reads / drain the current batch, then honor). The MHT keeps the lock but new EX-modifies after a BAST should be the LAST batch before release, OR
(b) after node B honors the BAST + releases + later reacquires, the reacquire does NOT reload (takes a fast path because i_dlm_mode wasn't actually demoted to NL on release) — fix: ensure release/demote sets i_dlm_mode=NL so the reacquire slow-paths.

## NEXT SESSION: instrument (carefully — masks) or REASON which of (a)/(b) holds. For (b): check bast_process / mxfs_v5_dlm_inode_unlock actually sets ip->i_dlm_mode=NL and clears cached state on EVERY release path (incl. MHT dwork honor). For (a): in the dir-strict gate (xfs_mxfs_dlm.c ~6520), when an EX MODIFY arrives and a BAST is pending (state==BAST, or i_dlm_bast_pending set by MHT-defer), force slow-path instead of serving — but ONLY for modifies, and verify it does not starve (dlm_fairness). This is the smallest sound change toward GPT's serialization. Baseline 5EC1F0BF.
