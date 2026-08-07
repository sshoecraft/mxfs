---
name: ccloop-c7ee71c6-sess32-282-283-barrier-convoy-lesson-and-incident
description: 282: unconditional i_lock barrier convoyed readdir (dd 240s, RULE 0 fail) → 283 bounded trylock (rarely wins; closed=7 vs deferred=119). INCIDENT: 1…
metadata:
  type: project
---

# sess32 — barrier lesson (0.11.282→283) + the aged-mount incident

## RULE-0 lesson: never a reader-blocking write wait on a hot dir
0.11.282 put an UNCONDITIONAL `down_write(&ip->i_lock); up_write(...)`
barrier in mxfs_relbar_close_or_defer between durable passes. Result:
dirent_durability **240s/240s** (4x its 65s wall). Mechanism: readdir holds
ILOCK_SHARED across iteration; a queued write-waiter blocks NEW readers
(rwsem fairness) → cluster-wide convoy on the shared parent. 0.11.283
replaced it with a ≤40ms `down_write_trylock` loop (timeout → skip barrier →
the defer stays, which is safe). Wall restored (65s).
**Generalize: any future admission/quiesce design must wait for WRITERS
ONLY — never queue a write on a reader-held hot-dir rwsem.** The real
interlock belongs at mxfs_dlm_ilock_begin admission (writers park there
BEFORE down_write — verified: the DLM hook runs before the rwsem in
xfs_ilock), not at the rwsem.

## Barrier effectiveness (measured, 227k unlocks cumulative on 283)
obligation=0 ALWAYS (the protective property holds — no open grant handed).
closed=7 vs deferred=119 (ino=138 ×113, 134 ×3, 146 ×3 — all anchored, all
hot shared dirs): the trylock almost never wins on a continuously-read dir,
so in-window closing stays rare; each defer costs the peer one BAST cycle;
walls healthy throughout (dd 65s, cache 20-27s, dir_reuse 108-112s).

## INCIDENT (RULE 6 — recorded, OPEN, unattributed)
On 283's FIRST aged-mount batch (after a dd lap): dir_reuse_coherency FAIL
0/32 (test1 6/7 checks, 31 peers ABORTED_BY_PEER) AND cache_coherency FAIL
1/32 (test1 652/654 failed=2 — cache_coherency's FIRST check failure of the
whole campaign). Enforcement counters quiet in that window (obligation=0
closed=2 deferred=0 — nothing loud). NOT reproduced: 3 subsequent identical
aging sequences (dd → cache → dir_reuse) and a fresh-prep pair all green.
Rate 1/4. Cannot attribute to the enforcement (counters quiet) nor exclude
it. NEXT OCCURRENCE: capture run.sh's preserved per-node logs + the failing
check identities BEFORE re-prepping; check whether test1 (rank1) failing
alone points at a coordinator-role artifact vs data. Ledgered under
D-DIR-REUSE-COHERENCY-32-FLAKY.incident_sess32.
