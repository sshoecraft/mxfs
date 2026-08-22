---
name: ccloop-c7ee71c6-sess389-GPT-ruling-publication-durability-gate-F1-F4
description: sess389 RULE-5 ruling on the publication-durability gate: F1 narrow PUBOB-at-PR flush, F2 converter honesty + re-log repair, F3 no ledger discharge o…
metadata:
  type: project
tags: [sess389, ruling, publication-obligation, P119, PUBOB, fossil-next-unlinked, reload, LOCAL_UNLINK]
---

# sess389 RULE-5 ruling (gpt-5.6-sol) — publication durability gate

## Measured chain brought to the consult (test10 ino 130023711 / test7 ino 92277034, identical)
P82-ADD (unlink committed while inode DLM mode was PR after a mid-drain re-acquire, P15-REL-ABORT)
-> P244-REL-TERMINAL-DEFER pend=1 dur=0 (release correctly deferred)
-> xfsaild P119-NONEX-FLUSH-SKIP i_dlm_mode=3 incore_nlink=0 disk_nlink=1 in_ail=1 (conversion LAUNDERED: clean, never written)
-> P245-REL-OBLIGATION-CONVERT rc=0 (mxfs_iflush_agino_target trusted xfs_inode_clean -> wrote nothing)
-> reload: P3-REFUSE-OLDER-DISK kept newer in-core BUT discharged the ledger (P177 identical=1) AND cleared MXFS_IF_LOCAL_UNLINK (sess19 clear at reload entry)
-> INACT-SKIP-STALE torn-live-no-local-unlink (B3 guard) -> inode never freed, AGI entry never removed
-> P88-PUBOB-RECLAIM-REFUSED every 5s, P88-PUBOB-UNREPAIRED x60/node per AG release, P87-PUBLISH-DEFER-EXHAUSTED 2x2s -> >4s dirent visibility (dirent_durability aged-lap FAIL) + fossil di_next_unlinked family.

## Ruling (verbatim essentials)
Invariants: an open obligation pins >=PR authority until the home write COMPLETES (not submits); only the owning node may perform the sanctioned PR write; reload cannot manufacture durability; a clean-but-mismatching inode must have a bounded repair writer; freer authority tied to the unlink incarnation.
- F1 (PR-held flush): viable ONLY narrowed to an OWNED PUBOB (MXFS_IF_PUBOB + nlink==0 + PR + same incarnation + live same-type slot + item in AIL + not poisoned), NOT generic pending!=durable (that would sanction PR writes of ordinary reg-file metadata). Hazards ranked: (1) authority-pin through I/O COMPLETION (P244 terminal gate does this: durable advances only in xfs_iflush_finish); (2) whole inode-cluster buffer sibling lost-update (pre-existing: ledger D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, P-CLMERGE); (3) uniqueness of sanctioned PR writers (PUBOB is node-local -> one owner); (4) TOCTOU of disk validation; (5) reg-file fork write conditional.
- F2: return distinct statuses (ALREADY_DURABLE / WROTE / CLEAN_MISMATCH / error); NEVER success on xfs_inode_clean alone; a narrow re-log-and-flush repair IS needed (pre-existing laundered inodes, residual paths) — re-log only core, pipe_relog so pending not bumped, sync flush, durable advances through the captured seq; audit tx-alloc vs locks (D-380 fault-inject target).
- F3: correct direction; kept-ahead (P3/P34F/P184) must NOT discharge; 'real adopt => durable' is not a proof either — a different-incarnation adopt is CANCELLATION/supersession, not durability; 'identical' predicate must include nlink. F3 must not ship without the F2 repair writer (else D-380 reopens).
- F4: preserve LOCAL_UNLINK on no-adopt/refused reload; 'different incarnation only' too weak as the complete rule — clear on every REAL adopt; destructive inactivation must revalidate under EX. F5 (PUBOB as freer authority) REJECTED.
- Landing order: F2 -> F3 -> F1 -> F4 as one unit, all nodes upgraded together. Verification: counters listed (P119 launder on owned PUBOB at PR=0, P177 discharge on keep=0, CLEAN_MISMATCH unrepaired=0, torn-live on local unlink=0, P88-UNREPAIRED=0, P87 exhaustion=0, LOGSAME=0, shutdowns=0) + on-disk AGI chain walk + fault-injection (pause after F1 eligibility; after submit before completion; P119 launder injection -> F2 repairs; sibling-dinode two-node test; crash points).

## Landed as 0.19.40 sv 912348C9747EAF8EB700B03 (xfs/xfs_inode.c F1 P55B-PUBOB-PR-FLUSH + mxfs_pubob_relog_core/P245-RELOG/P245-CLEAN-MISMATCH; xfs/xfs_mxfs_dlm.c reload_kept_ahead, P177-KEPT-AHEAD-OBLIGATION-OPEN, P177-PUBOB-SUPERSEDED, LOCAL_UNLINK clear moved to the real-adopt branch, identical predicate + di_nlink).
