---
name: ccloop-c7ee71c6-sess39-END2-327-fourth-green-board-grace10
description: sess39 END2: 0.11.327 (grace=10 default) FOURTH all-green board; dir_reuse 8r+9r in-board (first consecutive 9r); pin defect narrowed (unlink breaks…
metadata:
  type: project
---

# sess39 END2 — 0.11.327 (E178A8149C6A2ABB7D6CAB9) deployed, boarded

## 0.11.327 = dir_ex_batch_grace_ms default 40→10
Evidence: turn p50 81→50ms (three A/Bs), dir_reuse fresh 9r vs 8r. Board on 327: **ALL GREEN (4th all-green: 322/325/326/327)** — dir_reuse in-board TWICE: 8r then **9r (65 checks, 112s) — first consecutive-run 9-rounder**; cc 29s (vs 38s @40 — sess7 concern refuted on current machinery); sustained_load per_op 279→168ms; crash/fence/netpartition/soak green; fio 3313/13455 MiB/s.

## D-DWORK-RUNTIME-PIN narrowed (zero-build discriminators)
- Repro deterministic on 327: 200 creates + sync + drop_caches ×2 on n12 → slab +200 pinned (276), wire-EX slots held WITH memory (not orphaned; demand-release verified: peer stat → EX→PR gen 1→4).
- rm of 100 → those free normally (slab −106): pin breaks on unlink.
- Peer `ls` of parent dir (dir tenure BAST) does NOT release pins.
- NO P36-MHT-REARM/P6R/dwork prints for pinned inos → silent i_count holder, not an active rearm loop. Bounded by unmount.
- NEXT: 0.11.328 diagnostic — param walking sb->s_inodes printing ino/i_count/i_state/d_count for survivors of drop_caches; then fix the ref site.

## Session sess39 total arc (see also sess39-END-326 memory)
- dir_reuse flakiness DISPROVED as mxfs (host SSD write-path, fsync probe p90 26→95ms, nvme awaits below stack; RIG RULE: pace tests need ≥25min idle storage).
- D-EVICT-RETENTION-WIRE-EX-LEAK FIXED AND VERIFIED (326: wire-confirmed-PR retention; 190→0 orphans).
- D-RELEASE-BARRIER-OPEN FIXED AND VERIFIED (census: ~130K unlocks, obligation=0 all 32 nodes, backstop 2× correct).
- grace default landed (327) after its protective board.
- Found: D-STATFS-IFREE-NEGATIVE-RANK1 (n1 m_ifree>m_icount by 10851), D-DWORK-RUNTIME-PIN.

## 9 OPEN
Pace: D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE (re-baseline under rig rule; unlock CAS p50 9.7/p90 44ms is the in-mxfs lever, drain is only 1.6ms).
Authority: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (canary quiet).
Other: D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED, D-STATFS-IFREE-NEGATIVE-RANK1, D-DWORK-RUNTIME-PIN.
Criteria NO — 9 OPEN against RULE-6 zero-defect bar.
