---
name: ccloop-c7ee71c6-sess39-END4-330-fifth-green-board-7-open
description: sess39 END4 (final): 0.11.330 FIFTH all-green board; 5 defects closed this session (4 FIXED+VERIFIED, 2 DISPROVED, 3 found); 7 OPEN; next = authority…
metadata:
  type: project
---

# sess39 END4 — final boundary. 0.11.330 (07221E465DACB41A215A08E) deployed+boarded.

## Session net: 9 → 7 OPEN (found 3, fixed 4, disproved 2)
FIXED AND VERIFIED:
1. D-EVICT-RETENTION-WIRE-EX-LEAK (326): retention now wire-PR-confirmed.
2. D-RELEASE-BARRIER-OPEN: census ~130K unlocks obligation=0 all 32; backstop 2× correct.
3. D-STATFS-IFREE-NEGATIVE-RANK1 (328): statfs from cluster-coherent perag sums + mount-time all-AG init; cross-node agreement verified; NO negatives after churn; percpu admission counters untouched (GPT: no safe external adjust). RESIDUAL THREAD (unobserved, needs fill test): near-ENOSPC cross-node delalloc overcommit; fix shape = cluster reservation-credit ledger (GFS2 precedent).
4. **D-INODE-WIRE-EX-ORPHAN-ON-EVICT (330) — the TRUE slot-leak mechanism**: sess44 deferred-publish evict skip ('unpublished ⇒ no on-disk slot') is violated — every created file's type-1 slot exists (gen=1 EX) while still on the unpublished list → skip orphaned 1 slot/created-then-evicted file (the 13.4K population). dlmtr watch-ring named the line (m5>0 in the unpublish_drop branch). Fix = wire-truth hint-read at the skip (P-UNPUB-WIRE-DESYNC → real release). Verified: single-file LIVE gen=1 → TOMB gen=2; bulk 200 → live=0 tomb=200; full board green.
DISPROVED:
5. D-DIR-REUSE-COHERENCY-32-FLAKY: host rig storage (fsync probe p90 26→95ms below the stack; nvme awaits; RIG RULE ≥25min idle for pace tests).
6. D-DWORK-RUNTIME-PIN: upstream mapping_shrinkable design (page-held inodes off-LRU; echo 3 evicts; my echo-2 repro artifact). 329's lru_sweep default 0 (opt-in diag only, it fights the kernel and no-ops).

## Boards: FIVE consecutive all-green (322, 325, 326, 327, 330); dir_reuse in-board 2×/board on 327+330.
grace=10 default (327). Builds this session: 326 (retention wire-check) → 327 (grace) → 328 (statfs+pin_census) → 329 (on_lru + sweep, sweep now default-0) → 330 (evict wire-truth).

## 7 OPEN
- Authority: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (canary armed, quiet ALL sess39 incl. 5 boards' crash/fence cycles).
- Pace: D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE — re-baseline under RIG RULE; in-mxfs lever = wire-unlock CAS (P138 sx p50 9.7/p90 44ms, backoff ≤20ms); drain refuted (1.6ms).
- D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED.

## Techniques bank (sess39 additions)
- dlmtr per-ino ring: echo INO > watch_ino BEFORE create (ino prediction: next ≈ last+1); dump via stat <dir>/.mxfs_dirdump; P12-DLMTR lines carry m/s transitions + LINE numbers.
- pin_census param: refcount/i_state/on_lru/DLM/work state of every cached inode.
- Table parse (host): O_DIRECT read /home/steve/disk.img @67149824, 65536×512; live=0x4D584357 tomb=0x4D58444C; ino@+16 hex@+40 gm@+88 gen@+4.
- mxfs_v5_dlm_inode_granted_mode = wire-truth hint-read; the 326+330 fixes both use it — 'trust the wire, not the bookkeeping' is the proven pattern for evict-time decisions.
- P140 prints ino in HEX. P141 caps 500/boot. instr=1 enables idbg (P-H22 etc.) — sysfs, no build.
- Hygiene follow-up (optional): find the create/publish path that claims type-1 slots without clearing i_dlm_unpublished.

## Criteria: NO — 7 OPEN against RULE-6 zero-defect bar.
