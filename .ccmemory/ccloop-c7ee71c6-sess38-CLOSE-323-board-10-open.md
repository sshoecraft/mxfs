---
name: ccloop-c7ee71c6-sess38-CLOSE-323-board-10-open
description: sess38 CLOSE: 323 board 26/27 (dir_reuse red, bimodal); test21 SELF-FENCE during rsync -> NEW D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE; 10 OPEN; ne…
metadata:
  type: project
---

# sess38 CLOSE — final boundary

## 0.11.323 board @ 32/caw (all four chunks run)
26/27 functional green; dir_reuse red this board (5-round lap — bimodal, OPEN). Board incidents:
1. **test21 SELF-FENCE during rsync_paired** → NEW DEFECT **D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE** (#10): P15-REL-ABORT orph=1 loop (entry_gen==now_gen, gen_moved=0, age_starve climbing at 26ms cadence; ~600 dmesg lines/s storm) starves the disklock heartbeat past the lease; n1/n2/n20 all logged "slot 1 heartbeat expired after 0 checks — fencing"; test21 got reservation conflicts → EIO → shutdown. RECOVERY WORKED CLEANLY (fence, slice replay by test1, slot reclaim, 31/32 green; rsync re-run PASS 20s). Evidence tests/logs/sess38_t21_selffence/. Next steps in ledger: why the abort loop never breaks (identical abort reason repeats), what the heartbeat writer shares with release traffic, bound/escalate + prioritize heartbeat I/O; GPT before patching.
2. crash_consistency NO_TERMINAL_RECORD×32 once (barrier pile-up at its 90s box), re-run PASS 21s — transient.
3. seqW aged-fs 1071 vs 7721 MiB/s fresh (PASS both) — aging effect, future look.

## Cluster at boundary
32/caw on 0.11.323 (62A92FF1), defaults, healthy, freshly re-prepped mid-board after the fence; last actions all green.

## OPEN = 10
Pace: D-DIR-REUSE (bimodal 5-8 rounds), D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE.
Authority family: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (canary armed).
New: D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE.
Other: D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED.

## NEXT SESSION picks (any order defensible)
- D-RELABORT self-fence RULE-4 (fresh, reproducible-ish under rsync load; the loop's break-condition read + GPT).
- dir_reuse margin: release-drain pipelining design (GPT-first).
- Authority family batch design (incl. AGI canary watch).
All sess38 records: CHANGELOG 319-323 + 3 addenda; ledger; 4 ccmemory entries; awareness dlm/xfs/pal updated. Criteria NO.
