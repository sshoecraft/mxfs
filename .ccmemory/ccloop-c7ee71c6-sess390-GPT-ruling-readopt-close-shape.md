---
name: ccloop-c7ee71c6-sess390-GPT-ruling-readopt-close-shape
description: sess390 RULE-5 ruling on closing AG re-adoption after a pending BAST: explicit capability classes (nonblock -EAGAIN; restartable unwind; resource-fre…
metadata:
  type: project
tags: [sess390, ruling, readopt, AG, handoff, BAST, pinned, PACE-388, 474]
---

# sess390 RULE-5 ruling #2 (gpt-5.6-sol) — shape of "close local re-adoption after a pending BAST" (ruling-2 item 1 / item C)

## Evidence brought
Arm 3 at 25 AGs (0.21.0, ag_readopt_window_ms=50 with blocking acquirers WAITING for the handoff): rsync walls improved for 26 nodes (14-44 s) but test24+test32 wedged: the INODE BAST worker (mxfs_dlm_bast_process -> filemap_write_and_wait_range -> xfs_bmap_btalloc -> mxfs_ag_dlm_lock blocking pass) holding ILOCK_EXCL sat in the closed-admission wait loop; noino fence froze on its inode item outside the agwait bracket (convoy_stalls=0) -> 8 stalls -> shutdown. Evidence tests/logs/ag25_sess390_readopt_close_wedge.txt.

## Ruling
- Choose (c) explicit capability-based classes, fail closed toward PINNED: AG_ACQUIRE_NONBLOCK -> -EAGAIN after the gate; RESTARTABLE -> must NOT sleep at the gate holding ILOCKs/trans — unwind via the proven seam then fresh attested acquire; RESOURCE_FREE -> may wait for release then queue; PINNED (anything that may hold ILOCK/dirty trans/resources a BAST/release path needs, no proven unwind) -> re-adopt the still-owned cached grant, count P12-READOPT-PINNED by callsite. Nested (holders>0) unchanged.
- Interim (a) = nonblock-only close, blocking re-adopts = the safe fallback; preferable to a heuristic (c). Do NOT infer safety from current->journal_info / trans-clean (does not prove no ILOCK); TRYLOCK protocol does not prove the blocking pass can unwind.
- (b) bracket the wait as an AG wait for the fence: REJECTED — accounting does not remove the cross-resource dependency (inode BAST worker holds ILOCK, needs AG, waits on handoff/peer; peer needs the inode) — just a later shutdown / distributed stall; never use fence attribution as a substitute for a legal wait context.
- (d) one-op batching: adjunct only — on a pinned re-adoption set handoff debt, disable adaptive burst/quantum, schedule the worker immediately on last-holder exit, prevent UNPINNED re-adoption for that BAST generation; never make a pinned caller wait because a quota was consumed.
- (e) changing the inode BAST flush / deferring inode handoff on AG contention: not the primary fix (new inode<->AG cross-resource policy; invariant 1 for data pages).
- Required details: tie gate+counters to a BAST generation; serialize holders 0->1 re-adoption against the release CAS; classify EVERY post-gate 0->1 adoption (nonblock rejected / restart / resource-free queued / pinned / default-pinned); pinned status never propagates across adoptions.
- Measure: BAST->gate, BAST->holders==0, holders==0->release CAS, BAST->release p50/p95/p99/max per AG+generation, split by pinned/no-pinned and callsite; P-AGTRY-BASTPEND by callsite; pinned per generation (>1,2,4); worker wake->run; fence convoy counts; rsync wall distribution; allocation AG distribution/skip rate; -488 restart rate; intent relog rate; false ENOSPC; inode BAST latency; splits. Wedge signatures: bast_process->writeback->alloc->gate wait w/ ILOCK; dialloc blocking pass w/ parent ILOCK at gate; dir grow w/ dirty trans at gate; NOTDEFER free-extent at gate; frozen INODE owned by the BAST worker blocked on AG handoff; worker sees holders!=0 with rising pinned count; repeated -488 restarts; reciprocal inode/AG handoff waits across nodes.

## Landed (0.21.2 sv 0D1542A3ABA33D323BA7456)
Interim (a)+(d-adjunct): after ag_readopt_window_ms, nonblock -> -EAGAIN (P-AGTRY-BASTPEND), blocking -> PINNED re-adopt (P12-READOPT-PINNED, quantum_eff=1, stat readopt_pinned=). Knob default still -1 pending A/B.
