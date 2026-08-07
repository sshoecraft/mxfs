---
name: ccloop-c7ee71c6-sess168-adopted-arm-MEASURED-purge-proven
description: sess168: adopted-mount shadow-eval arm MEASURED (capable=0, notheld=7/7, uncap_match=0, WOULD_APPLY=0, csum exact) — purge PROVEN vs sess167 elected…
metadata:
  type: project
tags: [mxfs, sess168, foreign-replay, P273, shadow-evaluator, adopted-slice, rig-measured]
---

# sess168 — adopted-mount arm measured: the purge-worked outcome, completing the A/B

## How the sample was taken (repeatable procedure)
After a foreign_replay_ab kill+recovery cycle, the victim VM is rebooted un-prepped.
Mount it into the LIVE cluster (NO prep_cluster — that re-mkfses and destroys the slice):
1. `tools/mxfs_sshpass.sh testN "mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp"`
2. `tools/mxfs_sshpass.sh testN "MXFS_DEV='/dev/mapper/mpatha' MXFS_KO_MD5='<md5sum mxfs.ko>' bash /src/mxfs/tests/setup/prep_node.sh caw"` (~10s, NODE_PREP_OK)
The rejoin does a pass-2 fresh claim of the consumed slot (same slot number — first-free scan), `slice_adopted=true`, ADOPTED_SLICE gate set, victim_slot = own slot, and the shadow evaluator runs over the STILL-DIRTY slice at its own mount-time recovery (elected foreign replay never writes a clean marker into the victim slice — shadow xlog is read-only wrt slice state).

## THE MEASUREMENT (test7 rejoin after sess167's kill of slot 22, build 0.11.460/460F52B)
- `disklock: claimed heartbeat slot 22 ... fresh claim — slice ADOPTED` (attempt 0)
- `P273-SHADOW-CAP victim_slot=22 desc_rc=-2 stage=0 victim_epoch=0 victim_node=0 capable=0` — descriptor consumed/gone, exactly the designed adopted-arm shape.
- Same slice content as sess167's elected replay (7 v2 buf tokens, txns lsn=0x1000001c3 items=6 / 0x1000001c9 items=43, oepoch=7649372583590094136 node=1294269649): P227 containment wapply=0 wskip=7, both txns ATOMIC-SKIP.
- **P273-SHADOW-EVAL victim_slot=22 capable=0 buf=7 csum=7 untagged=0 malformed=0 v1=0 ... notheld=7 uncap_match=0 WOULD_APPLY=0 txn=2 none=2 missed_txns=0 uncached=0** — conservation EXACT; every token answers NOT_HELD.
- CAP=1 EVAL=1 (exactly-one-summary holds in the adopted path too).
- Post-join sweep: test7 1/1/1 conserved, cluster 31/31/31, all P246/P247/P248=0, phantom/backstop/publive=0. test7 dmesg clean (only benign boot noise; two t=10s `reservation conflict` = PR fence correctly blocking the unregistered reboot — fence working).

## What the A/B proves
Same journal content judged in both arms:
- **Elected arm (sess167)**: capable=1 (FENCED descriptor), manifest HELD → WOULD_APPLY=7/7, txn all_apply=2.
- **Adopted arm (sess168)**: capable=0 (descriptor -ENOENT), manifest PURGED → notheld=7/7, WOULD_APPLY=0, txn none=2.
The completed recovery's manifest purge is PROVEN observable end-to-end: post-recovery, NO stale authority survives that would authorize re-application (uncap_match=0 — the unpurged-manifest finding did NOT fire). The adopted-slice suppression gate (sess32) loses nothing on this evidence: the evaluator independently agrees nothing was applicable.

## Remaining unexercised arms (GPT sess166 menu)
desc -EPROTO/stage!=FENCED (degraded descriptor), spill >fill-cap, alloc failure, adopted-after-reacquisition, error-exit⇒one-summary. These are enforcement-phase forced tests; sampling continues opportunistically with every AB run (harness harvests P273 automatically).

## Rig state after sess168 sampling
All 32 mounted and formed on 460F52B (test7 rejoined at slot 22). Cluster is BOARD-READY — no prep needed (do NOT force prep unnecessarily; it re-mkfses).
