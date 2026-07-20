---
name: sess52-CORRECTION-datablocks-coherent-MATCH-loss-is-writeside-not-stale-read
description: sess52(ccloop) CORRECTION: P28-PLATTER proves dir DATA blocks are COHERENT (incore==platter MATCH) at modify; readdir=799 loss is WRITE-SIDE (sess28…
metadata:
  type: project
---

## sess52 — DECISIVE CORRECTION (supersedes the stale-read framing in [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]])

### The decisive measurement (build 236772FA, dirwr=1 dir_addname_epoch_refresh=1, FAIL run p28_run1)
P28-PLATTER (xfs_dir2_node.c:2074 — FUA-reads the platter at addname, compares to in-core buffer):
- **MATCH:14/537/547/564/483/597/483/604 per node; DIFFER: only 0/6/5/2/4/2/5/3.** Every DIFFER has `dirty=1` (our OWN in-flight add — expected, benign).
- Correlated the clobbered block to its P28-PLATTER: `daddr=6279744 b_epoch=378 valid=385 done=1 dirty=0 in_ail=0 incore_vs_platter=MATCH` immediately followed by `P-STALEBASE-MODIFY daddr=6279744 b_epoch=378 valid_epoch=385`. **The block is COHERENT (in-core==platter) even though its epoch tag lags (378<385).**

### What this PROVES / corrects
- The dir DATA block read by xfs_dir2_node_addname IS coherent vs the platter. **The loss is NOT a stale cached DATA-block read.**
- My `P-STALEBASE-MODIFY` probe (xfs_dir2_data.c:~1289, gated dirwr) has **FALSE POSITIVES**: `b_epoch < valid_epoch` only means the block wasn't modified since epoch 378 — NOT that it's stale (it MATCHes the platter). Epoch-lag ≠ staleness. Do not chase the epoch-tag as a stale-read signal.
- Therefore `dir_postread_reread=1 dir_postread_leaf_only=0` (force FUA re-read of epoch-stale DATA blocks) did NOT fix it (P67 fired ~1×; nothing to re-read — blocks already coherent). REFUTED this session.
- The existing acquire-side coherency (`dir_addname_coherent=1` default, FUA-read+compare+restart on DIFFER) is WORKING — DATA reads are coherent. Not the gap.

### So the root is WRITE-SIDE (re-confirms [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]])
The block is coherent at READ+MODIFY, but the loss is durable. Sequence (sess28): node X reads block coherently (MATCH), adds entry, commits (block in AIL), releases EX; peer Y adds to the SAME block durably in a later tenure; xfsaild destages X's OLD in-AIL image (pre-Y) over the platter → reverts Y's add. The read-coherent + write-side-revert = "diff0" sess28 already proved. Release-side airtight durability (data_durable loop, xfs_mxfs_dlm.c:9557) does NOT close it (sess44: whole-AIL bounded push still loses).

### Still-OPEN: why does X's in-AIL block survive release to be destaged stale?
Release pushes data_durable to completion (xfs_bwrite per block, unbounded). After that the block should be OUT of AIL. For sess28's destage to fire, the block must be RE-LOGGED after release OR the push misses it. The sound fix sess28 named (reacquire-site transactional 3-way merge of holder's delta onto fresh disk base, incl. leaf) was NEVER landed; `dir_write_merge=1` (write-chokepoint graft) WEDGES the cluster (sess52 confirmed) + leaf-incomplete; `dir_release_retire_done` REFUTED HARMFUL (round-1 readdir=0 CRC shutdown).

### GPT consults this session (both already-implemented → low yield)
- GPT#1: release-side EX-demotion barrier = ALREADY implemented+on.
- GPT#2: epoch-gate at da_read_buf + disable readahead + assertion-at-log-join. Readahead already off (dir_no_reada=1); da_read_buf epoch gate exists (P67); the assertion-at-log-join is what found the (false-positive) epoch lag. Net: confirmed DATA reads coherent.

### NEXT SESSION
The bug is write-side stale-in-AIL destage of a COHERENTLY-READ block (sess28). Focus: instrument WHY X's committed block survives the airtight release push into AIL and gets re-destaged after a peer supersedes it. Candidate: the block X commits is NOT the same daddr the release-loop drains (X's add lands in block B1 but the free-index/leaf update dirties B2 which isn't in the data_durable walk), OR a 2nd op re-logs it post-push. Build a probe at xfsaild dir-block destage (comm=xfsaild) that logs daddr + whether a peer superseded it on the platter (FUA compare) — the P-WMERGE infra (dir_writeprobe) already does this; run it to a FAIL and read held_mode/in_ail/comm at the clobber. Build 236772FA = baseline + gated probes (dirwr off = baseline-equiv). Marker NOT written.
