---
name: sess38-DECISIVE-loss-is-stale-EX-grant-bufepoch-eq-masterep
description: sess38 DECISIVE: 8/tcp dir_reuse loss buffer reads buf_epoch==master_ep==current yet content-stale = STALE EX GRANT (node retains EX across a peer mo…
metadata:
  type: project
---

## sess38 DECISIVE — the 8/tcp dir_reuse readdir=799 loss is a DLM STALE-EX-GRANT, not dir-block staleness. (build DA3255E3, dir_tenure_evict=1 dataclobber=1, run failed round 10.)

### THE MEASUREMENT (added true MASTER epoch `mxfs_v5_dlm_inode_dir_epoch` to P-DATACLOBBER-SKIP; the prior cur_epoch field was ex_grant_seq = wrong namespace):
The genuine loss clobber (filter comm!=rm; the buf=disk-1 xfsaild reflush of dir block 0):
`kind=data daddr=120 buf_cnt=154 disk_cnt=155 bufgen=8 dirgen=8 buf_epoch=329 master_ep=329 mode=5 real_mode=5 master_self=0 in_txn=0 in_ail=1 bdirty=0 pin=0 stale=0 comm=xfsaild`
- buffer is ONE dirent behind durable disk (154 vs 155) → xfsaild reflushes 154 → drops a peer's entry = the readdir=799.
- **bufgen==dirgen==8 AND buf_epoch==master_ep==329** → the buffer reads FULLY CURRENT by BOTH the gen token AND this node's own grant dir-epoch, yet its content is stale. NO read-side gen/epoch mechanism can catch it (this is why dir_tenure_evict only gets ~67% — the epoch the buffer carries EQUALS the epoch the node currently holds).

### WHY buf_epoch==master_ep while stale (the DLM root):
- `mxfs_v5_dlm_inode_dir_epoch` returns THIS node's CACHED grant dir_epoch (the value from its last grant response), NOT a live master query (dlm/v5_mount.c:1190 → mxfs_dlm_grant_dir_epoch = local lock entry).
- The master advances the epoch ONLY on a cross-node HANDOFF (dlm/dlm.c dg_grant_ex:2601 `dg_shadow[mine].epoch++` when last_owner != new owner). P64-MASTER-HANDOFF fired ~1100×/node, so handoffs ARE detected + epoch advances on the master.
- For test1 to hold grant epoch 329 while a peer added the 155th entry: a peer must have gotten EX (handoff, master epoch→330) and modified, then test1 should re-acquire (→331). But test1's epoch is STILL 329. **So test1 retained a STALE EX grant at epoch 329 across a peer's EX-modify** — it never observed the handoff. = a DLM mutual-exclusion / BAST-delivery failure.

### CORROBORATION:
- **P-STALEMASTER-GRANT fired** (1× on test2, 1× on test5) = SPLIT-BRAIN MASTERSHIP: a node reached a master-side EX grant for a resource the lockless recompute says it no longer masters (membership flap → two masters → concurrent EX the per-master dg_shadow P-DOUBLEGRANT canNOT see). dlm/dlm.c:2546.
- **P-DOUBLEGRANT fired 0×** — the single-master shadow table is internally consistent; the violation is CROSS-master (split brain) or a missed/dropped BAST leaving a stale cached EX.

### IMPLICATION / why 37 sessions of dir-block heuristics couldn't fix it: the freshness tokens (b_mxfs_dir_gen, b_mxfs_dir_epoch) LIE — they read "current" on a stale buffer because the node believes it still holds the EX tenure (epoch 329) under which the buffer was stamped, while a peer modified the block under a concurrent/handed-off EX the node never observed. GPT's verdict (sess38-GPT-...) names exactly this: writeback/freshness authority must come from the DLM, and a node must NOT retain writeback-capable state for a resource whose EX it has effectively lost.

### NEXT (DLM-layer, RULE 4): the fix is in dlm/ — either (a) split-brain mastership: make EX grants reject/recompute when the granting node is no longer the hash-master (close the P-STALEMASTER-GRANT window — membership-stable mastership or a master-handoff barrier), or (b) missed-BAST: a node holding cached EX must lose it reliably when the master hands EX to a peer (BAST delivery/ack, or a grant-epoch in the heartbeat that a stale holder checks). Decisive next probe: at the loss clobber, dump the master node's view (who holds EX for ino 131 right now) vs test1's local real_mode — to confirm test1's EX is stale vs the master. Consider GPT consult #2 (this issue) on the DLM stale-EX/split-brain fix. See [[sess38-DECISIVE-clobber-is-inail-clean-nonstale-subset-genblind]] [[sess38-GPT-architectural-fix-inail-survives-handoff-release-retire-genbump]] [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]].
</body>
