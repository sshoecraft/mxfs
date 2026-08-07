---
name: ccloop-c7ee71c6-sess47-TAIL11-aprime-needs-new-mount-store
description: sess47 final recon: P220 ledger is INODE-scoped (i_mxfs_pub_*_seq, dies at reclaim) — A-prime requires a NEW mount-level store; design sketch banked…
metadata:
  type: project
---

# A-prime prerequisite finding — do NOT reuse P220 (sess47 last recon)

`P220-EPOCH-LEDGER-OPEN`'s pend/dur/flush = `ip->i_mxfs_pub_pending_seq / i_mxfs_pub_durable_seq / (flush seq)` — **per-xfs_inode fields, destroyed at reclaim** (xfs_mxfs_dlm.c ~13195-13233). Useless for the fossil defense (victims are reclaimed). GPT's "extend the ledger" therefore means BUILD a mount-level store:

## Design sketch (implement fresh, ~250 lines + wiring)
- `mp->m_mxfs_iunl_store`: xarray or hash keyed by ino; entry {u32 gen; u64 fence_epoch; u32 next_unlinked_committed; u64 daddr; u16 slot_off; u8 state}. spinlock or xa_lock.
- INSERT/UPDATE: xfs_iunlink_log_dinode (xfs/xfs_iunlink_item.c:~128) right after the successful `dip->di_next_unlinked = cpu_to_be32(iup->next_agino)` + log_buf — record {ino, VFS gen, next_agino, daddr=ibp->b_maps[0].bm_bn, boffset>>inodelog}.
- RETIRE: cluster-buffer WRITE COMPLETION (pal __xfs_buf_ioend, the existing sess47 inocl stamp site ~2295): for a completed !error write of xfs_inode_buf_ops, retire all entries whose daddr ∈ [bm_bn, bm_bn+len) — home is now current for them. (Target-dropped-write arm: if platter later still stale, entry is GONE and overlay can't help → that arm needs write-side FUA policy instead; the overlay's telemetry (fossil found with NO store entry after clean retirement) is the discriminator.)
- OVERLAY (mini-A-prime): at BOTH installs — read_map cold-fill completion for cluster buffers (site of P-INOCL-COLDREAD, xfs_buf.c ~1516) and coherent_reread_verify before install: for each of ≤64 slots, lookup store by slot's ino (read ino from the fresh image's dinode? no — key by daddr+slot: secondary index or iterate store entries matching daddr range — store is small); if entry matches image gen → overlay 4-byte next_unlinked + xfs_dinode_calc_crc(slot) + P-INOCL-OVERLAY print. Gen mismatch → drop entry (reuse), loud.
- Teardown: unmount purge; fencing/withdraw purge for死 entries? Entries are OUR writes only — unmount-only purge fine.
- GPT constraints honored: value+gen+epoch typed records, retained until HOME completion, CRC recompute, no blind counts, shared-grain safe (only OUR committed values, keyed to exact incarnation).

## Verification plan
Aged soak on the build: P-INOCL-OVERLAY firing + P53 → 0 across ≥8 cycles incl. idle-gap + burst = promotion evidence for D-RSYNC-RENAME-361. The reap repro + matrix guard the -372 family.

Everything else: TAIL8 (ruling), TAIL9 (gate insufficiency), TAIL10 (install site). Rig: 31/32 on 382, test2 down (ring saved).
