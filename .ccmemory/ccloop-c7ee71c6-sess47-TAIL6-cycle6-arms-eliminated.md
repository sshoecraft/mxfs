---
name: ccloop-c7ee71c6-sess47-TAIL6-cycle6-arms-eliminated
description: sess47 cycle6: fatal P53 recurred on 381 (test2 t=10038, ring saved) with delwri tripwire SILENT + fence active — remaining arm = raw coherent re-rea…
metadata:
  type: project
---

# Cycle-6 fatal recurrence (0.11.381, test2, t=10038) — arm elimination complete

Ring: test2:/root/cyc6_t2_*.dmesg (saved pre-recovery). `P53-IUNLINK-MISMATCH ino=0x3000085 old_ptr=0x83 expected=NULL next=0x82 dip_gen==i_gen bli_dirty=1 uncp=1 b_flags=0x20` → 0x8 shutdown → withdrawal (slot 24). Preceded by repeated P-INOCL-COLDREAD fence=1 on agno 24 cluster daddrs (50237760/50240960/50240992) at t=10035-10037.

## Eliminated by direct evidence
- Delwri-window re-read arm: P-PINNED-REREAD (which now covers _XBF_DELWRI_Q) = ZERO through the event.
- Target-cache time-travel closable-by-flush arm: fence issued flushes on every cold-in-window read and the fossil formed anyway (second independent demonstration; first was the 377 wave).
- P-B-MODE-DIVERGE / P-IFR-AGI-STALE: zero — not the authority/AGI arms.

## PRIMARY REMAINING ARM (relay's first move)
The RAW coherent re-read path: mxfs_buf_is_multinode_dir_meta (pal/linux/xfs_buf.c ~1130, includes xfs_inode_buf_ops since 07-16) feeds a "coherently re-read straight from the shared medium" helper (~1170) that DMAs into b_addr WITHOUT passing xfs_buf_read_map — so BOTH the inocl fence AND the P-PINNED-REREAD tripwire are blind to it. If that helper refills a cluster buffer whose iunlink write is committed-but-undestaged, the delta dies exactly as observed (no probe fires).
INSTRUMENT: in that helper (and any other raw refill of cluster buffers — P34D src=plain reload path too), before DMA: if ops==xfs_inode_buf_ops && (bli dirty || pinned || DELWRI || mxfs_buf_has_uncheckpointed_mods) → P-INOCL-RAWREREAD-OVER-LOGGED print + dump_stack (report-only first). Also print per-refill fingerprint (daddr + pre/post di_next_unlinked of the affected slot if cheap).
Then decide fix shape with GPT: per-slot merge (P56-CORESIDENT precedent) vs refuse+in-place complete (P61 precedent — but sess122 AGI counter-lesson applies to shared-grain) vs destage-before-refill.

## Rig at handoff
test2 WITHDRAWN pending re-prep (ring saved; safe). Other 31 green. 5 clean cycles + this fatal on cycle 6 = producer rate ~1/6 cycles on 381. All other sess47 state per TAIL5/END memories.
