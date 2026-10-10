---
name: trap-a-bio-hook-that-calls-the-restored-bi-end-io-directly-panics-on-linux-7-0-for-a-chained-piece
description: TRAP (0.90.108-110): drbd write window restored bi_end_io and called it; for a bio_chain piece that is bio_chain_endio = BUG() on 7.0. Use bio_endio(…
metadata:
  type: feedback
tags: [kernel-version, bio, drbd, panic, pve]
---

Linux 7.0 (block/bio.c:367): `static void bio_chain_endio(struct bio *bio) { BUG(); }` — bio_endio() recognises it and unrolls the chain itself; nothing may call it. On 6.17 it still completed the chain, so code that worked on the physical PVE pair (6.17.2-1-pve) panics on Proxmox's 7.0.14-19-pve.

Bit us: pal/linux/drbd.c mxfs_ioq_end_io (the DRBD write window) saved bi_end_io/bi_private, and its completion restored them and called `bio->bi_end_io(bio)`. mxfs_pal_ioq_admit splits writes larger than the window's chunk (1 MiB) and bio_chain()s each piece to the remainder before hooking it, so the restored end_io was bio_chain_endio: 'kernel BUG at block/bio.c:367' in drbd_ack_receiver on the first large writeback (a 256 MiB buffered write + fsync). One host panicked outright (BUG in irq context, spun in vpanic), another lost its DRBD ack receiver and had to be reset.

Rule for any bio completion hook: restore the fields and call bio_endio(bio) (blk-crypto-fallback's pattern); the second pass is safe — a chained parent's flag is cleared on the first pass, and a bio-based device's bio has no QoS/integrity state to double-count. And test anything in pal/linux on the 7.0 kernel (nested pair), not only the physical pair's 6.17.
