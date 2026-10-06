---
name: trap-a-write-bound-that-admits-the-only-write-is-defeated-by-large-folio-writeback-bios
description: TRAP (0.90.70): on 6.17 large-folio writeback built a 392 MiB bio; a bound that lets "the only write" through whatever its size was full by one bio.…
metadata:
  type: feedback
tags: [drbd, writeback, large-folios, bio, trap]
---

0.90.70's DRBD write bound (pal/linux/drbd.c, 4 MiB / 64 requests per mount) admitted a write larger than the bound when nothing else was in flight, so it could never starve. On 6.17, iomap writeback on large folios builds bios of hundreds of MiB (BIO_MAX_VECS folios each up to MAX_PAGECACHE_ORDER): `P-DRBD-IOQ-DONE ... peak_kib=401408` = one 392 MiB bio admitted alone. Everything behind it waited: coordination swaps up to 0.97 s even on NVMe, O_DIRECT writers at 1.4-1.8 MiB/s with 8-10 s median completion, while the buffered writer ran at 80-115 MiB/s. DRBD splits a bio to its own 1 MiB limit only after it has queued all of it, so the queue depth the bound exists to cap was 392 MiB.

How to apply: any in-flight bound on bios must split large ones before admission (0.90.71: bio_split from the front into pieces of at most 1 MiB, bio_chain to the remainder, admit and submit each). Judge a bound by its peak in-flight bytes, not by its request count. Never split REQ_NOWAIT (a refusal after a piece went out cannot be retried whole) or REQ_ATOMIC bios (bio_split refuses them with -EINVAL on new kernels). A pre-6.9 kernel's iomap chains its own writeback bios and submits them itself, so a filesystem hook never sees those.
