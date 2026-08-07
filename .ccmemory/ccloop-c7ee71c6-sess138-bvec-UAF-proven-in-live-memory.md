---
name: ccloop-c7ee71c6-sess138-bvec-UAF-proven-in-live-memory
description: sess138 PROOF of the SCST fileio bvec UAF read out of live kernel memory: 3/3 kmalloc'd bvec arrays corrupted, 1/1 inline small_bvec intact.
metadata:
  type: project
tags: [scst, vdisk_fileio, use-after-free, loop, evidence, loop_unwedge, infra]
---

# sess138 — the SCST fileio bvec UAF, proven from live memory (not code reading)

sess137 root-caused this by reading `scst_vdisk.c` + `block/bio.c` and matching
an oops trace. sess138 went one better: `scripts/loop_unwedge/` (act=0, inspect
only) walked the four leaked loop0 requests' bvec arrays **in situ** and printed
them. Raw dmesg: `tests/evidence/sess138-scst-bvec-uaf-live-proof.txt`.

## The natural experiment

`vdisk_alloc_async_bvec()` uses the inline `p->async.small_bvec[4]` when the
command has <= 4 segments, else `kmalloc_objs()`. `fileio_exec_async()` frees
the kmalloc'd one unconditionally after submit, including on `-EIOCBQUEUED`.
So the >4-segment requests should be corrupt and the <=4-segment one should be
clean. That is exactly what the memory shows:

| rq | segs | bytes  | bvec source | state |
|----|------|--------|-------------|-------|
| 0  | 6    | 24576  | kmalloc     | **bv[3].bv_page pfn=0xff6e4207cea1c8c4 garbage**; bv[0..2],[4..5] valid |
| 1  | 15   | 61440  | kmalloc     | **bv[8].bv_page pfn=0xfe51e93acd313877 garbage**; other 14 valid |
| 2  | 31   | 126976 | kmalloc     | **bv[0] wholly clobbered: len=3625077377 off=446471261 pfn=0x2500000000** |
| 3  | 1    | 4096   | small_bvec  | **fully intact** (pfn=0x14ff7d len=4096 off=0) |

3 of 3 heap arrays corrupted; 1 of 1 inline array clean. The >4-segment trigger
boundary is now measured, not inferred.

## It matches the oops registers exactly

The sess137 GPF was:

```
general protection fault, probably for non-canonical address 0xdb9078b3a872313c
RIP: dma_direct_map_sg+0xa3/0x140   RBX=3 (sg index)   R12=6 (nents)
```

rq[0] is the 6-segment request and **bv[3]** is the corrupted entry. sg index 3
of 6 nents. The register file and the live bvec array agree on the same slot.

## Corruption shape: partial slab reuse

In rq[0] and rq[1] a **single 8-byte slot** — `bv_page` — was overwritten while
the adjacent `bv_len`/`bv_offset` in the same 16-byte bio_vec survived intact.
The recycled slab object's new owner wrote one pointer at that offset. In rq[2]
the whole first 16 bytes went.

This is why GPT's "a clean run does NOT establish absence" ruling is right in a
much sharper sense than expected: the freed array usually still *looks* valid.
Most entries survive. Corruption is sparse and positional, so a workload can
complete with plausible data and one silently wrong page.

## Consequence for the completion path (design input for loop_unwedge)

`blk_mq_end_request()` -> `blk_update_request()` -> `req_bio_endio()` ->
`bio_advance()` -> `bvec_iter_advance()`, which does

    while (bytes && bytes >= bv[idx].bv_len) { bytes -= bv[idx].bv_len; idx++; }

rq[2]'s `bv[0].bv_len = 3625077377` makes that loop consume the whole request in
one step and then read past the array; a garbage `bv_len == 0` would spin
forever. **You cannot force-complete these requests through the normal path.**
`loop_unwedge` therefore detaches `rq->bio`/`rq->biotail`, ends the (now
bio-less) request so `blk_update_request()` returns immediately, and terminates
each bio by hand: set `bi_status`, zero `bi_iter.bi_size`/`bi_bvec_done`, call
`bio_endio()`. No bvec is ever read.

Verified safe on every layer above (6.8.0-101 headers):
- `bio_release_pages()` is `if (bio_flagged(bio, BIO_PAGE_PINNED))` — and
  `bio_iov_bvec_set()` never sets BIO_PAGE_PINNED, so it no-ops.
- `bio_free()` -> `bvec_free(pool, bi_io_vec, bi_max_vecs)` with
  `bi_max_vecs == 0` for a bvec-set bio, so the SCST array is never double-freed.
- `fileio_async_complete()` (scst_vdisk.c:3120) with `ret < 0` takes the
  `scst_sense_hardw_error` branch and returns via `scst_cmd_done` without
  touching the bvec. The `do_verify` branch is `ret >= 0` only.

## Gotcha for anyone validating a struct page pointer in a module

`virt_addr_valid(struct page *)` is **always false** — a struct page lives in
vmemmap, not the direct map. The first survey pass flagged every page as bad
because of this. Use `pfn_valid(page_to_pfn(pg))`; `page_to_pfn` is plain
pointer arithmetic against vmemmap and is safe to evaluate on any value.
