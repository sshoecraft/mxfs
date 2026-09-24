---
name: technique-name-a-traceless-memmove-oops-by-stride-and-the-slub-freelist-offset
description: TECHNIQUE (0.89.85): a memmove oops with no call trace: RSI-RDI = element size picks the call site; a garbage count at object_size/2 = SLUB freelist…
metadata:
  type: feedback
---

0.89.84 oopsed in `memmove+0x24` on `mxfs-worker` and netconsole lost the call trace. The registers alone named the site and the cause:

- **Stride:** RSI - RDI = 0x40 on a forward shift-down means `memmove(&a[i], &a[i+1], ...)` with a 64-byte element. `gdb -batch -ex 'p sizeof(struct X)' <obj>.o` over each candidate: `struct v5_depart_req` = 48 (ruled out), `struct mxfs_node_lease` = 64 (dlm/lease.c:669).
- **Count:** RDX / 0x40 gave the element count = garbage. `p &((struct mxfs_lease_ctx *)0)->node_count` = 0x1000, and the ctx is 5448 bytes → kmalloc-8192, whose SLUB freelist pointer lives at object_size/2 = 0x1000. A field that is garbage exactly there while its neighbours (nodes[1]) are intact = the object was **freed**, not stomped.
- **Destination** page-aligned (R08 = ...000) = array at offset 0 of an 8 KiB kmalloc object.

Then the free-vs-user ordering in the teardown function names the race. To prove it, hold the teardown open in the window with a one-shot debug knob (`dbg_teardown_lease_hold_ms`) and add a range check on the count that logs instead of writing: the unfixed ordering fires the detector on every run regardless of the garbage's sign (a negative count just skips the loop, so the raw oops is only ~50%). tests/concurrent_umount_lease.sh.

Also: `mxfs-worker` is the name of EVERY `mxfs_pal_thread_create` thread (pal/linux/kern.c:1990), so the comm names no subsystem.
