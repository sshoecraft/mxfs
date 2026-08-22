---
name: scst-pr-overflow-caused-BOTH-clyde-wedges-jbd2-and-pagetable
description: CORRECTION+PROOF: the SCST PR READ FULL STATUS overflow caused BOTH 2026-08 clyde wedges. 08-20 corrupted a buffer_head (bh->b_state = ASCII Transpor…
metadata:
  type: project
tags: [scst, clyde, host-wedge, jbd2, ext4, memory-corruption, root-cause, pstore, erst, correction]
---

Supersedes the first read of the 2026-08-20 wedge. Root cause of the overflow
itself: `scst-pr-read-full-status-overflow-wedged-clyde-ROOT-CAUSE`.
Full write-up: `docs/host-safety.md`.

## The correction

The 2026-08-20 boot has **zero** `BUG:`/`Oops` in `journalctl -b -2 -k`, so it
read as a pure jbd2 deadlock caused by the SCST trace flood. **Wrong.**
journald could not write once the root ext4 wedged, so nothing after 19:24:43
reached the journal. The faults are in **pstore/ERST**, and that boot reached
**Oops #9**.

## The proof (one incident, decoded byte for byte)

`/var/lib/systemd/pstore/7675903811256320028/dmesg.txt`, oops #3:

```
BUG: kernel NULL pointer dereference, address: 000000000000000c
Oops: 0002 [#3]  Comm: CPU 0/KVM  Tainted: G      D W  OE
RIP: 0010:jbd2_journal_grab_journal_head+0x29/0x80
RDX: 66786d2d39717473
jbd2_journal_try_to_free_buffers <- ext4_release_folio <- filemap_release_folio
 <- shrink_folio_list <- evict_folios <- do_try_to_free_pages
 <- do_huge_pmd_anonymous_page <- __get_user_pages <- hva_to_pfn [kvm]
 <- kvm_tdp_page_fault [kvm] <- handle_ept_violation [kvm_intel]
```

From the `Code:` bytes at that RIP (`48 0f ba 2f 16` bts on b_state,
`48 8b 17` mov (%rdi),%rdx, `f7 c2 00 00 01 00` test $0x10000, `48 8b 47 40`
mov 0x40(%rdi)) **RDX is `bh->b_state`**. Little-endian it decodes to ASCII
**`"stq9-mxf"`** — an iSCSI TransportID fragment, same family as wedge B's
corrupted PTEs `"st16-mxf"` / `"s-node,i"`.

Then everything follows exactly:
- b_state has bit 16 (`BH_JBD`) set by accident of the ASCII, so
  `buffer_jbd(bh)` returns true;
- `b_private` at +0x40 is NULL;
- `jh->b_jcount++` writes `NULL + 0x0c` — **the exact faulting address**.

## What this means

**One defect, two victims.** The same PR overflow ran on both days; on 08-20 it
landed on a `struct buffer_head` (so jbd2 "deadlocked with the device idle"
because its buffer state was corrupt, not because of a lock cycle), on 08-21 on
a QEMU page-table page. `+caw-abort-reclaim.4` addresses both.

## The trace flood is still a real, separate harm — three ways

1. It drove the memory/journal pressure that put reclaim onto the corrupted
   buffer_head in the first place.
2. It stopped journald persisting anything once the fs wedged — which is why
   nine oopses left no journal trace and the first analysis was wrong.
3. It filled the ERST crash buffer with **716 KB** of `scst_check_scsi_atomicity`
   lines, pushing the oops context out. **Debug tracing left on destroyed the
   evidence for the bug it was left on to find.**

## Method note worth keeping

When a host wedges, `journalctl -b -N -k` is NOT the whole record and its
silence is not evidence of calm — a wedged root filesystem means journald
stopped. Always read `/var/lib/systemd/pstore/*` (systemd-pstore drains
`/sys/fs/pstore` at boot and clears it) and check the ERST header line for the
`Oops#N` count. clyde's backend is `erst`, not efi.
