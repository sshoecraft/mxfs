---
name: trap-a-harness-that-reads-a-kernel-line-through-journalctl-can-miss-it-and-a-rider-that-frees-an-inode-between-stages-confounds-the-next-stages-instrument
description: TRAP (s62, D-A-HARNESS laps): journalctl -k drops kmsg behind the module's print rate (use dmesg); a per-stage unlink lets the next create reuse the…
metadata:
  type: feedback
tags: [harness, instrument, journalctl, fault-around, d512]
---

# Three instrument traps that FAILed healthy laps on a healthy kernel (s62a → s62d)

1. **`journalctl -k` is not the kernel ring.** journald reads /dev/kmsg asynchronously and
   drops entries when the module prints faster than it drains; on s58h and s62a the `DLM init:
   node_id=` line was ABSENT from `journalctl -k` while `dmesg` held it (6 occurrences). A
   harness reading a kernel line reads `dmesg` (tests/rejoin_residue.sh now does). A
   state attribute would be better still, but the node id has none.

2. **A rider that frees an inode inside a stage hands the next stage a reused number with a
   PENDING bast.** tests/d512_t2_pause.sh's T6 rider unlinked stage N's file; stage N+1's
   create reused that inode number, the peer's pending request re-fired a release at the
   create — under the freshly armed pause — and H held nothing when W read: "leaked 450 ms"
   with both pause markers present (the re-fired release's). The stage-5/stage-3 FAIL had
   existed since 2026-08-24 and was read as the kernel. Fix: no free between stages (the
   rider runs after the whole ladder); every stage then held ~3.5 s of a 3 s pause.

3. **A read fault on a folio already in the page cache is served by `->map_pages`
   (fault-around) and never enters `xfs_filemap_fault`.** d512_race_verify's setup `dd`
   left the page cached on the same node, so the site=fault window could not fire (0) and
   the racer read 0x44 straight from the cache. `echo 3 > drop_caches` before the mmap
   racer makes the fault take the gated path (window 1, poisons 3).

General: a healthy lap that FAILs on an instrument measurement is adjudicated by reading the
kernel log around the instrument (who fired it, on which release) before it is a kernel
finding. The one real finding in the same batch (d512_t1: a held fd read the successor
file's bytes) was proven by adding the missing measurement — the bytes' digest — not by
trusting `rc=0`.
