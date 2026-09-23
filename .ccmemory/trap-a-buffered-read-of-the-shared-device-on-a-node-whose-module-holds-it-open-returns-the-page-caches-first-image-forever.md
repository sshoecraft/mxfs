---
name: trap-a-buffered-read-of-the-shared-device-on-a-node-whose-module-holds-it-open-returns-the-page-caches-first-image-forever
description: TRAP (s67e, 0.89.4): python open()/dd without iflag=direct on /dev/sda from a MOUNTED node returns the image cached at the first read; the module's b…
metadata:
  type: feedback
tags: [rig, harness, page-cache, O_DIRECT, disklock, instrument]
---

# A buffered read of the shared device from a mounted node is a cached image, not the platter

## Measured (test2, mounted, s67e)
- `tools/disklock_hb_dump.py` (then `open(dev, "rb", buffering=0)` — Python-level unbuffered, kernel page cache still in the path) printed slot 2 `ts_ms=167600` on three dumps 3 s apart.
- `dd if=/dev/sda bs=512 skip=131090 count=1 iflag=direct | od` on the same sector at the same moments: 332143 → 336239 → 338287 (the live 2 s heartbeat).
- The cached image also lacked the RECOVERY_GUARD (slot 1) and EMPTY (slot 0) records the direct read showed.
- Mechanism: the mxfs module's heartbeat/ledger writes are bios that never touch the block device inode's page cache; a buffered read populates that cache once and is served from it for as long as ANY opener (the module) keeps the device open. An UNMOUNTED node's last close flushes the bdev cache, so the same buffered read looks live there — which is why the tool "worked" in every unmounted-node dump and in the s67a/s67c prep guard.

## Consequences
- Every harness that dumped the heartbeat table from a mounted node before 0.89.4 (`hb_before`/`hb_after` in d0980, d0981, sole_survivor, d0932 families; d0356's `hb_after_B`) may have judged a stale image. Their next laps on 0.89.4 tools are the re-measurement (d0981 s67i, sole_survivor s67j, d0356 s67h/s67k all PASSed on the direct-I/O tool).
- The prep guard harness `prep_heartbeat_writer_guard` was VACUOUS (records "not advancing") until the tool was fixed.

## Rule
- Read a shared block device from userspace with O_DIRECT (Python: `os.open(..., O_RDONLY|O_DIRECT)` + `mmap.mmap(-1, n)` + `os.preadv`; shell: `dd ... iflag=direct` on whole sectors, then `od -j` for the byte offset). `buffering=0` is not it. `bs=1` cannot be direct.
- A value fixed at mkfs (envelope offsets) may be read buffered, and the script must say so.
- Converted at 0.89.4: disklock_hb_dump.py, tauth_page_auth.py, mxfs_sb_bytecmp.sh, closure_reuse_directed.sh, closure_footprint_shapes.sh. Open: chk_mxfs main fd, mkfs/resize non-O_DIRECT fallback (D-A-TEST-HARNESS record).
