---
name: clyde-taint-512-is-a-boot-time-dma-direct-map-page-warn-not-campaign-induced
description: clyde carries TAINT_WARN (taint 12800) from a single dma_direct_map_page WARNING 4s after boot; it is a driver boot warning, not an MXFS or campaign…
metadata:
  type: reference
tags: [clyde, host, taint, sess567, false-alarm]
---

# clyde's TAINT_WARN is a boot-time DMA warning — do not chase it

## The observation

`/proc/sys/kernel/tainted` on clyde reads **12800**, which decodes as:

- 4096 — `TAINT_OOT_MODULE` (out-of-tree: mxfs)
- 8192 — `TAINT_UNSIGNED_MODULE`
- **512 — `TAINT_WARN`**

The nodes read 12288 (the first two only), so the 512 is host-specific and looks
alarming next to a campaign that treats host faults as first-class defects.

## What it actually is

`dmesg` showed **zero** `WARNING:` lines — the ring had wrapped on a boot that
was already three days old, which is exactly the trap that makes taint bits the
load-bearing datum rather than log lines. journald still had it:

    Sep 06 13:37:55 clyde kernel: WARNING: CPU: 4 PID: 384 at
        kernel/dma/direct.h:105 dma_direct_map_page+0x22c/0x240

Boot was `2026-09-06 13:37:51`. **The warning fired four seconds after boot** —
a driver's DMA mapping complaint during device probe, before any MXFS work
existed on the machine.

Same boot: 0 `BUG:`, 0 `Oops`, 0 bad-page. Newest `/var/lib/systemd/pstore/`
record predates the boot, so nothing crashed.

## Why this is not a defect and not a preflight failure

`scripts/clyde_preflight.sh` gates on BAD_PAGE / oops / soft-lockup / MCE taint,
**not** on `TAINT_WARN` — correctly, since a boot-probe warning says nothing
about rig health. It reported `PASS (0 warning)` throughout.

## The method worth reusing

When a taint bit is set but the log looks clean:

1. `dmesg` alone is not the record — the ring wraps, and `WARN_ON_ONCE` fires
   at most once per boot.
2. `journalctl -b -k` persists it; grep there and **check the timestamp against
   `uptime -s`**. A warning seconds after boot is a probe-time driver issue, not
   your workload.
3. Cross-check `/var/lib/systemd/pstore/` mtimes against the boot time — a
   record older than the boot is not this boot's crash.
