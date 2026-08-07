---
name: ccloop-c7ee71c6-sess136-stage-ii-fileio-stack-BUILT-and-WEDGES
description: sess136: stage-(ii) fileio harness BUILT (prprobe fiemap + stack.sh fileio mode). Production LUN is vdisk_fileio o_direct=1 async=1. The fileio test…
metadata:
  type: reference
tags: [mxfs, fence, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, scst, fileio, stage-ii]
---

## The ruled stage (ii) is genuinely OUTSTANDING — it is NOT what sess133-135 measured

`ls /sys/kernel/scst_tgt/handlers/*/` on clyde:
- `vdisk_blockio: fencedelay` — the sess133-135 harness LUN (stage (i), method validation)
- `vdisk_fileio: mxfs` — **the production 32-node LUN**

All three sess135 arms (0x04/0x05/0x04, all VALID) ran on **blockio**. The sess133 ruling
requires stage (ii) on the SHIPPED handler and says verbatim: *"Stage (ii) still runs on
fileio — code agreement is not a measurement."* The sess135 resume's "only (C3) remains"
was incomplete: **(ii) AND (C3) both remain.**

## Production LUN attributes, measured — mirror these exactly

`/sys/kernel/scst_tgt/devices/mxfs/`: `filename=/home/steve/disk.img`, `blocksize=512`,
`o_direct=1`, **`async=1`**, `nv_cache=0`, `write_through=0`, `cluster_mode=0`,
`size_mb=51200`. `/home/steve` is **ext4** on `/dev/nvme0n1p2`.

`async=1` is mandatory, not decoration: SCST rejects `add_device` without it —
`vdisk_attach:1188: using o_direct without setting async is not supported` (-22). It also
means the shipped path is **AIO**, which is exactly the case the ruling singled out:
"establish that blockio and fileio do not report completion while a detached bio/AIO
capable of modifying storage is still live."

**sysfs gotcha:** SCST appends a `[key]` marker LINE to persisted attributes, so
`cat .../o_direct` returns two lines. Always `| head -1` or every comparison fails.

## Code shipped this session (compiles, syntax-checked)

**`tests/fence_inflight/prprobe.c` — new `fiemap <file> <byteoff> <len>`.** Programmatic
`FS_IOC_FIEMAP` (the ruling forbids parsing filefrag text). fsyncs first, uses
`FIEMAP_FLAG_SYNC`, requires `fm_mapped_extents == 1`, requires the range wholly inside
that extent, and REFUSES `UNKNOWN|DELALLOC|ENCODED|DATA_ENCRYPTED|NOT_ALIGNED|
DATA_INLINE|DATA_TAIL|UNWRITTEN|SHARED`. Prints `phys=` and `phys_lba512=`.

**`tests/fence_inflight/stack.sh` — `MXFS_FENCE_MODE=blockio|fileio`.** blockio path is
byte-identical to before. fileio adds: `fio-backing.img` → loop0 (`--direct-io=on`,
verified) → `dm-delay mxfsfencef` → **ext4 (noatime)** at `/var/lib/mxfs-fence/fiomnt` →
preallocated AND zero-initialized `disk.img` → `vdisk_fileio fencedelayf` → target
`iqn.2026-08.mxfs.fence:inflightf`. All names mode-suffixed so the two modes cannot reuse
each other's leftovers. `up` asserts o_direct/async/blocksize actually took. New
`stack.sh fiemap <off> [len]` translates a LUN byte offset to the loop-device offset
(identity in blockio mode) — that is what `inflight_ab.sh` still needs wiring to.

## THE BLOCKER: the fileio test LUN never answers a command

Built clean; both nexuses logged in; then **every command hung**. dmesg:

    sd 12:0:0:0: [sda] tag#79 FAILED Result: hostbyte=DID_TRANSPORT_DISRUPTED cmd_age=146s
    sd 12:0:0:0: [sda] tag#79 CDB: Read(10) 28 00 00 00 00 48 00 00 30 00
    sd 12:0:0:0: Device offlined - not ready after error recovery

A plain `Read(10)` of sector 72 (the initial partition probe) aged **146 s**. iscsid then
re-logged in repeatedly, leaving **6 SCST session entries** (`victim`, `victim_1`,
`victim_2`, `survivor`, `survivor_1`, `survivor_2`) for 2 real initiator sessions.

Teardown then deadlocked. `iscsiadm --logout` never returns. Stacks:

    kworker/u113:15  blk_execute_rq <- scsi_execute_cmd <- sd_sync_cache <- sd_shutdown
                     <- sd_remove <- __scsi_remove_device <- scsi_remove_target
    iscsi_conn_cleanup (x4)  msleep <- close_conn+0x6bf [iscsi_scst]

i.e. the initiator's device-removal path is blocked on SYNCHRONIZE CACHE to a target that
is trying to close the connection, while `close_conn` msleeps for commands to drain.
Residual stuck commands: victim=3, survivor=1, victim_2=1.

**The backing stack is NOT the cause — measured, not assumed.** Aligned O_DIRECT reads
at every layer below the handler are ~11 ms:
`/dev/loop0` 0.012 s, `/dev/mapper/mxfsfencef` 0.010 s, `disk.img` via ext4 0.011 s.
dm-delay table is `0 4194304 delay 7:0 0 0 7:0 0 0` — both delays ZERO. So the hang is in
or above the SCST **vdisk_fileio** device, not in ext4/dm/loop.

Leading hypothesis for the next session (UNPROVEN — RULE 4 step 1, needs instrumentation):
the fileio AIO submission path stalls for this device. Candidate discriminators, cheapest
first: (a) create the same fileio device with `async=0,o_direct=0` and see if it answers —
isolates AIO from everything else; (b) point a fileio device at a file on the ROOT ext4
(no dm-delay under it) — isolates the dm/loop sandwich; (c) `add pr`-style SCST trace or
`trace_level` on vdisk to see whether the command reaches the handler at all;
(d) check whether `/var/lib/mxfs-fence/fiomnt` ext4 writeback is itself blocked behind the
loop device under memory pressure (local-loopback reclaim deadlock is a known shape).
Note (b) matters most: production's disk.img sits on plain ext4 on nvme with NO dm-delay,
and it works — so the delta is the dm-delay/loop sandwich, not fileio per se.

## Rig state left behind — PRODUCTION IS INTACT

- Production target `iqn.2026-05.local.mxfs:shared`: **64 sessions**, unchanged throughout.
- Production device `mxfs` → `/home/steve/disk.img`, untouched.
- Blockio harness stack (`fencedelay`, `mxfsfence`) was torn down before the fileio build.
- **Left wedged (test target only):** 6 stale SCST sessions on `inflightf`, 5 stuck
  commands, 5 D-state tasks (1 kworker + 4 `iscsi_conn_cleanup`). `/dev/sda` and
  `/dev/sdb` are gone. `force_close` on the sessions did NOT clear them. No MXFS
  filesystem or node is affected; per RULE 2 clyde must NOT be rebooted for this.
  Next session should re-check whether close_conn drained on its own before rebuilding.
