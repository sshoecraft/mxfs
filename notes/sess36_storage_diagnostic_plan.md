# Sess36 storage stack diagnostic plan

**Authored**: sess35 close (2026-05-08).
**Goal**: empirically determine whether the bug surface (writes
acknowledged but not actually persisted at the expected LBA) is in
the SSD firmware, the LIO target stack, or the tcm_loop transport.

This plan does NOT involve mxfs source changes. It's pure
host/storage-stack diagnostics. Run before any v6 work.

## Hypothesis space

H30 — **Samsung SSD 870 EVO firmware drops cross-initiator writes**.
Two SCSI initiators on the same loopback target writing to the same
LBA simultaneously may not be handled correctly by the SSD's
firmware (consumer-grade, no PLP, may treat each as session-private
in a way that violates SCSI semantics).

H31 — **LIO `iblock` backstore drops/reorders writes** under
cross-initiator load. The iblock_execute_rw + bio submission path
might have a race that reorders or drops writes.

H32 — **tcm_loop transport** has a bug where writes from one
initiator session aren't reflected in another initiator session's
read view, despite both sessions hitting the same backstore.

H33 — **Linux kernel SCSI host** (host-side, the tcm_loop SCSI host)
has a per-initiator queue that may serve writes out of order across
initiators.

## Falsifying experiments

### E1 — minimal cross-initiator test (no mxfs)

Bypass mxfs entirely. From two VMs, both attached to the same
LIO-exported LUN (/dev/sda inside each VM), do:

- VM1: write known pattern A to LBA X
- VM1: blkdev_issue_flush
- VM2: read LBA X (with O_DIRECT)

If VM2 reads zeros (or stale), the bug is below mxfs.

If VM2 reads pattern A correctly, the bug is something specific to
mxfs's I/O patterns (timing, CAW, FUA).

Implementation: a 50-line shell script using `dd` from each VM:

```bash
# VM1
sudo dd if=/dev/zero of=/tmp/test_pattern bs=4096 count=1
echo -n "TESTPATTERN-AAAA" > /tmp/test_pattern
sudo dd if=/tmp/test_pattern of=/dev/sda bs=4096 count=1 seek=1500000000 oflag=direct,sync

# VM2
sudo dd if=/dev/sda bs=4096 count=1 skip=1500000000 iflag=direct | head -c 16
```

LBA 1500000000 sectors ≈ 768 GB into the disk — well past anywhere
mxfs uses for the test FS, but within the SSD's 2 TB capacity. Pick
an LBA known to be unused.

**WARNING:** writing to /dev/sda directly while mxfs is mounted
risks corrupting any blocks mxfs has there. Pick an LBA carefully,
or unmount mxfs first.

### E2 — single-initiator durability test

VM1 writes pattern, flushes, immediately reads back from VM1 itself.
If write + read from the SAME initiator works (returns the pattern),
the SSD itself is honoring its writes — the cliff is cross-initiator.

If even single-initiator write+read fails, the SSD is the cliff.

### E3 — alternate backstore: fileio instead of iblock

Change LIO config: replace iblock backstore with fileio (`fbo_*`).
fileio uses host's filesystem layer — writes go through `pwrite()`
+ `fsync()` on the underlying file. This has different durability
semantics than iblock's submit_bio.

If E1 passes with fileio backstore but fails with iblock, the bug
is iblock-specific.

User authorization required (LIO config affects shared host).

### E4 — iSCSI loopback instead of tcm_loop

Run an iSCSI target on the host (using LIO's iSCSI front-end with
the same iblock backstore), and have VMs connect via iSCSI initiator
instead of virtio-scsi+tcm_loop. Compare bug rate.

If iSCSI works but tcm_loop fails, the bug is tcm_loop-specific.

User authorization required.

### E5 — alternate physical storage

Replace the Samsung 870 EVO backstore with:
- A ramdisk (`brd` module) — definitively eliminates SSD firmware as cause
- An NVMe with PLP — eliminates consumer-SSD-firmware lazy-flush
- A different SATA SSD model

If bug doesn't reproduce on ramdisk, hardware is the cause.
Ramdisk is the cleanest test (no real durability, but demonstrates
the kernel/LIO stack is correct).

## Recommended order

1. E2 (single-initiator) — quickest, can run from one VM, no
   changes to shared state.
2. E1 (cross-initiator no mxfs) — slightly more involved but still
   minimal infra change.
3. E5 with ramdisk — requires LIO config change but is the cleanest
   isolation.
4. E3 (fileio backstore) — second LIO config change.
5. E4 (iSCSI) — most invasive test.

If E2 passes, E1 fails → the bug is cross-initiator coherency.
If E2 fails → SSD firmware can't be trusted; replace hardware.
If E5 (ramdisk) passes consistently → confirms hardware is the issue.

## What this DOESN'T diagnose

- Does NOT identify the actual fix. The diagnosis tells us
  whether/where the cliff lives; the fix likely involves changing
  LIO config or hardware.
- Does NOT validate that v6a will close the bug. v6a addresses
  cluster-coherency architecture; this test addresses storage-stack
  durability. Different layers.
- Does NOT close the underlying issue. Even if we find the cliff,
  the user may need to accept a hardware/firmware constraint or
  switch to a known-good storage stack.

## Estimated session cost

E1 + E2 + E5 (ramdisk): 0.5-1 session.
E3 + E4: 0.5-1 session each.

Total: 1-3 sessions to fully diagnose, BEFORE any mxfs source work.
