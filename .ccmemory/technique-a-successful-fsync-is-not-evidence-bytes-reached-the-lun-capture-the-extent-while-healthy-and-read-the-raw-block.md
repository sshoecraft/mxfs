---
name: technique-a-successful-fsync-is-not-evidence-bytes-reached-the-lun-capture-the-extent-while-healthy-and-read-the-raw-block
description: TECHNIQUE (s87): rc=0 from fsync proved nothing about the platter; capturing FIEMAP while the FS is still healthy, then dd iflag=direct on that offse…
metadata:
  type: feedback
tags: [measurement-integrity, harness, evidence]
---

# A successful fsync is not evidence that anything reached the LUN

Measuring whether a fenced node's write LANDED, on a rig with no target
instrumentation and where the mount under test is the thing you suspect.

## The trap

The first result was `PROBE_DATA rc=0 err=- ms=1` — a buffered write plus fsync
returning success in a millisecond from a node that had been PREEMPT AND
ABORTed. That is suggestive and it is not a defect: a failed fsync does not
prove nothing reached media, and a successful one does not prove anything did.
Reading the file back through the same mount is worse than useless — it returns
that node's own page cache.

## What settles it

1. **While the filesystem is still healthy**, write the probe file, fill it to a
   whole block, `fsync`, `sync -f`, and capture its PHYSICAL device offset with
   `FS_IOC_FIEMAP` (ioctl `0xC020660B`; the extent's `physical` field). This has
   to happen before anything is injected — afterwards the mount is either shut
   down or the thing under suspicion, and it will not answer.
2. **Take a baseline image of that block** straight off the device:
   `dd if=$DEV bs=4096 skip=$((PHYS/4096)) count=1 iflag=direct | od -c`.
3. Run the experiment.
4. **Read the same block again the same way.** No filesystem in the path, no
   page cache, no mount. The bytes are there or they are not.

On the 2-node TCP rig this turned `rc=0 in 1 ms` into
`0000000  f e n c e d - d i r e c t - w r`, and after the fix into
`0000000  b a s e l i n e`. That one line is the whole difference between a
suspicion and a disposition.

## Two companions worth copying

- **A control arm.** Every assertion in a containment harness is that a write
  FAILS, and a harness that has quietly broken its own probe satisfies all of
  them. Run the identical probe on a healthy node first and require it to
  SUCCEED.
- **Order the decisive read before the slow arm.** The metadata probe can sit
  out a whole DLM retry budget; running it in the same acquisition as the write
  arms let its timeout abort the lap *before* the platter read the lap existed
  to take. Read the block first, then run the slow arm, and treat its timeout as
  a recorded outcome rather than an abort.
