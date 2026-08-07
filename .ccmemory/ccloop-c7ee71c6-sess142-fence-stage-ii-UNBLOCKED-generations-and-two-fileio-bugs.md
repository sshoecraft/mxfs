---
name: ccloop-c7ee71c6-sess142-fence-stage-ii-UNBLOCKED-generations-and-two-fileio-bugs
description: sess142: stage-(ii) blocker cleared by design (generational images + admission gate, RULE-5 approved). Found 2 latent bugs that would have failed eve…
metadata:
  type: reference
tags: [fence_inflight, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, stack.sh, rule5, harness]
---

# sess142 — stage (ii) is unblocked by design; two latent fileio bugs found

## RULE-5 ruling (gpt-5.6-sol) on how to get past the poisoned inode

Asked whether to (A) use a fresh inode per generation and keep the ruled
`file -> loop(--direct-io=on) -> dm-delay -> ext4 -> disk.img -> vdisk_fileio`
stack, or (B) replace `file -> loop` with a `brd` RAM device to delete the
whole failure class.

**RULING: Plan A is the closure-grade implementation. Plan B is SUPPLEMENTAL
ONLY and must never be promoted to closure evidence.**

Reason, and it is a substantive one rather than a formality: the ruled stack
has TWO asynchronous layers — SCST fileio AIO into ext4 *above* dm-delay, and
loop/backing-file direct I/O *below* it. brd retains the first and deletes the
second. brd generally completes a bio synchronously in the submitter's context,
so it can COLLAPSE a race window that loop's submission-vs-completion interval
keeps open — exactly where SCST's abort/reclaim could wrongly consider a
command quiesced. A Plan-B pass after a Plan-A wedge shows only that the upper
half works; it does not clear stage (ii).

Also ruled:
- create the new image with O_CREAT|O_EXCL; never recycle a name.
- if the admission probe times out, quarantine that whole generation and STOP.
  Do not accumulate parked probes; do not detach a device that may still own
  stranded work.
- `purge` must exclude the quarantined generation and must never use broad
  operations (`losetup -D`, `dmsetup remove_all`, pathname globs).
- brd's observation point is sound in itself (an aligned O_DIRECT read of
  /dev/ram0 reads brd's own pages; there is no hidden VFS alias) — the
  objection to Plan B is completion semantics, not the observer.
- LEDGER REQUIREMENT: stage (ii) will run on a post-GPF, known-tainted kernel
  with the poisoned stack quarantined. Record that as a stated test-environment
  exception. Neither plan can technically erase it, and RULE 2 forbids
  rebooting clyde.

## Empirical isolation checks the ruling demanded — ALL PASS

`tests/fence_inflight/blocklayer_selftest.sh` (new) proves the quarantined
loop0 does not constrain the rest of the block layer:

    loop_attach/dio/write/read/flush   OK (4-5 ms each)
    dm create/suspend/reload/resume/remove  OK
    dm_delay_effective                 OK 110ms through a 50ms write delay
    mkfs.ext4 / mount / file_init / sync / umount   OK
    RESULT: HEALTHY

`loop_flush_probe.sh` also returns FLUSH_OK 4ms on all seven free loop devices,
so the loop workqueue still supplies replacement workers — the poisoning is
per-inode, not per-workqueue.

## stack.sh is now GENERATIONAL

- gen 0 = the original unnumbered names (`fio-backing.img`, `mxfsfencef`,
  `fiomnt`) and is PERMANENTLY QUARANTINED. `down` and `purge` both refuse to
  touch it; its loop worker still sleeps in wait_var_event(&i_dio_count).
- gen N>=1 owns `fio-backing.gN.img`, `mxfsfencefN`, `fiomnt.gN`.
- new subcommands: `newgen` (fresh inode; refused while a stack is up),
  `purge` (only torn-down, non-quarantined generations, named in full),
  `quarantine` (show the off-limits list).
- `up` now has TWO ADMISSION GATES:
  1. reads `i_dio_count` on the image via `scripts/inode_dio_probe` BEFORE
     attaching anything — a measurement that cannot itself hang;
  2. after attach, a 4 KiB write+flush that must complete inside 5 s (measured
     healthy: 4-5 ms). Non-destructive: the last 1 MiB of every image is now a
     scratch area deliberately left OUTSIDE the dm-delay mapping
     (`RESERVE_SECTORS=2048`, `sectors()` returns the mapped span), so the gate
     can run on every up including a re-up of a built generation.
  Either gate failing quarantines the generation and refuses to detach.

## TWO LATENT BUGS that would have failed every fileio arm

Neither was ever exercised: stage (i) is blockio, and stage (ii) had never run.

1. **`inflight_ab.sh` in-flight gate pointed at the STAGE-(i) TARGET.**
   `VSESS` hardcoded `iqn.2026-08.mxfs.fence:inflight`; the fileio target is
   `...:inflightf`. The read would return empty, `${WIN:-0}` stays 0, and every
   fileio arm would abort with "INVALID: write never observed in flight" no
   matter how the handler behaved. Now uses `$TARGET` from devmap.

2. **The observation offset was the LUN offset, not the physical one.**
   `OFF=$((LBA*512))` was used directly against `$LOOP`. That is the identity
   mapping and is correct ONLY for blockio. In fileio the LUN is `disk.img`, so
   the below-delay offset is its FIEMAP physical offset. `inflight_ab.sh` now
   resolves `PHYS`/`PHYS_C` via `stack.sh fiemap` (uniform across both modes —
   blockio reports identity), asserts 4 KiB alignment, records the map BEFORE
   and AFTER every run and sets `EXTENT_STABLE=0` if it moved.
   `verdict.py` correlates block tracepoints on `PHYS_LBA512` (falling back to
   `LBA` for pre-sess142 blockio arm dirs, where they are equal by
   construction).

Also fixed: `devmap` used `readlink -f` on a possibly-absent dm name, which
returned a path anyway and installed a bogus `DM_DEVNO=0` into
inflight_ab.sh's block-tracepoint filter.

NOTE: `loop_flush_probe.sh`'s header still argues the REFUTED hypothesis
(poisoned `lo->rootcg_work`). sess141 disproved it — loop0 flushed fine on a
fresh backing file — and proved the leaked `i_dio_count` instead. That header
needs correcting.

## Next

`sudo MXFS_FENCE_MODE=fileio bash tests/fence_inflight/stack.sh up` (gen 1
builds fresh), validate the delay stack standalone, then run the ruled order
0x04 -> 0x05 -> 0x04 with ARM_SEQ=1,2,3 and score with verdict.py.
