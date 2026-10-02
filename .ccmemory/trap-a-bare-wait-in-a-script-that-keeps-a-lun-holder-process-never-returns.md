---
name: trap-a-bare-wait-in-a-script-that-keeps-a-lun-holder-process-never-returns
description: TRAP (0.90.40 drbd_rig.sh): bare `wait` also waits for background LUN-holder processes that live until the script exits; it hung to its budget. Wait…
metadata:
  type: feedback
tags: [harness, bash, lun-pool, drbd]
---

A harness that owns pool LUNs through holder processes (`tail --pid=$$ -f /dev/null &`, one per allocation, because tools/lun_pool.sh lets one owner hold one allocation) must never use a bare `wait`: it waits for EVERY background child, the holders included, and they only end when the script does. scripts/drbd_rig.sh `up` finished its first fio leg in 20 s (FIO_OK in the evidence) and then sat in `wait` until its 620 s budget killed it.

- Collect `$!` per launched job and `wait "${pids[@]}"`.
- Kill the holders in an EXIT trap: `tail --pid` notices its pid gone only on its next ~1 s poll, and an invocation started right after found its node still held by a live allocation ("test1 is held by lun03's allocation").
- Spawn holders with the script's lock fds closed, or they keep the node/config flocks and run.sh is refused its own.

Related, same session: editing a bash script while it runs shifts the byte offset bash resumes from; computed that the running `up` would re-read the new `case` block and re-run `up` after finishing. Never edit a harness while an invocation of it is live.
