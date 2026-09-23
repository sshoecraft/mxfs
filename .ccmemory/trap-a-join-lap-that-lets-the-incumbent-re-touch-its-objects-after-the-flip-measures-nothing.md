---
name: trap-a-join-lap-that-lets-the-incumbent-re-touch-its-objects-after-the-flip-measures-nothing
description: TRAP (sess584, D-0959): three first-join laps read clean because the incumbent's loop touched every object again after the membership flip; its own r…
metadata:
  type: feedback
tags: [D-0959, harness, join, membership, measurement]
---

# A join harness must leave objects untouched after the flip, or it measures the re-acquire

**What happened (sess584, D-0959, 2 nodes/TCP).** Laps s583o/p/q and s584a/b had the incumbent add to three objects until it saw `active_count=2`, then B modified them. Every lap read clean. The join check was a full `dmesg | sed | grep` per iteration on a 16 MB ring (over a second each), so the loop stopped up to a second after the membership line, and the first post-flip add blocked ~0.7 s on the settle window before completing — under a REAL grant. That re-acquire is exactly what lands a dirty never-multi image: a shortform directory gets the reload's 3-way merge (`P56-RELOAD-MERGE`), a block directory gets its whole in-core block relogged. The hazard needs objects the incumbent does not touch again.

**The lap that reproduced (s584c).** Adds spread round-robin over 96 objects (32 block dirs, 32 shortform dirs, 32 files), join detected from a persistent `cat /dev/kmsg` reader (note the file offset after a kmsg mark, then `tail -c +OFF | grep` after every add: ~20 ms latency). Result: the incumbent's join-time flush could not converge against its own workload, force-shut down, and lost every unsynced byte; 34 objects lost the incumbent's entries.

**Lessons.**
- On a never-multi mount xfsaild lands a hot dir block every ~12 ms, so only the last tens of ms of metadata changes are dirty at any instant; file data stays dirty in the page cache until sync. A "dirty at the flip" shape needs continuous modification up to the flip AND no re-touch after it.
- `dmesg` on these nodes costs >1 s (16 MB ring); a per-iteration join check must not call it. A background `cat /dev/kmsg > file` and a byte offset is the cheap detector.
- A verdict that counts names by prefix must not collide with fixture names (`^b` matched `blockdir_entry_*`; `^A-` matched the `A-init` seed line): use `^b[0-9]`, `^A-[0-9]`.
- An `Edit` that drops the trailing space between a grep pattern and its path makes grep read stdin and return 0 silently — `f_A=0` on every sweep while the data was intact. Check the count expression on the node before trusting a zero.
