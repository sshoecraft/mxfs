---
name: trap-a-locality-probe-scoped-to-low-inode-numbers-goes-blind-on-an-aged-filesystem
description: TRAP (sess585): P7S-BAST-FIRE prints only for ino<=256; on an aged fs (inos 3713+) live_holder_wait.sh read every candidate as 'undetermined' and abo…
metadata:
  type: feedback
tags: [trap, harness, probe, live_holder_wait]
---

# A probe scoped to low inode numbers makes an aged filesystem unmeasurable

sess585, 2026-09-12. `tests/live_holder_wait.sh` establishes which node masters a
candidate inode from which node LOGS `P7S-BAST-FIRE` for it. That probe
(`dlm/dlm.c` fire_bast_records) prints only when `resource->ino <= 256` — it was
written for the hot directories of a fresh filesystem. After a module swap on the
existing (aged) fs the eight candidates were inodes 3713..3720, neither node
printed anything, all eight read `master=undetermined`, and the lap aborted
"none of the eight candidates is remote-mastered" — a false conclusion about the
hash, produced by a silent instrument.

The same silence would have made the lap's own after-the-fact locality check
(`otherfire == 0`) pass vacuously for any inode above 256.

Rule: before scoring anything on a probe line, check the probe's print
CONDITION (inode scope, budget, ratelimit), not just its existence. A probe that
selects by inode number is fresh-fs-only unless it also honours an explicit
target knob. Fix landed 0.84.0: `dbg_probe_ino` (0644) makes P7S-BAST-FIRE and
P7B-BASTNOTIFY print for the named inode whatever its number; the harness arms
it per candidate and for the chosen target.
