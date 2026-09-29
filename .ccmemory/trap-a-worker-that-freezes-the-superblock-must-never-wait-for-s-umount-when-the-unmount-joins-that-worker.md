---
name: trap-a-worker-that-freezes-the-superblock-must-never-wait-for-s-umount-when-the-unmount-joins-that-worker
description: TRAP (0.90.14→16): freeze_super in the join worker blocked on s_umount held by umount, whose put_super joined the worker (ABBA). Trylock + own s_acti…
metadata:
  type: feedback
---

# A kernel worker that calls freeze_super deadlocks with an unmount that joins it

**Shape (seen 0.90.14, 4/tcp; hung task captured):** `freeze_super` takes
`s_umount`.  `umount` holds `s_umount` for the whole `deactivate_locked_super`
→ `generic_shutdown_super` → `put_super` teardown, and MXFS's put_super joins
the DLM join worker (`v5_join_worker_stop`).  If that worker is inside
`freeze_super`'s `down_write(&sb->s_umount)` at that moment, each waits for
the other.  The window is between the peer sighting and the freeze's lock —
milliseconds — so random-delay tests never hit it (20 laps, 0 hits); the
`dbg_join_prefreeze_delay_ms` knob widens it deterministically (5 hits in 20).

**What does not fix it:** checking SB_ACTIVE/SB_DYING before the freeze (the
race is the check→lock gap); `freeze_super` itself (≤6.6 it even takes its own
`s_active` ref and `thaw` drops it — so `thaw_super` can run the teardown ON
the worker if that ref is the last: self-join); a trylock followed by
`freeze_super` alone (the same gap).

**What fixes it (xfs/xfs_mxfs_join.c 0.90.16, the kernel's own bdev-freeze
pattern):** `down_write_trylock(&sb->s_umount)`; under it check SB_BORN,
SB_ACTIVE, `s_root`, `s_active > 0`, not shut down; `atomic_inc(&sb->s_active)`;
`up_write`; then `freeze_super`.  With the extra active reference no teardown
can start under the freeze (the unmount's `deactivate_super` just decrements
and returns).  Drop the reference LAST, from a per-request work item on a
module-owned workqueue (`deactivate_super` may run the whole teardown, which
joins the worker — never on the worker; never embed the work in the mount, it
can be re-queued after the drop freed it; never flush a system-wide workqueue
from a module — attribute warning).  Cost: an umount landing mid-transition
returns before the teardown, which follows shortly.

**Verification pattern:** `tests/join_during_unmount.sh` — hold knob, random
umount start inside the hold, count `P-JOIN-FREEZE-BUSY` hits (must be ≥1 or
the run is VACUOUS), check umount/mount walls against budgets, hung tasks = 0,
and the module use count with nothing mounted before == after (a leaked
`s_active` shows there and nowhere else).
