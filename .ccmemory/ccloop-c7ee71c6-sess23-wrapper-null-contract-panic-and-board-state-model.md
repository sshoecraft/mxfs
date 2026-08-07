---
name: ccloop-c7ee71c6-sess23-wrapper-null-contract-panic-and-board-state-model
description: sess23: my igrab/iput macro wrapper broke iput(NULL) -> panic in pr_sweep -> whole-rig cascade; P202 leak detector roots D-UNMOUNT-BUSY-INODES; board…
metadata:
  type: project
tags: [ccloop-c7ee71c6, sess23, panic, leak, P202, harness, kernel_health, rig_recover]
---

# sess23 (ccloop c7ee71c6)

## THE EXPENSIVE LESSON — a wrapper MUST honour the wrapped function's contract

I added `#define igrab(vi) mxfs_igrab_tracked(...)` / `#define iput(vi)
mxfs_iput_tracked(...)` to tagged .c files to attribute reference leaks.
`mxfs_iput_tracked` dereferenced `vi` **before** calling `iput()`.

**`iput(NULL)` IS LEGAL** — upstream returns early on NULL, and MXFS relies on
it: `mxfs_dlm_pr_sweep_work_fn`'s bail-out paths call `iput(toput)` where
`toput` may never have been set.  `XFS_I(NULL)` is `-offsetof(i_vnode)`, so the
ring write landed at a tiny address:

    BUG: kernel NULL pointer dereference, address: 000000000000033c
    Workqueue: mxfs-ino-bast/dm-1 mxfs_dlm_pr_sweep_work_fn [mxfs]
    Kernel panic - not syncing: Fatal exception

**How it presented — this is the part that cost hours.**  It did NOT look like
a bad build.  Every node panicked at mount and rebooted; `/src` is deliberately
NOT an fstab automount, so they came back without it; prep then reported
"did not release mxfs / lost /src" and power-cycled them; the cycled nodes came
back without `/src` again.  Self-sustaining.  It read as a flapping TEST RIG.
Diagnosis came only from `sudo tail /var/log/libvirt/qemu/testN-serial.log`.

**Rules taken from this:**
- When wrapping ANY kernel function, replicate its NULL/edge contract exactly.
- When the rig starts flapping right after a new build, check a node's SERIAL
  CONSOLE for a panic BEFORE touching the rig. dmesg is gone after the reboot.
- NEVER launch a foreground run while another run is in flight — my first
  collision (foreground prep vs a backgrounded prep) started the whole cascade.
- Do not kill prep mid-power-cycle. Each truncated prep leaves the rig worse.
  Bounded prep phases: teardown 150s, power_cycle 180s ssh + 90s dev, then
  mkfs ~40s, node1 form, parallel joins ~3min. Budget >=560s when nodes cycle.
- `pkill -f "run.sh ..."` MATCHES YOUR OWN bash -c command line and kills your
  shell (exit 143/144). Use a character class: `pkill -f "prep_nod[e].sh"`.

## NEW: scripts/rig_recover.sh

Breaks the prep power-cycle loop. Phases: ssh reachability (cycle + wait) ->
`/src` restore with `timeout 40` (prep's own is `timeout 12`, too short under
load — measured: 8 nodes failed prep's restore and all 16 succeeded at 25s) ->
umount + rmmod with generous retry -> per-node READY report.
Run it BEFORE `MXFS_FORCE_PREP=1 ./run.sh N caw prep_cluster` whenever prep has
started power-cycling. After it reports READY, prep completed in 42s.

## D-UNMOUNT-BUSY-INODES — ROOTED to a call site, not yet to a caller

New **P202** detector (v0.11.186+): every xfs_inode joins a global list in
`xfs_inode_alloc` and leaves it in `xfs_inode_free_callback` (the RCU callback,
last instant before `kmem_cache_free`), so the list mirrors the slab exactly.
`xfs_destroy_caches()` dumps survivors AFTER `rcu_barrier()` — precisely where
the kernel reports "Slab cache still has objects".  Knob `mxfs.live_inode_track`.
P202 ALWAYS prints, including `leaked=0 tracked_allocs=N`, so a zero is a
measurement and not silence.

**Reproducer (leaks on 1-2 of 16 nodes, reliable):** prep ->
`tests/inode_reuse_typeflip.sh 15 16 2 8` -> `cache_coherency` ->
`sf_mkdir_storm 12 16 2 1` -> `tests/unmount_leak_check.sh 16`.

**5 captures, identical signature:**

    ino=44040328 icount=1 i_state=0x100(I_REFERENCED only) mode=040755 nlink=18
    iflags=0x0 pincount=0 itemp=1 in_ail=0
    dlm_mode=3(PR) dlm_state=1(CACHED) ex_h=0 pr_h=0 pin=0 bast_pending=0
    dwork_pending=0 dwork_timer=0 bwork_pending=0 unpub_linked=0 demoter=0
    dentries=0 lru_linked=1 sblist_linked=1 hashed=1 wcount=0
    GRAB=xfs_icache.c (xfs_iget_cache_hit's igrab)  iget_caller=xfs_lookup+0x16c

ALWAYS a DIRECTORY, always PR+CACHED, always exactly one.

**Refuted with measurement (do not re-walk):**
1. The known "ref intentionally leaked" path (`P142-DWORK-LASTREF`,
   `atomic_add_unless(&i_count,-1,1)`) — fired **0 times on all 16 nodes**.
2. Any pending mxfs work/dwork/timer — all zero in every capture.
3. A dentry holding it — `hlist_empty(&i_dentry)`.
4. `lru_linked=1` is NOT the anomaly: `xfs_fs_drop_inode` -> `inode_generic_drop`
   returns 0 for a live hashed nlink>0 inode, so XFS inodes DO go on the VFS LRU.

**Note:** `i_mxfs_iget_ret` is the LAST iget caller, not necessarily the leaked
one — nearly every inode's last iget is a lookup, so it is weak attribution.
The reference-event ring (`i_mxfs_refev_*`, replayed by P202) was built for
exactly this and is IN THE TREE but has not yet produced a capture.

## HARNESS — the board was lying in three different ways

1. **Unrun work scored as FAIL.** `finalize_pending` converted every still-
   PENDING marker to `FAIL measured:"aborted"`. A truncated sweep was
   indistinguishable from a broken filesystem. Now `mark_executing` stamps the
   in-flight test, and the lifecycle maps `executing <id>` -> **ABORTED**,
   `running <id>` -> **NOT_RUN**. Neither is green, so nothing can go green by
   not running. 3 fabricated cells migrated in criteria.json.
2. **A destructive criterion poisoned everything after it.** `crash_consistency`
   `virsh destroy`s a node and returned before reconvergence:
   `FAIL nodes_pass=9/16 checks=354 passed=354 failed=0` (every check PASSED),
   and `kernel_health` inherited it (`FAIL 15/16 hits=0 kinds=[]`).
   Added `DESTRUCTIVE_TESTS` + `wait_converged()`: the destructive test owns its
   recovery postcondition, and later criteria are **BLOCKED**, not FAILed, if
   the cluster does not reconverge. **crash_consistency now PASSES 16/16.**
   - The gate's FIRST version was itself wrong: it required an
     `MXFS-MEMBERSHIP active_count` dmesg beacon, and **dmesg is a ring** — on a
     long-up node the beacon scrolls out, so a healthy 16/16-mounted writable
     cluster read as RECONVERGENCE FAILED. Now LIVENESS-FIRST: mounted + `ls`
     answers + (beacon agrees IF still present). A beacon that DISAGREES is
     still a hard fail; an absent beacon is no evidence.
3. **`kernel_health` failed on a clean boot.** Its pattern includes bare
   `WARNING:`, which matches the firmware line every node logs at 0.13s uptime:
   `ITS: WARNING: ITS mitigation depends on retpoline and rethunk support`.
   Hidden only because long-up nodes had scrolled it out; the moment the panic
   cascade rebooted them it went red 15/16 with `hits=1 kinds=[WARNING:]` and no
   MXFS fault. Now scoped to lines after the mxfs module load, with boot/CPU
   mitigation prefixes excluded by source prefix (ITS|Spectre|MDS|x86/|...).

`showstat.sh` now has typed states (PASS/FAIL/POLICY/ABORTED/BLOCKED/NOT_RUN)
and a VERDICT line. `open_defects` renders as **POLICY** (📋), separate from a
detected fault — it is red by design under RULE 6 and must never be silenceable.

## BOARD @16/caw on 0.11.193 (1E80BA2BA779A20CE5ACE17) — fully re-measured

**28 tests: 26 PASS, 1 FAIL, 1 POLICY, 0 aborted/blocked/not-run.**
The single detected fault is `dirent_publish_integrity` 12/16 — GENUINE:
`stale_base_mutations=1..4` and `unlanded_at_unlock=1` on test4/12/14/15, i.e.
the P195/P188 deterministic precursor of D-SILENT-MKDIR-LOSS. It must stay red
until the freshness gate at EX acquire exists.

## NEW REPRODUCER: tests/inode_reuse_typeflip.sh

Half the nodes churn dirs (mkdir+rmdir) while the other half create regular
files in the SAME parent, so writers allocate precisely the just-freed DIR
inodes. Drives the type-flip machinery hard: **196 P95B-TYPEFLIP-WAIT, 137
RELOAD-TYPEFLIP-STALE-SKIP, 601 P-EVICT-RESULT in ~40s**, with 0 unresolved.
One run produced `typebad=360` (durable type mismatches) — NOT yet re-captured;
chase that.

Also: `cache_coherency`'s `rename_visibility` only ever creates REGULAR FILES
(`echo > nodeN_before_i` then `mv`), so `dirent_ftype=1 (REG)` is CORRECT. The
corrupt side is the INODE, i.e. free+reuse-as-directory under a surviving
dirent. sess22's "the dirent is the corrupt side" reading is wrong.
