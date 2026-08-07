---
name: unmount-leak-elimination-list-sess26
description: D-UNMOUNT-BUSY-INODES: consolidated list of paths eliminated by measurement or source verification in sess26, so the next session need not re-walk an…
metadata:
  type: reference
tags: [unmount-busy-inodes, elimination, refcount-leak, rule4]
---

# D-UNMOUNT-BUSY-INODES — what is ELIMINATED (sess26)

Reproduced 3 times in 5 full reproducer cycles at 16/caw, one node per catch.
Everything below is ruled out; do not re-walk it.

## Eliminated by probe counts ON THE LEAKING NODE, in the leak window

    P142-BWORK-LASTREF        0     both intentional-leak paths
    P142-DWORK-LASTREF        0     <-- NOTE: TWO variants exist
    P60-BWFN-BADREF           0     bast_work_fn's trailing-irele refusal
    P124-DWFN-BADREF          0     dwork's equivalent
    P134-ILEND-FREEING        0     ilock-end igrab refusal
    P204-CANCEL-ARMED-REF     0     cancelled queued arm (see note)
    P-DBLRECLAIM              0
    P72-DEMOTER-OVERRIDE      0
    P74-DEMOTER-CONTEST       0
    P76-DEMOTER-FOREIGN-CLEAR 0

**The P142 pair matters.** sess25 recorded "the known 'ref intentionally leaked'
path (P142-DWORK-LASTREF) fired 0 times" as ruling the family out, but there are
TWO probes — `P142-BWORK-LASTREF` (xfs_mxfs_dlm.c:16300, bast_work_fn's ident
guard) and `P142-DWORK-LASTREF` (:16469). Only one had been checked. Both now
read 0, so the family is genuinely eliminated.

**P204 is not knob-gated.** It fires on the cancellation EVENT (`c_w || c_d`);
`mxfs.cancel_ref_release` only gates the repair action. So `P204=0` really does
mean no queued arm was cancelled. Consistent with the rest: the leaked inode
never reached `mxfs_dlm_evict` at all — it survives to module unload with
`icount=1`.

`P76-QW-FALSE = 24`, but every one of those paths does an explicit `xfs_irele`.

## Eliminated by source verification

- **`xfs_lookup`** (xfs/xfs_inode.c:1066) releases on every internal path:
  `out_irele:` ireles; `out_unlock:` is reachable only from line 1226, which
  PRECEDES the `xfs_iget` at 1229; the type-flip ESTALE path (1768-1770) ireles
  and NULLs; of the five `goto retry_iget` sites, 1373/1510/1577 release first
  and 1301/1306 sit on the iget-FAILED branch holding no ref.
- **`d_splice_alias`** (/src/linux/fs/dcache.c:3130 — the kernel tree is at
  `/src/linux`, not `~/src/linux`) consumes the reference on EVERY path:
  `IS_ERR(inode)` returns ERR_CAST before touching it; the `S_ISDIR` alias branch
  does `iput(inode)` on all three sub-branches (ELOOP, `__d_unalias`, `__d_move`);
  otherwise `__d_add` transfers ownership to the dentry. So MXFS's unusual habit
  of passing `ERR_PTR(error)` into it (upstream returns early instead) is safe.
- **`xfs_lookup` has only 3 callers**: `xfs_vn_lookup`, `xfs_vn_ci_lookup`
  (ASCII-CI only), and `xfs_fs_get_parent` (NFS export). The first two hand the
  ref to `d_splice_alias`.
- **`mxfs_dlm_bast_work_fn`** has exactly ONE early return before its trailing
  `xfs_irele` — the ident guard at 16302, whose leak is the P142-BWORK path,
  measured 0.
- The shared PR-demote arm helper (~32320) pairs correctly: `igrab`, unwind
  `bast_pending` and return on refusal, else `queue_delayed_work` with
  `xfs_irele` when it reports already-armed.

## THEREFORE — the live hypothesis

`P203-LEVEL[1]` names `xfs_lookup`, but that table is sound only under LIFO
release order, and `d_splice_alias` is now proven to always consume the lookup
ref. So LEVEL[1] is almost certainly MISATTRIBUTING: xfs_lookup's grab took the
count 0->1, a later grab took 1->2, and the dentry's iput took it back to 1 —
leaving the LATER grabber's reference while LEVEL[1] still names xfs_lookup.

`LEVEL[3]` and `LEVEL[4]` name **`mxfs_dlm_bast_notify+0x71`** in both later
captures, and capture 1's `iget_caller` was also `mxfs_dlm_bast_notify` with
`bastq_src=1` (the ilock-end deferred-release site, xfs_mxfs_dlm.c ~27113).
Every capture shows `bast_pending=0 bwork_pending=0 dwork_pending=0
dwork_timer=0 demoter=0` — the work that OWNS the grabbed ref is not queued and
not running.

**So: a bast arm igrabbed, and the work that owns that reference neither ran to
its trailing irele nor is still pending.** The arm sites are enumerable via
`i_dlm_bastq_src` (21 assignment sites; captures show src 1, 9, 14), and each
must pair its igrab with either a successful queue or an irele. Audit the src=9
(16613, 16866) and src=14 (13867, 17816) sites next — src=1 (27113) was read and
is correct.

Do NOT rebuild a global refcount balance; see
`unmount-leak-global-refcount-balance-cannot-work`.
