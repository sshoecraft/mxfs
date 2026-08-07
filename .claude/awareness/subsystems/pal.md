# pal (Platform Abstraction Layer)
<!-- sess32: xfs_buf.c + xfs_super.c changes documented in the "sess32 (session 14)" sections at the end of this file -->
<!-- sess37: xfs_super.c put_super bast-arm gate + s_inodes sweep, xfs_aops.c
     knobs rel_stale_inject/evict_retain_pr — see the sess37 delta + the
     sess37 file-change index at the end of this file -->
<!-- sess47: xfs_buf.c inode-cluster time-travel fence (P-INOCL-COLDREAD +
     pag_mxfs_inocl_wr_epoch stamp) + xfs_super.c mxfs_inocl_fence param —
     see the two sess47 sections at the end of this file, INCLUDING the
     falsifier CORRECTION (fence arm incomplete; do not cite it as the
     fossil-producer fix).  Cross-subsystem: the perag epoch field lives in
     xfs/libxfs/xfs_ag.h and the consumer defect ledger is in xfs.md's
     sess47 section. -->


**Owner files**: `pal/` (29 files, ~27K LOC)
**Last updated**: 2026-08-02 (sess47, 0.11.376-377: inode-cluster cold-read fence in xfs_buf.c + inocl_fence param in xfs_super.c; falsifier outcome documented at end).  Previous: 2026-08-02 (sess43, 0.11.354: put_super PR-unregister ordering — deferred unregister moved AFTER xfs_shutdown_devices; see the sess43 delta at the end of this file).  Previous: 2026-08-01 (sess37, 0.11.313-317: put_super bast-arm gate +
s_inodes sweep in xfs_super.c — the D-DWORK-TEARDOWN-LASTREF class fix — plus
four new module knobs in xfs_aops.c; see the sess37 delta at the end of this
file.  Previous: sess36, 0.11.305-309: PROBE-A transient guard in
xfs_buf.c — re-reads AG authority before the once-per-boot dump_stack; a
self-refuting racy sample (payload cached=1) had tripped soak's call-trace
scan.  New TEST-ONLY knob mxfs.bast_qfalse_inject in xfs_aops.c (bast_work
self-requeue → deterministic queue_work-false collisions; the
D-UNMOUNT-BUSY-INODES branch-coverage injector).  xfs_file.c: stale_src=27
stamped at the rw-bail "keep armed across bails" setter.  See the sess36
section at file end.)
**Prior**: 2026-07-31 (sess32, 0.11.272-283: P222 mask default-ON with
fail-closed unlanded arm (P224 + shutdown, knob stale_stage_unlanded_shutdown);
P222 print extended (stage_mode/ili/pend/dur); xfs_super.c stamps
mp->m_mxfs_slice_adopted from the disklock claim for the ADOPTED-slice
recovery gate. Full detail in the sess32 sections at file end + ccmemory
ccloop-c7ee71c6-sess32-*.)
**Prior**: 2026-07-31 (sess31, 0.11.268-270: P219 format-string fix — the print PANICKED nodes on every fire pre-269; stale_nl counter + bflags= added; torn-stamp epoch double-read in xfs_iflush. The logged-slot authority question now has DATA: orphan images written at NL for real (class X), shared-parent dir submitted mid-EX with multi-epoch-old bytes (class Z). See ccmemory ccloop-c7ee71c6-sess31-P219-*.)
**Prior**: 2026-07-30 (ccloop-c7ee71c6 sess27, 0.11.236-238 —
`pal/linux/xfs_super.c`: `xfs_fs_drop_inode()` now calls
`mxfs_inode_tenure_reset(ip)` (new static inline in `xfs/xfs_inode.h`) before
`inode_generic_drop()`.  NO new PAL public API; this is a callback-body change.
WHY HERE: `->drop_inode` is invoked from `iput_final()` at the exact instant
`i_count` reaches 0, which is the ONLY point a filesystem can observe that
transition — `ihold()` is inline in the VFS and `dput()->iput()` reaches no FS
callback.  New per-inode fields `i_mxfs_zero_seq` / `i_mxfs_tenure_grabs` /
`i_mxfs_zero_jiffies` scope the grab-attribution table to the final busy tenure.
MEASURED NEGATIVE: it does not narrow the unmount leak (`tenure_grabs=499` and
`542` over a ~60 s tenure), so always print the tenure grab COUNT beside any
tenure-scoped attribution.  Kernel facts verified while building it, in
`/src/linux/fs/inode.c`: `__inode_lru_list_add()` returns early
`if (icount_read(inode))` so LRU membership PROVES the inode reached zero;
`inode_lru_list_del()` is called only from teardown paths, never from a grab, so
`lru_linked=1` with a live count is NORMAL; and `evict_inodes()` SKIPS any inode
with a nonzero count, which is why a leaked reference survives unmount.  See the
sess27 section below for the ownership probe (P206-OWNERS) that replaced the
pairing approach.)

## Purpose

PAL isolates everything-OS from the rest of mxfs so the same C code (dlm, tools, mxfs_clayer) can build for either kernel or user space. Provides: block-device I/O wrappers, thread/mutex/condvar primitives, sockets (TCP/UDP/multicast), time, random, logging, allocator. The kernel variant also hosts the linux fork of XFS's super/buf/ioend/iomap glue.

## Public API (PAL surface)

```c
mxfs_pal_alloc(size) / mxfs_pal_free(p)
mxfs_pal_log(level, fmt, ...)
mxfs_pal_time_ms() -> uint64_t                           // boot-relative, NOT cross-node comparable
mxfs_pal_time_real_ms() -> uint64_t                       // v0.10.78: wall-clock ms; use for ANY
                                                          // timestamp one node writes and another reads
mxfs_pal_sleep_ms(ms)
mxfs_pal_get_random_bytes(buf, len)
mxfs_pal_crc32c(crc, data, len) -> uint32_t               // 0.11.5: raw kernel crc32c()
                                                          // semantics (seed as-is, no
                                                          // inversion); kern.c wraps
                                                          // linux crc32c(), user.c has a
                                                          // matching table impl (MEPOCH
                                                          // record seal/validate)
mxfs_pal_thread_create(fn, data) / mxfs_pal_thread_join
mxfs_pal_mutex_create/destroy/lock/unlock                // CAN SLEEP — never call
                                                          // while holding a spinlock
mxfs_pal_spinlock_create/destroy/lock/unlock              // v0.10.80: NEVER sleeps —
                                                          // safe nested inside a caller's
                                                          // own spinlock-held section
mxfs_pal_cond_create/destroy/wait/timedwait/signal/broadcast
mxfs_bdev_t* mxfs_pal_bdev_open(path, ro) / wrap(struct block_device*) / close
mxfs_pal_bdev_read/write/read_prio (queue priority hints)
mxfs_pal_bdev_clone_with_offset(bdev, offset) -> *clone   // for XFS data region
mxfs_pal_scsi_read_fua_bdev(bdev, lba, buf, len) -> int   // sess21 FUA-read passthrough
mxfs_pal_scsi_write_fua_bdev(bdev, lba, buf, len) -> int  // v0.3.117 WRITE(16)+FUA sibling
mxfs_pal_caw_submit(...)                                  // v0.3.128 manual-bio CAW path
mxfs_pal_sdev_cache_release(void)                         // v0.6.0 (pal.h): drop cached
                                                          // backing-path scsi_device refs;
                                                          // called from exit_xfs_fs; no-op
                                                          // stub in user.c
TCP/UDP socket API: mxfs_pal_tcp_*, mxfs_pal_udp_*
```

Socket buffer sizing: `mxfs_pal_tcp_set_opts` pins TCP rcv/snd at 16MB
(DLM control bursts); `mxfs_pal_udp_open` pins UDP rcvbuf at 4MB with
SOCK_RCVBUF_LOCK (sess8 ccloop 72513a13: the ~208KB default dropped
BAST-hint/GRANT-nudge multicasts under 32-node storms — the recv thread
on a loaded VM can't drain >1k pkt/s bursts, and every lost GRANT nudge
costs that handoff a full poll backstop).

## Files (kernel-only `pal/linux/`)

- `kern.c` — module-init helpers (NOT the FS module init; that's `xfs_super.c`)
- `xfs_super.c` (~2900 LOC) — fork of upstream `fs/xfs/xfs_super.c`. Module init/exit lives here. v5 sess33 added cache-sizing module params + `mxfs_compute_cache_caps` + `m_mxfs_ag_bast_wq` ordered workqueue alloc + `mxfs_v5_dlm_init` call from fill_super.
- `xfs_buf.c` — fork of upstream xfs_buf with mxfs FUA-read hook (`mxfs_buf_read_fua`), `_XBF_FUA_FRESH` and `_XBF_MXFS_ALLOC_QUEUED` flag clearing. 2026-07-14: added `P-EXGUARD-SNAPSHOT` diagnostic logging right before the `dir_ex_write_guard`/`dataclobber` decision `if` (~L4988) — see the dated entry at the top of this doc for what it's diagnosing and what it's ruled out so far. Also the **dir-write chokepoint** (bio-submit path, ~L3300+): a family of default-off, module-param-gated arms that SUPPRESS a dir DATA/LEAF write that would clobber a peer's durable dirent — each does a raw plain/FUA disk read of the target daddr and compares (`mxfs_dir3_disk_has_extra_inum` counts dirents present in one image but absent in the other). Existing arms defend the DISK-superset direction (buffer drops a peer dirent): `dir_subset_guard` (P26), `dir_refresh_inplace` (P39), `dir_ex_write_guard`/`dataclobber` (P12), `dir_relepoch_skip`/`dir_reflush_skip` (P50/P33). sess2(ccloop 26c41354) added the CORE-superset direction via `mxfs_dir3_reintro_free_count()` + params `dir_reintro_probe`/`dir_reintro_skip` (P-REINTRO): a stale prior-tenure image reintroducing a removed dirent whose on-disk inode is now FREE (di_mode==0) — the 16-node dangling-dirent. All these arms are the RIGHT place for a lightweight (no per-handoff latency) dir-write fix. **PITFALL (ccloop cc87fed3 sess8, PROVEN by regression + revert, do not re-attempt this shape): the `mxfs_buf_xfsaild_skip_dir_write` clobber check (~L4890-4945, the `dir_ex_write_guard`/`dataclobber` arm's core comparison) is INTENTIONALLY one-directional — `clobber = (dcnt > bcnt) || (dcnt==bcnt && checksums differ)`, i.e. it only skips a write when DISK has MORE/different dirents than our buffer (protects against erasing a peer's committed entry). Symmetrizing it to `dcnt != bcnt` (to also catch the Case-B "our buffer has an entry disk lacks" reintroduce direction — see xfs.md's cache_coherency "uv gone" notes) REGRESSED `posix_multi@8/caw` (renamed file content came back empty, a hardlink's dirent vanished) — reverted same session, confirmed by rebuilding back to the identical prior srcversion. Root: `bcnt > dcnt` is ambiguous inside this already-suspect (`dc_stale` / not-holding-EX) gate between (a) a genuinely stale peer buffer about to wrongly resurrect a removed entry, and (b) OUR OWN buffer, correctly dirtied under EX, whose async post-release destage (xfsaild writeback, which legitimately happens AFTER EX is dropped in this architecture) simply hasn't caught up to disk yet — `dc_stale`'s whole-block gen-stamping cannot tell these apart by count/checksum alone. A correct fix for the reintroduce direction needs PER-ENTRY provenance (e.g. cross-check the specific extra inum against "did THIS node recently create it"), not a blind count symmetrization.
- `xfs_buf_item.c` — fork of upstream xfs_buf_item.
- `xfs_aops.c`, `xfs_iomap.c`, `xfs_inode.c` — upstream forks; small mxfs hooks.
- `xfs_symlink.c` — upstream fork; v0.5.6 sess29(run14d): after `xfs_dir_create_child` stamps `du.ip->i_mxfs_unpub_parent = dp->i_ino` for the scoped BAST-side publish drain (same hook as xfs_create — see xfs.md, mxfs_dlm_publish_unpublished).
- `pal_linux_kern.c` — kernel implementations of PAL functions.

## Files (user-space `pal/user/`)

- `pal_linux_user.c` — user-space implementations.
- Used only by tools (mkfs, chk, fua_verify, caw_verify) and tests.

## Internal Architecture

**Block-device wrapping:** in kernel, `mxfs_bdev_t` wraps a `struct block_device *` (no re-open — XFS owns it). Reads/writes use bio submission; FUA-read uses `scsi_execute_cmd` via `mxfs_pal_scsi_read_fua_bdev`. The `clone_with_offset` returns a `mxfs_bdev_t` that applies a base offset to all I/O — used to give XFS a virtual view starting at the XFS data region (after the MXFS envelope's super/journal/disklock prefix).

**Workqueues** (added v5 sess33): `m_mxfs_ag_bast_wq` is `alloc_ordered_workqueue("mxfs-ag-bast/%s", WQ_MEM_RECLAIM, ...)`. Allocated in `xfs_init_mount_workqueues`, destroyed in `xfs_destroy_mount_workqueues`. `m_mxfs_inode_bast_wq` (`mxfs-ino-bast/%s`, `WQ_UNBOUND | WQ_MEM_RECLAIM`) runs async in-core inode-BAST demotes, the reclaimed-inode `noino_bast_work_fn` releases, and `m_mxfs_publish_work`. **sess3 (ccloop 26c41354): its `max_active` is now the module param `mxfs_bast_wq_max_active` (declared in `xfs/xfs_mxfs_dlm.c`, extern'd + passed to `alloc_workqueue` in `xfs_super.c`; default 0 = kernel unbounded ~512).** See the tag-exhaustion pitfall below.

**Module init order:**
1. `xfs_check_ondisk_structs` + `xfs_dahash_test`
2. `mxfs_compute_cache_caps` (v0.4.0) — reads totalram_pages, populates `mxfs_cache_caps`
3. `xfs_dir_startup`, `xfs_init_caches`, `xfs_init_workqueues`, `xfs_init_procfs`
4. `xfs_qm_init`, `register_filesystem`

## Cross-Subsystem Dependencies

| Depends On | How | Notes |
|---|---|---|
| xfs | upstream-fork files in pal/linux/ are part of xfs_super module init | xfs_super.c lives here architecturally |
| dlm | calls `mxfs_v5_dlm_init`/`shutdown` from fill_super/put_super | |

| Depended On By | How |
|---|---|
| All other subsystems | Every C source file uses `mxfs_pal_*` | PAL is the floor |

## Invariants

1. **No direct kernel API calls outside `pal/`.** dlm, tools, mxfs_clayer must go through `mxfs_pal_*` so user-space builds work.
2. **`mxfs_pal_bdev_*` I/O paths apply `base_offset` for cloned bdevs.** The clone presents a virtual view; raw I/O on the underlying bdev would skip mxfs's envelope offset and corrupt the disk layout.
3. **`m_mxfs_ag_bast_wq` MUST NOT call `flush_workqueue()` / `cancel_work_sync` from inside `bast_work_fn` itself** — would deadlock on its own ordered queue.
4. **Module params are read at module init only.** Per-mount params on the existing user-space-tool path (`mxfs_mount_opts`) ARE read at mount time. Mixing the two paths confuses cap propagation.
5. **`mxfs_rwlock_t` IS A SLEEPING LOCK.** In the kernel PAL it wraps `struct rw_semaphore`, so `mxfs_pal_rwlock_rdlock()` / `_wrlock()` call `down_read()` / `down_write()` and CAN SCHEDULE. They are illegal with a spinlock held, with preemption disabled, or in any atomic context. The name reads like a spinlock and has twice misled callers into using it under `pag_ici_lock`. Use `mxfs_pal_rwlock_tryrdlock()` there instead — see below.

## Sleeping-vs-atomic PAL surface (ccloop c7ee71c6 sess21)

Added after the same defect class shipped **twice**: sess19 put a blocking SCSI
read under `pag_ici_lock`, sess20 "fixed" it for the CAW transport but left the
TCP arm calling `mxfs_dlm_held_mode()` -> `mxfs_pal_rwlock_rdlock()` ->
`down_read()` -> `schedule()`. Result: `BUG: scheduling while atomic`, corrupted
preempt_count, and a peer CPU spinning forever in `mxfs_ici_lock()`'s unbounded
`spin_trylock` loop (`soft lockup - CPU#2 stuck for 522s`), which took the whole
32-node cluster down.

| API | Sleeps? | Use |
|---|---|---|
| `mxfs_pal_rwlock_rdlock` / `_wrlock` | **YES** (`down_read`/`down_write`) | process context only |
| `mxfs_pal_rwlock_tryrdlock` | **NO** (`down_read_trylock`) | returns 1 if taken, 0 if not; the ONLY acquire legal with a spinlock held. Release with `mxfs_pal_rwlock_unlock` (drops a read ref; `up_read` also never sleeps). |
| `mxfs_pal_may_sleep` | n/a | 1 if the current context may sleep, 0 if atomic (`!in_atomic() && !irqs_disabled()`); user-mode always 1. Exists so `dlm/` can ASSERT its sleeping entry points aren't reached from atomic context WITHOUT importing a kernel API (invariant 1). Backs the `P191-SLEEP-IN-ATOMIC` tripwire on `mxfs_dlm_held_mode`. |

**When adding any new PAL call reachable from `xfs_buf.c`'s inode-cluster write
path, classify it against this table first** — that region runs under
`pag_ici_lock`.

## sess23 (ccloop c7ee71c6) — `xfs_super.c`: unmount-time inode-leak forensics

### What changed
`xfs_destroy_caches()` now calls **`mxfs_report_leaked_inodes()`** immediately
after its `rcu_barrier()` and before `kmem_cache_destroy(xfs_inode_cache)`.
That is the exact instant the kernel reports
`kmem_cache_destroy mxfs_inode: Slab cache still has objects`, so the survivor
is named instead of being an anonymous slab object.

`xfs_kill_sb()` still calls `mxfs_report_residual_inodes()` (P199) — **but note
the ordering pitfall below; P199 is forensics, NOT a leak detector.**

### Cross-subsystem (pal -> xfs)
`mxfs_report_leaked_inodes()` lives in `xfs/xfs_icache.c` and is declared in
`xfs/xfs_inode.h`. It walks a global registry (`mxfs_live_inodes`, guarded by
`mxfs_live_inodes_lock`) that every `xfs_inode` joins in `xfs_inode_alloc()`
and leaves in `xfs_inode_free_callback()` — the RCU callback, the last instant
before `kmem_cache_free`. The list therefore mirrors the slab's live objects
exactly. Knob: `mxfs.live_inode_track` (default 1). The probe **always**
prints, including `leaked=0 tracked_allocs=N`, so a zero is a measurement and
not silence.

### PITFALL — teardown ordering, and why P199 cannot see a leak
`generic_shutdown_super()` runs:

    shrink_dcache_for_umount -> evict_inodes -> sop->put_super -> busy-inode WARN

`xfs_kill_sb` calls P199 **before** `kill_block_super`, i.e. before the dcache
shrink and `evict_inodes`. A large "still referenced" census there is NORMAL
(measured on a healthy 32-node unmount: 770 icount=0, 216 icount=1, 32
icount=2, zero warnings). Do not read P199's count as a leak — a prior session
chased "775 leaked regular files" that were simply dentry-pinned inodes about
to be evicted. The real leak is exactly ONE inode and only P202 can see it.

`xfs_fs_put_super` flushes `m_mxfs_inode_bast_wq` and calls
`xfs_filestream_unmount()` **before** the busy-inode check, so a reference held
by pending inode-BAST work or the filestream cache would still be released in
time. A reference that survives to P202 is held by neither.

## sess27 (ccloop c7ee71c6) — `xfs_super.c`: `xfs_fs_drop_inode` opens a grab tenure

### What changed (public surface)
`xfs_fs_drop_inode()` now calls **`mxfs_inode_tenure_reset(ip)`** (static inline
in `xfs/xfs_inode.h`) before `inode_generic_drop()`. New per-inode fields:
`i_mxfs_zero_seq`, `i_mxfs_tenure_grabs`, `i_mxfs_zero_jiffies`.

### WHY THIS CALLBACK SPECIFICALLY (cross-subsystem: pal -> xfs -> VFS)
`->drop_inode` is invoked from `iput_final()`, i.e. **at the exact instant
`i_count` reaches 0**. It is the ONLY place a filesystem can observe that
transition — `ihold()` is inline in the VFS and `dput()->iput()` never reaches
any FS callback. That makes this callback the single hook point for anything
that needs to reason about inode reference *tenures* rather than raw counts.

Verified in `/src/linux/fs/inode.c` while building this:
- `__inode_lru_list_add()` returns early `if (icount_read(inode))`, so an inode
  joins the inode LRU **only** at `i_count == 0`. LRU membership therefore
  PROVES the inode previously reached zero.
- `inode_lru_list_del()` is called only from teardown paths (`evict_inodes`,
  `iput_final`) — **never from a grab**. So `lru_linked=1` together with
  `i_count > 0` is a normal, expected state (removal is lazy, done by the
  shrinker's isolate). Do not read it as an anomaly.
- `evict_inodes()` **skips** any inode with a nonzero count, which is why a
  leaked reference survives unmount rather than being swept.

### PITFALL — a tenure reset does NOT imply a narrow tenure
The point of the reset was to scope `i_mxfs_grabst[]` to the final busy tenure
so the level table stops depending on LIFO release order. **Measured: it does
not narrow anything on a hot directory** — captures read `zero_seq=1
tenure_grabs=499` and `zero_seq=9 tenure_grabs=542` over a ~60 s tenure. Always
print the tenure grab COUNT beside any tenure-scoped attribution; without it a
500-grab window is indistinguishable from a 1-grab window and the table gets
misread as an answer. (Same class of mistake as gating an exposure counter on
the fix being measured — see xfs.md, P208.)

### Ownership beats pairing (what to reach for next)
`P206-OWNERS` (in `xfs/xfs_icache.c`, printed beside P202) checks the VFS
structures that pin an inode invisibly: `i_fsnotify_marks`, `i_flctx`,
`i_private`, `i_data.nrpages`, `i_readcount`, and a true `i_dentry` alias COUNT
(the older probe printed a boolean, which cannot distinguish 0 from 1 alias).
All read zero on the leaked inode, so nothing reachable *from* the inode holds
it. Note `i_state=0x100` is `I_REFERENCED`, set by `__inode_lru_list_add` on
rotate — expected, not a finding.

### PITFALL (COST A KERNEL PANIC) — wrappers must honour the wrapped contract
sess23 macro-wrapped `igrab`/`iput` inside MXFS translation units for
call-site attribution. The `iput` wrapper dereferenced its argument before the
NULL check. **`iput(NULL)` is legal** — upstream returns early, and MXFS relies
on it (`mxfs_dlm_pr_sweep_work_fn`'s bail-out paths call `iput(toput)` where
`toput` may never have been set). `XFS_I(NULL)` is `-offsetof(i_vnode)`, so the
write landed at a tiny address:

    BUG: kernel NULL pointer dereference, address: 000000000000033c
    Workqueue: mxfs-ino-bast/dm-1 mxfs_dlm_pr_sweep_work_fn [mxfs]
    Kernel panic - not syncing: Fatal exception

Every node panicked at mount. It did **not** present as a bad build: the nodes
rebooted, came back without `/src` (deliberately not an fstab automount), prep
reported "did not release mxfs / lost /src" and power-cycled them, and they
came back without `/src` again — a self-sustaining loop that read as a flapping
test rig. **When the rig flaps right after a new build, read a node's serial
console (`/var/log/libvirt/qemu/testN-serial.log`) before touching the rig** —
dmesg is gone after the reboot and the panic is only there.

Generalised rule for this subsystem: any PAL-level or macro-level wrapper around
a kernel API must replicate that API's edge contract exactly, NULL included.

## Known Pitfalls

- **Do not trust this codebase's `~6.X` kernel-version-guard comments at face value — verify against the target kernel's actual installed headers before relying on one.** PROVEN (2026-07-20, Proxmox VE 9 / kernel 6.17.2-1-pve portability session): building against a real 6.17.2 kernel (previously only 6.8.0-101-generic had ever been validated) surfaced ~30 wrong version thresholds in `xfs/xfs_platform.h` alone — most guessed as landing "in ~6.19" (the fork's nominal upstream baseline) when the real upstream commit landed anywhere from v6.9 to v6.18, in both directions (some shims were removed too early, some too late). Two `pal/linux/` sites were part of this same class of bug and got fixed this session:
  - **`pal/linux/xfs_super.c`**: `d_revalidate` gained new leading `(struct inode *dir, const struct qstr *name)` params in v6.17 (verified against `linux/dcache.h` on 6.17.2-1-pve: `int (*d_revalidate)(struct inode *, const struct qstr *, struct dentry *, unsigned int)`), and `set_default_d_op()` replaces the direct `sb->s_d_op = ...` assignment starting the same version. Fixed via a thin calling-convention adapter (`mxfs_drevalidate_v617`, `LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)`) that forwards to the existing (unchanged) `mxfs_drevalidate(dentry, flags)` — the new `dir`/`name` params carry nothing `mxfs_drevalidate` doesn't already derive from `dentry` itself, so the 400-line function body needed zero changes.
  - **`pal/linux/xfs_iops.c`**: `xfs_vn_update_time`'s `enum fs_update_time`-typed 3-arg `.update_time`/`inode_update_time()` form (guarded `>= 6.15` in the code) does **not exist in any released kernel through 6.17.2** — verified absent from 6.17.2-1-pve's actual `linux/fs.h` (still the plain `int (*update_time)(struct inode *, int)` 2-arg form, and `S_ATIME`/`S_MTIME`/`S_CTIME` are still there, just as an `enum` instead of `#define`). The 3-arg form only exists in an unreleased/future commit in the local kernel reference tree (`/src/linux`, no reachable release tag via `git describe --contains`). Threshold raised to `KERNEL_VERSION(6, 90, 0)` (i.e. effectively disabled) with a comment not to lower it without checking a real kernel's headers first — **do not casually "fix" this back down to 6.15/6.17 without that check**, it was deliberately raised, not a leftover mistake.
  - **Verification method that worked**: for a "does kernel already have symbol X" question, `ssh` to the target and `grep` its `/usr/src/linux-headers-$(uname -r)/include/linux/*.h` directly — far more reliable than guessing from a version number alone. For "what version did X actually land in", `git log --all --oneline -S"X" -- path/to/header.h` then `git describe --contains --match 'v6.*' <commit> | sed -E 's/~.*//; s/(-rc[0-9]+)?\^.*//'` against the local kernel source reference tree at `/src/linux` (see project `CLAUDE.md` RULE 1) — fast and precise once you have a commit hash; `git tag --contains` on the same commit is far slower and sometimes hangs on old commits, prefer `describe`.
  - Also hit and reverted: a `replace_all: true` Edit meant for the `xfs_vn_update_time` fix accidentally matched **6 other** unrelated `KERNEL_VERSION(6, 15, 0)` guards in the same file (`xfs_vn_mkdir`'s dentry-return change, `STATX_DIO_READ_ALIGN` reporting, an `IOCB_NOWAIT` check in `xfs_vn_update_time`'s own lazytime branch) — **always use unique surrounding context per version-guard edit in `xfs_iops.c`/`xfs_platform.h`, never `replace_all` on a bare `#if LINUX_VERSION_CODE >= KERNEL_VERSION(...)` line**, this file reuses the same threshold constant at many unrelated sites.
  - Not yet fixed as of this note: `pal/linux/xfs_aops.c`'s buffered-writeback path (`xfs_end_ioend`, `xfs_map_blocks`, `xfs_writeback_ops`, `xfs_vm_writepages`) needs a real port to the 6.17+ `iomap_writeback_ops.writeback_range/writeback_submit` API (replaces `map_blocks`/`prepare_ioend`/`discard_folio`; `iomap_ioend` lost `io_type`/pointer-`io_bio` in favor of `IOMAP_IOEND_UNWRITTEN`/`IOMAP_IOEND_SHARED` flags and an embedded `struct bio io_bio`) — this is not a threshold fix, it's a genuine upstream API rework (Christoph Hellwig's iomap writeback-range conversion), still in progress.
- **`mxfs_pal_mutex_t` can sleep — never call a `mxfs_pal_mutex_*`-protected accessor from code that already holds a spinlock (kernel `spinlock_t`, or another `mxfs_spinlock_t`).** PROVEN (2026-07-13, fence_during_write@8/caw bug #3): `xfs/xfs_mxfs_dlm.c::mxfs_dlm_bast_process` holds `ip->i_dlm_lock` (a real `spinlock_t`) continuously across its orphan-release decision block; an early draft called `dlm/dlm_caw.c`'s existing `grant_meta`-table accessors from there, which take `grant_meta_lock` (`mxfs_mutex_t` → `mutex_lock()`, sleep-capable) — scheduling-while-atomic. Caught by tracing every `spin_lock`/`spin_unlock` on `ip->i_dlm_lock` from function entry to the call site (`awk` over the function body) BEFORE deploying, not by a runtime crash. Fix was a new dedicated `mxfs_spinlock_t`-protected table (`ctx->orphan_clock`, own lock, NOT sharing `grant_meta`'s struct or lock — sharing the struct while protecting it with a DIFFERENT lock would itself be a cross-lock data race on the overlapping fields). **Before adding any new cross-subsystem accessor call inside a function that already holds a lock, grep the enclosing function for the lock's acquire with no matching release before your insertion point, then check what lock type the callee itself takes** (`mxfs_pal_mutex_*` = sleep-capable, never call under a spinlock; `mxfs_pal_spinlock_*` = safe to nest).
- **`mxfs_pal_time_ms()` is boot-relative, not wall-clock — NEVER compare it across nodes.** In-kernel it's `ktime_get_boottime_ns()`; two independently-booted (or independently power-cycled) nodes have unrelated origins for this clock, sometimes off by hours. A timestamp written by node A and subtracted-from by node B (`age = mxfs_pal_time_ms() - remote_ts`, unsigned) silently underflows to a huge value whenever B has less boot-uptime than A had at write time — the value doesn't look wrong, it just looks like "instantly expired." PROVEN (2026-07-13, fence_during_write@8/caw): this exact bug defeated `dlm/dlm_caw.c`'s CAW fair-handoff anti-starvation ticket (`yield_set_ms`), which is written by the releasing node and read by every other waiter. Use `mxfs_pal_time_real_ms()` (wall-clock) for any timestamp that crosses node boundaries; reserve `mxfs_pal_time_ms()` for single-node-local elapsed/backoff timers where the writer and reader are provably the same node. When auditing for this class of bug, grep for `mxfs_pal_time_ms()` call sites whose result is stored in an on-disk/shared struct (CAW slot fields like `last_modified_ms`, DLM lease fields, etc.) rather than a local stack variable — a local `uint64_t start = mxfs_pal_time_ms()` compared later by the SAME function/node is fine.
- **`xfs_super.c` / `xfs_buf.c` carry both XFS-derived plumbing and MXFS hooks.** These files were copied from `~/src/linux/fs/xfs/` at 6.19-rc0 and are now project source code — modify them directly. Search for `mxfs` / `MXFS_` / `m_mxfs_` to find MXFS-added regions when reading; not all changes are flagged but most are. (There is no "upstream" to merge from.)
- **FUA-read not honored by LIO target:** sess21 finding. PAL-level fix is `mxfs_pal_scsi_read_fua_bdev` which submits SCSI READ(16) with FUA bit set. xfs uses this via `mxfs_buf_read_fua`. If you bypass that and use plain bio with REQ_FUA, the LIO target silently drops the bit (per upstream `target_core_iblock.c:772`).
- **Multi-node metadata reads flow through `mxfs_buf_read_fua`, NOT `xfs_buf_submit_bio` (sess5 ccloop 12e0d157, load-bearing for any read-storm work):** when `mxfs_buf_needs_fua_read(bp)` is true (ALL inode/dir/agmeta/bmbt buffers) and `!_XBF_FUA_FRESH` and multi-node, `xfs_buf_submit` diverts a COLD read to `mxfs_buf_read_fua` (SCSI READ(16)+FUA via `mxfs_pal_scsi_read_fua_bdev`) — it NEVER reaches `xfs_buf_submit_bio`. So a read-classifying probe placed at `xfs_buf_submit_bio` (as sess5's first `read_attr_probe` was) sees ~0 of the storm. The 32-node dlm_scaling/cache_coherency read storm is exactly these FUA re-reads. To attribute the storm, instrument the STALE side (`xfs_buf_stale`, which clears `_XBF_FUA_FRESH` → forces the next cold FUA read) — sess5's `read_attr_probe` STALE-INO arm there proved the staler is `mxfs_dlm_reload_inode` (xfs/xfs_mxfs_dlm.c) on the `mode==0` reused-inode grant + `mxfs_dlm_bast_process`. `_XBF_FUA_FRESH` set only by a successful `mxfs_buf_read_fua` (~L4970); cleared by `xfs_buf_stale` (~L131). See ccmemory `caw-sess5-32node-fresh-baselines-and-fua-read-root`, `caw-sess5-STALER-identified-reload-inode-and-levers-tried`.
- **`read_attr_probe` (sess5, DEFAULT 0, diagnostic-only, safe to leave):** module param declared in `xfs/xfs_mxfs_dlm.c` (with atomics `mxfs_rd_ino_real/ino_ra/dir/agmeta/other`, `mxfs_stale_ino`). Two arms in `xfs_buf.c`: (a) at `xfs_buf_submit_bio` — classifies each cold bio read by buffer class, periodic `RD-ATTR` dmesg every 512 + hard-ratelimited stack for inode reads; (b) at `xfs_buf_stale` — counts inode-buffer stales (`STALE-INO`) + ratelimited stack of the staler. Both hard-ratelimited (`HZ,1`), so no dmesg-clean risk when off. The submit-bio arm is of LIMITED use (storm bypasses it — see above); the stale arm is the useful one. Turn OFF for perf/soak runs.
- **Dir-write suppression, CORE-superset direction needs a free/live discriminator (sess2 ccloop):** the existing chokepoint arms explicitly treat an in-core dirent ABSENT on disk as a legit un-landed ADD that must NOT be dropped ("MERGE-NEEDED", sess28) — correct for creates. But that same shape is ALSO a stale-image REINTRODUCE of a removed dirent. You can only safely suppress the reintroduce case by proving the extra inum's on-disk inode is FREE (`di_mode==0`, via `xfs_imap`+FUA read of the inode cluster) — a dirent→free-inode is never a legit add. Gate the (rare) disk read on a cheap in-core predicate (`dc_stale`: `b_mxfs_dir_gen < i_dlm_dir_gen`) so the common write path pays nothing (RULE 0). This is the shape of `mxfs_dir3_reintro_free_count`.
- **FUA passthrough REJECTED by LIO/tcm_loop (sess-tcp 2026-06-14):** the current TCP-DLM test stack (LIO **fileio** + tcm_loop, write-through, `emulate_write_cache=0`) does not merely drop the FUA bit — it **rejects** the READ(16)/WRITE(16)+FUA CDB outright with CHECK CONDITION / sense key 5 (ILLEGAL REQUEST) ASC 0x24 (invalid field in CDB). Proven with `tools/fua_verify write/read`. `mxfs_pal_scsi_read_fua_bdev` therefore returned -EIO → dmesg `fua_disk_mode=0xffffffff` → metadata misread as corruption → cross-node reads failed EFSCORRUPTED ("Structure needs cleaning"). **Fix (build A70942DB+):** `mxfs_pal_scsi_read_fua_bdev` latches a static `mxfs_fua_read_unsupported` on ILLEGAL_REQUEST (or non-SCSI dev) and falls back to `mxfs_pal_bdev_read_plain_bdev` (a plain `submit_bio_wait` REQ_OP_READ) — coherent on a write-through backstore (no target write cache to defeat; the bio still reaches the device). A one-shot mount-time FUA probe in `xfs_fs_fill_super` (right after envelope setup) latches the flag before any real I/O. On a real FUA-capable target (SCST) the passthrough succeeds and the fallback never engages. NOTE: the WRITE-FUA sibling (`mxfs_pal_scsi_write_fua_bdev`) is also rejected by this stack — on write-through a plain buffered write is already durable, but if a write-FUA failure is ever treated as fatal it will need the same fallback.
- **v0.6.0 dm-multipath backing-sdev resolver (ccloop 186320ae, 2026-07-05, kern.c — the mechanism that makes CAW/FUA passthrough work on `/dev/mapper/mpathX`):** the three SCSI passthroughs (CAW 0x89, READ(16)+FUA, WRITE(16)+FUA) need a `struct scsi_device`; a dm gendisk has no SCSI parent and post-5.16 block layers cannot carry a CDB through a dm queue. All three call sites now use `mxfs_bdev_to_sdev()` (static, kern.c): parent-is-scsi fast path unchanged; otherwise resolve by CONTENT IDENTITY — plain-bio read of LBA 0 (MXFS super: magic+uuid, immutable while mounted) through the stacked dev, then scan all SCSI disks (`scsi_host_lookup` 0..4095 + `shost_for_each_device`, exported-only APIs; dm table internals are NOT exported) and READ(16)-compare their LBA 0. Referenced result cached per `bdev->bd_dev` (`mxfs_sdev_cache[4]`, spinlock); offline cached path → dropped + re-resolved (control-plane failover); failed resolve → 5s negative cache (NOT the permanent `mxfs_fua_read_unsupported` latch — a transiently path-less dm device must recover; virtio-blk still degrades to plain-bio reads, now via negative cache instead of the latch). Refs dropped by `mxfs_pal_sdev_cache_release()` from `exit_xfs_fs` (declared in pal/pal.h; user.c has a no-op stub — user mode SG_IOs through the device node and dm forwards the ioctl itself). PITFALLS: (1) requires the stack to map sector 0 → LUN LBA 0 (whole-LUN dm-multipath); partitions/dm-linear fail the match and get a clean -EOPNOTSUPP, never a mistranslated-LBA write; (2) an all-zero LBA 0 (not yet mkfs'd) refuses to match — CAW before mkfs is impossible anyway; (3) `shost_for_each_device` early-break leaks the iterator's device ref — the scan runs the loop to completion and takes its own `scsi_device_get` on the match.
- **v0.6.0 UNIT-ATTENTION retry (kern.c):** CAW and WRITE(16)+FUA now reissue on `sense_key == UNIT_ATTENTION` (bounded 5 tries, `2<<n` ms backoff, `caw_submit:`/`wfua_submit:` labels; logs `P-CAW-UA-RETRY`/`P-WFUA-UA-RETRY` ratelimited) — on dm-multipath the first command down a (re)selected path routinely reports UA (0x29 power-on/reset) INSTEAD of executing, so reissue is safe. READ-FUA's pre-existing 20-try generic retry already covered UA. `memset(&sshdr)` before every (re)submission — scsi_execute_cmd does not clear it on no-sense completions and the MISCOMPARE check below reads sshdr even on ret==0.
- **Workqueue WQ_FREEZABLE during system suspend:** XFS's per-mount queues use this. Don't add WQ_FREEZABLE to `m_mxfs_ag_bast_wq` — bast_work_fn might hold AG-DLM grants peer needs across suspend.
- **`m_mxfs_inode_bast_wq` UNBOUNDED concurrency → block-tag exhaustion WEDGE (sess3 ccloop 26c41354, RULE-4 PROVEN on dir_reuse@16/caw/mpatha):** the reclaimed-inode BAST path (`mxfs_dlm_noino_bast_work_fn`, `xfs/xfs_mxfs_dlm.c`) queues ONE work item PER BAST on the hot shared-dir inode. With the wq unbounded (`max_active=0`), a 16-node storm spawns **hundreds** of concurrent kworkers, each issuing a synchronous FUA `read_slot` inside `mxfs_dlm_caw_unlock_gen`. That exhausts the block layer's request tags → all kworkers block in `blk_mq_get_tag` (D-state) → 767 D-state on test5, load 733, `md5sum` hung 302s, self-reinforcing (BASTs keep arriving, more kworkers spawn). The FUA read never completes so the unlock can't progress — this is NOT a CAW-unlock-CAS-exhaustion problem (`unlock exhausted` count was 0 on the healthy nodes; a wall-clock unlock-retry gated `caw_unlock_backoff` did NOT help — the retries just re-block on tag alloc). **Fix = cap `mxfs_bast_wq_max_active`** (e.g. 16) so concurrent bast FUA reads stay well under the per-node device tag depth; the queued surplus drains in bounded batches and, once the hot inode is unlocked, the rest hit the `node_held==NL` fast path in `caw_unlock_gen`. Default 0 keeps old behavior for A/B; the eventual ship value must be a positive cap (unbounded ships the wedge).
- **Routine diagnostic probes MUST be gated behind `unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled)` for ship.** `xfs_buf.c` and `xfs_bmap.c` carry many `pr_warn`/`dump_stack` probes (`P20-*`, `P29-INSTR`, `P36-*`, `P133-*` …). Any that fire on a *routine* path (every read of a logged buffer, every bunmapi, every inode-cluster write) trip the `dmesg_clean` criterion — which greps node dmesg for `BUG:|Oops|Call Trace|WARNING:` — because a bare `dump_stack()` emits a `Call Trace:` line. sess39 (run14d): `P20-BIO-READ-LOGGED` (~line 3213) and `P29-INSTR` (xfs_bmap.c) were left ungated by the sess38 sweep → `dmesg_clean` FAIL (8 `Call Trace:` hits). Gating fixed it (build `5D2D50C8`). **Keep ungated only the real-anomaly detectors** that fire solely on an actual bug and carry a once-guard (`PROBE-A AG-META-WRITE-NOT-HELD`, `P125-AG-DIVERGE`, `P88-CLOBBER-PRODUCER`), plus the upstream `xfs_buf_verify_write` "no buf ops" warning — those are corruption canaries, not routine. When adding a probe: if it can fire on a healthy hot path, gate it. **sess6 tier refinement**: `dirwr=1` is the runs-with-the-suite observability tier and must stay dmesg-clean under HEALTHY load — a probe whose anomaly heuristic can false-positive on a healthy hot path (e.g. P124's "AIL content differs from disk" premise, which is normal for a sole-EX-holder that never destages) must be gated `instr`-only, not `dirwr`. See the sess6 P124 entry at the end of this doc.
- **`P35E-DIRWR` dir-block write trace (xfs_buf.c, dirwr/instr-gated):** logs every dir3 block/data (`XDB3`/`XDD3`) write submit with daddr/crc/lseq/wseq/in_ail. sess16 extended it to also dump the dirent NAMES (`nent=N names=[...]`) in the block (required adding `#include "xfs_dir2_priv.h"` for `xfs_dir2_data_entsize`) so a concurrent-RMW lost-update is directly visible (one node writes a dir block missing a peer's just-added entry). This is the trace that proved the crash_consistency durable lost-update is a real on-LUN clobber (test1 xfsaild flushing stale/own-stale dir-block images onto a reused daddr), not a read-visibility lag. Diagnostic-only — gated, safe to leave or strip.
- **Dir-block xfsaild-skip chokepoint + `P16-DIRBLK-SUBMIT` detector (xfs_buf.c `xfs_buf_submit_bio`, sess17):** the dirent-block analogue of the proven `P61-CHOKEPOINT-SKIP-BMBT` guard, placed immediately after it. For every dir3 DATA/block/leaf/free/node write reaching the single bio chokepoint it calls `mxfs_buf_xfsaild_skip_dir_write(bp, &dsi)` (defined in `xfs/xfs_mxfs_dlm.c`), which extracts the owner dir ino from the self-describing header and reports the skip-predicate state (owner `i_dlm_mode`, `b_tenure_id` vs the dir's current EX epoch). The detector line (gated `dirwr/instr`) logs `owner/daddr/ops/in_core/mode/tenure/epoch/nl/tmism/would_skip/enforce/comm`. **ENFORCE is gated by the new `mxfs.dirskip` module param (default 1; run detect-only with `dirskip=0`).** When enforcing, an NL-released or prior-tenure dir-block write is suppressed (emulate clean completion, no bio) so a stale lingering BLI can't clobber a peer's durable block. **PITFALL proven sess17 (RULE 4, do NOT re-enable the tenure-mismatch arm for dir blocks):** the `b_tenure_id != epoch` predicate FALSE-POSITIVES on `tenure=0` blocks — a freshly-created leaf during block→leaf conversion has its header owner unset at the first `xfs_trans_log_buf`, so `mxfs_dir_data_track` can't stamp it (`tenure` stays 0) → `would_skip=1` on a LEGIT `comm=dd` write → suppressing it would lose the whole leaf (corruption, the [[sess23-ccloop-suppression-was-corruptor-3of4]] class). The NL-released arm fired 0× in the probe, and the observed loss (`node1_f1`) was absent from the *earliest* block image = lost at INSERT time, not a reflush — so the chokepoint-skip does NOT address that loss. The detector + `mxfs.dirskip` param are kept as tooling; the modify-time stamp `mxfs_dir_data_track` (wired in `xfs/xfs_trans_buf.c`) is the dir analogue of `mxfs_dir_bmbt_track`.
- **`P-WRACT` cross-node dir-write ordering trace (xfs_buf.c submit chokepoint, sess48, gated `dirwr/instr`, capped 3000):** added right after the `P16-DIRBLK-SUBMIT` line, reusing the same `dsi` from `mxfs_buf_xfsaild_skip_dir_write`. `struct mxfs_dir_skip_info` gained two fields (`int active_count`, `uint64_t realns`) filled in that function: `active_count` = `xfs_dir2_block_tail count-stale` (incl. `.`+`..`) for **block-format** dir writes only (`bp->b_ops == &xfs_dir3_block_buf_ops`; leaf/data left −1), and `realns = ktime_get_real_ns()` at submit. The log line is `owner/daddr/act/mode/nl/would_skip/realns/comm`. **This is the decisive instrument prior sessions (sess69/97/68) wanted but never built**: merge BOTH nodes' `P-WRACT` for the contended dir by `realns` (sync node wall clocks first — `date -u -s` to a common second) to see the active-count progression and exactly which node durably writes a stale-base block (peer's already-deleted dirents still present) and when. PROVEN the 2/tcp uv root with it (sess48): test1 deletes 62→32 (landed), test2 deletes 32→**12 then stops** — test2's last 10 deletes (act 12→2) commit to log+cache but the block never destages (no NL-skip; xfsaild simply never pushes the post-EX-downgrade state), so the peer cold-reads the stale `active=12` LUN block. Diagnostic-only (no enforcement). Off by default (`dirwr=0`/`instr=0`). See ccmemory `sess48-PROVEN-uv-durable-stale-base-clobber-active12`.
- **`P-LEAFWRITECLOBBER` leaf-hash write-clobber detector (xfs_buf.c submit chokepoint, sess19, gated `dirwr/instr`):** added inside the existing sess56 coherent-disk-read block (which already plain-bdev-reads the target daddr for every dir3 block write). For a `xfs_dir3_leaf1/leafn` write it compares `xfs_dir3_leaf_hdr.count` of the buffer being written vs the coherent on-disk leaf; if `buf_cnt < disk_cnt` it logs `owner/daddr/buf_cnt/disk_cnt/comm`. **PROVEN the 2/tcp blocker (RULE 4):** `comm=xfsaild buf_cnt=140 disk_cnt=202 nl=0 tmism=0` — xfsaild reflushes a STALE in-core leaf over the newer durable disk leaf, dropping hash entries → readdir keeps the dirent (durable in the data block) but lookup ENOENTs (its hash gone). Note the existing `mxfs_buf_xfsaild_skip_dir_write` guard MISSES this: the stale leaf is stamped with the CURRENT tenure (`tmism=0`) and `nl=0`, so only a CONTENT compare (`buf_cnt<disk_cnt`) detects it. (Detector cosmetic bug: it reads `owner` via `xfs_dir3_blk_hdr` but a leaf uses `xfs_da3_blkinfo`, so the logged `owner` is garbage; the count compare is correct — P16's owner is authoritative.) A sibling read-side detector `P-LEAFREADSTALE` was added in `xfs/libxfs/xfs_da_btree.c` (before `*bpp = bp`) and fired 0× — the clobber is write-time, not a read-time count shortfall. Both are diagnostic-only. See ccmemory `sess19-PROVEN-xfsaild-stale-leaf-reflush-clobber`.
- **`mxfs_buf_leaf_clobber_skip` — image-origin leaf-clobber WRITE-GUARD (sess20, ALWAYS ON, the FIX for 2/tcp crash_consistency leaf-hash loss):** new `xfs_buf_submit_bio` chokepoint guard (in `xfs/xfs_mxfs_dlm.c`, called from `pal/linux/xfs_buf.c` right after the `mxfs.dirskip` block; on `true` the caller emulates a clean ioend — no bio). PROVEN root (RULE 4, build 5E54558B): the clobbering xfsaild leaf write carries `b_mxfs_dir_gen=0` (a STALE image — set by the acquire-time evict / fresh-init, never re-stamped to current gen), while legit current-tenure dir writes carry `bgen==i_dlm_dir_gen` (P16 showed `dgen=270 bgen=270`). So `b_mxfs_dir_gen` IS the image-origin epoch; the existing `b_tenure_id` (mxfs_dir_data_track) is only a *touch* stamp (nl=0, tmism=0 on the clobber — why the dirskip guard misses it). **Discriminator:** a leaf1/leafn write with `bp->b_mxfs_dir_gen < owner dir i_dlm_dir_gen` is a stale base. FAST PATH (`bgen>=dir_gen`, the overwhelming majority) returns immediately — NO disk read, so a legit current-tenure add OR remove is never skipped (the GPT count-compare hazard is avoided; count is consulted only on the rare stale-gen path). Only when `bgen<dir_gen` does it plain-bdev-read the coherent on-disk leaf and skip iff the disk is a VALID leaf of the SAME owner with MORE entries (`disk_cnt>buf_cnt`) — logs `P20-LEAFCLOBBER-SKIP` (always-on, ratelimited). Excludes fresh-leaf creation (disk not a valid leaf / different owner) and create-on-fresh-readahead-base (`disk_cnt<=buf_cnt`). The skipped buffer keeps `bgen=0` so the next dir read's gen-check (xfs_da_read_buf) FUA-refetches the durable superset.
- **Dir-block readahead auto-disabled on multinode (sess20, the PRIMARY fix):** `mxfs_dir_no_reada` default flipped 0→1 (`xfs/xfs_mxfs_dlm.c`). The gate in `xfs_da_reada_buf` (`xfs/libxfs/xfs_da_btree.c`) is scoped to multinode shared dirs only, so SINGLE-NODE keeps readahead (no perf regression). Speculative dir readahead bypasses the `xfs_da_read_buf` coherency gen-stamp, so a read submitted before a peer's write completing after re-acquire repopulates the cache with the stale `bgen=0` image that becomes the leaf-clobber base. With reada off, crash_consistency PASSES 3/3 (was reliably 1/2). The leaf-clobber write-guard above is the belt-and-suspenders backstop. See ccmemory `sess20-PROVEN-bgen0-leaf-clobber-discriminator`.
- **`P40-INCARN-ABA-DIRSKIP` — dir-block ABA-incarnation WRITE-GUARD (sess40, build B9F9326E, the FIX for dir_reuse_coherency 2/tcp Bug A):** at the same `xfs_buf_submit_bio` dir-write chokepoint, the existing `mxfs_buf_xfsaild_skip_dir_write` (xfs/xfs_mxfs_dlm.c) now ALSO sets skip when the dir buffer's `b_mxfs_dir_incarn != 0 && != owner dir's live VFS i_generation` — a DEAD prior-incarnation ABA leftover at a reused daddr (the dir inode was rm-rf'd+recreated, gen bumped). PROVEN (RULE 4, sess40 iter3): node1's xfsaild durably flushes block-0 (daddr 120) carrying `bufincarn=1517736483` over the live `gen=2642423927` → readdir short (node1_f1..f13 lost, lookup_fail=0); P29-DATAWRITE CLOBBER detector confirmed it but didn't prevent. The read-path ABA bypass (`xfs_da_btree.c:3484`) catches it on READ but xfsaild writeback never reads, so it slipped. The pal side adds the always-on (ratelimited) `P40-INCARN-ABA-DIRSKIP` log when the skip fires + extends `P16-DIRBLK-SUBMIT` with `aba/bincarn/cincarn`. **Backed by modify-time + init-time incarn stamps** (`mxfs_dir_data_track`, `xfs_dir3_data_init`) so a current-incarnation block ALWAYS carries the live gen → no false-skip of legit current work; the `incarn != 0` guard spares unstamped-fresh blocks. Distinct from the leaf-clobber guard (that keys on `b_mxfs_dir_gen` tenure; this keys on `b_mxfs_dir_incarn` incarnation) and from the REFUTED sess39 inode-cluster fence (that was `xfs_inode.c` merge_dirs). NOTE: does NOT address Bug B (AG free-space double-alloc → file data over inode cluster → EFSCORRUPTED). See ccmemory `sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E`.
- **`P-DATACLOBBER-SKIP` — dir DATA-block TENURE-gated clobber WRITE-GUARD (sess41, build AF02E775, the FIX for dir_reuse_coherency 2/tcp Bug A):** the DATA/BLOCK-block analogue of the sess20 `mxfs_buf_leaf_clobber_skip` (which only covers leaf1/leafn). Inlined in `xfs_buf_submit_bio` (`pal/linux/xfs_buf.c`) right after the `mxfs.dirskip` block, reusing the `dsi` already filled by `mxfs_buf_xfsaild_skip_dir_write` (so `dsi.dir_gen = owner i_dlm_dir_gen`, `dsi.owner`, `dsi.in_core` cost nothing extra). New `mxfs.dataclobber` module param (`xfs/xfs_mxfs_dlm.c`): 0=off, 1=detect-only (log, still write), **2=enforce (DEFAULT)**. Discriminator is TENURE (`bp->b_mxfs_dir_gen < dsi.dir_gen`), the PROVEN token — NOT the sess40 `b_mxfs_dir_incarn` (ABA, refuted: fired 0× at production). FAST PATH (`bgen>=dir_gen`, or `bgen==0` fresh, or single-node) returns with NO disk read → a current-tenure modify (incl. legit dirent removal, which carries `bgen==dgen` re-stamped at read) is never considered, avoiding the count-compare false-positive. SLOW PATH only on the rare prior-tenure write: plain-bdev-read the coherent on-disk block, require valid DATA/BLOCK magic + same format (`bblk==dblk`) + `downer==dsi.owner`, fingerprint both via `mxfs_dir3_data_fingerprint`, and skip (emulate clean ioend) iff `disk_cnt > buf_cnt` — the buffer would erase peer-committed dirents. WHY the existing read-time tenure invalidation (`xfs_da_btree.c:3084+`) misses it: that path uses XBF_TRYLOCK + dirty/pin/in-AIL guards, so a stale **dirty** block slips past and xfsaild flushes it; this write-side guard closes that gap. Always-on ratelimited `P-DATACLOBBER-SKIP` log. See ccmemory `sess41-FIX-tenure-gated-dataclobber-guard-AF02E775`.

- **sess69 — PROVEN TRUE ROOT of dir_reuse_coherency 4/tcp loss = cross-node STALE READ-CACHE HIT (the write side is downstream).** Using `P-DIRRD` (read crc+fua; needs `dirwr>=2`) + `P-DIRWR` (write crc+count), merged across all nodes by `realns` and mapping read-crc→write-count: **every stale read of the shared dir block (daddr 120) was `fua=0` AND cross-node** — a peer durably advanced the block, but this node's non-FUA read returned its OWN older cached `XBF_DONE` buffer (a local cache HIT that never re-fetched). That re-validates the stale buffer, poisoning the base for the next fast-path RMW, which durably drops the peer's entry. Layer implications: (1) **FUA cannot fix it** — a cache HIT never issues a disk read, so `fua_disable`/`mxfs_pal_*_fua*` are irrelevant; the buffer must be INVALIDATED to force a miss. (2) The clobbering WRITE is byte-identical to a legit `rm` removal (`in_ail=1 bdirty=0 pin=0 real_mode=EX buf_cnt=disk_cnt-1`), so **NO write-side chokepoint guard can distinguish clobber from legit removal**; `mxfs.dataclobber=2` ENFORCE re-tested sess69 = CATASTROPHIC (suppresses legit removals → readdir=0/400 empty dir). The doc's sess41 entry says dataclobber "DEFAULT 2" but the CODE is `int mxfs_dataclobber; /* default 0 */` (reverted) — **keep it 0; never ship dataclobber>=2 or dirskip=1.** (3) This CORRECTS the sess17 note below ("loss at INSERT time, not a reflush") — the base was poisoned by an earlier read-side stale hit. Fix belongs on the READ/invalidation side (reliable invalidate-on-loss-of-writer-exclusion), NOT the write side. See ccmemory `sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base`, `sess69-FIX-caveat-evict-on-release-refuted-thread-the-needle`.
- **sess69 — probe changes (all `dirwr`-gated, inert at production `dirwr=0`):** `P-WRACT` cap raised 3000→2,000,000 (block-0 churn exhausted 3000 before the dir grew to leaf-format, hiding later blocks). `P-DATACLOBBER-SKIP` extended with `real_mode`/`in_txn`/`in_ail`/`bdirty`/`pin`/`bflags`. CRITICAL: use the mode-aware `mxfs_v5_dlm_inode_held_rawmode` (returns EX=5/PR=3/NL=0), NOT `mxfs_v5_dlm_inode_held` which returns 1 for PR too (sess42) and cannot confirm EX — `_rawmode` proved the clobber holds genuine EX (non-owner-flush hypothesis refuted).

- **sess12 (ccloop) — `dir_ex_write_guard` EX-gated dir-write skip (xfs_buf.c submit chokepoint, default ON, build B5FB078A+):** new param `mxfs_dir_ex_write_guard` (`xfs/xfs_mxfs_dlm.c`). In the sess41 `xfs_buf_submit_bio` dir-write guard block, a dir DATA/LEAF write submitted while this node does NOT hold the dir DLM EX (`!dsi.in_core || dsi.mode != MXFS_LOCK_EX`) is treated as a superseded prior-tenure image: coherently plain-read the on-disk block and SKIP the write iff disk PROVES strictly-more/divergent dirents (logs `P12-DIR-EXGUARD-SKIP`). Distinct from the REFUTED `dataclobber>=2`: it never inspects EX-held writes, so it CANNOT suppress a legit removal/conversion/fresh-leaf (all run under EX) — avoiding the sess69 "keeps the ghost"/readdir=0 catastrophe; the release drain is synchronous-while-EX so it's never caught either. **CAVEAT (sess69, READ FIRST): the PROVEN true root of dir_reuse loss is a cross-node STALE READ-CACHE HIT poisoning the RMW base — the fix belongs on the READ/INVALIDATION side, not the write side.** This EX-guard is a narrow backstop only; it fired 0× on the dominant single-dirent-loss vector (those clobbering writes hold genuine EX, so it correctly does not touch them). KEEP but do not expect it to meet the criterion. The SHORTFORM sibling fix `mxfs_dir_rebase_shortform` (param `dir_sf_rebase`) also fired 0×. Dominant remaining vector = intra-create single-dirent revert: a peer `MXFS_EVICT_TYPE_DIR_MODIFY` BAST (xfs_mxfs_dlm.c:14430) bumps `i_dlm_dir_gen` + arms `MXFS_IF_DIR_RELOAD` mid-create; the create thread's own next read consumes it and reverts the just-added dirent. See ccmemory `sess12run-*`.

- **sess22 (ccloop) — `dir_stale_incarn_skip` EX-HELD stale-write skip: REFUTED, default 0 (INERT), do NOT enable.** New param `mxfs_dir_stale_incarn_skip` (`xfs/xfs_mxfs_dlm.c`) added to the SAME `xfs_buf_submit_bio` clobber-guard block (`pal/linux/xfs_buf.c`). It extends the guard to ALSO fire for an EX-HOLDER when the dir DATA/LEAF buffer is `dc_stale` (`b_mxfs_dir_gen < dsi.dir_gen`, prior-tenure base) AND same-incarnation (`dsi.buf_incarn == dsi.cur_incarn`, to dodge the rm-rf ghost) AND the existing disk-proven content fingerprint diverges → skip the write. **PROVEN CATASTROPHIC at `=1` (8/tcp dir_reuse): readdir 474/800, leaf-hash lookup_fail 124, 4-of-8-node SHUTDOWN.** `dc_stale && same_incarn && content-divergent` is STILL not a sufficient discriminator — it suppresses LEGIT dir writes (the sess23 [[sess23-ccloop-suppression-was-corruptor-3of4]] "suppression is the corruptor" trap, re-confirmed). Reverted to default 0; code paths inert, keeper (`D589FA5F`) functionally unchanged. **STANDING LESSON (now quadruple-proven: dataclobber>=2 sess11/69, dir_ex_write_guard EX-variant, dir_stale_incarn_skip sess22): NO write-side chokepoint guard can safely suppress a dir-block write — a stale-base clobber is indistinguishable from a legit write at submit time. The `readdir=799` fix MUST be READ-SIDE: force-evict + FUA-re-read any prior-tenure (`bgen<dir_gen`) CLEAN dir-fork block (data+leaf+freeindex) on EX (re)acquire/modify so the holder never RMWs a stale base** (re-target the sess41 `mxfs_dirrefresh` evict-refresh from its count-based gate to any `dc_stale` block). Also added (harmless, KEEP) a Layer-3 free-slot guard in `xfs/libxfs/xfs_dir2_node.c` `xfs_dir2_node_addname_int` (converts the upstream debug-only `ASSERT(bf[0].length>=length)` into a repair-summary-and-restart) — fired 0×, so the loss is NOT an addname-time freeindex double-alloc. See ccmemory `sess22-REFUTED-exheld-stale-write-suppression-harmful`, `sess22-freeslot-guard-0x-loss-is-postadd-stale-destage`.

- **sess25 (ccloop) — `mxfs_dir_ail_push_defer` AIL-deferral hook in `xfs_buf_item.c` iop_push: REFUTED, default OFF (`mxfs.dir_ail_defer=0`), do NOT enable.** New call in `xfs_buf_item_push` (`pal/linux/xfs_buf_item.c`, just before `trace_xfs_buf_item_push`): `if (mxfs_dir_ail_push_defer(bp)) { xfs_buf_unlock(bp); return XFS_ITEM_LOCKED; }` — keeps a contended multi-node dir DATA/LEAF BLI in the AIL with NO I/O (not staled, not fake-ioend'd) so the block's on-disk image would change ONLY via the EX holder's release-drain (GPT-5.5 GFS2-invariant design). Helper + param in `xfs/xfs_mxfs_dlm.c`; gate = owner dir in-core + `i_dlm_mode==EX` + (`i_dlm_dir_gen!=0 || i_dlm_dir_contended`) (sticky flag set on any dir BAST in `bast_notify`). **PROVEN HARMFUL (do not ship on):** (1) it WITHHOLDS background writes the release-drain does NOT reliably make up → 4/tcp dir_reuse round14 lost node2's WHOLE 49-file md5 batch (readdir=351/400); (2) deferred blocks pin the AIL/log tail → EX holder can't release promptly → peer DLM acquire times out 184s → SHUTDOWN_CORRUPT_INCORE (8/tcp); (3) it breaks `sync`-while-holding-EX semantics — the app syncs+barriers mid-tenure but data only lands at EX release. This is the same WRITE-SIDE family the STANDING LESSON forbids (the fix must be READ-SIDE invalidate-on-acquire). Default 0 → `xfs_buf_item_push` is upstream behavior. Also added (default 0, probe) `mxfs_dir_relverify` + `mxfs_dir_data_release_verify` (xfs_mxfs_dlm.c): at the EX release fence plain-reads each dir DATA block and compares fingerprint to in-core; PROVED the release does NOT hand off harmful stale blocks (all `P25-RELVERIFY-MISMATCH` are `done=0` = evict-pending-refetch, benign) → Inv-1 RELEASE holds; the loss is a MODIFY-time stale-base RMW. See ccmemory `sess25-FIX-ail-defer-...`, `sess25-DECISIVE-exheld-stale-cached-dirblock-subset-of-disk`.

- **sess26 (ccloop) — `xfs_buf.c`: 1 new helper + 2 gated default-0 levers, ALL refuted, build keeper-equivalent (`CA135E9C`).** Three additions to `pal/linux/xfs_buf.c`, all INERT at default (no modargs == keeper; 1/2/4 tcp unaffected):
  - **`mxfs_dir3_disk_has_extra_inum()`** (after `mxfs_dir3_data_fingerprint`): the REAL dirent subset test sess25 asked for — returns the count of on-disk dir3-data inumbers ABSENT from an in-core block (0 = in-core is a superset = safe to write). Bounded O(n·m), 256-inum cap (overflow ⇒ inconclusive ⇒ returns 0, never false-skips). **sess32: NON-static (was static) + no header decl — callers `extern`-declare it.** Now also called cross-file by `xfs/xfs_mxfs_dlm.c::mxfs_dir_postrmw_probe()` (the A-vs-B probe) and the P-WMERGE destage detector here. Reusable comparator for dir-block divergence.
  - **`mxfs_buf_read_fua` FUA-refresh exception (param `dir_fua_refresh_destaged`, default 0):** before the P91-FUA-SKIP-LOGGED skip, if the buf is a dir3 DATA/BLOCK block (NEVER leaf — leaf refresh vs a stale extent map ⇒ `XFS_DABUF_MAP_HOLE` shutdown ×140, sess20 family) AND DESTAGED (`pin==0 && b_mxfs_logged_seq==b_mxfs_written_seq`), `goto do_fua_read` to pierce instead of keeping the in-core image. REFUTED: P26-FUAREFRESH fired 8000× (reads ARE fresh) yet loss PERSISTS → **the dir_reuse lost-update is NOT a read-side stale base.** pin/undestaged still hard-skip (protects un-checkpointed work, the sess90 bnobt concern).
  - **Subset-guard write-skip (param `dir_subset_guard`, default 0):** in the `xfs_buf_submit_bio` dir-write chokepoint, for a CLEAN (`!p69_dirty`) in-AIL (`p69_inail`) xfsaild push of a dc_data block, same-incarnation, if `mxfs_dir3_disk_has_extra_inum>0` → suppress + mark-for-read-refresh. **PITFALL: must keep `XBF_DONE` SET before `xfs_buf_ioend` (it completes a WRITE); the v1 that CLEARED XBF_DONE corrupted buffer/AIL state → barrier-timeout abort at 110s.** Even with that fixed, REFUTED: a plain-read of disk at bio-submit RACES the peer's in-flight state ⇒ false-positive-suppresses LEGIT writes ⇒ `readdir=0` on a peer (the sess16/sess23 "suppression is the corruptor" / "write-side disk-compare is racy" class).
  - **NET (sess26 PIVOTAL, recorded ccmemory `sess26-PIVOTAL-...`, `sess26-subset-guard-refuted-...`):** read-side (FUA-pierce-all-reads) still loses AND write-side async suppression corrupts ⇒ the fix is NEITHER async chokepoint; it must be the SYNCHRONOUS RELEASE FENCE — `xfs_buf_stale` the clean drained dir buffers at EX release to drop the lingering BLI so xfsaild can't re-push them in a later tenure (the P126/P60 pattern at `xfs_buf_item.c:608/638`). Sibling inert levers this session: `dir_modify_target_flush` (SYNC-CACHE before RMW read — refuted FUA-platter-lag) and `dir_newtenure_evict` + field `i_dlm_dir_evict_mep` (xfs_inode.h — readdir=0, clearing XBF_DONE on in-AIL-undestaged corrupts).

- **sess28(ccloop) — `P-WMERGE` write-classifier (xfs_buf.c `xfs_buf_submit_bio`, gated `mxfs.dir_writeprobe`, default 0) + refined `dir_subset_guard`:** for every multinode dir3 DATA/block write, FUA-reads the target daddr and reports `disk_extra` (on-disk inumbers the in-core write LACKS = peer adds we'd revert) AND `incore_extra` (in-core inumbers absent on disk = our own new adds), plus `held_mode`/`in_ail`/`dirty`/`bgen`. **DECISIVELY localized the dir_reuse 8/tcp loss (RULE 4, from saved `/root/drc_failverify_*.dmesg` which survives ring rotation):** every clobbering write is `held_mode=5(EX) in_ail=1 dirty=0 bgen=0` and **MERGE-NEEDED** (`disk_extra>=1 AND incore_extra=1`; one was `disk_extra=154`). = the dir EX HOLDER destages a STALE in-AIL block (committed in tenure T1, base went stale because the holder RELEASED, a peer added B in T2, the holder RE-ACQUIRED) carrying its own add A on a base missing B → overwrites disk(base+B) → peer's B durably LOST. The read was coherent at addname (`diff1=0`); the staleness is in the *in-AIL base between commit and destage*. `ex_guard`/`P12` miss it (gated on dir-NOT-held-EX, but the holder HOLDS EX); `drain_evict` KEEPS in-AIL-undestaged blocks. **Refined `dir_subset_guard` (default 0):** added an `incore_extra==0` gate to P26-SUBSET-SKIP (only suppress a PURE-STALE subset rewrite, never a merge-needed write) — but STILL REFUTED: `subset_guard=1` full = catastrophic readdir=316 (drops legit merge-needed); pure-stale-only = SHUTDOWN (structurally unsafe, a legit remove also looks pure-stale). **STANDING LESSON re-confirmed: no drop-suppression works.** The correct fix (next session) = re-apply the holder's in-AIL delta onto the CURRENT disk base (3-way merge) at REACQUIRE (transaction context, so the leaf/freeindex hash blocks update too — a data-only graft leaves lookup_fail). Companion read-side lever `dir_addname_coherent` (xfs_dir2_data.c `mxfs_dir_addname_coherent_refresh`, default 0) ENGAGES safely but does NOT fix (read is coherent). New inert `xfs_buf` field `b_mxfs_coherent_gen`. Tooling: `tests/tcp/drc_one.sh` (EXTRA=modargs). **INFRA PITFALL: a background test driver SURVIVES `pkill -f <name>` and keeps spawning run.sh → two drivers mkfs the same LUN = false read-divergence/false 0/8 cascades; kill the driver PID explicitly + verify 0.** See ccmemory `sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded`, `sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0`, `sess28-HANDOFF-head-build-C1B4BFC0-next-step-3way-merge`.

- **sess29(ccloop) — `xfs_buf.c` write-side 3-way merge `mxfs_dir3_data_writemerge` + `mxfs_dir3_data_graft_one` (gated `mxfs.dir_write_merge`, default 0): ABANDONED, do NOT enable.** Called from `xfs_buf_submit` BEFORE `xfs_buf_verify_write` (so freescan-rebuilt bestfree + grafted dirents are covered by the CRC the verifier stamps). For a MERGE-NEEDED dir3_data destage (both images diverge by NAME — dedup by NAME not inumber, since rm+recreate reuses names with fresh inodes), it reads the current on-disk image (PLAIN read, NOT FUA — FUA reads the lagging platter and tears → phantom graft) and grafts the disk's name-unique dirents into the in-core block via a free-slot carve + `xfs_dir2_data_freescan`. **REFUTED: produces cross-block DUPLICATE names (readdir 801/802 over-count)** — the chokepoint sees only ONE block and can't verify global name-uniqueness across the dir's other data blocks. The read-side `dir_release_invalidate` + the NEW `dir_relinval_clean` levers (xfs_mxfs_dlm.c) are strictly better (got dir_reuse 8/tcp ~0%→~85%). Logs `P-WMERGE2`. Inert at default (whole helper is `if (!mxfs_dir_write_merge) return 0`; 1/2/4 tcp + keeper unaffected). **PITFALL re-confirmed (STANDING write-side lesson):** non-transactional dir-block byte surgery at the bio chokepoint cannot maintain dir invariants (cross-block name uniqueness, leaf hash, log redo) — the robust fix is read-side invalidate-on-release or a transactional re-apply. See ccmemory `sess29-CORRECTED-state-dir_reuse-85pct-not-100-flush-lockwait-harmful`, `sess29-HEAD-handoff-dir_reuse-solved-standalone-fullsuite-env-blocked`.

- **sess30(ccloop) — `xfs_buf_verify_write` ops-recover (NEW, default-ON, KEEP, build 04A615EE+):** `mxfs_buf_ops_from_magic(bp)` (static, just above `xfs_buf_verify_write` in `pal/linux/xfs_buf.c`) maps an on-disk block magic → the correct `xfs_*_buf_ops` (AGI/AGF/AGFL/inode/bnobt/cntbt/inobt/finobt/bmbt/dir3-block/data/free). When `xfs_buf_verify_write` finds `b_ops==NULL` on a CRC fs (a cached metadata buffer reached the write path with its verifier dropped — PROVEN: an mxfs reload/FUA path leaves an inode-cluster buffer `b_ops==NULL`, xfsaild delwri-flushes it), it re-derives ops and runs `verify_write` so the **CRC is recomputed** instead of writing an un-CRC'd block (the OLD code did `xfs_warn`+`xfs_hex_dump`+`dump_stack` then wrote it anyway). Logs `P30-OPS-RECOVER` (capped 400). **WHY IT MATTERS:** harmless for inodes (di_crc stamped at iflush) but the `dump_stack` tripped soak's `call trace` DPAT → **soak FAIL; this fix took 4/tcp 16/17→17/17.** Also a defensive guard against an un-CRC'd AG-meta write. NOTE: does NOT fix WHERE b_ops is dropped (an unidentified mxfs reload/FUA path) — it's a write-time backstop. See ccmemory `sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover`.

- **sess15(ccloop) — `P15-DIRFUA` FUA-read perf probe (xfs_buf.c FUA gate, gated `mxfs.dir_perf_probe`, default 0):** in the `xfs_buf_submit_bio` FUA gate (right after `mxfs_fua_count`, before/around `mxfs_buf_read_fua`), for dir-class buffers only, logs `daddr/owner/ops/rc/fresh_after/in_ail` (owner read from the dir3 blk header or da3 leaf blkinfo). Built to diagnose the 8/tcp dir_reuse SLOWNESS: PROVED the hot shared-dir block 0 (daddr=120, owner=test-dir ino 131) is FUA-re-read on nearly every lookup under 8-node contention (each read sets `_XBF_FUA_FRESH` but a subsequent gen-invalidation clears it). NOTE this is a SECONDARY effect — the dominant 8/tcp cost is TCP-DLM acquire starvation (`P36-RETRY`, dlm/dlm.c), NOT the FUA reads (`fua_disable=1` did not fix the slowness). Inert at default; safe to leave. See ccmemory `sess15run-UNIFYING-both-8tcp-blockers-are-tcp-dlm-acquire-starvation`.

- **sess5 (ccloop a864) — durable-signal bwrite LOST-WAKEUP + `P-IOWAIT-STUCK` probe (xfs_buf.c `xfs_buf_iowait`, NEW, always-on ratelimited, build 0349484E / v0.10.51, KEEP as diagnostic):** `xfs_buf_iowait`'s bare `wait_for_completion(&bp->b_iowait)` is now a `while (!wait_for_completion_timeout(&bp->b_iowait, 4s))` loop that logs `daddr/ops/flags/err/wr_counted/lseq/wseq/done/dir_inflight/rd/wr` every 4s of stall. Same blocking semantics (still waits until done); fires only on an abnormal >4s I/O stall so it stays dmesg-clean under healthy load. **WHY: one head of the dir_reuse@32/caw failure (wedge#2a) is a durable-signal `xfs_bwrite` that hangs in `xfs_buf_iowait` FOREVER with device `inflight=0` on ALL paths (dm-1/sda/sdb).** Stack: `xfs_buf_iowait ← xfs_bwrite ← mxfs_dir_bmbt_scan`/`mxfs_dir_data_owner_scan` (flush arm, `xfs/xfs_mxfs_dlm.c`) ← `mxfs_dir_flush_data_blocks` ← `mxfs_dlm_dir_durable_signal` (fires on EVERY create/unlink, `xfs/xfs_inode.c:2195/4326`) ← `xfs_remove`/`xfs_create`. inflight=0 = the bio was NEVER submitted OR its completion was lost — NOT an I/O stall (multipath healthy, zero SCSI/iSCSI errors) and NOT the sess4 multi-party AIL-jam (LONE task in D-state, xfsaild running, no bast kworkers stuck). Intermittent: owner_scan writes SUCCEED seconds before, so it's a RACE. **SUSPECT PATH in `xfs_buf_submit`:** `reinit_completion(&bp->b_iowait)` (~L5381, sync-only, "drain a stale token") runs BEFORE the real-bio-vs-skip-emulate decision; the skip-emulate returns (~L6867/6922/7141/7382/7454) all call `xfs_buf_ioend` which completes b_iowait — UNLESS `__xfs_buf_ioend` returns false (the error-retry branch ~L1667, no complete). Counted dir-write bios inc/dec `mp->m_mxfs_dir_wr_inflight` and wake "exactly once" at `__xfs_buf_ioend` (~L1433); a lost dec/wake there is the hang. **NEXT: on a repro that HITS wedge#2a (non-deterministic — a run may instead hit wedge#3 acquire-starvation or the reproducible hard-hang), grep `P-IOWAIT-STUCK` on rank1: `wr_counted=0` ⇒ no bio issued (skip-emulate no-complete); `wr_counted=1 && dir_inflight>0` ⇒ counted bio's completion lost.** The durable signal is LOAD-BEARING (unpins the dir buf so the next modify re-reads fresh instead of RMW-clobbering a peer — the `P-COUNTREGRESS` lost-update), so the fix must repair the completion, NOT skip the flush. See ccmemory `AAA-ccloopa864-sess5-WEDGE2-FRESH-bmbt-inflight0-lostwakeup`, `AAA-ccloopa864-sess5-COMPREHENSIVE-STATE-multihead-wedges`.

- **sess6 (ccloop a864) — ROOT FIX for wedge#2a: `b_mxfs_sync_wait` completion-routing (xfs_buf.c, build 7647E2C4 / v0.10.52).** RULE-4 PROVEN root of the sess5 lost-wakeup: the completion routers (`xfs_buf_ioend` L1698, `xfs_buf_bio_end_io` L1829) decide `complete(&b_iowait)` vs `relse`/`queue_work` off the **LIVE, non-atomically-shared `XBF_ASYNC` bit**. `XBF_ASYNC` is SET by readahead (L987), xfsaild delwri (L8097), buf-item unpin-remove (`xfs_buf_item.c:554`), inode-cluster-flush-fail (`xfs_inode.c:6622`). When one leaves it set at completion of `mxfs_dir_data_owner_scan`'s sync durable `xfs_bwrite` (which cleared it at submit, `xfs_bwrite:1762`), the completion routes ASYNC → `complete(&b_iowait)` is SKIPPED → the per-unlink durable-signal `rm` hangs forever in `xfs_buf_iowait` → the whole dir_reuse@32 round wedges (P-IOWAIT-STUCK captured live: `flags=0x30`=ASYNC|DONE, `wr_counted=0`, `done=0`, `lseq==wseq` ⇒ a completion DID run but routed away). Also a double-relse/unlock hazard. **FIX:** new `bool b_mxfs_sync_wait` (`xfs/xfs_buf.h`) snapshotted `= !(b_flags & XBF_ASYNC)` at `xfs_buf_submit` entry (under b_sema, every submit); both routers now `if ((b_flags & XBF_ASYNC) && b_mxfs_sync_wait) complete(&b_iowait)` — a sync submitter is ALWAYS woken regardless of a spurious ASYNC flip, and never double-relse'd. `P-SYNCWAIT-OVERRIDE` marker (both paths) proves it fires. See ccmemory `AAA-ccloopa864-sess6-ROOT-wedge2a-async-completion-routing`. (STATUS: under test on dir_reuse@32/caw at time of writing.)

- **sess32 — `mxfs_dir3_disk_has_extra_inum` un-static'd (only `xfs_buf.c` change this session); fix is NOT in this subsystem.** Un-static'd the comparator (above) so `xfs/xfs_mxfs_dlm.c::mxfs_dir_postrmw_probe()` can reuse it. That probe (gated `mxfs.dir_postrmw_probe`, default 0) runs right after `xfs_dir_create_child` and computes `disk_extra` on the in-core block. **DECISIVE RESULT (PROVEN on a losing 8/tcp iter, RULE 4): P-POSTRMW stale-base = 0 on ALL 8 nodes while P-WMERGE MERGE-NEEDED fires 3-6×/node** → the dir_reuse loss is the **async-destage-AFTER-RELEASE TOCTOU**: the in-core dir block is ALWAYS a fresh superset at addname time; it goes stale only AFTER EX release (the buffer-log-item LINGERS in the AIL — `xfs_bwrite` does NOT retire the BLI), and xfsaild RE-FLUSHES that stale image after a peer supersedes the on-disk block → reverts the peer's add (mutual ping-pong). **So the P-WMERGE chokepoint here is purely a DETECTOR — the fix is NOT a write-side suppression/merge at this chokepoint (all refuted: 798 regression, bnobt corruption, readdir=0). The fix is RELEASE-side in `xfs/xfs_mxfs_dlm.c`: retire the dir data/leaf/free BLIs from the AIL at EX release (push+wait) so no stale buffer can be re-flushed.** Deadlock-careful (RULE 2). See ccmemory `sess32-DECISIVE-A-vs-B-late-destage-toctou`, `sess32-HEAD-handoff`.

- **sess33 (ccloop) — diagnostics + refuted write-side guards in `xfs_buf.c`/`xfs_buf_item.c`; build keeper-equiv (`275EF4D4`, ALL new params default 0).** Changes:
  - **`mxfs_dir_canonical_buf_ptr()`** (new, `xfs_buf.c`, after `xfs_buftarg_buf_cache`): RCU-only rhashtable lookup returning the canonical xfs_buf for a daddr WITHOUT lock/hold (pointer compare only). Used by the **P-WGHOST** probe in the `P-WMERGE` block to test ghost vs canonical. **RESULT: P-WGHOST=0 — the loss-write IS the canonical buffer (sess32 mechanism B / duplicate-buffer REFUTED; the "8 bp pointers" was a heavy-probe artifact).**
  - **`P-WMERGE` extended** to log `DONE/fua_fresh/delwri/comm` + a capped **`P-WMERGE-STACK`** `dump_stack()`. **DECISIVE: the dir_reuse readdir=799 loss-write is the EX-RELEASE FENCE DRAIN's `xfs_bwrite`** (`mxfs_dir_flush_one_daddr → xfs_bwrite → xfs_buf_submit_bio`, comm=dd) of a STALE BASE (`disk_extra=1` = our in-core block lacks a peer's prior-tenure add). Note `xfs_buf_submit` does NOT clear XBF_DONE for writes (verified), so `DONE=0` at the bio site is a real acquire-evict invalidation signal.
  - **`mxfs_dir_reflush_skip` (param, default 0, REFUTED) + `P33-REFLUSH-SKIP`** in the `xfs_buf_submit` dir-skip block: write-suppression of a `!DONE`+clean+destaged dir buffer → CATASTROPHIC (readdir=0, drops legit writes). Re-confirms the STANDING LESSON: no write-side drop-suppression works.
  - **`mxfs_dir_zombie_push_retire()` (new helper) + `dir_zombie_push` (param, default 0) + `P33-PUSH-RETIRE`** in `xfs_buf_item.c::xfs_buf_item_push` (mirrors P126/P60): stale+retire a DONE=0 destaged in-AIL zombie at iop_push. **Fires 0× — the loss-write is the release drain in user (dd) ctx, NOT xfsaild iop_push.**
  - All write/push-side retires fire 0× or are harmful. **The fix is NOT in this subsystem** — it's the acquire-side stale-base refresh in `xfs/` (see ccmemory `sess33-HEAD-handoff`, `sess33-union-merge-ambiguous-acquire-refresh-is-root`). Write/drain-side union-merge is fundamentally ambiguous under dir_reuse's concurrent add+remove (a disk-only dirent = peer ADD vs our REMOVE, indistinguishable by name).

- **sess34 (ccloop) — `mxfs_dir3_data_drain_merge()` (NEW, `xfs_buf.c`, non-static) RESOLVES the sess33 ambiguity with a per-tenure removed-set.** The sess33 wall ("a disk-only dirent = peer ADD vs our REMOVE, indistinguishable by name") is broken by a *removed-set keyed by inumber* (`i_dlm_dir_removed` on the inode, populated in `xfs_dir_removename`; helpers `mxfs_dir_record_removed`/`mxfs_dir_was_removed`/`mxfs_dir_remset_valid` in `xfs/xfs_mxfs_dlm.c`). The merge runs at the PROVEN loss site — `mxfs_dir_flush_one_daddr` immediately BEFORE the release `xfs_bwrite` (NOT the async bio chokepoint; the dir inode `dp` is available there for the removed-set). For each disk-only-by-name dirent it grafts (via `mxfs_dir3_data_graft_one` + `xfs_dir2_data_freescan`) ONLY when its inumber is NOT in this tenure's removed-set = a genuine peer add, never our own pending remove. This is why the old `dir_write_merge` over-grafted to 803 (it resurrected our removes); the filter is the fix. DATA blocks only. Param `dir_drain_merge` (default 0). Probe `P34-DRAINEPOCH` (flush site) PROVED the loss-block is **current-tenure** (`b_epoch==valid_epoch`, undestaged, comm=rm) — refuting the epoch-skip approach (`dir_drain_epoch_skip`, also default 0) and confirming the discriminator must be provenance (removed-set), not flags. Grafted dirents land in the DATA block but not the LEAF hash → relies on sess22 datascan-heal for name lookups; readdir (data-scan) counts them correctly. **Status: built (`8F1E17A0`), under validation.**

- **sess37 (ccloop) — `dir_tenure_reflush_skip` write-skip in `xfs_buf.c`: REFUTED (both forms), default 0 (INERT), do NOT enable.** New param `mxfs_dir_tenure_reflush_skip` (`xfs/xfs_mxfs_dlm.c`) + a new arm in `mxfs_buf_xfsaild_skip_dir_write` (sets `info->tenure_reflush`) enforced in the `xfs_buf_submit_bio` dir-skip block (parallel to `reflush_enf`, logs `P37-TENURE-REFLUSH-SKIP`). Intent: skip an xfsaild reflush of a CLEAN, already-DESTAGED (`!mxfs_dir_buf_is_undestaged`), in-AIL dir buffer (a "zombie BLI" whose content is already on disk so re-writing can only revert a peer's later write). **REFUTED twice:** v1 (gated `bgen<dir_gen`, ALL buffer types) fired only 2× (the 8/tcp loss buffer is gen-CURRENT `bgen==dir_gen`, not prior-tenure) AND skipping LEAF/NODE index blocks → `XFS_DABUF_MAP_HOLE_OK` corruption (never skip leaf/node/free — breaks the da-btree mapping); v2 (DATA/BLOCK only, no gen gate, clean+destaged) → CATASTROPHIC `readdir=0/800` round1, P37=1920× (the `destaged` lseq==wseq predicate is NOT a reliable "content already durable" signal at the xfsaild push point — it drops writes the dir needs to persist). **Re-confirms the STANDING LESSON a 5th way: write-side suppression of dir DATA buffers is categorically the corruptor.** Inert at default → build keeper-equivalent. The two enforce sites added (`tenure_enf`) are no-ops when the param is 0. See ccmemory `sess37-HEAD-handoff`, `sess37-residual-is-equal-count-content-divergence-xfsaild-leaf`.
  - **sess37 fresh ground-truth (dataclobber=1 detect):** the daddr=120 `comm=rm disk_cnt=buf_cnt+1` clobbers are FALSE POSITIVES (legit rm-teardown removal lag — this is why `dataclobber>=2` enforce was catastrophic). The REAL residual loss (best config = read-side stack `dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1 dir_addname_platter_guard=2`, which gets ~50%/fails ~round20) is a GENUINE-EX-holder (`real_mode=5`, 1890 events vs 2 stale-cached-EX) **equal-count content-divergent** (`buf_cnt==disk_cnt`, `ds!=bs`, `bgen==dirgen`, `sameincarn`) background reflush — blind to all count/gen/incarn/cached-mode guards. Points to a DLM cross-master double-grant (single-master `mxfs_dlm_audit_double_grant` can't see it) or read-served-stale-on-acquire. Next: cross-node DLM holder dump at the clobber to settle it; then DLM demote-before-grant serialization OR GPT's owner-checkpoint (defer-not-drop).

- **sess38 (ccloop) — `dump_stack()` on data-clobber in `xfs_buf.c` (diagnostic only, ≤6 dumps, `dataclobber=1` path).** Added right after the `P-DATACLOBBER-SKIP` pr_warn in `xfs_buf_submit_bio`: when a dir DATA block write is detected clobbering a disk superset, dump the stack (capped). Confirmed the losing write is `xfs_buf_submit`/`xfs_buf_submit_bio` background AIL push (comm=xfsaild), not an active modify. No behavior change (only fires under `dataclobber=1`, a detect-only param). **DECISIVE sess38 measurement:** the 8/tcp readdir=799 losing write is `kind=data daddr=120(block0) buf_cnt=N disk_cnt=N+1 bgen==dirgen stale=0 in_ail=1 dirty=0 in_txn=0 comm=xfsaild`, buffer a STRICT SUBSET of disk = a ZOMBIE in_ail buffer surviving the EX handoff, reflushed over a peer's durable +1. Gen mechanism BLIND (bgen==dirgen). **ENV PITFALL:** `MXFS_EXTRA_MODARGS` → `insmod`, needs the BARE param name (`dataclobber=1`, NOT `mxfs.dataclobber=1` — the prefix is silently ignored → param stays 0 → probe inert). Verify `cat /sys/module/mxfs/parameters/<p>`. The fix is NOT in this subsystem (release-side = `xfs/xfs_mxfs_dlm.c`); write-side suppression re-refuted (`dir_subset_guard=1` → shutdown). GPT-5.5 verdict + direction in ccmemory `sess38-GPT-architectural-fix-inail-survives-handoff-release-retire-genbump`, `sess38-DECISIVE-clobber-is-inail-clean-nonstale-subset-genblind`, `sess38-HEAD-handoff`.

- **sess39 (ccloop) — `dir_refresh_inplace` REFRESH-in-place at the `xfs_buf_submit_bio` dir-write chokepoint: REFUTED, default 0 (INERT), do NOT enable.** New param `mxfs_dir_refresh_inplace` (`xfs/xfs_mxfs_dlm.c`; `extern` in `xfs_buf.c`) added as another trigger in the sess41 dir-clobber guard block (OR'd into the outer condition for `dc_data`). Unlike every prior refuted write-side fix (which DROP/SKIP/RETIRE → leave stale in-core or over-lose), this one tried to be non-lossy: when we hold the dir EX (`dsi.mode==EX`, so no peer is concurrently writing → the plain-bdev disk read `dco_tmp` is STABLE) and the on-disk image is a strict SUPERSET of a clean in-AIL buffer (`mxfs_dir3_disk_has_extra_inum`: disk has dirents we lack AND we have none disk lacks = pure stale-subset, no un-landed work), `memcpy(bp->b_addr, dco_tmp, dco_len)` + `XBF_DONE` + `xfs_buf_ioend` (no bio) — making in-core CORRECT and skipping the stale write. Logs `P39-REFRESH-INPLACE`. **REFUTED: round-1 `xfs_dir3_block_verify` metadata corruption (block 0x78).** A raw disk image is NOT a drop-in for the in-core buffer's verifier/CRC/log state — overwriting `b_addr` under a live BLI desyncs the buffer-log-item/CRC and trips the write verifier. **6th confirmation of the STANDING LESSON: no buffer-layer manipulation of a dir block at the bio chokepoint is safe** (skip/drop sess11/17/22/37/69, retire sess32/33, defer sess25 `dir_ail_defer`, now refresh sess39). Inert at default → keeper build unaffected. **The residual `readdir=799` zombie needs an ARCHITECTURAL fix (GPT write-authority token / write-through dir blocks), not this chokepoint.** Context: the sess39 KEEPER (`8CC09D97`) actually FIXED the CATASTROPHIC 8/tcp failures (membership split-brain) in `dlm/` — see `dlm.md` + ccmemory `sess39-ROOTFIX-membership-splitbrain-formation-and-flap`; this xfs_buf.c lever targets only the *remaining rare* zombie and failed.

- **sess40 (ccloop) — `xfs_buf.c` writeback-completion-barrier infra: REFUTED as a NO-OP, default OFF, infra retained.** Added to `xfs_buf_submit_bio` (after `mxfs_submit_partial_inode_write`): for a multi-node dir DATA/block/leaf1/leafn/free/da3_node WRITE, `atomic_inc(&bp->b_mount->m_mxfs_dir_wr_inflight)` + set `bp->b_mxfs_dir_wr_counted` (new `xfs_buf` field). `__xfs_buf_ioend` (top) decrements + clears (underflow-guarded). Backs `mxfs_dir_wr_barrier` (`xfs/xfs_mxfs_dlm.c`, **default 0**), which made the dir EX release fence wait for the counter to reach 0 before DLM unlock — intent (GPT-5.5): no prior-tenure in-flight dir bio lands after the next holder RMWs. **REFUTED: `P40-WRBARRIER` NEVER fired — the counter is ALWAYS 0 at release** because publish-before-notify already writes dir blocks SYNCHRONOUSLY (xfs_bwrite waits), so there are zero in-flight dir bios at handoff. The real root of `readdir=799` is NOT a buffer/bio issue — it's a **TCP DLM transport flap** dropping in-flight DLM control messages (fix in `dlm/peer.c`, see `dlm.md`). The inc/dec is cheap+harmless, kept as correct GFS2-style infra if an async dir-write path appears; `dir_wr_barrier` stays default 0. **7th** confirmation no buffer-layer chokepoint manipulation fixes the dir_reuse loss. See ccmemory `sess40-REFRAME-799-is-tcp-flap-not-buffer-barrier-noop`.

- **sess41 (ccloop) — `xfs_buf.c` dir-data write infra (all DEFAULT OFF, no-regression vs keeper).** (1) `mxfs_dir3_data_writemerge` (called from `xfs_buf_submit`, pre-CRC) extended with the removed-set-disambiguated graft (carries sess34 `mxfs_dir3_data_drain_merge` logic to the UNIVERSAL chokepoint via new helper `mxfs_dir_choke_merge_remset`), gated `dir_choke_merge` (**default 0 — PROVEN INERT**): probe `P-WMR-REACH` fires (disk≠in-core) but `disamb=0`/`dko=0` ALWAYS → **in-core ⊇ disk at every dir-data write**, so the loss is NOT a stale-base RMW. (2) `P-DLAND` in `__xfs_buf_ioend`: at I/O COMPLETION logs `daddr/owner/incarn/sum(FNV)/realns/comm` for dir3 data/leaf/block writes, gated `mxfs.dirland` (**default 0**) — landing-ORDER tool to prove the post-submit/REUSE write-ordering root (merge nodes by realns per daddr → which content version lands LAST). Caveat: kernel ring rotates over a 24-round run — use DRC_STREAM for a complete capture. The fix is release/free-side (drain by owner/incarnation incl FREED blocks; daddr-reuse fence), NOT this chokepoint. See ccmemory `sess41-PROVEN-799-is-post-submit-writeorder-not-stalebase-merge-dead`.

## Pitfalls

- **sess65 — `xfs_setattr_size` (xfs_iops.c) truncate-staleness guard does NOT work.** A tried-and-reverted fix added a FUA dinode-header read before `xfs_itruncate_extents` to catch a stale cached reg-file inode (the dir_reuse_coherency `do_truncate → xfs_free_ag_extent` bnobt double-free). It fired 0× and was removed: the staleness lives in the in-core **bmbt extent records (contents)**, not the dinode header — di_gen/di_mode/di_nextents/di_size all MATCH disk while the actual mapped blocks differ. A header-only FUA compare cannot detect it. (Superseded on the *incarnation* axis by the ccloop-4dd7 sess2 guard below — which checks the VFS mode class, a different and provable signal — but the extent-CONTENT staleness lesson still stands.)

## ccloop-4dd7 sess2 — `xfs_setattr_size` (xfs_iops.c) SETSIZE-REVALIDATE-MISS guard (KEEPER, PROVEN)

`xfs_setattr_size` now revalidates the inode's incarnation right after `xfs_ilock(ip, XFS_ILOCK_EXCL)` (which runs the mxfs DLM EX acquire + `mxfs_dlm_reload_inode`) and BEFORE `xfs_trans_ijoin`: if `!S_ISREG(VFS_I(ip)->i_mode)`, it cancels the still-clean transaction and returns **-ESTALE** (probe `SETSIZE-REVALIDATE-MISS`). Rationale (RULE-4 proven, ino 133/139 autopsies): the reload at that EX acquire can legitimately FLIP the inode to a peer's new incarnation (`P-RELOAD-TYPEFLIP` file→dir, or a `P116-ZOMBIE-ADOPT` free image with mode 0); proceeding walked a LOCAL-format dir fork in `__xfs_bunmapi` → `!xfs_ifork_has_extents` internal error → dirty `xfs_trans_cancel` → cluster-wide shutdown. `-ESTALE` is retried by `do_filp_open`/`do_sys_truncate` with `LOOKUP_REVAL`, so userspace sees a clean re-lookup, not an error. Mirrors `REMOVE-REVALIDATE-MISS` in `xfs/xfs_inode.c::xfs_remove`. Cross-subsystem: pairs with the xfs-side `IFREE-REVALIDATE-SKIP` (xfs_inactive_ifree) — both enforce "revalidate after any DLM re-acquire inside an op, before the transaction dirties". Firing + rescuing in live churn (v0.11.48+).

## sess18 (ccloop) — release-flush COALESCING state init (xfs_super.c)

`xfs_fs_fill_super` (`pal/linux/xfs_super.c`, right after `m_mxfs_inode_bast_wq = alloc_workqueue(...)`) now initializes three new `xfs_mount` fields (declared in `xfs/xfs_mount.h`): `atomic64_set(&mp->m_mxfs_flush_req, 0); atomic64_set(&mp->m_mxfs_flush_done, 0); mutex_init(&mp->m_mxfs_flush_lock);`. These back `mxfs_release_coalesced_flush(mp)` (in `xfs/xfs_mxfs_dlm.c`), which replaces the raw `blkdev_issue_flush(bt_bdev)` in the BAST-release drain (`mxfs_dlm_bast_process`) and the new NO_INODE BAST work fn. Purpose: under dir_reuse 8/tcp the rm/verify storm issues hundreds of device-serialized release flushes/round; coalescing lets concurrent releases share one `blkdev_issue_flush` (ticket: inc `flush_req` AFTER the writes are submitted, then either observe a completed flush already covered the ticket or issue one and advance `flush_done` to the snapshot). SAFE: may over-flush, never under-flush (the issued flush persists everything submitted before it returns ≥ the snapshot ticket). No PAL API change — uses the existing `bt_bdev`. Nothing to tear down (mutex not destroyed; matches the surrounding wq lifecycle, flushed at put_super).

## Historical Bugs

- **v0.3.130-135 sess31 CIL→AIL log_force timing:** PAL's mutex/cond_var primitives are correct; the bug was at the xfs layer (lazy_ag_drain + log_force throttle interactions). Diagnosis required PAL-level trace adds.
- **sess21 LIO FUA drop** (see above): the workaround lives in PAL.
- **sess19(ccloop) FUA-read cost accounting** (`pal/linux/xfs_buf.c`): `mxfs_buf_read_fua()` now bumps two always-on atomics — `mxfs_fua_scsi_actual` (real SCSI FUA READ(16) issued, the slow ~0.93ms/op path) and `mxfs_fua_p91_skip` (the P91-FUA-SKIP-LOGGED in-core return that does NO SCSI and does NOT set `_XBF_FUA_FRESH`). PROVEN this session: in the 8/tcp dir_reuse workload **99.99% of FUA gate-entries are real SCSI reads** (scsi=152304 vs p91skip=15 on rank1) — so the FUA gate count == actual SCSI latency, and the dir/inode block re-read thrash is genuine I/O cost. Counters surface in the always-on `FUA-COUNT` pr_warn (every 256) as `scsi=/p91skip=/oskip=/igstale=`. The `P15-DIRFUA` probe (gated on `dir_perf_probe`) now logs `comm=` for per-phase attribution. Pure instrumentation — no behavior change.

## Subdirectories

- `pal/linux/` — kernel + user (`pal_linux_kern.c` vs `pal_linux_user.c`)
- `pal/headers, common*.c` — shared bits

## sess42 (ccloop): written_seq stamp timing — submit vs completion (param `dir_wseq_at_completion`, default 0)

`xfs_buf.c` stamps `b_mxfs_written_seq = b_mxfs_logged_seq` for XBF_WRITE buffers; `mxfs_dir_buf_is_undestaged()` (logged!=written) is the cluster-wide "this dir block has un-landed local content" predicate used by the EX-release durability fence + evict logic.
- **OLD/default**: stamped in `xfs_buf_submit` (~line 4255) — at SUBMIT, so an in-flight (or skip-emulated, no-bio) dir-metadata write reports "destaged/durable" immediately.
- **sess42 fix (param `mxfs.dir_wseq_at_completion=1`, default OFF)**: for shared dir-metadata bufs (dir3 data/block/leaf1/leafn/free + da3node) DEFER the stamp to `__xfs_buf_ioend` (completion), gated on `b_mxfs_dir_wr_counted` (real bio, set only in `xfs_buf_submit_bio`) and `!b_error`. Defer-set == counted-set, only bmbt early-returns FUA, so all deferred bufs reach the counted submit+ioend pairing → no wedge. CORRECT (GPT-endorsed) but INSUFFICIENT alone for the 8/tcp dir_reuse readdir=799 loss (root is the cached-EX stale-grant demote in xfs_mxfs_dlm.c ~13485; see ccmemory sess42). Default OFF + UNVERIFIED on 1/2/4 tcp.

## sess50 (ccloop): b_mxfs_relepoch field + dormant release-epoch dir gates (xfs_buf.c)

Added `b_mxfs_relepoch` (uint32_t) to `struct xfs_buf` (xfs/xfs_buf.h): the owning dir inode's `i_dlm_epoch` (the RELIABLE local release counter, bumped on every grant-loss/stale — immune to the grant_gen/i_mxfs_ex_grant_seq handoff-underfire) at the last coherent read/modify of a dir DATA/leaf block. Stamped at modify (`mxfs_dir_data_track`) + fresh read (`xfs_da_btree.c` read-completion); reset on buffer reuse (`xfs_buf.c`).
Two new dir writeback/read gates were built on it and **both default OFF (refuted/inert)** — kept as dormant modargs:
- `dir_relepoch_skip` (xfs_buf.c P50-RELEPOCH-SKIP): skip an xfsaild reflush of a CLEAN dir buffer whose relepoch < i_dlm_epoch. REFUTED (8/tcp reliability loop PASS=0/4; losses occur with 0 skips → not a pre-release reflush).
- `dir_relepoch_reread` (xfs_da_btree.c P50-RELEPOCH-REREAD): FUA-re-read a CLEAN dir cache-hit whose relepoch < i_dlm_epoch. INERT — P50-RD proved `relepoch == i_dlm_epoch` at EVERY read (the existing acquire-evict keeps the base fresh), so it never fires.
Also added dirwr/instr-gated diagnostics (no behavior change): P50-RD/P50-WR dirent-count content-history trace, P50B-TENURE (wrcnt_max/xnode cross-node discriminator), and grant_gen fields in P-DATACLOBBER-SKIP.
**Net functional effect: NONE** (both gates default-off) — build behaves as the baseline. Conclusion (see ccmemory sess50-FINAL-*): every cache-coherency theory (stale read/writeback/modify-base) is refuted; the dir_reuse single-dirent loss is a DLM **serialization hole**, not a PAL/buffer-cache bug. Next work is in dlm/ + xfs_mxfs_dlm.c (the fast-path cached-EX serve), not pal/.

## sess2 (ccloop a16ec5f2): two always-off/zero-cost diagnostics in xfs_buf.c (build 7781DCE7)

Pure instrumentation, no behavior change (no public-API change, no new
invariant enforced); both stay in the tree:

- **PW-DADDR block watch** (top of `xfs_buf_submit_bio`, before all skip arms):
  new param `mxfs.watch_daddr` (ullong, defined in `xfs/xfs_mxfs_dlm.c`,
  default 0=off). When a bio's map range covers the watched envelope-relative
  daddr, logs `PW-DADDR READ|WRITE daddr= bn= len= first8= ops= flags= comm=`
  and `dump_stack()` for WRITES. Used to catch whichever path writes a given
  block (e.g. the dir-leaf daddr, the ino131 inode-cluster daddr for the
  dinode-regression hunt). CAVEAT: `first8` is bytes 0-8 of `b_addr` — for
  dir3 LEAF/NODE blocks those are forw/back sibling pointers (legitimately 0
  for a single-leaf dir); the dir3 leaf **magic is a be16 at offset 8**
  (owner@48, count@56, stale@58, ents@64). Reading offset 0 as "magic" cost
  this session a full false lead ("zero leaf on disk") — decode leaf headers
  at offset 8+ (see `scripts/dir_leaf_dump.py`, fixed accordingly).

- **P-PINNED-REREAD detector** (`xfs_buf_read_map`, in the `!XBF_DONE` read
  branch): logs + stack when a real read is about to overwrite `b_addr` of a
  buffer whose BLI is LI_DIRTY or pinned — the destructive moment where a
  committed-but-not-checkpointed delta is silently replaced by the older disk
  image (only mxfs's coherence-evict DONE-clears can create that state;
  upstream never re-reads such a buffer). 0 hits so far. **BLIND SPOT: inode
  CLUSTER buffers** — inode modifications live in inode log items (ILIs), not
  buffer log items, so a cluster-buffer re-read over uncheckpointed inode
  state does NOT trip this probe. The run12 durable-dinode regression
  (disk nx=9→1 mid-create; see ccmemory
  `sess2-END-dinode-regression-root-run12-odsync-pace-fixed`) is in that
  blind spot; catching it needs the PW-DADDR watch on the cluster daddr.

Cross-subsystem note (env, not PAL code): `mxfs_pal_scsi_write_fua_bdev`'s
chronic rc=-5 was the LIO target rejecting the FUA bit (`target_check_fua`
requires emulate_fua_write AND emulate_write_cache>0), not a PAL bug; and the
backstore mode drives pace (buffered-WCE ≈ +50% on write-phase wall vs
O_DSYNC). Both fixed in `scripts/lio_tcm_setup.sh` (write_back=false + WCE=1).

## sess3 (ccloop a16ec5f2) — xfs_buf.c watch upgrades + partial-writer visibility

- **PW-DADDR watch enriched** (`xfs_buf_submit_bio` chokepoint): when the
  watched sector sits in an inode-cluster buffer (`b_ops == xfs_inode_buf_ops`)
  the watch now decodes the dinode AT the watched sector — `PW-SLOT
  READ|WRITE[ REGRESS] ino= magic= mode= fmt= nlink= nx= size= nblocks= gen=
  nunl= lsn= maxnx= bp= comm=`. Tracks max nx per di_gen; a WRITE carrying a
  lower nx for the same gen is tagged REGRESS (stack, ratelimited 4/5s).
  NOTE: legit rm-phase shrink and hole-refill also lower/raise nx with a
  constant gen (the drc dir is reused) — REGRESS is a hint, not proof.
  Non-inode watched writes keep the old unconditional dump_stack.
- **PW-IWR** (`mxfs_submit_partial_inode_write`): when the watch daddr is in
  the buffer, logs the partial-writer DECISION — `wsect= included= whole=
  logged= bli_dirty= skip= dirty=` masks — i.e. whether the watched dinode
  sector is actually in the submitted bio. (The `all`/`dirty` mask computation
  was hoisted above the `nskip==0` early-return; behavior unchanged.)
- **PW-WDONE** (`xfs_buf_bio_end_io`): completion marker for watched WRITEs
  (`status= bp= realns=`) — pairs with PW-DADDR/PW-SLOT by bp pointer to
  catch late-landing prior-tenure bios.
- All gated on `mxfs.watch_daddr` (0644). Cross-node ordering: use the
  `realns=` wall-clock fields, NOT dmesg timestamps (boot clocks skew ~10s;
  the drc barrier aligns phase markers to ~ms if you must use boot time).
- **P29-DATAWRITE caveat** (dirwr-gated, this file): its `tag=CLOBBER` fires
  on every legitimate dirent ADD (`bsum!=dsum` includes additions); use the
  `buf_cnt`/`disk_cnt` fields (a true stale-RMW drop has buf_cnt<disk_cnt).
- Cross-subsystem (fix lives in xfs/): the partial-writer's per-slot skip
  logic is sound, but an inode whose iflush was SKIPPED by the SFTORN branch
  used to have its ILI fields consumed via flush_out with nothing copied into
  the cluster buffer — see xfs.md sess3 note + ccmemory
  `sess3-ROOT-FIX-sftorn-skip-consumed-ili-fields`.

## sess4 (ccloop a16ec5f2) — xfs_buf.c submit-path probe upgrades

- **P4C-IALLOC-WR / P4C-IFREE-WR** (new, dirwr/instr-gated): per-slot dinode
  mode-transition decode at inode-cluster write SUBMIT — placed BEFORE the
  `mxfs_submit_partial_inode_write` interception (which handles most multi-node
  cluster writes and would bypass a later probe). Reads the current disk image
  (plain read) and logs each slot whose di_mode transitions 0↔!0 with di_ino,
  gens, comm, realns. Cap 200k.
- **P27-SKIPNL-IWRITE** now prints hex masks `logged_m/dirty_m/skip_m` +
  realns so a P4C transition can be joined against whether that slot's sectors
  were actually written or skipped by the partial writer.
- **P29-DATAWRITE cap 4000→100000, P-LEAFWRITE cap 2000→50000** — 4000 capped
  out mid-run (rm-phase burns it) leaving failing rounds unrecorded; the
  cross-node chain replay (scripts/p29_replay.py) needs every dir-data submit.
- Pitfall (probe authorship): P29's realns is wall-clock but cross-VM skew is
  ~tens of ms — order same-daddr writes by content chain (dsum/dxor of write
  i+1 == bsum/bxor of write i), not by timestamp, when interleaved <50ms.
- Cross-subsystem: P4C/P29/P27 outputs join with xfs-side P4X-UNLINK /
  P4I-IFREE (xfs/xfs_inode.c) and dlm-side P4L lifecycle (dlm/dlm.c) to give a
  complete create/unlink/free/destage ledger per inode number.
- (sess4 note) All three probe families above are dirwr-gated and were
  verified live in runs 23-28; no functional-path changes were made to
  xfs_buf.c this session — submit/partial-write logic is untouched.

## sess2 (ccloop a9a03929) — xfs_super.c: MXFS mounts default to NOATIME

- **Behavior change** (`xfs_fs_fill_super`, right after the SB_I_VERSION
  block): `sb->s_flags |= SB_NOATIME;` — unconditional for every MXFS mount.
  No API change; no new params.
- **Why (measured, P2D-DRAINWHY/P2G-LOGWHO)**: an atime-only update is a
  logged CORE change; on a shared-LUN cluster every such inode must be
  checkpointed + cluster-written-back before its DLM grant can move.  A
  read-mostly phase (8 nodes × 800 md5sum/reads; relatime fires on every
  fresh file because atime==mtime at create) left the whole working set
  dirty-in-AIL, so the next owner's EX pull paid a ~7ms drain per file
  (the entire 10.6s rm phase of dir_reuse_coherency).  Same rationale
  GFS2/OCFS2 document for noatime on cluster mounts.
- **Pitfall**: in-kernel there is no `SB_STRICTATIME` (strictatime is an
  fs_context-level concept that *clears* NOATIME/RELATIME); do not try to
  honor it here.  `/proc/mounts` still shows `relatime` — that is the
  per-mount (MNT_*) flag; the superblock SB_NOATIME overrides it in
  `atime_needs_update()` via `IS_NOATIME()`.
- **Status**: build 391F2F21 ran it in runs 56-61.  It removes the atime
  txn flood (mask-removal — shifts xfsaild/AIL timing everywhere) and is a
  listed bisect suspect for the run60/61 barriers-off regression (see
  ccmemory `sess2-END-road-b-barriers-off-t6-silent-eio-blocker`).  If a
  revert-bisect exonerates it, keep it — the pace rationale stands.
- Cross-subsystem: the cost it removes is paid in xfs/'s
  `mxfs_dlm_bast_process` drain (`mxfs_ail_drain_inode_to`) — see xfs.md.
- Doc note: this section was first appended via a Bash heredoc, which the
  awareness track hook cannot see (it ledgers Edit/Write tool calls only);
  re-registered via the Edit tool.  Update awareness docs with Edit/Write,
  never shell redirection.

## sess3 (ccloop a9a03929) — xfs_buf.c: P3W-DIRWR write-lineage probe (always-on)

- **New probe, no behavior change** (`xfs_buf_submit_bio`, inside the
  existing dir-skip `dsi` block, right after `mxfs_buf_xfsaild_skip_dir_write`
  computes `dsi`): `P3W-DIRWR` logs EVERY write submit of a dir-owned buffer
  with `dsi.owner <= 256` — daddr, ops name, `b_mxfs_logged_seq`/
  `b_mxfs_written_seq`, pin/in_ail/dirty, the skip verdict, comm, realns.
  Always-on, capped 6000 (static atomic).  Unlike P16/P-WRACT/P50-WR (all
  dirwr/instr-gated = 100x-slow builds only), this is cheap enough for
  production runs — the low-ino gate keeps it to the shared test dirs.
- **Why it exists / what it proved**: run62/run64 cluster kills were dir
  blocks whose extent was in the DURABLE dinode while the platter held
  prior-life garbage.  P3W=0 for those daddrs across all 8 nodes proved
  NEVER-SUBMITTED (vs written-then-clobbered), which localized the root to
  the release-drain durability predicates in `xfs/xfs_mxfs_dlm.c`
  (`mxfs_dir_data_durable` / `mxfs_dir_flush_one_daddr`): their undestaged
  term was XBF_DONE-gated, so a !DONE+`lseq>wseq` buffer (fresh block whose
  DONE bit an invalidation cleared) was declared durable and its content
  stayed log-only forever.  Fixed in xfs.md's subsystem (undestaged made
  unconditional + validated re-land, P3R-RELAND/P3F-UNLANDED-LOST).
- **Cross-subsystem invariant this probe guards**: any dir buffer write
  MUST eventually appear as a P3W line; a durable-dinode extent with no P3W
  lineage on any node = Invariant-1 violation in the release drain.
  Pairs with `P3B-UNLOCK-UNDESTAGED` (xfs) at the DLM unlock and
  `P3L-DIRLOG-BIRTH` (xfs_trans_buf.c) at first-log; a REPEAT birth for the
  same daddr means the buf struct was staled+recreated and the seq pair
  reset — the blindness window (the seq pair lives on the STRUCT, not the
  block; `xfs_buf_stale` + re-get resets it via `xfs_buf_find_lock`).
- **Pitfall (probe placement)**: the `dsi` block runs for reads too;
  gate on `bp->b_flags & XBF_WRITE` or the probe floods with read traffic.

## sess5 (ccloop a9a03929) — xfs_buf.c + kern.c: undestaged-suppression fixes, FUA-read retry

- **xfs_buf.c — P12/ex_guard suppression arm now excludes undestaged
  buffers** (the inline dataclobber/ex_guard/stale_incarn block, ~3880):
  condition gained `&& !mxfs_dir_buf_is_undestaged(bp)`.  Run75 root: the
  arm fired on `ex_guard` (dir mode already NL mid-release) against a
  freshly-grown dir block whose FIRST write had not landed; the
  emulated-clean ioend retired the BLI, the release evict destroyed the
  in-core copy, and the platter kept a **prior-mkfs** image at the reused
  daddr (uuid-mismatch EFSCORRUPTED loop, deterministic across remount).
  Invariant: NO write-suppression arm may act on a buffer with unlanded
  logged content, whatever the tenure/mode says — the release fence's own
  flush is what must land it.
- **Ordering fact that made this exploitable** (documented at both sites):
  in the submit path the `wseq = lseq` stamp (`xfs_buf_submit`, ~4683)
  runs BEFORE the dir-skip gate (`xfs_buf_submit_bio`, ~3268).  With
  `mxfs_dir_wseq_at_completion=0` (the historical default) every dir write
  self-marked "destaged" before any gate looked, voiding all
  `mxfs_dir_buf_is_undestaged` checks tree-wide.  The param now defaults
  to **1** (defined in xfs/xfs_mxfs_dlm.c) — dir-metadata wseq advances
  only at real bio completion (`__xfs_buf_ioend`, gated on
  `b_mxfs_dir_wr_counted`, which only real bios set).  Emulated-clean
  ioends can therefore never fake destage anymore.  Anyone adding a new
  skip/suppression arm in xfs_buf.c MUST keep the undestaged exclusion.
- **kern.c — `mxfs_pal_scsi_read_fua_bdev` now retries transient SCSI
  failures** (up to 20 tries, 5ms+5ms/try backoff, ~1s worst case):
  previously any `scsi_execute_cmd` failure that wasn't ILLEGAL_REQUEST —
  and any short transfer (`resid != 0`, queue pressure) — returned a
  SILENT `-EIO` on the first attempt.  Under the 8-node verify storm those
  transients outlasted callers' short retry windows (inode reload's 30ms),
  reloads EIO'd for seconds, and the mount ROOT got health-poisoned until
  remount (run76: nodes lost the whole mount for 9+ test rounds).
  New prints: `P-FUA-READ-RETRY` (capped 50) per retry,
  `P-FUA-READ-ERR` (capped 200) with ret/resid/sense on final failure —
  a persistent transport failure is now attributable, never silent.
  ILLEGAL_REQUEST still breaks out on the first attempt to the existing
  "target does not support FUA reads" plain-read fallback.
- **API unchanged** in both files (no new/renamed exports; the retry is
  internal to the existing function; the suppression fix tightens an
  existing predicate).
- Cross-subsystem: the undestaged predicate (`mxfs_dir_buf_is_undestaged`,
  defined in xfs/xfs_mxfs_dlm.c, declared in xfs_mxfs_dlm.h) is now
  load-bearing at three pal/xfs chokepoints: this P12 arm, the dir-skip
  predicate entry (xfs), and the P3D release-invalidate (xfs).  Its
  accuracy depends entirely on completion-time wseq (above).  The same
  invariant was applied in libxfs (xfs_dir2_data.c keep-guard: undestaged
  check made unconditional, no longer `b_inail &&`-qualified — CIL-window
  fresh adds were falling through to the platter-compare and being
  invalidated, durably dropping the last adds of a create wave).

## sess6 (ccloop a9a03929) — xfs_buf.c: P-DIRSTALE ungated + the incore locking contract

- **`xfs_buf_stale` tracer P-DIRSTALE is now ALWAYS-ON** (was
  `mxfs_instr_enabled`-gated; xfs_buf.c ~92-121).  Fires (capped 200,
  with `dump_stack`) when a multinode dir3 data/block buffer that is
  UNDESTAGED or in-AIL is being staled.  Post-FIX-11/14 no mxfs path may
  legally do that, so any hit's stack IS a root cause.  Known legitimate
  hits: `xfs_trans_binval` via `xfs_dir2_shrink_inode` (unlink freeing
  the block — content is dead by definition; run87 confirmed these are
  the only firings in a healthy run).
- **LOAD-BEARING KERNEL FACT — `xfs_buf_incore(target, blkno, len,
  flags, &bp)` LOCKS the buffer it returns** (xfs_buf.h:299 maps it to
  `xfs_buf_get_map(XBF_INCORE|flags)`; `xfs_buf_find_lock` does a
  BLOCKING `xfs_buf_lock` unless `XBF_TRYLOCK`).  Return codes:
  `0` = found + locked, `-EAGAIN` = found but locked elsewhere
  (TRYLOCK only), `-ENOENT` = not cached.  Two long-standing callers
  were wrong about this:
  - the dir reload walk (xfs_mxfs_dlm.c H18) did `incore(0)` then
    `xfs_buf_trylock(dbp)` — a SELF-trylock that always failed, making
    its inline-stale arm dead code and routing every cached block to the
    deferred `b_mxfs_stale_pending` path (fixed sess6, FIX-15b: decide
    inline under the already-held lock);
  - any `incore(0)` on a busy buffer silently BLOCKS (the sess37
    "trylock-skip avoids deadlock" comments predate this contract).
  When writing new lookups: use `XBF_TRYLOCK` and branch on
  `-EAGAIN` vs `-ENOENT`; after success, release with `xfs_buf_relse`
  (unlock+rele), never bare `xfs_buf_rele`.
- Cross-subsystem: the deferred-stale honor point consuming
  `b_mxfs_stale_pending` lives in libxfs (`xfs_da_btree.c` ~3227) and is
  now a bounded (~50ms) trylock-retry wait (FIX-15) — pal's
  `xfs_buf_stale` still clears the flag on incarnation end
  (`b_mxfs_stale_pending = false` at buffer reuse, xfs_buf.c:133).
- **API unchanged** (no new/renamed exports in pal; the ungated tracer
  and the H18 repair are internal).  Related but xfs-side (for
  cross-reference): `xfs_ail_push_upto_sync_bounded` + `xfs_ail_max_lsn`
  were added in xfs/xfs_trans_ail.c (declared in xfs_trans_priv.h) as the
  noino-release Invariant-1 fence; pal code does not call them directly.

## sess7 (ccloop a9a03929) — xfs_buf.c: FIX-19 shrinker guard for undestaged dir buffers

- **Change** (`xfs_buftarg_isolate`, ~line 6560): the buffer-LRU shrinker
  isolate callback now returns `LRU_ROTATE` (refuses reclaim) for any
  dir-class buffer (`xfs_dir3_{data,block,free,leaf1,leafn}_buf_ops` or
  `xfs_da3_node_buf_ops`) that `mxfs_dir_buf_is_undestaged(bp)` reports
  (pinned or `b_mxfs_logged_seq != b_mxfs_written_seq`).  Capped print
  `P-SHRINK-UNDEST-ROTATE` (2000).
- **Why (RULE-4 proven, run92 r1)**: an mxfs-seq-tracked dir buffer with
  committed-but-undestaged content carries NO BLI/AIL hold and looks clean
  (dirty=0, pin=0, hold==LRU-only), so `drop_caches`/memory pressure freed
  it — the only landed copy of those dirents was the journal, which nothing
  replays without a crash.  node7's md5-tail block (daddr=4188352, lseq=15
  wseq=0) was freed by the verify-phase drop_caches while node7 still held
  EX with no intervening release; every node then FUA-read the pre-add
  platter → uniform 795/800 durable loss (LOOKUP_ENOENT + REREAD_MISS).
- **Invariant established**: an undestaged dir buffer must survive reclaim
  until the release-drain lands it.  Upstream-logged buffers never needed
  this (BLI holds a buffer reference); the mxfs seq-tracked class had no
  reclaim guard at all.  `xfs_buftarg_drain_rele` (unmount drain) is
  deliberately NOT guarded — releases have all run by then.
- **Bound**: rotation is transient (a tenure's undestaged window); the
  release/BAST drain or FIX-16's noino land-scan destages and the buffer
  becomes reclaimable again.  If a leak of lseq>wseq state ever appears,
  this rotation would pin those buffers in cache — a P-SHRINK-UNDEST-ROTATE
  storm on an idle system is the tell.
- **Cross-subsystem**: predicate `mxfs_dir_buf_is_undestaged` comes from
  xfs/xfs_mxfs_dlm.c (declared in xfs_mxfs_dlm.h, already included).
  Verified load-bearing in the first full 8/tcp dir_reuse PASS (run93,
  build CAE7BFBD): fired 74× across the cluster with zero fail rounds.
- **API unchanged** (internal isolate-callback behavior only).

## sess8 (ccloop a9a03929) — xfs_buf.c P-DIRSTALE gating; xfs_aops.c new API xfs_task_in_ioend

### xfs_buf.c: P-DIRSTALE dump_stack instr-gated (~line 121)
- The always-on `P-DIRSTALE` probe in `xfs_buf_stale` (staling an
  undestaged/in-AIL dir block) keeps its one-line pr_warn but its
  `dump_stack()` is now gated `unlikely(mxfs_instr_enabled)`.
- **Why**: an in-AIL dir-block `binval` is NORMAL in block→shortform
  shrink (`xfs_dir2_shrink_inode → xfs_trans_binval`), which fires
  constantly under same-dir churn.  The stack dump's "Call Trace"
  keyword failed the soak criterion's dmesg-clean scan (run106) and each
  dump costs ~2KB serial console (11.5KB/s budget — printk stalls
  propagate cluster-wide).  Same treatment applied xfs-side to the
  P1-AGWAIT dump in xfs_mxfs_dlm.c.

### xfs_aops.c: NEW public API `xfs_task_in_ioend(void)` (FIX-25)
- Returns true when `current` is the xfs-conv workqueue worker running
  `xfs_end_io` (implemented via `current_work()->func == xfs_end_io`;
  `current_work` is EXPORT_SYMBOL in the kernel).  Declared in
  `xfs/xfs_aops.h` (along with a now-explicit `xfs_end_io` decl).
- **Consumer**: `mxfs_ilock_admit_ioend()` in xfs/xfs_mxfs_dlm.c — the
  ilock demote-wait admits this context to a NESTED EX while an inode's
  BAST/DEMOTING drain is in flight and the DLM mirror still holds EX.
- **Invariant/pitfall it addresses (live-stack proven, run109 test6,
  wedged 150s+)**: a 3-task cycle —
  `mxfs_dlm_bast_process → filemap_write_and_wait → folio_wait_writeback`
  waits for a folio whose writeback only ends when `xfs_end_ioend`
  converts the unwritten extent, which does `xfs_trans_alloc_inode →
  xfs_ilock(EXCL) → mxfs_dlm_ilock_begin` and queued behind that same
  drain.  Rule of thumb: **the ioend completion path must never block on
  an inode-DLM demote of the same inode** — any future wait added to the
  release pipeline that can depend on I/O completion must keep this admit
  reachable.  The nested admit is safe because the mirror is still
  EX-granted; the existing P15-REL-ABORT holders!=0 gate re-arms the
  release afterward.
- **Cross-subsystem**: pal (xfs_aops.c) provides the detector; the policy
  lives xfs-side in xfs_mxfs_dlm.c.  A mode=PR-with-pending-conversion
  state can no longer form (EX drains complete conversions first).
- **Open pal-side lead (sess8, run112 PROVEN evidence)**: `P3W-DIRWR`
  (xfs_buf.c ~3290) recorded test2's xfsaild writing a SHARED dir DATA
  block (daddr 4186528, lseq=7 wseq=0, in_ail=1, `skip=0`) mid-peer-tenure
  — the uncoordinated-writeback class behind the 4/tcp readdir-undercount
  tear.  The skip guard printed by that probe did not engage; extending it
  (sess40 "dir-block ABA writeback skip" / sess61 `P61-CHOKEPOINT-SKIP-BMBT`
  pattern) is the staged next fix.

## sess10 (ccloop a9a03929, 2026-07-03) — P-DIRWR watch-scope rework (xfs_buf.c)

### xfs_buf.c: P-DIRWR dir-write content trace now fires for the armed watch ino
- The write-submission trace (`P-DIRWR`, ~line 5610: fmt/owner/daddr/
  crc32c-past-header/count/stale/active + buffer state per dir metadata
  write) previously required `mxfs_instr_enabled || mxfs_dirwr_enabled>=2`
  and was capped at 8000 fires per boot — exhausted long before
  dir_reuse runs in-suite.
- Now ALSO fires, **uncapped**, when the block's owner inode matches the
  armed probe scope: `READ_ONCE(mxfs_watch_ino) > 1 &&
  mxfs_ino_watched(owner)` (helper in `xfs/xfs_mxfs_dlm.h`, reuses the
  pre-existing `mxfs.watch_ino` ullong modparam; 0 = legacy ino<=256,
  1/impossible-ino = silent sentinel, N = only inode N).
- Owner extraction extended to LEAF blocks: `xfs_dir3_leaf_hdr.info.owner`
  (was -1 for leaf1/leafn, so leaf writes could never match a watch).
- Legacy instr/dirwr>=2 behavior unchanged (same 8000 cap).
- **Cross-subsystem**: the dir_reuse/fence suite tests arm `watch_ino`
  per round via sysfs (`tests/suite/*.sh`), and `tests/suite/lib.sh
  finish()` resets it to the sentinel — a leaked watch (inode-number
  reuse across tests) makes the armed per-op probes fire during the
  NEXT test; the per-op sync platter reads collapsed tcp_dlm_scaling's
  pace (s10 iter3/iter5) before the hygiene reset existed.
- **Pitfall**: pr_warn args are evaluated before ratelimit/cap checks —
  any probe doing I/O inside a print argument list pays that I/O on
  every call.  The P50-RD platter read (xfs side) was removed for
  exactly this class of cost.

### xfs_buf.c: NEW detector P10-CLREGRESS — inode-cluster dir-slot regression (sess10, later)
- At every multinode inode-cluster WRITE submit (`xfs_inode_buf_ops` /
  `_ra_ops`), gated `mxfs_dir_relverify`: SCSI-FUA-read the on-disk
  cluster and, for each DIR dinode slot (magic `IN` @0x0, S_ISDIR
  di_mode @0x2, same di_gen @0x5C), warn `P10-CLREGRESS` when the DISK
  slot is AHEAD of the bytes about to be written (disk di_size @0x38 >
  buf, or equal size with a higher shortform count byte @176 for v3
  LOCAL/LOCAL).  Includes `owned` (an `XFS_LI_INODE` item on
  `b_li_list` whose `im_boffset` matches the slot) + `ili_fields`.
- Cost: one FUA read per cluster write — only when `dir_relverify=1`;
  default suite runs pay nothing.
- **Why / first catch**: dlm_scaling rate-collapse run (artifact
  20260703T210920Z) showed 1630 hits on one node: its OWN dirty ili
  (ofields=0x3) held an EMPTY shortform dir while the platter had the
  peer's newer image — a stale-dirty-ili writeback livelock; if such a
  write lands it durably regresses the shared parent dir (the
  dlm_scaling/fence dirent-loss family).
- **Pitfall (raw dinode offsets)**: di_format is @0x5, di_gen @0x5C —
  first cut used 0x5a/0x50 and compiled fine while comparing garbage;
  prefer struct access where a mapped `xfs_dinode *` is available.
- **Cross-subsystem**: interpretation depends on the xfs-side
  `i_mxfs_lastrel_*` release ledger (xfs_inode.h) and
  `P-SFDIR-REVERT` reload detector (xfs_mxfs_dlm.c); the trio
  discriminates release-flush-ran vs platter-regressed vs who-rewrote.


### sess12(a9a03929): mxfs_pal_dump_stack (pal.h + linux/kern.c)
- New PAL API: `void mxfs_pal_dump_stack(void)` (pal.h, doc-comment'd) —
  kernel impl in linux/kern.c calls `dump_stack()`, placed next to
  mxfs_pal_cond_resched; EXPORT_SYMBOL_GPL'd in the export block beside
  mxfs_pal_log.  User builds: no-op contract (no user impl dir exists
  in-tree today; add a stub if/when one returns — Invariant 4).
- Consumer: dlm/dlm.c P36-STACK — on the FIRST acquire-timeout retry of
  an episode (capped 8/boot) the waiter dumps its own call chain, naming
  the wait SITE for hold-and-wait/ABBA forensics.  Proven payoff same
  session: captured `xfs_remove → xfs_trans_alloc_dir →
  xfs_lock_two_inodes → DLM EX wait` while the task held AG-0 — the
  fence-family AG→dir inversion's exact edge.
- Cross-subsystem note: xfs-side stuck-holder dumps (P12-HOLDERTASK in
  xfs_mxfs_dlm.c) use kernel `sched_show_task`/`find_get_pid` DIRECTLY
  (xfs/ is kernel-only); only dlm/-reachable code routes through this
  PAL wrapper.


### sess13(a9a03929): P64-N1F1 write tracer extended with a victim pattern (linux/xfs_buf.c)
- No public-API change; diagnostic-only delta to the existing tracer.
- The always-on dir-block write tracer (scans every XDD3/XDB3 buffer WRITE
  for the dirent byte pattern) now scans TWO exact patterns per write:
  `\x08node1_f1` (survivor baseline, unchanged) and `\x08node2_f1`
  (victim — the recurring drc loss is the REMOTE nodes' f1 while node1's
  survives).  Print gains `present2=` alongside `present=`; same 6000/boot
  cap, same single-pass scan (both memcmp's keyed on the 0x08 length byte,
  early-out when both found) — cost delta is negligible.
- Purpose: the cross-node write sequence for a lost dirent distinguishes
  never-destaged (present2 never 1 on any node = committed in-core then
  dropped by an adopt) from durable clobber (1→0 flip names the clobbering
  writer + comm).  Pairs with the xfs-side P13-PLACE placement ledger
  (libxfs/xfs_dir2_data.c, dirwr-gated as of sess13) and P13-SFRM
  (libxfs/xfs_dir2_sf.c) for the shortform variant.
- Pitfall rediscovered at 8 nodes: always-on printk volume (with journald
  rate-limiting disabled by the test prep) inflates round walls enough to
  blow test budgets — new heavy probes must be dirwr/instr-gated by
  default; run.sh prep now also drops console loglevel (kernel.printk
  '1 4 1 1') so pr_warn traffic stays off the slow serial console.

## sess15(a9a03929) — P15I-CRCFAIL read-verify diagnostic (pal/linux/xfs_buf.c)
- Site: `__xfs_buf_ioend`, immediately after `b_ops->verify_read` and before
  the XBF_DONE set.  Fires when a READ completion carries
  `-EFSBADCRC`/`-EFSCORRUPTED` on a multi-node mount.  Capped ×16/boot.
- Prints daddr/len/err/ops-name/b_flags/b_hold plus `secrc=[...]` — a
  crc32c fingerprint of EACH 512B sector of the FAILED in-memory image.
  Purpose: offline compare against the raw platter (clyde
  /home/steve/disk.img at xfs_data_offset from `tools/chk_mxfs -v`) to name
  WHICH sectors diverged — discriminates a torn in-core page mix (e.g. a
  read racing `xfs_buf_stale` from the P126 xfsaild AG-meta skip in
  xfs_buf_item.c) from durable platter garbage later repaired by a peer's
  flush.  Armed for the 2/tcp-r3 inobt 0x7fc2b8 face (both post-mortems
  found the platter VALID afterward — late raw-disk reads cannot refute
  this face; only the at-failure fingerprint can).
- No extra I/O, no behavior change.  `b_hold` is a plain unsigned int in
  this fork (NOT atomic_t — atomic_read() on it is a build error).
- Public API: none added/removed — the probe is local to __xfs_buf_ioend.
- Cross-subsystem: pairs with xfs-side FIX-I (xfs_mxfs_dlm.c publish-drain
  P78 skip arm now makes an evicted-unpublished child's inode-cluster
  durable before the parent-dir handoff returns — P15J-PUBSKIP-FLUSH), and
  with the P126/P60 xfsaild skip-stale sites in pal/linux/xfs_buf_item.c
  which remain suspect #1 for discarding committed (in-AIL) AG-meta.

## sess2 (ccloop 186320ae) — kern.c: PR UA-retry on all PROUT/PRIN wrappers (v0.6.1)

- **Problem (PROVEN)**: a PROUT can consume a pending UNIT ATTENTION and fail
  `SAM_STAT_CHECK_CONDITION` (positive 2) without performing its service action.
  The harness's stale-PR CLEAR (prep_fs.sh) pends "Reservations preempted" on
  every OTHER registered I_T nexus — including the clearing node's own second
  dm-multipath path (register-ignore through /dev/mapper registers BOTH paths,
  the CLEAR goes down one). The very next mount-time `mxfs_scsipr_register` ate
  that UA → rc=2 → v5_mount treated PR as unavailable → node ran UNREGISTERED
  under the peers' WRITE-EXCLUSIVE-REGISTRANTS-ONLY reservation → every write
  EBADE (-52), whole 4/caw suite 0/4 (node fenced; `sg_persist -in -k` showed
  6 keys not 8). Flaky per run because mkfs I/O usually consumes the UA first.
- **Fix**: `mxfs_pal_scsi_pr_register/reserve/preempt/unregister/read_keys`
  (pal/linux/kern.c) retry up to `MXFS_PR_UA_RETRIES=5` (2<<n ms) while the
  pr_ops return equals SAM_STAT_CHECK_CONDITION — the UA is consumed by the
  failing command, so the first retry is deterministic. Mirrors the CAW /
  write-FUA UA-retry pattern. Preempt retry is fencing-critical (an aborted
  preempt leaves a dead node unfenced).
- **Paired dlm change**: `dlm/v5_mount.c` CAW path now hard-fails the mount on
  register failure ("refusing to join unfenced") instead of continuing without
  PR; -EOPNOTSUPP (no PR support at all) keeps best-effort.
- Return-code lore: pr_ops pass positive SCSI status through (2 = CHECK
  CONDITION, 0x18/24 = RESERVATION CONFLICT); negative errno otherwise.
- Cross-subsystem (late-session addition): the dlm layer gained a gen-aware
  CAW release (`mxfs_dlm_caw_unlock_gen` + grant-meta `grant_seq`/`releasing`,
  see dlm doc / docs/multipath_support.md §5) — no pal API impact; pal's PR
  wrappers are unchanged by it.  kern.c public surface this session:
  no functions added/removed/renamed — only retry loops inside the five
  existing `mxfs_pal_scsi_pr_*` bodies (register/reserve/preempt/unregister/
  read_keys) plus the `MXFS_PR_UA_RETRIES` internal constant.

## sess5 (ccloop 186320ae) — xfs_buf.c: P136-DIRINO-WRDONE probe upgraded (v0.6.5)

- **Instrumentation-blindness fix, no behavior change.** The P136 dir-dinode
  write-COMPLETION probe (in `__xfs_buf_ioend`, gated `mxfs_dirwr_enabled ||
  mxfs_instr_enabled`) had two forensic holes that mis-led two sessions:
  1. It **skipped LOCAL (shortform) dir dinodes** (filter was
     EXTENTS/BTREE-only) — so block→sf conversion destages were invisible and
     "nobody wrote the sf image" was an artifact, not a fact.
  2. Its cap was 1200 events per module load; under a dlm_fairness storm 3 of
     4 nodes exhausted it ~40 s before the failure window, blinding the
     cross-node write timeline ("only test2 wrote the cluster" was void).
- **Now**: logs ALL dir dinode images in the written buffer, with `fmt=` and
  `gen=` fields added (incarnation discrimination — ino reuse across rounds
  shares daddrs), cap raised to 60000.
- Line format: `P136-DIRINO-WRDONE ino= fmt= gen= size= nx= daddr= realns=`.
  Consumers grepping the old format (no fmt/gen) must update.
- Public API: none added/removed — probe-local edit inside __xfs_buf_ioend.
- Cross-subsystem: this probe's full-coverage timeline is what proved the
  xfs-side v0.6.5 fixes (stale-tenure destage clobber → P-ICD-TENURE-REFUSE in
  xfs_mxfs_dlm.c; block-format-for-life in libxfs) — see the xfs subsystem doc
  and ccmemory `caw-v065-fix-chain-4caw-17of17`.
- Pitfall reaffirmed for future probe authors: a capped `pr_warn` probe that
  goes silent is INDISTINGUISHABLE from "no writes happened" in post-hoc
  forensics — always log a final "cap exhausted" marker or size the cap to the
  storm (60000 ≈ 10× the worst observed per-load volume in a dlm_fairness
  50-round 4-node run).

## sess6 (ccloop 186320ae, 2026-07-06) — P124-ALLOC-REVERT re-gated instr-only

- **What**: `xfs_buf.c` P124 (bnobt/cntbt write-vs-coherent-disk diff detector,
  ~line 5280) gate changed `(dirwr || instr)` → `instr` only.
- **Why**: its "prior-tenure-stale signature carries NO this-node-ahead
  content" premise is FALSE for a sole-EX-holder under sustained load (2/caw
  soak): with no release/BAST there is no destage, so committed-ahead bnobt
  content legitimately sits in the AIL and every xfsaild push differs from the
  coherent disk image (EQNR-CONTENT-DIFF, in-core exactly one allocation
  ahead; P88 companion lines showed disk catching up step-for-step,
  rec0.start 33→34→35→36 — forward progress, nothing reverted).  Its
  dump_stack under `dirwr=1` failed soak's clean-dmesg criterion (DPAT
  matches "call trace") on healthy traffic.
- **Rule refinement for probe authors** (extends the sess39 note above): a
  probe that can fire on a HEALTHY hot path must be gated `instr`-only, not
  `dirwr` — `dirwr=1` is the suite-runs-with-it observability tier and must
  stay dmesg-clean under load.  The revert family P124 chased is fixed at the
  AG acquire path; P124 was log-only by design (suppression reverted, see
  in-code comment).
- Build: `57773CBD` (= 656E89B4 + this change only).

## sess4 (ccloop 46efd8b6, 2026-07-10) — xfs_buf.c: P63-LEAFWR straggler fields; bmbt-gate context

- **What**: the sess63 bmbt FUA-passthrough block's `P63-LEAFWR` print (submit
  tail, ~line 7205) now also captures, AT WRITE-COMPLETION TIME, the owner
  dir's DLM tenure state: `buf_tenure` (bp->b_tenure_id) vs `cur_seq`
  (i_mxfs_ex_grant_seq via pag_ici lookup), `mode`, `ex` holders, and appends
  `<<STRAGGLER` when the write completed at mode==NL or stamp!=seq.
- **Why / verdict**: hunting the cache_coherency@32 backward-content bmbt
  child images (run 072239Z).  Result: **0 stragglers in a full failing run**
  — every bmbt FUA write completes under a current tenure.  Cross-boundary
  in-flight writes are REFUTED as the poison source; and the whole
  "PLATTER-TORN" verdict family later proved to be a probe decoder artifact
  (da3 NODE block parsed as a leaf — fixed in xfs_mxfs_dlm.c, not here).
- **Pitfall recorded this session (probe authors)**: `mp->m_bsize` is the fs
  block size **in 512-byte BASIC BLOCKS** (xfs_sb.c:1396 `XFS_FSB_TO_BB(mp,1)`
  = 8), NOT bytes.  Passing it as a byte length to
  `mxfs_pal_bdev_read_plain_bdev` fails the `(len & 511)` check → -EINVAL and
  the probe is silent.  Use `mp->m_sb.sb_blocksize` for byte lengths.  Also:
  `submit_bio_wait`-based plain reads and `mxfs_pal_scsi_read_fua_bdev` both
  accept 4096-byte reads at fsb-aligned LBAs on the dm-multipath stack — the
  FUA READ(16) passthrough is the reliable fallback when the bio path errors.
- **Cross-subsystem**: the write-suppression lattice for dir DATA/LEAF blocks
  (~4040-4130) and the `mxfs_buf_xfsaild_skip_bmbt_write` gate were audited
  this session — all skip-family probes (P-DATACLOBBER-SKIP, P39-EXSUBSET-
  DROP, P50B-TENURE, P40-INCARN-ABA-DIRSKIP, P61-FUA-SKIP-BMBT) fired **0×**
  in failing runs; the read-time analogue of the sess12 gap (stale dirty/
  locked dir buffer SERVED locally when the read-time invalidation trylock-
  skips, xfs_da_btree.c ~3776) is the remaining suspect, owned by the xfs
  subsystem.
- Builds: DD94481C (v0.10.9) … 91A7D62B (v0.10.16); the P63 extension landed
  in 4FF566A4 (v0.10.13).  No public-API changes in pal this session — probe
  fields and gate audits only; submit/partial-write logic untouched.

## sess5 (ccloop 46efd8b6, 2026-07-10) — xfs_buf.c: P76 discriminator at the P61 bmbt chokepoint skip

- **What**: added `P76-SKIP-EATS-COMMIT` inside the
  `mxfs_buf_xfsaild_skip_bmbt_write` arm of the bio chokepoint (~line 3803).
  Before the fake-clean ioend, plain-read the LUN at the buffer's LBA and
  memcmp against `b_addr`; on DIFFERS, print owner/daddr/numrecs +
  in_ail/dirty/pin + lseq/wseq.  Probe only — the skip behavior is unchanged
  this build.
- **Why / verdict (RULE 4)**: run 104051Z caught the skip firing
  content-DIFFERS on the exact (owner=39846019, daddr=66983240) seconds
  before that dir's `i != 1` shutdown (P75 in xfs_bmap.c).  The skip's
  justification ("release drain already landed every legitimate leaf
  change") is FALSE for bmbt children: the release fence's break condition
  consults the dir INODE item + dir DATA blocks (`mxfs_dir_data_durable`,
  which does call `mxfs_dir_bmbt_scan`) — but at least one release path
  (suspect: bast_process drain+unlock, P35-DIRHONOR) lets a committed bmbt
  write reach xfsaild after NL.  The skip then retires the BLI and (because
  `b_mxfs_written_seq` is stamped at SUBMIT, even for skipped writes)
  forges lseq==wseq "destaged", so every downstream guard trusts it, the
  evict discards the in-core truth, and the re-read time-travels the bmbt
  behind the iext ⇒ `xfs_bmap_del_extent_real` i!=1 ⇒ dirty trans_cancel ⇒
  node shutdown.
- **Population caveat**: most P76 fires are `in_ail=0 lseq==wseq` — benign
  stale-reflush discards (the skip doing its designed job); the eating case
  is the same fingerprint AFTER the first eaten write already retired the
  BLI.  Don't read bulk P76 counts as loss counts; correlate (owner,daddr)
  with P75.
- **Queued fix (next session, designed)**: at the skip, when DIFFERS, bump
  `bp->b_mxfs_logged_seq` (mark undestaged) before the fake ioend so evict
  guards keep the in-core image and the next EX tenure's fence bwrites it
  under lock; and audit the P35 release path for bmbt-scan coverage.
- **Also this session (other subsystems, for cross-ref)**: dir leafless
  ghost REMOVE heal `mxfs_dir2_leafless_removename` (xfs/libxfs/xfs_dir2_leaf.c,
  P73) + `XFS_DABUF_MAP_HOLE_OK` on datascan/leafless reads; P74-BMBT-RELDRAIN
  arm added to `mxfs_dir_flush_data_blocks_relsafe` (xfs_mxfs_dlm.c — inert:
  fence breaks before the retry arm runs); P75/P75b at the bmap del site.
- Builds: 39DF66F4 (v0.10.17) … 345C285B (v0.10.23, deployed).  No public-API
  changes in pal this session; probe-only additions to the bio submit path
  (the P61 skip arm), behavior unchanged pending the queued fix above.
## sess6 (ccloop 46efd8b6) changes — pal/linux/xfs_buf.c, pal/linux/xfs_super.c

### xfs_buf.c
- **Completion barrier now covers bmbt writes**: `xfs_bmbt_buf_ops` added to BOTH
  the dir_wr_counted list (xfs_buf_submit_bio; increments
  `m_mxfs_dir_wr_inflight`, wseq stamps at ioend) and the wseq-defer list
  (xfs_buf_submit). Invariant: bmbt writes are xfsaild-ASYNC plain bios on
  multipath (SCSI FUA passthrough returns EOPNOTSUPP → fallback), so an
  in-flight committed leaf bio could cross the dir EX handoff and land after
  the peer's iread — counted+deferred closes it. The release fence
  (xfs_mxfs_dlm.c P3B loop) polls the counter to 0 before unlock.
- **Skip-arm semantics tightened** (both bmbt skip sites: chokepoint in
  xfs_buf_submit_bio, FUA arm in xfs_buf_submit):
  - `mxfs_bmbt_skip_preserve_truth(bp, site)` — NEW static helper, PRINT-ONLY
    tripwire (P77-SKIP-DIFFERS): compares the to-be-skipped image against the
    LUN; `undest=1` in the print would mean a committed image escaped the
    fence. Do NOT re-add the v0.10.24 lseq-bump variant — REFUTED: it made
    fences late-republish stale leafs under later tenures.
  - Chokepoint skip now UNCOUNTS (`b_mxfs_dir_wr_counted` unwind + counter
    decrement) before the emulated ioend so a skip-emulated completion can
    never stamp written_seq ("destaged" lie) nor double-decrement.
  - **No XBF_DONE resurrect**: both skip arms no longer `|= XBF_DONE`. A write
    buffer normally has it; if the reload's bmbt evict just invalidated the
    buffer (cleared DONE for cold re-read), re-marking DONE resurrected the
    stale prior-tenure image with NO read → acquire-side iread cache-hit stale
    records vs adopted dinode → EFSCORRUPTED (RULE-4 proven run 122308Z).
    PITFALL: the dirent-analogue skip (dir DATA/leaf arms ~line 4112) STILL
    does `|= XBF_DONE` — suspected cause of the residual 32-node uv ghost
    (1 stale dirent visible on one node); fix pending evidence.
- **FUA-write success arm stamps wseq manually** (`b_mxfs_written_seq =
  b_mxfs_logged_seq`): the synchronous SCSI FUA path never runs submit_bio
  counting, so ioend won't stamp; without this the buffer reads undestaged
  forever and the fence rewrites it every release.
- **Write-completion flush-epoch stamp** (early in `__xfs_buf_ioend`): every
  successful XBF_WRITE completion records
  `bp->b_mxfs_wr_flush_epoch = atomic64_read(&mp->m_mxfs_flush_epoch)`.
  Consumed by libxfs/xfs_bmap.c `xfs_iread_bmbt_block` P34B guard: written in
  the CURRENT epoch ⇒ no device flush since ⇒ the platter may be BEHIND this
  buffer (LIO drops FUA; completion = target write cache) ⇒ never
  regress/refresh it from a platter/FUA read. Cross-subsystem: the epoch is
  advanced by `mxfs_blkdev_flush_epoch()` (xfs_mxfs_dlm.c) wrapping all 23
  DLM-layer blkdev_issue_flush sites.
- New buf field: `b_mxfs_wr_flush_epoch` (xfs_buf.h). New mount field:
  `m_mxfs_flush_epoch` (xfs_mount.h).

### xfs_super.c
- `atomic64_set(&mp->m_mxfs_flush_epoch, 1)` at DLM init (epoch starts at 1 so
  a buffer stamp of 0 unambiguously means "never written by this node").

### Pitfalls learned (pal-relevant)
- Module-lifetime hazard (OPEN BUG, dir_reuse killer): bios submitted by a
  prior mxfs.ko instance can complete after rmmod (multipath retry windows) →
  `blk_done_softirq` jumps into unloaded module text (Oops 0010, netconsole-
  captured). Module exit needs an in-flight-I/O drain; the counted-barrier
  infra is the natural backing.
- `xfs_buf_delwri_submit_buffers` in this tree routes through `xfs_buf_submit`
  (not directly to submit_bio) — the FUA arm sees delwri writes too; only
  FUA-fallback traffic reaches the chokepoint skip.
- Builds this session: v0.10.24 (8AFB69E2) → v0.10.30 (DEA32227, deployed).

## sess7 (ccloop 46efd8b6) — xfs_buf.c completion-ledger + bmbt skip-reconcile (v0.10.32-33)

### INVARIANT: b_iowait tokens must pair 1:1 with iowait consumers — drained at sync submit
`xfs_buf_submit` now does `reinit_completion(&bp->b_iowait)` for !XBF_ASYNC
buffers before dispatch.  Why it's safe: I/O owns the buffer lock until its
ioend and submit holds the lock, so no bio of ours can be in flight — any
token present at submit is a stale leftover.  Why it's needed: the mxfs
emulated-completion arms (bmbt chokepoint/FUA skips, P91 in-place read) call
the FULL `xfs_buf_ioend()` (which for sync buffers deposits a token AND runs
`__xfs_buf_ioend`), and readahead-steal conversions (~line 800 P-RAFIX) flip
XBF_ASYNC between deposit and consumption.  A stale token makes
`xfs_buf_iowait` return BEFORE the new DMA lands, and its
`while (!__xfs_buf_ioend())` loop then CRC-verifies the PRE-DMA b_addr —
the perpetual EFSBADCRC read loop on a fully-valid LUN (run 164056Z test1,
kcore-proven b_iowait.done=1 at rest).  If you add ANY new skip/emulated
completion arm, keep it token-neutral or rely on this drain.

### mxfs_bmbt_skip_preserve_truth (v0.10.32): probe → RECONCILER
Called from both bmbt write-skip arms (chokepoint ~3930, FUA ~7345) with the
buffer locked.  Now, after the raw-LUN compare:
- content == LUN (`same==1`): certify destaged (`b_mxfs_written_seq =
  b_mxfs_logged_seq`), P82-SKIP-ALREADY-ON-LUN.
- differs + undestaged: **P81-BMBT-SUPERSEDED-DROP** (a committed local bmbt
  delta missed its release fence and the peer era owns the LUN — the delta is
  LOST; every P81 in a run is a fence bug to chase), certify, then
  `xfs_buf_stale(bp)`.
- differs + clean: `xfs_buf_stale(bp)` only.
Staleing implements what the sess66 gate comment always promised: the next
access cold-reads the peers' era instead of resubmitting forever (the 40Hz
P61/P77 walls that flooded dmesg/journals and pinned iflush resubmits).

### __xfs_buf_ioend read branch: verify_read gated by b_mxfs_inplace_read
New xfs_buf field `b_mxfs_inplace_read` (xfs_buf.h): set by the P91
FUA-SKIP-LOGGED guard just before its emulated ioend; consumed (cleared) at
the top of the read branch, which then SKIPS `verify_read`.  An in-place
completion never DMA'd, and a logged buffer's embedded CRC is only stamped at
write submit, so CRC-verifying modified-since-last-write in-core content
manufactures EFSBADCRC (sess15 P15I inobt corpse family).  Note the pairing
subtlety: with the token drain above, the arm's own `__xfs_buf_ioend` consumes
the flag AND clears XBF_READ, so iowait's second `__xfs_buf_ioend` pass skips
the read branch entirely — do not "fix" the double-run by removing either.

### Forensics pitfalls learned here (cross-cutting)
- clyde's SCST backend (/home/steve/disk.img) is o_direct=1: buffered reads
  of the image on clyde are a STALE page-cache alias — always `dd iflag=direct`.
- `watch_daddr` module param → PW-DADDR prints `bp=%px` → kcore-read buffer
  fields (b_iowait.done @+184, b_flags @+28, b_addr @+144, b_error @+280).
- kprobe `caller=$stack0:x64` + kallsyms bisect resolves a verifier's true
  caller when ftrace stacks mislead (inlining).
- block:block_bio_queue tracepoint answers "did a bio really go out" for a
  suspected in-place completion; multipath content divergence checks read
  each sd slave directly.

## sess1 (ccloop a8642ea1, 2026-07-10) — read-once demote hook + PR-sweep lifecycle (v0.10.36-39, build B7A8BCAB)

### xfs_file.c: close-time PR demote call (v0.10.36)
`xfs_file_release` now calls `mxfs_dlm_close_release(ip)` (declared in
`xfs/xfs_mxfs_dlm.h`, implemented in `xfs/xfs_mxfs_dlm.c`) for READ-ONLY
closes (`!(file->f_mode & FMODE_WRITE)`), placed AFTER the readonly/shutdown
early-return and BEFORE the FMODE_WRITE early-return (read-only closes exit
there — a hook below it never fires for readers).  It queues the drain-free
DLM demote of a CACHED PR grant on a regular file (bpend+dwork idiom).
- Modparam `mxfs.close_release` (default 1).
- PITFALL learned: this is a NO-OP for lookup/stat-acquired PR grants —
  `[ -e ]`/stat igets take PR with no file open/close, so dir_reuse verify
  PRs are untouched.  The dir-EX-BAST sweep (xfs subsystem) covers those.

### xfs_super.c: m_mxfs_pr_sweep_work lifecycle (v0.10.38)
- Mount (xfs_init_mount_workqueues, right after `m_mxfs_inode_bast_wq`
  creation): `INIT_WORK(&mp->m_mxfs_pr_sweep_work, mxfs_dlm_pr_sweep_work_fn)`
  + `m_mxfs_pr_sweep_last = 0`.  Fields live in xfs_mount.h.
- Unmount (the put_super path that flushes the inode-bast wq before log
  teardown): `cancel_work_sync(&mp->m_mxfs_pr_sweep_work)` MUST run BEFORE
  `flush_workqueue(m_mxfs_inode_bast_wq)` — the sweep queues per-inode
  dworks onto that wq; cancel-after-flush could re-arm work post-flush.
- The sweep worker itself (xfs_mxfs_dlm.c) walks `sb->s_inodes` with the
  fs/drop_caches.c igrab/iput idiom and bails on shutdown/unmounting.

- `mxfs.p6_honor_src_mask` (default **0x1A4**; 0 = pre-fix) — **the sess26 fix
  for the mechanism above.** Bitmask of `i_dlm_stale_src` values the P6
  mid-tenure skip must NOT swallow. `0x1A4` = srcs 2, 5, 7, 8, every one
  peer-driven:
  src 2 = consuming a peer's `DIR_MODIFY`; src 5 = set at release, a peer may
  have held EX for the whole interval; src 7 = the else-branch of
  `dir_slow_skip`, whose skip condition is literally "no peer handoff"; src 8 =
  `MXFS_IF_DIR_RELOAD` consumed on the EX-acquire fast path.
  At src=8 the flag is CLEARED before the reload is attempted, so skipping
  destroys the peer notification on both channels and the peer's dirent is never
  observed. Measured effect: swallowed notifications 173/43/42 -> 0/0/0 on three
  nodes, consecutive-skip streaks (`i_dlm_p6skip_n`) max 29 -> 0, and
  `dirent_durability` unchanged at 117-124s.
  **Pitfall:** the first cut used `0x104` (srcs 2 and 8 only). Srcs 5 and 7 do
  not appear in a single run — they surfaced only in a 3-run accumulation of the
  `P81-P6-SRC` histogram. Read that histogram across several runs before
  believing a source set is complete. It is a bitmask precisely so widening
  needs no rebuild.

### Cross-subsystem note
xfs_file.c now includes "xfs_mxfs_dlm.h" (was not included before); the
i_dlm_bastq_src codes gained 14=close_release, 15=pr_idle_release,
16=dir_ex_sweep (documented in xfs_inode.h field comment).

### xfs_super.c: m_mxfs_destage_kick lifecycle (v0.11.82, ccloop c7ee71c6 sess2)
- New `struct delayed_work m_mxfs_destage_kick` in xfs_mount.h; worker
  `mxfs_destage_kick_fn` + queueing helper `mxfs_destage_kick(mp)` live in
  xfs/xfs_mxfs_dlm.c (extern'd in xfs_mxfs_dlm.h; the INIT site in
  xfs_super.c uses a local extern for the fn).
- Mount: `INIT_DELAYED_WORK(&mp->m_mxfs_destage_kick, mxfs_destage_kick_fn)`
  right after the `m_mxfs_publish_work` INIT in the same setup fn.
- Unmount (put_super): `cancel_delayed_work_sync(&mp->m_mxfs_destage_kick)`
  placed just AFTER the v5dlm shutdown block (unconditional — INIT is
  unconditional too) and BEFORE `xfs_unmountfs` — same teardown-ordering
  family as `m_mxfs_foreign_replay_work`: the worker calls
  `xfs_log_force`, so it must be dead while `mp->m_log` is still valid.
- Purpose (perf/correctness split, see xfs.md + state.md): unlink no longer
  does the eager per-ifree force+drain+flush (`mxfs.ifree_eager_durable=0`
  default); ifree and create instead queue this debounced (10ms) worker,
  which does one ASYNC `xfs_log_force(mp, 0)` + `xfs_ail_push_all` per
  batch so freed/created inode clusters reach the LUN within ~ms (the
  reuse-convergence machinery — VISNUDGE/iget-retry — assumes ms-scale
  destage; pure-lazy xfsaild left 30-55s gaps).
- PITFALL: a SYNC force here at 2ms cadence taxed the slowest node's own
  commit stream ~15% (dlm_scaling node1 rate 47/s vs floor 50) — keep the
  force async and the debounce ≥10ms.
- Queueing uses `queue_delayed_work(system_unbound_wq, ...)` (NOT
  mod_delayed_work: a pending timer must keep its deadline or storms
  starve the kick forever).

## sess9 (ccloop a8642ea1, 2026-07-11) — buffer event ring + shutdown withdrawal (v0.10.59-60, build CEB546B0)

### pal/linux/xfs_buf.c: per-buffer lifecycle event ring (v0.10.59, diagnostic)
`mxfs_buf_ev(bp, type)` (defined near the top, after the xfs_buf_submit fwd
decl) packs type|b_flags|sync_wait|force_sync|pid|~1ms-realns into a u64 and
stores it in `bp->b_mxfs_evring[bp->b_mxfs_evi++ & 7]` (fields in
xfs/xfs_buf.h next to the sess6 counters).  Event types (enum MXFS_BEV_*):
1 SUBMIT (at the sync_wait snapshot in xfs_buf_submit; force_sync bit =
pre-consume latch), 2 BIOEND (xfs_buf_bio_end_io), 3 IOEND (xfs_buf_ioend),
4 WORKER (xfs_buf_ioend_work), 5 EHERR (ioend_handle_error entry),
6 RESUB (its resubmit branch), 7 BIO (real bio issued — both in
xfs_buf_submit_bio and the partial-sector writer), 8 IOFAIL
(xfs_buf_ioend_fail), 9 IOWAIT (iowait got a completion token),
10 STALE (xfs_buf_stale).  P-IOWAIT-STUCK dumps the ring
(`ev=[8x hex]`, oldest→newest); decode with `scripts/decode_bufev.py`.
Purpose: name the exact ordered completion history of a wedge#2
(lost-wakeup) buffer — counters alone (ioend_seen/relse_seen) proved
insufficient in run 150528Z.

### pal/linux/xfs_buf.c: handle_error resubmit carries sync intent (v0.10.59)
`xfs_buf_ioend_handle_error` resubmit: sets
`bp->b_mxfs_force_sync = bp->b_mxfs_sync_wait` before `xfs_buf_submit` so an
error-retry of a sync submit cannot latch sync_wait=0 (latent hole; NOT the
run-59 trigger — zero I/O-error alerts that run).

### pal/linux/xfs_super.c: shutdown-withdrawal work lifecycle (v0.10.60)
- Mount (right after `mp->m_mxfs_dlm = mxfs_v5_dlm_init(...)` succeeds):
  `INIT_WORK(&mp->m_mxfs_withdraw_work, mxfs_dlm_withdraw_work_fn)`.
- Teardown ORDER at all three sites (put_super + out_filestream_unmount +
  out_unmount): save ptr, `mp->m_mxfs_dlm = NULL` FIRST (future withdraws
  no-op), `cancel_work_sync(&mp->m_mxfs_withdraw_work)`, then
  `mxfs_v5_dlm_shutdown(ptr)` — prevents the worker touching a freed ctx.
- The work is queued by `xfs_do_force_shutdown` (xfs/xfs_fsops.c) on the
  FIRST shutdown; worker runs `mxfs_v5_dlm_shutdown_withdraw` (dlm/v5_mount.c:
  sets ctx->withdrawn = acquire fence, stops disklock heartbeat so peers'
  dead-node purge reclaims our slots).  Rationale: run 150528Z r13 collapse —
  27 shutdown nodes kept contending the hot dir slot (CAS gen 512→130k) and
  one acquired the dir EX 6 minutes post-shutdown, starving survivors.

### pal/linux/xfs_buf.c: `mxfs_dir_wr_inflight_dec()` underflow-safe decrement helper (2026-07-11, interactive session, GPT-consult follow-up)

New static function, placed just above `__xfs_buf_ioend`. Replaces the two
previously-duplicated inline `atomic_dec_return(&mp->m_mxfs_dir_wr_inflight)
< 0 → atomic_set(...,0)` clamp sites (in `__xfs_buf_ioend` and the bmbt
`xfs_buf_xfsaild_skip_bmbt_write` chokepoint-skip path) with one shared
helper that also logs a new probe, `P-WRCNT-UNDERFLOW` (daddr/ops/flags/
event-ring), whenever the clamp actually fires. The old code silently
absorbed underflow; that could mask a genuine double-retirement (a leaked
completion on one submission of a reused buffer "recovered" by a second,
distinct submission's completion, then the original arriving late too) —
two decrements against one increment, silently clamped, would let the
dir-EX release fence (xfs_mxfs_dlm.c wr-barrier wait sites) see "0
in-flight" one write earlier than true. Purely additive/diagnostic —
does not change pass/fail behavior on its own. **First live test result
(build `1BAFC14435BA2FFEBEF0742`, 32-node dir_reuse_coherency@caw): zero
fires** — rules out this specific race for the hang observed that run,
not in general.

### IMPORTANT — the dir_reuse_coherency@32/caw wedge signature has moved (2026-07-11)

Every prior session (see the sess5-9 `xfs_buf.c` entries above, and
dlm.md/xfs.md) chased a stall in `xfs_buf_iowait` — a lost completion
wakeup at the xfs_buf layer, fixed through several iterations
(`b_mxfs_sync_wait` → `b_mxfs_force_sync` → the wr_inflight counter). The
same live test above caught `rm` stuck ONE LAYER DEEPER instead:
`xfs_vn_unlink → xfs_inactive → mxfs_dir_data_owner_scan → [mxfs] →
scsi_execute_cmd → __timer_delete_sync` (waiting on a concurrently-running
timer callback), captured via the test harness's new `run_bounded`
hang-detector (see tests.md). This is the same neighborhood as a
separately-discovered mass-unmount wedge (`blk_execute_rq`, both a
`umount` process and an `mxfs-worker` kthread stuck, 21/32 idle nodes, no
active workload — ccmemory `NEW-BUG-mass-unmount-blk_execute_rq-wedge-2026-07-11`).
Two different triggers landing in the same SCSI/block dispatch layer
strongly suggests one bug, not two, and that this layer — not xfs_buf
completion routing, which now looks closed (zero P-WRCNT-RESUBMIT/
UNDERFLOW/WRBARRIER-LONG fires) — is the current live bottleneck. Next
step here is a kprobe/kretprobe on `scsi_execute_cmd`/`blk_execute_rq`
callers and the timer callback they block on, not more xfs_buf
instrumentation. Full detail: ccmemory
`wedge-root-has-moved-to-scsi-layer-2026-07-11`.

### 2026-07-12 (ccloop3e02 sess2) — wedge#2a ROOT-CAUSED + FIXED: `b_sema` corruption from a completion-routing double-relse, not a "moved" wedge

The note directly above was **premature**: the very next session hit the
IDENTICAL `xfs_buf_iowait` stall (`mxfs_dir_data_owner_scan → xfs_bwrite →
xfs_buf_iowait`, same `xfs_dir3_data` daddr class) live, on the SAME build
lineage. The wedge is genuinely non-deterministic between the xfs_buf-level
and SCSI-level signatures (both real, both still possible) — "zero fires
this run" was never proof of closure, just proof that *particular* run's
race didn't land there. Lesson for future sessions: don't retire an
instrumented-but-unconfirmed hypothesis on a single clean run; the
underlying defect can hide for many rounds before resurfacing.

**Root cause, this time proven definitively (RULE 4, no guessing):** the
stuck buffer's `b_sema.count` — read LIVE out of the running kernel via a
`/proc/kcore` reader (no rebuild/reboot needed) — was **83**, not the
correct 0 (locked) or 1 (unlocked). Method, reusable for future live
kernel-struct inspection without kdump/drgn: `gdb -batch -ex 'print
(long)&((struct xfs_buf*)0)->b_sema' mxfs.ko` (and similarly for any other
field) against the exact deployed `.ko`'s DWARF debug info gives byte
offsets; a ~100-line Python script parses `/proc/kcore`'s ELF PT_LOAD
program headers to map a raw pointer (from a `bp=%p`-style dmesg print) to
a file offset and `pread`s the live bytes. `b_sema.count=83` means ~83 net
unmatched `xfs_buf_unlock()`/`xfs_buf_relse()` calls had accumulated on
that ONE buffer object over the test run, so `xfs_buf_lock()`/`trylock()`
no longer provided real mutual exclusion — this is WHY an unrelated
concurrent submitter (`xfsaild`'s async delwri push) could be "holding" the
same buffer at the same time as `mxfs_dir_data_owner_scan`'s synchronous
durable flush, a scenario that should be structurally impossible under an
intact semaphore. The sess6/8/9 fixes (`b_mxfs_sync_wait`, then
`b_mxfs_force_sync`) all patched *which branch* a completion takes but
never addressed that the routing itself could cause MORE `xfs_buf_relse()`
calls than there were lock acquisitions — each occurrence of the race
leaked +1 into `b_sema.count`, making the NEXT occurrence easier (self-
reinforcing — explains the "residual"/non-deterministic framing across
~9 prior sessions' fix attempts).

**The fix (KEEP — do not revert any part of it):**
- `xfs/xfs_buf.h`: removed `bool b_mxfs_sync_wait`. Added
  `atomic_t b_mxfs_sync_waiters` — an ADDITIVE credit incremented once per
  genuinely-synchronous `xfs_buf_submit` call, consumed by exactly ONE
  completion event regardless of how many unrelated submissions race on
  the same buffer object. `b_mxfs_force_sync` (bool) is unchanged —
  still the caller-side "this one's sync" latch consumed at submit entry.
- `pal/linux/xfs_buf.c`: new helper `mxfs_buf_completion_wake_sync(bp)`
  (`atomic_add_unless(&b_mxfs_sync_waiters, -1, 0)` then `complete()`,
  returns whether it fired) — call this FIRST in both completion routers
  (`xfs_buf_ioend`, `xfs_buf_bio_end_io`); if it returns false, fall
  through to the pre-existing flags-based (`XBF_ASYNC`) relse/complete
  decision unchanged. Also used in `xfs_buf_ioend_handle_error`'s
  "permanent error" branch, which previously called `xfs_buf_relse()`
  UNCONDITIONALLY — a second, independent source of the same double-relse
  class of bug (any repeated I/O error on a buffer with a pending sync
  waiter, no race with another submitter needed).
- `xfs_buf_submit()` is now a thin wrapper over a new
  `static void xfs_buf_submit_ex(struct xfs_buf *bp, bool fresh)`.
  `fresh=true` (the public wrapper, used by all 7 pre-existing call sites —
  `_xfs_buf_read`, `xfs_buf_readahead_map`, `xfs_buf_read_uncached`,
  `xfs_buf_delwri_submit{,_nowait,_nopinwait}`) registers a new credit.
  **`fresh=false` is ONLY for the `xfs_buf_ioend_handle_error` resubmit
  path** — a resubmit re-dispatches an ALREADY-credited operation (the
  original submit's credit was never consumed, since the error path
  bypasses normal completion routing entirely); registering a second
  credit there would leak +1 per retried I/O error, recreating the exact
  `b_sema` corruption this fix closes. **If you ever add a new
  `xfs_buf_submit`-adjacent call site, use the plain `xfs_buf_submit(bp)`
  wrapper (fresh=true) unless you are certain a credit for this exact
  operation is already outstanding.**
- `mxfs_buf_ev()`'s event-ring packing (bit 43) and the `P-IOWAIT-STUCK`
  probe's `sync_wait=` field now source from
  `atomic_read(&b_mxfs_sync_waiters)` (renamed `sync_waiters=` in the
  latter) instead of the removed bool — same wire format, `scripts/
  decode_bufev.py` needs no changes.

**Validated:** full 32-node/CAW `dir_reuse_coherency`, 24/24 rounds, zero
`P-IOWAIT-STUCK` / `has been shut down` / `EFSCORRUPTED` / `BUG:` for the
entire run — furthest any session has reached (prior attempts always
wedged by round 7-14). Full mechanism + kcore reader script description:
ccmemory `ccloop3e02-sess2-WEDGE2A-FIXED-full24round-clean-new-r18-undercount`.

**Separately** (not a pal/xfs_buf.c bug, noted here only for
cross-reference): once wedge#2a stopped masking it, the SAME run hit a
different, shallower bug at round 18 — a single durable lost dirent during
directory shortform→block(→leaf→node) conversion under concurrent
multi-node creates. That investigation and fix belong in `xfs.md` /
`dlm.md` (the affected code is `xfs/libxfs/xfs_dir2_*.c`,
`xfs/xfs_inode.c`, `xfs/xfs_inode_buf.c` — not `pal/`); see ccmemory
`ccloop3e02-sess2-INPROGRESS-r18undercount-instrumented-repro-launched`
for the in-progress state if picking that up.

### 2026-07-12 (ccloop e8e920f7 sess1, v0.10.65→0.10.66 = C5EF60D5) — b_sema POISONER found by new lock-integrity probes; fix was in xfs_mxfs_dlm.c, probes live HERE

The credit protocol above stopped the completion-router double-relse, but
`b_sema` poisoning kept recurring (+1 per dir-inode reload). v0.10.65 added
four ALWAYS-ON capped probes to `pal/linux/xfs_buf.c` / `xfs_buf_item.c`
that caught the remaining poisoner in ONE run (run65, storms by round 3):

- **`mxfs_buf_sema_dualock_check(bp, path)`** (~L1412; called from
  `xfs_buf_trylock` ~L1455 and `xfs_buf_lock` ~L1481): fires
  `P-SEMA-DUALLOCK` when a lock/trylock SUCCEEDS while the buffer already
  has another owner (`count` was already >0 pre-acquire shape) — catches
  multi-ownability at the moment it is exploited. Logs prev_owner_ip + the
  16-slot `mxfs_buf_ev` event ring. Cap 400, stack dump ×8.
- **`P-SEMA-OVERUP`** (in `xfs_buf_unlock`, ~L1515): fires when an unlock
  leaves `b_sema.count > 1` — the poisoning MOMENT (an up() with no
  matching down()). Same cap/stack policy. This is the probe whose stacks
  named the root: `xfs_buf_unlock ← mxfs_dir_evict_bmbt_blocks ←
  mxfs_dlm_reload_inode ← mxfs_dlm_ilock_begin ← xfs_ilock ←
  mxfs_dlm_dir_consumer_refresh ← xfs_lookup`.
- **`P-SYNCWAIT-OVERRIDE path=worker`** (~L2192): the ioend WORKER router
  (`xfs_buf_ioend_work`) now mirrors the ioend/bio_end credit protocol —
  an async-flagged worker completion consumes a pending sync waiter's
  credit and `complete()`s instead of relse'ing (third router, previously
  unmirrored).
- **`P-BLI-DOUBLEDONE`** (`xfs_buf_item.c` ~L1182): `xfs_buf_item_done`
  now claims the BLI via `xchg(&bp->b_log_item, NULL)`; the xchg loser
  logs and returns — permanently kills the double-item_done class
  (xfsaild NULL-relse oops + spurious "not in AIL" SHUTDOWN 0x8).
- **`P-WRCNT-RESUBMIT`** (~L1724 comment): double-submit detector on
  `m_mxfs_dir_wr_inflight` accounting (54× on run65's validate2).

**The ROOT those probes exposed was NOT in pal/**: two sess4(46efd8b6)-era
sites in `xfs/xfs_mxfs_dlm.c` (`mxfs_dir_evict_bmbt_blocks`,
`mxfs_dir_evict_bmbt_by_root`) did `xfs_buf_unlock(bp); xfs_buf_relse(bp);`
— and relse IS unlock+rele — so every EX reload of a btree-format shared
dir double-unlocked every held bmbt buffer. v0.10.66 removed the bare
unlock at both sites (see xfs.md). Validation: run66 + run67 = first two
consecutive dir_reuse_coherency@32/caw full passes (32/32, 24/24 rounds),
ALL probes 0 on all 32 nodes; further consecutive passes tracked in
criteria.json.

**Sweep tool:** `scripts/probe_sweep.sh <N>` (ccloop daf50d34 sess1)
greps all N node rings for P-SEMA-*/P-WRCNT-RESUBMIT/P-BLI-DOUBLEDONE/
SYSCALL_HANG/shutdown/BUG/Oops and exits 0 iff clean — run it after every
criteria run, BEFORE any VM recycle (ring dies on reboot).

## sess6 (ccloop 8ba7ae5c) — AG-meta read fence + fingerprint probes (v0.10.116-117)

**New in `pal/linux/xfs_buf.c`** (all multi-node gated on
`m_mxfs_dlm && !single_node`):

- **`mxfs_agmeta_ops(ops)`** (file-local, fwd-declared ~L90): classifier
  for AG allocation metadata buf ops — AGF/AGI/AGFL/bnobt/cntbt/inobt/
  finobt. Used by the fence and the write-completion stamp.
- **AG-meta write-completion stamp** (`__xfs_buf_ioend`, beside the
  per-buffer `b_mxfs_wr_flush_epoch` stamp): on successful WRITE of an
  AG-meta buffer, stamps `pag->pag_mxfs_meta_wr_epoch` (new atomic64 in
  `xfs/libxfs/xfs_ag.h`) with `m_mxfs_flush_epoch`. Rationale: the
  per-buffer epoch dies with buffer eviction; the per-AG stamp survives.
- **P143-AGMETA-FLUSHREAD fence** (`xfs_buf_read_map`, cold `!XBF_DONE`
  branch): if the AG's stamp >= current flush epoch (local AG-meta write
  completed into the LIO write cache with no device flush since), issue
  `mxfs_release_coalesced_flush(mp)` (xfs_mxfs_dlm.c — made NON-STATIC
  for this) BEFORE the read, so a cold FUA read can't return the
  pre-write media image ("time travel"). Print cap 60.
- **Readahead skip** (`xfs_buf_readahead_map`): hazardous AG-meta RA is
  skipped entirely — an async RA would populate the buffer DONE with a
  possibly stale image and the sync read would then bypass the fence.
- **P144-WR / P144-RD** (`mxfs_p144_print`, ~L95): always-on bnobt/cntbt
  content fingerprints — crc32c past the 56-byte v5 short-btree header
  (LSN/CRC excluded, so identical records hash equal across relogs) +
  numrecs/level/lsn/realns. WR at `xfs_buf_submit_ex` (beside P-DIRWR),
  RD at cold-read completion in `xfs_buf_read_map`. Joined offline per
  (agno,daddr) across node journals to decide writer-image vs
  reader-image identity. Cap 12000 shared.

**Pitfall hit:** an earlier P133 fix called `xfs_bwrite()` on a buffer
whose BLI was joined to the OPEN carve transaction — `__xfs_buf_ioend`'s
`xfs_buf_item_done` then AIL-deleted (not-in-AIL → log shutdown 0x8) and
freed the bli still linked in `tp->t_items`; the next
`xfs_trans_buf_item_match` walk spun forever (test30 soft lockup,
31-node ETIMEDOUT collapse). Rule: NEVER submit buffer I/O through the
xfs_buf path on a tx-joined buffer; use the raw SCSI passthrough
(`mxfs_pal_scsi_write_fua_bdev` + kmalloc bounce — vmalloc-backed
b_addr is not mappable by the passthrough). The carve-time sync init in
`xfs/libxfs/xfs_ialloc.c` now does exactly that.

**Cross-subsystem:** fence state lives in `xfs_perag`
(`pag_mxfs_meta_wr_epoch`, xfs_ag.h); the flush primitive + epoch are
dlm-owned (`mxfs_release_coalesced_flush`, `m_mxfs_flush_epoch`).
Status: the fence did NOT stop the iter_12/13 double-alloc (P143=0 at
reproduction) — iter_13's P145 free-trace (xfs/libxfs/xfs_alloc.c)
proved the reused block WAS freed; the live bug is dir-fork
shrink-resurrection (see xfs.md / sess6 memories). The fence stays as
cheap defense-in-depth for the eviction window it does close.
(Section written sess6, ccloop 8ba7ae5c; build 0.10.117/A3BD5947.)

## P150 READ-PRESERVE — inode-cluster read-side false-sharing fix (sess7, ccloop 8ba7ae5c, 0.10.119)

The read-side mirror of `mxfs_submit_partial_inode_write`.  PROVEN root of
the AG-x/agbno-295 dangling-extent double-alloc (iter_14 braid, ino
56623258): a cold DMA READ of an inode-cluster buffer that still had inode
log items attached (`b_li_list` non-empty) clobbered a just-iflushed dinode
image (dir block→shortform conversion, nx 3→0 chg 1922) with the platter's
pre-shrink bytes; xfsaild's queued delwri write then pushed the stale image
back to disk and the flush completion marked the inode clean — the shrink
existed nowhere but RAM, peers adopted the stale nx=3 map, and the freed
block's later legal reuse cross-linked two inodes (EFSCORRUPTED dir).
Upstream XFS never re-reads a cluster buffer with attached items; MXFS's
reload invalidation (stale → cold read for peer freshness) breaks that
invariant, so the read path must merge, not clobber.

Mechanics (`pal/linux/xfs_buf.c`):
- **Capture** (`xfs_buf_submit_ex` READ branch, after the P20 probe):
  multi-node inode-cluster read (`xfs_inode_buf_ops`/`_ra_ops`, single map)
  with attached items → snapshot `b_addr` (kmemdup) + slot mask of items
  whose `ili_inode->i_dlm_mode == MXFS_LOCK_EX` (EX-only: an attached NL
  item can be a P119-family ghost; restoring it would resurrect
  prior-tenure bytes over a peer's image).  Fields:
  `bp->b_mxfs_rd_preserve` / `b_mxfs_rd_preserve_mask` (xfs_buf.h).
- **Restore** (`__xfs_buf_ioend` READ branch, before `verify_read`): copy
  masked slots back over the DMA'd image (each slot is a complete iflush
  product with valid per-inode CRC → merged buffer verifies), free
  snapshot.  P150-RDRESTORE prints ino/mode/nx/chg/realns (cap 20000).
- Error path keeps the snapshot for the resubmit; freed at `xfs_buf_free`;
  cleared at `xfs_buf_stale` (incarnation end — must never restore into a
  reused buffer).
- Sibling merge in `mxfs_buf_coherent_reread_verify` (CRC-retry whole-copy
  path): EX slots merged from `b_addr` into the fresh snapshot before
  install (P150-REREAD-MERGE).

Validation: pre-fix repro ~1-in-2 (iters 10/12/13/14); post-fix iters
15/17/18/19 all corruption-clean (cc 3021/3021 32/32, static xref CLEAN,
uv extents=0 — the final shrink lands).  P150-RDRESTORE observed live
protecting the posix_multi dir (ino 12583068 nx=31) in iter_15.
Release-path diagnostics added same session (xfs_mxfs_dlm.c): P146-RELDUR
(durable-loop exit state), P147-PREUNLOCK (both unlock arms), P105 high-ino
arm un-ratelimited; P56-CORESIDENT-DIR-SKIP now capped+identity-carrying.

Amendment (0.10.120): P56-CORESIDENT-DIR-SKIP reverted to
`pr_warn_ratelimited` (keeping the sess7 identity fields: img_ino/img_nx/
img_chg/comm/realns).  The 0.10.118 capped-unratelimited variant printed
~75 lines/s/node in create/unlink storms and its printk cost alone pushed
dlm_scaling@32 below the 50 ops/s per-node floor.  Hot-path rule: anything
that can fire per partial-cluster WRITE stays ratelimited or param-gated.

## Buffer free-path guards + PAL thread-join semantics (0.11.7, ccloop 72513a13)

Two crash families root-caused from the 32-node direct-iSCSI (cawd) boards
landed guards/fixes in `pal/linux/xfs_buf.c` and PAL thread teardown:

- **Single free chokepoint invariant**: every `struct xfs_buf` free funnels
  through `xfs_buf_free()` → `call_rcu(&bp->b_rcu, xfs_buf_free_callback)`
  → the only `kmem_cache_free(xfs_buf_cache,...)`.  A double free therefore
  always means TWO `xfs_buf_free()` calls (test25 panic: BUG mm/slub.c:553
  in the RCU callback during 32-node dir_reuse churn; the same double
  call_rcu also corrupts the RCU list — post-rmmod callbacks into unloaded
  text are the SAME defect, not a missing rcu_barrier; exit_xfs_fs'
  barrier is present and ordered).
- **New guards (both in pal/linux/xfs_buf.c)**:
  - `xfs_buf_free()` tripwire: `b_mxfs_freeflag` bit 0 via test_and_set —
    second free logs `P-BUF-DOUBLEFREE` + dump_stack and returns (no-op).
    Field lives in xfs/xfs_buf.h; both alloc sites zalloc, so slab reuse
    starts clear.
  - `xfs_buf_rele_cached/_uncached` entry: `b_hold==0` ⇒ WARN
    `P-BUF-RELE-ZERO` + return.  Stops the zombie-rele wrap
    (0→0xFFFFFFFF) that resurrects a freed-pending buffer into a second
    free, AND the second perag-put/hash-remove side effects.
  - If either fires, that stack IS the RULE-4 evidence for the real
    producer.  Ranked suspects (agent-mapped, unproven): P-RAFIX hold
    steal in `_xfs_buf_read` (`stole_hold`, b_hold>1 heuristic); the
    3-router sync-credit completion protocol (`mxfs_buf_completion_wake_sync`,
    handle_error wake-vs-relse); stale `b_iowait` token.
- **PAL thread joins**: `mxfs_pal_thread_join_timeout()` on timeout leaves
  the kthread RUNNING and unfreed — callers must NEVER treat that as
  "done".  Its only caller (disklock stop_heartbeat, Bug 99) now escalates
  to a blocking `mxfs_pal_thread_join` after the 5s fast path: an abandoned
  kthread still executes module text and owns in-flight 512B heartbeat
  bios (`bdev_pipelined_read`, `mxfs_bio_end_io` = module text); rmmod
  then unmaps the text and the late completion crashes in bio_endio
  (recurring "Unable to access opcode bytes at 0xffffffffc1..." panics,
  4-20/node in serial logs, `end_clone_bio` frames on the mpath rig).
  Blocking join is bounded by the guest SCSI command timeout + EH.
- **Known latent (backlog, low)**: `build_bio()` first-page
  `bio_add_page` failure returns batch_len=0 → `bdev_pipelined_read`
  caller loops forever.  Not yet observed live.

## Fault-path cluster-ilock holds + buffer recycle discriminators (0.11.8-0.11.9, ccloop 72513a13 sess2)

### pal/linux/xfs_file.c — mmap faults must hold the cluster ilock (0.11.8)

**Invariant (new, load-bearing):** any path that LOCKS FOLIOS and then reaches
`xfs_ilock` (→ `mxfs_dlm_ilock_begin`) must already hold a COUNTED cluster
ilock.  The buffered read/write syscalls satisfy it via IOLOCK (both IOLOCK
and ILOCK map to the ONE per-inode cluster DLM lock; MMAPLOCK maps only to the
local `invalidate_lock` and counts NOTHING at the DLM).  mmap faults were the
only reader path violating it — filemap_fault adds folios LOCKED, then
`->readahead`/`->read_folio` → `xfs_read_iomap_begin` → ilock.  If the inode's
bast drain is running, that inner acquire sleeps on the drain while the drain
sleeps in `invalidate_inode_pages2 → __folio_lock` on the fault's own locked
folio: permanent local ABBA (proven live on test20, mmap_coherency 32/cawd:
P73-WAITSTALL state=DEMOTING work_busy=2 forever vs mxfs-ino-bast kworker in
folio_wait_bit_common; relatime atime-EX BASTs during the 32×32 cross-read
supplied the demotes; cascaded into AG AIL-push wedge + next chunk's fio
D-state).

Changes:
- `xfs_filemap_fault` (non-DAX): `mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR)`
  around `filemap_fault`, `..._end` after.  DLM only — taking i_rwsem in
  fault context would invert against write()'s rwsem→mmap_lock order.
- `__xfs_write_fault` (non-DAX): begin/end `MXFS_LOCK_EX` around
  `mxfs_iomap_page_mkwrite` (same inversion: iomap locks the folio then
  iomap_begin takes ILOCK_EXCL → cluster EX).
- Why safe: with holders counted, `bast_notify` DEFERS (sets ISTATE_BAST,
  queues NO work — xfs_mxfs_dlm.c ~15902); nested inner acquires admit via
  the FIX-1 / RELFLUSH arms; the last ilock_end refires the deferred
  release.  Folio locks still held when the hold drops resolve at read-bio
  completion (I/O-bound, DLM-independent).
- Watch-codes: P79-NESTADMIT with a faulting comm = fix engaging;
  P47-FILEBLOCK / P73-WAITSTALL from a fault comm = fix insufficient.

### pal/linux/xfs_buf.c — allocation-generation stamp + free-with-items tripwire (0.11.9)

For the dir_reuse@32 P113-DRAIN-WEDGE (dirty ILI stuck in AIL forever:
li_buf set, `b_li_list` EMPTY, `xfs_iflush_cluster` returns -EAGAIN with
zero per-item skips → suspected PREMATURE FREE + slab recycle of the
attached cluster buffer — the same hold-miscount family as the test25
double-free, but with no second free to trip the 0.11.7 tripwire):
- `_xfs_buf_alloc` stamps `bp->b_mxfs_alloc_gen` from a global monotonic
  atomic (field in xfs/xfs_buf.h).  `xfs_inode_item_precommit` records it
  in `iip->ili_mxfs_buf_gen` at li_buf attach (xfs/xfs_inode_item.{c,h}).
  At P113 wedge time the drain prints igen/bgen: MISMATCH ⇒ li_buf was
  recycled under the item.
- `xfs_buf_free()` now also screams (`P-BUF-FREE-WITH-ITEMS`, capped 6,
  dump_stack) when freeing a buffer whose `b_li_list` is non-empty — the
  attached items hold buffer references, so reaching the free with
  attachments means the hold count was corrupted.  The free is NOT
  suppressed (count says zero; suppressing would leak and hide the
  recycle evidence).
- Status: armed, not yet fired — dir_reuse@32/cawd passed 32/32 on the
  instrumented build (first ever); wedge seen once (0.11.8 board, all-32
  shutdown cascade).  If P113 recurs, igen/bgen + the free stack ARE the
  RULE-4 evidence.

### Cross-subsystem note (dlm, 0.11.10)
CAW grant waits (dlm/dlm_caw.c) now liveness-extend past the 120s base
timeout while every blocking holder heartbeats (oracle: v5_mount →
`mxfs_disklock_slot_live`), hard cap 480s (`MXFS_CAW_WAIT_HARDCAP_MS`).
-ETIMEDOUT therefore means dead-or-wedged holder, not "slow under load";
pal-level D-state waits up to 8 min are EXPECTED under saturation
(P-WAIT-EXTEND in dmesg names the episode).

### Addendum (0.11.11): close-release hook now fires for WRITE closes too

`xfs_file_release` (pal/linux/xfs_file.c ~1758) previously called
`mxfs_dlm_close_release(ip)` only for `!(f_mode & FMODE_WRITE)` (the
v0.10.36 read-once PR demote).  The gate is REMOVED — the hook now runs on
every last close and the DLM layer routes: read closes → the proven 2ms PR
demote; written-file closes → the NEW delayed EX demote
(`mxfs_dlm_queue_ex_demote` + `mxfs.ex_close_release_ms`, default 250ms,
xfs/xfs_mxfs_dlm.c ~27360).  Rationale (microbench 2026-07-18, 8/cawd):
a creator's cached EX on every fresh file made each first cross-node
stat/read pay a full on-demand handoff — 6.1ms avg, 33ms max, only
~0.8ms of it device time — the dominant term of dir_reuse's verify
phase.  With write-once demote, readers claim a free slot in ~1ms.
Pitfall encoded in the param comment: do NOT re-shape this into per-stat
timers (`pr_idle_release_ms` default was refuted at 32 nodes — timer storm
during the read phase); per-written-file-at-close, creator-only, is the
safe shape.  Status: built (0.11.11 srcversion 5621731E17F26DFAC3BCFB5),
not yet deployed/tested — next session validates on the 8/cawd rig.

### Addendum (0.11.12-0.11.15, sess3 ccloop 72513a13): xfs_buf.c P125 gating + demote outcomes

- **`P125-AG-DIVERGE` is no longer in the ungated corruption-canary set.**
  It reads the on-disk AG CAW slot (a probe-chain of FUA SCSI reads) on
  EVERY bnobt/cntbt/agf/agi buffer write in `xfs_buf_submit_ex` — kprobe
  attribution measured 5.3 FUA reads per file-create through xfsaild from
  this probe alone.  Now compiled behind `mxfs.p125_ag_diverge` (extern in
  xfs/xfs_mxfs_dlm.h, param in xfs_mxfs_dlm.c, default 0).  The divergence
  family it guarded (double-alloc root) was fixed by 0.10.120; re-arm the
  knob only when hunting AG exclusion divergence.  The p88 sibling probe
  stays as-is (gated by the rare nr<=2 empty-bnobt condition).
- 0.11.11 addendum outcome (validated sess3): write-once EX demote works
  (cross-node cold stat 6.1→4.4ms) but is NOT a dir_reuse round win — the
  release drain (~5-50ms, one per file, competing with the create stream)
  offsets it, and it made rm SLOWER until 0.11.15 suppressed close-demote
  for `i_nlink==0` files (unlinked files head straight to xfs_inactive,
  which wants the cached EX for ifree + slot tombstone).
- pal-adjacent perf context now documented in DLM_PLAN.md "ICLUSTER PLAN":
  per-file DLM device-op counts are the metadata-workload wall; the
  inode-cluster granularity pivot lives in dlm/ + xfs/, no pal surface
  change beyond what's listed here.

### Addendum (0.11.36-0.11.39, sess10 ccloop 72513a13): append-size pipeline probes + the write-unwritten clamp invariant

**Load-bearing invariant discovered (RULE-4 proven):** on this 6.19 base,
`xfs_setfilesize` (pal/linux/xfs_aops.c) is effectively DEAD CODE for
buffered appends.  `xfs_bmapi_convert_one_delalloc` maps data-fork
writeback extents as UNWRITTEN (`XFS_BMAPI_PREALLOC`), so every append
ioend is IOMAP_UNWRITTEN and the on-disk size advance happens ONLY in
`xfs_iomap_write_unwritten` (pal/linux/xfs_iomap.c ~700) via
`xfs_new_eof` — which CLAMPS to VFS `i_size`.  Consequence: anything that
shrinks VFS i_size while an append's conversion is pending (the mxfs
reload path's `i_size_write(VFS_I(ip), ip->i_disk_size)` re-sync did
exactly this on kept-in-core reloads) silently severs the append —
di_size never advances, writeback discards beyond-EOF pages, durable
size=0/nx=0 with sync(2) reporting success.  The fix lives in the xfs
subsystem (`mxfs_reload_size_keep=1`, xfs/xfs_mxfs_dlm.c ~19380); the
pal-side files carry the tripwires:

- `xfs_setfilesize` (xfs_aops.c): `P-SFS` print (cap 1500) on BOTH arms —
  including the isize=0 clamped no-op, which is the severing signature if
  a MAPPED-append path ever appears.  A full drc@32 run printing ZERO
  P-SFS is normal (see invariant above), not a probe failure.
- `xfs_end_ioend` (xfs_aops.c): `P-IOEND-ERR` (cap 300) — an errored
  ioend ends page writeback WITHOUT setfilesize and plain sync(2)
  swallows it; every such swallow is now loud.
- `xfs_iomap_write_unwritten` (xfs_iomap.c): `P-WU-CLAMP` (cap 300) —
  fires when the conversion covers bytes beyond di_size but xfs_new_eof
  refused the advance (VFS i_size below the written range) = the
  durable-short signature at the actual decision point.

No public API changes; all three are pure capped pr_warn probes.  Trace
chain for future size-loss triage: write → (delalloc) → writeback maps
UNWRITTEN → bio done → xfs_end_ioend → xfs_iomap_write_unwritten
(size advance, P-WU-CLAMP guard) → iomap_finish_ioends (page-WB end,
what sync waits on).  Cross-subsystem: the destage-side twin tripwire
`P-CCREGRESS` (di_changecount regression at iflush serialize) lives in
xfs/libxfs/xfs_inode_buf.c; cross-incarnation inode reuse fires it
benignly (gen-qualified reads required before treating as clobber).

### Addendum (0.11.40, 2026-07-20 interactive): update_time IOCB_NOWAIT gate fix + AGI-wedge known-open bug

**FIX (landed, verified) — `xfs_iops.c::xfs_vn_update_time`, `IOCB_NOWAIT`
check gate `6.15.0` → `6.90.0`.**  The non-SB_LAZYTIME `else` branch does
`#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,90,0) if (flags & IOCB_NOWAIT)
return -EAGAIN; #endif`.  The check belongs ONLY to the 3-arg
`->update_time(inode, enum fs_update_time type, unsigned int flags)` form
where `flags` genuinely carries IOCB_* bits — introduced upstream by commit
`761475268fa8` ("fs: refactor ->update_time handling"), first released in
**v7.0-rc1** (pinned via `git describe --contains` in `/src/linux`; matches
the sibling 3-arg-signature gates already in this function).  Before v7.0
(every kernel through 6.17.2) `->update_time` is the 2-arg `int flags` form
carrying **S_*** time bits, and **`S_VERSION == 8 == IOCB_NOWAIT (0x8)`**
(verified against 6.17.2-1-pve's real `linux/fs.h`: the S_ time flags are an
enum `S_ATIME=1, S_MTIME=2, S_CTIME=4, S_VERSION=8`).  A version-bumping write
passes `flags = S_MTIME|S_CTIME|S_VERSION = 0xE`, which the old `6.15.0` gate
matched against IOCB_NOWAIT and returned a spurious `-EAGAIN` to a BLOCKING
write.  RULE-4 proven (Proxmox 2-node): `fio_perf` recorded seqW=0/randW=0
because every O_DIRECT rewrite after `drop_caches` (which evicts the inode so
`file_modified` re-runs `->update_time`) EAGAIN'd here; fix → 110-154 MiB/s,
dir_reuse 11/11, full 2/tcp battery green.  Invisible on 6.8 (<6.15 =
compiled out), which is where the whole matrix was validated.  The VFS caller
`file_modified_flags` already returns `-EAGAIN` for a genuine IOCB_NOWAIT
write BEFORE calling `->update_time`, so the pre-v7.0 form must not repeat it.
**New invariant:** never test `flags & IOCB_NOWAIT` in the 2-arg
`->update_time` form — `flags` is S_* there and S_VERSION collides with
IOCB_NOWAIT's bit.  See ccmemory `pve-fio-odirect-write-eagain-after-dropcaches`.

**AGI-buffer umount wedge — ROOT-CAUSED + FIXED (2026-07-21).**  After a forced
shutdown (dirty `xfs_trans_cancel`, `xfs_create`→`xfs_dialloc`), `umount` hung
forever in `xfs_buftarg_drain` on AG-alloc-meta buffers stuck at `b_hold=2`
(`xfs_agi` daddr=2, `xfs_inobt` 24, `xfs_finobt` 32; flags
`XBF_ASYNC|XBF_DONE|_XBF_KMEM`, no bli, pin=0, not delwri).  GPT's a-priori
`xfs_trans_bhold` guess was WRONG; the instrument found the real culprit.

- **New instrument (permanent, toggleable) — per-buffer HOLD/RELE ring.**
  `MXFS_HOLD_TRACE` toggle + `struct mxfs_hold_evt` + `b_mxfs_hold_ring[32]` in
  `xfs/xfs_buf.h`; recorder `mxfs_hold_ev(bp, site, delta, caller)` in
  `pal/linux/xfs_buf.c`, called at ALL 8 `b_hold` mutation sites (alloc,
  `xfs_buf_try_hold`, `xfs_buf_hold`, stale-LRU-drop, RA-orphan-drop,
  `xfs_buf_rele_uncached`, `xfs_buf_rele_cached`×3).  Dumped as **P-HOLDRING**
  (site + `%pS` caller + hold_after) at the P-DRAINSTUCK drain-stuck site in
  `xfs_buftarg_drain_rele`, once per buffer, globally capped.
- **API change (pal-internal):** `xfs_buf_rele_uncached` / `xfs_buf_rele_cached`
  now take an extra `unsigned long caller` (the external `_RET_IP_` captured in
  `xfs_buf_rele`) so the ring names the real releaser, not the dispatcher.
- **INVARIANT confirmed:** every `b_hold` mutation is under `bp->b_lock` (except
  the single-threaded `_xfs_buf_alloc` init) — so the ring is written under
  b_lock with no extra locking / no torn entries.
- **PROVEN root cause:** the leaked ref is the extra `xfs_buf_hold` taken by
  `mxfs_ag_meta_track` (xfs_mxfs_dlm.c) on every logged AG-meta buffer.  Its ONLY
  releaser is `mxfs_dlm_ag_meta_iodone`, installed as `b_iodone` — and `b_iodone`
  is invoked at EXACTLY ONE site, `__xfs_buf_ioend` (`xfs_buf.c:2507`), i.e. only
  on writeback completion.  On forced shutdown the dirty AG-meta buffers are
  aborted WITHOUT writeback: `xfs_buf_item_release`'s `(aborted ||
  xlog_is_shutdown)` branch (`pal/linux/xfs_buf_item.c:832`) detaches the bli via
  `xfs_buf_item_done`, which never runs ioend → iodone never fires → the hold +
  `pag_dlm_meta_pending` leak forever.
- **PITFALL (this doc's files):** the `xfs_buf_item_release` abort branch and the
  `xfs_buf_item_unpin` STALE branch detach the bli with NO ioend, so ANY cleanup
  keyed on `b_iodone` leaks there.  (The unpin `remove` branch is safe — it calls
  `xfs_buf_ioend_fail` → ioend → iodone.)
- **FIX (one-shot ownership token — GPT "consumed once by completion-OR-abort"):**
  `mxfs_ag_meta_track` arms `atomic_t bp->b_mxfs_agmeta_hold=1`; consumed
  (`cmpxchg 1→0`) by exactly one of `mxfs_dlm_ag_meta_iodone` (writeback) or the
  new `mxfs_ag_meta_reclaim_abort(bp)` — **called from `pal/linux/xfs_buf_item.c`'s
  abort branch** to drop the hold + dec pending when the bli detaches without
  writeback.  Logs **P-AGMETA-RECLAIM** when it fires.  Cross-subsystem: pal
  buf-item teardown now calls into the xfs AG-meta DLM tracking.
- **DO NOT** force-relse in `xfs_buftarg_drain` (double-free/UAF) — fix stayed at
  the owning path.
- **STATUS:** builds clean (`D1DA64…`); one natural post-shutdown umount completed
  cleanly (0 P-DRAINSTUCK).  Definitive deterministic A/B (GOINGDOWN-mid-churn,
  `scripts/agi_wedge_verify_det.sh`) PENDING — blocked by pve1 hung on `sysrq-b`
  (HP Z400, no iLO; needs manual reset).  See ccmemory
  `pve-agi-wedge-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung`.

**P144 btree fingerprint extended to the inode btrees (2026-07-24, ccloop-4dd7).**
The always-on multi-node content fingerprint (`mxfs_p144_print`: crc32c of the
short-btree body past the 56-byte header, emitted as `P144-WR` at write
submission and `P144-RD` at cold-read completion) now covers **all four
short-form AG btrees**.  New helper `mxfs_p144_ops(ops)` (static inline, top of
`pal/linux/xfs_buf.c`) gates both call sites; the tag prints
`bnobt|cntbt|inobt|finobt`.  Two new externs: `xfs_inobt_buf_ops`,
`xfs_finobt_buf_ops`.  Purpose: the inobt double-free corruption campaign — an
offline realns-ordered join of both nodes' `P144-WR`/`P144-RD` per
(agno,daddr) decides whether a reader's first post-handoff image matches the
writer's last write (reader-served-stale vs writer-destaged-late).  Measured
rate at 2/tcp churn: ~1400-1900 inobt WRs vs only ~120 cold RDs per 180s round
— cold re-reads are RARE, so cached-buffer staleness across AG handoffs
dominates; see ccmemory `ccloop4dd7-sess1-C-inobt-divergence-root-lead`.

**Cross-subsystem note (same campaign, consumer of pal's stamps):** every
`P150-*` inobt record-RMW probe line (xfs/libxfs/xfs_ialloc.c) prints this
file's per-buffer coherency stamps — `btenure` = `bp->b_tenure_id` (stamped
MODIFY-time by `mxfs_ag_meta_track`), `bgen` = `bp->b_mxfs_ag_gen` (stamped
ONLY on the FUA-read success path here, ~line 6458).  **Pitfall proven this
session:** `bgen==0` on every inobt RMW = those buffers never travelled the
FUA path, so any coherency logic keyed on `b_mxfs_ag_gen` is inert for them on
the tcm_loop/TCP rig.

**Busy-extent duplicate guard (2026-07-24, `xfs/xfs_extent_busy.c` — noted here
because the failure presents as a pal-level wedge):** upstream
`xfs_extent_busy_insert_list` on an EXACT-duplicate `bno` hits `ASSERT(0)`
(no-op in production) and then **never advances `*rbp` → infinite loop holding
`eb_lock`** — observed as a 2-CPU soft-lockup (insert spinning; `xlog_ioend_work
→ xlog_cil_committed → xfs_extent_busy_clear` spinning behind it), wedging the
node hard enough that the peer's DLM requests time out (184s) and IT shuts
down.  Now logs `P-BUSY-DUP` and bails without inserting (`P-BUSY-OVERLAP`
ratelimited for partial overlaps).  A duplicate insert = the same extent freed
twice in-flight on one node — the cross-node stale-map double-free family; the
probe exists to catch the producer.

**New PAL API: `mxfs_pal_dump_task_stack(int pid)` (2026-07-24, ccloop-4dd7
sess4; `pal/linux/kern.c` next to `mxfs_pal_dump_stack`, declared in
`pal/pal.h`, EXPORT_SYMBOL_GPL).**  Dumps ANOTHER task's kernel stack by pid
(rcu pid lookup + task ref + `sched_show_task`; pid 0/gone = no-op; needs
`<linux/sched/debug.h>`, added to kern.c includes).  Safe from process/work
context.  Consumer: `xfs_mxfs_dlm.c` P36-EXH-STACK — when the inode-DLM demote
dwork has been refused >200 strikes by a live EX admission, the stamped holder
(`i_dlm_exh_pid`/`_comm`/`_since_ns`, new diag fields in `xfs/xfs_inode.h`,
stamped at every `i_dlm_ex_holders` 0→1 site) gets its stack dumped, which is
how the b58r1/b61r6 184s dual-shutdown root was proven (writer parked on
i_rwsem while holding the DLM admission → xfs_ilock lock-order fix v0.11.62).
Pitfall: the dump output (`task:... state:D` + trace lines) lands in dmesg —
any test that greps dmesg for error patterns (e.g. criteria `soak`) may count
these diagnostic lines as hits; scope/gate accordingly (open item, sess4 end:
soak FAILed with 833 dmesg hits on an otherwise-clean build/boot).

**P110-BIO-OVER-LOGGED re-armed, undestaged-gated (2026-07-24 sess4,
`pal/linux/xfs_buf.c` ~8395, v0.11.61+63).**  The sess122 blanket LOG-ONLY
disable of the AG-meta plain-bio read interlock was itself proven a corruptor:
b60r2 `i != 1` (read DMA'd platter cntbt over PINNED in-CIL records, same task,
500µs before the shutdown).  The keep action is back, gated on
`mxfs_buf_is_undestaged(bp)` (NOT the broad `mxfs_buf_has_uncheckpointed_mods`)
— refuses the DMA and completes the read in place (`XBF_DONE` + `xfs_buf_ioend`,
mirrors the active sess61 bmbt guard below it) ONLY for pinned /
committed-unwritten buffers; destaged-lingering BLIs still read-proceed
(preserves the sess122 cache_coherency fix).  The print now includes
`undest=%d` and names the arm taken.  CRITICAL cross-subsystem dependency: the
gate's strength comes from the v0.11.63 `mxfs_buf_is_undestaged` fix
(xfs/xfs_mxfs_dlm.c) — a live BLI that is unpinned and NOT in the AIL (the
async CIL→AIL callback window) now reports undestaged; before that, b62r4's
bnobt slipped through this guard as `undest=0` mid free-chain and the platter
re-read reverted a committed free (the durable bnobt/cntbt divergence root).

## sess5 (ccloop-4dd7) — s_remove_count shadow-ledger hooks in the PAL glue

Context: root #6 (the suite-soak "833 dmesg hits" WARN storm) was an
`sb->s_remove_count` underflow.  The ledger core lives in xfs/xfs_inode.h
(`MXFS_IF_RMC_ACCT` flag bit 23 + `mxfs_set_nlink`/`mxfs_drop_nlink`/
`mxfs_inc_nlink` wrappers); the PAL owns the two VFS boundary points:

### pal/linux/xfs_super.c — destroy-side verifier
- `xfs_fs_destroy_inode()` now checks, for every `i_nlink == 0` destroy,
  that `MXFS_IF_RMC_ACCT` is set — i.e. the `__destroy_inode()` dec that
  just ran (VFS calls it immediately before this sop) was paired with an
  accounted 0-edge.  Unpaired → capped `P9-RMC-UNPAIRED-DESTROY` pr_alert
  + dump_stack with `last0=`/`lastclr=` provenance (%pS of the last
  0-install / last flag-clear, stored in `ip->i_rmc_last0_ra` /
  `i_rmc_lastclr_ra`).  It then CLEARS the flag and stamps lastclr — this
  is load-bearing, not just diagnostic: a recycled corpse must present
  flag=0 so `xfs_reinit_inode`'s re-inc (set_nlink(0) after the raw
  __i_nlink=1 from inode_init_always) re-arms it correctly.
- Pitfall: `destroy_inode()` runs `__destroy_inode()` BEFORE the sop, so
  this hook can only verify/clean up after the dec — it cannot prevent it.
  Prevention lives in the wrappers' corpse-raw arm (I_CLEAR inodes adopt
  nlink raw; see xfs.md sess5 entry).

### pal/linux/xfs_iops.c — tmpfile accounting seam
- The O_TMPFILE dance (`xfs_generic_create`) converted to
  `mxfs_set_nlink(ip, 1)` before `d_tmpfile()`.  d_tmpfile internally
  calls drop_nlink (VFS code, invisible to the xfs wrappers) taking
  i_nlink back to 0 and INCrementing s_remove_count — so the code
  re-arms `MXFS_IF_RMC_ACCT` + stamps `i_rmc_last0_ra` right after
  d_tmpfile returns when i_nlink==0.  Without this, every tmpfile evict
  or linkat would report a false unpaired dec.
- Pitfall for future edits: any OTHER VFS helper that changes nlink
  outside the xfs wrappers (d_tmpfile is the only known one) needs the
  same flag resync at the call site.

### Cross-subsystem contract
- Flag writers/consumers span three subsystems: libxfs (from_disk, init,
  droplink/bumplink), xfs (reinit, reset4create, the corpse-raw rule),
  and these two PAL files.  The invariant: at any instant, flag set ⇔
  this inode's current nlink-0 state contributed +1 to s_remove_count.
  A skewed counter is user-visible: `sb_prepare_remount_readonly` returns
  -EBUSY whenever s_remove_count != 0, and a NEGATIVE counter WARNs at
  fs/inode.c:289 once per unlink+destroy pair (exactly one line per op —
  the soak failure signature).
- `xfs_inode_free` (xfs/xfs_icache.c) carries the armed DISCARD-LEAK
  tripwire for the upstream-inherited +1 leak (from_disk incs, then
  iget error path frees with no destroy dec).  Never observed live;
  do not "fix" it without a P9-RMC-DISCARD-LEAK observation (RULE 4).

## v0.11.74-75 additions (2026-07-24, physical QNAP campaign)

### kern.c
- `mxfs_pal_scsi_pr_unregister_bdev(struct block_device*, key)` (decl in
  xfs_mxfs_dlm.h, local redecl in kern.c per the read_fua_bdev pattern):
  raw-bdev PROUT unregister for the deferred umount path — the scsipr ctx's
  own bdev clone is closed by v5 shutdown before the late unregister runs,
  so it goes through mp->m_ddev_targp->bt_bdev. Treats RESERVATION CONFLICT
  (0x18/-EBUSY) as success (key already gone = desired outcome).
- `mxfs.dbg_pr_register_fail` one-shot module param: fails the next PR
  REGISTER (in `mxfs_pal_scsi_pr_register`, after the pr_ops check) to
  verify the TCP-branch mount-abort. Never enable in production.

### xfs_super.c — put_super teardown ORDER INVARIANT (do not regress)
`xfs_fs_put_super` sequence is now:
1. `pr_late_key = mxfs_v5_dlm_detach_pr_key(v5dlm)` — detaches the scsipr
   ctx from the v5 ctx (dlm/v5_mount.h API) so `mxfs_v5_dlm_shutdown` skips
   PR teardown entirely (its `if (ctx->scsipr)` block no-ops).
2. `mxfs_v5_dlm_shutdown(v5dlm)` — unchanged otherwise.
3. `xfs_unmountfs(mp)` — writes the unmount log record.
4. `if (pr_late_key) mxfs_pal_scsi_pr_unregister_bdev(...)` — the PR key is
   unregistered ONLY NOW, after the unmount record is on disk and before
   `xfs_shutdown_devices` closes the bdev.
WHY: unregistering inside v5 shutdown (the old order) fenced the node's OWN
final log write on WE-RO-enforcing targets whenever a peer still held the
reservation — EBADE → log-error shutdown on EVERY clean non-holder umount,
unmount record lost, dirty slice recovered on next mount (QNAP physical rig,
3/3 repro; fixed and verified 0/7 with recovery drained across all slices).
Mount-FAILURE error paths (xfs_super.c:2797/2824) intentionally keep the
old inline shutdown behavior — no unmount record exists to protect there.
Cross-subsystem: pairs with dlm-side `mxfs_scsipr_key/abandon` (scsipr.h)
and `mxfs_disklock_release_slot` (see dlm.md same-date section).

## v0.11.77 (D9) — envelope mount is fail-closed (2026-07-25)

`xfs_fs_fill_super` (pal/linux/xfs_super.c): `m_mxfs_has_envelope` +
`mxfs_v5_dlm_init` NULL ⇒ `xfs_alert` + `error = -ENOTCONN` +
`goto out_filestream_unmount`. The removed "MXFS DLM init failed (continuing
single-node)" fallback let two nodes mount one LUN uncoordinated (observed).
Repair tooling works on the unmounted device; a legitimate single-node mount
is a SUCCESSFUL 1-node DLM init, never a failed one. Verified via
`mxfs.dbg_pr_register_fail` injection: armed → mount(2) fails ENOTCONN clean.

### D9 unwind + put_super interplay (constraints proven this session)

- The D9 abort uses `goto out_filestream_unmount` from the DLM-init site —
  safe there because the adjacent zoned/reflink error paths use the same
  label and `m_mxfs_dlm` is NULL on this path (the label's DLM teardown
  block self-gates). Verified live: armed injection → clean mount(2)
  failure, node stable, subsequent mount succeeds.
- Teardown order (unchanged, still load-bearing): put_super runs
  `mxfs_v5_dlm_detach_pr_key` BEFORE `mxfs_v5_dlm_shutdown`, and the final
  PR unregister via `mxfs_pal_scsi_pr_unregister_bdev` AFTER
  `xfs_unmountfs`. The v5 shutdown itself now broadcasts the D6 goodbye
  (dlm.md v0.11.79) between release_all and peer teardown — no pal-side
  ordering change, but any future put_super reshuffle must keep goodbye
  after the final log write path.

## v0.11.87-93 (FIX-26) — writepages admit registry + collision instrumentation (2026-07-25, sess6)

`pal/linux/xfs_aops.c`:

- **FIX-26 registry**: `xfs_task_in_writepages()` — global 64-bucket
  hashtable of `struct xfs_wptask` nodes keyed by task pointer; nodes are
  STACK-RESIDENT in `xfs_vm_writepages` (zero allocation), added before and
  removed after the `iomap_writepages` call on both the <6.17 and >=6.17
  branches.  Decl lives in `xfs/xfs_aops.h` next to `xfs_task_in_ioend`.
  Consumer: `mxfs_ilock_admit_ioend` (xfs_mxfs_dlm.c) now admits
  writepages tasks through the BAST/DEMOTING demote-wait under a
  still-granted EX/PR mirror — same nested-EX/ex_holders contract as the
  FIX-25 ioend admit (release pipeline aborts at its holders!=0 gate and
  re-arms).
- **Deadlock anatomy this closes** (test8, live, wedge persisted 70+ min
  and poisoned every subsequent run via `sync` hanging behind the dead
  flusher): flusher holds folio lock in `iomap_writepage_map` →
  `xfs_bmapi_convert_delalloc` → `xfs_ilock(EX)` parks (state=BAST,
  P73 `req=5 mode=3 work_busy=3`); bast worker's
  `filemap_write_and_wait` blocks in `__folio_lock` on that folio.
- **fix26_delay_ms** (module param, 0644, default 0): in
  `xfs_convert_blocks`, wait up to N ms — 1 ms granularity, exits the
  moment `i_dlm_state` leaves CACHED — before the conversion, folio held.
  Demoter-exempt so the injection can never stall the drain itself.
  P26DBG-INJ (cap 40) prints st0/md0→st1/md1 + waited_ms + wp flag.
- **P26PRE-DELALLOC-SUBEX** (cap 200): writeback converting delalloc at
  `i_dlm_mode < EX`.  Fields: mode/state/relflush/stale/demoter/dem_cur/
  exh/prh/pin/wp/comm.  First harvest: all events were `mode=0
  relflush=1 demoter=1` = bast_process's own drain flush after its early
  mode pre-clear (xfs_mxfs_dlm.c ~12350-12390) — NORMAL.  Watch
  `dem_cur=0`.
- Pitfalls: `MXFS_LOCK_*` needs `<mxfs/mxfs_dlm.h>` explicitly;
  `conv=notrunc` rewrites produce NO delalloc (exerciser must
  truncate-reallocate); mode==EX bast collisions are served by the
  fast path BY DESIGN (only sub-EX requests park in the demote-wait).

## v0.11.95-98 — FENCE-V1 submit-site dir-block write fence (ccloop c7ee71c6 sess7, 2026-07-25)

`pal/linux/xfs_buf.c` — `xfs_buf_submit_ex`, right after the P122
stale-AG-write act block:
- **P123 dir-block write fence**: for multinode XBF_WRITE submissions of the
  six dir metadata ops (dir3 block/data/leaf1/leafn/free + da3_node), the
  owner ino is read from the block header and
  `mxfs_v5_dlm_inode_granted_mode(owner) < MXFS_LOCK_EX` classifies the
  write.  No log obligation (no bli-dirty, not IN_AIL, unpinned) →
  SUPPRESS: `P123-DIRFENCE-SKIP` + (bli-free) `xfs_buf_stale` + ~XBF_DONE,
  then `xfs_buf_ioerror(bp,0)+xfs_buf_ioend` (complete-as-success, the P122
  idiom — wseq stamps at ioend so release loops converge).  Obligated →
  ALLOW + `P-FENCE-AILLEAK` census.  `bp->b_mxfs_fence_skipped` records the
  verdict for `mxfs_dir_flush_one_daddr`'s FUA arm (xfs.md same-date entry).
  Sanction query `mxfs_task_in_dir_drain()` is attribution-only (v1.1).
  Fail-open when the owner is unresolvable; `_XBF_LOGRECOVERY` exempt.
  First 5 suppressions per boot dump_stack for producer attribution.

## sess10 (ccloop c7ee71c6, 2026-07-26, v0.11.104-108) delta
- xfs_super.c mxfs_drevalidate affine own-AG fast path: P165-AFFINE-STALE probe (cap 100000)
  logs epoch-mismatched positive-dentry blessings — path is epoch-blind by design; ~40/run/node,
  benign so far, harden only with evidence.

## sess13 (ccloop c7ee71c6, 2026-07-26, v0.11.115-117) delta
- xfs_buf.c write-submission (~7730, next to P144-WR): P170-CLWR — inode-CLUSTER write
  provenance (per-write daddr + every slot's ino:mode:gen-tail + comm + realns; cap 800
  always-on, uncapped under mxfs.instr). Built for the D3 co-resident stale-slot clobber
  (32/caw cache_coherency). NOTE: dirwr>=1 printk tracing SUPPRESSES the D3 race (4/4 hits
  untraced vs 0/3 traced) — session-14 needs an in-memory ring instead for dir-block writes.

## sess14 (ccloop c7ee71c6, 2026-07-26, v0.11.118-131) delta — xfs_buf.c

### New: P172-WRTR non-perturbing write-provenance ring (~3430, after mxfs_dir3_data_fingerprint)
- `mxfs_wrtr_record(bp)` (static) + `mxfs_wrtr_dump(void)` / `mxfs_wrtr_dump_auto(void)`
  (both EXPORTED — called from xfs_mxfs_dlm.c's `dirring_dump` module param and from
  xfs_inode.c at P26-IGET-FAIL respectively).
- 8192-entry static ring, ~64B/entry. Records EVERY dir-metadata + inode-cluster write
  submission on a multi-node mount from `xfs_buf_submit_ex` (call site sits right after
  P170-CLWR): daddr, owner ino, live-dirent/allocated-slot count, slot masks (cluster:
  dirmask<<32|allocmask; dir: inum sum<<32|xor), lineage crc32c (past the 48B hdr for dir
  blocks, whole buffer for clusters), DLM granted mode, buffer flags, comm/pid, realns.
- **WHY memory-only:** sess13 proved printk at the dir write path SUPPRESSES the D3 race
  (4/4 hits untraced vs 0/3 with dirwr>=1). Never add a printk to this path to debug it.
- Dump: `echo 1 > /sys/module/mxfs/parameters/dirring_dump` per node, or auto (hard-throttled,
  max 4/boot, 120s apart) on P26-IGET-FAIL. Merge nodes with `tests/d3_ring_analyze.py`;
  `tests/d3_dirring.sh` runs the repro recipe and harvests automatically on failure.

### New: P56-NL-LOGGED-DIR-SKIP in mxfs_submit_partial_inode_write (~3101)
- The co-resident cluster-write filter's legacy rule was "slot logged/buf-dirtied THIS round
  => ALWAYS write", evaluated BEFORE the NL/free guards. PROVEN byte-exact to cause durable
  loss: a node published a DIRECTORY slot image from a PRIOR tenure after going NL, reverting
  the platter (7 names -> 3) and erasing 4 peers' files permanently.
- Now a DIR slot is skipped when the in-core grant is NL **and we do not hold the
  publication token** `MXFS_IF_DLM_RELFLUSH`. Param `mxfs.dir_nl_logged_skip` (default 1).
- **INVARIANT (learn this before touching the filter):** `MXFS_IF_DLM_RELFLUSH` is the only
  valid post-demote publication authority — it is set solely across the sanctioned release
  drain, during which the on-disk DLM grant is STILL HELD (xfs_inode.h:585,
  xfs_mxfs_dlm.c:23160), so no successor EX can exist and publishing is safe. Anything else
  writing a dir slot at NL is a background flusher racing the current owner.
- **PITFALL (cost two deploy cycles):** two other discriminators were tried and REFUTED.
  (1) Skipping every NL dir slot stranded a freshly created dir — its landing legitimately
  happens after demote — leaving the platter slot FREE, the dir invisible cluster-wide, and
  the creator poisoning its own inode (permanent ESTALE). (2) Gating on the dir epoch is
  useless here: after release the local DLM resource view is dropped and
  `mxfs_v5_dlm_inode_dir_epoch()` returns 0, silently disabling the guard.
- **A publish-side filter cannot repair a poisoned RMW base.** When this filter's token check
  showed the reverting writes carried `relflush=1`, that proved the image itself was already
  wrong and the real defect was acquire-side (fixed in xfs/ as P174-STALEGEN-ADOPT). Check
  `dgen` vs `lgen` before designing any new write-side guard.

### Extended: P56-DIRWRITE trace (~3116)
Now prints `relflush= dgen= lgen= vep= sfc= comm=` alongside the shortform name list. These
fields are what made the acquire-side root visible (`mode=0 relflush=1 dgen=8 lgen=5` = an
authorized drain publishing a fork never rebuilt across 3 generations of peer changes).
Merge across nodes by realns to get the cluster-wide publish ledger.

### sess14 CLOSING lesson for anyone touching the cluster-write filter
The write-side guards in `mxfs_submit_partial_inode_write` (P56-NL-LOGGED-DIR-SKIP and
friends) are **assertions, not the fix**, and must stay that way. Four predicates were built
and refuted in one session trying to make this filter decide correctness on its own:
1. skip every NL logged DIR slot -> stranded a freshly created dir (permanent ESTALE);
2. gate on dir epoch -> `mxfs_v5_dlm_inode_dir_epoch()` returns 0 after release, guard dead;
3. gate on `i_mxfs_self_created` -> heuristic about peer *interest*, not about successor
   images (cold LUN reads never BAST, so the flag stays true on genuinely shared dirs);
4. compare shortform fork content in the release drain -> defect recurred with 0 fires.
Root reason they all fail: at write time the buffered image may ALREADY be a poisoned RMW
base, and every locally available signal (dirty flags, AIL membership, header equality,
content equality) reads identical whether or not a committed change is still owed. The
correct mechanism lives in xfs/ (per-inode pending-vs-durable publication obligation +
land-before-release), not here. Before adding any new predicate to this filter, read
ccmemory `ccloop-c7ee71c6-sess14-J-P175-REFUTED-obligation-tracking-required`.

**Cross-subsystem note:** this filter's only valid post-demote authority is
`MXFS_IF_DLM_RELFLUSH` (set in xfs/xfs_mxfs_dlm.c across the release drain, during which the
on-disk grant is still held). Anything else publishing a dir slot at NL is racing the
current owner. The P56-DIRWRITE trace now prints `relflush=`, `dgen=`, `lgen=` precisely so
that distinction is visible in a merged cross-node ledger.

## sess22 (ccloop c7ee71c6, 2026-07-29, v0.11.175-178) delta — xfs_super.c

### NEW internal function: `mxfs_report_residual_inodes(struct xfs_mount *mp)`

`static` in `pal/linux/xfs_super.c`, called from `xfs_kill_sb()` immediately
**before** `kill_block_super(sb)`.  Not part of the PAL surface — it is a
diagnostic for one specific defect and deliberately has no header declaration.

Walks every perag's `pag_ici_root` radix tree (RCU read side only, batches of
32, `radix_tree_gang_lookup`) and emits `P199-UNMOUNT-RESIDUAL-INODE` for each
inode whose `i_count > 0`, with the DLM bookkeeping that could explain a
retained reference: `dlm_mode`, `dlm_state`, `ex_holders`, `pr_holders`,
`dlm_pin_count`, `bast_pending`, `unpublished`, `i_flags`, `pincount`,
`in_ail`.  Caps printing at 16 inodes and finishes with
`P199-UNMOUNT-RESIDUAL-TOTAL in_tree=N still_referenced=M`.

**Why it exists** — the defect it serves (`D-UNMOUNT-BUSY-INODES` in
`tests/criteria/OPEN_DEFECTS.json`), captured on test9:

    WARNING at fs/super.c:649 generic_shutdown_super   (umount -> xfs_kill_sb)
    kmem_cache_destroy mxfs_inode: Slab cache still has objects
        when called from xfs_destroy_caches+0xc2/0x140 [mxfs]
    Slab objects=18 used=1        -> exactly ONE mxfs_inode survives
    node taint -> G B W OE

The kernel's own warning fires inside `generic_shutdown_super` and names
nothing — no inode number, no state.  A leaked slab cache is a use-after-free
hazard for the next `insmod`, so the survivor has to be identifiable.

### PITFALL — this probe runs BEFORE the VFS evicts, so its output is NOT a leak

`generic_shutdown_super()` does `shrink_dcache_for_umount()` then
`evict_inodes()`.  `xfs_kill_sb` runs before both, so at P199 time the ICI
radix tree legitimately still holds every cached inode and plenty of them have
`i_count > 0`.  **Measured baseline on a healthy 32-node unmount: 770
`icount=0`, 216 `icount=1`, 32 `icount=2` (one per node — the mount root), and
ZERO VFS warnings.**  Every referenced one was `dlm_mode=3 (MXFS_LOCK_PR)
dlm_state=1 (MXFS_DLM_ISTATE_CACHED)`, which is normal, not evidence.

So P199 is **forensics for when the VFS warn fires**, never a leak detector on
its own.  Read it only alongside a `fs/super.c` `generic_shutdown_super`
warning in the same boot.

### MEASUREMENT TRAP that cost a cycle — probe text vs search pattern

Grepping the 32 nodes for `generic_shutdown_super` reported "32/32 affected".
The real count was **0**: P199's own message contains the string
"generic_shutdown_super will report it busy".  When adding a probe, make sure
its text cannot match the pattern used to search for the condition it
describes.  (The message has since been reworded, but the class of mistake is
the point.)

### Constants note

`XFS_LOOKUP_BATCH` is private to `xfs/xfs_icache.c` and is NOT visible from
`pal/linux/`.  The walk uses a literal 32 instead; do not "fix" this by
exporting the icache constant into the PAL layer.

### Cross-subsystem

Reads `xfs_inode` DLM fields owned by the **xfs** subsystem
(`xfs/xfs_mxfs_dlm.c`) and the perag ICI radix tree owned by
`xfs/xfs_icache.c`.  Read-only; takes no locks beyond `rcu_read_lock()`.  Runs
once per unmount, so it is off every hot path.

---

## Writeback submission vs the DLM demote-wait (sess25, ccloop c7ee71c6)

`xfs_vm_writepages` brackets the whole of `iomap_writepages` with
`xfs_wptask_enter/exit`, so `xfs_task_in_writepages()` is true for the bdi
flusher, `sync` and `fsync` for the entire walk.  `mxfs_ilock_admit_ioend`
(xfs subsystem) uses that to admit writeback submitters through a
BAST/DEMOTING demote-wait — they hold folio locks the release drain needs, so
parking them is a guaranteed deadlock, not a conservative choice.

**`xfs_map_blocks` takes `xfs_ilock(ip, XFS_ILOCK_SHARED)` FIRST**, before any
delalloc conversion is considered.  FIX-26 admitted only EX requests, so a
folio needing no conversion asked for PR, failed the gate and parked.
`mxfs.fix27_shared_admit` (now **default 1**) widens the admit to shared-class
requests from writepages context.  See `D-BAST-WRITEBACK-ABBA-DEADLOCK` in
`tests/criteria/OPEN_DEFECTS.json` for the deterministic A/B that proved it.

### Verification knobs (all debug-only, default 0)

| knob | where | what it widens |
|---|---|---|
| `fix26_delay_ms` | `xfs_convert_blocks` | the folio-locked → ILOCK_**EX** window |
| `fix27_delay_ms` | `xfs_map_blocks`, before the SHARED acquire | the folio-locked → ILOCK_**SHARED** window |
| `fix28_drain_stall_ms` | `xfs_map_blocks`, **demoter-only, drain-site-2 only, once per drain** | stalls the DRAIN mid-batch so a submitter can park on a later folio of the batch it already fetched |

`fix27_delay_ms` must break out on **`i_dlm_mode == NL`**, not on
`state == BAST|DEMOTING`.  The state is reached at drain site 1, where the
nest-admit fast path (`i_dlm_mode >= request`) grants the request outright and
nothing ever parks — that is why sess24's exerciser recorded 200/200
"collisions" with zero demote-wait entries.  Only site 2 (post-mode-clear) can
park a submitter.

`fix28` is the drain half.  `writeback_get_folio()` (mm/page-writeback.c) calls
`folio_lock()` **unconditionally** and works off an already-fetched
dirty-tagged batch, so a submitter that has cleared the dirty bit is still a
folio the drain will block on.

## ccloop c7ee71c6 sess26 — test-only injection knobs in `pal/linux/xfs_aops.c`

(Distinct from the older "sess26 (ccloop)" `xfs_buf.c` entry above, which is a
different run. Cross-reference by run id, not session number.)

Module params live here alongside the writeback glue. Added:

- `mxfs.bast_irele_unclaim_inject` (default 0, **TEST-ONLY, never ship on**) —
  makes `mxfs_dlm_bast_work_fn` drop its own demoter claim immediately before its
  trailing `xfs_irele`, reproducing the state a stolen claim leaves. Exists
  because the theft and the resulting wedge have different rates: 30 measured
  live-claim steals produced zero wedges, since the wedge additionally needs the
  irele to be the LAST reference (`i_count==1`) AND `i_dlm_state != NONE`.

- `mxfs.p6_midtenure_skip` (default **1** = current behaviour; 0 = always
  reload) — A/B lever for D-SILENT-MKDIR-LOSS. Gates the
  `P6-MIDTENURE-RELOAD-SKIP` branch in `mxfs_dlm_reload_inode`, which clears
  `i_dlm_stale` and returns WITHOUT reloading when a directory was dirtied under
  the current EX tenure. Nominated by a token-frequency differential: the node
  that durably lost 8 dirents emitted that probe **661** times against a peer
  median of **37** (range 25-215) in the same scoped window.
  **RULE 0 pitfall measured here:** with the lever at 0, correctness is
  unharmed (cache_coherency 654/654 28s, dir_reuse_coherency 65/65 105s) but
  `dirent_durability` goes from 120s to a **240s/240s timeout**. The skip is a
  hot-path optimisation, so "always reload" is not an available fix — a real fix
  must narrow WHEN the skip applies, not remove it.

Existing neighbours: `mxfs.demoter_legacy_clobber` (pre-fix claim behaviour, for
same-build A/B), `mxfs.cancel_ref_release`, `mxfs.fix28_drain_stall_ms`.

### Cross-subsystem note

These params are DEFINED in `pal/linux/xfs_aops.c` but CONSUMED in
`xfs/xfs_mxfs_dlm.c` via `extern int`. Adding one means touching both files;
declaring the extern is easy to forget and fails only at link time. All three
above are plain BSS ints, so their default is 0 unless explicitly initialised —
`mxfs_p6_midtenure_skip` IS initialised to 1 because its zero value changes
behaviour.


---

## sess29 — INODE-CLUSTER WRITE AUTHORITY: the gap, the detector, and a NULL trap

### Where the per-slot masking loop lives, and what it already guards

`pal/linux/xfs_buf.c` walks every dinode slot of an inode-cluster buffer before
submission and builds a `skip` mask (`dirty = all & ~skip`, so a skipped slot's
sectors are simply not part of the I/O). The classes it already handles:

| slot class | treatment | why |
|---|---|---|
| FREE (`di_mode == 0` on the buffer) | **skip** | prior-tenure freed image; writing it reverts a peer's realloc (BUG1) |
| NL in-core (we released it) | **skip** | BUG2, dir `di_size` revert |
| DIRECTORY, not logged this round | **skip** (`P56-CORESIDENT-DIR-SKIP`) | our cached copy is stale prior-tenure content; writing it durably resurrects a peer-removed dirent (PROVEN sess56) |
| logged / buf-logged this round | write | our genuine committed change |
| **anything else (held non-dir)** | **write unconditionally** | ← **THE GAP** |

The physical write unit is the whole 16 KB cluster; the coherency protocol locks
per **inode**. So that last row republishes whatever the cached buffer holds for
every neighbouring slot — including inodes a peer owns and has since modified.
`D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY`.

### New probes / module param (public surface added this session)

- `P218-CLUSTER-PASSENGER` — per slot, ratelimited, only when a numerator fires.
- `P218-CLUSTER-AUTHORITY` — per write, carries the denominator on the same line.
- `P218-CLUSTER-AUTHORITY-TOTAL` — cumulative, via
  **`echo 1 > /sys/module/mxfs/parameters/cluster_authority_dump`**
  (`module_param_cb`, defined in `xfs_buf.c`; unlike the `xfs_aops.c` params
  below it is consumed only here, so no `extern` is needed).
- Census harness: `tests/cluster_authority_census.sh [nodes] [full]`.

Detection only — no behaviour change, no knob gating the write itself.

First measurement, 32/caw over cache_coherency + dir_reuse_coherency +
dirent_durability (all PASS): `writes=9787 unlogged_written=73097`
(**denominator**), **`no_write_tenure=2970`**, `gen_mismatch=33`,
**`no_incore=68277`**. Writer is `xfsaild` in every sample.

**The counting trap (sess27, and it is real):** do NOT count "slots we lack EX
for". ~20 of the 21 slots in every cluster write are bytes preserved from
whenever the buffer was last read, so that predicate fires on essentially every
write and measures nothing. Count only slots whose bytes can be STALE, and never
print a numerator without `unlogged_written` beside it.

**Honest limit:** this measures AUTHORITY, not DIVERGENCE. Pair a numerator with
a plain-bio platter read (the `P207-COHERENT-TRUTH` primitive) before assigning
any loss count to the defect.

### ⚠ PITFALL — `ip` CAN BE NULL in the held-non-dir branch

```c
is_free = (magic == XFS_DINODE_MAGIC && d->di_mode == 0);   /* no ip needed */
ip      = radix_tree_lookup(&pag->pag_ici_root, base_agino + s);
is_nl   = (ip && ip->i_dlm_mode == MXFS_LOCK_NL);           /* ip may be NULL */
...
if (!is_free && !is_nl)
        continue;   /* comment says "held non-dir inode" — but ip may be NULL */
```

The comment describes the INTENT, not the CONDITION. Dereferencing `ip` there is
a NULL deref in the writeback path. It killed **one node per run on three
consecutive runs**, and every symptom pointed away from the real cause:

- `cache_coherency 0/32 NO_TERMINAL_RECORD` — all 32 nodes, not just the dead one
- the next boot's `mount` hung in `mxfs_disklock_claim_slot` →
  `mxfs_pal_bdev_read` → `bdev_pipelined_read`, with
  `sd 4:0:0:0: reservation conflict` — i.e. it read as a SCSI/PR storage fault
- the new probe printed **zero** lines, because the oops preceded any print

**Rule: after a kernel-side change, "a node lost its mount" is YOUR change until
proven otherwise — read `journalctl -k -b -1` (the PREVIOUS boot) before
blaming the rig.** A real spurious-power-cycle issue does exist (ccmemory
`rig-prep-spurious-powercycle-under-host-load`), which is exactly what makes
this misattribution easy.

Also: `scripts/cluster_reset.sh` is the OLD 2-NODE harness (it looks for
`/mnt/mxfs-src/mxfs.ko`) and cannot reset the 32-node rig. Use
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`.

`ip == NULL` is not a nuisance case to skip: it is **93% of the exposure**
(68277 of 73097), and P56's directory rationale explains why it is the worst
class — the flushing node holds the cluster cached for a churned child while the
slot's own inode is not in core at all, so the bytes are a stale prior-tenure
image and no tenure can even be consulted.


## sess29 — THE FIX: `mxfs.cluster_passenger_skip`, and a trap in the skip contract

`mxfs.cluster_passenger_skip` (bit0 = un-logged slots held only in PR, bit1 =
un-logged slots with no in-core inode, ships **3**, 0 = pre-fix control) drops
from the inode-cluster write every un-logged slot this node has no write
authority for — the same treatment `P56-CORESIDENT-DIR-SKIP` already gives an
un-logged DIRECTORY slot.

**A/B, same build, both arms fresh prep, identical workload:** 32 nodes 2242
unauthorised slots written / 3 divergent -> 0 / 0; 8 nodes 1446 / 10 -> 0 / 0.
Every arm passed `dir_reuse_coherency` and `dirent_durability`, i.e. the
control's corruption is silent to every criterion. No pace regression
(`crash_consistency` 65 s/90 s, the pre-fix baseline).

**Lost-write safety is structural.** `logged` is built by walking
`bp->b_li_list` — every inode log item attached to THIS BUFFER — and a logged or
buf-logged slot is never skipped. A skipped slot therefore provably has no item
for the buffer's iodone to complete, so no AIL item is wrongly removed and no
dirty state wrongly cleared.

### ⚠ PITFALL — `nskip` IS THE PARTIAL-WRITE SWITCH, NOT A STATISTIC

```c
if (nskip == 0)
        return false;   /* "not a partial write" -> caller writes the WHOLE buffer */
```

`return false` hands the buffer back to the caller for a **whole-buffer write**.
A new skip mask that does not feed `nskip` is therefore *computed and thrown
away*: sess29 added the authority mask in a separate `pr_skip`/`n_pr_skip` pair,
and every buffer whose only skips were authority skips silently wrote all its
unauthorised passengers anyway. The per-slot probe stamped `skipped=` from the
mask at consideration time, so it reported INTENT and the measurement looked
correct — "2241 slots dropped" was really 6187 once fixed, ~2.8x.

**Any future skip rule must be included in the `nskip == 0` test.**

### Open items on this fix (GPT review, RULE 5)

- The `declined` fallback reinstates skipped slots when the mask would empty the
  write — "nothing legal to write, so write the illegal bytes". Should refuse
  instead; `dirty == 0` implies no logged items and no `bli_dirty`, and the
  helper already owns submission (`return true` = "I submitted it").
- **Logged slots are still written without an authority check.** "Logged this
  round" proves a JOURNAL representation, not authority to publish to HOME. The
  directory case is guarded (`P56-NL-LOGGED-DIR-SKIP`); non-dir is not.
- Per-inode v5 CRCs detect torn images but do NOT make concurrent sub-block
  writes safe — verify range alignment against the device logical block size.
- Every other publisher of an inode-cluster buffer (log recovery, inode
  alloc/free, reclaim, unmount flush, error/retry) needs the same audit.
- Stale-READ mirror: skipped bytes remain in our cached buffer and must not
  later be consumed as authoritative without reload.


## sess29 (later) — THE EMPTY-WRITE CASE, and a new always-on protocol alarm

Build 0.11.259. The authority mask is now **always applied**; an empty result is
left empty and resolved by *obligation state* rather than by silently reinstating
the unauthorised slots (the old fallback was "there was nothing legal to write,
so write the illegal bytes anyway"):

| case | action | probe |
|---|---|---|
| empty, `(logged\|bli_dirty) == 0` | refuse the write, `xfs_buf_ioend(bp)`, `return true` | `P218-WRITE-REFUSED` |
| empty, an obligation exists | keep the whole write so a committed change is not lost, and shout | `P218-SKIP-DECLINED` |

The no-obligation proof is exact, not a guess: `logged` is built by walking
`bp->b_li_list`, so `(logged|bli_dirty) == 0` **proves** the buffer's completion
cannot satisfy an unsent item. Refusal is expressible because the helper owns
submission (`return true` = "I submitted it"), so completing with no I/O is
legitimate.

Measured over a 32-node board: `skipped=158218 refused=0 declined=1`.

### The alarm found something on its first run

    P218-SKIP-DECLINED daddr=4064 slots=14 logged=0x4000 bli_dirty=0x0

One logged slot (sector 14) plus 14 unauthorised passengers, and `dirty == 0` —
so that logged slot is itself inside `skip`, almost certainly
`P56-NL-LOGGED-DIR-SKIP` (a logged DIRECTORY slot at NL without a RELFLUSH
token, deliberately not published). Every slot in the buffer is unpublishable,
and the pre-existing code whole-writes **all** of them: the dir slot it just
decided not to publish, plus every passenger. That is "we owe bytes we do not
own".

**Identified refinement, deliberately NOT applied yet:** the refusal test should
be `((logged | bli_dirty) & ~skip) == 0` — *nothing we both owe and were going to
write* — since a logged slot already inside `skip` was never going to be written.
Before applying it, verify that `P56-NL-LOGGED-DIR-SKIP`'s own roll-back of
`i_mxfs_pub_flush_seq` plus the `MXFS_IF_PUB_SKIPPED` re-arm already makes it
safe to discharge that log item without its bytes landing. Do not apply it
blind — discharging an obligation whose bytes never landed converts a clobber
into a lost write, which is worse.

### sess31 (0.11.269-270) — P219 hardening and what it measured

- **P219-LOGGED-NO-AUTHORITY print had a %s-vs-integer format bug** (an extra
  `stage_ns` arg landed on `comm=%s`): every fire dereferenced a ~1.78e18
  timestamp as a char* and PANICKED the node from xfsaild context. Fixed by
  adding `stage_ns=%llu` to the format. Any counter harvested before 0.11.269
  is survivorship-biased. When adding probe prints here, count specifiers vs
  args — and check `make 2>&1 | grep "char \*"` (the -Wformat warning is easy
  to lose in the build noise; that is exactly how this shipped).
- New: `mxfs_logwr_stale_nl` counter (stale tenure && submit at NL — the
  corruption-capable shape) in P219-LOGGED-AUTHORITY-TOTAL; `bflags=0x%x`
  in the P219 line (0.11.270+ marker; also proves XBF_STALE is NOT set on
  these writes — they are real home writes, not stale-buffer traversals).
- Measured classes (dirent_durability@32/caw, ~13 events/lap even on PASS):
  class X = ORPHAN images (nlink=0, di_mode retained) written at NL after the
  staging tenure died; class Z = the shared parent dir submitted mid-EX with
  bytes staged 2-4 epochs earlier. Invariant insight: inode log items attach
  to the cluster buffer at transaction PRECOMMIT (xfs_inode_item.c:190) and
  survive iodone when re-logged — so b_li_list membership means "committed
  change pins this buffer", NOT "freshly staged", and XFS_IFLUSHING is the
  wrong predicate for the publication obligation.

### Still open on this path (GPT review)

Logged slots are still written with no authority check — "logged this round"
proves a JOURNAL representation, not authority to publish to HOME. The directory
case is guarded; non-dir is not. Also outstanding: storage-granule alignment vs
lower-layer RMW, the other publishers of an inode-cluster buffer (log recovery,
inode alloc/free, reclaim, unmount flush, error/retry), split-I/O error
handling, and the stale-READ mirror.

## sess32 (session 14) — buffer-side mask changes
- P222-STALE-STAGE-SKIP (xfs_buf.c ~3684): landed/unlanded arms; unlanded now
  fails closed by default (P224-UNLANDED-STALE-FATAL + xfs_force_shutdown,
  knob mxfs.stale_stage_unlanded_shutdown; pre-roll staged seq captured as
  p224_staged). Print extended with stage_mode/ili fields/pend/dur for the
  release-barrier forensics. Buffer item recovery (xfs_buf_item_recover.c)
  remains UNGATED for authority — its skip now happens upstream in the pass2
  item loop under xlog_is_mxfs_untrusted_replay.
- xfs_super.c mount path: after mxfs_v5_dlm_init succeeds, it now also stamps
  `mp->m_mxfs_slice_adopted = mxfs_v5_dlm_slice_adopted(...)` right where
  m_mxfs_node_slot is taken — consumed by xfs_log_mount to set the
  XLOG_MXFS_ADOPTED_SLICE recovery gate. Cross-subsystem: disklock claim
  (dlm) → v5_mount → THIS assignment → xfs log recovery gates.

## sess36 (ccloop c7ee71c6, 2026-07-31, 0.11.305-309) delta

### xfs_buf.c — PROBE-A transient guard (309)
PROBE-A (AG-META-WRITE-NOT-HELD, ~line 8159) gates on a racy-by-design read
of the per-AG DLM fields.  PITFALL PROVEN: the gate can sample `!held` in the
middle of an AG re-acquire and then print a payload that says `cached=1` — a
self-refuting transient — while its once-per-boot `dump_stack()` emits a
"Call Trace:" line that soak's kernel-log scan (DPAT) counts as a failure
(cost one 4/caw soak FAIL).  Fix shape: re-read `held` immediately before
emitting; a transient logs `P-A-TRANSIENT` (no stack); only a persistently
unauthorized write earns the crash-shaped artifact.  RULE: diagnostics that
print kernel-crash-shaped text (Call Trace/BUG/WARNING lookalikes) must be
gated on re-validated conditions — soak/kernel_health treat them as real.
The P219/P222/P235 containment block directly above it is unchanged and its
knobs are all default-ON now (stale_stage_skip=1, unlanded_shutdown=1,
stale_stage_skip_ex=1); on the 306 board: 64 class-X masks (all landed),
55 P235 EX-restages, 0 unlanded, 0 P224.

### xfs_aops.c — new TEST-ONLY knob (308)
`mxfs.bast_qfalse_inject` (int, 0644, default 0, NEVER ship on): consumed in
xfs/xfs_mxfs_dlm.c bast_work_fn — the work self-requeues at entry with its
OWN donated igrab ref, holding WORK_STRUCT_PENDING for the run's duration so
every concurrent bast_notify dispatch deterministically takes its
queue_work-false branch.  Purpose: branch-coverage proof for the
D-UNMOUNT-BUSY-INODES fix (the notify queue-false paths used to LEAK their
iget ref; 126 forced collisions on 308 = zero leaks).  Declared beside the
other injectors (bast_irele_unclaim_inject, cancel_ref_release).

### xfs_file.c — stale_src stamp (305)
The rw-bail retry loop's `ip->i_dlm_stale = true; /* keep armed across
bails */` (~line 1895) now also stamps `i_dlm_stale_src = 27` so the P220
`dss=` census can name it.  Decode lives in xfs/xfs_inode.h (field comment):
26=reload_identical_keepfork (xfs_mxfs_dlm.c), 27=file_rw_bail (HERE).

### Cross-subsystem facts worth keeping
- The i_dlm_stale flag means NEXT-TENURE READ-CACHE staleness only; it says
  nothing about un-landed committed writes.  sess36 removed the dstale
  exemption from the xfs-side terminal release gate after a dss census
  proved 459/459 "leaked tenure" events carried dss=5 (the release
  pipeline's own mark) — any future PAL-side consumer of i_dlm_stale must
  not treat it as write-obligation state.
- Kernel-side ref tracing for PAL/VFS boundary hunts: tests/refleak_trace.sh
  arms tracefs kprobes on igrab/ihold/__iget/iput (all real T symbols on
  6.8.0-101-generic; BTF offsets i_sb=+56 i_ino=+80 i_count=+344).  This
  sees the dput->iput releases that are structurally invisible to module
  chokepoints — the instrument that ended the 5-session unmount-leak hunt.

## sess37 (ccloop c7ee71c6, 2026-08-01, 0.11.313-317) delta

### xfs_super.c — put_super teardown sweep (313)
- Gate close FIRST (m_mxfs_arms_off under m_mxfs_arm_lock), then pr_sweep cancel +
  bast wq flush (existing), then **s_inodes sweep**: for inodes with pending bast
  work/dwork — igrab pin, cancel_work_sync + cancel_delayed_work_sync OUTSIDE all
  spinlocks, xfs_irele per canceled arm (BADREF guard cnt<2), iput pin, restart
  scan (terminates: closed gate ⇒ pending can't return). Breaks the last-ref
  circular flush_workqueue can't see (timer-pending dwork). P6S-ARMSWEEP
  cancels= arm_refs_dropped=. Verified: engaged on every surviving node's umount
  in teardown_leak_repro (cancels=1 refs=1 ×7), 0 leaks; board 20/21.
- Mount init: spin_lock_init(&m_mxfs_arm_lock) + arms_off=false near pr_sweep INIT_WORK.

### xfs_aops.c — new module knobs (311-316; xfs_aops.c is the knob home)
- **mxfs.evict_retain_pr** (int, 0644, default 1): retain a clean PR DLM grant
  across inode eviction instead of CAS-clearing it (demand-release via the
  noino BAST path).  Consumed in xfs_mxfs_dlm.c mxfs_dlm_evict.  Killed the
  32-way barrier-aligned drop_caches unlock convoy (dir_reuse dc 6-9s→0.15s).
- **mxfs.rel_stale_inject** (int, 0644, default 0, TEST-ONLY): force the
  stranded (-ESTALE) verdict on inode DLM releases while shutdown/unmounting —
  drives the P6G teardown-era arm decision.  In practice post-withdraw drains
  abort before the release eval, so it rarely fires; kept for strand-path A/B.
- (313 gate fields live in xfs_mount.h: m_mxfs_arm_lock + m_mxfs_arms_off;
  the 25-site wrappers are static in xfs_mxfs_dlm.c — see xfs.md.)
- Pitfall recorded: dlm/ also declares knobs via module_param (dlm_caw.c
  caw_direct_handoff, sess37) — grep BOTH homes when auditing the knob surface.
- Cross-subsystem: put_super's sweep must run BEFORE the DLM teardown block so
  a sweep-triggered evict still sees live DLM (GPT design condition).

### sess37 file-change index (for the awareness tracker)
- pal/linux/xfs_super.c: put_super gained the bast-arm gate close + s_inodes
  arm sweep (before the DLM teardown block); mount init gained
  spin_lock_init(&mp->m_mxfs_arm_lock) / m_mxfs_arms_off=false.  No public-API
  signature changes; behavior change is teardown-only.
- pal/linux/xfs_aops.c: knob block ~line 388-410 gained mxfs.rel_stale_inject
  (default 0, TEST-ONLY) and mxfs.evict_retain_pr (default 1).  No function
  changes — xfs_aops.c is only the module-param home for these.

### sess38 file-change index (for the awareness tracker)
- pal/linux/xfs_aops.c: mxfs.create_intent_ex DEFAULT 1 -> 0 (same-build A/B
  at 32/caw dir_reuse: knob-on 6 rounds vs knob-off 7 — the EX'd lookup
  serializes consumer-refresh evict + FUA re-read inside the dir-EX critical
  section, while the EDEADLK self-demote it avoids is already drain-free via
  dir_pr_release_fast=1 and burst batching comes from dir_ex_tenure_floor +
  sliding grace either way).  Rationale comment sits on the initializer.  No
  function or signature changes — xfs_aops.c remains only the module-param
  home; the mechanism lives in xfs/xfs_inode.c + xfs/xfs_mxfs_dlm.c (see
  xfs.md sess38).
- PITFALL (measurement): P44-MODGRANT (xfs_mxfs_dlm.c, gated on instr||dirwr,
  ino<=256) does a SYNCHRONOUS FUA slot read per dir modify — instr=1 nodes
  self-straggle under create churn; never attribute pace from instr-node
  windows alone, and prefer arming instr only for the phase under test.
- (tracker note, sess38 close: xfs_aops.c's only sess38 delta remains the
  create_intent_ex default flip documented above; no further pal changes.)

## sess40 (ccloop c7ee71c6) — `xfs_super.c`: two new module params + deferred-reap lifecycle

### What changed (public surface)
`pal/linux/xfs_super.c` gained two `module_param_named` knobs and two mount
lifecycle calls.  No PAL function signatures changed; this file remains the
module-param home plus the mount/unmount wiring point.

- **`mxfs.iunlink_slot_buckets`** (uint, 0644, default **1**) — backs
  `mxfs_iunlink_slot_buckets`, defined in `xfs/libxfs/xfs_inode_util.c` (a
  plain variable there so user-mode libxfs links).  1 = multi-node AGI
  unlinked-list inserts use **this node's disklock slot** as the bucket index
  instead of `agino % 64`; 0 = legacy hashing (same-build A/B control).
  **CLUSTER-UNIFORM ONLY** — mixed settings recreate the shared-bucket hazard
  for new inserts.  Removals stay correct across a flip because membership is
  recorded per inode (`i_unlinked_bucket`) and *used*, never recomputed.
- **`mxfs.open_tracking`** (uint, 0644, default **1**) — defined *in this
  file* (`mxfs_open_tracking`), consumed by `xfs/xfs_mxfs_dlm.c` (BAST-release
  publish) and `xfs/xfs_inode.c` (the B6 open-defer guard) via `extern`.
  1 = publish a cluster open-holder bit when releasing a still-open inode
  under BAST, and defer a peer-open unlinked inode's destructive
  inactivation; 0 = pre-sess40 behaviour.

- **`mxfs_defer_reap_init(mp)`** is called in the DLM-init block immediately
  before `INIT_WORK(&mp->m_mxfs_withdraw_work, ...)`; **`mxfs_defer_reap_destroy(mp)`**
  is called at all **three** `cancel_work_sync(&mp->m_mxfs_withdraw_work)`
  sites (normal unmount + both mount-failure unwind paths).  Both live in
  `xfs/xfs_mxfs_dlm.c`; declared in `xfs/xfs_mxfs_dlm.h`.

### Ordering invariant (pal -> xfs)
`mxfs_defer_reap_init(mp)` **must** run before `xfs_mountfs(mp)` (currently
line ~2953 vs ~2959).  `xfs_mountfs` performs log recovery, whose scoped
AGI-bucket walk can iget/irele an unlinked inode and reach the B6 guard —
which calls `mxfs_defer_reap_add()`.  Initialising the list/worker after
`xfs_mountfs` would touch an uninitialised spinlock and list head.  The
existing `m_mxfs_dlm` assignment already precedes both, so the guard's own
`mp->m_mxfs_dlm` test is satisfied at that point too.

### PITFALL (cost two 32-node board regressions) — new per-inode I/O in hot paths
Both regressions were introduced in `xfs/` but were only *visible* as
cluster-wide symptoms, and both are the same lesson: **any new slot probe or
CAS added to a per-inode path is I/O on the shared LUN, and at 32 nodes that
is a load multiplier, not a constant.**

1. Publishing the open bit from `xfs_file_open` (this subsystem's
   `pal/linux/xfs_file.c`) put one generation-bumping CAS on the shared slot
   per `open()`.  `zero_silent_loss` issues ~20k opens per node; 32 nodes'
   CASes invalidated each other's in-flight compare images and starved real
   acquires (`ea_claim=100` -> `rc=-110` -> `SHUTDOWN_CORRUPT_INCORE`,
   234/644 checks lost).  Fix: publish on the **BAST-release CAS** that
   already happens — the only moment a peer's destructive path can be
   imminent, since it must BAST every holder off to take EX.
2. Clearing the bit unconditionally at evict ran a **full slot probe for
   every evicted inode**.  `zero_silent_loss` 440/644.  Fix: gate every clear
   on `ip->i_mxfs_open_pub` (set only when we actually published) — only what
   we set gets cleared, restoring 644/644.

`pal/linux/xfs_file.c` therefore only **counts** opens now
(`atomic_inc/dec(&ip->i_mxfs_open_n)` in `xfs_file_open` / `xfs_file_release`);
it issues no DLM I/O.  The decrement sits **before** the readonly/shutdown
early return so the count cannot drift upward and pin a peer's reap forever.

### sess40 file-change index (for the awareness tracker)
- pal/linux/xfs_super.c: `mxfs_open_tracking` definition + both
  `module_param_named` blocks; `mxfs_defer_reap_init` at mount;
  `mxfs_defer_reap_destroy` at all three withdraw-work cancel sites.
- pal/linux/xfs_file.c: `#include "../../dlm/v5_mount.h"`; `xfs_file_open`
  increments `i_mxfs_open_n` after a successful `generic_file_open`;
  `xfs_file_release` decrements it before any early return.  No signature
  changes.


## sess43 delta (2026-08-02, v0.11.354) — put_super teardown ordering

**Change:** in `xfs_fs_put_super` (pal/linux/xfs_super.c) the deferred SCSI-PR
unregister now runs **after** `xfs_shutdown_devices(mp)` instead of immediately
after `xfs_unmountfs(mp)`.  No signature changes; nothing else moved.

**Why (D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER, FIXED AND VERIFIED).**
`xfs_shutdown_devices()` ends with an unconditional
`blkdev_issue_flush(mp->m_ddev_targp->bt_bdev)` — inherited upstream, whose
purpose is bdev-pagecache coherency with udev/blkid, NOT XFS metadata
durability.  It ran after the unregister, so on a PR-protected LUN the target
rejected that flush and every clean unmount ended in a failed block I/O:

    sd 4:0:0:0: [sdb] CDB: Synchronize Cache(10) ... FAILED
    reservation conflict error, dev dm-1, sector 0 op 0x1:(WRITE)
        flags 0x800 phys_seg 0

Durability was never at risk (the log and its unmount record are written and
flushed by `xfs_unmountfs` while still registered — that is what v0.11.74's
`mxfs_v5_dlm_detach_pr_key` deferral bought), but a failed I/O on a clean path
is not acceptable output, and it poisons every health check that greps for
reservation conflicts — it produced a false COLLAPSE verdict in one of this
session's own diagnostic harnesses before the detector was tightened.

### Invariant this establishes (do not re-order back)
**No device I/O of any kind may outlive this mount's own PR registration.**
The teardown order is now:

1. DLM shutdown, but `pr_late_key = mxfs_v5_dlm_detach_pr_key(v5dlm)` keeps our
   PR key REGISTERED at the target (v0.11.74 — unregistering inside v5 shutdown
   fenced our own unmount log record on WE-RO targets whenever a peer still held
   the reservation: EBADE -> log-error shutdown -> unmount record lost -> dirty
   slice recovered on the next mount).
2. `xfs_unmountfs(mp)` — writes and flushes the unmount record.
3. `xfs_shutdown_devices(mp)` — `blkdev_issue_flush` + `invalidate_bdev`.
4. **only now** `mxfs_pal_scsi_pr_unregister_bdev(mp->m_ddev_targp->bt_bdev,
   pr_late_key)`.

Safe because `xfs_shutdown_devices()` only flushes and invalidates; it does not
release the buftargs, so `m_ddev_targp->bt_bdev` is still valid at step 4.  If a
future change frees the buftargs earlier, step 4 must take its own bdev
reference rather than move back before step 3.

### Reading trap for anyone auditing reservation conflicts here
The bare SCSI notice `sd N:0:0:0: reservation conflict` is the NORMAL PR-probe
artifact emitted at EVERY mount on EVERY healthy node (`P-PR-PROBE` writes a
test registration before the key is registered) — a passing 24-unmount
verification run still contained 50 of them.  Only the block-layer line
`reservation conflict error, dev ...` means a command was actually rejected.

### Verification
`tests/unmount_flush_clean.sh [N] [cycles]` — bar: zero
`reservation conflict error, dev` lines across >= 24 clean unmounts with every
node remounting.  Measured on 0.11.354 at 8/caw: 24 cycles, 0 failed I/O.
Pre-fix the same arm found the failure on essentially every unmount.

### sess43 file-change index (for the awareness tracker)
- pal/linux/xfs_super.c: `xfs_fs_put_super` — the `if (pr_late_key) { ... }`
  block relocated from before `xfs_rtmount_freesb` to after
  `xfs_shutdown_devices(mp)`.  No API, no new knobs, no other call moved.

## sess47 (0.11.377) — inode-cluster time-travel fence
- pal/linux/xfs_buf.c: cluster write completions now stamp
  pag_mxfs_inocl_wr_epoch (sibling of the sess6 agmeta stamp at ~2295);
  cold inode-cluster read inside an unflushed write window fires
  P-INOCL-COLDREAD and (mxfs.inocl_fence=1 default, xfs_super.c param 0644)
  a coalesced device flush before the read — closes the fossil
  di_next_unlinked producer arm (P53-IUNLINK-MISMATCH; LIO completion =
  target write cache, cold FUA reads bypass it). Report-only via
  inocl_fence=0 for A/B. Exposure measured on 376: 25+ windows/cycle across
  4 nodes; zero perf cost (rsync_paired 18-20s vs 23-28s baseline).
- P-PINNED-REREAD (~1448) and P-BUF-FREE-WITH-ITEMS (~387) are the standing
  eviction-arm tripwires for this class — both silent through sess47's event.

## sess47 tail — CORRECTION: fence arm INCOMPLETE (falsifier fired)
- P53-IUNLINK-MISMATCH wave occurred WITH inocl_fence=1 (cycle-7 lap-1,
  ~23 nodes, all absorbed by the idempotent carve-out, zero shutdowns).
  The read_map fence therefore does NOT close the fossil producer by
  itself.  Standing leads: (1) the coherent re-read machinery
  (mxfs_buf_is_multinode_dir_meta, xfs_buf.c ~1130, includes
  xfs_inode_buf_ops) re-reads cluster sectors from the medium via its own
  raw path and NEVER passes through xfs_buf_read_map — unfenced; same for
  the P34D-RELOAD src=plain dinode reads.  (2) post-crash rejoin churn /
  foreign-replay image regression.  Keep inocl_fence=1 (harmless, may
  cover a minor arm); do NOT cite it as the producer fix.  Rings:
  test9/test10:/root/cycle7_*.dmesg.
- xfs_super.c: mxfs_inocl_fence param (0644 runtime, default 1) — A/B
  lever for the above; flipping it does not require re-insmod.

## sess48 — write-side iunlink overlay + payload-verified retire (0.11.389-390)

- `pal/linux/xfs_buf.c` xfs_buf_submit: install site 4 — before
  `xfs_buf_verify_write`, multi-node inode-cluster writes run
  `mxfs_iunl_store_overlay` on the OUTGOING payload (mirrors the
  mxfs_dir3_data_writemerge precedent); P-IUNLSTORE-WRSITE prints the
  buffer state (pin/delwri/bli/in_ail/lseq/wseq/comm) when it corrects —
  fires only if an in-core reverter slipped past install sites 1-3/5.
- Write-completion retire hook (~line 2460) now passes the completed
  image (`b_addr`, single-map only) so `mxfs_iunl_store_retire_range`
  can payload-verify before stamping wr_epoch.
- Coherent-reread (site 2) and cold-fill/reverify (sites 1/3) overlay
  calls unchanged in location; overlay itself gained tenure scoping and
  live-skew refusal (see xfs.md sess48).
- Anchors: site 4 sits between `mxfs_dir3_data_writemerge(bp)` and the
  `xfs_buf_verify_write` call in `xfs_buf_submit`; the payload-passing
  retire hook is the inode-cluster branch of the write-completion block
  (`pag_mxfs_inocl_wr_epoch` stamp + `mxfs_iunl_store_retire_range`).
  Cross-subsystem contract: the store's functions
  (`mxfs_iunl_store_{record,overlay,retire_range,purge_ag,query_print}`)
  live in xfs/xfs_mxfs_dlm.c and are extern-declared at each pal call
  site; retire's `base` must be NULL for multi-map buffers (offset math
  assumes map 0 covers the range).  All five overlay sites and every
  legit di_next_unlinked writer hold the cluster buffer lock — that lock
  is what makes the overlay's icache live-skew peek coherent.
