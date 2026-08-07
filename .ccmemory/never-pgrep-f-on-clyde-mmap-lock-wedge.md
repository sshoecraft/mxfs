---
name: never-pgrep-f-on-clyde-mmap-lock-wedge
description: NEVER use `pgrep -f` / `ps -e` host-locally on clyde: it reads every /proc/cmdline and wedges forever on a stuck mmap_lock. Use tools/mxfs_pgrep.sh.
metadata:
  type: reference
tags: [clyde, host-safety, pgrep, test-harness, dstate, wedge]
---

# NEVER `pgrep -f` (or `ps -e`/`ps aux`) host-locally on clyde

**2026-08-07: this took clyde to loadavg 583 and forced a manual host reset.**
The MXFS test harness — written by prior sessions — caused it.

## Mechanism

`pgrep -f PATTERN` matches the *full command line*, so it opens
`/proc/<pid>/cmdline` for EVERY process. Reading cmdline goes through
`__access_remote_vm` and takes the **target task's mmap_lock**.

If any task on the box wedges *while holding its own mmap_lock*, every
later `pgrep -f` / `ps -e` / `ps aux` blocks there **forever, in
uninterruptible (D) sleep**. SIGKILL does nothing. `timeout` does nothing —
it can signal but not reap a D-state task. Each stuck caller adds 1 to
loadavg permanently.

`pgrep -x NAME` and bare `pgrep NAME` match on `comm` only and are SAFE.
Only `-f` (and full `ps` listings) read cmdline.

## The chain that happened

```
stuck bio in dm-delay `mxfsfencef` (dm-0 over loop0, inflight 0 1, ~61h)
  └─ mount 1833866  __wait_on_buffer → jbd2_write_superblock  ← holds ext4 sb
       ├─ mount 1834825   super_lock
       └─ ffmpeg 1867972  __lock_buffer via THP direct compaction
            │              ← blocked HOLDING its own mmap_lock
            └─ ~580 ps/pgrep  __access_remote_vm on /proc/1867972/cmdline
```

Origin was the MXFS **fence harness**: a `dm-delay` device over
`/var/lib/mxfs-fence/fio-backing.img` left with an orphaned bio, table
reloaded out from under it (`delay 7:0 0 0 7:0 0 0`, delay params zeroed).

Accumulation was NOT one-per-tick. The *first* `pgrep -f` in each watcher
hangs and the loop never advances — so the count tracks **how many watcher
instances were launched**, i.e. roughly one per ccloop session.

## The recovery procedure does NOT work — do not retry it

```
dmsetup suspend --noflush --nolockfs mxfsfencef   # rc=124, wedged
dmsetup wipe_table --force mxfsfencef             # rc=124, wedged
dmsetup resume mxfsfencef                         # never returned
```

Stack of the wedged dmsetup:
```
super_lock → bdev_super_lock → get_bdev_super → fs_bdev_freeze
→ bdev_freeze → __dm_suspend → dm_suspend → do_resume → dev_suspend
```

It is **circular**: swapping in the error target needs a table reload, a
table reload needs `dm_suspend()`, and `dm_suspend()` must first freeze the
fs (blocked on the superblock held by the wedged `mount`) and then drain
in-flight bios (blocked on the very bio being cleared). `--noflush
--nolockfs` do not help — for a bio-based target they govern queued-IO
pushback, not the in-flight drain, and the implicit suspend inside
`do_resume()` freezes regardless.

Worse: the failed attempt leaves a dmsetup holding `md->suspend_lock`, so
every later suspend/resume/remove on that device blocks behind it. **The
attempt consumes the escape hatch.** Only a host reset clears it — and per
CLAUDE.md RULE 2 that is the user's call, never a session's.

## The fix (in tree, 2026-08-07)

`tools/mxfs_pgrep.sh` — reads `/proc/<pid>/stat` (task state; never touches
mm) FIRST and **skips any D-state task** before opening cmdline. Validated
on the wedged host itself, where `pgrep -f` hangs.

Patched host-local call sites:
- `tests/drc_autocapture.sh` (×2 — the `while :;` + `sleep 5`/`sleep 20`
  pollers; these were the main accumulators)
- `tests/drc_progress_watch.sh`
- `tests/dd_loss_differential.sh`, `tests/rank1_stall_stacks.sh` (cleanup traps)

Deliberately NOT patched — these run on test nodes over SSH, not clyde:
`tests/setup/prep_node.sh:144`, `tests/criteria/bail_storm_watch.sh:49`,
`tests/drc_run_capture.sh:29`. Same hazard exists there, but nodes are
destroyed/reset routinely.

## Rules going forward

1. Host-local process matching: use `tools/mxfs_pgrep.sh`, or a **pidfile**
   (better — no scan at all) where you control the launcher.
2. `pgrep -x` is fine. `pgrep -f`, `ps -e`, `ps aux`, `ps ax` are not.
3. Diagnosing a wedged host: iterate `/proc/*/comm` and `/proc/*/stat`.
   NEVER `/proc/*/cmdline`, `/proc/*/maps`, or any full `ps`. `/proc/<pid>/stack`
   is safe (needs root).
4. The fence harness must not leave dm-delay devices with orphaned bios.
   Tear the device down before reloading or resuming its table.
