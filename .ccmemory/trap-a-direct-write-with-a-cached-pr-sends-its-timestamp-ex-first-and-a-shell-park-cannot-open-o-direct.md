---
name: trap-a-direct-write-with-a-cached-pr-sends-its-timestamp-ex-first-and-a-shell-park-cannot-open-o-direct
description: TRAP (sess596, D-0958): the acquire a DIO write meets first with a cached PR is xfs_vn_update_time's ILOCK_EXCL, not the exclusive retry; and a sh pa…
metadata:
  type: feedback
tags: [D-0958, dio, timestamp, harness, fallible-acquire, trap]
---

# A direct write's first request is its timestamp update, and a shell cannot hold an O_DIRECT fd

Two things bit the black-hole arm for the unaligned direct-write retry (s596d, 0.84.13, fails=4).

1. **The harness parked a `sh -c` that held `exec 9< FILE` and then ran a python that did `os.open(FILE, O_WRONLY|O_DIRECT)` inside the armed command.** A shell cannot open O_DIRECT, so the "held fd" was a read fd and the real open happened AFTER the fault was armed — the blocked stack was `__x64_sys_openat -> xfs_file_open -> mxfs_dlm_open_protect`, the refusal was open's (`P912-OPEN-UNRECEIPTED`), and the verdict scored the wrong site. Fix: the parked process is `tests/dio_unaligned_pwrite.py` (open O_DIRECT, write the opened marker, wait for the go marker, one pwrite), exec'd in place of the shell so the pid the harness wrote survives.

2. **The exclusive retry is not the first request a direct write sends when its data grant is a cached PR.** The shared IOLOCK ride fast-paths on PR; then `xfs_file_write_checks -> kiocb_modified -> xfs_vn_update_time` takes `xfs_ilock(ILOCK_EXCL)`, a cluster EX, inside a `tr_fsyncts` transaction that is reserved and clean with nothing joined. That EX request goes out before `iomap_dio_rw` is ever called, so it is what a discarded request meets, and until 0.84.14 it was in the non-fallible class (waits for ever, DEGRADED). The retry's own ride is reachable as a request only when the timestamp needed no update (mgtime coarse tick unchanged), which cannot be arranged on demand — its conversion stands on the reference-iomap proof, not on a fault lap.

Consequences: any "which acquire meets the fault" reasoning for a WRITE must include the timestamp transaction; the fix (0.84.14) registers the inode around `kiocb_modified` and lets `xfs_vn_update_time` cancel the clean reservation on a refused acquire (`P958-WRITE-REFUSED stage=timestamp`). The live-holder control for that site needs the holder to keep a CLEAN PR beside the writer's cached PR (`live_holder_wait.sh HOLDER=pr`: re-dirty+sync, W reads, H reads, THEN arm the pause), so that the timestamp's EX is the request that revokes the holder — the stage-1 pause fires for a PR release too (it sits before `filemap_write_and_wait`, unconditional).
