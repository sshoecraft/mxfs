---
name: compiled-mount-liveness-probe-traps
description: Harness mount/liveness checks that lied: mountpoint -q, /proc/mounts presence, GOINGDOWN ioctl, mount_rc grep — all produced false verdicts.
metadata:
  type: project
tags: [compiled, harness, mount, liveness-probe, mxfs, quarantine, shell-bugs]
---

# Mount/liveness probe traps: four ways a harness misreads whether MXFS is actually up

Four incidents, sess383 → sess573, all with the same shape: a cheap probe the
harness trusted to mean "the filesystem is mounted and usable" instead meant
something narrower, and the mismatch produced a false verdict — sometimes a
false FAIL, sometimes a false clean PASS, once a wrecked node. Ordered by when
each was hit.

## sess383 — `mountpoint -q` reads a quarantine as unmounted

[[never-mountpoint-q-on-a-quarantined-mxfs-mount]]: `mountpoint -q /mnt/shared`
works by `stat()`ing the mount root. On MXFS the root inode is ino 128, which
lives in AG 0, so any AG-scoped quarantine covering AG 0 makes the stat EIO —
correctly, that's the quarantine working — and `mountpoint -q` reports "not
mounted" on a perfectly healthy, correctly-contained mount. In the D-513
harness this cascaded: a cleanup step skipped its `umount` because the probe
said nothing was mounted, the next `mount` failed with `already mounted`, and
five downstream shapes' own start-of-run guards used the same probe, saw "not
mounted", and refused to run. Net 6 FAIL of 17, none a filesystem defect — the
tell is a FAIL whose only evidence is the harness's own mount bookkeeping, plus
`umount` succeeding by hand afterward.

Fix: any liveness/mountedness probe must read `/proc/mounts`, which the VFS
answers without touching the filesystem at all:

```sh
is_mounted() { ssh "$1" "grep -qs ' /mnt/shared mxfs ' /proc/mounts && echo YES || echo NO"; }
```

Generalizes beyond `mountpoint`: `ls`, `stat`, `df`, `test -d` are all
EIO-able by a quarantine, a withdraw, or a shutdown, and each one turns "the
containment worked" into "the harness failed." `mount | grep`,
`/proc/mounts`, and dmesg are the only safe channels. This is not a reason to
narrow a quarantine's reach — AG 0 holding the root inode is why an AG-0
refusal is close to fs-wide, and that's intended.

## sess432 — an unconditional shutdown ioctl hit the wrong filesystem

[[trap-the-goingdown-ioctl-shut-down-the-node-root-filesystem]]: `vergate.sh`
issued `XFS_IOC_GOINGDOWN` (`0x8004587d`) on `/mnt/vgate` right after a mount
attempt, without checking whether that mount had actually succeeded. The mount
had in fact been refused (`P303-FENCECAP-NOCAPS`, pre-dating the
`fence_capability_override=1` requirement added in 0.15.0), so `/mnt/vgate`
was still a plain directory on the node's ext4 root. `EXT4_IOC_SHUTDOWN`
shares the same ioctl number as `XFS_IOC_GOINGDOWN`, so the call hit the root
filesystem instead: root-fs EIO, ssh reset, node needed a power-cycle — and
because the root fs was down, every post-mortem dmesg capture from that node
was empty.

Same root cause as the `mountpoint -q` case one layer up: the harness acted
on a path without first proving the path was the MXFS mount it meant. Fix:
gate the ioctl on `/proc/mounts` showing that path as type `mxfs` first, and
never issue a shutdown-class ioctl unconditionally after a mount call whose
return code wasn't checked.

## sess570 — `mount_rc=` matched as a substring of `umount_rc=`

[[trap-bare-mount-rc-grep-matches-inside-umount-rc-and-reports-every-lap-as-success]]:
a death/rejoin harness extracted the per-lap verdict with
`grep -ao 'mount_rc=[0-9]*' "$OUT/lap_$i.log" | head -1`. The log always
printed an `UNLOAD umount_rc=0 ...` line before the `REJOIN mount_rc=N ...`
line, and the unanchored pattern matched inside `umount_rc=0` first — so every
lap, in every arm, read `mount_rc=0` regardless of what REJOIN actually
returned. The real result (5 of 7 control laps failed to mount with rc=32,
fix 8/8 clean) was the opposite in strength from what got reported (control
4/6, fix 6/6). This was the second time the project produced this exact
sentence — sess567 hit it too. Dangerous because it fails toward good news and
silently: no error, a plausible number in every row, and it survived sitting
next to a correct shadow-verdict vector in the same report without anything
flagging the disagreement.

Fix: anchor extraction to the line that owns the field —
`sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p'` — and prefer a per-node
evidence file with fewer neighboring fields over parsing harness stdout.
Treat any unanchored `grep -o '<field>=[0-9]*'` as suspect whenever another
field in the same stream ends with that field's name.

## sess573 — present in `/proc/mounts` is not the same as usable

[[trap-a-mount-in-proc-mounts-is-not-a-working-mount-and-two-shell-counter-bugs]]:
this is the direct sequel to the sess383 fix — `/proc/mounts` is the safe
channel for "is something mounted here," but it is not sufficient for "is it
usable." `d0949_sole_survivor_chunkfree.sh` used
`grep -c ' /mnt/shared mxfs ' /proc/mounts` = 1 as its precondition; it
passed even though the filesystem had already self-fenced
(`P305-RESV-SELF-GONE`) and returned EIO on everything. The workload step
then created 0 of 12000 files, the counters came out zero, and the harness
printed `verdict=VACUOUS` — a broken precondition disguised as a completed
measurement with a null result, one careless read away from "the defect did
not reproduce." A manual `touch /mnt/shared/x` "confirmation" made the same
mistake worse: it silently succeeded by writing to the root filesystem at the
mountpoint directory, since nothing was actually mounted there.

Fix: probe usability, not presence, and fail loudly on precondition failure:

```sh
mkdir -p $MNT/.probe.$$ && rmdir $MNT/.probe.$$ && echo WRITABLE   # else exit 2
```

Two unrelated shell bugs surfaced in the same session and are worth keeping
attached to this note because they hit the same class of harness (counter
correctness, not mount detection):
- `grep -c` prints `0` and still exits 1 on zero matches, so
  `cnt() { grep -ac -- "$1" "$f" || echo 0; }` returns `"0\n0"` (the `|| echo 0`
  fires in addition to the printed 0). Use
  `c=$(grep -ac -- "$1" "$f" 2>/dev/null | head -1); echo "${c:-0}"`.
- `df -i --output=itotal` errors (`-i` and `--output` are mutually exclusive),
  and even `df --output=itotal` is the wrong number for counting allocated
  inode chunks: XFS statfs reports `f_files` as the dynamic maximum
  (`maxicount`), not `sb_icount` — it read the same value before and after
  12000 file creates. Use `tools/chk_mxfs -v <dev>` (`Superblock icount:`,
  `Total inodes (inobt sum):`) instead; it works on a mounted device.

## Standing rule

For "is MXFS mounted and healthy," read `/proc/mounts` only — never `stat`,
`ls`, `df`, `mountpoint`, or any path-touching probe, because a quarantine,
withdraw, or shutdown makes those EIO and reads as "unmounted" instead of
"contained." For "is it usable," presence in `/proc/mounts` is necessary but
not sufficient — do a real write-and-remove probe and `exit` non-zero on
failure rather than letting a broken precondition flow into a "measurement"
that reports zeros as VACUOUS. Before any shutdown-class ioctl or destructive
op on a path, prove via `/proc/mounts` that the path is the MXFS mount
intended — ioctl numbers are shared across filesystem types, so acting on
mount-command return code alone, or unconditionally, can hit the wrong
filesystem entirely. And when parsing harness output for a per-field result,
anchor to the owning line — an unanchored `field=N` pattern can match inside
a differently-named field that happens to end the same way, and that failure
mode is silent and biased toward reporting success.
