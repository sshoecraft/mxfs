---
name: trap-a-refused-mount-leaves-the-mountpoint-a-writable-local-directory-so-the-post-recovery-workload-check-passes-on-the-wrong-disk
description: TRAP (s86): with B's recovering mount refused, "new work accepted after the recovery" wrote 16 files into B's ROOT filesystem under /mnt/shared and P…
metadata:
  type: feedback
tags: [harness, false-pass, mountpoint, recovery]
---

# A refused mount leaves the mountpoint writable, and the oracle writes there

**Where it bit.** `tests/fence_crash_cuts.sh` cut 7, lap s86b, 0.89.19. B's
recovering mount was REFUSED (`MOUNT_RC=32`, `NOT_MOUNTED`). The
post-recovery section then ran anyway and reported:

```
PASS cut 7: the filesystem accepts and persists new work after recovering (16)
```

It created 16 files, `sync -f`'d and read back 16 checksums — all on B's
**root filesystem**, in the empty directory that `/mnt/shared` is when nothing
is mounted over it. The very next check, `umount`/remount, returned 32 and
failed, which is the only reason the lap did not report a clean recovery.

**Why it is a whole class.** A mountpoint is an ordinary directory. Every
"write something and read it back" oracle keeps working when the filesystem
under test is absent — it just measures the local disk instead. The failure
mode is the worst kind: it produces a PASS, it produces plausible evidence
(16 real sha256 lines), and it appears in the section of the lap that is
supposed to be the strongest check.

**The fix.** Make the mountpoint the *precondition* of the section, not an
assumption inside it: assert `mountpoint -q` first and report NOT MEASURED if
it fails, rather than grading whatever the writes landed on. Checking it once
at the top is enough — but it has to be checked, and it has to be checked on
the node the workload runs on, after the event that could have lost the mount.

**Neighbouring case, same shape.** A post-recovery content oracle that reads
files back through the *same mount that did the recovering* cannot tell a
recovery that reached the platter from one that exists only in that kernel's
caches. Both checks are needed and they are different claims: "am I mounted at
all" and "is this on the platter".
