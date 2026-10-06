#!/usr/bin/env python3
"""One node's part of tests/mkdir_mutex_storm.sh: for a fixed time, take and
release a directory-as-mutex shared with every other node and churn files
beside it, so one inode number is a file, a directory and free in quick
succession while peers are resolving the lock directory's name.

Every operation's errno is counted.  The only errors the workload itself
produces are FileExistsError on the mkdir (the mutex is held) and
FileNotFoundError on the unlink of a churn file; anything else is reported.

Usage: mutex_storm.py <shared dir> <node> <seconds>
Prints: STORM node=<n> laps=<n> held=<n> busy=<n> double_grant=<n> err=<n> errs=<errno:count,...>
"""
import errno
import os
import sys
import time


def main():
    shared, node, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    os.makedirs(shared, exist_ok=True)
    lockdir = os.path.join(shared, "LOCK")
    priv = os.path.join(os.path.dirname(shared), os.path.basename(shared) + "." + node)
    os.makedirs(priv, exist_ok=True)
    errs = {}
    held = busy = double = laps = 0
    end = time.time() + seconds

    def bad(e):
        k = errno.errorcode.get(e.errno, str(e.errno))
        errs[k] = errs.get(k, 0) + 1

    while time.time() < end:
        # churn: a file created, renamed and removed, so its number is freed
        # and handed to whichever node allocates next
        # (the shape of tests/mpath/pathload.py, which is where the failure
        # was measured: the renamed file outlives the mutex attempt and is
        # removed a lap later, and a private file is written every lap)
        a = os.path.join(shared, f"{node}.{laps}")
        try:
            fd = os.open(os.path.join(priv, f"f{laps % 64}"), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
            os.write(fd, b"x" * 4096)
            os.fsync(fd)
            os.close(fd)
            os.close(os.open(a, os.O_CREAT | os.O_WRONLY, 0o644))
            os.rename(a, a + ".r")
            if laps > 0:
                try:
                    os.unlink(os.path.join(shared, f"{node}.{laps - 1}.r"))
                except FileNotFoundError:
                    pass
            if laps % 10 == 0:
                os.listdir(shared)
        except OSError as e:
            bad(e)
        try:
            os.mkdir(lockdir)
        except FileExistsError:
            busy += 1
            laps += 1
            continue
        except OSError as e:
            bad(e)
            laps += 1
            continue
        mine = os.path.join(lockdir, node)
        try:
            os.close(os.open(mine, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))
            inside = os.listdir(lockdir)
            if inside != [node]:
                double += 1
            held += 1
        except OSError as e:
            bad(e)
        try:
            os.unlink(mine)
        except FileNotFoundError:
            pass
        except OSError as e:
            bad(e)
        try:
            os.rmdir(lockdir)
        except OSError as e:
            bad(e)
        laps += 1
    print(f"STORM node={node} laps={laps} held={held} busy={busy} double_grant={double} "
          f"err={sum(errs.values())} errs={','.join(f'{k}:{v}' for k, v in sorted(errs.items()))}")


if __name__ == "__main__":
    main()
