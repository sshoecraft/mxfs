#!/usr/bin/env python3
"""pathload.py — the load a path-fault row runs on every node, and its audit.

A path fault is only a test if something is using the filesystem when it
lands, and only a verdict if what was acknowledged can be checked afterwards
(docs/mpath-verification.md, section 3).  One instance per node:

  run     loops until the stop file appears, each lap doing
            - a private file: create, write, fsync; once fsync returns the
              path and its sha256 go into the manifest (an acknowledged file)
            - metadata churn in a directory every node shares: create, rename,
              unlink of the lap before, and a listing every tenth lap
            - a cross-node mutual exclusion: mkdir of one shared name is the
              lock; the holder plants an O_EXCL marker inside, looks for
              anyone else's, and removes both.  A second holder inside, or a
              marker that would not create, is a double grant.
          Every operation is logged with its start and end time, so the stall
          a fault caused is the longest gap between completions, read from
          the log and not from a guess about timers.
  verify  reads every file of a manifest (written by ANOTHER node's run) and
          compares checksums.
  stall   reads an ops log and prints the longest gap between completed
          operations inside a time window, with the operations either side.

The log and manifest live OUTSIDE the filesystem under test (a local
directory on the node): a record of what was acknowledged that is stored on
the thing being broken proves nothing.

Usage:
  pathload.py run <node> <mountpoint> <outdir> <stopfile> [<size_bytes>]
  pathload.py verify <manifest>
  pathload.py stall <opslog> <from_ms> <to_ms>
"""
import errno
import hashlib
import os
import sys
import time


def now_ms():
    return int(time.time() * 1000)


def payload(node, lap, size):
    seed = hashlib.sha256(f"{node}:{lap}".encode()).digest()
    return (seed * (size // len(seed) + 1))[:size]


def run(node, mnt, outdir, stopfile, size):
    os.makedirs(outdir, exist_ok=True)
    # the pid, so a harness can read this process's kernel stack while an
    # operation of it is blocked (/proc/<pid>/stack)
    with open(os.path.join(outdir, "pid"), "w") as f:
        f.write(f"{os.getpid()}\n")
    priv = os.path.join(mnt, "pathload", node)
    shared = os.path.join(mnt, "pathload", "shared")
    lockdir = os.path.join(shared, "LOCK")
    os.makedirs(priv, exist_ok=True)
    os.makedirs(shared, exist_ok=True)
    ops = open(os.path.join(outdir, "ops.log"), "a", buffering=1)
    man = open(os.path.join(outdir, "manifest"), "a", buffering=1)
    # The inode number each create was given, as the creating node saw it.
    # A cold audit that finds a name naming the wrong inode (seen once on
    # 8/net/mesh/mpath: a churn file left by one row named a number that was
    # free on disk) can then be read against what the creator was handed,
    # instead of against kernel logs that a passing row deletes.
    inos = open(os.path.join(outdir, "inos.log"), "a", buffering=1)
    counts = {"ok": 0, "err": 0, "mutex_held": 0, "mutex_busy": 0, "double_grant": 0}

    def op(name, fn):
        t0 = now_ms()
        try:
            r = fn()
            ops.write(f"{t0} {now_ms()} {name} ok\n")
            counts["ok"] += 1
            return r
        except OSError as e:
            ops.write(f"{t0} {now_ms()} {name} ERR {errno.errorcode.get(e.errno, e.errno)}\n")
            counts["err"] += 1
            return None

    def write_private(lap):
        p = os.path.join(priv, f"f{lap:07d}")
        data = payload(node, lap, size)
        fd = os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        try:
            inos.write(f"{now_ms()} {p} {os.fstat(fd).st_ino}\n")
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        return p, hashlib.sha256(data).hexdigest()

    def churn(lap):
        a = os.path.join(shared, f"{node}.{lap}")
        fd = os.open(a, os.O_CREAT | os.O_WRONLY, 0o644)
        try:
            inos.write(f"{now_ms()} {a} {os.fstat(fd).st_ino}\n")
        finally:
            os.close(fd)
        os.rename(a, a + ".r")
        if lap > 0:
            try:
                os.unlink(os.path.join(shared, f"{node}.{lap - 1}.r"))
            except FileNotFoundError:
                pass

    def mutex(lap):
        try:
            os.mkdir(lockdir)
        except FileExistsError:
            counts["mutex_busy"] += 1
            return
        mine = os.path.join(lockdir, node)
        try:
            fd = os.open(mine, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.close(fd)
            inside = os.listdir(lockdir)
            if inside != [node]:
                counts["double_grant"] += 1
                ops.write(f"{now_ms()} {now_ms()} mutex DOUBLE_GRANT inside={','.join(sorted(inside))}\n")
            counts["mutex_held"] += 1
        finally:
            try:
                os.unlink(mine)
            except OSError:
                pass
            os.rmdir(lockdir)

    # The log and the manifest are read by the harness WHILE this runs, from
    # the other end of an NFS mount.  A buffered write stays in this node's
    # page cache until writeback gets to it, tens of seconds: the harness saw
    # an empty log 20 s into a load that had completed 2000 operations.  So
    # both are pushed to the server twice a second.
    lap = 0
    last_sync = now_ms()
    while not os.path.exists(stopfile):
        if now_ms() - last_sync >= 500:
            for f in (ops, man, inos):
                f.flush()
                os.fsync(f.fileno())
            last_sync = now_ms()
        r = op("write", lambda: write_private(lap))
        if r:
            man.write(f"{r[1]} {r[0]}\n")
        op("churn", lambda: churn(lap))
        op("mutex", lambda: mutex(lap))
        if lap % 10 == 0:
            op("list", lambda: os.listdir(shared))
        lap += 1
    ops.close()
    man.close()
    inos.close()
    print(f"PATHLOAD node={node} laps={lap} ok={counts['ok']} err={counts['err']} "
          f"mutex_held={counts['mutex_held']} mutex_busy={counts['mutex_busy']} "
          f"double_grant={counts['double_grant']}")


def verify(manifest, workers=16):
    """Every file of a manifest, read back and checksummed.  The files are
    read by several threads at once: reading a file another node wrote takes
    a lock round trip on this cluster before the first byte, and one reader
    at a time made the read-back of a long run take minutes."""
    from concurrent.futures import ThreadPoolExecutor
    want = {}
    with open(manifest) as f:
        for line in f:
            line = line.replace("\x00", "")
            if not line.strip():
                continue
            sha, path = line.split(None, 1)
            want[path.rstrip("\n")] = sha

    def one(item):
        path, sha = item
        # A file that does not verify says how: a read that failed is not a
        # read that returned other bytes, and only the second is the
        # filesystem handing back wrong data.
        try:
            with open(path, "rb") as g:
                data = g.read()
        except FileNotFoundError:
            detail.append(f"MISSING {path}")
            return "missing"
        except OSError as e:
            detail.append(f"BAD {path} read_error={errno.errorcode.get(e.errno, e.errno)}")
            return "bad"
        if hashlib.sha256(data).hexdigest() == sha:
            return "ok"
        nz = sum(1 for b in data if b)
        detail.append(f"BAD {path} content size={len(data)} nonzero_bytes={nz} "
                      f"head={data[:8].hex()} want_sha={sha[:16]}")
        return "bad"

    detail = []
    t0 = now_ms()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(one, want.items()))
    ms = now_ms() - t0
    for line in sorted(detail)[:200]:
        print(line)
    ok, bad, missing = res.count("ok"), res.count("bad"), res.count("missing")
    print(f"VERIFY files={len(res)} ok={ok} bad={bad} missing={missing} ms={ms} workers={workers}")


def stall(opslog, lo, hi):
    """The longest gap between completions that overlaps [lo, hi].

    A gap counts when any part of it lies in the window: one that began before
    the fault, or one still open when the window closed (its far edge is then
    the first completion after the window, or the window's end when the log
    has none, in which case the true stall is at least that long).
    """
    ends = []
    errs = 0
    with open(opslog) as f:
        for line in f:
            # a log still being appended over NFS can show a run of NULs
            # where a later write reached the server first
            p = line.replace("\x00", "").split()
            if len(p) < 4 or not (p[0].isdigit() and p[1].isdigit()):
                continue
            t1 = int(p[1])
            if p[3] == "ok":
                ends.append(t1)
            elif lo <= t1 <= hi:
                errs += 1
    ends.sort()
    worst = (0, 0, 0)
    for a, b in zip(ends, ends[1:]):
        if b >= lo and a <= hi and b - a > worst[0]:
            worst = (b - a, a, b)
    if ends and ends[-1] < hi and hi - max(ends[-1], lo) > worst[0]:
        worst = (hi - ends[-1], ends[-1], hi)
    inwin = sum(1 for t in ends if lo <= t <= hi)
    print(f"STALL max_ms={worst[0]} last_before_ms={worst[1]} first_after_ms={worst[2]} "
          f"completed_in_window={inwin} errors_in_window={errs}")


def main():
    a = sys.argv[1:]
    if len(a) >= 5 and a[0] == "run":
        run(a[1], a[2], a[3], a[4], int(a[5]) if len(a) > 5 else 16384)
    elif len(a) == 2 and a[0] == "verify":
        verify(a[1])
    elif len(a) == 4 and a[0] == "stall":
        stall(a[1], int(a[2]), int(a[3]))
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
