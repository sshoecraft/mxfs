#!/usr/bin/env python3
"""In-flight O_DIRECT writer for tests/lu_reset_probe.sh.

A LOGICAL UNIT RESET aborts the tasks of the logical unit.  To measure what
that does to an initiator that HAS work in flight, something must actually have
work in flight — and a writer that never started reports no errors, which reads
exactly like a writer the reset did not disturb.  That false negative is why
this is a real process with a real error tally instead of a shell loop:

  - one long-lived process, so a `ps -C python3` check is a true liveness test
    and there is no gap between iterations for the reset to land in;
  - O_DIRECT with a page-aligned buffer, so each write is a SCSI command to the
    LUN rather than a page-cache deposit that lands whenever;
  - every errno counted and named, because "the reset aborted my commands with
    EIO" and "the reset wedged me" and "nothing happened" are three different
    findings and only the tally separates them;
  - a self-imposed deadline, so an abandoned lap cannot leave a writer hammering
    the shared LUN.

It writes ONE 4 KiB block, repeatedly, at a caller-chosen offset — the probe
picks a scratch offset in the LUN tail.  It never scans, never grows and never
touches anything else.

Usage: lu_reset_writer.py <device> <byte-offset> <seconds>
Prints, at the end: WRITER_OK=<n> WRITER_ERR_<errno>=<n> ... WRITER_DONE
"""
import errno
import mmap
import os
import sys
import time


def main():
    if len(sys.argv) != 4:
        print("usage: lu_reset_writer.py <device> <byte-offset> <seconds>")
        return 2
    dev = sys.argv[1]
    off = int(sys.argv[2])
    secs = float(sys.argv[3])

    # O_DIRECT demands an aligned buffer; an anonymous mmap is page-aligned.
    buf = mmap.mmap(-1, 4096)
    buf.write(b"LURST-IN-FLIGHT-" * 256)

    try:
        fd = os.open(dev, os.O_RDWR | os.O_DIRECT)
    except OSError as e:
        print("WRITER_OPEN_ERR=%d" % e.errno)
        print("WRITER_DONE")
        return 1

    ok = 0
    errs = {}
    t0 = time.time()
    deadline = t0 + secs
    next_progress = t0 + 5.0
    print("WRITER_START off=%d secs=%.0f" % (off, secs), flush=True)
    while time.time() < deadline:
        # A PERIODIC TALLY, not just a final one.  The end-of-run print cannot
        # distinguish the three outcomes that matter while the run is still
        # going: a writer whose pwrite returned EIO keeps looping and stays
        # silent until its deadline, exactly like one wedged in an
        # uninterruptible wait that will never return.  A reader watching this
        # file sees `ok` advancing (healthy), `err` advancing (hurt but alive)
        # or the line stop appearing at all (stranded), and those are three
        # different findings.
        now = time.time()
        if now >= next_progress:
            print("WRITER_PROGRESS ok=%d err=%d t=%.0f"
                  % (ok, sum(errs.values()), now - t0), flush=True)
            next_progress = now + 5.0
        try:
            os.pwrite(fd, buf, off)
            ok += 1
        except OSError as e:
            errs[e.errno] = errs.get(e.errno, 0) + 1
            # A storm of identical failures is a finding, not a reason to spin
            # the CPU; a target that is gone stays gone for a while.
            if errs[e.errno] % 64 == 0:
                time.sleep(0.05)
    os.close(fd)

    print("WRITER_OK=%d" % ok)
    for en, n in sorted(errs.items()):
        print("WRITER_ERR_%d=%d  # %s" % (en, n, errno.errorcode.get(en, "?")))
    print("WRITER_ERRTOTAL=%d" % sum(errs.values()))
    print("WRITER_DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
