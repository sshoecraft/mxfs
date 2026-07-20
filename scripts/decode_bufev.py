#!/usr/bin/env python3
"""Decode the per-buffer lifecycle event ring dumped by P-IOWAIT-STUCK.

sess9 (ccloop a864), residual wedge#2 diagnosis.  mxfs_buf_ev() in
pal/linux/xfs_buf.c packs each event as:

  [63:60] event type      [59:44] b_flags & 0xffff
  [43]    b_mxfs_sync_wait [42]   b_mxfs_force_sync
  [41:30] pid & 0xfff      [29:0] ktime_get_real_ns() >> 20  (~1.05ms units)

Usage:
  scripts/decode_bufev.py 'mxfs: P-IOWAIT-STUCK ... ev=[16x hex ...]'   # one line
  grep P-IOWAIT-STUCK stream_rank1.log | scripts/decode_bufev.py       # stdin
"""
import re
import sys

EV = {
    1: "SUBMIT",   # xfs_buf_submit snapshot (force_sync bit = pre-consume latch)
    2: "BIOEND",   # xfs_buf_bio_end_io entry (real bio completed)
    3: "IOEND",    # xfs_buf_ioend entry (full completion incl. emulated)
    4: "WORKER",   # xfs_buf_ioend_work entry (deferred async completion)
    5: "EHERR",    # xfs_buf_ioend_handle_error entry (b_error set)
    6: "RESUB",    # handle_error resubmit branch taken
    7: "BIO",      # real bio issued to the block layer
    8: "IOFAIL",   # xfs_buf_ioend_fail
    9: "IOWAIT",   # xfs_buf_iowait received a completion token
    10: "STALE",   # xfs_buf_stale
}

# XBF_* bits (xfs_buf.h)
FLAGS = [
    (0x0001, "READ"), (0x0002, "WRITE"), (0x0004, "RA"), (0x0008, "NOIOACCT"),
    (0x0010, "ASYNC"), (0x0020, "DONE"), (0x0040, "STALE"), (0x0080, "WRFAIL"),
    (0x0100, "b8"), (0x0200, "b9"), (0x0400, "b10"), (0x0800, "b11"),
    (0x1000, "b12"), (0x2000, "b13"), (0x4000, "b14"), (0x8000, "b15"),
]


def flags_str(f):
    s = [n for b, n in FLAGS if f & b]
    return "|".join(s) if s else "0"


def decode_val(v):
    if v == 0:
        return None
    typ = (v >> 60) & 0xF
    flg = (v >> 44) & 0xFFFF
    sw = (v >> 43) & 1
    fs = (v >> 42) & 1
    pid = (v >> 30) & 0xFFF
    ts = v & 0x3FFFFFFF
    return dict(type=EV.get(typ, str(typ)), flags=flg, sync_wait=sw,
                force_sync=fs, pid=pid, ts=ts)


def decode_line(line):
    m = re.search(r"ev=\[([0-9a-fA-F ]+)\]", line)
    if not m:
        return
    vals = [int(x, 16) for x in m.group(1).split()]
    evs = [e for e in (decode_val(v) for v in vals) if e]
    if not evs:
        print("  (ring empty)")
        return
    base = min(e["ts"] for e in evs)
    hdr = re.search(r"daddr=(\S+).*?sync_wait=(\d).*?ioend_seen=(\d+).*?relse_seen=(\d+)", line)
    if hdr:
        print(f"--- daddr={hdr.group(1)} live: sync_wait={hdr.group(2)} "
              f"ioend_seen={hdr.group(3)} relse_seen={hdr.group(4)}")
    for e in evs:
        dt = (e["ts"] - base) * 1.048576  # ms
        print(f"  +{dt:9.1f}ms {e['type']:6s} pid={e['pid']:4d} "
              f"sw={e['sync_wait']} fs={e['force_sync']} "
              f"flags={flags_str(e['flags'])}")


def main():
    args = sys.argv[1:]
    lines = args if args else sys.stdin.read().splitlines()
    seen = set()
    for ln in lines:
        key = re.sub(r"^\[[0-9. ]+\]\s*", "", ln.strip())
        if key in seen:
            continue
        seen.add(key)
        if "ev=[" in ln:
            decode_line(ln)


if __name__ == "__main__":
    main()
