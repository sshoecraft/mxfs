#!/usr/bin/env python3
# Diagnose SCST per-device blocking state on the LIVE kernel, read-only.
#
# This host has no kernel vmlinux debuginfo, so drgn cannot enumerate the
# module list to relocate scst.ko (it prints "did not match any loaded
# modules" and symbol lookups fail).  We therefore use drgn ONLY as a
# /proc/kcore virtual-address memory reader, resolve scst_dev_list from
# /proc/kallsyms (its address changes every boot), and decode the
# struct scst_device fields at offsets pulled live from scst.ko's DWARF
# via gdb (so the script survives rebuilds / field reordering).
#
# Background (sess37/38): under mass initiator teardown while CAW
# (COMPARE AND WRITE, strictly-serialized) commands are in flight, a
# device's block_count is left > 0 with no owning command, so every later
# command parks forever in EXEC_CHECK_BLOCKING on dev->blocked_cmd_list.
# Symptom set: D-state iscsi_conn_cleanup threads, stuck commands in
# .../sessions/*/commands, PR registrations held by zombie sessions.
#
# Usage:
#   sudo PYTHONPATH=/home/steve/.local/lib/python3.12/site-packages \
#        python3 scst_block_diag.py [path/to/scst.ko]
import os
import re
import struct
import subprocess
import sys

import drgn

KO = sys.argv[1] if len(sys.argv) > 1 else "/src/scst/scst/src/scst.ko"

FIELDS = [
    "block_count", "on_dev_cmd_count", "virt_name",
    "dev_list_entry", "blocked_cmd_list", "ext_blocks_cnt",
]


def dwarf_offsets(ko):
    """Pull struct scst_device member byte-offsets live from scst.ko DWARF."""
    exprs = ["-ex", "print sizeof(struct scst_device)"]
    for f in FIELDS:
        exprs += ["-ex", "print &((struct scst_device *)0)->%s" % f]
    out = subprocess.check_output(
        ["gdb", "-q", "-batch", ko] + exprs,
        stderr=subprocess.DEVNULL).decode()
    nums = []
    for hexv, decv in re.findall(r"\$\d+ = .*?0x([0-9a-fA-F]+)|\$\d+ = (\d+)", out):
        nums.append(int(hexv, 16) if hexv else int(decv))
    off = dict(zip(FIELDS, nums[1:]))
    # bitfield word holding strictly_serialized_cmd_waiting / ext_blocking_pending
    pt = subprocess.check_output(
        ["gdb", "-q", "-batch", ko, "-ex", "ptype /o struct scst_device"],
        stderr=subprocess.DEVNULL).decode()
    off["_bits_byte"] = off["_sscw_bit"] = off["_extp_bit"] = None
    for line in pt.splitlines():
        m = re.search(r"/\*\s*(\d+):\s*(\d+)\s*\|", line)
        if not m:
            continue
        byte, bit = int(m.group(1)), int(m.group(2))
        if "strictly_serialized_cmd_waiting" in line:
            off["_bits_byte"], off["_sscw_bit"] = byte, bit
        elif "ext_blocking_pending" in line:
            off["_extp_bit"] = bit
    return off


def kallsym(name):
    with open("/proc/kallsyms") as f:
        for line in f:
            p = line.split()
            if len(p) >= 3 and p[2] == name:
                return int(p[0], 16)
    return None


def main():
    if not os.path.exists(KO):
        sys.exit("scst.ko not found: %s" % KO)
    off = dwarf_offsets(KO)
    prog = drgn.program_from_kernel()

    def rd(addr, n):
        return prog.read(addr, n)

    def ru64(addr):
        return struct.unpack("<Q", rd(addr, 8))[0]

    def ri32(addr):
        return struct.unpack("<i", rd(addr, 4))[0]

    def ru32(addr):
        return struct.unpack("<I", rd(addr, 4))[0]

    def cstr(addr):
        if not addr:
            return "<null>"
        out = b""
        while len(out) < 128:
            c = rd(addr + len(out), 1)
            if c == b"\x00":
                break
            out += c
        return out.decode(errors="replace")

    def list_count(lh):
        n, cur = 0, ru64(lh)
        while cur != lh and n < 1000000:
            n += 1
            cur = ru64(cur)
        return n

    head = kallsym("scst_dev_list")
    if head is None:
        sys.exit("scst_dev_list not in /proc/kallsyms (is scst loaded?)")
    print("scst_dev_list @ %#x  (offsets from %s)" % (head, KO))

    leaks = 0
    node = ru64(head)
    ndev = 0
    while node != head and ndev < 256:
        base = node - off["dev_list_entry"]
        bits = ru32(base + off["_bits_byte"]) if off["_bits_byte"] is not None else 0
        sscw = (bits >> off["_sscw_bit"]) & 1 if off["_sscw_bit"] is not None else 0
        extp = (bits >> off["_extp_bit"]) & 1 if off["_extp_bit"] is not None else 0
        name = cstr(ru64(base + off["virt_name"]))
        bc = ri32(base + off["block_count"])
        od = ri32(base + off["on_dev_cmd_count"])
        eb = ri32(base + off["ext_blocks_cnt"])
        blk = list_count(base + off["blocked_cmd_list"])
        bad = bc != 0 or blk != 0 or sscw != 0
        leaks += bad
        print("dev=%-14s block_count=%d on_dev_cmd_count=%d sscw=%d "
              "ext_blocks_cnt=%d ext_blocking_pending=%d blocked_cmds=%d%s"
              % (name, bc, od, sscw, eb, extp, blk,
                 "   <-- BLOCKED" if bad else ""))
        node = ru64(node)
        ndev += 1

    print("total devs: %d   suspicious: %d" % (ndev, leaks))
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
