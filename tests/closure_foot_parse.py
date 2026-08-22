#!/usr/bin/env python3
"""closure_foot_parse.py — platter/dmesg parsing for closure_footprint_shapes.sh.

Two jobs, both of which the shell got wrong when it tried to do them itself:

  slots  — from a `caw_slotdump --all` capture, list every lock slot in which a
           given CAW node bit appears, with the 9-bit FOOTPRINT (the same
           encoding the kernel logs as vfoot=) and the AG the closure
           classifier would actually use.

  strips — from a dmesg capture, list every P299-CLOSURE-STRIP /
           P299-SCRUB-STRIP with the same computed AG.

THE AG TRAP.  `struct mxfs_resource_id.ag_number` is only meaningful for
type=AG resources; for INODE/ICLUSTER it is left 0, and BOTH the slotdump and
the kernel's own strip log print that 0.  The closure classifier does NOT use
it — mxfs_dlm_closure_classify_cb -> mxfs_quarantine_covers_ino ->
XFS_INO_TO_AGNO(ino), i.e. `ino >> (agblklog + inopblog)`.  So an audit that
trusts the printed ag= field concludes every inode lock lives in AG 0 and
silently passes an in-closure strip.  agblklog/inopblog come from the on-disk
XFS superblock (xfs_dsb bytes 124 and 123).

Resource types that are not AG-scoped (JOURNAL/SUPER/EXTENT) get ag=-1: the
classifier refuses to answer for them, so they are never out of closure.

Usage:
  closure_foot_parse.py slots  <dumpfile> <bit> <inoshift>
  closure_foot_parse.py strips <dmesgfile> <inoshift>

Output lines: "<slot> <ag> <ino> 0x<foot>"  (strips: foot is the logged vfoot)
"""
import re
import sys

FIELDS = [("ex", 0x001), ("pw", 0x002), ("pr", 0x004), ("cw", 0x008),
          ("cr", 0x010), ("wait", 0x020), ("wait_ex", 0x040),
          ("yield", 0x080), ("open", 0x100)]

# caw_slotdump type names -> whether the resource is AG-scoped, and how.
AG_FROM_INO = ("INODE", "ICLUS")
AG_FROM_FIELD = ("AG",)


def res_agno(typename, ag_field, ino, inoshift):
    if typename in AG_FROM_FIELD:
        return ag_field
    if typename in AG_FROM_INO:
        return -1 if ino is None or ino == 0 else (ino >> inoshift)
    return -1


def do_slots(path, bit, inoshift):
    for line in open(path):
        if not line.startswith("slot="):
            continue
        slot = re.search(r"^slot=(\d+)", line).group(1)
        tm = re.search(r"\btype=(\w+)", line)
        agm = re.search(r"\bag=(\d+)", line)
        im = re.search(r"\bino=(\d+)", line)
        foot = 0
        for name, mask in FIELDS:
            # slotdump prints e.g.  wait=0x80000000[31]
            m = re.search(r"\b%s=0x[0-9a-f]+\[([^\]]*)\]" % name, line)
            if m and str(bit) in m.group(1).replace(",", " ").split():
                foot |= mask
        if not foot:
            continue
        ino = int(im.group(1)) if im else None
        ag = res_agno(tm.group(1) if tm else "?",
                      int(agm.group(1)) if agm else -1, ino, inoshift)
        print("%s %d %s 0x%03x" % (slot, ag, ino if ino is not None else "-",
                                   foot))


def do_strips(path, inoshift):
    pat = re.compile(r"P299-(?:CLOSURE|SCRUB)-STRIP\b")
    for line in open(path):
        if not pat.search(line):
            continue
        slot = re.search(r"\bslot=(\d+)", line)
        typ = re.search(r"\btype=(\d+)", line)
        ino = re.search(r"\bino=(\d+)", line)
        agf = re.search(r"\bag=(\d+)", line)
        vf = re.search(r"\bvfoot=0x([0-9a-f]+)", line)
        # kernel logs the numeric mxfs_lock_type: 1=INODE, 3=AG, 6=ICLUSTER
        t = int(typ.group(1)) if typ else -1
        name = {1: "INODE", 3: "AG", 6: "ICLUS"}.get(t, "OTHER")
        i = int(ino.group(1)) if ino else None
        ag = res_agno(name, int(agf.group(1)) if agf else -1, i, inoshift)
        print("%s %d %s 0x%s" % (slot.group(1) if slot else "?", ag,
                                 i if i is not None else "-",
                                 vf.group(1) if vf else "000"))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "slots":
        do_slots(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif mode == "strips":
        do_strips(sys.argv[2], int(sys.argv[3]))
    else:
        sys.exit("usage: closure_foot_parse.py slots|strips ...")
