#!/usr/bin/env python3
"""
inode_flag_bits_audit.py — every in-core inode flag in xfs/xfs_inode.h must
own its bit.

The XFS and MXFS inode flags share one word, ip->i_flags, and every one of
them is a `#define NAME (1 << N)` (or `(1U << N)`, `(1UL << N)`, or a bit
number named by a `__NAME_BIT` define).  Nothing in the language stops two
of them naming the same N, and on 2026-09-28 two did: MXFS_IF_ACQ_REFUSED,
the acquire classifier's "the DLM denied this inode" mark, and
MXFS_IF_ADOPTED_UNLINK, the deferred-reap "this node is the adopted freer of
this orphan" mark, were both 1U << 28 — so a denial under a blocked recovery
read as freer authority at inactivation.  The header now carries a
compile-time check as well; this audit is the one full_verify.sh runs, and
it says WHICH two names collide.

XFS_IPINNED is excluded: it is a wait-bit KEY (wake_up_bit / DEFINE_WAIT_BIT
on &ip->i_flags with __XFS_IPINNED_BIT), never stored in the word, and the
tree keeps MXFS_IF_FOREIGN_ZOMBIE on that bit deliberately.

Exit 0 when every stored flag has a bit of its own, 1 on a collision (each
one printed), 2 when the header cannot be parsed.
"""
import os
import re
import sys

HEADER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "xfs", "xfs_inode.h")
WAIT_BIT_KEYS = {"XFS_IPINNED"}

DEFINE = re.compile(r"^#define\s+(XFS_I[A-Z_0-9]*|XFS_[A-Z_0-9]*_RELEASED|XFS_NEED_INACTIVE|MXFS_IF_[A-Z_0-9]*)\s+\(1U?L?\s*<<\s*([0-9]+|__[A-Z_0-9]+_BIT)\)")
BITDEF = re.compile(r"^#define\s+(__[A-Z_0-9]+_BIT)\s+([0-9]+)\b")


def main():
    try:
        with open(HEADER) as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"inode_flag_bits_audit: cannot read {HEADER}: {e}")
        return 2
    bitnames = {}
    for line in lines:
        m = BITDEF.match(line)
        if m:
            bitnames[m.group(1)] = int(m.group(2))
    owners = {}
    total = 0
    for n, line in enumerate(lines, 1):
        m = DEFINE.match(line)
        if not m:
            continue
        name, bit = m.group(1), m.group(2)
        if bit.startswith("__"):
            if bit not in bitnames:
                print(f"inode_flag_bits_audit: {HEADER}:{n}: {name} uses {bit}, which is not defined")
                return 2
            bit = bitnames[bit]
        else:
            bit = int(bit)
        total += 1
        if name in WAIT_BIT_KEYS:
            continue
        owners.setdefault(bit, []).append((name, n))
    if total < 20:
        print(f"inode_flag_bits_audit: only {total} flag defines parsed from {HEADER}; the header's shape changed")
        return 2
    rc = 0
    for bit in sorted(owners):
        if len(owners[bit]) > 1:
            rc = 1
            who = ", ".join(f"{name} (line {n})" for name, n in owners[bit])
            print(f"inode_flag_bits_audit: bit {bit} is shared by {who}")
    print(f"inode_flag_bits_audit: {total} flags, {len(owners)} stored bits, {'FAIL' if rc else 'OK'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
