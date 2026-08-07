#!/bin/bash
# tests/hb_live_count.sh — AUTHORITATIVE live-member count from the on-disk
# disklock heartbeat table.  Prints a single integer (or "err").
#
# Why this exists: the MXFS-MEMBERSHIP beacon reports the LEASE view, which
# retains a dead identity until MXFS_LEASE_TIMEOUT_DEFAULT_MS (600000 = 10
# MINUTES) has passed.  Any node that dies and rejoins takes a NEW node_id,
# so after every fault-injecting test the lease legitimately reads N+1 for
# up to ten minutes while the disk table — the real membership — already
# reads exactly N.  Gating a board on the beacon therefore blocks whole
# chunks on a healthy cluster (sess43: crash_consistency at 32/caw left
# active_count=33 and BLOCKED the rest of the chunk; the disk table showed
# exactly 32 correct members the whole time, and the beacon returned to 32
# on schedule).
#
# TWO TRAPS this script exists to get right:
#  1. HB timestamps are each writer's MONOTONIC clock (uptime), not wall
#     time, so they cannot be compared against local time.  A slot is LIVE
#     iff its timestamp CHANGES across two samples — the same rule the
#     kernel monitor uses.
#  2. The samples MUST bypass the page cache (O_DIRECT).  Peers write these
#     sectors; a buffered re-read returns this node's cached copy and every
#     slot looks frozen (first version of this script reported live=0 on a
#     perfectly healthy 32-node cluster).
#
# usage: hb_live_count.sh [node=test1] [dev=/dev/mapper/mpatha] [gap_s=5]
set -u
NODE="${1:-test1}"
DEV="${2:-/dev/mapper/mpatha}"
GAP="${3:-5}"

tools/mxfs_sshpass.sh "$NODE" "
DL=\$(python3 -c \"
import struct,os
f=os.open('$DEV',os.O_RDONLY)
print(struct.unpack_from('<Q',os.pread(f,4096,0),64)[0])\")
SK=\$((DL/512))
A=\$(mktemp); B=\$(mktemp)
dd if=$DEV of=\$A bs=512 skip=\$SK count=64 iflag=direct 2>/dev/null
sleep $GAP
dd if=$DEV of=\$B bs=512 skip=\$SK count=64 iflag=direct 2>/dev/null
python3 - \$A \$B <<'EOF'
import struct, sys
def snap(p):
    d=open(p,'rb').read(); out={}
    for s in range(64):
        r=d[s*512:(s+1)*512]
        if len(r)<32: continue
        magic,flags,node,gen=struct.unpack_from('<IIII',r,0)
        ts,=struct.unpack_from('<Q',r,16)
        if magic==0x4D584C4B and flags==1:
            out[s]=(node,ts)
    return out
a=snap(sys.argv[1]); b=snap(sys.argv[2])
print(sum(1 for s in a if s in b and b[s][1]!=a[s][1]))
EOF
rm -f \$A \$B" 2>/dev/null | tr -d ' \r\n'
