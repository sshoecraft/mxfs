#!/bin/bash
# tests/hb_slots.sh — dump the on-disk disklock heartbeat slot table.
#
# Ground truth for "who does the cluster think is a member": every 512-byte
# HB record in the disklock region, decoded.  Use when active_count disagrees
# with the number of mounted nodes (ghost/stale member hunting), or to see
# recovery GUARD records (flags=3, sess43) during an unclaimed-bucket sweep.
#
# Record layout (dlm/disklock.h struct mxfs_disklock_heartbeat):
#   0x00 magic "MXLK" 0x4D584C4B | 0x04 flags (0=empty 1=ACTIVE 2=WITHDRAWN
#   3=RECOVERY_GUARD) | 0x08 node_id | 0x0C fs_gen | 0x10 timestamp_ms
#   | 0x18 epoch | 0x20 lock_count
#
# LIVENESS IS A TWO-SAMPLE TEST, NOT AN AGE (sess88 evidence-integrity fix).
#   timestamp_ms is ktime_get_boottime — per-node UPTIME.  It is ONLY ever
#   comparable to ITSELF (same slot, same incarnation); it is NOT a wall clock
#   and NOT comparable across nodes.  The previous version of this script did
#   `age = wall_now_ms - timestamp_ms`, which on a healthy 32-node cluster
#   yields ~1.79e9 seconds and made every record look decades stale: it printed
#   "live ACTIVE: 0" with all 32 nodes mounted and heartbeating.  That is a
#   false negative on the single question this tool exists to answer.
#   The correct test is the one hb_guard_clobber_probe.sh uses: sample the
#   record TWICE, at least one HB interval apart, and ask whether timestamp_ms
#   ADVANCED.
#
# ALL DEVICE I/O IS O_DIRECT.  A buffered re-read of /dev/mapper/mpatha is
# served from the READER's page cache, which no peer's write ever invalidates,
# so the second sample would return the first sample's bytes and every live
# node would read as dead.  O_DIRECT is what makes the two-sample test mean
# anything.
#
# usage: hb_slots.sh [node=test1] [dev=/dev/mapper/mpatha] [settle_s=5]
#   settle_s must exceed MXFS_DISKLOCK_HB_INTERVAL_MS (2000ms); default 5s
#   gives every live node at least two chances to tick.
set -u
NODE="${1:-test1}"
DEV="${2:-/dev/mapper/mpatha}"
SETTLE="${3:-5}"

tools/mxfs_sshpass.sh "$NODE" "python3 - <<'EOF'
import struct, os, time, mmap

DEV='$DEV'
SETTLE=float('$SETTLE')
NSLOTS=64
RECSZ=512
REGION=NSLOTS*RECSZ            # 32768
MAGIC=0x4D584C4B               # 'MXLK'
FL={0:'empty',1:'ACTIVE',2:'WITHDRAWN',3:'GUARD'}

# The superblock read may be buffered (it is static for the life of the FS);
# only the repeated HB-region reads need O_DIRECT.
f=os.open(DEV, os.O_RDONLY)
sup=os.pread(f,4096,0)
dloff,=struct.unpack_from('<Q',sup,64)
os.close(f)

# O_DIRECT demands an aligned buffer AND an aligned offset/length.  The
# disklock region is 4096-aligned by mkfs layout and 32768 bytes long, so one
# whole-region read satisfies both; mmap gives us a page-aligned buffer.
if dloff % 4096:
    raise SystemExit('disklock_offset %d is not 4096-aligned — O_DIRECT read '
                     'would EINVAL; layout assumption broken' % dloff)

def sample():
    fd=os.open(DEV, os.O_RDONLY|os.O_DIRECT)
    try:
        buf=mmap.mmap(-1, REGION)
        n=os.preadv(fd,[buf],dloff)
        if n!=REGION:
            raise SystemExit('short O_DIRECT read: %d of %d' % (n,REGION))
        return bytes(buf)
    finally:
        os.close(fd)

a=sample()
time.sleep(SETTLE)
b=sample()

def dec(blob,s):
    r=blob[s*RECSZ:(s+1)*RECSZ]
    magic,flags,node,gen=struct.unpack_from('<IIII',r,0)
    ts,=struct.unpack_from('<Q',r,16)
    ep,=struct.unpack_from('<Q',r,24)
    return magic,flags,node,gen,ts,ep

live=0; present=0
print('slot flags      node_id     fs_gen      d_ts_ms  hb   epoch')
for s in range(NSLOTS):
    m0,f0,n0,g0,t0,e0=dec(a,s)
    m1,f1,n1,g1,t1,e1=dec(b,s)
    if m0!=MAGIC and m1!=MAGIC:
        continue
    present+=1
    dts=t1-t0
    # A live heartbeater advances timestamp_ms.  Anything else (no advance,
    # or a backwards jump = the slot was reclaimed by a rebooted incarnation)
    # is NOT live.
    beating = (m1==MAGIC and f1==1 and dts>0)
    if beating: live+=1
    tag=FL.get(f1,'?%d'%f1)
    hb='beat' if beating else ('--' if dts==0 else 'BACK')
    note=''
    if e0!=e1: note+=' EPOCH-CHANGED(%d->%d)'%(e0,e1)
    if f0!=f1: note+=' FLAGS-CHANGED(%s->%s)'%(FL.get(f0,f0),FL.get(f1,f1))
    if n0!=n1: note+=' NODE-CHANGED(%d->%d)'%(n0,n1)
    print('%4d %-10s %-11d %-11d %8d %-4s %d%s' % (s,tag,n1,g1,dts,hb,e1,note))
print('--- records present: %d   beating (ts advanced over %.1fs): %d'
      % (present,SETTLE,live))
EOF" 2>/dev/null
