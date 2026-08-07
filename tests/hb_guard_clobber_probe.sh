#!/bin/bash
# tests/hb_guard_clobber_probe.sh — does a LIVE node's heartbeat destroy a
# foreign write to its own disklock slot?
#
# WHY THIS EXISTS (sess77 GPT RULE-5 ruling, D-FENCED-STAGE-WITHOUT-PROVEN-
# EXCLUSION / D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION):
#   disklock_hb_fn() fills a 512B record and BLIND-writes it every
#   MXFS_DISKLOCK_HB_INTERVAL_MS (2000).  No read, no CAS.  So any recovery
#   GUARD / recovery descriptor a survivor lays into that node's slot is
#   destroyed by the victim's very next heartbeat.  That
#     (a) destroys the one-shot SCSI-PR fence certificate (the key is consumed
#         by the PREEMPT AND ABORT but the certify CAS then fails, so NO
#         successor can ever prove exclusion — the slice is unreplayable), and
#     (b) leaves a node whose slot is guarded still heartbeating and still
#         writing to the filesystem while a survivor replays its journal.
#
# THE MEASUREMENT
#   1. Learn the victim's HB slot + node_id from its own kmsg claim line.
#   2. From a DIFFERENT node, prove the victim is live: its record's
#      timestamp_ms must ADVANCE across one HB interval.  (timestamp_ms is
#      ktime_get_boottime — per-node UPTIME.  It is ONLY ever comparable to
#      ITSELF; never subtract a reader's clock from it.  See tests/hb_slots.sh)
#   3. Write back the SAME 512 bytes with one field changed: flags 1 (ACTIVE)
#      -> 3 (RECOVERY_GUARD).  That is exactly the transition
#      mxfs_disklock_recovery_begin() makes (it preserves magic/node_id/fs_gen/
#      epoch/timestamp byte for byte and only moves `flags`).
#   4. Poll the record for WATCH_S seconds.
#
# ALL DEVICE I/O IS O_DIRECT.  Buffered reads of /dev/mapper/mpatha are served
# from the READER's page cache, which no peer's write ever invalidates — a
# buffered probe reads back its own write and reports a false HELD.
#
# VERDICT
#   CLOBBERED  — flags returned to ACTIVE (and timestamp_ms moved).  The
#                victim's heartbeat overwrote a foreign write to its own slot.
#                DEFECT PRESENT.
#   HELD       — flags stayed RECOVERY_GUARD for the whole window.  The
#                heartbeat writer refused to clobber it.  For a PASS the victim
#                must ALSO self-fence (this script greps its kmsg for that).
#
# AFTER THE FIX THIS PROBE FORCE-SHUTS-DOWN THE VICTIM'S MOUNT, BY DESIGN.
# That is the correct behaviour under test: a node whose slot has been taken
# over by a recovery must stop writing.  Remount/prep the victim afterwards.
#
# usage: hb_guard_clobber_probe.sh [victim=test2] [writer=test1] [dev] [watch_s]
set -u
VICTIM="${1:-test2}"
WRITER="${2:-test1}"
DEV="${3:-/dev/mapper/mpatha}"
WATCH_S="${4:-12}"

SSH=tools/mxfs_sshpass.sh

if [ "$VICTIM" = "$WRITER" ]; then
    echo "probe: victim and writer must be different nodes" >&2
    exit 2
fi

# ── 1. victim's slot + node_id, from its own claim line ──────────────────────
claim=$($SSH "$VICTIM" \
    "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
NODEID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
if [ -z "${SLOT:-}" ] || [ -z "${NODEID:-}" ]; then
    echo "probe: could not learn $VICTIM's slot/node_id from kmsg" >&2
    echo "       last claim line: '$claim'" >&2
    exit 2
fi
echo "probe: victim=$VICTIM slot=$SLOT node_id=$NODEID writer=$WRITER dev=$DEV"

# Mark the victim's kmsg so we only read this probe's window.
MARK="HBGUARD-PROBE-$$-$(date -u +%s)"
$SSH "$VICTIM" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# ── 2-4. liveness proof, guard write, watch ─────────────────────────────────
$SSH "$WRITER" "SLOT=$SLOT NODEID=$NODEID DEV=$DEV WATCH_S=$WATCH_S python3 - <<'PYEOF'
import struct, os, sys, time, mmap

SLOT=int(os.environ['SLOT']); NODEID=int(os.environ['NODEID'])
DEV=os.environ['DEV']; WATCH=float(os.environ['WATCH_S'])
MAGIC=0x4D584C4B; ACTIVE=1; GUARD=3
DESC_OFF=40                      # union {evict,recov} starts at HB byte 40
DESC_MAGIC=0x5643524D            # MXFS_RECOV_DESC_MAGIC 'MRCV'

fd=os.open(DEV, os.O_RDWR|os.O_DIRECT)
buf=mmap.mmap(-1, 4096)          # page-aligned: O_DIRECT requires it
mv=memoryview(buf)

def dread(off, n):
    got=os.preadv(fd, [mv[:n]], off)
    if got!=n: raise IOError('short O_DIRECT read %d' % got)
    return bytes(mv[:n])

def dwrite(off, data):
    mv[:len(data)]=data
    put=os.pwritev(fd, [mv[:len(data)]], off)
    if put!=len(data): raise IOError('short O_DIRECT write %d' % put)

sup=dread(0,4096)
dloff,=struct.unpack_from('<Q',sup,64)
off=dloff+SLOT*512
print('disklock_offset=%d slot_off=%d' % (dloff,off))

def rd():
    b=dread(off,512)
    magic,flags,node,gen=struct.unpack_from('<IIII',b,0)
    ts,=struct.unpack_from('<Q',b,16)
    ep,=struct.unpack_from('<Q',b,24)
    dm,=struct.unpack_from('<I',b,DESC_OFF)
    return b,magic,flags,node,gen,ts,ep,dm

FL={0:'empty',1:'ACTIVE',2:'WITHDRAWN',3:'GUARD'}
def show(tag,r):
    _,magic,flags,node,gen,ts,ep,dm=r
    print('%-9s magic=%s flags=%-9s node=%-11d ts=%d epoch=%d desc=%s'
          % (tag,'MXLK' if magic==MAGIC else hex(magic),
             FL.get(flags,'?%d'%flags),node,ts,ep,
             'MRCV' if dm==DESC_MAGIC else ('0' if dm==0 else hex(dm))))

a=rd(); show('t0',a)
if a[1]!=MAGIC or a[3]!=NODEID:
    print('ABORT: slot %d is not node %d record' % (SLOT,NODEID)); sys.exit(2)
if a[2]!=ACTIVE:
    print('ABORT: slot %d flags=%d, expected ACTIVE — victim not a live member'
          % (SLOT,a[2])); sys.exit(2)

# liveness: timestamp_ms MUST advance across one HB interval (2 s) + slack
time.sleep(2.6)
b=rd(); show('t+2.6',b)
if b[5]<=a[5]:
    print('ABORT: timestamp_ms did not advance (%d -> %d) — victim is NOT'
          ' heartbeating; the probe would measure nothing' % (a[5],b[5]))
    sys.exit(2)
print('LIVE: timestamp_ms advanced %d -> %d (+%d ms) — victim IS heartbeating'
      % (a[5],b[5],b[5]-a[5]))

# the foreign write: exactly recovery_begin() transition, flags field only
img=bytearray(b[0])
struct.pack_into('<I',img,4,GUARD)
dwrite(off,bytes(img))
wr_ts=b[5]
print('WROTE: flags ACTIVE -> RECOVERY_GUARD at slot %d (all other bytes'
      ' unchanged, ts=%d)' % (SLOT,wr_ts))

t0=time.time(); clob=None; samples=[]
while time.time()-t0 < WATCH:
    time.sleep(0.4)
    c=rd()
    samples.append((round(time.time()-t0,1),c[2],c[5]))
    if c[2]!=GUARD and clob is None:
        clob=(round(time.time()-t0,1),c)
        show('CLOBBER',c)
        break
for s in samples[-3:]:
    print('  sample t+%-5s flags=%-9s ts=%d' % (s[0],FL.get(s[1],'?%d'%s[1]),s[2]))

f=rd(); show('final',f)
if clob:
    print('VERDICT: CLOBBERED at t+%ss — the victim heartbeat destroyed a'
          ' foreign write to its own slot (flags now %d, ts %d -> %d).'
          ' DEFECT PRESENT.' % (clob[0],f[2],wr_ts,f[5]))
    sys.exit(1)
print('VERDICT: HELD for %.0fs — flags stayed RECOVERY_GUARD (ts %d -> %d).'
      % (WATCH,wr_ts,f[5]))
sys.exit(0)
PYEOF"
rc=$?

echo "--- $VICTIM kmsg since probe mark ---"
$SSH "$VICTIM" \
  "dmesg | sed -n '/$MARK/,\$p' | grep -a -i 'mxfs\|disklock\|XFS' | tail -40" \
  2>/dev/null

echo "--- probe rc=$rc (0=HELD 1=CLOBBERED 2=setup/abort) ---"
exit $rc
