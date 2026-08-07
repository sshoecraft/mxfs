#!/bin/bash
# tests/withdraw_slot_reclaim_probe.sh — does the next mount STEAL a WITHDRAWN
# heartbeat slot that still owes journal replay, and adopt (suppress) its slice?
#
# ── WHY THIS PROBE EXISTS ────────────────────────────────────────────────────
#
# mxfs_disklock_withdraw() stamps flags=WITHDRAWN on the dying node's HB slot.
# Its own comment (dlm/disklock.c) states the contract:
#
#     "The owning FS has force-shut down; its journal slice MAY HOLD COMMITTED
#      TRANSACTIONS whose buffers were only partially destaged ... Peers MUST
#      replay that slice before they touch anything we held"
#
# But mxfs_disklock_claim_slot()'s pass-2 "fresh claim" scan (disklock.c) walks
# slots 0..63 in index order and accepts the FIRST slot that is
#
#     magic != MXLK  ||  flags != ACTIVE  ||  foreign fs_gen
#
# skipping only flags == RECOVERY_GUARD.  WITHDRAWN satisfies `flags != ACTIVE`,
# so it is claimable.  A pass-2 claim sets ctx->slice_adopted = true, which
# becomes XLOG_MXFS_ADOPTED_SLICE at xfs_log_mount() and SUPPRESSES replay of
# image records in the inherited slice — precisely the records the withdraw
# contract says peers MUST replay.
#
# The scan order makes this near-deterministic rather than rare: on a healthy
# N-node cluster slots 0..N-1 are ACTIVE and N..63 are empty, so a withdrawn
# slot k < N is the FIRST non-ACTIVE slot the scan meets.  It is preferred over
# every genuinely free slot.
#
# Pass-1 ("own-stamp reclaim", the path that keeps FULL replay via
# slice_adopted=false) cannot save this: it matches on node_id alone, and
# node_id = uuid_to_node_id(random UUID drawn fresh at every mount)
# (dlm/v5_mount.c) — so it never matches after a remount.  Measured on the
# 32-node rig: 0 own-stamp reclaims out of 91 claims.
#
# ── WHAT IT MEASURES ─────────────────────────────────────────────────────────
#
# 1. Which slot the victim's remount claims, and whether the claim was a
#    pass-2 "fresh claim - slice ADOPTED" or a pass-1 "own-stamp reclaim".
# 2. The width of the claimable window: the flags timeline of the victim's slot
#    sampled O_DIRECT from a survivor (ACTIVE -> WITHDRAWN -> GUARD/zeroed).
#    If a RECOVERY_GUARD lands before the remount, pass-2 skips the slot and
#    the hazard is not reachable on that timing.
# 3. DURABILITY: the payload is fsync'd files (fsync file + fsync parent dir =
#    a durability ACKNOWLEDGEMENT) written immediately before the force
#    shutdown, so their metadata is committed to the journal slice but not
#    necessarily destaged.  Replay is what makes them survive.  If they are
#    missing afterwards, that is ACKNOWLEDGED METADATA LOSS, not a soft miss.
#
# Every device read is O_DIRECT: a buffered re-read of the shared LUN is served
# from the reader's own page cache, which no peer write invalidates, so a
# buffered sampler would report the first sample forever (sess88).
#
# All kmsg evidence is scoped to a per-run marker dropped on every node —
# unscoped dmesg windows are themselves an evidence bug (sess27), and the ring
# buffers here hold prior runs.
#
# Usage: tests/withdraw_slot_reclaim_probe.sh [victim=test32] [reader=test1] \
#                                             [nfiles=100] [dev=/dev/mapper/mpatha]
set -u

VICTIM="${1:-test32}"
READER="${2:-test1}"
NFILES="${3:-100}"
DEV="${4:-/dev/mapper/mpatha}"
MNT=/mnt/shared

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$ROOT/tools/mxfs_sshpass.sh"

RUN=$$-$(date -u +%H%M%S)
MARK="WSRP-$RUN"
PAYLOAD="wsrp_$RUN"
OUT=$(mktemp -d)

# RULE 0 budgets, derived (not round numbers):
#   payload: NFILES fsync'd creates; native XFS ~1s, mxfs cluster pace x2 -> 60s
#   unmount after force-shutdown: fs already down, teardown only          -> 90s
#   mount: measured mxfs mount ~5-15s; pre-mountfs recovery barrier can
#          wait out the dead-confirm window (~124s) -> 124 + 15 + slack   -> 180s
BUDGET_PAYLOAD=60
BUDGET_UMOUNT=90
BUDGET_MOUNT=180
WINDOW_S=150          # reader-side slot sampling span

say() { printf '\n==== %s ====\n' "$*"; }

# ── decode one slot of the HB region, O_DIRECT, from an arbitrary node ───────
slot_probe() {   # slot_probe <node> <mode> [slot] [span_s]
    local node="$1" mode="$2" slot="${3:-0}" span="${4:-0}"
    "$SSH" "$node" "python3 - <<'PYEOF'
import struct, os, time, mmap
DEV='$DEV'; MODE='$mode'; SLOT=int('$slot'); SPAN=float('$span')
NSLOTS=64; RECSZ=512; REGION=NSLOTS*RECSZ; MAGIC=0x4D584C4B
FL={0:'empty',1:'ACTIVE',2:'WITHDRAWN',3:'GUARD'}
f=os.open(DEV, os.O_RDONLY); sup=os.pread(f,4096,0); os.close(f)
dloff,=struct.unpack_from('<Q',sup,64)
if dloff % 4096: raise SystemExit('disklock_offset not 4096-aligned')
def sample():
    fd=os.open(DEV, os.O_RDONLY|os.O_DIRECT)
    try:
        buf=mmap.mmap(-1, REGION)
        if os.preadv(fd,[buf],dloff)!=REGION: raise SystemExit('short read')
        return bytes(buf)
    finally: os.close(fd)
def dec(blob,s):
    r=blob[s*RECSZ:(s+1)*RECSZ]
    magic,flags,node,gen=struct.unpack_from('<IIII',r,0)
    ts,=struct.unpack_from('<Q',r,16); ep,=struct.unpack_from('<Q',r,24)
    return magic,flags,node,gen,ts,ep
if MODE=='table':
    b=sample()
    for s in range(NSLOTS):
        m,fl,n,g,t,e=dec(b,s)
        if m!=MAGIC and fl==0 and n==0: continue
        print('%d %s %d %d %d' % (s, FL.get(fl,'?%d'%fl), n, g, e))
else:
    # timeline: sample SLOT every 250ms for SPAN seconds, print only CHANGES
    t0=time.time(); last=None
    while time.time()-t0 < SPAN:
        m,fl,n,g,ts,e=dec(sample(),SLOT)
        cur=(m,fl,n,e)
        if cur!=last:
            print('t+%6.2fs slot=%d magic=%s flags=%-9s node=%-10d epoch=%d'
                  % (time.time()-t0, SLOT, 'MXLK' if m==MAGIC else hex(m),
                     FL.get(fl,'?%d'%fl), n, e), flush=True)
            last=cur
        time.sleep(0.25)
    print('t+%6.2fs (timeline end)' % (time.time()-t0), flush=True)
PYEOF" 2>/dev/null
}

say "PRE: heartbeat slot table (O_DIRECT via $READER)"
slot_probe "$READER" table | tee "$OUT/pre_table"

# Which slot does the victim hold?  Take it from the victim's OWN kernel view
# (authoritative) and cross-check against the on-disk table.
VSLOT=$("$SSH" "$VICTIM" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null \
        | sed -n 's/.*claimed heartbeat slot \([0-9]*\) for node \([0-9]*\).*/\1/p')
VNODE=$("$SSH" "$VICTIM" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null \
        | sed -n 's/.*claimed heartbeat slot \([0-9]*\) for node \([0-9]*\).*/\2/p')
if [ -z "${VSLOT:-}" ]; then
    echo "FATAL: cannot determine $VICTIM's heartbeat slot from its dmesg"; exit 2
fi
VEPOCH=$(awk -v s="$VSLOT" '$1==s {print $5}' "$OUT/pre_table")
DISK_NODE=$(awk -v s="$VSLOT" '$1==s {print $3}' "$OUT/pre_table")
echo
echo "victim=$VICTIM slot=$VSLOT node_id=$VNODE epoch=$VEPOCH (on-disk node at that slot: $DISK_NODE)"
if [ "$DISK_NODE" != "$VNODE" ]; then
    echo "FATAL: on-disk slot $VSLOT names node $DISK_NODE, victim believes $VNODE — refusing to probe"
    exit 2
fi

# First free (empty) slot — where a claim SHOULD go if the withdrawn slot is
# correctly refused.  This is the discriminator for the verdict.
FREE=$(awk '{seen[$1]=1} END {for(i=0;i<64;i++) if(!(i in seen)) {print i; exit}}' "$OUT/pre_table")
echo "first genuinely-free slot = $FREE   (a correct claim lands HERE, not on $VSLOT)"

say "MARK: scoping every node's kmsg to this run ($MARK)"
for i in $(seq 1 32); do
    ( "$SSH" "test$i" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) &
done
wait
echo "marker $MARK dropped on 32 nodes"

say "PAYLOAD: $NFILES fsync'd creates on $VICTIM (budget ${BUDGET_PAYLOAD}s)"
t0=$(date +%s)
"$SSH" "$VICTIM" "python3 - <<'PYEOF'
import os
d='$MNT/$PAYLOAD'
os.mkdir(d)
dfd=os.open(d, os.O_RDONLY)
for i in range($NFILES):
    p=os.path.join(d,'f%04d'%i)
    fd=os.open(p, os.O_CREAT|os.O_WRONLY, 0o644)
    os.write(fd, b'wsrp')
    os.fsync(fd)          # file data+metadata committed to the journal
    os.close(fd)
os.fsync(dfd)             # the DIRECTORY entries are acknowledged too
os.close(dfd)
print('payload: %d files fsync-acknowledged in %s' % ($NFILES, d))
PYEOF" 2>&1 | tail -3
t1=$(date +%s); PAY=$((t1-t0))
echo "payload wall=${PAY}s budget=${BUDGET_PAYLOAD}s"
if [ "$PAY" -gt "$BUDGET_PAYLOAD" ]; then
    echo "RULE0-FAIL: payload exceeded its derived budget (${PAY}s > ${BUDGET_PAYLOAD}s)"
fi

# The reader-side timeline must be running BEFORE the shutdown so it captures
# the ACTIVE->WITHDRAWN transition and whatever follows.
say "TIMELINE: sampling slot $VSLOT from $READER for ${WINDOW_S}s (O_DIRECT, 250ms)"
( slot_probe "$READER" timeline "$VSLOT" "$WINDOW_S" > "$OUT/timeline" 2>&1 ) &
TLPID=$!
sleep 2

say "SHUTDOWN: XFS_IOC_GOINGDOWN(2, NOLOGFLUSH) on $VICTIM"
date -u +'shutdown issued at %H:%M:%SZ'
"$SSH" "$VICTIM" "python3 -c \"
import fcntl, os, struct
fd = os.open('$MNT', os.O_RDONLY)
fcntl.ioctl(fd, 0x8004587d, struct.pack('I', 2))
os.close(fd)
print('GOINGDOWN(2) sent')\"" 2>&1 | tail -2

say "REMOUNT: unmount + mount $VICTIM as fast as the node allows"
t0=$(date +%s)
"$SSH" "$VICTIM" "timeout $BUDGET_UMOUNT umount $MNT 2>&1 || { echo 'plain umount failed/timed out — lazy'; umount -l $MNT 2>&1; }" 2>&1 | tail -3
t1=$(date +%s); echo "umount wall=$((t1-t0))s budget=${BUDGET_UMOUNT}s"

t0=$(date +%s)
"$SSH" "$VICTIM" "timeout $BUDGET_MOUNT mount -t mxfs $DEV $MNT 2>&1; echo mount_rc=\$?" 2>&1 | tail -4
t1=$(date +%s); MNTW=$((t1-t0))
echo "mount wall=${MNTW}s budget=${BUDGET_MOUNT}s"
if [ "$MNTW" -gt "$BUDGET_MOUNT" ]; then
    echo "RULE0-FAIL: mount exceeded its derived budget (${MNTW}s > ${BUDGET_MOUNT}s)"
fi

say "CLAIM: which slot did the remount take?"
CLAIM=$("$SSH" "$VICTIM" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null)
echo "${CLAIM:-<no claim line after marker>}"
NSLOT=$(printf '%s' "$CLAIM" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
KIND=$(printf '%s' "$CLAIM" | grep -o 'own-stamp reclaim\|fresh claim — slice ADOPTED')

echo
echo "--- reader-side slot $VSLOT timeline (captured across the shutdown) ---"
wait $TLPID 2>/dev/null
cat "$OUT/timeline"

say "SURVIVOR EVIDENCE (scoped to $MARK)"
for i in $(seq 1 32); do
    ( "$SSH" "test$i" "dmesg | sed -n '/$MARK/,\$p' | grep -aoE 'P237-[A-Z-]+|P234-RECOV-[A-Z-]+|P163-RECOVERY-[A-Z]+|P236-WITHDRAW-[A-Z]+|P97-SWEEP-DONE' | sort | uniq -c" 2>/dev/null \
        | sed "s/^/test$i /" > "$OUT/ev_$i" ) &
done
wait
cat "$OUT"/ev_* 2>/dev/null | awk '{c[$3]+=$2; n[$3]++} END {for(k in c) printf "%-30s total=%-5d nodes=%d\n", k, c[k], n[k]}' | sort

say "DURABILITY: are the $NFILES fsync-acknowledged files still there?"
SEEN=$("$SSH" "$READER" "ls -1 $MNT/$PAYLOAD 2>/dev/null | wc -l" 2>/dev/null | tr -d '[:space:]')
echo "reader $READER sees ${SEEN:-0} of $NFILES files in $MNT/$PAYLOAD"

say "VERDICT"
echo "withdrawn slot .......... $VSLOT   (victim node $VNODE, epoch $VEPOCH)"
echo "first free slot ......... $FREE"
echo "slot claimed on remount . ${NSLOT:-<none>}"
echo "claim kind .............. ${KIND:-<none>}"
echo "files surviving ......... ${SEEN:-0} / $NFILES"
rc=0
if [ "${NSLOT:-}" = "$VSLOT" ]; then
    echo
    echo "STOLEN: the remount claimed the WITHDRAWN slot $VSLOT, not the free slot $FREE."
    if [ "$KIND" = "fresh claim — slice ADOPTED" ]; then
        echo "ADOPTED: the slice that the withdraw contract says peers MUST replay was"
        echo "         taken as a pass-2 fresh claim, which sets XLOG_MXFS_ADOPTED_SLICE"
        echo "         and suppresses image replay of exactly those records."
    fi
    rc=1
else
    echo
    echo "REFUSED: the remount did not take the withdrawn slot (took ${NSLOT:-none})."
fi
if [ "${SEEN:-0}" != "$NFILES" ]; then
    echo "ACK-LOSS: ${SEEN:-0}/$NFILES fsync-acknowledged files are missing after recovery."
    rc=1
fi
echo
echo "artifacts: $OUT"
exit $rc
