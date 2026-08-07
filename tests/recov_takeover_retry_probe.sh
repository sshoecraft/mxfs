#!/bin/bash
# tests/recov_takeover_retry_probe.sh — what does a recovery owner do when its
# milestone advance can NEVER succeed?
#
# WHY THIS EXISTS (D-RECOV-ADVANCE-UNBOUNDED-RETRY, sess91)
#   sess91 measured a recovery owner logging 11 P234-RECOV-NOTOURS /
#   P234-COMPLETE-REPLAYEDFAIL pairs over 12 minutes with no bound, no backoff,
#   no classification, no relinquish-to-another-owner and no escalation, while
#   the victim's CAW grants stayed frozen behind it.  The particular -EBUSY
#   source in that incident is fixed (D-RECOV-AUTH-ZERO-VICTIM-EPOCH-WEDGE,
#   0.11.421), but the RETRY STRUCTURE that turned it into an indefinite hang is
#   unchanged: any permanent advance failure reproduces it.  This probe creates
#   one on demand.
#
#   It also exercises the 0.11.421 P234-RECOV-NOTOURS rework, which added
#   kind=TAKEOVER vs kind=TOKEN-MISMATCH.  That code shipped having only ever
#   been observed NOT firing; this is its positive test.
#
# THE INJECTION
#   1. Hard-kill the victim and wait for a survivor to publish a durable
#      recovery descriptor into the victim's slot (flags -> RECOVERY_GUARD).
#   2. Rewrite ONLY desc.owner_node, to a value no live node can hold.  The
#      owner then fails recov_auth_holds()'s FIRST test
#      (d->owner_node != ctx->local_node), which is a real takeover as far as
#      the code is concerned, and every subsequent advance returns -EBUSY.
#
#   The descriptor is CRC-protected, so the write must reseal it:
#     crc = crc32c(0xFFFFFFFF, desc[0 .. offsetof(crc32c)=116])
#     crc = crc32c(crc, packed{ fs_gen:u32, node_id:u32, epoch:u64 })
#   where that identity triple comes from the RECORD HEADER, not from the
#   descriptor's own victim_* fields — recov_desc_crc() binds the payload to the
#   header it was sealed against, so a payload spliced next to a different
#   victim's header fails.  In a GUARD record the header still carries the
#   VICTIM's identity (the descriptor rule that the victim's node_id / fs_gen /
#   epoch are never overwritten), so it is readable straight off the sector.
#
#   SELF-CHECK, load-bearing: recompute the crc of the UNMODIFIED descriptor
#   first and abort unless it reproduces the stored value.  Without that, a
#   wrong crc convention would silently produce an unparseable descriptor and
#   the probe would measure -EPROTO instead of -EBUSY — a different arm.
#
# WHAT IT ASSERTS
#   1. The refusal is CLASSIFIED correctly: P234-RECOV-NOTOURS must say
#      kind=TAKEOVER (the descriptor owner really is not us), not
#      kind=TOKEN-MISMATCH.
#   2. The retry is BOUNDED.  Over the observation window the owner must stop
#      retrying and do something terminal — relinquish, escalate, or fail the
#      filesystem loudly.  A retry count that just keeps climbing IS the defect
#      and this probe reports it as a FAIL with the observed rate.
#
# NOTE: this leaves the slot frozen.  The victim's grants are held by a dead
#   node and the descriptor is unowned-by-anyone-live.  A re-prep is REQUIRED
#   afterwards:  MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
#
# TIMING (RULE 0 — derived, not chosen)
#   guard appears : DEAD_THRESHOLD(31)*HB_INTERVAL_MS(2000) declare  = 62s
#                 + the confirm sweep                                = 62s
#                 + fence/dispatch/replay                            = 15s
#                 = 139s;  GUARD_S default 180 is that plus ssh slack.
#   observe       : the loop's own period is unbounded by construction, so the
#                   window is a policy choice, not a budget: 120s is long enough
#                   that "bounded" and "unbounded" are distinguishable, given
#                   the 12-minute/11-retry incident that motivated this.
#
# usage: recov_takeover_retry_probe.sh [victim=test32] [writer=test1]
#                                      [guard_s=180] [observe_s=120]
set -u
VICTIM="${1:-test32}"
WRITER="${2:-test1}"
GUARD_S="${3:-180}"
OBSERVE_S="${4:-120}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NODES_N="${MXFS_NODES:-32}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
[ "$VICTIM" = "$WRITER" ] && { echo "probe: victim and writer must differ" >&2; exit 2; }

MARK="TAKEOVER-$$-$(date -u +%s)"
echo "probe: victim=$VICTIM writer=$WRITER dev=$DEV mark=$MARK"

claim=$($SSH "$VICTIM" \
    "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
     journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
    2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
NODEID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
[ -n "${SLOT:-}" ] && [ -n "${NODEID:-}" ] || {
    echo "probe: could not learn $VICTIM's slot/node_id: '$claim'" >&2; exit 2; }
echo "probe: victim slot=$SLOT node=$NODEID"

SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
for n in "${SURV[@]}"; do ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done
wait

echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy failed" >&2; exit 2; }

TD=$(mktemp -d)
$SSH "$WRITER" "SLOT=$SLOT DEV=$DEV GUARD_S=$GUARD_S python3 - <<'PYEOF'
import struct, os, sys, time, mmap
SLOT=int(os.environ['SLOT']); DEV=os.environ['DEV']
GUARD_S=float(os.environ['GUARD_S'])
MAGIC=0x4D584C4B; GUARD=3; DESC_OFF=40; DESC_MAGIC=0x5643524D
CRC_OFF=116                      # offsetof(struct mxfs_recov_desc, crc32c)

fd=os.open(DEV, os.O_RDWR|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    got=os.preadv(fd,[mv[:n]],off)
    if got!=n: raise IOError('short read %d'%got)
    return bytes(mv[:n])
def dwrite(off,data):
    mv[:len(data)]=data
    put=os.pwritev(fd,[mv[:len(data)]],off)
    if put!=len(data): raise IOError('short write %d'%put)
def crc32c(crc,data):
    for b in data:
        crc^=b
        for _ in range(8):
            crc=(crc>>1)^(0x82F63B78 & -(crc&1))
    return crc&0xFFFFFFFF

sup=dread(0,4096); dloff,=struct.unpack_from('<Q',sup,64)
off=dloff+SLOT*512
print('slot_off=%d'%off)

# ── wait for a survivor to publish the descriptor ───────────────────────────
t0=time.time(); rec=None
while time.time()-t0 < GUARD_S:
    r=dread(off,512)
    magic,flags=struct.unpack_from('<II',r,0)
    dm,=struct.unpack_from('<I',r,DESC_OFF)
    if magic==MAGIC and flags==GUARD and dm==DESC_MAGIC:
        rec=r; break
    time.sleep(0.25)
if rec is None:
    print('ABORT: no RECOVERY_GUARD descriptor within %ds'%GUARD_S); sys.exit(2)
el=round(time.time()-t0,1)

hmagic,hflags,hnode,hgen=struct.unpack_from('<IIII',rec,0)
hepoch,=struct.unpack_from('<Q',rec,24)
desc=rec[DESC_OFF:DESC_OFF+120]
stage,=struct.unpack_from('<H',desc,6)
vep,oep,rgen=struct.unpack_from('<QQQ',desc,8)
onode,=struct.unpack_from('<I',desc,44)
oterm,=struct.unpack_from('<I',desc,72)
stored,=struct.unpack_from('<I',desc,CRC_OFF)
print('GUARD    t+%-6s stage=%d owner_node=%d owner_epoch=%d gen=%d term=%d'
      %(el,stage,onode,oep,rgen,oterm))
print('header   fs_gen=%d node=%d epoch=%d'%(hgen,hnode,hepoch))

def desc_crc(d):
    c=crc32c(0xFFFFFFFF, d[:CRC_OFF])
    return crc32c(c, struct.pack('<IIQ', hgen, hnode, hepoch))

mine=desc_crc(desc)
if mine!=stored:
    print('ABORT: descriptor CRC self-check FAILED (stored=%d computed=%d) —'
          ' refusing to write an unparseable descriptor'%(stored,mine))
    sys.exit(2)
print('CRCSELF  OK (stored=%d == computed=%d)'%(stored,mine))

# ── the injection: a foreign owner_node, resealed ───────────────────────────
FOREIGN=(onode ^ 0x5A5A5A5A) & 0xFFFFFFFF
if FOREIGN==0: FOREIGN=0x5A5A5A5A
nd=bytearray(desc)
struct.pack_into('<I',nd,44,FOREIGN)
struct.pack_into('<I',nd,CRC_OFF,desc_crc(bytes(nd)))
img=bytearray(rec); img[DESC_OFF:DESC_OFF+120]=nd
diff=sorted(set((i//4)*4 for i in range(512) if img[i]!=rec[i]))
print('INJECT   owner_node %d -> %d ; resealed ; byte offsets changed: %s'
      %(onode,FOREIGN,diff))
dwrite(off,bytes(img))
print('RESULT   real_owner=%d foreign_owner=%d guard_at=%s'%(onode,FOREIGN,el))
PYEOF" 2>&1 | tee "$TD/inject"

grep -q '^RESULT' "$TD/inject" || {
    echo "probe: injection did not complete — nothing measured" >&2
    echo "probe: $VICTIM is DESTROYED; re-prep required." >&2; exit 2; }
REAL=$(sed -n 's/^RESULT   real_owner=\([0-9]*\) .*/\1/p' "$TD/inject")

# ── observe the retry loop ─────────────────────────────────────────────────
echo
echo "probe: observing the advance retry for ${OBSERVE_S}s"
O0=$(date +%s); prev=-1
while [ $(( $(date +%s) - O0 )) -lt "$OBSERVE_S" ]; do
    sleep 20
    for n in "${SURV[@]}"; do
        ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P234-RECOV-NOTOURS'" \
            > "$TD/c.$n" 2>/dev/null ) &
    done
    wait
    tot=0
    for n in "${SURV[@]}"; do tot=$(( tot + $(cat "$TD/c.$n" 2>/dev/null || echo 0) )); done
    echo "  t+$(( $(date +%s) - O0 ))s: NOTOURS total=$tot"
    prev=$tot
done

for n in "${SURV[@]}"; do
    ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p' | grep -aE 'P234-RECOV-NOTOURS|P234-COMPLETE-REPLAYEDFAIL|P163-RECOVERY-COMPLETE|P234-RECOV-OWNED|withdraw|shutdown'" \
        > "$TD/v.$n" 2>/dev/null ) &
done
wait

echo
echo "probe: distinct lines"
cat "$TD"/v.test* 2>/dev/null | sed 's/^\[[^]]*\] //' | sort | uniq -c | sort -rn | head -8

NT=$(cat "$TD"/v.test* 2>/dev/null | grep -ac 'P234-RECOV-NOTOURS')
KTAKE=$(cat "$TD"/v.test* 2>/dev/null | grep -ac 'kind=TAKEOVER')
KTOK=$(cat "$TD"/v.test* 2>/dev/null | grep -ac 'kind=TOKEN-MISMATCH')
DONE=$(cat "$TD"/v.test* 2>/dev/null | grep -ac 'P163-RECOVERY-COMPLETE')
rc=0
echo
echo "probe: NOTOURS=$NT  kind=TAKEOVER:$KTAKE  kind=TOKEN-MISMATCH:$KTOK"
echo "       real owner was $REAL; recoveries completed: $DONE"
if [ "$NT" -eq 0 ]; then
    echo "probe: INCONCLUSIVE — the owner never attempted an advance in the window."
    echo "       Either the recovery finished before the injection landed, or the"
    echo "       descriptor was taken over by a third node.  Re-run."
    rc=2
else
    if [ "$KTAKE" -lt 1 ]; then
        echo "probe: FAIL — the refusal was NOT classified as kind=TAKEOVER."
        echo "       The descriptor owner genuinely is not us, so any other"
        echo "       classification misreports the cause (0.11.421 rework)."
        rc=1
    else
        echo "probe: PASS-part — the refusal is correctly classified kind=TAKEOVER."
    fi
    [ "$KTOK" -eq 0 ] || { echo "probe: FAIL — $KTOK spurious kind=TOKEN-MISMATCH"; rc=1; }
    if [ "$NT" -ge 3 ]; then
        echo "probe: FAIL — $NT advance attempts over ${OBSERVE_S}s and still going:"
        echo "       the retry is UNBOUNDED.  A permanently-failing advance must"
        echo "       classify, relinquish or escalate — not spin quietly with the"
        echo "       victim's grants frozen.  (D-RECOV-ADVANCE-UNBOUNDED-RETRY)"
        rc=1
    else
        echo "probe: the owner stopped after $NT attempt(s) — retry appears bounded."
    fi
fi
echo
echo "probe: THE SLOT IS LEFT FROZEN BY DESIGN — re-prep before any other test:"
echo "       virsh -c qemu:///system start $VICTIM"
echo "       MXFS_FORCE_PREP=1 ./run.sh $NODES_N caw prep_cluster"
echo "probe: artifacts in $TD"
exit $rc
