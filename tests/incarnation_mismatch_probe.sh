#!/bin/bash
# tests/incarnation_mismatch_probe.sh — do the incarnation predicates actually
# DISCRIMINATE, or do they merely carry a nonzero number?
#
# WHY THIS EXISTS (D-MOUNT-INCARNATION-CONSTANT-ZERO, sess83 -> sess91)
#   sess83 measured the on-disk mount incarnation as a hard-coded 0, which made
#   ~8 recovery/fence predicates vacuous.  0.11.420 gives every mount a random
#   nonzero 64-bit incarnation; sess88 measured that it is nonzero, distinct
#   per node, distinct per mount, and carried into the recovery descriptor.
#
#   That is only half a verification.  A nonzero identifier on disk does not
#   prove the COMPARISONS became live — the guards could still be structurally
#   skipped and nobody would see a difference on a healthy cluster, because
#   every guard is a refusal arm that only shows itself when it refuses.
#   sess88 and sess89 both recorded that the refusal arms (P237-RECOV-
#   SUPERSEDED / -INC-MISMATCH / -COMPLETE-SUPERSEDED) have NEVER executed on
#   the rig, and sess89 proved the route the code comments assume (claim pass-1
#   own-stamp reclaim) is unreachable by construction.
#
#   This probe reaches those arms by a different, reachable route: the monitor's
#   EPOCH-CHANGE arm (disklock.c:1147).  When a tracked slot's on-disk epoch
#   changes, the monitor declares the PREVIOUS incarnation dead — capturing
#   victim_epoch from node_track (the cached, last-observed value) and NOT from
#   a re-read — then rebases onto the successor.  Recovery then calls
#   mxfs_disklock_recovery_begin(slot, victim, victim_epoch), which RE-READS the
#   sector and compares.  Cached-vs-on-disk is exactly the discrimination under
#   test.
#
# THE INJECTION
#   1. Hard-kill the victim (virsh destroy).  Its sector is now written by
#      nobody, so a foreign write is stable and cannot race the victim's own
#      heartbeat (and cannot trip the sess78/79 own-slot CAS self-fence).
#   2. Rewrite ONLY the 8-byte epoch field of the victim's heartbeat sector,
#      512B O_DIRECT, from a survivor — every other byte byte-for-byte
#      identical, EXCEPT feat.crc32c, which is recomputed so the feature block
#      stays VALID for the new incarnation (see hb_feature_crc(): the crc binds
#      {magic,proto_gen,feat_flags,fs_gen,node_id,epoch}).  Leaving it stale
#      would make the record CORRUPT and route the test through the version
#      gate instead of the incarnation gate.
#
# THE TWO ARMS  (arm=zero | arm=nonzero)
#   zero     epoch := 0.  This is the PRE-FIX on-disk value.  The GPT ruling
#            behind the fix (sess83) states "zero is never a wildcard", so the
#            survivor must REFUSE:
#              disklock: P237-RECOV-INC-MISMATCH ... victim_inc=<E1> slot_inc=0
#              mxfs: P234-COMPLETE-FENCEFAIL ... rc=-116 (-ESTALE)
#            and NO RECOVERY_GUARD may appear in the sector.  If instead a
#            guard is laid, the epoch=0 record was accepted as a match — the
#            defect would still be present in a new form.
#   nonzero  epoch := a fresh random nonzero value, flags left ACTIVE, feature
#            block valid.  This is a provable supersession, so the survivor
#            must retire its pending recovery rather than guard the slot:
#              disklock: P237-RECOV-SUPERSEDED ... victim_inc=<E1> slot_inc=<E2>
#              mxfs: P237-COMPLETE-SUPERSEDED ...
#            again with NO RECOVERY_GUARD in the sector.
#
#   Both arms assert the same safety property from opposite sides: a recovery
#   is never published against an incarnation the slot does not carry.
#
# SELF-HEALING (why this does not strand the cluster)
#   The mutated record has a frozen timestamp, so the rebased "successor" is
#   itself declared dead on the normal path (dead_threshold * hb_interval) and
#   recovered with victim_epoch == the on-disk value — which matches, so the
#   ordinary path runs and zeroes the slot.  The probe waits for that and
#   reports it.  No repair write is needed and none is performed.
#
# TIMING (RULE 0 — derived, not chosen)
#   epoch-change detection : 1 monitor pass = HB_INTERVAL_MS(2000)        =  2s
#   fence + dispatch + slice replay (idle victim, measured sess88 <10s)   = 15s
#   recovery_begin                                                        =  1s
#   budget = 18s; 2x = 36s.  DETECT_S default 45 is that plus ssh slack.
#   self-heal: dead_threshold(31) * 2000ms + FUA confirm + the same 18s
#            = 62 + 18 = 80s; 2x = 160s.  HEAL_S default 180.
#   Exceeding either budget is a FAILURE, not a slow pass.
#
# usage: incarnation_mismatch_probe.sh [arm=zero] [victim=test32] [writer=test1]
#                                      [detect_s=45] [heal_s=180]
set -u
ARM="${1:-zero}"
VICTIM="${2:-test32}"
WRITER="${3:-test1}"
DETECT_S="${4:-45}"
HEAL_S="${5:-180}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NODES_N="${MXFS_NODES:-32}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh

case "$ARM" in
  zero|nonzero) ;;
  *) echo "probe: arm must be 'zero' or 'nonzero' (got '$ARM')" >&2; exit 2 ;;
esac
if [ "$VICTIM" = "$WRITER" ]; then
    echo "probe: victim and writer must differ" >&2; exit 2
fi

MARK="INCMIS-$ARM-$$-$(date -u +%s)"
echo "probe: arm=$ARM victim=$VICTIM writer=$WRITER dev=$DEV mark=$MARK"

# ── 1. victim's slot + node_id, from its OWN claim line ─────────────────────
# Retention differs ~60x across nodes and between dmesg and journalctl -k
# (ccmemory kernel-log-retention-varies-per-node-pick-best-source), and on a
# node that has run a board the ring buffer has long since rolled the claim
# out.  Ask both and take whichever still holds it; the on-disk cross-check
# below catches a stale answer.
claim=$($SSH "$VICTIM" \
    "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
     journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
    2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
NODEID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
if [ -z "${SLOT:-}" ] || [ -z "${NODEID:-}" ]; then
    echo "probe: could not learn $VICTIM's slot/node_id from kmsg or journal" >&2
    echo "       last claim line: '$claim'" >&2
    exit 2
fi

# ── 2. pre-kill record + CRC SELF-CHECK, read O_DIRECT from a survivor ──────
# The CRC self-check is load-bearing: if this script's crc32c does not
# reproduce the crc the KERNEL wrote for the live record, then every byte this
# probe would write is wrong and the experiment would measure the version gate
# instead of the incarnation gate.  Abort rather than inject garbage.
PRE=$($SSH "$WRITER" "SLOT=$SLOT DEV=$DEV python3 - <<'PYEOF'
import struct, os, mmap
SLOT=int(os.environ['SLOT']); DEV=os.environ['DEV']
fd=os.open(DEV, os.O_RDONLY|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    got=os.preadv(fd,[mv[:n]],off)
    if got!=n: raise IOError('short read')
    return bytes(mv[:n])
sup=dread(0,4096); dloff,=struct.unpack_from('<Q',sup,64)
off=dloff+SLOT*512
r=dread(off,512); os.close(fd)
magic,flags,node,gen=struct.unpack_from('<IIII',r,0)
ts,=struct.unpack_from('<Q',r,16); ep,=struct.unpack_from('<Q',r,24)
fmag,fpg,fff,fcrc=struct.unpack_from('<IHHI',r,500)

def crc32c(crc,data):
    for b in data:
        crc^=b
        for _ in range(8):
            crc=(crc>>1)^(0x82F63B78 & -(crc&1))
    return crc&0xFFFFFFFF
def featcrc(fs_gen,node_id,epoch,fmag,fpg,fff):
    b=struct.pack('<IHHIIQ',fmag,fpg,fff,fs_gen,node_id,epoch)
    return crc32c(0xFFFFFFFF,b)
mine=featcrc(gen,node,ep,fmag,fpg,fff)
print('%d %d %d %d %d %d %d %d %d %d %d %d' %
      (dloff,off,magic,flags,node,gen,ts,ep,fmag,fpg,fff,fcrc))
print('CRCSELF %d %d' % (mine, 1 if mine==fcrc else 0))
PYEOF" 2>/dev/null)
LINE1=$(printf '%s\n' "$PRE" | sed -n '1p')
LINE2=$(printf '%s\n' "$PRE" | sed -n '2p')
read -r DLOFF OFF PMAGIC PFLAGS PNODE PGEN PTS PEPOCH FMAG FPG FFF FCRC <<<"$LINE1"
read -r _ MYCRC CRCOK <<<"$LINE2"

if [ "${PMAGIC:-0}" != "1297632331" ]; then          # 0x4D584C4B 'MXLK'
    echo "probe: slot $SLOT has no valid MXLK record (magic=${PMAGIC:-none})" >&2; exit 2; fi
if [ "${PNODE:-0}" != "$NODEID" ]; then
    echo "probe: slot $SLOT holds node $PNODE, $VICTIM claims $NODEID — stale map" >&2; exit 2; fi
if [ "${PFLAGS:-0}" != "1" ]; then
    echo "probe: slot $SLOT flags=$PFLAGS, expected ACTIVE(1)" >&2; exit 2; fi
if [ "${PEPOCH:-0}" = "0" ]; then
    echo "probe: the victim's on-disk incarnation is ALREADY 0 —"
    echo "       D-MOUNT-INCARNATION-CONSTANT-ZERO is present in the running build." >&2
    exit 1; fi
if [ "${CRCOK:-0}" != "1" ]; then
    echo "probe: ABORT — feature-block CRC self-check FAILED." >&2
    echo "       kernel wrote crc=$FCRC, this script computes $MYCRC over" >&2
    echo "       {fmag=$FMAG proto_gen=$FPG flags=$FFF fs_gen=$PGEN node=$PNODE epoch=$PEPOCH}." >&2
    echo "       Refusing to inject a record whose feature block would be wrong." >&2
    exit 2; fi
echo "probe: pre-kill slot=$SLOT node=$NODEID flags=ACTIVE EPOCH=$PEPOCH proto_gen=$FPG"
echo "probe: feature-block CRC self-check OK (kernel=$FCRC == computed=$MYCRC)"
echo "probe: disklock_offset=$DLOFF slot_off=$OFF"

# ── 3. marker on every survivor, then hard-kill ─────────────────────────────
SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
for n in "${SURV[@]}"; do ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done
wait

echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy $VICTIM failed" >&2; exit 2; }
T0=$(date +%s)

# ── 4. the injection + a slot timeline across the detect window ─────────────
TD=$(mktemp -d)
$SSH "$WRITER" "SLOT=$SLOT OFF=$OFF DEV=$DEV ARM=$ARM E1=$PEPOCH WATCH=$DETECT_S python3 - <<'PYEOF'
import struct, os, sys, time, mmap
SLOT=int(os.environ['SLOT']); OFF=int(os.environ['OFF']); DEV=os.environ['DEV']
ARM=os.environ['ARM']; E1=int(os.environ['E1']); WATCH=float(os.environ['WATCH'])
MAGIC=0x4D584C4B
FL={0:'empty',1:'ACTIVE',2:'WITHDRAWN',3:'GUARD'}
DESC_OFF=40; DESC_MAGIC=0x5643524D

fd=os.open(DEV, os.O_RDWR|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    got=os.preadv(fd,[mv[:n]],off)
    if got!=n: raise IOError('short O_DIRECT read %d'%got)
    return bytes(mv[:n])
def dwrite(off,data):
    mv[:len(data)]=data
    put=os.pwritev(fd,[mv[:len(data)]],off)
    if put!=len(data): raise IOError('short O_DIRECT write %d'%put)
def crc32c(crc,data):
    for b in data:
        crc^=b
        for _ in range(8):
            crc=(crc>>1)^(0x82F63B78 & -(crc&1))
    return crc&0xFFFFFFFF

def fields(b):
    magic,flags,node,gen=struct.unpack_from('<IIII',b,0)
    ts,=struct.unpack_from('<Q',b,16); ep,=struct.unpack_from('<Q',b,24)
    dm,=struct.unpack_from('<I',b,DESC_OFF)
    return magic,flags,node,gen,ts,ep,dm

# The victim is destroyed; wait until its sector is provably frozen before
# injecting, so the write cannot race a last in-flight heartbeat.
prev=None; frozen=0
for _ in range(30):
    b=dread(OFF,512); f=fields(b)
    if prev is not None and f[4]==prev: frozen+=1
    else: frozen=0
    prev=f[4]
    if frozen>=2: break
    time.sleep(1.0)
if frozen<2:
    print('ABORT: victim sector still advancing (ts=%d) after 30s'%prev); sys.exit(2)
b=dread(OFF,512); magic,flags,node,gen,ts,ep,dm=fields(b)
print('frozen   flags=%-9s node=%d ts=%d epoch=%d'%(FL.get(flags,'?'),node,ts,ep))
if magic!=MAGIC or ep!=E1 or flags!=1:
    print('ABORT: sector changed under us (magic=%x flags=%d epoch=%d, wanted epoch=%d ACTIVE)'
          %(magic,flags,ep,E1)); sys.exit(2)

if ARM=='zero':
    E2=0
else:
    E2=struct.unpack('<Q',os.urandom(8))[0] | (1<<63)
    while E2==E1: E2=struct.unpack('<Q',os.urandom(8))[0] | (1<<63)

fmag,fpg,fff,fcrc=struct.unpack_from('<IHHI',b,500)
img=bytearray(b)
struct.pack_into('<Q',img,24,E2)
newcrc=crc32c(0xFFFFFFFF,struct.pack('<IHHIIQ',fmag,fpg,fff,gen,node,E2))
struct.pack_into('<I',img,508,newcrc)
# nothing else may differ
diff=[i for i in range(512) if img[i]!=b[i]]
print('INJECT   epoch %d -> %d ; feat.crc %d -> %d ; bytes changed: %s'
      %(E1,E2,fcrc,newcrc,sorted(set((i//8)*8 for i in diff))))
dwrite(OFF,bytes(img))
t0=time.time()
print('WROTE at t+0.0 (kill-relative offset is on the caller side)')

guard_at=None; zero_at=None
while time.time()-t0 < WATCH:
    time.sleep(0.5)
    c=dread(OFF,512); f=fields(c)
    el=round(time.time()-t0,1)
    if f[1]==3 and guard_at is None:
        guard_at=el
        print('SECTOR   t+%-6s flags=GUARD desc=%s victim_epoch=%d'
              %(el,'MRCV' if f[6]==DESC_MAGIC else hex(f[6]),
                struct.unpack_from('<Q',c,DESC_OFF+8)[0]))
        break
    if f[0]!=MAGIC and zero_at is None:
        zero_at=el; print('SECTOR   t+%-6s ZEROED (recovery published)'%el); break
c=dread(OFF,512); f=fields(c)
print('final    flags=%-9s node=%d ts=%d epoch=%d'%(FL.get(f[1],'?%d'%f[1]),f[2],f[4],f[5]))
print('RESULT   injected_epoch=%d guard_at=%s zeroed_at=%s'
      %(E2,guard_at if guard_at is not None else '-',
        zero_at if zero_at is not None else '-'))
PYEOF" 2>&1 | tee "$TD/inject"

INJ_RC=${PIPESTATUS[0]}
E2=$(sed -n 's/^RESULT   injected_epoch=\([0-9]*\) .*/\1/p' "$TD/inject")
GUARD_AT=$(sed -n 's/^RESULT   .*guard_at=\([^ ]*\) .*/\1/p' "$TD/inject")
if [ "$INJ_RC" != "0" ] || [ -z "${E2:-}" ]; then
    echo "probe: injection failed (rc=$INJ_RC) — nothing measured" >&2
    echo "probe: $VICTIM is DESTROYED; restart + re-prep it." >&2
    exit 2
fi

# ── 5. self-heal watch (the cluster must recover the injected incarnation) ──
# This runs BEFORE the census on purpose.  The interesting half of this probe
# is the SECOND death round — the one that publishes a descriptor for the
# injected incarnation and drives it to completion — and that round has not
# started yet when the detect window closes.  Censusing first (as this script
# did originally) reports a window that stops short of the evidence and reads
# as "nothing happened".
echo
echo "probe: watching for self-heal (budget ${HEAL_S}s) — the frozen successor"
echo "       must be declared dead on the normal path and its slot zeroed."
H0=$(date +%s); HEALED=0
while [ $(( $(date +%s) - H0 )) -lt "$HEAL_S" ]; do
    sleep 15
    st=$($SSH "$WRITER" "SLOT=$SLOT DEV=$DEV python3 - <<'PYEOF'
import struct,os,mmap
SLOT=int(os.environ['SLOT']); DEV=os.environ['DEV']
fd=os.open(DEV,os.O_RDONLY|os.O_DIRECT); buf=mmap.mmap(-1,4096); mv=memoryview(buf)
os.preadv(fd,[mv[:4096]],0); dloff,=struct.unpack_from('<Q',bytes(mv[:4096]),64)
os.preadv(fd,[mv[:512]],dloff+SLOT*512); r=bytes(mv[:512]); os.close(fd)
m,fl=struct.unpack_from('<II',r,0); ep,=struct.unpack_from('<Q',r,24)
print('%d %d %d'%(m,fl,ep))
PYEOF" 2>/dev/null)
    read -r HM HF HE <<<"$st"
    echo "  heal t+$(( $(date +%s) - H0 ))s: magic=$HM flags=$HF epoch=$HE"
    if [ "${HM:-1}" = "0" ]; then HEALED=1; break; fi
done
if [ "$HEALED" = "1" ]; then
    echo "probe: self-heal OK — slot $SLOT zeroed; the injected incarnation was"
    echo "       recovered on the normal path."
else
    echo "probe: FAIL — slot $SLOT NOT reclaimed within ${HEAL_S}s.  A refused"
    echo "       recovery left the slot permanently un-recoverable (RULE 0 budget)."
fi

# ── 6. what did the survivors decide? ──────────────────────────────────────
echo
echo "probe: collecting survivor verdicts (window scoped to $MARK)"
PATS='P237-RECOV-INC-MISMATCH|P237-RECOV-SUPERSEDED|P237-RECOV-INC-UNOBSERVED|P234-RECOV-FENCED|P234-COMPLETE-FENCEFAIL|P237-COMPLETE-SUPERSEDED|P163-RECOVERY-PENDING|P163-RECOVERY-COMPLETE|P237-SLOT-REOCCUPIED|P-VERGATE|P234-RECOV-NOTOURS|P234-COMPLETE-REPLAYEDFAIL|P237-COMPLETE-REARMED|P237-PENDING-REARMED|P97-SWEEP-DONE'
for n in "${SURV[@]}"; do
    ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p' | grep -aE '$PATS'" > "$TD/v.$n" 2>/dev/null ) &
done
wait

echo "probe: marker census across ${#SURV[@]} survivors"
for p in P163-RECOVERY-PENDING P234-RECOV-FENCED P237-RECOV-INC-MISMATCH \
         P237-RECOV-SUPERSEDED P237-RECOV-INC-UNOBSERVED P234-COMPLETE-FENCEFAIL \
         P237-COMPLETE-SUPERSEDED P237-SLOT-REOCCUPIED P-VERGATE P163-RECOVERY-COMPLETE \
         P234-RECOV-NOTOURS P234-COMPLETE-REPLAYEDFAIL P237-COMPLETE-REARMED \
         P237-PENDING-REARMED P97-SWEEP-DONE; do
    c=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "$p")
    nn=$(grep -lc "$p" "$TD"/v.test* 2>/dev/null | wc -l)
    printf '  %-28s lines=%-5s nodes=%s\n' "$p" "$c" "$nn"
done
echo
echo "probe: sample lines (slot $SLOT)"
cat "$TD"/v.test* 2>/dev/null | grep -aE "slot=$SLOT( |,)" | sed 's/^\[[^]]*\] //' \
    | sort | uniq -c | sort -rn | head -14

# ── 7. verdict ─────────────────────────────────────────────────────────────
MIS=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-RECOV-INC-MISMATCH")
SUP=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-RECOV-SUPERSEDED")
CSUP=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-COMPLETE-SUPERSEDED")
FFAIL=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P234-COMPLETE-FENCEFAIL")
# The assertion is NOT "no descriptor was ever published" — the census now
# spans the self-heal, and the second death round legitimately publishes one for
# the INJECTED incarnation (that is what reclaims the slot).  What must never
# happen is a descriptor published for the incarnation the refusal arm just
# declined: the CACHED value $PEPOCH.  Count only those.
FENCED=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P234-RECOV-FENCED.*epoch=$PEPOCH ")
FENCED_ANY=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P234-RECOV-FENCED")
COMPLETE=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P163-RECOVERY-COMPLETE")
echo "probe: descriptors published: $FENCED_ANY total, $FENCED for the refused"
echo "       incarnation $PEPOCH (must be 0); recoveries completed: $COMPLETE"
rc=0
echo
if [ "$GUARD_AT" != "-" ]; then
    echo "probe: FAIL — a RECOVERY_GUARD was laid at t+${GUARD_AT}s against an"
    echo "       incarnation the slot does not carry (asked for $PEPOCH, disk has $E2)."
    rc=1
fi
if [ "$ARM" = "zero" ]; then
    if [ "$MIS" -lt 1 ]; then
        echo "probe: FAIL — no P237-RECOV-INC-MISMATCH.  An on-disk incarnation of 0"
        echo "       was NOT refused; zero is behaving as a wildcard."
        rc=1
    else
        echo "probe: PASS-part — $MIS P237-RECOV-INC-MISMATCH: on-disk epoch 0 refused"
        echo "       against cached victim incarnation $PEPOCH (zero is not a wildcard)."
    fi
    [ "$FFAIL" -ge 1 ] || { echo "probe: FAIL — refusal did not surface as P234-COMPLETE-FENCEFAIL"; rc=1; }
    [ "$FENCED" -eq 0 ] || { echo "probe: FAIL — $FENCED P234-RECOV-FENCED carried epoch=$PEPOCH: a descriptor was published for the incarnation the guard had just refused"; rc=1; }
else
    if [ "$SUP" -lt 1 ]; then
        echo "probe: FAIL — no P237-RECOV-SUPERSEDED for a valid ACTIVE successor"
        echo "       incarnation; the supersession arm did not execute."
        rc=1
    else
        echo "probe: PASS-part — $SUP P237-RECOV-SUPERSEDED / $CSUP P237-COMPLETE-SUPERSEDED:"
        echo "       victim_inc=$PEPOCH vs slot_inc=$E2 discriminated, recovery retired."
    fi
    [ "$FENCED" -eq 0 ] || { echo "probe: FAIL — $FENCED P234-RECOV-FENCED carried epoch=$PEPOCH: a guard was laid on the superseded incarnation"; rc=1; }
fi

# ── 8. the second-round obligations the completion must also discharge ─────
# A recovery published for an UNOBSERVED (zero) incarnation still has to retire
# its own pending marker.  mxfs_disklock_clear_recovery_pending() is a
# COMPARE-and-clear on (node, incarnation), so if it cannot match the marker it
# leaves it standing and reports P237-COMPLETE-REARMED — which claims ANOTHER
# victim is still owed.  On a zero-incarnation recovery that claim would be
# false, and the marker would never be retired.  Report it either way.
REARM=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-COMPLETE-REARMED")
PREARM=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-PENDING-REARMED")
REOCC=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P237-SLOT-REOCCUPIED")
NOTOURS=$(cat "$TD"/v.test* 2>/dev/null | grep -ac "P234-RECOV-NOTOURS")
if [ "$REARM" -gt 0 ] || [ "$PREARM" -gt 0 ]; then
    echo "probe: FAIL — $REARM COMPLETE-REARMED / $PREARM PENDING-REARMED: the"
    echo "       recovery could not retire its own pending marker, and reported"
    echo "       another victim as still owed.  No second victim exists in this"
    echo "       run — the compare-and-clear failed to match its own marker."
    rc=1
fi
if [ "$NOTOURS" -gt 0 ]; then
    echo "probe: FAIL — $NOTOURS P234-RECOV-NOTOURS: the recovery owner could not"
    echo "       authenticate against its own descriptor."
    rc=1
fi
[ "$REOCC" -eq 0 ] || echo "probe: note — $REOCC P237-SLOT-REOCCUPIED (dedup arm fired)"
if [ "$HEALED" != "1" ]; then rc=1; fi

echo
if [ "$rc" = "0" ]; then
    echo "probe: RESULT PASS (arm=$ARM) — the incarnation predicate discriminated"
    echo "       two different on-disk incarnations of the same node and took the"
    echo "       correct arm; no recovery was published against the wrong one."
else
    echo "probe: RESULT FAIL (arm=$ARM) — see the FAIL lines above."
fi
echo "probe: $VICTIM is DESTROYED — restart + re-prep it before the next test."
echo "probe: artifacts in $TD"
exit $rc
