#!/bin/bash
# tests/incarnation_mismatch_probe.sh — do the incarnation predicates actually
# DISCRIMINATE, or do they merely carry a nonzero number?
#
# WHY THIS EXISTS (D-MOUNT-INCARNATION-CONSTANT-ZERO, sess83 -> sess91;
#                  D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO, sess91 -> sess456)
#   sess83 measured the on-disk mount incarnation as a hard-coded 0, which made
#   ~8 recovery/fence predicates vacuous.  0.11.420 gives every mount a random
#   nonzero 64-bit incarnation; sess88 measured that it is nonzero, distinct
#   per node, distinct per mount, and carried into the recovery descriptor.
#
#   That is only half a verification.  A nonzero identifier on disk does not
#   prove the COMPARISONS became live — the guards could still be structurally
#   skipped and nobody would see a difference on a healthy cluster, because
#   every guard is a refusal arm that only shows itself when it refuses.
#
#   This probe reaches those arms by a reachable route: the monitor's
#   EPOCH-CHANGE arm (disklock.c, "epoch-change").  When a tracked slot's
#   on-disk epoch changes, the monitor declares the PREVIOUS incarnation dead —
#   capturing victim_epoch from node_track (the cached, last-observed value)
#   and NOT from a re-read — and the fence prover then RE-READS the sector and
#   compares.  Cached-vs-on-disk is exactly the discrimination under test.
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
# THE TWO ARMS  (arm=zero | arm=nonzero) — shapes as of sess456
#   zero     epoch := 0.  A zero is NOT an incarnation (no member at this
#            proto_gen writes one): it is an unreadable/spliced sector or a
#            foreign writer.  sess426 (hb_rebase_epoch) made the monitor RETAIN
#            the cached incarnation instead of laundering E1 into 0, and the
#            fence prover refuses to lay a descriptor on a zero-incarnation
#            record (P238-FENCE-ZEROINC).  So the survivor must:
#              mxfs:     P-HB-INC-ZERO ... cached_inc=<E1> (retained, once)
#              mxfs:     P163-RECOVERY-PENDING slot=S node=N epoch=<E1>
#              disklock: P238-FENCE-ZEROINC slot=S
#              mxfs:     P238-FENCE-NOINTENT ... rc=-71
#            and NO descriptor of any kind may appear while the sector reads
#            0.  A sector that reads 0 can never self-heal by design (there
#            is no successor to expire), so the probe then RESTORES the
#            original record byte-for-byte and the slot must be recovered
#            under E1 on the normal path (P238-FENCE-REDRIVE from the elected
#            replayer -> P163-RECOVERY-COMPLETE) and zeroed.  A descriptor
#            carrying victim_epoch=0 at any point is a FAIL (D-RECOV-ZERO-
#            EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN: unconstructible).
#   nonzero  epoch := a fresh random nonzero value, flags left ACTIVE, feature
#            block valid.  This is a provable SUPERSESSION (same node, later
#            ACTIVE incarnation, valid feature block) — sess86 rule.  The
#            survivor must retire its pending recovery for E1 rather than
#            guard the slot:
#              disklock: P237-FENCE-SUPERSEDED ... victim_inc=<E1> slot_inc=<E2>
#              mxfs:     P237-FENCE-SUPERSEDED-RETIRED ...
#            with NO RECOVERY_GUARD laid for E1 or E2 inside the detect
#            window.  (Before sess456 the intent path adopted the sector's E2
#            and laid a GUARD at t+0.5 s — chain 61, D-0520.)  The forged
#            successor's timestamp is frozen, so it then expires on the
#            ordinary path (dead_threshold * hb_interval) as (N, E2) and is
#            recovered with victim_epoch == the on-disk value; the probe
#            waits for that and reports it.
#
#   Both arms assert the same safety property from opposite sides: a recovery
#   is never published against an incarnation nobody observed stop.
#
# TIMING (the budget rule — derived, not chosen)
#   epoch-change detection : 1 monitor pass = HB_INTERVAL_MS(2000)        =  2s
#   fence + dispatch + slice replay (idle victim, measured sess88 <10s)   = 15s
#   recovery_begin                                                        =  1s
#   budget = 18s; 2x = 36s.  DETECT_S default 45 is that plus ssh slack.
#   zero heal (after restore): the elected replayer's acquire retry period
#            (30s) + fence + replay (18s) = 48s; 2x = 96s.  Chain 16 (sess438,
#            0.42.0) measured complete=1 in 50s after restore.  HEAL_S 100.
#   nonzero heal: dead_threshold(31) * 2000ms + FUA confirm + the same 18s
#            = 62 + 18 = 80s; 2x = 160s.  HEAL_S default 180.
#   Exceeding either budget is a FAILURE, not a slow pass.
#
# EVIDENCE
#   tests/evidence/<UTC>_incmis_<arm>/ — inject (the injector's transcript),
#   pre.bin (the victim's 512B record before injection), v.<node> (EVERY
#   mxfs:/disklock: kernel line on that survivor since the marker — not just
#   the census patterns; chain 61's sweep kept only 15 patterns and the whole
#   fence path (P236/P238) was invisible, which read as "silence").
#
# usage: incarnation_mismatch_probe.sh [arm=zero] [victim=test32] [writer=test1]
#                                      [detect_s=45] [heal_s=<per-arm>]
set -u
ARM="${1:-zero}"
VICTIM="${2:-test32}"
WRITER="${3:-test1}"
DETECT_S="${4:-45}"
HEAL_S="${5:-}"
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$VICTIM"; DEV=$MXFS_DEV_RESOLVED
NODES_N="${MXFS_NODES:-32}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh

case "$ARM" in
  # zero: the retained-incarnation design declares the death on the TIMESTAMP
  # expiry (31 samples x 2 s = 62 s) + fence dispatch (~2 s) => 64 s; 2x = 128.
  # nonzero: the epoch-change arm fires within one monitor pass (2 s) and the
  # supersession verdict follows immediately => 45 keeps its ssh slack.
  # Both windows end early when the verdict line is seen on the writer.
  zero)    [ -n "$HEAL_S" ] || HEAL_S=100; [ "$DETECT_S" != 45 ] || DETECT_S=130 ;;
  nonzero) [ -n "$HEAL_S" ] || HEAL_S=180 ;;
  *) echo "probe: arm must be 'zero' or 'nonzero' (got '$ARM')" >&2; exit 2 ;;
esac
if [ "$VICTIM" = "$WRITER" ]; then
    echo "probe: victim and writer must differ" >&2; exit 2
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EV="tests/evidence/${STAMP}_incmis_${ARM}"
mkdir -p "$EV"
MARK="INCMIS-$ARM-$$-$(date -u +%s)"
echo "probe: arm=$ARM victim=$VICTIM writer=$WRITER dev=$DEV mark=$MARK evidence=$EV"

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
T0UTC=$(date -u '+%Y-%m-%d %H:%M:%S')

echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy $VICTIM failed" >&2; exit 2; }
T0=$(date +%s)

# ── 4. the injection + a slot timeline across the detect window ─────────────
# The pre-injection record is kept on the writer (/tmp/incmis_pre_<slot>.bin,
# data not code) for the zero arm's restore, and copied into $EV/pre.bin.
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
with open('/tmp/incmis_pre_%d.bin'%SLOT,'wb') as pf: pf.write(b)

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

guard_at=None; zero_at=None; guard_epoch=None; seen_at=None
# The survivors' verdict for THIS arm, read from this node's own kernel log:
# the zero arm's death fires on the timestamp expiry (31 samples x 2 s), not
# on the epoch-change arm (which now RETAINS the cached incarnation), so the
# window must reach the fence prover's refusal; the nonzero arm's
# supersession verdict comes within one monitor pass.  End the watch as soon
# as the verdict line is on this node.
import subprocess
VERDICT = 'P238-FENCE-ZEROINC slot=%d ' % SLOT if ARM=='zero' else 'P237-FENCE-SUPERSEDED slot=%d ' % SLOT
it=0
while time.time()-t0 < WATCH:
    time.sleep(0.5)
    it+=1
    c=dread(OFF,512); f=fields(c)
    el=round(time.time()-t0,1)
    if it % 10 == 0:
        try:
            out=subprocess.run(['sh','-c','dmesg | tail -n 4000 | grep -c "%s"' % VERDICT],
                               capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            out='0'
        if out.isdigit() and int(out) >= 1 and seen_at is None:
            seen_at=el
            print('VERDICT  t+%-6s %s seen on the writer (%s lines)' % (el, VERDICT.strip(), out))
            break
    if f[1]==3 and guard_at is None:
        guard_at=el
        guard_epoch=struct.unpack_from('<Q',c,DESC_OFF+8)[0]
        print('SECTOR   t+%-6s flags=GUARD desc=%s victim_epoch=%d'
              %(el,'MRCV' if f[6]==DESC_MAGIC else hex(f[6]),guard_epoch))
        break
    if f[0]!=MAGIC and zero_at is None:
        zero_at=el; print('SECTOR   t+%-6s ZEROED (recovery published)'%el); break
c=dread(OFF,512); f=fields(c)
print('final    flags=%-9s node=%d ts=%d epoch=%d'%(FL.get(f[1],'?%d'%f[1]),f[2],f[4],f[5]))
print('RESULT   injected_epoch=%d guard_at=%s guard_epoch=%s zeroed_at=%s verdict_at=%s'
      %(E2,guard_at if guard_at is not None else '-',
        guard_epoch if guard_epoch is not None else '-',
        zero_at if zero_at is not None else '-',
        seen_at if seen_at is not None else '-'))
PYEOF" 2>&1 | tee "$EV/inject"

INJ_RC=${PIPESTATUS[0]}
E2=$(sed -n 's/^RESULT   injected_epoch=\([0-9]*\) .*/\1/p' "$EV/inject")
GUARD_AT=$(sed -n 's/^RESULT   .*guard_at=\([^ ]*\) .*/\1/p' "$EV/inject")
GUARD_EPOCH=$(sed -n 's/^RESULT   .*guard_epoch=\([^ ]*\) .*/\1/p' "$EV/inject")
if [ "$INJ_RC" != "0" ] || [ -z "${E2:-}" ]; then
    echo "probe: injection failed (rc=$INJ_RC) — nothing measured" >&2
    echo "probe: $VICTIM is DESTROYED; restart + re-prep it." >&2
    exit 2
fi
$SSH "$WRITER" "cat /tmp/incmis_pre_$SLOT.bin" > "$EV/pre.bin" 2>/dev/null

# ── 4b. zero arm: restore the original record ───────────────────────────────
# A sector that reads incarnation 0 has no successor to expire, so it cannot
# self-heal: the survivors retained E1 (P-HB-INC-ZERO) and refused to lay a
# descriptor on the zero (P238-FENCE-ZEROINC).  Put the victim's own record
# back byte-for-byte; the elected replayer's acquire retry then re-drives the
# fence under E1 (P238-FENCE-REDRIVE) and the slot is recovered normally.
# Refuse to restore if the sector is not exactly the injected image any more
# — that would paper over whatever wrote it.
RESTORED=0
if [ "$ARM" = "zero" ]; then
    echo
    echo "probe: restoring the original record (epoch $PEPOCH) at $(date -u +%H:%M:%S)Z"
    rst=$($SSH "$WRITER" "SLOT=$SLOT OFF=$OFF DEV=$DEV E1=$PEPOCH python3 - <<'PYEOF'
import struct, os, sys, mmap
SLOT=int(os.environ['SLOT']); OFF=int(os.environ['OFF']); DEV=os.environ['DEV']; E1=int(os.environ['E1'])
pre=open('/tmp/incmis_pre_%d.bin'%SLOT,'rb').read()
fd=os.open(DEV, os.O_RDWR|os.O_DIRECT); buf=mmap.mmap(-1,4096); mv=memoryview(buf)
os.preadv(fd,[mv[:512]],OFF); cur=bytes(mv[:512])
magic,flags=struct.unpack_from('<II',cur,0); ep,=struct.unpack_from('<Q',cur,24)
diff=[i for i in range(512) if cur[i]!=pre[i]]
blocks=sorted(set((i//8)*8 for i in diff))
if magic!=0x4D584C4B or flags!=1 or ep!=0 or blocks!=[24,504]:
    print('RESTORE-REFUSED magic=%x flags=%d epoch=%d changed_blocks=%s'%(magic,flags,ep,blocks)); sys.exit(1)
mv[:512]=pre
put=os.pwritev(fd,[mv[:512]],OFF)
os.preadv(fd,[mv[:512]],OFF); back=bytes(mv[:512]); os.close(fd)
ep2,=struct.unpack_from('<Q',back,24)
print('RESTORED put=%d epoch=%d matches_pre=%d'%(put,ep2,1 if back==pre else 0))
PYEOF" 2>&1)
    echo "  $rst" | tee "$EV/restore"
    # the ssh banner precedes the line — match anywhere, not at the start
    grep -q 'RESTORED.*matches_pre=1' <<<"$rst" && RESTORED=1
    if [ "$RESTORED" != "1" ]; then
        echo "probe: FAIL — restore did not land; the heal watch below measures nothing"
    fi
fi

# ── 5. self-heal watch (the cluster must recover the slot) ──────────────────
# This runs BEFORE the census on purpose.  The interesting half of this probe
# is the SECOND round — the one that publishes a descriptor and drives it to
# completion — and that round has not started when the detect window closes.
echo
echo "probe: watching for self-heal (budget ${HEAL_S}s, arm=$ARM)"
H0=$(date +%s); HEALED=0; HEAL_AT=-
while [ $(( $(date +%s) - H0 )) -lt "$HEAL_S" ]; do
    sleep 10
    st=$($SSH "$WRITER" "SLOT=$SLOT DEV=$DEV python3 - <<'PYEOF'
import struct,os,mmap
SLOT=int(os.environ['SLOT']); DEV=os.environ['DEV']
fd=os.open(DEV,os.O_RDONLY|os.O_DIRECT); buf=mmap.mmap(-1,4096); mv=memoryview(buf)
os.preadv(fd,[mv[:4096]],0); dloff,=struct.unpack_from('<Q',bytes(mv[:4096]),64)
os.preadv(fd,[mv[:512]],dloff+SLOT*512); r=bytes(mv[:512]); os.close(fd)
m,fl=struct.unpack_from('<II',r,0); ep,=struct.unpack_from('<Q',r,24)
dv,=struct.unpack_from('<Q',r,48)
print('%d %d %d %d'%(m,fl,ep,dv))
PYEOF" 2>/dev/null)
    read -r HM HF HE HDV <<<"$st"
    echo "  heal t+$(( $(date +%s) - H0 ))s: magic=$HM flags=$HF epoch=$HE desc_victim_epoch=$HDV"
    if [ "${HM:-1}" = "0" ]; then HEALED=1; HEAL_AT=$(( $(date +%s) - H0 )); break; fi
done
if [ "$HEALED" = "1" ]; then
    echo "probe: self-heal OK — slot $SLOT zeroed at t+${HEAL_AT}s of ${HEAL_S}s."
else
    echo "probe: FAIL — slot $SLOT NOT reclaimed within ${HEAL_S}s (derived time budget)."
fi

# ── 6. what did the survivors decide? ──────────────────────────────────────
# EVERY mxfs:/disklock: line since the marker is kept per survivor (v.<node>);
# the census below is only a summary of that capture.  If the marker has
# rolled out of a node's ring, fall back to journalctl -k --since the marker
# time (retention trap, ccmemory dmesg-ring-wraps-under-board).
echo
echo "probe: collecting survivor kernel lines (window scoped to $MARK)"
for n in "${SURV[@]}"; do
    ( $SSH "$n" "if dmesg | grep -aq '$MARK'; then dmesg | sed -n '/$MARK/,\$p'; \
                 else echo 'MARK-ROLLED-OUT: journalctl fallback'; journalctl -k --no-pager --since '$T0UTC' 2>/dev/null; fi \
                 | grep -aE 'mxfs:|disklock:|MARK-ROLLED-OUT'" > "$EV/v.$n" 2>/dev/null ) &
done
wait
ROLLED=$(grep -l 'MARK-ROLLED-OUT' "$EV"/v.test* 2>/dev/null | wc -l)
[ "$ROLLED" = "0" ] || echo "probe: note — $ROLLED survivor(s) had the marker rolled out; journalctl --since used"

echo "probe: marker census across ${#SURV[@]} survivors"
CENSUS='P-HB-INC-ZERO P163-RECOVERY-PENDING P238-FENCE-ZEROINC P238-FENCE-NOINTENT P238-FENCE-NOINC
P237-FENCE-SUPERSEDED P237-FENCE-SUPERSEDED-RETIRED P237-FENCE-INC-MISMATCH P237-FENCE-DESC-FOREIGN
P238-FENCE-REDRIVE P236-FENCE-INTENT P236-FENCEKIND P236-FENCE-CERTIFIED P236-FENCE-SEALED P238-FENCE-DONE
P238-FENCE-PENDING P238-FENCE-UNPROVEN P-PRKEY-FENCE-REFUSED P234-RECOV-FENCED P237-RECOV-INC-MISMATCH
P237-RECOV-SUPERSEDED P237-RECOV-INC-UNOBSERVED P234-COMPLETE-FENCEFAIL P237-COMPLETE-SUPERSEDED
P234-COMPLETE-SUPERSEDED P237-SLOT-REOCCUPIED P-VERGATE P163-RECOVERY-COMPLETE P163-RECOVERED
P234-RECOV-NOTOURS P234-COMPLETE-REPLAYEDFAIL P237-COMPLETE-REARMED P237-PENDING-REARMED P97-SWEEP-DONE'
for p in $CENSUS; do
    c=$(cat "$EV"/v.test* 2>/dev/null | grep -ac "$p ")
    nn=$(grep -l "$p " "$EV"/v.test* 2>/dev/null | wc -l)
    printf '  %-32s lines=%-5s nodes=%s\n' "$p" "$c" "$nn"
done | tee "$EV/census"
echo
echo "probe: sample lines (slot $SLOT)"
cat "$EV"/v.test* 2>/dev/null | grep -aE "slot=$SLOT( |,)" | sed 's/^\[[^]]*\] //' \
    | sort | uniq -c | sort -rn | head -24

# ── 7. verdict ─────────────────────────────────────────────────────────────
cnt() { cat "$EV"/v.test* 2>/dev/null | grep -ac "$1"; }
HBZ=$(cnt "P-HB-INC-ZERO ")
PEND_E1=$(cnt "P163-RECOVERY-PENDING slot=$SLOT node=$NODEID epoch=$PEPOCH")
PEND_0=$(cnt "P163-RECOVERY-PENDING slot=$SLOT node=$NODEID epoch=0 ")
ZEROINC=$(cnt "P238-FENCE-ZEROINC slot=$SLOT ")
SUP=$(cnt "P237-FENCE-SUPERSEDED slot=$SLOT ")
SUPR=$(cnt "P237-FENCE-SUPERSEDED-RETIRED slot=$SLOT ")
MIS=$(cnt "P237-FENCE-INC-MISMATCH slot=$SLOT ")
REDRIVE=$(cnt "P238-FENCE-REDRIVE slot=$SLOT ")
UNOBS=$(cnt "P237-RECOV-INC-UNOBSERVED")
# IS THAT COUNT A MEASUREMENT AT ALL?  P237-RECOV-INC-UNOBSERVED is emitted from
# mxfs_disklock_recovery_begin BELOW its retirement return, so on a build where
# that function is retired the string is not in mxfs.ko and the count is a
# guaranteed zero.  The assertion below is that the probe NEVER fires, so an
# absent probe makes it pass for free — silently, and in the direction of good
# news.  Ask the module rather than assuming either way.
KO=$(dirname "$0")/../mxfs.ko
if [ -f "$KO" ] && strings -a "$KO" 2>/dev/null | grep -q 'P237-RECOV-INC-UNOBSERVED'; then
    UNOBS_LIVE=1
else
    UNOBS_LIVE=0
fi
# descriptors: any certificate/intent line carrying the forbidden incarnation.
# P234-RECOV-FENCED was dropped from this alternation in 0.89.60: it comes from
# the same retired function and cannot appear, so listing it only made the
# pattern claim a reach it does not have.  The three P236 names are live.
DESC_0=$(cat "$EV"/v.test* 2>/dev/null | grep -aE "P236-FENCE-(INTENT|CERTIFIED|SEALED)" | grep -ac "epoch=0 ")
DESC_E1=$(cat "$EV"/v.test* 2>/dev/null | grep -aE "P236-FENCE-(INTENT|CERTIFIED|SEALED)" | grep -ac "epoch=$PEPOCH ")
DESC_E2=$(cat "$EV"/v.test* 2>/dev/null | grep -aE "P236-FENCE-(INTENT|CERTIFIED|SEALED)" | grep -ac "epoch=$E2 ")
COMPLETE=$(cnt "P163-RECOVERY-COMPLETE slot=$SLOT ")
REARM=$(cnt "P237-COMPLETE-REARMED"); PREARM=$(cnt "P237-PENDING-REARMED")
REOCC=$(cnt "P237-SLOT-REOCCUPIED"); NOTOURS=$(cnt "P234-RECOV-NOTOURS")
echo "probe: pending(E1)=$PEND_E1 pending(0)=$PEND_0 hb_inc_zero=$HBZ zeroinc=$ZEROINC redrive=$REDRIVE"
echo "       superseded=$SUP retired=$SUPR mismatch=$MIS unobserved=$UNOBS"
echo "       descriptor lines: epoch=0:$DESC_0 epoch=E1:$DESC_E1 epoch=E2:$DESC_E2 complete=$COMPLETE"
rc=0
echo
if [ "$GUARD_AT" != "-" ]; then
    echo "probe: FAIL — a RECOVERY_GUARD was laid at t+${GUARD_AT}s inside the detect window"
    echo "       (descriptor victim_epoch=$GUARD_EPOCH; declared death was $PEPOCH, disk carried $E2)."
    rc=1
fi
[ "$PEND_E1" -ge 1 ] || { echo "probe: FAIL — no survivor declared (slot=$SLOT node=$NODEID epoch=$PEPOCH) dead"; rc=1; }
[ "$PEND_0" -eq 0 ] || { echo "probe: FAIL — $PEND_0 P163-RECOVERY-PENDING carried epoch=0: a death was declared for a zero incarnation"; rc=1; }
if [ "$UNOBS_LIVE" = 1 ]; then
    [ "$UNOBS" -eq 0 ] || { echo "probe: FAIL — $UNOBS P237-RECOV-INC-UNOBSERVED: a caller reached the descriptor path without an observed incarnation"; rc=1; }
else
    echo "probe: NOT-MEASURED — P237-RECOV-INC-UNOBSERVED is not in mxfs.ko, so its count of $UNOBS is this harness's own silence and not a statement about the filesystem.  The question it asked (did a caller reach the descriptor path with no observed incarnation?) is UNANSWERED by this run; re-point it at the probes the live fence/recovery path emits, or retire it."
fi
[ "$DESC_0" -eq 0 ] || { echo "probe: FAIL — $DESC_0 descriptor line(s) carry epoch=0 (a zero-incarnation descriptor was constructed)"; rc=1; }
if [ "$ARM" = "zero" ]; then
    if [ "$HBZ" -lt 1 ]; then
        echo "probe: FAIL — no P-HB-INC-ZERO: the monitor did not retain the cached incarnation"
        echo "       against the zero read (laundering arm still present)."; rc=1
    else
        echo "probe: PASS-part — $HBZ P-HB-INC-ZERO: cached incarnation $PEPOCH retained against the zero read."
    fi
    if [ "$ZEROINC" -lt 1 ]; then
        echo "probe: FAIL — no P238-FENCE-ZEROINC: the fence prover did not refuse the zero-incarnation record"; rc=1
    else
        echo "probe: PASS-part — $ZEROINC P238-FENCE-ZEROINC: no intent laid on the zero record."
    fi
    [ "$RESTORED" = "1" ] || rc=1
    if [ "$HEALED" = "1" ]; then
        [ "$COMPLETE" -ge 1 ] || { echo "probe: FAIL — slot zeroed but no P163-RECOVERY-COMPLETE for slot $SLOT"; rc=1; }
        [ "$DESC_E1" -ge 1 ] || { echo "probe: FAIL — the post-restore recovery published no certificate naming epoch=$PEPOCH"; rc=1; }
        echo "probe: PASS-part — after restore: redrive=$REDRIVE, certificate lines for E1=$DESC_E1, complete=$COMPLETE, healed at t+${HEAL_AT}s."
    fi
else
    if [ "$SUP" -lt 1 ] || [ "$SUPR" -lt 1 ]; then
        echo "probe: FAIL — supersession arm did not execute (P237-FENCE-SUPERSEDED=$SUP, -RETIRED=$SUPR):"
        echo "       a valid ACTIVE successor incarnation must retire the pending recovery for $PEPOCH."
        rc=1
    else
        echo "probe: PASS-part — $SUP P237-FENCE-SUPERSEDED / $SUPR retired: victim_inc=$PEPOCH vs slot_inc=$E2 discriminated."
    fi
    [ "$DESC_E1" -eq 0 ] || { echo "probe: FAIL — $DESC_E1 descriptor line(s) name the superseded incarnation $PEPOCH"; rc=1; }
    if [ "$HEALED" = "1" ]; then
        echo "probe: PASS-part — the frozen successor $E2 expired on the normal path: certificate lines for E2=$DESC_E2, complete=$COMPLETE, healed at t+${HEAL_AT}s."
    fi
fi

# ── 8. the second-round obligations the completion must also discharge ─────
if [ "$REARM" -gt 0 ] || [ "$PREARM" -gt 0 ]; then
    echo "probe: FAIL — $REARM COMPLETE-REARMED / $PREARM PENDING-REARMED: the"
    echo "       recovery could not retire its own pending marker, and reported"
    echo "       another victim as still owed.  No second victim exists in this run."
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
echo "probe: evidence in $EV"
exit $rc
