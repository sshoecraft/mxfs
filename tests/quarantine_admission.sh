#!/bin/bash
# quarantine_admission.sh — D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376,
# ruling test A ("reproduce the original maximum-capacity defect") plus the
# acceptance test for patch item 1 of the sess377 RULE-5 ruling
# (ccmemory ccloop-c7ee71c6-sess377-GPT-ruling-quarantine-slot-repair-design).
#
# THE DEFECT.  A terminal replay refusal writes a RECOVERY_GUARD record into the
# victim's disklock heartbeat slot.  That record IS the durable verdict, so it
# must stay.  But slot index == journal-slice index, and the claim path is
# bounded by the volume's slice count, so on a volume formatted with exactly as
# many slices as nodes — the default, and what the 32-node rig runs — the
# rebooted victim finds NO free slot and cannot mount at all.
#
# WHAT THIS TEST MEASURES.  Not the capacity loss itself (that is real and
# unavoidable until the slice is repaired: a quarantined slice genuinely has no
# usable journal).  It measures whether the refusal is HONEST and
# NON-DESTRUCTIVE, which is what patch item 1 changed:
#
#   1. the victim's mount must fail CLOSED (never admitted without a journal);
#   2. its dmesg must classify the table — live members vs quarantined verdicts
#      vs withdrawn slices — instead of calling the cluster "full";
#   3. it must name the quarantined slot and its victim node;
#   4. it must NOT advise "reformat with more slices".  At 32 slices that advice
#      is unfollowable (mkfs_mxfs refuses -n > 32) AND destructive: mkfs_mxfs -f
#      erases the verdict the quarantine exists to preserve;
#   5. the guard record must be byte-for-byte intact afterwards — a failed
#      admission may not damage the evidence;
#   6. no survivor may have replayed or adopted the quarantined slice.
#
# This is a COMPONENT test.  It does not close the defect: the defect closes
# only when the operator repair path exists (ruling patch items 2+3).  A PASS
# here means the failure is now diagnosable and safe, not that it is fixed.
#
# PRECONDITION, and it is the opposite of tests/closure_hb_slot_reuse.sh:
# this test REQUIRES slices == occupied slots (a full table), because the
# exhaustion is the thing under test.  Prep with the default
# MXFS_LOG_SLICES == node count.
#
# Usage: tests/quarantine_admission.sh <N> <victim> [ag_mask_hex]
# Env: AUDIT_HOST (default test1), RECOVERY_WAIT (default 150),
#      REJOIN_WAIT (default 240)
# Exit 0 PASS, 1 FAIL, 2 PRECONDITION-NOT-MET.
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

N="${1:?usage: quarantine_admission.sh <N> <victim> [ag_mask_hex]}"
VICTIM="${2:?usage: quarantine_admission.sh <N> <victim> [ag_mask_hex]}"
AGMASK="${3:-0x2}"
AUDIT_HOST="${AUDIT_HOST:-test1}"
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"
REJOIN_WAIT="${REJOIN_WAIT:-240}"

[ "$VICTIM" = "$AUDIT_HOST" ] && { echo "FAIL: victim is the audit host"; exit 1; }
[ $(( AGMASK & 1 )) -ne 0 ] && {
    echo "FAIL: ag_mask $AGMASK includes ag0 — the root inode would be IN closure"
    exit 1; }

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

DD=$(mktemp -d)
pass=1
fail() { echo "FAIL: $*"; pass=0; }

# Raw heartbeat-table reader (O_DIRECT — peers write these sectors, a buffered
# re-read returns this node's stale cached copy).  One line per non-empty slot.
hb_dump() {
    "$SSH" "$1" "python3 - <<'PYEOF'
import struct, os, mmap
dev='$DEV'
f=os.open(dev, os.O_RDONLY)
dl=struct.unpack_from('<Q', os.pread(f,4096,0), 64)[0]
os.close(f)
f=os.open(dev, os.O_RDONLY|os.O_DIRECT)
m=mmap.mmap(-1, 64*512)
os.preadv(f, [m], dl)
d=m.read(64*512)
for s in range(64):
    r=d[s*512:(s+1)*512]
    magic,flags,node,fsgen=struct.unpack_from('<IIII', r, 0)
    ts,epoch=struct.unpack_from('<QQ', r, 16)
    if magic==0 and flags==0 and node==0:
        continue
    print('%d flags=%d node=%u fsgen=%u epoch=%u magic=0x%x' % (s,flags,node,fsgen,epoch,magic))
PYEOF" 2>/dev/null | grep -E '^[0-9]+ flags='
}

slices_of() {
    "$SSH" "$1" "python3 -c \"
import struct,os
f=os.open('$DEV',os.O_RDONLY)
d=os.pread(f,4096,0)
print(struct.unpack_from('<I',d,96)[0])\"" 2>/dev/null | tr -d '[:space:]' | tail -1
}

echo "=== quarantine_admission: N=$N victim=$VICTIM ag_mask=$AGMASK @ $(date -u +%FT%TZ) ==="

# ── arm the forced refusal on every survivor ──────────────────────────────
echo "--- arming freplay_force_refusal=1 ag_mask=$AGMASK on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = "1" ] && armed=$((armed+1))
done
[ "$armed" -eq "${#survivors[@]}" ] || { echo "FAIL: armed on $armed/${#survivors[@]}"; exit 1; }

# The victim must hold something worth freezing when it dies.
"$SSH" "$VICTIM" "nohup bash -c '
    end=\$((SECONDS + 20)); i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1)); echo hot > $MNT/.qadm-victim.\$i
        rm -f $MNT/.qadm-victim.\$((i-3))
    done' >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 8

hb_dump "$AUDIT_HOST" > "$DD/hb.pre"
[ -s "$DD/hb.pre" ] || { echo "PRECONDITION-NOT-MET: could not read the heartbeat table"; exit 2; }
OCC=$(wc -l < "$DD/hb.pre")
SLICES=$(slices_of "$AUDIT_HOST")
echo "--- heartbeat table before the kill: $OCC occupied slot(s), volume has ${SLICES:-?} log slices"
[ -n "${SLICES:-}" ] || { echo "PRECONDITION-NOT-MET: could not read the slice count"; exit 2; }
# THE precondition, and it is the inverse of closure_hb_slot_reuse.sh's.
if [ "$OCC" -lt "$SLICES" ] 2>/dev/null; then
    echo "PRECONDITION-NOT-MET: the table has spare slots ($OCC of $SLICES occupied)."
    echo "  The exhaustion under test cannot happen — the victim would just take"
    echo "  a free slot.  Re-prep with MXFS_LOG_SLICES == node count and re-run."
    exit 2
fi

date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }

echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish..."
sleep "$RECOVERY_WAIT"

# ── identify the quarantined slot, off the platter ────────────────────────
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg" > "$DD/$h.dmesg" 2>/dev/null & done
wait
cat "$DD"/*.dmesg > "$DD/all.dmesg" 2>/dev/null

VSLOT=$(grep -h "P241-RECOV-TERMINAL slot=" "$DD/all.dmesg" | grep -o "slot=[0-9]*" | head -1 | cut -d= -f2)
if [ -z "${VSLOT:-}" ]; then
    VSLOT=$(grep -h "P240-QUAR-IMPORT victim_slot=" "$DD/all.dmesg" | grep -o "victim_slot=[0-9]*" | head -1 | cut -d= -f2)
fi
[ -n "${VSLOT:-}" ] || { echo "PRECONDITION-NOT-MET: no terminal quarantine was published — nothing to test"; exit 2; }

hb_dump "$AUDIT_HOST" > "$DD/hb.quar"
GUARD=$(awk -v s="$VSLOT" '$1==s' "$DD/hb.quar")
echo "--- quarantined heartbeat slot $VSLOT: ${GUARD:-<empty>}"
case "$GUARD" in
    *"flags=3"*) ;;
    *) echo "PRECONDITION-NOT-MET: slot $VSLOT is not a RECOVERY_GUARD record"
       echo "  (want flags=3, got: ${GUARD:-empty})"; exit 2 ;;
esac
V_NODE=$(echo "$GUARD"  | grep -o 'node=[0-9]*'  | cut -d= -f2)
V_EPOCH=$(echo "$GUARD" | grep -o 'epoch=[0-9]*' | cut -d= -f2)
NGUARD=$(awk '$2=="flags=3"' "$DD/hb.quar" | wc -l)
NACTIVE=$(awk '$2=="flags=1"' "$DD/hb.quar" | wc -l)
echo "PROVEN on the platter: slot $VSLOT is GUARD, node=$V_NODE epoch=$V_EPOCH"
echo "table now: $NACTIVE live member(s), $NGUARD quarantined verdict(s) of $SLICES slices"
echo "USABLE RW SLICES: $(( SLICES - NGUARD )) (was $SLICES) — the capacity fact this defect is about"

# ── bring the victim back and let it TRY to rejoin ────────────────────────
date -u "+REJOIN-ATTEMPT $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1 || {
    echo "PRECONDITION-NOT-MET: could not start $VICTIM"; exit 2; }

booted=0
for a in $(seq 1 24); do
    sleep 5
    timeout 8 "$SSH" "$VICTIM" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP && { booted=1; break; }
done
[ "$booted" -eq 1 ] || { echo "PRECONDITION-NOT-MET: $VICTIM never came back on ssh"; exit 2; }
timeout 90 "$SSH" "$VICTIM" "
    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1
    iscsiadm -m session --rescan >/dev/null 2>&1
    multipath >/dev/null 2>&1" >/dev/null 2>&1
devup=0
for a in $(seq 1 20); do
    timeout 8 "$SSH" "$VICTIM" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && { devup=1; break; }
    timeout 20 "$SSH" "$VICTIM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; multipath >/dev/null 2>&1" >/dev/null 2>&1
    sleep 3
done
[ "$devup" -eq 1 ] || { echo "PRECONDITION-NOT-MET: $DEV / /src never came up on $VICTIM"; exit 2; }

"$SSH" "$VICTIM" "dmesg --clear" >/dev/null 2>&1
KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')
"$SSH" "$VICTIM" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh caw" > "$DD/rejoin.out" 2>&1
echo "--- rejoin prep: $(grep -h "NODE_PREP_" "$DD/rejoin.out" | tail -1)"
sleep 10
"$SSH" "$VICTIM" "dmesg" > "$DD/victim.dmesg" 2>/dev/null

# ── assertions ────────────────────────────────────────────────────────────
echo "--- assertions"

# 1. fail closed: the victim must NOT be mounted.
vm=$("$SSH" "$VICTIM" "mountpoint -q $MNT && echo YES || echo NO" 2>/dev/null | tr -d '[:space:]' | tail -1)
echo "victim mounted (want NO — a node with no journal slice must never be admitted): $vm"
[ "$vm" = "NO" ] || fail "the victim was ADMITTED with no journal slice available"

# 2..4. the diagnostic.
echo "--- victim admission diagnostic:"
grep -h "P300-CLAIM-" "$DD/victim.dmesg" | sed 's/^/    /'

grep -q "P300-CLAIM-EXHAUSTED" "$DD/victim.dmesg" \
    || fail "no P300-CLAIM-EXHAUSTED line — the table was not classified"
grep -q "P300-CLAIM-QUARANTINE" "$DD/victim.dmesg" \
    || fail "no P300-CLAIM-QUARANTINE line — the refusal did not name the quarantine as the cause"
grep -q "P300-CLAIM-QUARANTINE.*slot $VSLOT" "$DD/victim.dmesg" \
    || fail "the refusal did not name the quarantined slot $VSLOT"
grep -q "P300-CLAIM-EXHAUSTED.*$NGUARD quarantined recovery verdict" "$DD/victim.dmesg" \
    || fail "the refusal miscounted the quarantined verdicts (platter says $NGUARD)"
grep -q "P300-CLAIM-EXHAUSTED.*$NACTIVE live member" "$DD/victim.dmesg" \
    || fail "the refusal miscounted the live members (platter says $NACTIVE)"

if grep -qi "reformat with more slices" "$DD/victim.dmesg"; then
    fail "the refusal still advises 'reformat with more slices' — unfollowable at the 32-slice cap AND destructive (mkfs -f erases the verdict)"
else
    echo "no 'reformat with more slices' advice in the refusal: OK"
fi

# 5. the evidence survived the failed admission.
hb_dump "$AUDIT_HOST" > "$DD/hb.post"
AFTER=$(awk -v s="$VSLOT" '$1==s' "$DD/hb.post")
echo "slot $VSLOT after the failed admission: ${AFTER:-<empty>}"
case "$AFTER" in
    *"flags=3"*) ;;
    *) fail "the GUARD record at slot $VSLOT was damaged by the failed admission (now: ${AFTER:-empty})" ;;
esac
A_NODE=$(echo "$AFTER"  | grep -o 'node=[0-9]*'  | cut -d= -f2)
A_EPOCH=$(echo "$AFTER" | grep -o 'epoch=[0-9]*' | cut -d= -f2)
[ "${A_NODE:-x}"  = "$V_NODE"  ] || fail "slot $VSLOT now names a different node"
[ "${A_EPOCH:-x}" = "$V_EPOCH" ] || fail "slot $VSLOT now names a different incarnation"
echo "guard identity unchanged (node=$V_NODE epoch=$V_EPOCH): OK"

# 6. nobody replayed or adopted the quarantined slice.
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg" > "$DD/$h.post.dmesg" 2>/dev/null & done
wait
cat "$DD"/*.post.dmesg > "$DD/all.post.dmesg" 2>/dev/null
adopt=$(grep -hc "slice ADOPTED.*slot $VSLOT\|ADOPTED_SLICE.*slot=$VSLOT" "$DD/all.post.dmesg" || true)
echo "adoptions of the quarantined slice $VSLOT (want 0): ${adopt:-0}"
[ "${adopt:-0}" -eq 0 ] || fail "the quarantined slice was ADOPTED — the loss decision was taken implicitly"

shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown" "$DD"/*.post.dmesg 2>/dev/null | wc -l)
echo "survivors with a shutdown (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || fail "a survivor shut down during the failed admission"

mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || fail "the cluster lost survivors"

echo "--- evidence kept in $DD"
if [ "$pass" -eq 1 ]; then
    echo "=== quarantine_admission PASS — the refusal is accurate, fail-closed and"
    echo "    non-destructive.  The CAPACITY LOSS IS STILL REAL: $(( SLICES - NGUARD )) of $SLICES slices"
    echo "    usable, and no repair path exists yet (ruling patch items 2+3)."
    exit 0
fi
echo "=== quarantine_admission FAIL ==="
exit 1
