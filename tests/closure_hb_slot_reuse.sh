#!/bin/bash
# closure_hb_slot_reuse.sh — the NODE-SLOT INCARNATION REUSE interlock, for
# D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 (sess376 RULE-5 review, question 2).
#
# THE HAZARD THE REVIEW NAMED.  The CAW slot table addresses nodes by BITMAP
# INDEX, and that index is the node's disklock heartbeat slot — a REUSABLE
# resource, not an identity.  Every out-of-closure strip is authorized against
# "the victim's bit" at index N.  So the dangerous sequence is:
#
#   1. victim incarnation I1 owns heartbeat slot N; a CAW slot's image carries
#      bit N as I1's footprint;
#   2. a strip attempt (publisher scan or leaseless demand scrub) reads that
#      image and passes its gate;
#   3. I1's state is cleared and the CAW slot reaches tombstone;
#   4. a NEW incarnation I2 joins and REUSES heartbeat slot N;
#   5. I2 legitimately takes a grant on that resource, physically re-setting
#      bit N;
#   6. the stale strip's CAS runs — and if it succeeded it would revoke a LIVE
#      node's lock, which is silent corruption, not a frozen grant.
#
# Steps 1-3 are already proven reachable (tests/closure_reuse_directed.sh).
# THIS TEST ATTACKS STEP 4: can a new incarnation take the quarantined victim's
# heartbeat slot at all while the terminal verdict is live?
#
# WHAT THE CODE SAYS, so the assertions below are not invented.  Every closure
# gate — the publisher's per-CAS revalidate AND the leaseless
# mxfs_disklock_terminal_gate_check the demand scrub calls — funnels into
# closure_gate_predicate (dlm/disklock.c), which reads the victim's heartbeat
# SECTOR FRESH and calls recov_desc_of().  That reader requires
# `hb->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD` (=3).  A live tenant writes
# MXFS_DISKLOCK_FLAG_ACTIVE (=1) into that same field, and cannot present a
# recovery descriptor at all.  It further requires the descriptor to name the
# sector it sits in: victim_slot == slot, victim_node == hb->node_id,
# victim_epoch == hb->epoch, victim_fs_gen == hb->fs_gen.  And
# terminal_gate_check refuses outright, before any read, if the monitor calls
# the slot live.  So step 4 is supposed to be UNREACHABLE while the quarantine
# stands, and if it ever became reachable the gate is supposed to fail closed
# on the very next fresh read.
#
# THE MEASUREMENT.  Nothing here is forged: the victim is really killed, the
# replay really refuses, and the victim is really rebooted and really rejoins.
#   A. quarantine slot N (forced refusal, forged out-of-closure AG mask);
#   B. record N, the victim's node_id/epoch, and slot N's raw flags off the
#      platter with O_DIRECT (peers write these sectors — a buffered read
#      returns this node's stale cached copy);
#   C. boot the victim back up and let it rejoin the cluster;
#   D. ASSERT: the rejoined node did NOT take slot N; slot N is STILL a
#      RECOVERY_GUARD record carrying the ORIGINAL victim node_id and epoch;
#      no strip was logged against any CAW slot after the rejoin; and the
#      cluster is intact.
#
# A run in which the victim never rejoins proves nothing about the interlock
# and exits 2 (PRECONDITION-NOT-MET), never 0.
#
# Usage: tests/closure_hb_slot_reuse.sh <N> <victim> [ag_mask_hex]
# Env: AUDIT_HOST (default test1), RECOVERY_WAIT (default 150),
#      REJOIN_WAIT (default 240).
# Exit 0 PASS, 1 FAIL, 2 PRECONDITION-NOT-MET.
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

N="${1:?usage: closure_hb_slot_reuse.sh <N> <victim> [ag_mask_hex]}"
VICTIM="${2:?usage: closure_hb_slot_reuse.sh <N> <victim> [ag_mask_hex]}"
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

# Raw heartbeat-table reader.  O_DIRECT, per hb_live_count.sh trap 2: peers
# write these sectors and a buffered re-read returns our own cached copy.
# Prints one line per non-empty slot: "<slot> flags=<f> node=<id> fsgen=<g> epoch=<e>"
hb_dump() {
    "$SSH" "$1" "python3 - <<'PYEOF'
import struct, os
dev='$DEV'
f=os.open(dev, os.O_RDONLY)
dl=struct.unpack_from('<Q', os.pread(f,4096,0), 64)[0]
os.close(f)
f=os.open(dev, os.O_RDONLY|os.O_DIRECT)
buf=bytearray(64*512)
mv=memoryview(buf)
import mmap
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

echo "=== closure_hb_slot_reuse: N=$N victim=$VICTIM ag_mask=$AGMASK @ $(date -u +%FT%TZ) ==="

# ── A. arm the forced refusal on every survivor ────────────────────────────
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
        i=\$((i+1)); echo hot > $MNT/.hbreuse-victim.\$i
        rm -f $MNT/.hbreuse-victim.\$((i-3))
    done' >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 8

hb_dump "$AUDIT_HOST" > "$DD/hb.pre"
[ -s "$DD/hb.pre" ] || { echo "PRECONDITION-NOT-MET: could not read the heartbeat table"; exit 2; }
OCC=$(wc -l < "$DD/hb.pre")
SLICES=$("$SSH" "$AUDIT_HOST" "python3 -c \"
import struct,os
f=os.open('$DEV',os.O_RDONLY)
d=os.pread(f,4096,0)
print(struct.unpack_from('<I',d,96)[0])\"" 2>/dev/null | tr -d '[:space:]' | tail -1)
echo "--- heartbeat table before the kill: $OCC occupied slot(s)"
# THE PRECONDITION THIS TEST CANNOT DO WITHOUT, and it is not obvious.
# A quarantined victim's slot stays occupied by its RECOVERY_GUARD record
# FOREVER (that is the point).  On a volume whose slice count equals the node
# count there is then no free slot at all, and the rejoining node cannot even
# mount: "disklock: no free heartbeat slot in 0..N-1 ... Cluster is full" ->
# claim_slot -28 -> "MXFS DLM init failed - aborting mount".  Step 4 of the
# hazard is then unreachable for a reason that has nothing to do with the
# interlock, so the run must say so instead of reading as a pass.
if [ -n "${SLICES:-}" ] && [ "$OCC" -ge "$SLICES" ] 2>/dev/null; then
    echo "PRECONDITION-NOT-MET: the heartbeat table is FULL ($OCC of $SLICES slots)."
    echo "  After the kill the victim's slot becomes a permanent RECOVERY_GUARD, so"
    echo "  there will be NO free slot and the rejoin cannot mount at all — the"
    echo "  interlock would go unmeasured.  Re-prep with spare slices"
    echo "  (MXFS_LOG_SLICES > N in tests/setup/prep_fs.sh) and re-run."
    exit 2
fi

date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }

echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+purge..."
sleep "$RECOVERY_WAIT"

# ── B. identify the quarantined slot and its occupant, off the platter ─────
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
       echo "  (want flags=3, got: ${GUARD:-empty}) — the interlock cannot be measured"
       exit 2 ;;
esac
V_NODE=$(echo "$GUARD" | grep -o 'node=[0-9]*' | cut -d= -f2)
V_EPOCH=$(echo "$GUARD" | grep -o 'epoch=[0-9]*' | cut -d= -f2)
echo "PROVEN on the platter: slot $VSLOT is GUARD, node=$V_NODE epoch=$V_EPOCH"

STRIPS_BEFORE=$(grep -hc "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$DD/all.dmesg" || true)
echo "strips logged so far (the legitimate out-of-closure repair): $STRIPS_BEFORE"

# ── C. bring the victim back and let it rejoin as a NEW incarnation ────────
date -u "+REJOIN $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1 || {
    echo "PRECONDITION-NOT-MET: could not start $VICTIM"; exit 2; }

# A rebooted VM comes back with NO /src (NFS is deliberately not an fstab
# automount) and often only ONE iSCSI portal, so /dev/mapper/mpatha never
# assembles and nothing can mount.  run.sh restores exactly this after a
# power-cycle; the rejoin has to do the same or the node just sits there.
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
# Same node-prep the rig uses: insmod + mount.  It does NOT mkfs, so the
# quarantined descriptor on the platter is untouched by it.
KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')
"$SSH" "$VICTIM" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh caw" > "$DD/rejoin.out" 2>&1
echo "--- rejoin prep: $(grep -h "NODE_PREP_" "$DD/rejoin.out" | tail -1)"
echo "--- rejoin evidence: $DD/rejoin.out"
joined=0
for a in $(seq 1 $(( REJOIN_WAIT / 10 ))); do
    m=$("$SSH" "$VICTIM" "mountpoint -q $MNT && echo YES" 2>/dev/null | tr -d '[:space:]')
    [ "$m" = "YES" ] && { joined=1; break; }
    sleep 10
done
if [ "$joined" -ne 1 ]; then
    echo "PRECONDITION-NOT-MET: $VICTIM did not remount within ${REJOIN_WAIT}s —"
    echo "  step 4 of the hazard was never attempted, so nothing is proven."
    echo "  evidence kept in $DD (see rejoin.out)"
    exit 2
fi
echo "$VICTIM has rejoined and mounted"
sleep 15   # let its heartbeat land and the table settle

# ── D. assertions ─────────────────────────────────────────────────────────
hb_dump "$AUDIT_HOST" > "$DD/hb.post"
echo "--- assertions"

AFTER=$(awk -v s="$VSLOT" '$1==s' "$DD/hb.post")
echo "slot $VSLOT after the rejoin: ${AFTER:-<empty>}"
case "$AFTER" in
    *"flags=3"*) ;;
    *) fail "the quarantined GUARD record at slot $VSLOT was overwritten (now: ${AFTER:-empty}) — a new incarnation reused the victim's slot index while the terminal verdict was live" ;;
esac
A_NODE=$(echo "$AFTER" | grep -o 'node=[0-9]*' | cut -d= -f2)
A_EPOCH=$(echo "$AFTER" | grep -o 'epoch=[0-9]*' | cut -d= -f2)
echo "guard identity: node $V_NODE->${A_NODE:-none} epoch $V_EPOCH->${A_EPOCH:-none} (want unchanged)"
[ "${A_NODE:-x}" = "$V_NODE" ] || fail "slot $VSLOT now names a different node"
[ "${A_EPOCH:-x}" = "$V_EPOCH" ] || fail "slot $VSLOT now names a different incarnation"

# The rejoined node must be somewhere ELSE in the table.  Its node_id is new
# (a rejoin always draws a new identity), so find the slots that appeared.
comm -13 <(cut -d' ' -f1 "$DD/hb.quar" | sort -n) \
         <(cut -d' ' -f1 "$DD/hb.post" | sort -n) > "$DD/newslots"
NEW=$(tr '\n' ' ' < "$DD/newslots")
echo "heartbeat slots that appeared after the rejoin (want: exactly one, and not $VSLOT): ${NEW:-<none>}"
nnew=$(wc -l < "$DD/newslots")
[ "$nnew" -ge 1 ] || fail "the rejoined node claimed no new heartbeat slot — it must have taken an existing one"
grep -qx "$VSLOT" "$DD/newslots" && fail "the rejoined node claimed the QUARANTINED slot $VSLOT"

# Nothing may have been stripped on account of the rejoin.
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg" > "$DD/$h.post.dmesg" 2>/dev/null & done
wait
cat "$DD"/*.post.dmesg > "$DD/all.post.dmesg" 2>/dev/null
STRIPS_AFTER=$(grep -hc "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$DD/all.post.dmesg" || true)
echo "strips logged in total after the rejoin (want == $STRIPS_BEFORE): $STRIPS_AFTER"
[ "${STRIPS_AFTER:-0}" -eq "${STRIPS_BEFORE:-0}" ] || \
    fail "$(( STRIPS_AFTER - STRIPS_BEFORE )) strip(s) fired AFTER the victim rejoined — a stale closure attempt acted on a live incarnation"

# Any gate that refused is fine; any gate that could not be EVALUATED is not.
aborts=$(grep -hc "P299-SCRUB-ABORT" "$DD/all.post.dmesg" || true)
echo "scrub gate aborts (want 0): $aborts"
[ "${aborts:-0}" -eq 0 ] || fail "a closure gate could not be evaluated"

shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$DD"/*.post.dmesg 2>/dev/null | wc -l)
echo "nodes with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || fail "a node withdrew"

mounted=0
for h in "${survivors[@]}" "$VICTIM"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "nodes mounted (want $(( ${#survivors[@]} + 1 ))): $mounted"
[ "$mounted" -eq $(( ${#survivors[@]} + 1 )) ] || fail "a node lost its mount"

for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
done
wait

echo "evidence kept in $DD"
[ "$pass" -eq 1 ] && { echo "=== closure_hb_slot_reuse PASS @ $(date -u +%FT%TZ) ==="; exit 0; }
echo "=== closure_hb_slot_reuse FAIL @ $(date -u +%FT%TZ) ==="
exit 1
