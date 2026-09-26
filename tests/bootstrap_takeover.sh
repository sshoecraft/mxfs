#!/bin/bash
# bootstrap_takeover.sh — D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437
# item 5f, the TAKEOVER (docs/whole-cluster-restart.md §6.8; sess442 design-consult
# ruling docs/rulings/item5f-bootstrap-takeover.md):
# the bootstrap owner is DESTROYED (virsh destroy — a different boot, its PR
# key left registered, its record heartbeat silent) while it HOLDS at a chosen
# durable point (mxfs.bootstrap_inject HOLD points, TEST ONLY), and a SECOND
# host must take the term over: contender election, fence of the old owner's
# key (PREEMPT AND ABORT, certificate), validated inheritance of T's manifest
# and completed slots, T+1 sealed, K adopted with composite provenance, 32
# replays, RECOVERY_COMPLETE, payload intact, peers admitted, clean umount,
# chk clean.
#
# Hold points (the durable shape the takeover must handle):
#   11  after phase 3: record RECOVERING, escrow NONE     -> old owner slotless
#   12  after escrow PREPARED, before the claim CAW       -> old owner slotless
#   13  after K claimed (K_CLAIMED, owner's ACTIVE|PENDING record on K)
#   14  after the 8th foreign completion (bits set, sectors zeroed, receipts)
#
# the budget rule (derived): crash 10 s; boot <= 120 s; owner attempt = two dead-window
# scans + 32 fences ~150 s to the hold (bound 300; point 14 adds K replay +
# 8 completions ~60 s); destroy 5 s; contender boot <= 120 s; takeover = abandon
# window 6 s + election + REGISTER + P&A + K fence + manifest + CAS ~30 s, then
# phase-3 re-lease + K own replay + foreign replays ~5 s/slice + completion
# ~200-300 s, 31 descriptor re-proofs at 6 s = 186 s (bound 660); peers 300;
# payload/umount/chk ~270.  Total ~1500 s,
# caller bound 1500 s (derived above).
#
# Usage: tests/bootstrap_takeover.sh <label> <point 11|12|13|14> [N=32] [owner=test1] [contender=test2]
set -u
LABEL=${1:?label}
POINT=${2:?hold point 11|12|13|14}
N=${3:-32}
OWN=${4:-test1}
CON=${5:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$OWN"; DEV=$MXFS_DEV_RESOLVED
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
HOLD_BOUND=300
[ "$POINT" = 14 ] && HOLD_BOUND=360
TAKEOVER_BOUND=660
PEER_BOUND=300
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_boottakeover${POINT}
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
bringup() {
    local h=$1 a
    sshq 90 "$h" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
        iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1; iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
        iscsiadm -m node --login >/dev/null 2>&1; iscsiadm -m session --rescan >/dev/null 2>&1; multipath >/dev/null 2>&1" >/dev/null
    for a in $(seq 1 20); do
        sshq 8 "$h" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" | grep -q DEV_UP && return 0
        sshq 20 "$h" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; multipath >/dev/null 2>&1" >/dev/null
        sleep 3
    done
    return 1
}
boot_node() {   # boot_node <host> -> 0 when ssh + DEV + /src are up
    local h=$1 a up=0
    $VIRSH start "$h" >/dev/null 2>&1 || return 1
    for a in $(seq 1 24); do sleep 5; sshq 8 "$h" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }; done
    [ $up -eq 1 ] || return 1
    bringup "$h"
}
load_module() {  # load_module <host> <extra sysfs writes>
    sshq 120 "$1" "echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
        modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; cat /sys/module/mxfs/srcversion
        echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce; $2"
}
case "$POINT" in
    11) EXP_ESCROW=NONE;   OLD_SHAPE=slotless;;
    12) EXP_ESCROW=PREPARED; OLD_SHAPE=slotless;;
    13) EXP_ESCROW=K_CLAIMED; OLD_SHAPE=onK;;
    14) EXP_ESCROW=K_REPLAY_OK; OLD_SHAPE=onK;;
    *) echo "bad point $POINT"; exit 2;;
esac
echo "=== bootstrap_takeover label=$LABEL point=$POINT N=$N owner=$OWN contender=$CON out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED" > "$OUT/test$i.gate" &
done; wait
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then :; else fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"; fi
done
[ $fails -eq 0 ] && pass "srcgate: $N nodes run $TREE_SV and are mounted"
[ $fails -eq 0 ] || { echo "=== bootstrap_takeover $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. payload
for i in $(seq 1 "$N"); do
    sshq 30 "test$i" "d=$MNT/boottk_$LABEL; mkdir -p \$d; f=\$d/test$i.bin; head -c 65536 /dev/urandom > \$f && sync -f \$f && md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
np=0
for i in $(seq 1 "$N"); do
    m=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    case "$m" in [0-9a-f]??????????????????????????????? ) np=$((np+1));; *) fail "payload test$i: md5='$m'";; esac
done
[ "$np" -eq "$N" ] && pass "payload written + fsynced on $N/$N nodes" || fail "payload on $np/$N nodes only"
[ $fails -eq 0 ] || { echo "=== bootstrap_takeover $LABEL: fails=$fails (payload) out=$OUT ==="; exit 1; }

# 3. whole-cluster crash
TK=$(date +%s)
for i in $(seq 1 "$N"); do ( $VIRSH destroy "test$i" >/dev/null 2>&1; echo "test$i rc=$?" ) >> "$OUT/destroy.txt" & done; wait
info "destroyed $N VMs in $(( $(date +%s) - TK ))s: $(grep -c 'rc=0' "$OUT/destroy.txt")/$N rc=0"

# 4. the owner alone, holding at the point; destroyed there
boot_node "$OWN" || { fail "$OWN never came up after the crash"; echo "=== bootstrap_takeover $LABEL: fails=$fails out=$OUT ==="; exit 1; }
info "$OWN up at +$(( $(date +%s) - TK ))s"
load_module "$OWN" "echo $POINT > /sys/module/mxfs/parameters/bootstrap_inject" > "$OUT/owner_load.txt" 2>&1
grep -q "^$TREE_SV" "$OUT/owner_load.txt" && pass "$OWN loaded $TREE_SV" || fail "$OWN module: $(tr '\n' ' ' < "$OUT/owner_load.txt")"
TM=$(date +%s)
# the mount blocks at the hold point; run it detached on the node and watch dmesg
sshq 30 "$OWN" "echo BOOTTK-OWN-$LABEL > /dev/kmsg; mkdir -p $MNT; (setsid nohup sh -c 'timeout $((HOLD_BOUND+600)) mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$? > /tmp/boottk_mount_rc' >/dev/null 2>&1 &); echo LAUNCHED" | grep -q LAUNCHED || fail "owner mount did not launch"
held=0
for a in $(seq 1 $((HOLD_BOUND/5))); do
    sleep 5
    if sshq 15 "$OWN" "dmesg | grep -a 'P-BOOT-INJECT-HOLD point=$POINT' | head -1" | grep -q 'P-BOOT-INJECT-HOLD'; then held=1; break; fi
    if sshq 15 "$OWN" "cat /tmp/boottk_mount_rc 2>/dev/null" | grep -q MOUNT_RC; then break; fi
done
WH=$(( $(date +%s) - TM ))
sshq 60 "$OWN" "dmesg | sed -n '/BOOTTK-OWN-$LABEL/,\$p'" > "$OUT/owner_dmesg.txt"
[ $held -eq 1 ] && pass "owner reached hold point $POINT at +${WH}s" || fail "owner never reached hold point $POINT in ${WH}s: $(grep -ao 'P-BOOT-[A-Z-]*FAILED.*\|P-BOOT-[A-Z-]*REFUSED.*\|MOUNT_RC.*' "$OUT/owner_dmesg.txt" | head -2 | cut -c1-140 | tr '\n' ' ')"
grep -aq "P-BOOT-PHASE3-COMPLETE certs=$N" "$OUT/owner_dmesg.txt" && pass "owner: phase 3 certified $N" || fail "owner phase 3: $(grep -ao 'P-BOOT-PHASE3-[A-Z]*.*' "$OUT/owner_dmesg.txt" | cut -c1-120)"
OWN_TERM=$(grep -ao 'P-BOOT-CLAIM term=[0-9]*' "$OUT/owner_dmesg.txt" | head -1 | grep -o '[0-9]*$')
OWN_KEY=$(grep -ao 'P-BOOT-CLAIMED node=[0-9]* epoch=[0-9]* key=0x[0-9a-f]*' "$OUT/owner_dmesg.txt" | head -1 | grep -o 'key=0x[0-9a-f]*' | cut -d= -f2)
info "owner term=${OWN_TERM:-?} key=${OWN_KEY:-?}"
[ $held -eq 1 ] || { echo "=== bootstrap_takeover $LABEL: fails=$fails (no hold) out=$OUT ==="; exit 1; }
if [ "$POINT" = 14 ]; then
    c=$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/owner_dmesg.txt"); [ "$c" -ge 8 ] && pass "owner completed $c slots before the hold" || fail "owner completed only $c slots before hold 14"
fi
# 4b. sess446 LIVE-OWNER PROBE (MXFS_TK_LIVE_PROBE=1), the negative direction
# of D-BOOTSTRAP-OWNER-LIVENESS-CROSS-NODE-CLOCK-0450: the owner is ALIVE at
# the hold (its record heartbeat thread keeps seq advancing every
# MXFS_BOOTSTRAP_REFRESH_MS) and a fresh-boot contender — whose uptime is
# ~10 s against the owner's ~150 s, the exact skew the old clock arithmetic
# misjudged — must refuse to contend: P-BOOT-CONTENDER-OWNER-ALIVE after >3
# moving windows (~5 s), mount rc != 0, no election, no takeover, no fence of
# the owner's key, the owner's heartbeat never LOST.  Only then is the owner
# destroyed and the same contender boot must take the term over (step 5 skips
# its boot + module load).  budget: contender boot <= 120 s; refusal ~5 s
# after the watch starts (bound 60 s).
CON_UP=0
if [ -n "${MXFS_TK_LIVE_PROBE:-}" ]; then
    boot_node "$CON" || { fail "live probe: $CON never came up"; echo "=== bootstrap_takeover $LABEL: fails=$fails (live probe boot) out=$OUT ==="; exit 1; }
    CON_UP=1
    load_module "$CON" ":" > "$OUT/contender_load.txt" 2>&1
    grep -q "^$TREE_SV" "$OUT/contender_load.txt" && pass "$CON loaded $TREE_SV (live probe)" || fail "$CON module: $(tr '\n' ' ' < "$OUT/contender_load.txt")"
    TL=$(date +%s)
    sshq 120 "$CON" "echo BOOTTK-LIVE-$LABEL > /dev/kmsg; mkdir -p $MNT; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/live_probe.txt" 2>&1
    LW=$(( $(date +%s) - TL ))
    lrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/live_probe.txt" | cut -d= -f2)
    sshq 60 "$CON" "dmesg | sed -n '/BOOTTK-LIVE-$LABEL/,\$p'" > "$OUT/live_probe_dmesg.txt"
    LD=$OUT/live_probe_dmesg.txt
    info "live probe: contender mount rc=${lrc:-?} wall=${LW}s while the owner holds at point $POINT"
    [ "${lrc:-0}" -ne 0 ] && pass "live probe: mount refused (rc=$lrc)" || fail "live probe: the contender MOUNTED (rc=${lrc:-?}) over a live owner"
    grep -aq 'P-BOOT-CONTENDER-OWNER-ALIVE' "$LD" && pass "live probe: P-BOOT-CONTENDER-OWNER-ALIVE ($(grep -ao 'P-BOOT-CONTENDER-OWNER-ALIVE.*seq=[0-9]*' "$LD" | head -1 | grep -o 'seq=[0-9]*'))" || fail "live probe: no P-BOOT-CONTENDER-OWNER-ALIVE: $(grep -ao 'P-BOOT-CONTENDER.*' "$LD" | head -2 | cut -c1-140 | tr '\n' ' ')"
    for pat in 'P-BOOT-CONTENDER-ABANDONED' 'P-BOOT-CONTENDER-ELECTED' 'P-BOOT-TAKEOVER-FENCE' 'P-BOOT-TAKEOVER term=' 'P-BOOT-CLAIM term=' 'P-BOOT-ADOPT slot='; do
        c=$(grep -ac "$pat" "$LD"); [ "$c" -eq 0 ] && pass "live probe: no $pat" || fail "live probe: $pat x$c against a LIVE owner: $(grep -ao "$pat.*" "$LD" | head -1 | cut -c1-140)"
    done
    [ "$LW" -le 60 ] && pass "live probe: refusal wall ${LW}s <= 60s" || fail "live probe: refusal wall ${LW}s > 60s (budget)"
    sshq 60 "$OWN" "dmesg | sed -n '/BOOTTK-OWN-$LABEL/,\$p'" > "$OUT/owner_dmesg.txt"
    c=$(grep -ac 'P-BOOT-HB-LOST' "$OUT/owner_dmesg.txt"); [ "$c" -eq 0 ] && pass "live probe: owner heartbeat never LOST" || fail "live probe: owner P-BOOT-HB-LOST x$c"
    hbrc=$(grep -ac 'P-BOOT-HB-RC' "$OUT/owner_dmesg.txt"); [ "$hbrc" -eq 0 ] && pass "live probe: owner heartbeat landed every cycle" || info "live probe: owner P-BOOT-HB-RC x$hbrc"
    sshq 15 "$OWN" "dmesg | grep -a 'P-BOOT-INJECT-HOLD point=$POINT' | tail -1" | grep -q 'P-BOOT-INJECT-HOLD' && pass "live probe: owner still parked at the hold" || fail "live probe: owner no longer at the hold"
    timeout 120 tools/chk_mxfs -v "$IMG" > "$OUT/chk_live.txt" 2>&1
    grep -aq 'bootstrap: RECOVERING' "$OUT/chk_live.txt" && pass "live probe: record still RECOVERING" || fail "live probe: $(grep -ao 'bootstrap: .*' "$OUT/chk_live.txt" | head -1 | cut -c1-100)"
    [ -n "${OWN_KEY:-}" ] && { grep -aq "owner.*$OWN_KEY\|key=$OWN_KEY\|$OWN_KEY" "$OUT/chk_live.txt" && pass "live probe: record still names the owner's key" || info "live probe: chk record: $(grep -ao 'bootstrap.*' "$OUT/chk_live.txt" | head -2 | cut -c1-120 | tr '\n' ' ')"; }
fi
TD=$(date +%s)
$VIRSH destroy "$OWN" >/dev/null 2>&1 && pass "owner $OWN destroyed at the hold (+$(( TD - TK ))s)" || fail "virsh destroy $OWN"
timeout 120 tools/chk_mxfs -v "$IMG" > "$OUT/chk_between.txt" 2>&1
grep -a 'bootstrap' "$OUT/chk_between.txt" | head -4
grep -aq 'bootstrap: RECOVERING' "$OUT/chk_between.txt" && pass "after the owner's death: record RECOVERING" || fail "after the owner's death: $(grep -ao 'bootstrap: .*' "$OUT/chk_between.txt" | head -1 | cut -c1-100)"
if [ "$EXP_ESCROW" = NONE ]; then
    grep -aq 'bootstrap escrow:' "$OUT/chk_between.txt" && fail "unexpected escrow $(grep -ao 'bootstrap escrow: [A-Z_]*' "$OUT/chk_between.txt")" || pass "escrow NONE"
else
    grep -aq "bootstrap escrow: $EXP_ESCROW" "$OUT/chk_between.txt" && pass "escrow $EXP_ESCROW" || fail "escrow: $(grep -ao 'bootstrap escrow: .*' "$OUT/chk_between.txt" | head -1 | cut -c1-100)"
fi

# 5. the contender: a different host, fresh boot, must TAKE OVER
if [ "$CON_UP" -eq 1 ]; then
    info "$CON already booted + loaded by the live probe; the SAME boot now takes over"
else
    boot_node "$CON" || { fail "$CON never came up"; echo "=== bootstrap_takeover $LABEL: fails=$fails out=$OUT ==="; exit 1; }
    load_module "$CON" ":" > "$OUT/contender_load.txt" 2>&1
    grep -q "^$TREE_SV" "$OUT/contender_load.txt" && pass "$CON loaded $TREE_SV" || fail "$CON module: $(tr '\n' ' ' < "$OUT/contender_load.txt")"
fi
TM=$(date +%s)
sshq $((TAKEOVER_BOUND+60)) "$CON" "echo BOOTTK-CON-$LABEL > /dev/kmsg; mkdir -p $MNT; timeout $TAKEOVER_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/contender.txt" 2>&1
W2=$(( $(date +%s) - TM ))
mrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/contender.txt" | cut -d= -f2)
info "takeover mount rc=${mrc:-?} wall=${W2}s (+$(( $(date +%s) - TD ))s after the owner's death)"
sshq 60 "$CON" "dmesg | sed -n '/BOOTTK-CON-$LABEL/,\$p'" > "$OUT/contender_dmesg.txt"
D=$OUT/contender_dmesg.txt
grep -a 'P-BOOT-\|P238-RECOV-LEASE\|P238-FENCE\|foreign replay of\|P163-RECOVERY-COMPLETE\|barrier complete\|P226-ICENSUS' "$D" | cut -c1-200 > "$OUT/timeline_takeover.txt"
[ "${mrc:-1}" -eq 0 ] && pass "$CON MOUNTED by takeover (rc=0)" || fail "takeover rc=${mrc:-?}: $(grep -ao 'P-BOOT-[A-Z-]*REFUSED.*\|P-BOOT-[A-Z-]*FAILED.*\|P-BOOT-TAKEOVER-[A-Z-]*.*\|MXFS mount ABORTED.*' "$D" | head -2 | cut -c1-160 | tr '\n' ' ')"
[ "$W2" -le "$TAKEOVER_BOUND" ] && pass "takeover wall ${W2}s <= ${TAKEOVER_BOUND}s" || fail "takeover wall ${W2}s > ${TAKEOVER_BOUND}s (budget)"
grep -aq 'P-BOOT-CONTENDER-ABANDONED' "$D" && pass "abandon window observed (record frozen)" || fail "no P-BOOT-CONTENDER-ABANDONED"
grep -aq 'P-BOOT-CONTENDER-ELECTED' "$D" && pass "contender election won" || fail "no P-BOOT-CONTENDER-ELECTED: $(grep -ao 'P-BOOT-CONTENDER.*' "$D" | head -1 | cut -c1-140)"
if [ "$OLD_SHAPE" = onK ]; then
    grep -aq 'P-BOOT-TAKEOVER-FENCE-K' "$D" && pass "old owner fenced on K (certificate)" || fail "no P-BOOT-TAKEOVER-FENCE-K: $(grep -ao 'P-BOOT-TAKEOVER-FENCE.*' "$D" | head -1 | cut -c1-140)"
else
    grep -aq 'P-BOOT-TAKEOVER-FENCE-REG' "$D" && pass "old owner fenced as a slotless registrant" || fail "no P-BOOT-TAKEOVER-FENCE-REG: $(grep -ao 'P-BOOT-TAKEOVER-FENCE.*' "$D" | head -1 | cut -c1-140)"
fi
[ -n "${OWN_KEY:-}" ] && { grep -aq "P-BOOT-TAKEOVER-FENCE.*key=$OWN_KEY" "$D" && pass "the fenced key is the owner's ($OWN_KEY)" || fail "fence names another key than $OWN_KEY: $(grep -ao 'P-BOOT-TAKEOVER-FENCE.*' "$D" | head -1 | cut -c1-140)"; }
grep -aq 'P-BOOT-INHERIT ' "$D" && pass "T manifest imported: $(grep -ao 'P-BOOT-INHERIT .*' "$D" | head -1 | cut -c1-120)" || fail "no P-BOOT-INHERIT"
c=$(grep -ac 'P-BOOT-INHERIT-UNPROVEN\|INHERITANCE_UNPROVEN' "$D"); [ "$c" -eq 0 ] && pass "no unproven inheritance" || fail "P-BOOT-INHERIT-UNPROVEN x$c: $(grep -ao 'P-BOOT-INHERIT-UNPROVEN.*' "$D" | head -1 | cut -c1-140)"
if [ "$POINT" = 14 ]; then
    grep -aq 'P-BOOT-INHERIT .*receipts=[1-9]' "$D" && pass "completed slots inherited by receipt" || fail "no receipt-backed inheritance: $(grep -ao 'P-BOOT-INHERIT .*' "$D" | head -1 | cut -c1-140)"
fi
[ -n "${OWN_TERM:-}" ] && { grep -aq "P-BOOT-TAKEOVER term=$OWN_TERM->$((OWN_TERM+1))" "$D" && pass "record CAS'd T=$OWN_TERM -> T+1" || fail "no P-BOOT-TAKEOVER term=$OWN_TERM->$((OWN_TERM+1)): $(grep -ao 'P-BOOT-TAKEOVER term.*' "$D" | head -1 | cut -c1-140)"; }
grep -aq 'P-BOOT-LINEAGE ' "$D" && pass "lineage entry written for T" || fail "no P-BOOT-LINEAGE"
c=$(grep -ac 'P-BOOT-CLAIM term=\|P-BOOT-SCAN-FROZEN' "$D"); [ "$c" -eq 0 ] && pass "no fresh claim, no scan (takeover, not a new bootstrap)" || fail "contender scanned/claimed x$c"
grep -aq 'P-BOOT-ADOPT slot=' "$D" && pass "K adopted under T+1" || fail "no P-BOOT-ADOPT"
if [ "$OLD_SHAPE" = onK ]; then
    grep -aq 'P-BOOT-ADOPT slot=.*pending' "$D" && pass "K = the predecessor's PENDING record (preferred)" || info "adopt line: $(grep -ao 'P-BOOT-ADOPT slot=.*' "$D" | head -1 | cut -c1-140)"
    grep -aq 'P-BOOT-K-COMPOSITE' "$D" && pass "K replay gated by the composite lineage" || fail "no P-BOOT-K-COMPOSITE"
fi
grep -aq 'P-BOOT-ADOPTED-LOG' "$D" && pass "K mounted as own log" || fail "no P-BOOT-ADOPTED-LOG"
c=$(grep -ac 'P-BOOT-ADOPTED-REFUSED\|P-BOOT-K-REFUSED' "$D"); [ "$c" -eq 0 ] && pass "K replay refused nothing" || fail "K refused x$c: $(grep -ao 'P-BOOT-ADOPTED-REFUSED.*\|P-BOOT-K-REFUSED.*' "$D" | head -1 | cut -c1-140)"
frc=$(grep -ac 'foreign replay of slot .* complete' "$D"); frf=$(grep -ac 'foreign replay of slot .* failed' "$D")
inh=$(grep -ao 'P-BOOT-INHERIT .*complete=[0-9]*' "$D" | head -1 | grep -o 'complete=[0-9]*' | cut -d= -f2)
want=$(( N - 1 - ${inh:-0} ))
[ "$frc" -eq "$want" ] && pass "$frc foreign slices replayed complete (inherited ${inh:-0})" || fail "foreign replays complete=$frc failed=$frf (want $want, inherited ${inh:-0})"
[ "$frf" -eq 0 ] && pass "0 failed foreign replays" || fail "$frf failed foreign replays"
c=$(grep -ac 'P-BOOT-COMPLETE-CASFAIL' "$D"); [ "$c" -eq 0 ] && pass "every completion bit landed" || fail "P-BOOT-COMPLETE-CASFAIL x$c"
grep -aq 'P-BOOT-RECOVERY-COMPLETE' "$D" && pass "RECOVERY_COMPLETE: admission open" || fail "no P-BOOT-RECOVERY-COMPLETE: $(grep -ao 'P-BOOT-FINISH.*\|P-BOOT-RECONCILE.*\|P-BOOT-TERMINAL.*' "$D" | head -2 | cut -c1-140 | tr '\n' ' ')"
for pat in 'BUG:' 'Oops' 'P-RMAN-FSWIDE-HALT' 'P-RMAN-POSTSEAL-MUTATION' 'P240-QUAR-IMPORT' 'POLICY-REFUSED' 'P-BOOT-HB-LOST' 'P-BOOT-UNWIND' 'P-BOOT-KEY-UNCLASSIFIED'; do
    c=$(grep -ac "$pat" "$D"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $CON"
done
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    got=$(sshq 20 "$CON" "md5sum $MNT/boottk_$LABEL/test$i.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_takeover.txt"; fi
done
[ "$ok" -eq "$N" ] && pass "payload on the new owner: $N/$N intact" || { fail "payload on the new owner: $ok/$N intact"; head -3 "$OUT/payload_mismatch_takeover.txt"; }

# 6. admit the other N-1 nodes (the old owner comes back as an ordinary member in a NEW boot)
TP=$(date +%s)
for i in $(seq 1 "$N"); do [ "test$i" = "$CON" ] || $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
for i in $(seq 1 "$N"); do
    [ "test$i" = "$CON" ] && continue
    (
        up=0; for a in $(seq 1 24); do sleep 5; sshq 8 "test$i" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }; done
        [ $up -eq 1 ] || { echo "NO_SSH"; exit 1; }
        bringup "test$i" || { echo "NO_DEV"; exit 1; }
        sshq 120 "test$i" "cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH; exit 1; }
            modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
            mkdir -p $MNT; timeout 120 mount -t mxfs $DEV $MNT && echo MOUNT_OK || echo MOUNT_RC=\$?; dmesg | grep -a 'P-BOOT-STATE\|P-BOOT-ADMISSION\|P305\|P302' | tail -2"
        # sess445: a failed peer's reason died with its volatile journal
        # (point 14: test20 30/31, only the P305 + RECOVERY_COMPLETE tail
        # survived; prep re-imaged the node before anyone looked).  Keep
        # the whole mount attempt's kernel log for a non-MOUNT_OK peer.
        grep -q MOUNT_OK "$OUT/test$i.peer" || sshq 40 "test$i" "dmesg | grep -a 'mxfs\|XFS' | tail -150" > "$OUT/test$i.peer_dmesg.txt" 2>&1
    ) > "$OUT/test$i.peer" 2>&1 &
done; wait
pm=0
for i in $(seq 1 "$N"); do [ "test$i" = "$CON" ] && continue; grep -q MOUNT_OK "$OUT/test$i.peer" && pm=$((pm+1)) || echo "    test$i: $(tr '\n' ' ' < "$OUT/test$i.peer" | cut -c1-160)" >> "$OUT/peer_fail.txt"; done
PW=$(( $(date +%s) - TP ))
[ "$pm" -eq $((N-1)) ] && pass "$pm/$((N-1)) peers admitted after RECOVERY_COMPLETE (${PW}s)" || { fail "$pm/$((N-1)) peers mounted (${PW}s)"; head -3 "$OUT/peer_fail.txt"; }
grep -q MOUNT_OK "$OUT/$OWN.peer" && pass "the old owner $OWN rejoined in its new boot (old key succeeded)" || fail "old owner $OWN did not rejoin: $(tr '\n' ' ' < "$OUT/$OWN.peer" | cut -c1-160)"
[ "$PW" -le "$PEER_BOUND" ] && pass "peer admission wall ${PW}s <= ${PEER_BOUND}s" || fail "peer admission wall ${PW}s > ${PEER_BOUND}s (budget)"
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    got=$(sshq 20 "$OWN" "md5sum $MNT/boottk_$LABEL/test$i.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    [ "$got" = "$want" ] && ok=$((ok+1)) || echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_peer.txt"
done
[ "$ok" -eq "$N" ] && pass "payload from the rejoined old owner $OWN: $N/$N" || { fail "payload from $OWN: $ok/$N"; head -3 "$OUT/payload_mismatch_peer.txt"; }

# 7. clean umount everywhere + chk
for i in $(seq 1 "$N"); do sshq 90 "test$i" "timeout 80 umount $MNT && echo UMOUNT_OK" > "$OUT/test$i.umount" 2>&1 & done; wait
um=0; for i in $(seq 1 "$N"); do grep -q UMOUNT_OK "$OUT/test$i.umount" && um=$((um+1)); done
[ "$um" -eq "$N" ] && pass "clean umount on $N/$N nodes" || fail "clean umount on $um/$N nodes"
timeout 240 tools/chk_mxfs -v "$IMG" > "$OUT/chk.txt" 2>&1; chkrc=$?
chk_err=$(grep -c 'ERROR' "$OUT/chk.txt"); chk_sb=$(grep -c 'ERROR.*\(icount\|ifree\)' "$OUT/chk.txt")
[ $(( chk_err - chk_sb )) -eq 0 ] && pass "chk_mxfs non-SB errors 0 (rc=$chkrc)" || fail "chk_mxfs non-SB errors=$(( chk_err - chk_sb )) rc=$chkrc (see $OUT/chk.txt)"
grep -a 'bootstrap' "$OUT/chk.txt" | head -5
grep -aq 'bootstrap: RECOVERY_COMPLETE' "$OUT/chk.txt" && pass "chk_mxfs: record RECOVERY_COMPLETE" || fail "chk_mxfs bootstrap: $(grep -ao 'bootstrap: .*' "$OUT/chk.txt" | head -1 | cut -c1-120)"
[ -n "${OWN_TERM:-}" ] && { grep -aq "bootstrap: RECOVERY_COMPLETE term=$((OWN_TERM+1))" "$OUT/chk.txt" && pass "chk_mxfs: term $((OWN_TERM+1))" || info "chk term line: $(grep -ao 'bootstrap: RECOVERY_COMPLETE.*' "$OUT/chk.txt" | head -1 | cut -c1-120)"; }
grep -aq 'bootstrap episode: .*lineage=1 ' "$OUT/chk.txt" && pass "chk_mxfs: one lineage entry (T): $(grep -ao 'bootstrap lineage\[0\]: .*' "$OUT/chk.txt" | head -1 | cut -c1-100)" || fail "chk_mxfs lineage: $(grep -ao 'bootstrap episode: .*\|bootstrap lineage.*' "$OUT/chk.txt" | head -1 | cut -c1-120)"
grep -aq 'bootstrap escrow: K_REPLAY_OK' "$OUT/chk.txt" && pass "chk_mxfs: escrow K_REPLAY_OK" || fail "chk_mxfs escrow: $(grep -ao 'bootstrap escrow: .*' "$OUT/chk.txt" | head -1 | cut -c1-120)"
info "wall=$(( $(date +%s) - T0 ))s"
echo "=== bootstrap_takeover $LABEL point=$POINT: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
