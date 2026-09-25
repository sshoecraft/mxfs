#!/bin/bash
# transport_conformance.sh — 0.75.0 (D-JOINER-TRANSPORT-NOT-CONFORMED-DEFAULT-
# CAW-MOUNT-JOINS-LIVE-TCP-CLUSTER-SPLIT-DLM-0904): a mount must run the DLM
# transport the cluster on the platter runs.  Four arms on two nodes A/B,
# starting from a live 2/tcp cluster (prep_cluster 2 tcp beforehand):
#
#   A  B leaves (clean umount), reloads with DEFAULT module arguments (no
#      force_transport) and mounts: it must ADOPT TCP (P-TRANSPORT-ADOPTED,
#      'DLM init ... transport=tcp', P-DOMAIN-ADMITTED ... transport=TCP),
#      A must see it as a peer, and B's clean umount must be observed by A
#      as a clean departure (P163-CLEAN-DEPART for B's node id) — the s507
#      symptom was a departure that was never recognised.
#   B  everyone leaves; A forms a CAW cluster with default arguments; B
#      mounts with force_transport=1: REFUSED (P-TRANSPORT-MISMATCH-REFUSED,
#      mount rc!=0, no P-DOMAIN-ADMITTED, not mounted).
#   C  B reloads with default arguments and mounts: joins on CAW
#      (P-TRANSPORT-CONFORMED caw, 'transport=caw', rc=0).
#   D  both leave cleanly; modules unloaded.  The caller re-preps 2/tcp.
#
# Usage: tests/transport_conformance.sh <label> [A=test1] [B=test2]
# Env:   MXFS_DEV (default: the device of A's live mxfs mount, resolved by
#        mxfs_dev_resolve — no rig's device path is assumed), MXFS_MNT,
#        MXFS_FAULT_UNREACHABLE=<tag> (capture-contract verification only:
#        the acquisition that writes <tag>.txt, e.g. A_join or B_forceB, is
#        issued to a host that does not resolve — a real ssh failure — and
#        the lap must then ABORT, never reach a verdict).
# budget: a TCP join measured 5-15 s, a CAW formation ~10 s, a refused mount
# < 1 s, umount ~5 s, rmmod/insmod ~3 s; nine mount/umount cycles => ~150 s,
# bound 240 s.  Exit 0 = PASS, 1 = FAIL, 2 = INFRA/ABORT (precondition not
# met, or a measurement that did not complete).
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted.
set -u
LABEL=${1:?label}
A=${2:-test1}
B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
KO=/root/mxfs.ko.prep
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_transport_conformance_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/capture_require/require_epoch/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
sshq() { rs "$@"; }
# jl <node> <mark> > <file>: a kernel journal window since a node-side
# epoch-seconds mark; the caller validates the file ('kernel: ') first
jl() { rsx 20 "$1" "journalctl -k --since @$2 --no-pager 2>/dev/null | cut -c1-700"; }
fault_host() { # <tag> <node> -> the node to acquire from
    if [ "${MXFS_FAULT_UNREACHABLE:-}" = "$1" ]; then
        echo "STAGE FAULT: acquiring $1 from an unresolvable host instead of $2" >&2
        echo "$2-unreachable.invalid"
    else
        echo "$2"
    fi
}

# leave <node> <tag>: clean umount + rmmod on a node; writes $OUT/<tag>.txt
# holding UMOUNT_RC and UNLOADED/STILL_LOADED, validated
leave() {
    local h; h=$(fault_host "$2" "$1")
    rsx 60 "$h" "mountpoint -q $MNT && timeout 40 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/$2.txt"
    capture_require "$OUT/$2.txt" '^(UNLOADED|STILL_LOADED)$' "$2: the departure of $1"
}
# arm <node> <modargs> <tag>: insmod + mount; writes $OUT/<tag>.txt holding
# MARK=<epoch> INSMOD_RC MOUNT_RC WALL NODE_ID TRANSPORT MOUNTED/NOT_MOUNTED,
# validated (the mount state line is the shape; MARK feeds the journal window)
arm() {
    local h; h=$(fault_host "$3" "$1")
    rsx 60 "$h" "M=\$(date +%s); echo MARK=\$M; insmod $KO dyndbg=+p $2; echo INSMOD_RC=\$?; T0=\$(date +%s); timeout 40 mount -t mxfs $DEV $MNT; R=\$?; echo MOUNT_RC=\$R; echo WALL=\$(( \$(date +%s) - T0 )); journalctl -k --since @\$M --no-pager 2>/dev/null | grep -a 'DLM init: node_id=' | tail -1 | sed 's/.*node_id=\([0-9]*\).*transport=\([a-z]*\).*/NODE_ID=\1\nTRANSPORT=\2/'; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$3.txt"
    capture_require "$OUT/$3.txt" '^(MOUNTED|NOT_MOUNTED)$' "$3: the mount on $1"
    capture_require "$OUT/$3.txt" '^MARK=[0-9]+$' "$3: the clock mark of the mount on $1"
}
# journal <node> <mark> <tag>: writes $OUT/<tag>.txt, validated
journal() {
    jl "$1" "$2" > "$OUT/$3.txt"
    capture_require "$OUT/$3.txt" 'kernel: ' "$3: the kernel journal on $1"
}
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# precondition: both mounted, both on tcp
measure "$A" 15 "$OUT/rv_pre_a_1.txt" '^READ_RC=[0-9]+$' "pre_a on $A" "mountpoint -q $MNT && echo M; cat /sys/module/mxfs/parameters/force_transport 2>/dev/null; printf '\nREAD_RC=%s\n' \$?"; pre_a=$(grep -av '^READ_RC=' "$OUT/rv_pre_a_1.txt")
measure "$B" 15 "$OUT/rv_pre_b_1.txt" '^READ_RC=[0-9]+$' "pre_b on $B" "mountpoint -q $MNT && echo M; cat /sys/module/mxfs/parameters/force_transport 2>/dev/null; printf '\nREAD_RC=%s\n' \$?"; pre_b=$(grep -av '^READ_RC=' "$OUT/rv_pre_b_1.txt")
if ! echo "$pre_a" | grep -q '^M' || ! echo "$pre_b" | grep -q '^M'; then
    echo "INFRA: precondition not met (A='$(echo $pre_a | tr '\n' ' ')' B='$(echo $pre_b | tr '\n' ' ')') — prep 2/tcp first"; exit 2
fi
ck "precondition: both nodes mounted on force_transport=1" "$(echo "$pre_a $pre_b" | tr '\n' ' ' | grep -c 'M 1 M 1')" "1"
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "=== transport_conformance label=$LABEL A=$A B=$B dev=$DEV sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') out=$OUT $(date -u +%FT%TZ) ==="

# ---- arm A: default-argument joiner adopts TCP ----
echo "--- arm A: $B leaves and rejoins with default module arguments $(date -u +%T)"
am=$(rsx 10 "$A" "date +%s" | tail -1)
require_epoch "$am" "A: $A's clock mark before arm A"
leave "$B" A_leave
ck "A: $B left cleanly" "$(grep -c '^UNLOADED' "$OUT/A_leave.txt")" "1"
arm "$B" "target_cache_protected=1" A_join
journal "$B" "$(field "$OUT/A_join.txt" MARK)" A_join_journal_B
ck "A: default-argument mount on $B succeeded (rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL)s)" "$(field "$OUT/A_join.txt" MOUNT_RC)" "0"
if [ -z "$(field "$OUT/A_join.txt" MOUNT_RC)" ]; then
    # s509d: the mount never returned (D state in xfs_iget); the arms that
    # follow would run against a wedged node and the rig needs a destroy
    sshq 30 "$B" "for p in \$(pidof mount); do echo \"--- mount pid \$p state \$(awk '{print \$3}' /proc/\$p/stat)\"; cat /proc/\$p/stack; done" > "$OUT/A_join_hung_stack_B.txt"
    echo "  INFO A: mount on $B HUNG — stack: $(tr '\n' '|' < "$OUT/A_join_hung_stack_B.txt" | cut -c1-400)"
    echo "INFRA: $B's mount is hung; destroy $B before the next prep — stopping here"
    exit 1
fi
ck "A: $B adopted the platter's transport (P-TRANSPORT-ADOPTED)" "$(grep -ac 'P-TRANSPORT-ADOPTED' "$OUT/A_join_journal_B.txt")" "1"
ck "A: $B's DLM initialised on tcp" "$(field "$OUT/A_join.txt" TRANSPORT)" "tcp"
ck "A: $B admitted with transport=TCP" "$(grep -a 'P-DOMAIN-ADMITTED' "$OUT/A_join_journal_B.txt" | grep -ac 'transport=TCP')" "1"
bnode=$(field "$OUT/A_join.txt" NODE_ID)
sleep 8
journal "$A" "$am" A_journal_A
ckge "A: $A discovered $B (node $bnode) as a peer" "$(grep -a "peer discovered: node_id=$bnode" "$OUT/A_journal_A.txt" | grep -ac .)" 1
ck "A: zero P-TRANSPORT-MISMATCH-PEER on $A" "$(grep -ac 'P-TRANSPORT-MISMATCH-PEER' "$OUT/A_journal_A.txt")" "0"
ck "A: zero 'connection to cluster node $bnode failed' on $A" "$(grep -ac "connection to cluster node $bnode failed" "$OUT/A_journal_A.txt")" "0"
# clean departure must be recognised
am2=$(rsx 10 "$A" "date +%s" | tail -1)
require_epoch "$am2" "A: $A's clock mark before $B's second departure"
leave "$B" A_leave2
ck "A: $B left cleanly again" "$(grep -c '^UNLOADED' "$OUT/A_leave2.txt")" "1"
sleep 12
journal "$A" "$am2" A_journal_A2
# on TCP the GOODBYE retires the peer's tracking before the monitor can see
# the released slot, so the departure is observed as P-GOODBYE-RX (a
# P163-CLEAN-DEPART* line is the disklock-side observation when it wins)
ckge "A: $A observed $B's clean departure (P-GOODBYE-RX node $bnode or P163-CLEAN-DEPART node=$bnode)" "$(grep -a "P-GOODBYE-RX node $bnode \|P163-CLEAN-DEPART.*node=$bnode" "$OUT/A_journal_A2.txt" | grep -ac .)" 1
ck "A: zero P304-RETIRE-UNKNOWN-STALLED on $A for node $bnode" "$(grep -a 'P304-RETIRE-UNKNOWN-STALLED' "$OUT/A_journal_A2.txt" | grep -ac "node=$bnode")" "0"
# 0.75.1: each clean departure makes A take over B's authority-ledger pages
# on the heartbeat thread.  Measured before 0.75.1 on this LUN: a 26426-page
# walk cost 48.8 s of monitor stall (P-HB-MONSLOW, two P278-HB-STALL dumps)
# and every grant from the rejoining node failed meanwhile.  The takeover
# must stay well inside one heartbeat interval and never stall the thread.
journal "$A" "$am" A_journal_A_all
tk=$(grep -a 'P-TAUTH-TAKEOVER ' "$OUT/A_journal_A_all.txt")
ckge "A: $A ran the ledger takeover for $B's departures (P-TAUTH-TAKEOVER)" "$(echo "$tk" | grep -ac 'departed=')" 1
tkmax=$(echo "$tk" | grep -ao 'scan_ms=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
tktot=$(echo "$tk" | grep -ao 'total_ms=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
echo "  INFO takeover lines: $(echo "$tk" | grep -ac .) scan_ms_max=${tkmax:-?} total_ms_max=${tktot:-?} $(echo "$tk" | grep -ao 'scanned=[0-9]* cand=[0-9]* bad=[0-9]*' | tail -1)"
# 0.75.2: the passes run on the departure worker; what is asserted about
# the heartbeat thread is the zero-stall pair below.  The worker's own wall
# is bounded: two ~4 s passes on this LUN + margin.
dw=$(grep -a 'P-DEPART-WORK ' "$OUT/A_journal_A_all.txt" | grep -ao 'total_ms=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
ckge "A: departure work ran on $A's worker (P-DEPART-WORK)" "$(grep -ac 'P-DEPART-WORK ' "$OUT/A_journal_A_all.txt")" 1
ck "A: departure work total_ms max under 15000 (got ${dw:-?})" "$([ "${dw:-99999}" -lt 15000 ] 2>/dev/null && echo 1 || echo 0)" "1"
ck "A: zero P-TAUTH-TAKEOVER-SCAN-FAIL on $A" "$(grep -ac 'P-TAUTH-TAKEOVER-SCAN-FAIL' "$OUT/A_journal_A_all.txt")" "0"
ck "A: zero P278-HB-STALL on $A across arm A" "$(grep -ac 'P278-HB-STALL' "$OUT/A_journal_A_all.txt")" "0"
ck "A: zero P-HB-MONSLOW on $A across arm A" "$(grep -ac 'P-HB-MONSLOW' "$OUT/A_journal_A_all.txt")" "0"
ck "A: zero 'lock request failed after' retry exhaustion on $B during the rejoin" "$(grep -ac 'lock request failed after' "$OUT/A_join_journal_B.txt")" "0"
# both of B's departures must be CLEAN on B's own record: s509a's second
# leave was recorded DIRTY (P-SB-SEAL-DIRTY-DEPARTURE) because its final
# SB-summary lock request exhausted its retries while A's heartbeat thread
# was inside the ledger walks
journal "$B" "$am" A_journal_B_all
ck "A: $B's two departures released the slot cleanly (P304-RETIRE-PENDING-RELEASED x2)" "$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/A_journal_B_all.txt")" "2"
ck "A: zero P-SB-SEAL-DIRTY-DEPARTURE on $B" "$(grep -ac 'P-SB-SEAL-DIRTY-DEPARTURE' "$OUT/A_journal_B_all.txt")" "0"
ck "A: zero P277-SLOT-RETAINED-UNMOUNT-DIRTY on $B" "$(grep -ac 'P277-SLOT-RETAINED-UNMOUNT-DIRTY' "$OUT/A_journal_B_all.txt")" "0"
ck "A: zero 'lock request failed after' on $B across arm A (its own unmounts included)" "$(grep -ac 'lock request failed after' "$OUT/A_journal_B_all.txt")" "0"
echo "  INFO departure work on $A: $(grep -a 'P-DEPART-WORK\|P-DEPART-COALESCED' "$OUT/A_journal_A_all.txt" | sed 's/.*mxfs: mxfs: //' | cut -c1-200 | tr '\n' '|')"

# ---- arm B: forced TCP against a CAW cluster is refused ----
echo "--- arm B: $A re-forms on CAW; $B forces TCP $(date -u +%T)"
leave "$A" B_leaveA
ck "B: $A left cleanly" "$(grep -c '^UNLOADED' "$OUT/B_leaveA.txt")" "1"
arm "$A" "target_cache_protected=1" B_formA
ck "B: $A formed a cluster with default arguments (rc=$(field "$OUT/B_formA.txt" MOUNT_RC))" "$(field "$OUT/B_formA.txt" MOUNT_RC)" "0"
ck "B: $A's DLM is on caw" "$(field "$OUT/B_formA.txt" TRANSPORT)" "caw"
sleep 6   # A's first heartbeat records land
arm "$B" "target_cache_protected=1 force_transport=1" B_forceB
journal "$B" "$(field "$OUT/B_forceB.txt" MARK)" B_forceB_journal
ck "B: forced-TCP mount on $B REFUSED (rc=$(field "$OUT/B_forceB.txt" MOUNT_RC) wall=$(field "$OUT/B_forceB.txt" WALL)s)" "$([ "$(field "$OUT/B_forceB.txt" MOUNT_RC)" != 0 ] && echo 1 || echo 0)" "1"
ck "B: P-TRANSPORT-MISMATCH-REFUSED named" "$(grep -ac 'P-TRANSPORT-MISMATCH-REFUSED' "$OUT/B_forceB_journal.txt")" "1"
ck "B: no admission on $B" "$(grep -ac 'P-DOMAIN-ADMITTED' "$OUT/B_forceB_journal.txt")" "0"
ck "B: $B not mounted" "$(grep -c '^NOT_MOUNTED' "$OUT/B_forceB.txt")" "1"
rsx 30 "$B" "for i in 1 2 3; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/B_unload.txt"
capture_require "$OUT/B_unload.txt" '^(UNLOADED|STILL_LOADED)$' "B: the module unload on $B after the refusal"
ck "B: refusal left the module loadable (rmmod ok)" "$(grep -c '^UNLOADED' "$OUT/B_unload.txt")" "1"

# ---- arm C: default-argument joiner conforms to CAW ----
echo "--- arm C: $B joins with default arguments $(date -u +%T)"
arm "$B" "target_cache_protected=1" C_joinB
journal "$B" "$(field "$OUT/C_joinB.txt" MARK)" C_joinB_journal
ck "C: default-argument mount on $B succeeded (rc=$(field "$OUT/C_joinB.txt" MOUNT_RC) wall=$(field "$OUT/C_joinB.txt" WALL)s)" "$(field "$OUT/C_joinB.txt" MOUNT_RC)" "0"
ck "C: $B's DLM is on caw" "$(field "$OUT/C_joinB.txt" TRANSPORT)" "caw"
ck "C: P-TRANSPORT-CONFORMED caw" "$(grep -a 'P-TRANSPORT-CONFORMED' "$OUT/C_joinB_journal.txt" | grep -ac 'CONFORMED caw')" "1"
ck "C: admitted with transport=CAW" "$(grep -a 'P-DOMAIN-ADMITTED' "$OUT/C_joinB_journal.txt" | grep -ac 'transport=CAW')" "1"

# ---- arm D: everyone leaves ----
echo "--- arm D: both leave $(date -u +%T)"
leave "$B" D_leaveB; leave "$A" D_leaveA
ck "D: $B left cleanly" "$(grep -c '^UNLOADED' "$OUT/D_leaveB.txt")" "1"
ck "D: $A left cleanly" "$(grep -c '^UNLOADED' "$OUT/D_leaveA.txt")" "1"

echo "=== transport_conformance $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
