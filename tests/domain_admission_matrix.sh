#!/bin/bash
# domain_admission_matrix.sh — sess447 (D-FOREIGN-REPLAY-UNGATED-IMAGES
# default-on, design-consult ruling phase 3): the MOUNT-TIME durability-domain
# admission table of mxfs_durability_domain_admit (pal/linux/xfs_super.c),
# asserted on ONE node by real insmod+mount attempts.  Every invalid row must
# refuse deterministically (mount rc!=0, P-DOMAIN-REFUSED naming the row's
# condition, NO 'foreign replay' / recovery lines, no P-DOMAIN-ADMITTED); the
# valid row must admit with P-DOMAIN-ADMITTED ... COHERENCE-ONLY and mount
# rc=0; a read-only mount is not gated.
#
#   R1 fua_disable=1 tcp=0 (module defaults)      -> REFUSED 'target_cache_protected=0'
#   R2 fua_disable=0 tcp=0                         -> REFUSED 'fua_disable=0'
#   R3 fua_disable=0 tcp=1                         -> REFUSED 'fua_disable=0'
#   R4 fua_disable=1 tcp=1 foreign_replay_token_enforce=0 -> REFUSED 'foreign_replay_token_enforce=0'
#   R5 fua_disable=1 tcp=1 icluster_dlm=1          -> REFUSED 'icluster_dlm=1'
#   R6 fua_disable=1 tcp=1 (production declaration) -> ADMITTED coherence-only, rc=0
#   R7 fua_disable=1 tcp=0, mount -o ro            -> rc=0, no P-DOMAIN line (RO not gated)
#   R8 production knobs + force_transport=1 (TCP)  -> ADMITTED (0.73.0: the TCP authority
#      ledger qualifies the domain; 0.55.0-0.72.x refused it 'transport is not CAW')
#
# The node LEAVES the cluster for the matrix (clean umount first) and rejoins
# at the end with the production declaration; the rest of the fleet stays up.
# Usage: tests/domain_admission_matrix.sh <label> [node=test32]
# budget: per row rmmod+insmod+mount attempt <= 25 s (measured insmod ~2 s,
# a refused mount returns in < 1 s; an admitted mount joins in ~5-15 s);
# 7 rows + final rejoin => bound 240 s.
set -u
LABEL=${1:?label}
NODE=${2:-test32}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$NODE"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_domainmx_$LABEL
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
# dev= is printed because a run without MXFS_DEV on the QNAP rig silently
# mounts the multipath default: every row then returns rc=32 in 0 s (s517c).
echo "=== domain_admission_matrix label=$LABEL node=$NODE dev=$DEV sv=$TREE_SV out=$OUT $(date -u +%FT%TZ) ==="

# leave the cluster cleanly
sshq 60 "$NODE" "mountpoint -q $MNT && timeout 40 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null && break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/leave.txt"
grep -q '^UNLOADED' "$OUT/leave.txt" && pass "node left the cluster cleanly ($(grep -o 'UMOUNT_RC=[0-9]*' "$OUT/leave.txt"))" || { fail "node did not unload mxfs: $(tr '\n' ' ' < "$OUT/leave.txt" | cut -c1-120)"; echo "=== domain_admission_matrix $LABEL: fails=$fails (setup) ==="; exit 1; }

# row <id> <modargs> <mountopts> <expect: REFUSED|ADMITTED|RO> <why-substring>
row() {
    local id=$1 args=$2 mopts=$3 expect=$4 why=$5 r=""
    sshq 60 "$NODE" "for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done
        M=\$(date +%s); insmod /root/mxfs.ko.prep dyndbg=+p $args; echo INSMOD_RC=\$?
        echo eff enforce=\$(cat /sys/module/mxfs/parameters/foreign_replay_token_enforce) rpe=\$(cat /sys/module/mxfs/parameters/release_proof_enforce) fua=\$(cat /sys/module/mxfs/parameters/fua_disable) tcp=\$(cat /sys/module/mxfs/parameters/target_cache_protected) iclus=\$(cat /sys/module/mxfs/parameters/icluster_dlm)
        T0=\$(date +%s); timeout 25 mount -t mxfs $mopts $DEV $MNT; echo MOUNT_RC=\$? WALL=\$(( \$(date +%s) - T0 ))
        journalctl -k --since @\$M --no-pager 2>/dev/null | grep -a 'P-DOMAIN-\|foreign replay\|P163-\|P238-RECOV\|MXFS: xfs_log_mount\|Mounting' | cut -c1-260
        mountpoint -q $MNT && { echo MOUNTED; timeout 40 umount $MNT; echo UMOUNT_RC=\$?; } || echo NOT_MOUNTED" > "$OUT/$id.txt" 2>&1
    local mrc; mrc=$(grep -ao '^MOUNT_RC=[0-9]*' "$OUT/$id.txt" | head -1 | cut -d= -f2)	# anchored: UMOUNT_RC= also contains MOUNT_RC=
    local eff; eff=$(grep -a '^eff ' "$OUT/$id.txt" | head -1)
    case $expect in
      REFUSED)
        if [ "${mrc:-0}" -ne 0 ] && grep -aq "P-DOMAIN-REFUSED.*$why" "$OUT/$id.txt" && ! grep -aq 'P-DOMAIN-ADMITTED\|foreign replay\|P238-RECOV' "$OUT/$id.txt" && grep -q NOT_MOUNTED "$OUT/$id.txt"; then
            pass "$id [$eff] REFUSED rc=$mrc '$why' (no admission, no replay)"
        else
            fail "$id [$eff] expected REFUSED '$why': rc=${mrc:-?} $(grep -a 'P-DOMAIN\|MOUNTED' "$OUT/$id.txt" | head -2 | cut -c1-140 | tr '\n' '|')"
        fi ;;
      ADMITTED)
        if [ "${mrc:-1}" -eq 0 ] && grep -aq 'P-DOMAIN-ADMITTED.*COHERENCE-ONLY' "$OUT/$id.txt" && grep -q '^MOUNTED' "$OUT/$id.txt" && grep -q 'UMOUNT_RC=0' "$OUT/$id.txt"; then
            pass "$id [$eff] ADMITTED coherence-only rc=0 ($(grep -o 'WALL=[0-9]*' "$OUT/$id.txt")), clean umount"
        else
            fail "$id [$eff] expected ADMITTED: rc=${mrc:-?} $(grep -a 'P-DOMAIN\|MOUNTED\|UMOUNT' "$OUT/$id.txt" | head -3 | cut -c1-140 | tr '\n' '|')"
        fi ;;
      RO)
        if [ "${mrc:-1}" -eq 0 ] && ! grep -aq 'P-DOMAIN-' "$OUT/$id.txt" && grep -q '^MOUNTED' "$OUT/$id.txt"; then
            pass "$id [$eff] read-only mount not gated (rc=0, no P-DOMAIN line)"
        else
            fail "$id [$eff] expected RO mount admitted without gating: rc=${mrc:-?} $(grep -a 'P-DOMAIN\|MOUNTED' "$OUT/$id.txt" | head -2 | cut -c1-140 | tr '\n' '|')"
        fi ;;
    esac
}
row R1 ""                                                  ""      REFUSED  "target_cache_protected=0"
row R2 "fua_disable=0"                                     ""      REFUSED  "fua_disable=0"
row R3 "fua_disable=0 target_cache_protected=1"            ""      REFUSED  "fua_disable=0"
row R4 "target_cache_protected=1 foreign_replay_token_enforce=0" "" REFUSED "foreign_replay_token_enforce=0"
row R5 "target_cache_protected=1 icluster_dlm=1"           ""      REFUSED  "icluster_dlm=1"
row R6 "target_cache_protected=1"                          ""      ADMITTED ""
row R7 ""                                                  "-o ro" RO       ""
# the SELECTED transport is checked after DLM init; since 0.73.0 a TCP-transport
# clustered RW mount is a qualified domain and is admitted with the production
# knobs (0.55.0-0.72.x refused it, D-0288).
row R8 "target_cache_protected=1 force_transport=1"        ""      ADMITTED ""

# rejoin with the production declaration.
# s516b (0.75.25): the rejoin failed REJOIN_RC=32 and this capture held
# nothing — the node's journal is volatile and it was rebooted before anyone
# looked; only its serial console kept 'lock request failed after 60 retries
# ... ino=128 mode=EX why[remaster=60]' x3 and the mount's shutdown.  Both
# nodes' full kernel windows are saved now (the noisy ledger-page lines
# dropped), and the peer's view is the half the requester's log cannot show.
PEER=${3:-test1}
RJM=$(date +%s)
sshq 90 "$NODE" "for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; insmod /root/mxfs.ko.prep dyndbg=+p target_cache_protected=1; T0=\$(date +%s); timeout 60 mount -t mxfs $DEV $MNT; echo REJOIN_RC=\$? WALL=\$(( \$(date +%s) - T0 ))" > "$OUT/rejoin.txt"
for n in "$NODE" "$PEER"; do
    sshq 40 "$n" "journalctl -k --since @$RJM --no-pager 2>/dev/null | grep -av 'P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|bdev_io\|P-TAUTH-HANDOFF \|P-TAUTH-TAKEOVER-RETIRE' | cut -c1-400" > "$OUT/rejoin_journal_$n.txt"
done
echo "  INFO rejoin: $(grep -ao 'REJOIN_RC=[0-9]* WALL=[0-9]*' "$OUT/rejoin.txt") | $NODE: retries=$(grep -ac 'lock request failed after' "$OUT/rejoin_journal_$NODE.txt") remaster_rx=$(grep -ac 'P-TAUTH-REMASTER-RX' "$OUT/rejoin_journal_$NODE.txt") shutdown=$(grep -ac 'Shutting down filesystem' "$OUT/rejoin_journal_$NODE.txt") | $PEER: remaster_view=$(grep -ac 'P-TAUTH-REMASTER-VIEW' "$OUT/rejoin_journal_$PEER.txt") parked=$(grep -ac 'P-TAUTH-PARKED\|P-TAUTH-REMASTER-PARKED' "$OUT/rejoin_journal_$PEER.txt") depart=$(grep -ac 'P-DEPART-WORK' "$OUT/rejoin_journal_$PEER.txt") takeover=$(grep -ac 'P-TAUTH-TAKEOVER ' "$OUT/rejoin_journal_$PEER.txt")"
grep -q 'REJOIN_RC=0' "$OUT/rejoin.txt" && pass "node rejoined with target_cache_protected=1" || fail "rejoin: $(tr '\n' ' ' < "$OUT/rejoin.txt" | cut -c1-120)"
[ "$(grep -ac 'Shutting down filesystem' "$OUT/rejoin_journal_$NODE.txt")" = 0 ] || fail "the rejoin mount shut the filesystem down on $NODE ($(grep -a 'unrecoverable\|lock request failed after' "$OUT/rejoin_journal_$NODE.txt" | head -1 | cut -c1-160))"
echo "=== domain_admission_matrix $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
