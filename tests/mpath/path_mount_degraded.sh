#!/bin/bash
# tests/mpath/path_mount_degraded.sh — F8 of docs/mpath-verification.md: a
# node joins the cluster with one path down, uses the other path when it
# appears, and leaves with a different path down.
#
# A reservation key is registered per path, at mount.  A path that is down at
# that moment gets no registration then, and a path that is down at unmount
# cannot be unregistered then; this row walks both.
#
#   1. the victim (last node) unmounts with both paths up; the others keep
#      running the load throughout
#   2. its path a is taken down and, once multipathd has failed it, the victim
#      mounts: it must join on path b alone
#   3. the victim runs the load; path a is restored and reinstated
#   4. path b is taken down: the victim's I/O must continue on path a, the
#      path that carried no registration when the node mounted
#   5. with b still down the victim stops its load and unmounts
#   6. b is restored; the target must hold no registration of the victim on
#      either path
#   7. the victim mounts again on two paths, and the cluster is whole
#
# What a PASS claims: every mount and unmount returned 0 inside its bound; the
# victim's load returned no error and its stall at step 4 is under the bound
# of tools/mpath_settings.sh; the path left standing carried the writes; the
# other nodes' load returned no error for the whole row; no node shut down,
# withdrew or was declared dead (the victim's own orderly departures aside);
# after step 6 the target holds exactly the other nodes' registrations, and
# after step 7 every node's on both paths; every acknowledged file reads back
# with its checksum from another node.
#
# derived time budget: warm-up 20 s + unmount <= 10 s + path failure 20 s +
# mount <= 30 s + load 20 s + reinstatement <= 20 s + fault 40 s + unmount
# <= 10 s + reinstatement <= 20 s + mount <= 30 s + stop, verify and audit
# ~10 s per node: about 200 s at 2 nodes.
set -u
ROW=path_mount_degraded
. "$(dirname "$0")/lib.sh"
HOLD=${PF_HOLD_S:-40}
DEV=${MXFS_DEV:-/dev/mapper/mpatha}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_LEAVES=1
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
LOAD_NODES=$OTHERS
pf_start_gate
pf_load_start

um() {  # <tag>: the victim's unmount, bounded
    measure "$V" 70 "$OUT/umount_$1.txt" '^UMOUNT_RC=[0-9]+ ms=[0-9]+ mounted=[01]$' "the victim's unmount ($1)" \
        "s=\$(date +%s%3N); timeout 60 umount $MNT; rc=\$?; e=\$(date +%s%3N); grep -q ' $MNT mxfs ' /proc/mounts && m=1 || m=0; echo UMOUNT_RC=\$rc ms=\$((e-s)) mounted=\$m"
    echo "  INFO $1: $(grep -a '^UMOUNT_RC=' "$OUT/umount_$1.txt" | head -1)"
    ck "$1: $V unmounted (rc 0, no mount left)" "$(grep -a '^UMOUNT_RC=' "$OUT/umount_$1.txt" | head -1 | sed 's/ ms=[0-9]*//')" "UMOUNT_RC=0 mounted=0"
}
mo() {  # <tag>: the victim's mount, bounded
    measure "$V" 70 "$OUT/mount_$1.txt" '^MOUNT_RC=[0-9]+ ms=[0-9]+ mounted=[01]$' "the victim's mount ($1)" \
        "s=\$(date +%s%3N); timeout 60 mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%3N); grep -q ' $MNT mxfs ' /proc/mounts && m=1 || m=0; echo MOUNT_RC=\$rc ms=\$((e-s)) mounted=\$m"
    echo "  INFO $1: $(grep -a '^MOUNT_RC=' "$OUT/mount_$1.txt" | head -1)"
    ck "$1: $V mounted (rc 0)" "$(grep -a '^MOUNT_RC=' "$OUT/mount_$1.txt" | head -1 | sed 's/ ms=[0-9]*//')" "MOUNT_RC=0 mounted=1"
}
wait_failed() {  # <tag>: until the victim sees 1 usable path, bound 40 s
    local s=$SECONDS u
    while [ $((SECONDS - s)) -lt 40 ]; do
        state "$V" "$1"; u=$(usable "$OUT/state_${V}_$1.txt")
        [ "${u:-2}" = 1 ] && { echo $((SECONDS - s)); return 0; }
        sleep 2
    done
    echo 999
}

# 1. leave on two paths
um leave_two_paths
[ "$fails" = 0 ] || { finish FAIL "stage=first-unmount"; exit 1; }
keys left1
ck "after the unmount the target holds only the other nodes' registrations ($(( 2 * (N - 1) )))" "$(grep -c . "$OUT/keys_left1.txt")" "$(( 2 * (N - 1) ))"

# 2. join on one path
link "$V" a down
fa=$(wait_failed a_failed)
cklt "multipathd failed the victim's path a, seconds" "$fa" 41
mo join_one_path
[ "$fails" = 0 ] || { link "$V" a up; finish FAIL "stage=degraded-mount"; exit 1; }
keys joined1
echo "  INFO registrations with the victim mounted on one path: $(grep -c . "$OUT/keys_joined1.txt")"

# 3. the victim works on one path; the other returns
pf_load_start "$V"
link "$V" a up
ra=$(wait_usable "$V" a_back)
cklt "multipathd reinstated the path that was down at mount, seconds" "$ra" 61
keys joined2
ck "the path that was down at mount carries the victim's registration once it is back ($(( 2 * N )) registrations)" "$(grep -c . "$OUT/keys_joined2.txt")" "$(( 2 * N ))"

# 4. the path that was down at mount must carry the I/O
T0=$(now_ms)
link "$V" b down
echo "  INFO $V path b DOWN at $(date -u +%T), holding ${HOLD}s: I/O must continue on the path that was down at mount"
sleep $((HOLD / 2)); state "$V" late_mid
sleep $((HOLD - HOLD / 2)); state "$V" late_end
T1=$(now_ms)
pf_carried "$V" late a b
pf_window late "$T0" "$T1" "$V"

# 5. leave with b down
pf_load_stop "$V"
um leave_one_path

# 6. nothing left behind
link "$V" b up
rb=$(wait_usable "$V" b_back)
cklt "multipathd reinstated path b, seconds" "$rb" 61
keys left2
ck "no registration of the victim is left on either path after it unmounted with one down ($(( 2 * (N - 1) )))" "$(grep -c . "$OUT/keys_left2.txt")" "$(( 2 * (N - 1) ))"

# 7. whole again
mo rejoin_two_paths
keys rejoined
ck "every node is registered on both paths at the end ($(( 2 * N )))" "$(grep -c . "$OUT/keys_rejoined.txt")" "$(( 2 * N ))"

pf_load_stop
PF_VERIFY_ON=$V pf_verify
PF_VERIFY_ON=$W pf_verify "$V"
PF_NO_KEYCMP=1 pf_health
pf_done "victim=$V mount_one_path_ms=$(sed -n 's/.* ms=\([0-9]*\).*/\1/p' "$OUT/mount_join_one_path.txt" | head -1) late_stall_ms=$(stall_of late "$V") reinstate_a_s=$ra reinstate_b_s=$rb"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
