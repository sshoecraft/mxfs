#!/bin/bash
# tests/mpath/path_peer_withdrawn.sh — a node shuts its filesystem down and
# leaves with its reservation key already gone, and the others recover it:
# once with both of their paths, once with one.
#
# A node that withdraws (its filesystem shut down under it) unregisters its
# key on the way out.  The survivors then have nothing to PREEMPT, and at two
# nodes the one survivor proves the withdrawn node's accepted writes are dead
# with a LOGICAL UNIT RESET, which it may issue only as the sole registrant.
# On multipath its key is registered once per path, so "sole" has to mean
# "every registration is mine", and with a path down one of those
# registrations cannot be asked.  Measured before this row existed
# (2/net/mesh/mpath, 0.90.45): the admission refused 21 times in 112 s with
# our-key-is-registered-on-more-than-one-nexus and the withdrawn node's
# journal was never replayed.
#
#   1. every node runs the load
#   2. the victim (last node) stops its load, shuts its filesystem down
#      (XFS_IOC_GOINGDOWN, no log flush) and unmounts
#   3. the others recover it: its registrations are gone, a survivor reports
#      the recovery complete, and every survivor's load keeps completing
#   4. the victim mounts again and runs the load
#   5. network a is taken down on every survivor, and steps 2-4 are repeated
#      with every survivor on one path
#   6. network a is restored; every node ends registered on both paths
#
# What a PASS claims: both recoveries completed inside 120 s of the unmount
# with no survivor operation returning an error and no survivor stall over
# 120 s; in the one-path phase each survivor's remaining path carried the
# writes; the victim mounted again both times (rc 0) and its load ran; every
# acknowledged file reads back with its checksum from another node; no
# survivor shut down or withdrew; no double grant; at the end every node is
# registered on both paths.
#
# derived time budget: warm-up 20 s + (stop 5 s + shutdown and unmount <= 10 s
# + recovery, measured 5-40 s, bound 120 s + mount <= 30 s + load 20 s) twice
# + path failure 16-20 s + reinstatement 15-20 s + late registration <= 30 s
# + stop, verify and audit ~10 s per node: about 260 s at 2 nodes.
set -u
ROW=path_peer_withdrawn
. "$(dirname "$0")/lib.sh"
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_DEATH=1
PF_STOPS=$V
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
pf_start_gate
pf_load_start

recoveries() {  # -> recoveries the survivors have reported complete since the row's mark
    local n t=0 c
    for n in $OTHERS; do
        c=$(rs 20 "$n" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -ac 'P163-RECOVERY-COMPLETE'" | grep -aE '^[0-9]+$' | tail -1)
        t=$((t + ${c:-0}))
    done
    echo "$t"
}
withdraw() {  # <tag>: the victim shuts its filesystem down and leaves; the others recover it
    local tag=$1 before s tr rr TW
    pf_load_stop "$V"
    mv "$OUT/load_$V/run.out" "$OUT/load_$V/run_$tag.out" 2>/dev/null
    before=$(recoveries)
    TW=$(now_ms)
    measure "$V" 80 "$OUT/withdraw_${V}_$tag.txt" '^WITHDRAW ioctl_rc=[0-9]+ umount_rc=[0-9]+ mounted=[01]$' "the withdrawal of $V ($tag)" \
        "python3 -c \"import fcntl,os,struct; fd=os.open('$MNT',os.O_RDONLY); fcntl.ioctl(fd,0x8004587d,struct.pack('I',2))\"; i=\$?; timeout 60 umount $MNT; u=\$?; grep -q ' $MNT mxfs ' /proc/mounts && k=1 || k=0; echo WITHDRAW ioctl_rc=\$i umount_rc=\$u mounted=\$k"
    echo "  INFO $tag: $V $(grep -a '^WITHDRAW ' "$OUT/withdraw_${V}_$tag.txt" | head -1) at $(date -u +%T)"
    ck "$tag: $V shut its filesystem down and unmounted" "$(grep -a '^WITHDRAW ' "$OUT/withdraw_${V}_$tag.txt" | head -1)" "WITHDRAW ioctl_rc=0 umount_rc=0 mounted=0"
    # by distinct key, not by count: a survivor on one path may drop its
    # unreachable path's registration while it recovers the victim
    s=$SECONDS; tf=999
    while [ $((SECONDS - s)) -lt 60 ]; do
        keys "gone_$tag"
        [ "$(sort -u "$OUT/keys_gone_$tag.txt" | grep -c .)" = $((N - 1)) ] && { tf=$((SECONDS - s)); break; }
        sleep 3
    done
    cklt "$tag: $V's registrations left the target (only the other nodes' keys remain), seconds" "$tf" 61
    s=$SECONDS; tr=999
    while [ $((SECONDS - s)) -lt 120 ]; do
        [ "$(recoveries)" -gt "$before" ] && { tr=$((SECONDS - s)); break; }
        sleep 3
    done
    cklt "$tag: a survivor reported $V's recovery complete, seconds after the unmount" "$tr" 121
    # how the recovery was proved, kept with the row (the ring and the journal
    # hold seconds of this module's output)
    for n in $OTHERS; do
        rsx 30 "$n" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -aE 'P308-LURESET-FENCE|P306-LURESET-MULTINEXUS|P-PR-COLLAPSED-TO-ONE-NEXUS|P-PR-OWN-NEXUSES|P236-FENCE-CERTIFIED|P236-FENCEKIND|P163-RECOVERY-COMPLETE|P-PR-PATH-FILLED' | cut -c1-420; echo FENCE_READ" > "$OUT/fence_${n}_$tag.txt"
        capture_require "$OUT/fence_${n}_$tag.txt" '^FENCE_READ$' "the fence lines of $n ($tag)"
    done
    # How each recovery was proved.  The survivors fence a withdrawn node the
    # moment they see it stop, and its key is normally still registered then
    # (measured: the unmount of a shut-down filesystem leaves it), so the
    # proof is a PREEMPT AND ABORT naming that registration.  When the key
    # is already gone the one survivor of two proves it with a witnessed
    # reset of the logical unit instead.  Either is a certificate; a recovery
    # with neither is not one.
    pre=$(cat "$OUT"/fence_*_"$tag".txt | grep -ac 'P236-FENCE-CERTIFIED.*PREEMPT_ABORT')
    lur=$(cat "$OUT"/fence_*_"$tag".txt | grep -ac 'P308-LURESET-FENCE.*certified=1')
    echo "  INFO $tag: certificates so far: preempt-and-abort=$pre witnessed-reset=$lur"
    ck "$tag: the recovery of $V was certified (certificates so far)" "$([ $((pre + lur)) -ge "${2:-1}" ] && echo yes || echo no)" yes
    if [ "$tag" = one_path ] && [ "$lur" -gt "${lur_before:-0}" ]; then
        ck "$tag: the survivor removed its key from the path it could not ask before it reset the unit" "$([ "$(cat "$OUT"/fence_*_"$tag".txt | grep -ac 'P-PR-COLLAPSED-TO-ONE-NEXUS.*preempt_rc=0')" -ge 1 ] && echo yes || echo no)" yes
    fi
    lur_before=$lur
    rr=$(pf_resumed "$(now_ms)" 60 "$OTHERS")
    cklt "$tag: every survivor's load completed operations after the recovery, seconds" "$rr" 61
    PF_BOUND_MS=$DEATH_BOUND_MS pf_window "$tag" "$TW" "$(now_ms)" "$OTHERS"
    eval "rec_$tag=$tr"
}
rejoin() {  # <tag>: the victim mounts again and runs the load
    measure "$V" 70 "$OUT/mount_$1.txt" '^MOUNT_RC=[0-9]+ ms=[0-9]+ mounted=[01]$' "the victim's mount ($1)" \
        "s=\$(date +%s%3N); timeout 60 mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%3N); grep -q ' $MNT mxfs ' /proc/mounts && m=1 || m=0; echo MOUNT_RC=\$rc ms=\$((e-s)) mounted=\$m"
    echo "  INFO $1: $(grep -a '^MOUNT_RC=' "$OUT/mount_$1.txt" | head -1)"
    ck "$1: $V mounted again (rc 0)" "$(grep -a '^MOUNT_RC=' "$OUT/mount_$1.txt" | head -1 | sed 's/ ms=[0-9]*//')" "MOUNT_RC=0 mounted=1"
    [ "$fails" = 0 ] || { finish FAIL "stage=$1"; exit 1; }
    pf_load_start "$V"
}

# 2-4. with every survivor on two paths
LOAD_NODES=$OTHERS
withdraw two_paths
rejoin rejoin_two_paths
keys whole1
ck "every node is registered on both paths once $V is back ($(( 2 * N )))" "$(grep -c . "$OUT/keys_whole1.txt")" "$(( 2 * N ))"

# 5. the same, with every survivor on one path
links a down "$OTHERS"
s=$SECONDS; one=0
while [ $((SECONDS - s)) -lt 40 ]; do
    states a_failed "$OTHERS"; one=1
    for n in $OTHERS; do [ "$(usable "$OUT/state_${n}_a_failed.txt")" = 1 ] || one=0; done
    [ "$one" = 1 ] && break
    sleep 2
done
ck "multipathd failed path a on every survivor (within 40 s)" "$one" 1
states one_mid "$OTHERS"
withdraw one_path 2
states one_end "$OTHERS"
for n in $OTHERS; do pf_carried "$n" one b a; done

# 6. whole again
links a up "$OTHERS"
ra=$(wait_usable_all a_back 60 "$OTHERS")
cklt "every survivor reinstated path a, seconds" "$ra" 61
rejoin rejoin_one_path
tk=$(pf_wait_keys $(( 2 * N )) 30 whole2)
cklt "every node is registered on both paths at the end ($(( 2 * N ))), seconds" "$tk" 31

LOAD_NODES=$NODES
pf_load_stop
pf_verify
PF_NO_KEYCMP=1 pf_health
pf_done "victim=$V recovered_two_paths_s=${rec_two_paths:-?} recovered_one_path_s=${rec_one_path:-?} reinstate_s=$ra survivor_stall_two_ms=$(stall_of two_paths "$W") survivor_stall_one_ms=$(stall_of one_path "$W")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
