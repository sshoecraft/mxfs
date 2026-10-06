#!/bin/bash
# tests/mpath/fenced_takeover_stop.sh — a node is fenced in the middle of a
# ledger takeover pass, and comes back: does the pass stop, or does it go on
# writing page after page into a target that refuses every command?
#
# Measured on 8/net/mesh/mpath (0.90.51, D-NETMESH-LEDGER-TICKET-RETRY-
# HAMMERS-LUN-AFTER-FENCE): a node shut down and fenced kept sending ~27
# commands a second to the LUN (P-TAUTH-TICKET-FAIL 9270 in 68 s); the host
# logged 1607 reservation conflicts from it in one minute and the host guard
# halted the rig.  The fix stops the hand-off, takeover and departure passes at
# the next page once the node's authority over the device is closed
# (P-TAUTH-TAKEOVER-INTERRUPTED for the takeover pass).  That shape came from
# survivors shut down by another defect while they ran a takeover; this row
# makes it on purpose:
#
#   1. two nodes, the load on both for a while (ledger records on many pages)
#   2. B unmounts, then A, the last member: A's incarnation keeps every page
#   3. A's takeover pass is held between pages (test-only dl_takeover_pause_ms)
#      and A mounts alone: its departure worker starts the takeover-only pass
#      over its previous incarnation's pages, and the pause keeps it open
#   4. B joins (requests on A's pages are served on demand, ahead of the pass)
#   5. A is frozen (virsh suspend); B declares it dead and fences it
#   6. A is thawed and the pause cleared at once: its pass moves to its next
#      page with its authority closed
#   7. for 30 s: A's kernel log (P-TAUTH-TAKEOVER-INTERRUPTED, ticket failures,
#      reservation conflicts) and the host's count of reservation conflicts
#      naming A's initiators
#
# A PASS: the pass was in flight when A was frozen (takeover activations logged
# before the freeze and the pass not finished), A was fenced (the target holds
# only B's two registrations), and after the thaw A's pass stopped
# (P-TAUTH-TAKEOVER-INTERRUPTED logged after the thaw) with at most
# FT_CONFLICT_MAX reservation conflicts from A's initiators on the host.
#
# Run directly on a prepared 2/net/mesh/mpath cluster:
#   MXFS_NODES=2 MXFS_NODE_LIST=test1,test2 MXFS_CONFIG=2/net/mesh/mpath \
#     tests/mpath/fenced_takeover_stop.sh
#
# derived time budget: load 20 s + two unmounts ~10 s + alone mount ~10 s +
# join ~10 s + death window 62 s + fence 15-25 s + hold 30 s + remount ~20 s:
# about 200 s.
set -u
ROW=fenced_takeover_stop
. "$(dirname "$0")/lib.sh"
A=$W
B=$V
P=/sys/module/mxfs/parameters
FT_PAUSE_MS=${FT_PAUSE_MS:-2000}
FT_CONFLICT_MAX=${FT_CONFLICT_MAX:-20}
sincek() { rsx 30 "$1" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -ac -- '$2'; echo COUNT_READ" | grep -aE '^[0-9]+$' | tail -1; }
main() {
[ "$N" = 2 ] || { why="needs exactly 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_DEATH=1
pf_start_gate
pf_load_start
pf_load_stop
trap 'timeout 30 $VIRSH resume "$A" >/dev/null 2>&1; rs 15 "$A" "echo 0 > $P/dl_takeover_pause_ms" >/dev/null 2>&1; links_all_up; kmsg_stop' EXIT

# 2. B leaves, then A, the last member
for n in "$B" "$A"; do
    measure "$n" 60 "$OUT/umount_$n.txt" '^UMOUNT rc=[0-9]+$' "the unmount of $n" "timeout 40 umount $MNT; echo UMOUNT rc=\$?"
    ck "$n unmounted (rc 0)" "$(grep -a '^UMOUNT ' "$OUT/umount_$n.txt" | head -1)" "UMOUNT rc=0"
done
[ "$fails" = 0 ] || { finish FAIL "stage=unmount"; exit 1; }

# 3. A alone, its takeover pass held open
measure "$A" 60 "$OUT/mount_alone_$A.txt" '^MOUNT rc=[0-9]+ pause=[0-9]+$' "the lone mount of $A" \
    "echo $FT_PAUSE_MS > $P/dl_takeover_pause_ms; timeout 45 mount -t mxfs $DEV $MNT; echo MOUNT rc=\$? pause=\$(cat $P/dl_takeover_pause_ms)"
ck "$A mounted alone with the takeover pass held ${FT_PAUSE_MS} ms a page" "$(grep -a '^MOUNT ' "$OUT/mount_alone_$A.txt" | head -1)" "MOUNT rc=0 pause=$FT_PAUSE_MS"
[ "$fails" = 0 ] || { finish FAIL "stage=alone"; exit 1; }
sleep 5

# 4. B joins
measure "$B" 60 "$OUT/mount_join_$B.txt" '^MOUNT rc=[0-9]+$' "the join of $B" "timeout 45 mount -t mxfs $DEV $MNT; echo MOUNT rc=\$?"
ck "$B joined (mount rc 0)" "$(grep -a '^MOUNT ' "$OUT/mount_join_$B.txt" | head -1)" "MOUNT rc=0"
[ "$fails" = 0 ] || { finish FAIL "stage=join"; exit 1; }
sleep 5
act0=$(sincek "$A" 'P-TAUTH-ACTIVATE')
echo "  INFO $A's takeover activations before the freeze: ${act0:-unread}"
ck "$A's takeover pass is in flight before the freeze (activations logged)" "$([ "${act0:-0}" -gt 0 ] && echo yes || echo no)" yes

# 5. A frozen, fenced by B
timeout 30 $VIRSH suspend "$A" >/dev/null 2>&1
ck "$A is frozen" "$($VIRSH domstate "$A" 2>/dev/null | head -1)" paused
echo "  INFO $A frozen at $(date -u +%T)"
tf=$(pf_wait_keys 2 110 fenced "$B")
cklt "$B fenced $A: its registrations left the target, seconds after the freeze" "$tf" 111
[ "$fails" = 0 ] || { finish FAIL "stage=fence"; exit 1; }

# 6. thawed, the pause cleared at once
HOST_T0=$(date '+%Y-%m-%d %H:%M:%S')
timeout 30 $VIRSH resume "$A" >/dev/null 2>&1
rs 15 "$A" "echo 0 > $P/dl_takeover_pause_ms" >/dev/null 2>&1
ck "$A is running again" "$($VIRSH domstate "$A" 2>/dev/null | head -1)" running
echo "  INFO $A thawed at $(date -u +%T), pause cleared"
sleep 30

# 7. what A did with its closed authority
# SCST names the session's initiator by its IQN, which ends in the node's
# name: "Reservation conflict (dev mxfspool04, initiator
# iqn.2004-10.com.ubuntu:01:test20-mxfs-node, tgt_id 4)"
ini="*:$A-mxfs-node"
hc=$(timeout 30 journalctl -k --since "$HOST_T0" --no-pager 2>/dev/null | grep -a 'Reservation conflict' | grep -acE "initiator [^ ,]*:${A}-mxfs-node[, ]")
intr=$(sincek "$A" 'P-TAUTH-TAKEOVER-INTERRUPTED')
tick=$(sincek "$A" 'P-TAUTH-TICKET-FAIL')
rconf=$(sincek "$A" 'reservation conflict')
closed=$(sincek "$A" 'P290-AUTH-CLOSED')
echo "  INFO $A after the thaw: takeover_interrupted=${intr:-?} ticket_fail=${tick:-?} reservation_conflicts_in_its_log=${rconf:-?} auth_closed=${closed:-?}; host reservation conflicts naming ${ini:-?}: ${hc:-?}"
rsx 30 "$A" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -aE 'P-TAUTH-TAKEOVER-INTERRUPTED|P290-AUTH-CLOSED|P131-SELF-FENCE' | cut -c1-240 | tail -12; echo LINES_READ" > "$OUT/after_thaw_$A.txt"
ck "$A's authority closed (P290-AUTH-CLOSED)" "$([ "${closed:-0}" -gt 0 ] && echo yes || echo no)" yes
ck "$A's takeover pass stopped at its next page (P-TAUTH-TAKEOVER-INTERRUPTED)" "$([ "${intr:-0}" -gt 0 ] && echo yes || echo no)" yes
cklt "reservation conflicts from $A's initiator on the host in the 30 s after the thaw" "${hc:-999}" "$((FT_CONFLICT_MAX + 1))"

# back to two members: A leaves and joins as a new incarnation
V=$A pf_remount "$A" rejoin
pf_done "pause_ms=$FT_PAUSE_MS fenced_s=$tf interrupted=${intr:-?} ticket_fail=${tick:-?} host_conflicts=${hc:-?}"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
