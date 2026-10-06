#!/bin/bash
# tests/mpath/umount_pair_race.sh — the last two nodes of a net/mesh cluster
# unmount together, and the second is still releasing its grants when the
# first has gone.
#
# Measured on 8/net/mesh/mpath (0.90.53, chk_clean unmount judged stuck): the
# later node's shutdown release-all sent each of its ~938 grants to the peer
# that had already left, three attempts 100 ms apart per grant, ~62 s.  Since
# 0.90.54 a master a release could not reach is sent nothing more by that
# release-all (P-RELALL-UNREACHABLE); dl_relall_skip_unreachable=0 is the
# same-build control.
#
# The race is made certain rather than waited for: B (the last node) sleeps
# dl_relall_step_ms after each release of its release-all, so its release-all
# outlasts A's whole unmount, which starts PF_GAP_S later.
#
#   tests/mpath/lap_chain.sh row <N>/net/mesh/mpath <group> <run> tests/mpath/umount_pair_race.sh \
#       --budget 300 --knobs "dl_relall_skip_unreachable=1"     (0 for the control)
#
# What a PASS claims: B's unmount returned within its bound (the release-all's
# own stepping plus PF_UMOUNT_SLACK_S), and A's within its own; B's
# P-RELALL-WALL line reports the release-all.  The row leaves both nodes
# unmounted; the next step must prep the group.
#
# derived time budget: gate + warm-up 20 s + load 30 s + stop/verify ~15 s +
# B's stepped release-all (grants x step, ~1000 x 20 ms = 20 s) + slack 30 s
# + readback ~10 s: ~150 s; --budget 300.
set -u
ROW=umount_pair_race
. "$(dirname "$0")/lib.sh"
LOAD_S=${PF_LOAD_S:-30}
STEP_MS=${PF_STEP_MS:-20}
GAP_S=${PF_GAP_S:-2}
SLACK_S=${PF_UMOUNT_SLACK_S:-30}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
A=$W; B=$V
pf_start_gate
pf_load_start
sleep "$LOAD_S"
pf_load_stop
pf_verify
echo "$B dl_relall_step_ms want=$STEP_MS got=$(rs 15 "$B" "echo $STEP_MS > /sys/module/mxfs/parameters/dl_relall_step_ms && cat /sys/module/mxfs/parameters/dl_relall_step_ms" | tr -d '\r\n')" >> "$OUT/knobs.txt"
ck "$B took dl_relall_step_ms=$STEP_MS" "$(awk -v b="$B" '$1 == b && $2 == "dl_relall_step_ms" {print $4}' "$OUT/knobs.txt" | tail -1)" "got=$STEP_MS"
[ "$fails" = 0 ] || { finish FAIL "stage=knobs"; exit 1; }
# B first, A PF_GAP_S later; each unmount timed on its own node, bounded
rsx 200 "$B" "s=\$(date +%s%3N); timeout 180 umount $MNT; r=\$?; echo UMOUNT node=$B rc=\$r ms=\$((\$(date +%s%3N)-s))" > "$OUT/umount_$B.txt" &
pb=$!
sleep "$GAP_S"
rsx 200 "$A" "s=\$(date +%s%3N); timeout 180 umount $MNT; r=\$?; echo UMOUNT node=$A rc=\$r ms=\$((\$(date +%s%3N)-s))" > "$OUT/umount_$A.txt" &
pa=$!
wait "$pa" "$pb"
for n in $A $B; do
    capture_require "$OUT/umount_$n.txt" '^UMOUNT node=' "the unmount of $n"
    echo "  INFO $(grep -a '^UMOUNT ' "$OUT/umount_$n.txt" | tail -1)"
done
rsx 30 "$B" "sed -n '/$PFMARK/,\$p' $KFILE | grep -aE 'P-RELALL-WALL|P-RELALL-UNREACHABLE|P-RELALL-MASTER-UNREACHABLE' | cut -c1-240; echo FAILED_SENDS=\$(sed -n '/$PFMARK/,\$p' $KFILE | grep -ac 'lock release to node .* failed'); echo READ_DONE" > "$OUT/relall_$B.txt"
capture_require "$OUT/relall_$B.txt" '^READ_DONE$' "the release-all lines of $B"
cat "$OUT/relall_$B.txt" | sed 's/^/  INFO /'
wall=$(sed -n 's/.*P-RELALL-WALL released=\([0-9]*\) ms=\([0-9]*\).*/\1 \2/p' "$OUT/relall_$B.txt" | tail -1)
rel=${wall%% *}; rms=${wall##* }
ck "$B logged its release-all (P-RELALL-WALL)" "$([ -n "$wall" ] && echo yes || echo no)" yes
ck "$B's unmount returned rc 0" "$(sed -n 's/.* rc=\([0-9]*\) .*/\1/p' "$OUT/umount_$B.txt" | tail -1)" 0
ck "$A's unmount returned rc 0" "$(sed -n 's/.* rc=\([0-9]*\) .*/\1/p' "$OUT/umount_$A.txt" | tail -1)" 0
bound=$(( ${rel:-0} * STEP_MS + SLACK_S * 1000 ))
cklt "$B's unmount, ms (its release-all's stepping ${rel:-?} x ${STEP_MS} ms + ${SLACK_S} s)" "$(sed -n 's/.* ms=\([0-9]*\).*/\1/p' "$OUT/umount_$B.txt" | tail -1)" "$bound"
echo "  INFO release-all wall on $B: ${rms:-?} ms for ${rel:-?} grants"
kmsg_stop
trap - EXIT
links_all_up
finish "$([ "$fails" = 0 ] && echo PASS || echo FAIL)" "released=${rel:-?} relall_ms=${rms:-?} b_umount_ms=$(sed -n 's/.* ms=\([0-9]*\).*/\1/p' "$OUT/umount_$B.txt" | tail -1) a_umount_ms=$(sed -n 's/.* ms=\([0-9]*\).*/\1/p' "$OUT/umount_$A.txt" | tail -1) knobs=${PF_KNOBS:-none}"
[ "$fails" = 0 ]
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
