#!/bin/bash
# tests/mpath/path_answer_lost.sh — F9 of docs/mpath-verification.md
# (disk/caw): a lock command the target applied and the node never heard the
# answer to.
#
# MXFS sends COMPARE AND WRITE down one path of the map itself.  When that
# path dies after the target applied a swap and before the answer arrived,
# the lock manager sends the swap again down the other path, and the second
# copy miscompares against the first one's write.  It has to recognise its own
# completed swap (P-CAW-ANSWER-LOST-LANDED) and neither lose the lock nor
# grant it twice.  A link taken down reaches that window only when a swap
# happens to be in flight; this reaches it on purpose:
#
#   on the victim (last node), every frame TOWARD the node on one path is
#   dropped (scripts/san_net.sh mute) while its own frames still arrive, so
#   the target goes on applying the node's commands and the node hears no
#   answer, until the initiator gives the session up and the path fails;
#   the mute is lifted, the path reinstated, and the same is done on the
#   other path.  Whichever path was carrying the lock commands, one of the
#   two faults lands on it;
#
#   then, with both paths up, the victim is told to treat the answers of its
#   next 40 applied swaps as lost (caw_inject_answer_lost_n, a test-only
#   module parameter).  The mutes are the real fault and whatever it catches;
#   this is the window itself, every time: measured on 4/disk/caw/mpath the
#   two mutes caught slot reads and no swap.
#
# What a PASS claims: at least one resent swap met its own write on the victim
# (the row counts them in the kernel log and FAILS on zero, so a pass is a
# pass through the window); per fault, no operation on any node returned an
# error, every node's longest stall is under the bound of
# tools/mpath_settings.sh, and the path left standing carried the writes; no
# double grant; no node shut down, withdrew or was declared dead; the target
# holds the same reservation keys at the end; every acknowledged file reads
# back with its checksum from another node.
#
# derived time budget: warm-up 20 s + 2 x (answers lost 40 s + reinstatement,
# bound 60 s, measured 15-20 s) + the injected answers, bound 30 s + 5 s
# + stop, verify and audit ~10 s per node: about 190 s at 2 nodes.
set -u
ROW=path_answer_lost
. "$(dirname "$0")/lib.sh"
HOLD=${PF_HOLD_S:-40}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_MUTED=1
pf_start_gate
pf_load_start

lost() {  # <muted net> <kept net> <tag>
    local net=$1 kept=$2 tag=$3 T0 T1 r
    T0=$(now_ms)
    scripts/san_net.sh mute "$V" "$net" on >> "$OUT/links.log" \
        || { why="could not mute $V's path $net"; finish FAIL "stage=mute"; exit 1; }
    echo "  INFO $tag: every frame toward $V on path $net DROPPED from $(date -u +%T), for ${HOLD}s: the target applies $V's commands and $V hears no answer"
    sleep $((HOLD / 2)); state "$V" "${tag}_mid"
    sleep $((HOLD - HOLD / 2)); state "$V" "${tag}_end"
    T1=$(now_ms)
    pf_carried "$V" "$tag" "$kept" "$net"
    pf_window "$tag" "$T0" "$T1"
    scripts/san_net.sh mute "$V" "$net" off >> "$OUT/links.log" \
        || { why="could not unmute $V's path $net"; finish FAIL "stage=mute"; exit 1; }
    r=$(wait_usable "$V" "${tag}_back")
    cklt "$tag: multipathd reinstated path $net once its answers arrive again, seconds" "$r" 61
}
lost a b F9a
lost b a F9b

# F9c. The window itself, on purpose.  A muted path catches a swap only when
# the mute lands between the swap and its answer, and every swap follows a
# slot read of the same size, which is what the two mutes above were measured
# to catch instead.  Here the node is told to treat the answers of its next
# $INJ applied swaps as lost (caw_inject_answer_lost_n): each is sent again,
# and the copy meets the first one's write on a platter the peers are using.
INJ=${PF_INJECT_N:-40}
KNOB=/sys/module/mxfs/parameters/caw_inject_answer_lost_n
T0=$(now_ms)
rsx 20 "$V" "echo $INJ > $KNOB; echo ARMED=\$(cat $KNOB)" > "$OUT/inject_arm_$V.txt"
capture_require "$OUT/inject_arm_$V.txt" '^ARMED=[0-9]+$' "arming the lost answers on $V"
s=$SECONDS; left=$INJ
while [ $((SECONDS - s)) -lt 30 ]; do
    left=$(rs 15 "$V" "cat $KNOB" | grep -aE '^-?[0-9]+$' | tail -1)
    [ "${left:-$INJ}" -le 0 ] 2>/dev/null && break
    sleep 2
done
rs 15 "$V" "echo 0 > $KNOB" >/dev/null 2>&1
ck "F9c: $V's lock traffic used up all $INJ lost answers within 30 s (left)" "${left:-?}" 0
sleep 5
pf_window F9c "$T0" "$(now_ms)"

pf_load_stop
pf_verify
# the resends that met their own write, from the kernel log followed since
# the row's mark
rsx 60 "$V" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -a 'P-CAW-ANSWER-LOST' | cut -c1-300; echo CAW_READ" > "$OUT/answer_lost_$V.txt"
capture_require "$OUT/answer_lost_$V.txt" '^CAW_READ$' "the lock-command lines of $V's kernel log"
inj=$(grep -ac 'P-CAW-ANSWER-LOST-INJECT' "$OUT/answer_lost_$V.txt")
landed=$(grep -ac 'P-CAW-ANSWER-LOST-LANDED' "$OUT/answer_lost_$V.txt")
unres=$(grep -ac 'P-CAW-ANSWER-LOST-UNRESOLVED' "$OUT/answer_lost_$V.txt")
echo "  INFO $V: answers reported lost on purpose: $inj; resent swaps that met their own write: $landed; resent swaps that did not find their image (a peer wrote in between): $unres"
ck "the window was reached: at least one resent swap met its own write on $V" "$([ "$landed" -ge 1 ] && echo yes || echo no)" yes
ck "every lost answer was accounted for: landed + written-over >= the $inj injected" "$([ $((landed + unres)) -ge "$inj" ] && [ "$inj" -ge 1 ] && echo yes || echo no)" yes
pf_health
pf_done "victim=$V injected=$inj landed=$landed unresolved=$unres stall_a_ms=$(stall_of F9a "$V") stall_b_ms=$(stall_of F9b "$V")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
