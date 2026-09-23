#!/bin/sh
# d0286_tcp_wedge.sh — D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286 verification
# (sess418, 0.29.0 departure state machine; sess416 design-consult ruling "Shape B
# strengthened", sess418 review item F).
#
# Runs the transport-agnostic T8 injector matrix (tests/d512_t8_inject.sh:
# kinds 2/1/3/4 — synthetic drain failures -> inode WEDGE on a holder while
# a peer reader is blocked) on a fleet that is mounted with the TCP DLM
# transport, then asserts the TCP-specific containment the CAW on-disk pin
# provides for free on that transport:
#
#   on each fail-stop holder H (kinds 1/3/4):
#     - P-SESSION-POISON fired (the synchronous poison from force-shutdown);
#     - ZERO P-GOODBYE-SENT (the clean-departure goodbye was refused);
#     - ZERO P-POISON-AFTER-CLEAN-LEAVE (the linearization contradiction);
#     - ZERO P-DEPART-POISON-WINS is NOT required (H never unmounts here);
#   on the reader W, within this run's kmsg window:
#     - ZERO P-GOODBYE-RX (no peer's grants were purged by a goodbye);
#     - the death path ran for the wedged holders ("recovery starting" or
#       P-TCPDEATH-DEFERRED), never an immediate purge;
#   from the T8 harness itself: destructive kinds blocked W at +8s, W's read
#   completed only after recovery with H's exact md5, zero splats.
#
# Then the CLEAN-UNMOUNT REGRESSION on TCP: H2 (the kind-2 holder, alive)
# unmounts cleanly; assert P-GOODBYE-SENT==1 on H2, P-DEPART-POISON-WINS==0
# on H2, and >=1 P-GOODBYE-RX on W after the umount marker.
#
# Leaves H1/H3/H4 wedged and H2 unmounted — run `./run.sh 32 <dlm>
# prep_cluster` before any other rig work.
#
# the budget rule (derived): T8 ~370s (its own derivation) + 5 dmesg sweeps ~15s +
# clean umount ~20s + sweeps ~10s => ~415s.  Caller bound 450s.
#
# Usage: tests/d0286_tcp_wedge.sh <label> [W] [H2] [H1] [H3] [H4]
set -u
LABEL=${1:?label}
W=${2:-test1}; H2=${3:-test2}; H1=${4:-test3}; H3=${5:-test4}; H4=${6:-test5}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0286tcp
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
cnt() { # $1=node $2=marker $3=pattern -> count of lines after marker
    timeout 25 $SSH "$1" "dmesg | sed -n \"/$2/,\\\$p\" | grep -ac '$3'" 2>/dev/null | filt | tr -dc '0-9'
}

echo "=== d0286_tcp_wedge label=$LABEL W=$W H2=$H2 H1=$H1 H3=$H3 H4=$H4 out=$OUT $(date -u +%FT%TZ) ==="

# -- transport gate: every involved node must be on the TCP DLM --
for n in "$W" "$H2" "$H1" "$H3" "$H4"; do
    ft=$(timeout 15 $SSH "$n" "cat /sys/module/mxfs/parameters/force_transport" 2>/dev/null | filt | tr -dc '0-9')
    if [ "$ft" != "1" ]; then
        echo "ABORT: $n force_transport='$ft' — fleet is not on TCP (./run.sh 32 tcp prep_cluster first)"
        exit 2
    fi
done
echo "  transport gate OK: all 5 nodes force_transport=1"

MARK="D0286-$LABEL-$$"
for n in "$W" "$H2" "$H1" "$H3" "$H4"; do
    timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1
done

# -- the T8 matrix (its own asserts count toward this verdict) --
D512_OUT="$OUT/t8" timeout 420 sh tests/d512_t8_inject.sh "$LABEL" "$W" "$H2" "$H1" "$H3" "$H4" | tee "$OUT/t8.log"
t8fails=$(grep -ac '^  FAIL' "$OUT/t8.log")
ck "T8 matrix: zero FAIL lines" "$t8fails" "0"

# -- TCP containment sweep on the fail-stop holders --
for H in "$H1" "$H3" "$H4"; do
    window_count_into p "$H" 20 "$MARK" 'P-SESSION-POISON' "p"; ck "$H: P-SESSION-POISON fired" "$([ "${p:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    window_count_into g "$H" 20 "$MARK" 'P-GOODBYE-SENT' "g";   ck "$H: zero P-GOODBYE-SENT" "${g:-nossh}" "0"
    window_count_into c "$H" 20 "$MARK" 'P-POISON-AFTER-CLEAN-LEAVE' "c"; ck "$H: zero P-POISON-AFTER-CLEAN-LEAVE" "${c:-nossh}" "0"
    window_count_into r "$H" 20 "$MARK" 'P-TCP-RELEASE-POISONED' "r"; echo "  INFO $H: P-TCP-RELEASE-POISONED=$r (post-poison wire releases refused)"
    timeout 25 $SSH "$H" "dmesg | sed -n \"/$MARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/dmesg_$H.txt"
done
# -- reader side: no goodbye-driven purge, death path engaged --
window_count_into grx "$W" 20 "$MARK" 'P-GOODBYE-RX' "grx"; ck "$W: zero P-GOODBYE-RX during the wedge phase" "${grx:-nossh}" "0"
window_count_into dp "$W" 20 "$MARK" 'P-TCPDEATH-DEFERRED\|lease expired/died\|recovery starting\|elected (slot' "dp"
ck "$W: death/recovery path engaged for the wedged holders" "$([ "${dp:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
window_count_into ip "$W" 20 "$MARK" 'did not reconnect within.*declaring dead, recovering locks' "ip"
echo "  INFO $W: TCP grace deaths=$ip (each must be followed by P-TCPDEATH-DEFERRED, never an immediate purge)"
window_count_into tdd "$W" 20 "$MARK" 'P-TCPDEATH-DEFERRED' "tdd"
if [ "${ip:-0}" -gt 0 ]; then ck "$W: every TCP grace death deferred" "$tdd" "$ip"; fi
timeout 25 $SSH "$W" "dmesg | sed -n \"/$MARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/dmesg_$W.txt"

# -- clean-unmount regression on TCP (H2 is alive) --
echo "--- clean unmount regression: $H2 ---"
UMARK="D0286U-$LABEL-$$"
timeout 12 $SSH "$W" "echo '$UMARK' > /dev/kmsg" >/dev/null 2>&1
timeout 12 $SSH "$H2" "echo '$UMARK' > /dev/kmsg" >/dev/null 2>&1
value_now_into urc "$H2" 60 "$OUT/rv_urc_1.txt" '^rc=' "urc on $H2" "timeout 45 umount $MNT; echo rc=\$?"; urc=$(printf '%s\n' "$urc" | sed -n 's/^rc=//p')
ck "$H2: clean umount rc" "${urc:-nossh}" "0"
window_count_into gs "$H2" 20 "$UMARK" 'P-GOODBYE-SENT' "gs"; ck "$H2: P-GOODBYE-SENT on clean umount" "${gs:-nossh}" "1"
window_count_into pw "$H2" 20 "$UMARK" 'P-DEPART-POISON-WINS' "pw"; ck "$H2: zero P-DEPART-POISON-WINS" "${pw:-nossh}" "0"
sleep 2
window_count_into grx2 "$W" 20 "$UMARK" 'P-GOODBYE-RX' "grx2"; ck "$W: P-GOODBYE-RX after clean umount" "$([ "${grx2:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
window_count_into gdi "$W" 20 "$UMARK" 'P-GOODBYE-DEAD-IGNORED' "gdi"; ck "$W: zero P-GOODBYE-DEAD-IGNORED for a clean departer" "${gdi:-nossh}" "0"
timeout 25 $SSH "$H2" "dmesg | sed -n \"/$UMARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/dmesg_${H2}_umount.txt"

echo "=== d0286_tcp_wedge $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
echo "NOTE: $H1 $H3 $H4 wedged, $H2 unmounted — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
