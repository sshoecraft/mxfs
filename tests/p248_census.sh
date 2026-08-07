#!/bin/bash
# tests/p248_census.sh — one prep_cluster cycle + teardown-window probe census
# for the P248-family closures (D-RELEASEALL-LREQ-RETIRE-MISSING,
# D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK).
#
# sess153 RULE-5 fleet requirement: >=3x 32-node prep cycles, zero P248
# aggregate + per-entry, kept=0, P253/255/257-262 deltas zero, 32/32 clean
# departures, ioretry consistent with one-shot.  sess159 adds: P254/P259/
# P269/P270 silent; P263/P267/P271 sane (with zero residue that means zero).
# P272 is an injection-only probe — any natural firing is a defect.
#
# Usage: tests/p248_census.sh <N> <expect_clean_per_node>
#   expect_clean_per_node  1  -> assert exactly one clean departure per node
#                              (use when the previous cycle left all N mounted)
#                          -1 -> report clean-departure counts only (first
#                              cycle after a partial/mixed mount state)
#
# Mechanics: kmsg marker on every node BEFORE the prep; window = LAST marker
# to end of dmesg.  One dmesg pass per node with a single multi-pattern awk
# (sess152: per-pattern greps time out at 32-way).  prep_cluster does not
# reboot nodes on the healthy path, so dmesg keeps the window; a node that
# got power-cycled during prep escalation loses its marker and is reported
# NO-WINDOW (that cycle cannot be counted — rerun it).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
CEN="$REPO/tests/census_p.sh"
N=${1:?usage: p248_census.sh <N> <expect_clean_per_node>}
EXPECT=${2:?usage: p248_census.sh <N> <expect_clean_per_node>}
NONCE=$$
cd "$REPO" || exit 2

echo "=== p248_census N=$N expect_clean=$EXPECT nonce=$NONCE ==="

# ── mark every node ──────────────────────────────────────────────────────
MARKED=$("$CEN" "$N" "echo 'P248CENSUS-$NONCE BEGIN' > /dev/kmsg && echo MARKED" |
         grep -c ' MARKED$')
if [ "$MARKED" -ne "$N" ]; then
    echo "FAIL: only $MARKED/$N nodes marked — aborting before prep"
    exit 1
fi
echo "--- $MARKED/$N nodes marked ---"

# ── the prep cycle (tears down the previous mount, re-mkfs, mounts N) ────
./run.sh "$N" caw prep_cluster
prc=$?
if [ "$prc" -ne 0 ]; then
    echo "FAIL: prep_cluster rc=$prc — census window not evaluated"
    exit 1
fi

# ── harvest: one dmesg pass per node, multi-pattern awk ──────────────────
SNIP='dmesg | awk '\''
/P248CENSUS-'$NONCE' BEGIN/ { delete c; seen=1; next }
!seen { next }
/P248-LREQ-LEAK entries=/     { c["agg"]++ }
/P248-LREQ-LEAK-ENT/          { c["ent"]++ }
/P248-LREQ-REL-KEPT/          { c["kept"]++ }
/P253-OWED-STUCK/             { c["p253"]++ }
/P254-OWED-TEARDOWN/          { c["p254"]++ }
/P255-CAW-OPS-UNBALANCED/     { c["p255"]++ }
/P257-RELEASEALL-/            { c["p257"]++ }
/P258-QUIESCE-/               { c["p258"]++ }
/P259-DEPART-UNCLEAN/         { c["p259"]++ }
/P260-CAW-CTX-LEAKED/         { c["p260"]++ }
/P261-ESCALATE-UNDELIVERED/   { c["p261"]++ }
/P262-TEARDOWN-JOIN-/         { c["p262"]++ }
/P266-RETIRE-REFUSED/         { c["p266"]++ }
/P269-FROZEN-TENURE-ATTEMPTS/ { c["p269"]++ }
/P270-MOOT-RETRACT-REFUSED/   { c["p270"]++ }
/P272-INJECT-WAIT-EXPIRE/     { c["p272"]++ }
/P263-OWED-TEARDOWN-RETIRE/   { c["p263"]++ }
/P267-RETIRE-SUM/             { c["p267"]++ }
/P271-OWED-DISCHARGE/         { c["p271"]++ }
/P268-RELEASEALL-IORETRY/     { c["p268"]++ }
/P245-RECONCILE-EXHAUST/      { c["p245"]++ }
/P109-CLR-RELEASE-ALL/        { c["p109"]++; if ($0 !~ /cas_rc=0( |$)/) c["p109nz"]++ }
/released heartbeat slot .* \(clean teardown\)/ { c["clean"]++ }
END {
  if (!seen) { print "NO-WINDOW"; exit }
  printf "agg=%d ent=%d kept=%d p253=%d p254=%d p255=%d p257=%d p258=%d p259=%d p260=%d p261=%d p262=%d p266=%d p269=%d p270=%d p272=%d p263=%d p267=%d p271=%d p268=%d p245=%d p109=%d p109nz=%d clean=%d\n",
    c["agg"],c["ent"],c["kept"],c["p253"],c["p254"],c["p255"],c["p257"],
    c["p258"],c["p259"],c["p260"],c["p261"],c["p262"],c["p266"],c["p269"],
    c["p270"],c["p272"],c["p263"],c["p267"],c["p271"],c["p268"],c["p245"],
    c["p109"],c["p109nz"],c["clean"]
}'\'''
OUT=$("$CEN" "$N" "$SNIP")
echo "$OUT"

# ── verdict ──────────────────────────────────────────────────────────────
# zero-required: agg ent kept p253 p254 p255 p257 p258 p259 p260 p261 p262
#                p266 p269 p270 p272; with residue=0, p263/p267/p271 must
#                also be 0 (any drain/retire activity without residue is
#                inconsistent).  INFO: p268 p245 p109 p109nz.
FAILS=0
for i in $(seq 1 "$N"); do
    line=$(echo "$OUT" | awk -v n="test$i " 'index($0, n) == 1 { sub(/^[^ ]+ /, ""); print; exit }')
    if [ -z "$line" ]; then
        echo "FAIL test$i: no census output (ssh timeout?)"; FAILS=$((FAILS+1)); continue
    fi
    if [ "$line" = "NO-WINDOW" ]; then
        echo "FAIL test$i: marker lost (power-cycled during prep?) — window unusable"
        FAILS=$((FAILS+1)); continue
    fi
    bad=""
    for kv in $line; do
        k=${kv%%=*}; v=${kv#*=}
        case "$k" in
        agg|ent|kept|p253|p254|p255|p257|p258|p259|p260|p261|p262|p266|p269|p270|p272|p263|p267|p271)
            [ "$v" -eq 0 ] || bad="$bad $kv" ;;
        clean)
            if [ "$EXPECT" -ge 0 ] && [ "$v" -ne "$EXPECT" ]; then
                bad="$bad clean=$v(want=$EXPECT)"
            fi ;;
        esac
    done
    if [ -n "$bad" ]; then
        echo "FAIL test$i:$bad"; FAILS=$((FAILS+1))
    fi
done
if [ "$FAILS" -ne 0 ]; then
    echo "=== p248_census FAIL: $FAILS/$N node(s) failed ==="
    exit 1
fi
echo "=== p248_census PASS: $N/$N nodes, teardown probes silent$([ "$EXPECT" -ge 0 ] && echo ", clean=$EXPECT per node") ==="
