#!/bin/bash
# cluster_authority_census.sh — cluster-wide readout of the
# D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY detector.
# (ccloop c7ee71c6 sess29.)
#
# WHAT IT MEASURES
#   The physical write unit is the whole 16 KB inode CLUSTER; the coherency
#   protocol locks at INODE granularity.  So a node writing one slot it does own
#   republishes whatever its buffer holds for every neighbouring slot.
#
#   writes            cluster writes that carried at least one passenger slot
#   unlogged_written  DENOMINATOR — slots written carrying no committed change
#                     of ours this round.  NOT a defect on its own: those are
#                     ordinary preserved bytes and ~20 of 21 slots qualify on
#                     every write.  That is exactly why the naive predicate
#                     ("slots we lack EX for") measures nothing — sess27
#                     recorded this trap in the ledger; never report a numerator
#                     without this number beside it.
#   no_write_tenure   NUMERATOR — we hold the slot only in PR, i.e. no write
#                     authority for the very bytes we are publishing.
#   gen_mismatch      NUMERATOR — the buffer image's di_gen is a different
#                     incarnation from the one we hold in core: the bytes
#                     provably predate a reallocation.
#   no_incore         NUMERATOR — no in-core inode for the slot at all, so we
#                     cannot even consult a tenure.  P56's directory rationale
#                     says this is the worst case: the flushing node holds the
#                     cluster cached for a churned child while the slot's own
#                     inode is not in core, so the bytes are a stale
#                     prior-tenure image.
#
# The detector is detection-only; there is no knob and it changes no behaviour.
#
# USAGE
#   tests/cluster_authority_census.sh [nodes] [full]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:-32}"
MODE="${2:-brief}"
D=$(mktemp -d)

for ((i = 1; i <= N; i++)); do
    (
        timeout 30 tools/mxfs_sshpass.sh "test$i" \
            'echo 1 > /sys/module/mxfs/parameters/cluster_authority_dump 2>/dev/null
             sleep 1
             dmesg | grep "P218-CLUSTER-AUTHORITY-TOTAL" | tail -1' \
            2>/dev/null | grep P218 > "$D/test$i"
        if [ "$MODE" = full ]; then
            timeout 30 tools/mxfs_sshpass.sh "test$i" \
                'dmesg | grep "P218-CLUSTER-PASSENGER" | tail -3' \
                2>/dev/null | grep P218 > "$D/test$i.lines"
        fi
    ) >/dev/null 2>&1 &
done
wait

printf '%-8s %8s %10s %8s %8s %8s\n' \
    node writes unlogged no_tenure gen_mm no_incore
tw=0; tu=0; tp=0; tg=0; tn=0
for ((i = 1; i <= N; i++)); do
    l=$(cat "$D/test$i" 2>/dev/null)
    [ -n "$l" ] || continue
    w=$(echo "$l"  | grep -oE 'writes=[0-9]+'           | cut -d= -f2)
    u=$(echo "$l"  | grep -oE 'unlogged_written=[0-9]+' | cut -d= -f2)
    p=$(echo "$l"  | grep -oE 'no_write_tenure=[0-9]+'  | cut -d= -f2)
    g=$(echo "$l"  | grep -oE 'gen_mismatch=[0-9]+'     | cut -d= -f2)
    nc=$(echo "$l" | grep -oE 'no_incore=[0-9]+'        | cut -d= -f2)
    tw=$((tw + w)); tu=$((tu + u)); tp=$((tp + p)); tg=$((tg + g)); tn=$((tn + nc))
    [ "$w" = 0 ] && continue
    printf '%-8s %8s %10s %8s %8s %8s\n' "test$i" "$w" "$u" "$p" "$g" "$nc"
done
printf '%-8s %8d %10d %8d %8d %8d\n' TOTAL "$tw" "$tu" "$tp" "$tg" "$tn"

if [ "$MODE" = full ]; then
    echo
    echo "=== P218-CLUSTER-PASSENGER samples ==="
    cat "$D"/*.lines 2>/dev/null | sed 's/^.*mxfs: */  /' | head -12
fi

echo
echo "READ IT LIKE THIS:"
echo "  no_tenure/gen_mm/no_incore ALL 0 with unlogged_written > 0 = exposure"
echo "  present and the protocol held on this workload."
echo "  Any nonzero numerator = a cluster write published bytes this node had no"
echo "  authority for.  writes=0 everywhere means the workload never exercised a"
echo "  multi-slot cluster write -- the run proved NOTHING, use a shared-dir churn."
