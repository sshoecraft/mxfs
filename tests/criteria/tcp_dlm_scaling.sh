#!/bin/bash
# tcp_dlm_scaling.sh — ship criterion: TCP DLM transport scaling sweep.
#
# MXFS supports two DLM transports: CAW (disk-based, default, used by every
# other criterion on the SCST shared LUN) and TCP (force_transport=1).  The
# rest of the gate exercises CAW; this criterion exercises the TCP DLM path
# under the SEPARATE-INITIATOR topology that TCP is meant for — each VM is
# its own iSCSI initiator direct to the QNAP LUN (/dev/sdb), so there is no
# shared SCST loopback nexus.  We sweep the workload-A mkdir storm at
# 1 -> 2 -> 4 -> 8 -> 16 nodes and find the wall: the criterion PASSes only
# if, at EVERY scale, all nodes mount, zero dirents are silently lost, and
# no node's filesystem shuts down.
#
# This is a thin wrapper over scripts/qnap_scale.sh (single source of truth
# for the sweep) that translates its per-N RESULT lines into the one
# standard ship-criterion RESULT line + .criteria_results.json entry.
#
#   RESULT: PASS criterion=tcp_dlm_scaling measured=... threshold=...
#
# Usage: tcp_dlm_scaling.sh [--dpn N] [--steps "1 2 4 8 16"] [--nodes N]
#   --nodes N  : cap the sweep at the first N nodes (e.g. --nodes 4 -> "1 2 4")
#   --dpn N    : dirs per node per step (default 100)
#   --steps S  : explicit space-separated step list (overrides --nodes)

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init tcp_dlm_scaling

DPN=100
STEPS=""
MAXN=16
while [ $# -gt 0 ]; do
    case "$1" in
        --dpn)   DPN="$2"; shift 2 ;;
        --steps) STEPS="$2"; shift 2 ;;
        --nodes) MAXN="$2"; shift 2 ;;
        --module) MXFS_MODULE="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# Derive the step list from --nodes if --steps wasn't given: powers of two
# up to MAXN, with MAXN itself always included.
if [ -z "$STEPS" ]; then
    s=""; k=1
    while [ "$k" -lt "$MAXN" ]; do s="$s $k"; k=$((k*2)); done
    s="$s $MAXN"
    STEPS="$(echo "$s" | xargs)"
fi

# Wall-clock guard.  This is an INFRA-bounded sweep, not a per-op perf
# assertion (that is what silent/shutdown below assert).  Budget per step:
# 16-node teardown+verify-clean (~60s) + form mkfs/mount (~30s) + parallel
# joiners (~30s) + 200s storm cap + drop_caches verify (~30s) ~= 350s.
# 5 steps -> ~30 min; guard at 40 min so a genuinely wedged step trips it.
nsteps=$(echo "$STEPS" | wc -w)
set_script_timeout $(( nsteps * 480 + 120 ))

SWEEP="$MXFS_REPO/scripts/qnap_scale.sh"
[ -x "$SWEEP" ] || result_fail "no-sweep-script" "qnap_scale.sh present+executable" "missing $SWEEP"

echo "=== tcp_dlm_scaling: dpn=$DPN steps='$STEPS' (TCP DLM, separate-initiator QNAP /dev/sdb) ==="
out=$(bash "$SWEEP" "$DPN" $STEPS 2>&1)
echo "$out"

# Parse qnap_scale.sh per-step lines, e.g.:
#   N=4 RESULT: PASS mounted=4/4 expected=400 found=400 silent=0 conn_errs=12 shutdown_nodes=0
# Build a compact measured= summary and decide PASS/FAIL.
measured=""
worst="PASS"
worst_reason=""
for N in $STEPS; do
    line=$(echo "$out" | grep -E "(^|[[:space:]])N=$N RESULT:" | tail -1)
    if [ -z "$line" ]; then
        worst="FAIL"; worst_reason="N=$N produced no RESULT (form/teardown wedge)"
        measured="${measured}${measured:+ }N=$N:NORESULT"
        continue
    fi
    verdict=$(echo "$line" | sed -n 's/.*RESULT: \([A-Z-]*\).*/\1/p')
    mounted=$(echo "$line" | sed -n 's/.*mounted=\([0-9]*\/[0-9]*\).*/\1/p')
    silent=$(echo "$line"  | sed -n 's/.*silent=\([0-9]*\).*/\1/p')
    sd=$(echo "$line"      | sed -n 's/.*shutdown_nodes=\([0-9]*\).*/\1/p')
    ce=$(echo "$line"      | sed -n 's/.*conn_errs=\([0-9]*\).*/\1/p')
    measured="${measured}${measured:+ }N=$N:${mounted},silent=${silent:-?},sd=${sd:-?},ce=${ce:-?}"
    if [ "$verdict" != "PASS" ]; then
        worst="FAIL"
        [ -z "$worst_reason" ] && worst_reason="N=$N $verdict (mounted=$mounted silent=$silent shutdown=$sd)"
    fi
done

THRESHOLD="every N in {$STEPS}: mounted=N/N silent=0 shutdown_nodes=0"
if [ "$worst" = "PASS" ]; then
    result_pass "$measured" "$THRESHOLD"
else
    result_fail "$measured" "$THRESHOLD" "$worst_reason"
fi
