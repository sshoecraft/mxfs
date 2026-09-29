#!/bin/bash
# quiesce_remount_chain.sh — the arms of tests/quiesce_remount_access.sh in
# one detached run, one line per lap in a summary:
#
#   control          the settled-owner retirement off, once (SETTLED_RETIRE=0)
#   tenant control   TENANT_CONTROL laps with the attribution from the
#                    heartbeat table off and the import injection armed
#                    (TENANT_ATTRIBUTE=0 INJECT_UNRESOLVABLE=INJECT_N): the
#                    import with no owner, made to happen
#   injected         INJECT_LAPS laps with the attribution on and the same
#                    injection armed
#   natural          LAPS laps with everything on and nothing injected
#
# Launched detached (nohup setsid) so it outlives the session that started
# it; it holds no rig lock of its own, so check the summary's last line for
# CHAIN-END before starting anything else on the rig.
#
# budget: control 880 + 120 s worst case, each lap 880 s worst case and about
# 100 s healthy.
# Usage: tests/quiesce_remount_chain.sh <tag> [laps] [control] [tenant_control] [inject_laps]
#        (default 3 laps, the control arm, no tenant control, no injected laps)
# Env:   INJECT_N (default 100000) the injection's count, per node;
#        UNHELD_ANSWER (default 1) is passed through to every lap
set -u
TAG=${1:?tag}
LAPS=${2:-3}
CONTROL=${3:-1}
TENANT_CONTROL=${4:-0}
INJECT_LAPS=${5:-0}
INJECT_N=${INJECT_N:-100000}
cd "$(dirname "$0")/.." || exit 2
E=tests/evidence/quiesce_remount_access
mkdir -p "$E"
SUM=$E/chain_$TAG.summary
echo "CHAIN-BEGIN tag=$TAG laps=$LAPS control=$CONTROL tenant_control=$TENANT_CONTROL inject_laps=$INJECT_LAPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ)" > "$SUM"
lap() { # <label> <settled_retire> [tenant_attribute] [inject]
    local label=$1 sr=$2 ta=${3:-1} inj=${4:-0} t0 rc
    t0=$(date +%s)
    SETTLED_RETIRE=$sr TENANT_ATTRIBUTE=$ta INJECT_UNRESOLVABLE=$inj \
        tests/quiesce_remount_access.sh "$label" > "$E/$label.out" 2>&1 < /dev/null
    rc=$?
    echo "LAP label=$label settled_retire=$sr tenant_attribute=$ta inject=$inj rc=$rc wall=$(( $(date +%s) - t0 ))s pass=$(grep -ac '^  PASS' "$E/$label.out") fail=$(grep -ac '^  FAIL' "$E/$label.out") :: $(grep -a -E '^CONTROL |^TENANT |^WALK |^=== quiesce_remount_access .*fails=|^ABORT|^INFRA' "$E/$label.out" | tail -4 | tr '\n' ' ' | cut -c1-520) :: failed: $(grep -a '^  FAIL' "$E/$label.out" | cut -c8-90 | tr '\n' ';' | cut -c1-300)" >> "$SUM"
}
[ "$CONTROL" = 0 ] || lap "${TAG}_control" 0
for i in $(seq 1 "$TENANT_CONTROL"); do
    lap "${TAG}_tctl$i" 1 0 "$INJECT_N"
done
for i in $(seq 1 "$INJECT_LAPS"); do
    lap "${TAG}_inj$i" 1 1 "$INJECT_N"
done
for i in $(seq 1 "$LAPS"); do
    lap "${TAG}_lap$i" 1
done
echo "CHAIN-END tag=$TAG $(date -u +%FT%TZ)" >> "$SUM"
