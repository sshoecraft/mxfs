#!/bin/bash
# pve_knob_ab.sh — A/B a runtime module parameter on both hosts of a Proxmox
# pair, interleaved, around one measuring command: the parameter is set on
# both hosts, the command runs, and the next arm sets the other value, so the
# arms share the pair's state as closely as two runs can.  The parameter is
# restored to the value it had before the first arm when the script ends.
#
# Usage: tests/pve_knob_ab.sh <param> "<value> <value> ..." <command...>
#   e.g. tests/pve_knob_ab.sh dir_ex_bast_sweep "0 1 0 1" \
#            env PHASES="seed both" SEED_DIRS=4 tests/pve_ledger_commit_profile.sh
#   Each arm runs the command with ARM_LABEL=<param>-<value>-<n> in its
#   environment and as its last argument, so its evidence names the arm.
# Env:
#   PVE_PAIR   "<addr> <addr>" (default the physical pair)
#   ARM_BUDGET seconds each arm's command may take (default 600)
# Output: one line per arm (value, rc, wall) and the arm's own output in
# tests/evidence/pve_knob_ab/<stamp>/<label>.out.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
[ $# -ge 3 ] || { sed -n '2,20p' "$0" >&2; exit 2; }
PARAM=$1; VALUES=$2; shift 2
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
EVID="$REPO/tests/evidence/pve_knob_ab/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1
P=/sys/module/mxfs/parameters/$PARAM

on() { timeout 20 "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; }
setall() {  # <value>: set on both hosts, echo what each reads back
    local h
    for h in "${H[@]}"; do on "$h" "echo $1 > $P && cat $P" | tr '\n' ' ' | sed "s/^/$h=/"; done
}

orig=$(on "${H[0]}" "cat $P")
[[ "$orig" =~ ^-?[0-9]+$ ]] || { echo "cannot read $P on ${H[0]}: $orig" >&2; exit 2; }
echo "[$(date +%T)] $PARAM was $orig; evidence $EVID" | tee "$EVID/log"
n=0
for v in $VALUES; do
    n=$((n + 1))
    label="$PARAM-$v-$n"
    echo "[$(date +%T)] arm $n: $(setall "$v")" | tee -a "$EVID/log"
    t0=$(date +%s)
    ARM_LABEL=$label PVE_PAIR="${H[*]}" timeout "${ARM_BUDGET:-600}" "$@" "$label" > "$EVID/$label.out" 2>&1
    rc=$?
    echo "[$(date +%T)] arm $n $PARAM=$v rc=$rc wall=$(( $(date +%s) - t0 ))s" | tee -a "$EVID/log"
done
echo "[$(date +%T)] restored: $(setall "$orig")" | tee -a "$EVID/log"
