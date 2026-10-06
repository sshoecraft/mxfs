#!/bin/bash
# tests/wait_reg_lost.sh — a disk/caw lock wait that loses its registration:
# does it register again, and does the build without that still hang?
#
# A peer can hand a grant straight to a waiting node; when that node's own
# release clears the holder bit it was just given, the wait is left neither a
# waiter nor a holder (measured, 4/disk/caw/mpath path_fabric: 115 s; the
# wait's ceiling is 480 s).  The natural race is rare, so this puts a wait in
# that state on purpose (module parameter caw_inject_wait_reg_lost: the wait
# clears its own waiter bit) and runs two arms on one build and one mount:
#
#   control  caw_wait_reg_requeue=0: the wait keeps polling, as before the
#            fix.  Must HANG: some node completes no operation for 30 s.
#            A control that does not hang means the injection does not reach
#            the defect, and the other arm then proves nothing.
#   fix      caw_wait_reg_requeue=1 (the default): must NOT hang (no 20 s
#            without a completion on any node), with zero failed operations,
#            and the kernel log must show waits that registered again.
#
# Usage (cluster formed and mounted on a disk/caw configuration):
#   MXFS_NODE_LIST=test15,test16 MXFS_CONFIG=2/disk/caw/mpath tests/wait_reg_lost.sh [inject_n]
# Exit 0 PASS, 1 FAIL, 3 VACUOUS (the control did not hang).
#
# derived time budget: control 90 s load + 30 s to see the hang + 40 s watch
# + ~60 s stop and copy; fix 90 s load + ~60 s stop and copy: about 400 s.
set -u
cd "$(dirname "$0")/.." || exit 2
NODES=${MXFS_NODE_LIST:?MXFS_NODE_LIST}
N_INJ=${1:-6}
P=/sys/module/mxfs/parameters
knobs() {  # <requeue> <inject>
    local n
    for n in ${NODES//,/ }; do
        timeout 20 tools/mxfs_sshpass.sh "$n" "echo $1 > $P/caw_wait_reg_requeue; echo $2 > $P/caw_inject_wait_reg_lost" >/dev/null 2>&1 \
            || { echo "ABORT: could not set the parameters on $n"; exit 2; }
    done
}
arm() {  # <name> <requeue> <hang_s> <resolve_s> -> prints the watcher's output
    knobs "$2" "$N_INJ"
    tests/pathload_hang_watch.sh 90 "$3" "$4" 2>&1
    knobs 1 0
}
count() {  # <evidence dir> <pattern> -> matching kernel-log lines over every node
    local f t=0 c
    for f in "$1"/kmsg_*.txt.gz; do c=$(zcat "$f" 2>/dev/null | grep -ac "$2"); t=$((t + ${c:-0})); done
    echo "$t"
}
fails=0
echo "=== wait_reg_lost nodes=$NODES inject=$N_INJ per node $(date -u +%FT%TZ) ==="
out=$(arm control 0 30 40); echo "$out" | sed 's/^/  control| /'
cdir=$(echo "$out" | sed -n 's/.*evidence=\([^ ]*\).*/\1/p' | tail -1)
chang=$(echo "$out" | sed -n 's/^RESULT: hangs=\([0-9]*\).*/\1/p')
cinj=$(count "$cdir" 'P-WAIT-REG-LOST-INJECT')
echo "  INFO control: hangs=${chang:-?} injected=$cinj registered_again=$(count "$cdir" 'P-WAIT-REG-LOST type')"
# let whatever the control left waiting finish under the default before the next arm
sleep 20
out=$(arm fix 1 20 40); echo "$out" | sed 's/^/  fix    | /'
fdir=$(echo "$out" | sed -n 's/.*evidence=\([^ ]*\).*/\1/p' | tail -1)
fhang=$(echo "$out" | sed -n 's/^RESULT: hangs=\([0-9]*\).*/\1/p')
finj=$(count "$fdir" 'P-WAIT-REG-LOST-INJECT')
fre=$(count "$fdir" 'P-WAIT-REG-LOST type')
ferr=$(echo "$out" | grep -a 'PATHLOAD' | grep -avc ' err=0 ')
echo "  INFO fix: hangs=${fhang:-?} injected=$finj registered_again=$fre nodes_with_errors=$ferr"
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails + 1)); fi; }
ck "fix: no node went 20 s without completing an operation" "${fhang:-?}" 0
ck "fix: waits were put in the state (injected >= 1)" "$([ "$finj" -ge 1 ] && echo yes || echo no)" yes
ck "fix: waits registered again (>= 1)" "$([ "$fre" -ge 1 ] && echo yes || echo no)" yes
ck "fix: no operation failed on any node" "$ferr" 0
if [ "${chang:-0}" = 0 ] || [ "$cinj" = 0 ]; then
    echo "RESULT: VACUOUS control_hangs=${chang:-?} control_injected=$cinj — the control arm did not hang, so the injection does not reach the defect (fix arm fails=$fails) evidence=$cdir,$fdir"
    exit 3
fi
[ "$fails" = 0 ] && { echo "RESULT: PASS control_hangs=$chang control_injected=$cinj fix_injected=$finj fix_registered_again=$fre evidence=$cdir,$fdir"; exit 0; }
echo "RESULT: FAIL fails=$fails evidence=$cdir,$fdir"; exit 1
