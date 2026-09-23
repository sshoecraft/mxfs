#!/bin/bash
# refused_mount_workers.sh — a mount that is REFUSED after its bootstrap fenced
# a victim must join the workers that fence started before it frees its DLM
# context (D-A-REFUSED-MOUNT-FREES-THE-DLM-CONTEXT-UNDER-ITS-FENCE-RETRY-WORKER).
#
# THE SHAPE, as s151a produced it by accident (0.89.69 7A0C5DF3088079E22768EB3,
# 2/tcp, tests/evidence/netconsole.log): the prover P unmounts cleanly,
# rman_inject=1 is armed on its still-loaded module, the victim V is destroyed,
# and P mounts again alone.  A lone mount is a whole-cluster bootstrap: two
# 62 s survivor scans, then the fence of V, which arms the fence-retry series
# and thereby creates the PR worker (v5_fence_retry_arm -> v5_pr_worker_start);
# the victim's manifest snapshot then fails (the injector), the bootstrap
# refuses (P-BOOT-FENCE-UNPROVEN -> P-BOOT-MOUNT-REFUSED) and the mount unwinds
# to mxfs_pal_free(ctx).  On 0.89.69 the worker, asleep in its 250 ms tick,
# then read ctx->fence_retry_stop from the freed context: BUG: unable to handle
# page fault, Oops #1 in v5_fence_retry_worker_fn+0x8f, Kernel panic, reboot.
#
# PREDICTION on 0.89.70 (v5_refused_mount_stop_workers, called from the TCP
# unwind and from err_disklock): the mount returns a nonzero rc BY ITSELF inside
# the bound, P stays up, its window carries P-BOOT-MOUNT-REFUSED and
# P-MOUNT-REFUSED-WORKERS-STOPPED with bit 2 (fence-retry) set, no BUG/Oops,
# and afterwards no mxfs-worker thread exists on P and auth_withdraw_threads
# reads 0.  On the old build the same lap reads the prover GONE (no ssh, or an
# uptime shorter than the lap) and FAILs on that.
#
# CONTROL, in the same lap before the subject: the ordinary mount prep made
# started the PR worker (P304-PR-WORKER started >= 1 since boot) and
# auth_withdraw_threads reads 1 on both nodes — the success path is unchanged.
#
# BUDGET: boot-wait + prep (60-185 s measured) + identities and the clean
# unmount (~30 s) + the refused mount (two 62 s scans + fence + snapshot:
# ~170 s measured s151a; bound MOUNT_MAX 240 s) + the post-checks (~20 s)
# = ~480 s worst case.  Caller bound 700 s.  A mount still running at
# MOUNT_MAX is SIGKILLed and graded FAIL: the refusal is supposed to be
# bounded by the bootstrap's own scans.
#
# Cleanup on every exit: rman_inject cleared on P when it still answers, V
# started; the caller must prep_cluster before the next lap.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
N1=${MXFS_NODE_LIST%%,*}
N2=${MXFS_NODE_LIST##*,}
P=${PROVER:-$N2}                 # the node that unmounts and mounts again alone
V=$N1; [ "$P" = "$N1" ] && V=$N2 # the node destroyed before the remount
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MOUNT_MAX=${MOUNT_MAX:-240}
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_rmw_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="RMW-MARK-$LABEL"
echo "=== refused_mount_workers label=$LABEL prover=$P victim=$V mount_max=${MOUNT_MAX}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

CLEANED=0
cleanup() {
    [ "$CLEANED" = 1 ] && return 0
    CLEANED=1
    rs 20 "$P" "echo 0 > $PARM/rman_inject 2>/dev/null; cat $PARM/rman_inject 2>/dev/null" > "$OUT/P_inject_clear.txt" 2>/dev/null
    $VIRSH start "$V" >/dev/null 2>&1
    echo "STAGE cleanup: rman_inject on $P now '$(tail -1 "$OUT/P_inject_clear.txt" 2>/dev/null)', $V started; the caller must prep_cluster before the next lap at +$(el)s"
}
trap cleanup EXIT

# ---- 0. the fleet on the tree build
if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
waitboot "$N1" "$N2"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$N1" "$N2"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$N1"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. identities, and the CONTROL: the ordinary mount's workers
for n in "$N1" "$N2"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "SLOT1=\$slot_$N1; SLOT2=\$slot_$N2"
[ -n "$SLOT1" ] && [ -n "$SLOT2" ] && [ "$SLOT1" != "$SLOT2" ] || {
    echo "ABORT: could not read two distinct slots ($N1 '$SLOT1', $N2 '$SLOT2')"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }
eval "VSLOT=\$slot_$V"
echo "STAGE identities: $N1 slot $SLOT1, $N2 slot $SLOT2; victim $V slot $VSLOT at +$(el)s"
for n in "$N1" "$N2"; do
    measure "$n" 30 "$OUT/${n}_control.txt" '^CTL_END$' "the worker control on $n" \
        "echo WITHDRAW_THREADS=\$(cat $PARM/auth_withdraw_threads 2>/dev/null); echo PR_WORKER_STARTED=\$(dmesg | grep -ac 'P304-PR-WORKER started'); echo MXFS_WORKERS=\$(ps -o pid= -C mxfs-worker 2>/dev/null | wc -l); echo CTL_END"
    wt=$(grep -ao 'WITHDRAW_THREADS=[0-9]*' "$OUT/${n}_control.txt" | head -1 | cut -d= -f2)
    ps_started=$(grep -ao 'PR_WORKER_STARTED=[0-9]*' "$OUT/${n}_control.txt" | head -1 | cut -d= -f2)
    ck "CONTROL: the ordinary mount on $n runs one withdraw thread (auth_withdraw_threads)" "${wt:-none}" 1
    ckge "CONTROL: the ordinary mount on $n started the PR worker (P304-PR-WORKER started since boot)" "${ps_started:-0}" 1
done

# ---- 2. the setup: P departs cleanly, the injector is armed on its loaded
#         module, V is destroyed.  Nothing here is the subject.
rs 15 "$P" "echo $MARK > /dev/kmsg" >/dev/null 2>&1
rs 120 "$P" "timeout -s KILL 90 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/P_umount.txt" 2>/dev/null
URC=$(grep -ao 'UMOUNT_RC=[0-9]*' "$OUT/P_umount.txt" | head -1 | cut -d= -f2)
[ "${URC:-none}" = 0 ] || {
    echo "ABORT: the prover's clean unmount returned rc='${URC:-none}'; there is no clean departure to mount again after"
    echo "RESULT: ABORT label=$LABEL stage=setup-umount evidence=$OUT"; exit 2; }
value_now_into inj "$P" 20 "$OUT/P_inject_set.txt" '^1$' "the rman_inject knob after arming on the unmounted $P" "echo 1 > $PARM/rman_inject; cat $PARM/rman_inject"
echo "STAGE $P departed cleanly (rc=0) and rman_inject=$inj is armed on its loaded module at +$(el)s"
$VIRSH destroy "$V" >/dev/null 2>&1 || {
    echo "ABORT: virsh destroy $V failed"
    echo "RESULT: ABORT label=$LABEL stage=destroy evidence=$OUT"; exit 2; }
echo "STAGE destroyed $V at +$(el)s"

# ---- 3. THE SUBJECT: the lone remount, bounded, its task sampled, its rc read
value_now_into pup0 "$P" 20 "$OUT/P_uptime0.txt" '^[0-9]+' "the prover's uptime before the mount" "cut -d. -f1 /proc/uptime"
rs 15 "$P" "echo $MARK-REMOUNT > /dev/kmsg" >/dev/null 2>&1
echo "STAGE mounting $P again alone with $V dead and its recovery parked by the injector (bound ${MOUNT_MAX}s) at +$(el)s"
rs $((MOUNT_MAX + 40)) "$P" "rm -f /run/rmw_mount.txt
setsid sh -c 'timeout -s KILL $MOUNT_MAX mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?' > /run/rmw_mount.txt 2>&1 < /dev/null &
prev=0
for t in 60 130 200; do
    sleep \$(( t - prev )); prev=\$t
    grep -q MOUNT_RC= /run/rmw_mount.txt 2>/dev/null && { echo SAMPLE t=\$t mount-returned; break; }
    pid=\$(ps -o pid= -C mount 2>/dev/null | head -1 | tr -d ' ')
    echo SAMPLE t=\$t MOUNT_PID=\${pid:-none} wchan=\$(cat /proc/\${pid:-0}/wchan 2>/dev/null)
    [ -n \"\$pid\" ] && { echo STACK_BEGIN t=\$t; cat /proc/\$pid/stack 2>/dev/null; echo STACK_END; }
done
echo PROBE_END" > "$OUT/P_mount_probe.txt" 2>/dev/null
grep -a '^SAMPLE' "$OUT/P_mount_probe.txt" | cut -c1-160 | sed 's/^/  /'
for t in 60 130 200; do
    st=$(sed -n "/^STACK_BEGIN t=$t/,/^STACK_END/p" "$OUT/P_mount_probe.txt" | grep -a 'mxfs\|dlm\|xfs\|mount\|schedule' | sed 's/^\[<[0-9a-fx]*>\] //' | head -6 | tr '\n' ' ' | cut -c1-300)
    [ -n "$st" ] && echo "  mount task stack at ${t}s: $st"
done
# the rc, with the prover's liveness read first: a prover that panicked
# answers nothing, and that absence is the old build's verdict, not an abort
rs $((MOUNT_MAX + 60)) "$P" "for i in \$(seq 1 $((MOUNT_MAX + 30))); do grep -q MOUNT_RC= /run/rmw_mount.txt 2>/dev/null && break; sleep 1; done; cat /run/rmw_mount.txt 2>/dev/null; echo UPTIME_NOW=\$(cut -d. -f1 /proc/uptime); echo READ_END" > "$OUT/P_mount_rc.txt" 2>/dev/null
if ! grep -qa '^READ_END$' "$OUT/P_mount_rc.txt"; then
    sleep 20
    rs 30 "$P" "echo UPTIME_NOW=\$(cut -d. -f1 /proc/uptime); echo READ_END" > "$OUT/P_alive.txt" 2>/dev/null
    up1=$(grep -ao 'UPTIME_NOW=[0-9]*' "$OUT/P_alive.txt" | head -1 | cut -d= -f2)
    echo "  FAIL the prover stopped answering during its refused mount (uptime before ${pup0}s, now '${up1:-no answer}'): a prover that panicked and rebooted, as s151a's did — a node crashed"
    fails=$((fails+1))
    echo "=== refused_mount_workers $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
    echo "RESULT: FAIL label=$LABEL fails=$fails prover=gone evidence=$OUT"; exit 1
fi
MRC=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/P_mount_rc.txt" | head -1 | cut -d= -f2)
up1=$(grep -ao 'UPTIME_NOW=[0-9]*' "$OUT/P_mount_rc.txt" | head -1 | cut -d= -f2)
echo "STAGE mount on $P returned rc='${MRC:-none}' at +$(el)s (uptime ${pup0}s -> ${up1:-?}s)  [$(grep -av '^READ_END$\|^UPTIME_NOW' "$OUT/P_mount_rc.txt" | tr '\n' ' ' | cut -c1-160)]"
if [ "${up1:-0}" -lt "${pup0:-0}" ] 2>/dev/null; then
    echo "  FAIL the prover's uptime went backwards across the mount (${pup0}s -> ${up1}s): it rebooted — a node crashed"
    fails=$((fails+1))
fi

# ---- 4. the window on P from the remount mark
window_into "$OUT/P_window.txt" "$P" 60 "$MARK-REMOUNT"
count_file_into refused "$OUT/P_window.txt" 'P-BOOT-MOUNT-REFUSED'
count_file_into unproven "$OUT/P_window.txt" 'P-BOOT-FENCE-UNPROVEN'
count_file_into injn    "$OUT/P_window.txt" 'P-RMAN-INJECT'
count_file_into wstop   "$OUT/P_window.txt" 'P-MOUNT-REFUSED-WORKERS-STOPPED'
count_file_into oops    "$OUT/P_window.txt" 'BUG:\|Oops\|kernel NULL pointer\|Kernel panic'
wmask=$(grep -ao 'P-MOUNT-REFUSED-WORKERS-STOPPED node=[0-9]* mask=0x[0-9a-f]*' "$OUT/P_window.txt" | tail -1 | sed -n 's/.*mask=0x//p')
echo "STAGE remount window on $P: mount-refused=$refused fence-unproven=$unproven injected-snapshot-failures=$injn workers-stopped=$wstop (mask '${wmask:-none}') oops=$oops"
grep -a 'P-BOOT-\|P-RMAN-INJECT\|P-MOUNT-REFUSED-WORKERS-STOPPED\|P304-PR-WORKER\|BUG:\|Oops' "$OUT/P_window.txt" | tail -8 | cut -c1-220 | sed 's/^/    /'
ck   "no BUG/Oops/panic on the prover across the refused mount" "$oops" 0
if [ "${MRC:-none}" = 137 ]; then
    echo "  FAIL the mount was STILL RUNNING at the ${MOUNT_MAX}s bound and only a SIGKILL ended it — the bootstrap's refusal is not bounded by its own scans on this build; the sampled stacks say where it sat"
    fails=$((fails+1))
elif [ -z "${MRC:-}" ]; then
    echo "  FAIL the mount produced no rc although the prover still answers — read $OUT/P_mount_rc.txt"
    fails=$((fails+1))
elif [ "$MRC" = 0 ]; then
    echo "  FAIL the mount SUCCEEDED (rc=0) with the victim's snapshot parked: the arm produced no refusal, so nothing here measured the refused-mount unwind"
    fails=$((fails+1))
    rs 100 "$P" "timeout -s KILL 90 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/P_umount2.txt" 2>/dev/null
else
    echo "  PASS the mount returned by itself (rc=$MRC) inside the bound"
fi
ckge "the bootstrap refused the mount by name (P-BOOT-MOUNT-REFUSED)" "$refused" 1
ckge "the refusal was the victim's parked snapshot (P-BOOT-FENCE-UNPROVEN, with P-RMAN-INJECT $injn)" "$unproven" 1
ckge "the refused mount joined the workers it had started (P-MOUNT-REFUSED-WORKERS-STOPPED)" "$wstop" 1
if [ -n "${wmask:-}" ]; then
    if [ $(( 0x$wmask & 2 )) -ne 0 ]; then
        echo "  PASS the fence-retry worker was among them (mask 0x$wmask has bit 2)"
    else
        echo "  FAIL the workers-stopped line does not name the fence-retry worker (mask 0x$wmask lacks bit 2), which is the one that read the freed context on 0.89.69"
        fails=$((fails+1))
    fi
fi

# ---- 5. after the refusal: nothing of the refused context may still run
sleep 3
measure "$P" 30 "$OUT/P_after.txt" '^AFTER_END$' "the worker state on $P after the refusal" \
    "echo MXFS_WORKERS=\$(ps -o pid= -C mxfs-worker 2>/dev/null | wc -l); echo WITHDRAW_THREADS=\$(cat $PARM/auth_withdraw_threads 2>/dev/null); echo MOUNTED=\$(grep -c ' $MNT ' /proc/mounts); echo AFTER_END"
mw=$(grep -ao 'MXFS_WORKERS=[0-9]*' "$OUT/P_after.txt" | head -1 | cut -d= -f2)
wt=$(grep -ao 'WITHDRAW_THREADS=-\?[0-9]*' "$OUT/P_after.txt" | head -1 | cut -d= -f2)
mt=$(grep -ao 'MOUNTED=[0-9]*' "$OUT/P_after.txt" | head -1 | cut -d= -f2)
ck "no mxfs-worker thread survives the refused mount on $P" "${mw:-none}" 0
ck "auth_withdraw_threads reads 0 on $P after the refusal" "${wt:-none}" 0
ck "$P has no $MNT mount after the refusal" "${mt:-none}" 0

echo "=== refused_mount_workers $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ $fails -eq 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 mrc=$MRC refused=$refused workers_stopped=$wstop mask=0x${wmask:-0} evidence=$OUT"
    exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails mrc=${MRC:-none} refused=$refused workers_stopped=$wstop mask=0x${wmask:-0} evidence=$OUT"
exit 1
