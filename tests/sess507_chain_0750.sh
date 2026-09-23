#!/bin/bash
# sess507_chain_0750.sh — the 0.75.0 verification chain on the 2-node TCP rig
# (QNAP TS-453 Pro LUN, test1/test2).  Runs the steps that must follow one
# another on the rig, each with its own derived bound, and stops at the first
# infrastructure failure.  Builds NOTHING: the tree's mxfs.ko must already be
# the build under test (every prep copies it).
#
#   1  prep 2/tcp                                   300 s (measured 47-91 s)
#   2  tests/transport_conformance.sh               240 s (nine mount cycles)
#   3  prep 2/tcp (step 2 leaves both unmounted)    300 s
#   4  tests/d513_write_eio_containment.sh verify   230 s (+ victim restart 120 s)
#   5  tests/tcp_2node_death_chain.sh BLOCK_INJECT  555+160 s (prep + 400 s oracle)
#   6  tests/domain_admission_matrix.sh on test2    240 s (test1 stays up)
#   7  yardstick: both leave; raw ceiling N=1,2     RAWCEIL: 2 N x 3 samples x ~45 s = 270 s + 60
#   8  native-XFS baseline: run.sh 1 xfs fio_perf   prep ~30 s + fio_perf 120 s = 150 s + 30
#   9  prep 2/tcp + fio_perf + fio_perf_vs_xfs      300 + 120 + 10 + 24 = 454 s
#  10  full 2/tcp board                             sum(elapsed) 553 s + 12 s x 28 + 15 s = 904 -> 1000 s
#  11  umount-while-blocked arm (needs a prep first: run as "1,11"):
#      tests/tcp_2node_death_chain.sh BLOCK_INJECT+BLOCK_UMOUNT   300 s oracle
#      + the survivor's recovery (destroy if the umount hung) + both restarts.
#      Not in the default step list: it leaves the rig unmounted and, on the
#      defect, leaves W to be destroyed; the next prep re-forms the cluster.
#
# Usage: tests/sess507_chain_0750.sh <label> [steps=1,2,3,4,5,6,7,8,9,10]
# Env:   MXFS_DEV (default: the QNAP LUN by-path), MXFS_NODE_LIST (test1,test2)
set -u
LABEL=${1:?label}
STEPS=${2:-1,2,3,4,5,6,7,8,9,10}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
# The per-rig yardsticks steps 7 and 8 CAPTURE must be named for the rig this
# chain is actually running on.  They were named by a literal rig tag written
# into the script, which is correct only for as long as nobody runs it
# anywhere else -- and the failure is silent and destructive in the wrong
# direction: a run on another rig OVERWRITES this one's baseline and ceiling
# with that rig's numbers, corrupting the very files the rig tag exists to
# keep apart, after which every later comparison here is scored against
# foreign hardware.  Derive it, and if the rig cannot be established,
# capture nothing rather than write somebody else's file.
RIGTAG=$(MXFS_DEV="$MXFS_DEV" tools/mxfs_rig_tag.sh "$MXFS_DEV" 2>/dev/null || true)
YSUF="tcp${RIGTAG:+.$RIGTAG}"
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
LOG=tests/evidence/sess507_chain_0750_${LABEL}.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
want() { case ",$STEPS," in *",$1,"*) return 0;; *) return 1;; esac; }
stage() { say "STAGE $1 rc=$2 wall=$3s $(date -u +%T)"; }
fails=0
say "=== sess507_chain_0750 label=$LABEL steps=$STEPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') dev=$MXFS_DEV $(date -u +%FT%TZ) ==="

prep() {   # <bound>
    local s=$(date +%s) n want got i
    # s515h/s515i: a prep launched within a minute of a rebuild failed on
    # 'mxfs.ko content never matched expected md5 ... (NFS staleness)' —
    # the node's NFS attribute cache still served the previous image.
    # Settle each node's view of the module first (cache drop + re-read,
    # bounded 60 s) so the prep's own bounded retries start from truth.
    want=$(md5sum mxfs.ko | cut -c1-32)
    for n in ${MXFS_NODE_LIST//,/ }; do
        for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
            got=$(timeout 25 $SSH "$n" "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; md5sum /src/mxfs/mxfs.ko 2>/dev/null | cut -c1-32" 2>/dev/null | tail -1)
            [ "$got" = "$want" ] && break
            sleep 5
        done
        [ "$got" = "$want" ] || say "WARN: $n still sees a stale mxfs.ko after 60 s (got ${got:-none} want $want)"
    done
    MXFS_FORCE_PREP=1 timeout "$1" ./run.sh 2 tcp prep_cluster >> "$LOG" 2>&1
    local rc=$?; stage "prep" $rc $(( $(date +%s) - s )); return $rc
}
restart_node() {  # <node>: virsh start (if off) + wait ssh + restore /src
    local n=$1 i
    $VIRSH domstate "$n" 2>/dev/null | grep -q running || $VIRSH start "$n" >/dev/null 2>&1
    for i in $(seq 1 24); do
        timeout 8 $SSH "$n" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP && break
        sleep 5
    done
    timeout 20 $SSH "$n" "mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; echo /src_ok=\$?" 2>/dev/null | grep -a src_ok | tee -a "$LOG"
}

if want 1; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi

if want 2; then
    s=$(date +%s); timeout 240 tests/transport_conformance.sh "$LABEL" test1 test2 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^===|^INFRA'
    rc=${PIPESTATUS[0]}; stage "transport_conformance" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
fi

if want 3; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi

if want 4; then
    # The d513 harness's verify arm was vacuous here (s508c): its "files
    # visible from the survivor" check drains the victim's dirty metadata
    # home before the kill, so the replay writes nothing and the verifier
    # injection cannot fire.  The death-replay lap applies buffer overrides
    # on every lap (6/6 on 0.74.1), so the verifier arm lives there.
    s=$(date +%s); TDR_VERIFY_INJECT=1 TDR_LAP_BOUND=240 timeout 560 tests/tcp_2node_death_chain.sh "${LABEL}_vfy" 1 2>&1 | tee -a "$LOG" | grep -aE '^STAGE|^DONE|^  FAIL|INFO (verify-inject|replay verdict|refusal|survivor probe|quarantine)'
    rc=${PIPESTATUS[0]}; stage "verify_inject_lap" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    restart_node test2
fi

if want 5; then
    s=$(date +%s); TDR_BLOCK_INJECT=1 TDR_LAP_BOUND=400 timeout 720 tests/tcp_2node_death_chain.sh "${LABEL}_blk" 1 2>&1 | tee -a "$LOG" | grep -aE '^STAGE|^DONE|^  FAIL|INFO (blocked|replay verdict|fail-fast|LSN)'
    rc=${PIPESTATUS[0]}; stage "block_inject_lap" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    restart_node test2
fi

if want 6; then
    s=$(date +%s); timeout 240 tests/domain_admission_matrix.sh "${LABEL}_R8" test2 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^  PASS|^==='
    rc=${PIPESTATUS[0]}; stage "domain_admission_matrix" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
fi

if want 7; then
    s=$(date +%s)
    for n in test1 test2; do
        timeout 60 $SSH "$n" "mountpoint -q /mnt/shared && timeout 40 umount /mnt/shared; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; mountpoint -q /mnt/shared && echo $n STILL_MOUNTED || echo $n unmounted" 2>/dev/null | grep -a 'mounted\|MOUNTED' | tee -a "$LOG"
    done
    if grep -q STILL_MOUNTED "$LOG"; then say "ABORT: a node still has /mnt/shared mounted; the raw ceiling is destructive"; exit 1; fi
    if [ -z "$RIGTAG" ]; then
        say "SKIP step 7: the rig could not be established, so a captured ceiling would be written under a name that claims hardware it may not describe"
    else
    RAWCEIL_FORCE=1 RAWCEIL_DEV="$MXFS_DEV" timeout 330 scripts/raw_fio_ceiling.sh "$YSUF" 1,2 2>&1 | tee -a "$LOG" | grep -a 'MEDIAN\|wrote\|sample'
    rc=${PIPESTATUS[0]}; stage "raw_ceiling" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    say "ceiling file (rig=$RIGTAG): $(cat ".raw_fio_ceiling.$YSUF.json" 2>/dev/null | tr -d '\n ')"
    fi
fi

if want 8; then
    # a one-node run needs a one-node list (s515h: 'MXFS_NODE_LIST has 2
    # entries, N=1 requires exactly 1' — the chain exports test1,test2)
    # s516a: with a test filter the runner refuses conditions that differ
    # from the cluster marker ('cluster is prepped for 2/tcp, you requested
    # 1/xfs') — the one-node native prep must run first, on its own.
    s=$(date +%s); MXFS_NODE_LIST=test1 MXFS_FORCE_PREP=1 timeout 120 ./run.sh 1 xfs prep_cluster 2>&1 | tee -a "$LOG" | grep -aE 'prep|ERROR|FAIL'
    rc=${PIPESTATUS[0]}; stage "xfs_prep" $rc $(( $(date +%s) - s ))
    s=$(date +%s); MXFS_NODE_LIST=test1 MXFS_TEST_ENV="XFS_BASELINE=/src/mxfs/.xfs_fio_baseline.$YSUF.json" timeout 180 ./run.sh 1 xfs fio_perf 2>&1 | tee -a "$LOG" | grep -aE 'PASS|FAIL|prep|ERROR'
    rc=${PIPESTATUS[0]}; stage "xfs_baseline" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    say "baseline file (rig=$RIGTAG): $(cat ".xfs_fio_baseline.$YSUF.json" 2>/dev/null | tr -d '\n ')"
    timeout 60 $SSH test1 "umount /mnt/shared 2>/dev/null; echo xfs_umount_rc=\$?" 2>/dev/null | grep -a rc | tee -a "$LOG"
fi

if want 9; then
    prep 300 || { say "ABORT: prep failed"; exit 1; }
    s=$(date +%s); timeout 160 ./run.sh 2 tcp fio_perf fio_perf_vs_xfs 2>&1 | tee -a "$LOG" | grep -aE '^\s+(PASS|FAIL|SKIP)'
    rc=${PIPESTATUS[0]}; stage "fio_rows" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
fi

if want 10; then
    s=$(date +%s); timeout 1000 ./run.sh 2 tcp 2>&1 | tee -a "$LOG" | grep -aE '^\s+(PASS|FAIL|SKIP|ABORT)|^===|VERDICT'
    rc=${PIPESTATUS[0]}; stage "board_2tcp" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    ./showstat.sh 2 tcp 2>/dev/null | grep -aE 'FAIL|FLAKY|ABORT|Total|VERDICT' | tee -a "$LOG"
fi

if want 11; then
    s=$(date +%s); TDR_BLOCK_INJECT=1 TDR_BLOCK_UMOUNT=1 TDR_LAP_BOUND=300 timeout 420 tests/tcp_2node_death_chain.sh "${LABEL}_umb" 1 2>&1 | tee -a "$LOG" | grep -aE '^STAGE|^DONE|^  FAIL|^  PASS|INFO (blocked|umount|first stack|fail-fast|the rig)'
    rc=${PIPESTATUS[0]}; stage "umount_blocked_lap" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
    # a survivor whose umount hung can only leave by power-cycle today; the
    # arm's evidence dir holds its stack samples.  Bounded so a wedged ssh
    # cannot hold the chain.
    st=$(timeout 30 $SSH test1 "mountpoint -q /mnt/shared && echo STILL_MOUNTED || echo UNMOUNTED" 2>/dev/null | grep -a 'MOUNTED' | tr -d '\r')
    say "survivor test1 after the arm: ${st:-NO_ANSWER}"
    if [ "${st:-NO_ANSWER}" != UNMOUNTED ]; then
        $VIRSH destroy test1 >/dev/null 2>&1; say "test1 destroyed (umount hung or unreachable)"
    fi
    restart_node test1
    restart_node test2
fi

say "DONE label=$LABEL fails=$fails $(date -u +%FT%TZ)"
exit $fails
