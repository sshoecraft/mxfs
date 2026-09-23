#!/bin/bash
# tests/dirshard_rmdir_verify.sh <label> [node1] [node2]
#
# Verification of the two sharded-directory rmdir defects on the 2-node TCP
# release configuration:
#   D-DIRSHARD-CONTAINER-HOLDER-FREE-UNLOCKS-JOINED-ILOCK-TWICE-RWSEM-UNDERFLOW-0530
#     container/holder free released an ILOCK the transaction join already
#     owned: WARN in mxfs_ilk_note_unlock, P71-UNDERFLOW.
#   D-DIRSHARD-RMDIR-DIRTY-CANCEL-SHUTS-DOWN-AND-FENCES-0531
#     holder free refused after its first dirty: P-DIRSHARD-LOCATOR-DEFERRED,
#     "Internal error xfs_trans_cancel", shutdown, self-fence.
#
# Stages:
#   1. prep 2/tcp (fresh mkfs, both nodes mounted, tree build deployed)
#   2. tests/dirshard_stage1_selftest.sh x LAPS on the same mount.  Every lap
#      rmdirs its N=16 dir; laps 2.. also rm -rf the previous lap's N=16 (64
#      files) and N=64 (1500 files) dirs, so each lap after the first frees
#      80 containers under rmdir.
#   3. REPEAT same-name cycles per node: sharded mkdir N=16, 64 creates, unlink
#      all, rmdir — the record's "repeated mkdir/rmdir of the same sharded dir
#      on the same node" (a wedged rwsem hangs the next cycle).
#   After every stage both nodes' kernel logs are captured and the failure
#   signatures of both defects counted; any nonzero count is a FAIL.
#   4. umount both, chk_mxfs -v on the platter from test1.
#
# derived time budgets: prep 400 s (tests/lu_reset_bystander_eh.sh's bound for
# the same 2/tcp prep); selftest 240 s each (its header); one repeat cycle =
# mkdir N=16 < 2 s + 64 creates ~1 s + unlink ~1 s + rmdir < 5 s (the 0530
# record's own bound) + ssh ~2 s = 11 s, bound 30 s per cycle; capture 40 s
# per node; umount 60 s per node; chk 120 s.
# Exit 0 PASS, 1 FAIL, 2 ABORT.
set -u
cd /src/mxfs || exit 2
LABEL=${1:?label}
N1=${2:-test1}; N2=${3:-test2}
LAPS=${LAPS:-3}
CYCLES=${CYCLES:-10}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PY=/src/mxfs/tests/dirshard_ioctl.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dirshard_rmdir_$LABEL
mkdir -p "$OUT"
export MXFS_NODE_LIST=$N1,$N2
fails=0
SIGS='mxfs_ilk_note_unlock P71-UNDERFLOW P-DIRSHARD-LOCATOR-DEFERRED Internal.error.xfs_trans_cancel Corruption.of.in-memory P-SESSION-POISON P-WITHDRAW P277-FENCED-SELF-WITHDRAW P131-SELF-FENCE P-DIRSHARD-CORRUPT P-DIRSHARD-STRANGER P-DIRSHARD-ABANDON WARNING: BUG: Oops'

. tests/lib/rig.sh
stage() { # <budget_s> <label> <cmd...>
    local b="$1" l="$2" rc T0; shift 2
    T0=$(date +%s)
    timeout "$b" "$@" > "$OUT/$l.log" 2>&1; rc=$?
    echo "STAGE $l rc=$rc wall=$(( $(date +%s) - T0 ))s $(grep -a '^VERDICT\|RESULT' "$OUT/$l.log" | tail -1 | cut -c1-160)"
    return $rc
}
health() { # <tag>: capture both nodes, count every signature, FAIL on any
    local tag="$1" n f s c line
    for n in $N1 $N2; do
        f="$OUT/dmesg_${tag}_$n.txt"
        rs 40 "$n" 'dmesg' > "$f"
        line=""
        for s in $SIGS; do
            c=$(grep -ac -- "${s//./ }" "$f")
            line="$line ${s}=$c"
            [ "$c" = 0 ] || bad=1
        done
        echo "HEALTH $tag $n lines=$(wc -l < "$f") dirshard=$(grep -ac P-DIRSHARD "$f")$line"
        if [ "${bad:-0}" = 1 ]; then
            echo "FAIL: $tag $n carries a failure signature"
            fails=$((fails+1)); bad=0
        fi
    done
}

echo "=== dirshard_rmdir_verify $LABEL START $(date -u +%FT%TZ) VERSION=$(cat VERSION) sv=$(modinfo -F srcversion mxfs.ko) LAPS=$LAPS CYCLES=$CYCLES out=$OUT ==="

# sharding is off unless the format carries its gates
MXFS_MKFS_OPTS=-D MXFS_FORCE_PREP=1 stage 400 prep ./run.sh 2 tcp prep_cluster || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
SV=$(modinfo -F srcversion mxfs.ko)
for n in $N1 $N2; do
    o=$(rs 20 "$n" "cat /sys/module/mxfs/srcversion; grep -c ' $MNT mxfs ' /proc/mounts; grep -rh . /sys/module/mxfs/parameters/dlm_transport 2>/dev/null" | tr '\n' ' ')
    echo "NODE $n: $o"
    set -- $o
    [ "${1:-}" = "$SV" ] && [ "${2:-}" = 1 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy ($n: $o, want sv=$SV mounted=1) evidence=$OUT"; exit 2; }
done

for l in $(seq 1 "$LAPS"); do
    stage 240 "selftest_$l" tests/dirshard_stage1_selftest.sh "$N1" "$N2" || fails=$((fails+1))
    health "selftest_$l"
done

for n in $N1 $N2; do
    rs 20 "$n" "dmesg --clear; echo 1 > /sys/module/mxfs/parameters/dirshard_mkdir_enable" > /dev/null
    ok=0
    T0=$(date +%s)
    for c in $(seq 1 "$CYCLES"); do
        o=$(rs 30 "$n" "cd $MNT && python3 $PY mkdir $MNT dirshard_cycle 16 | tail -1 && cd dirshard_cycle && for i in \$(seq -f %04g 1 64); do echo c\$i > c_\$i; done && ls | wc -l && rm -f c_* && cd $MNT && rmdir dirshard_cycle && echo RMDIR_OK && stat dirshard_cycle 2>&1 | grep -c 'No such file'")
        if [ "$(echo "$o" | tr '\n' ' ')" = "OK 64 RMDIR_OK 1 " ]; then
            ok=$((ok+1))
        else
            echo "FAIL: repeat $n cycle $c: $(echo "$o" | tr '\n' '|' | cut -c1-240)"
            fails=$((fails+1)); break
        fi
    done
    echo "STAGE repeat_$n cycles_ok=$ok/$CYCLES wall=$(( $(date +%s) - T0 ))s"
    health "repeat_$n"
done

# resolved while the mount is live, so the device is the one that was measured
mxfs_dev_resolve "$N1"
DEV=$MXFS_DEV_RESOLVED
for n in $N1 $N2; do
    echo "UMOUNT $n $(rs 60 "$n" "timeout 50 umount $MNT; echo rc=\$?" | tail -1)"
done
T0=$(date +%s)
rs 120 "$N1" "/src/mxfs/tools/chk_mxfs -v $DEV; echo CHK_RC=\$?" > "$OUT/chk.txt"
echo "STAGE chk dev=$DEV wall=$(( $(date +%s) - T0 ))s $(grep -a 'CHK_RC' "$OUT/chk.txt") errors=$(grep -ac 'ERROR' "$OUT/chk.txt") leaked=$(grep -ac 'leaked internal inode' "$OUT/chk.txt") $(grep -a 'Directory sharding' "$OUT/chk.txt" | head -1)"
grep -q 'CHK_RC=0' "$OUT/chk.txt" && [ "$(grep -ac 'ERROR' "$OUT/chk.txt")" = 0 ] || { echo "FAIL: chk"; fails=$((fails+1)); }

echo "fails=$fails"
[ "$fails" = 0 ] && echo "RESULT: PASS label=$LABEL evidence=$OUT" || echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"
[ "$fails" = 0 ]
