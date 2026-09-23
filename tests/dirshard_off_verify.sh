#!/bin/bash
# tests/dirshard_off_verify.sh <label> [node1] [node2]
#
# Directory sharding is off by default: mkfs.mxfs sets neither on-disk gate
# (XFS sb incompat bit 29, envelope MXFS_FORMAT_F_DIRSHARD) unless given -D,
# and the module refuses MXFS_IOC_DIRSHARD_MKDIR unless dirshard_mkdir_enable
# is set.  This checks the default format end to end on the 2-node rig:
#   1. prep 2/tcp with the default mkfs (no -D)
#   2. both nodes: the module parameter reads N, the mount logged dirshard=off
#   3. both nodes: sharded mkdir refused EOPNOTSUPP with the parameter off,
#      and STILL refused with it on (the format has no gates); nothing created
#   4. an ordinary mkdir/create/rmdir on the same parent works on both nodes
#   5. umount both; chk_mxfs -v: both gates clear, rc=0, zero errors
#
# derived time budgets: prep 400 s (tests/lu_reset_bystander_eh.sh's bound for
# the same 2/tcp prep); each probe is one ssh round trip plus at most a few
# syscalls, bound 20 s; umount 60 s per node; chk 120 s.
# Exit 0 PASS, 1 FAIL, 2 ABORT.
set -u
cd /src/mxfs || exit 2
LABEL=${1:?label}
N1=${2:-test1}; N2=${3:-test2}
MNT=/mnt/shared
PY=/src/mxfs/tests/dirshard_ioctl.py
PARAM=/sys/module/mxfs/parameters/dirshard_mkdir_enable
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dirshard_off_$LABEL
mkdir -p "$OUT"
export MXFS_NODE_LIST=$N1,$N2
fails=0
. tests/lib/rig.sh
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails+1)); }

echo "=== dirshard_off_verify $LABEL START $(date -u +%FT%TZ) VERSION=$(cat VERSION) sv=$(modinfo -F srcversion mxfs.ko) out=$OUT ==="

T0=$(date +%s)
MXFS_MKFS_OPTS= MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1; rc=$?
echo "STAGE prep rc=$rc wall=$(( $(date +%s) - T0 ))s"
[ $rc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
SV=$(modinfo -F srcversion mxfs.ko)

for n in $N1 $N2; do
    o=$(rs 20 "$n" "cat /sys/module/mxfs/srcversion; grep -c ' $MNT mxfs ' /proc/mounts; cat $PARAM; dmesg | grep -a 'MXFS envelope v' | tail -1")
    echo "$o" > "$OUT/pre_$n.txt"
    set -- $(echo "$o" | head -3 | tr '\n' ' ')
    [ "${1:-}" = "$SV" ] && [ "${2:-}" = 1 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy ($n: $(echo "$o" | tr '\n' '|')) evidence=$OUT"; exit 2; }
    [ "${3:-}" = N ] && ok "$n: dirshard_mkdir_enable defaults to N" || bad "$n: dirshard_mkdir_enable reads '${3:-}'"
    env=$(echo "$o" | tail -1)
    case "$env" in
        *dirshard=off*) ok "$n: mount logged dirshard=off" ;;
        *"MXFS envelope"*) bad "$n: mount line without dirshard=off: $env" ;;
        *) echo "NOTE: $n: the mount's envelope line has left the kernel ring; the on-disk gates are checked by chk below" ;;
    esac
done

for n in $N1 $N2; do
    o=$(rs 20 "$n" "echo 0 > $PARAM; python3 $PY mkdir $MNT ds_off_$n 16 2>&1 | tail -1; echo 1 > $PARAM; python3 $PY mkdir $MNT ds_on_$n 16 2>&1 | tail -1; echo 0 > $PARAM; ls -d $MNT/ds_off_$n $MNT/ds_on_$n 2>/dev/null | wc -l")
    echo "$o" > "$OUT/refuse_$n.txt"
    # EOPNOTSUPP and ENOTSUP are the same errno on Linux; python names it
    # ENOTSUP, so grade on the message, which is the same under either name
    set -- $(echo "$o" | sed -n '1,2p' | sed 's/.*Operation not supported$/REFUSED/' | tr '\n' ' ')
    [ "${1:-}" = REFUSED ] && ok "$n: sharded mkdir refused with the parameter off" || bad "$n: parameter off: $(echo "$o" | sed -n 1p)"
    [ "${2:-}" = REFUSED ] && ok "$n: sharded mkdir refused with the parameter on (no gates on the format)" || bad "$n: parameter on: $(echo "$o" | sed -n 2p)"
    [ "$(echo "$o" | tail -1)" = 0 ] && ok "$n: no directory created by a refused ioctl" || bad "$n: refused ioctl left $(echo "$o" | tail -1) entries"
done

for n in $N1 $N2; do
    o=$(rs 20 "$n" "mkdir $MNT/plain_$n && echo x > $MNT/plain_$n/f && cat $MNT/plain_$n/f && rm $MNT/plain_$n/f && rmdir $MNT/plain_$n && echo PLAIN_OK")
    [ "$(echo "$o" | tail -1)" = PLAIN_OK ] && ok "$n: ordinary mkdir/create/read/rmdir" || bad "$n: ordinary dir ops: $(echo "$o" | tr '\n' '|')"
done

for n in $N1 $N2; do
    f="$OUT/dmesg_$n.txt"
    rs 40 "$n" 'dmesg' > "$f"
    c=$(grep -ac 'WARNING:\|BUG:\|Oops\|Internal error\|Corruption of in-memory\|P-DIRSHARD-CORRUPT' "$f")
    [ "$c" = 0 ] && ok "$n: kernel log clean ($(wc -l < "$f") lines)" || bad "$n: $c splat/corruption lines"
done

mxfs_dev_resolve "$N1"
DEV=$MXFS_DEV_RESOLVED
for n in $N1 $N2; do
    echo "UMOUNT $n $(rs 60 "$n" "timeout 50 umount $MNT; echo rc=\$?" | tail -1)"
done
T0=$(date +%s)
rs 120 "$N1" "/src/mxfs/tools/chk_mxfs -v $DEV; echo CHK_RC=\$?" > "$OUT/chk.txt"
gates=$(grep -a 'dirshard: sb bit=' "$OUT/chk.txt" | head -1)
echo "STAGE chk dev=$DEV wall=$(( $(date +%s) - T0 ))s $(grep -a CHK_RC "$OUT/chk.txt") errors=$(grep -ac ERROR "$OUT/chk.txt") gates: $gates"
echo "$gates" | grep -q 'sb bit=no envelope flag=no' && ok "chk: both sharding gates clear" || bad "chk gates: '$gates'"
grep -q 'CHK_RC=0' "$OUT/chk.txt" && [ "$(grep -ac ERROR "$OUT/chk.txt")" = 0 ] && ok "chk: rc=0, zero errors" || bad "chk: $(grep -a 'ERROR\|CHK_RC' "$OUT/chk.txt" | head -5 | tr '\n' '|')"

echo "fails=$fails"
[ "$fails" = 0 ] && echo "RESULT: PASS label=$LABEL evidence=$OUT" || echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"
[ "$fails" = 0 ]
