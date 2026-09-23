#!/bin/bash
# concurrent_create_race_2node.sh — both nodes open(O_CREAT|O_APPEND) the
# SAME new name at the same instant, many rounds, on the two-node TCP rig.
#
# Found by tests/append_contention_2node.sh s525e (0.75.44): the multipage
# phase lost B's first 64 KB record.  test2's log showed it reloaded the
# directory, saw test1's `multipage` entry, allocated inode 8392721 anyway,
# put it on the unlinked list with nlink 0 (the xfs_create EEXIST-loser
# branch) and returned -EEXIST — which the VFS hands straight to open(2).
# For open(O_CREAT) WITHOUT O_EXCL that is a POSIX violation: the open must
# succeed on the file the peer just created.  The append harness had thrown
# the shell's error away, so this harness captures every open's rc and
# stderr on each node and pairs them with the lines that actually landed.
#
# Method: a shared wall-clock schedule.  Round i fires at T0 + i*STEP_MS on
# both nodes (each node busy-waits on its own clock; node offsets are
# measured and applied), and each round appends "<node><i>" to a fresh
# name f<i>.  Two files per round would never collide, one file per round
# collides whenever the two creates fall inside the create window.
#
# Assertions: every open returned 0 (no EEXIST, no ESTALE, nothing);
# every f<i> holds exactly the two lines A<i> and B<i>; both nodes read the
# same directory listing; no DLM deadline expired; kernel health; mounted.
# The race count (P127-EEXIST-LOSER lines) is reported, not asserted: it
# says whether the collision was reached at all — a lap with race=0 proves
# nothing and is reported as INCONCLUSIVE.
#
# budget: R rounds x STEP_MS + 3 s barrier + capture ~10 s.  R=200 x 25 ms
# = 5 s of rounds; NOPREP wall ~25 s.
#
# CREATE_DELAY_MS=<n> (0.75.47, D-0921): arms mxfs.create_race_delay_ms on
# node A for the loop and clears it afterwards, so A's create sleeps n ms
# between its negative lookup and the directory lock and B's create of the
# same name wins every round.  Without it the loser branch was reached 0
# times in 800 scheduled rounds (s527f, s528a, s528b): the lookup and the
# lock are microseconds apart in one open(2).  Rounds then cost >= n ms on
# A, so STEP_MS must exceed n.
#
# Usage: tests/concurrent_create_race_2node.sh <label> [R=200] [STEP_MS=25]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2), NOPREP=1,
#        CREATE_DELAY_MS=<n>.
set -u
LABEL=${1:?label}
R=${2:-200}
STEP_MS=${3:-25}
CREATE_DELAY_MS=${CREATE_DELAY_MS:-0}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/ccr_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ccr_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
offset_ms() {
    local t0 tr t1
    t0=$(date +%s%N); tr=$(rs 15 "$1" "date +%s%N" | tr -dc 0-9); t1=$(date +%s%N)
    python3 -c "print(int(($tr - ($t0 + $t1) / 2) / 1e6))"
}

echo "=== concurrent_create_race_2node label=$LABEL A=$A B=$B R=$R step_ms=$STEP_MS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -z "${NOPREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat /sys/module/mxfs/parameters/force_transport)" | tr -d '\n')"
done
ck "both nodes mounted on the tree's build" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
offA=$(offset_ms "$A"); offB=$(offset_ms "$B")
echo "  INFO clock offsets ms A=$offA B=$offB"
MK="CCR-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
rs 30 "$A" "mkdir -p $D && sync -f $MNT && echo ok" | tail -1 >/dev/null
rs 30 "$B" "ls $D >/dev/null; echo ok" | tail -1 >/dev/null
if [ "$CREATE_DELAY_MS" != 0 ]; then
    echo "  INFO arming create_race_delay_ms=$CREATE_DELAY_MS on $A: $(rs 15 "$A" "echo $CREATE_DELAY_MS > /sys/module/mxfs/parameters/create_race_delay_ms && cat /sys/module/mxfs/parameters/create_race_delay_ms" | tr -d '\n')"
fi

# T0 on clyde's clock, 3 s out; each node converts with its own offset.
T0=$(( $(date +%s%N) / 1000000 + 3000 ))
loop='t0=@T0@; i=0; ok=0; bad=0; : > @ERR@; while [ $i -lt @R@ ]; do i=$((i+1)); tgt=$((t0 + i * @STEP@)); while [ $(( $(date +%s%N) / 1000000 )) -lt $tgt ]; do :; done; if echo @TAG@$i >> @DIR@/f$i 2>>@ERR@; then ok=$((ok+1)); else rc=$?; bad=$((bad+1)); echo "round=$i rc=$rc" >> @ERR@; fi; done; echo @TAG@_DONE ok=$ok bad=$bad'
loop=${loop//@R@/$R}; loop=${loop//@STEP@/$STEP_MS}; loop=${loop//@DIR@/$D}
# A_LEAD_MS: A fires this many ms BEFORE B each round (default half the armed
# delay).  With the delay alone A lost 0 of 100 rounds (s528e): A is the
# later node by ~10 ms of offset error, so its lookup already saw B's file
# and never entered the race.  The loser branch needs A's lookup BEFORE B's
# create and B's create inside A's sleep, which the lead arranges.
A_LEAD_MS=${A_LEAD_MS:-$(( CREATE_DELAY_MS / 2 ))}
[ "$A_LEAD_MS" != 0 ] && echo "  INFO A fires $A_LEAD_MS ms ahead of B each round"
la=${loop//@T0@/$((T0 + offA - A_LEAD_MS))}; la=${la//@TAG@/A}; la=${la//@ERR@/\/tmp\/ccr_${LABEL}_A.err}
lb=${loop//@T0@/$((T0 + offB))}; lb=${lb//@TAG@/B}; lb=${lb//@ERR@/\/tmp\/ccr_${LABEL}_B.err}
( rs 120 "$A" "$la" | tail -1 > "$OUT/loop_$A.txt" ) &
pa=$!
( rs 120 "$B" "$lb" | tail -1 > "$OUT/loop_$B.txt" ) &
pb=$!
wait $pa; wait $pb
if [ "$CREATE_DELAY_MS" != 0 ]; then
    echo "  INFO disarming create_race_delay_ms on $A: $(rs 15 "$A" "echo 0 > /sys/module/mxfs/parameters/create_race_delay_ms && cat /sys/module/mxfs/parameters/create_race_delay_ms" | tr -d '\n')"
fi
echo "  INFO $(cat "$OUT/loop_$A.txt") | $(cat "$OUT/loop_$B.txt")"
rs 30 "$A" "cat /tmp/ccr_${LABEL}_A.err" > "$OUT/err_$A.txt"
rs 30 "$B" "cat /tmp/ccr_${LABEL}_B.err" > "$OUT/err_$B.txt"
# Every round's file, from both nodes' view.
rs 60 "$A" "cd $D && for f in f*; do echo \"\$f:\$(tr '\n' ',' < \$f)\"; done | sort -V" > "$OUT/files_$A.txt"
rs 60 "$B" "cd $D && for f in f*; do echo \"\$f:\$(tr '\n' ',' < \$f)\"; done | sort -V" > "$OUT/files_$B.txt"
verdict=$(python3 - "$OUT/files_$A.txt" "$R" <<'EOF'
import sys
path, r = sys.argv[1], int(sys.argv[2])
seen = {}
for ln in open(path):
    ln = ln.rstrip('\n')
    if ':' not in ln: continue
    f, body = ln.split(':', 1)
    seen[f] = sorted(x for x in body.split(',') if x)
missing_files = [i for i in range(1, r + 1) if f"f{i}" not in seen]
lost = []
extra = []
for i in range(1, r + 1):
    got = seen.get(f"f{i}")
    if got is None: continue
    want = [f"A{i}", f"B{i}"]
    if got != want:
        (lost if len(got) < 2 else extra).append((i, got))
print(f"files={len(seen)} missing_files={len(missing_files)} lost_lines={sum(2-len(g) for _, g in lost)} rounds_with_loss={len(lost)} rounds_with_extra={len(extra)} first_loss={lost[:3]}")
EOF
)
eexist=$(cat "$OUT/err_$A.txt" "$OUT/err_$B.txt" | grep -aic 'File exists')
estale=$(cat "$OUT/err_$A.txt" "$OUT/err_$B.txt" | grep -aic 'Stale file handle')
errs=$(cat "$OUT/err_$A.txt" "$OUT/err_$B.txt" | grep -ac 'round=')
for n in $A $B; do
    rs 40 "$n" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'" > "$OUT/dmesg_full_$n.txt"
done
race=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P127-EEXIST-LOSER')
raceA=$(grep -ac 'P127-EEXIST-LOSER' "$OUT/dmesg_full_$A.txt"); raceB=$(grep -ac 'P127-EEXIST-LOSER' "$OUT/dmesg_full_$B.txt")
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
underflow=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P71-UNDERFLOW')
echo "  CCR-MEASURE $LABEL rounds=$R step_ms=$STEP_MS open_errors=$errs eexist=$eexist estale=$estale race_losers=$race (A=$raceA B=$raceB) lock_timeouts=$lkto underflow=$underflow $verdict"
[ "$errs" != 0 ] && echo "  INFO first errors: $(cat "$OUT/err_$A.txt" "$OUT/err_$B.txt" | head -4 | tr '\n' ';' | cut -c1-300)"
[ "$race" = 0 ] && echo "  INCONCLUSIVE: no cross-node create collision occurred in this lap (race_losers=0); the assertions below cannot exercise the defect"
ck "every open(O_CREAT|O_APPEND) on both nodes returned 0" "$errs" "0"
ck "no open returned EEXIST" "$eexist" "0"
ck "every round's file holds exactly A<i> and B<i> (no lost line)" "$(echo "$verdict" | grep -ao 'lost_lines=[0-9]*' | cut -d= -f2)" "0"
ck "no round's file is missing" "$(echo "$verdict" | grep -ao 'missing_files=[0-9]*' | cut -d= -f2)" "0"
ck "no round's file holds extra lines" "$(echo "$verdict" | grep -ao 'rounds_with_extra=[0-9]*' | cut -d= -f2)" "0"
ck "both nodes read identical directory contents" "$(cmp -s "$OUT/files_$A.txt" "$OUT/files_$B.txt" && echo 1 || echo 0)" "1"
ck "no DLM request deadline expired on either node" "$lkto" "0"
ck "no inode hold-count underflow on either node" "$underflow" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT race_losers=$race"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT race_losers=$race"; fi
exit $fails
