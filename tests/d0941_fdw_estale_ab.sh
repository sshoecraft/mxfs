#!/bin/bash
# d0941_fdw_estale_ab.sh — is the fence_during_write setup ESTALE caused by the
# deferred-publish diversion, or does it predate it?
#
# The 2026-09-10 06:02 board failed fence_during_write on test2 with
#   FDW-MKDIR-FAIL rc=1 err=[mkdir: cannot create directory
#     '/mnt/shared/.fence_during_write/node2': Stale file handle]
#   FDW-MKDIR-RETRY rc2=0
# — first attempt ESTALE, retry clean.  That is the D-0941 family (a lookup
# resolving a poisoned inode shell), and D-0941 was closed FIXED AND VERIFIED
# the session before.  The board immediately preceding this one passed the same
# row 8 checks of 8.  Between them sit 0.75.110 (an unpublished inode that owns
# metadata outside its core now takes a real grant at its first exclusive
# modify) and 0.75.112 (the inode-free poisoned-release gate, which cannot run
# on a healthy row).  So the diversion is the candidate and it has to be
# measured, not argued about.
#
# unpub_publish_owned_meta is mode 0644, so both arms run on ONE build with no
# prep between them — which also removes the confound a prep would add (a fresh
# mkfs is not the same test as an aged one).  The knob is written to every node
# and read back before every lap, because an arm that did not take is a control
# arm that is silently a treatment arm.
#
# The row is run through run.sh so it is scored exactly as the board scores it.
#
# derived time budget: the row measured 21 s of test wall on the failing board and 18 s
# on the passing one, plus the harness's ~12 s of per-row ssh fan-out and
# criteria bookkeeping.  60 s per lap, 8 laps, no prep: 480 s.
#
# Usage: tests/d0941_fdw_estale_ab.sh <label> [LAPS_PER_ARM=4]
set -u
LABEL=${1:?label}
LAPS=${2:-4}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fdwestale_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

echo "=== d0941_fdw_estale_ab label=$LABEL laps_per_arm=$LAPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
for ARM in 1 0; do
    for n in $A $B; do rs 20 "$n" "echo $ARM > /sys/module/mxfs/parameters/unpub_publish_owned_meta" >/dev/null; done
    got=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/parameters/unpub_publish_owned_meta"; done | tr -d '\n')
    if [ "$got" != "$ARM$ARM" ]; then echo "ARM $ARM KNOB-FAIL got=$got"; continue; fi
    estale=0; fail=0; ran=0
    for i in $(seq 1 "$LAPS"); do
        # The evidence directory BEFORE the lap.  run.sh refuses to start while
        # another run holds /tmp/mxfs_run.lock and exits 3 without producing
        # one; re-reading the newest directory then scores the PREVIOUS lap's
        # artifacts again, which is how four laps in a row "reproduced" a
        # failure none of them had run.
        before=$(ls -dt tests/evidence/run_fence_during_write_* 2>/dev/null | head -1)
        timeout 60 ./run.sh 2 tcp fence_during_write > "$OUT/arm${ARM}_lap$i.log" 2>&1
        rc=$?
        ran=$((ran+1))
        d=$(ls -dt tests/evidence/run_fence_during_write_* 2>/dev/null | head -1)
        if [ "$d" = "$before" ]; then
            echo "  ARM $ARM lap $i rc=$rc NO-NEW-EVIDENCE (run produced nothing; not counted) $(grep -am1 'ERROR' "$OUT/arm${ARM}_lap$i.log" | cut -c1-90)"
            ran=$((ran-1))
            continue
        fi
        # grep -c prints "file:count" per file across a glob, which turns the
        # sum into a bc syntax error; concatenate first.
        e=$(cat "$d"/*.raw 2>/dev/null | grep -ac 'FDW-MKDIR-FAIL')
        st=$(cat "$d"/*.raw 2>/dev/null | grep -a 'RESULT:' | grep -ac 'FAIL')
        [ "${e:-0}" -gt 0 ] && estale=$((estale+1))
        [ "${st:-0}" -gt 0 ] && fail=$((fail+1))
        echo "  ARM $ARM lap $i rc=$rc estale_lines=${e:-0} fail_records=${st:-0} evidence=$d"
        cat "$d"/*.raw 2>/dev/null | grep -a 'FDW-MKDIR-FAIL' | head -1 | cut -c1-160 | sed 's/^/      /'
    done
    echo "ARM $ARM SUMMARY laps=$ran laps_with_estale=$estale laps_with_fail_record=$fail"
done
echo "  evidence: $OUT"
