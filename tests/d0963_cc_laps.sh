#!/bin/bash
# d0963_cc_laps.sh — repeat the board's cache_coherency criterion on the 2-node
# TCP rig until a removed shortform dirent is resurrected, or LAPS laps pass.
#
# D-PEER-STATS-A-NAME-THE-DELETER-UNLINKED-AND-SYNCED-WHILE-ITS-DIRECTORY-
# PUBLICATION-IS-IN-FLIGHT-0963.  The defect was measured by this criterion's
# unlink_visibility phase (1 lap in 5 on 0.84.17), and the synthetic shape in
# tests/d0963_sf_dirent_resurrect.sh did not reproduce it in 20 laps (s604a):
# it needs the deleter's fork stale-gen for its whole removal loop with its own
# flushes landing one removal behind, which the real phase produces (the peer's
# verify loop overlapping the deleter's removals) and the synthetic one did
# not.  So the reproduction IS the criterion, driven by run.sh exactly as the
# board drives it, with the merge diagnostics armed on both nodes.
#
# Per lap: a kernel-log marker on both nodes, one `run.sh 2 tcp
# cache_coherency`, then from each node's log window since the marker:
#   readd    P-SFM-READD lines      (the merge re-added an entry: the defect's
#                                    own signature, printed under sfm_dbg=1)
#   sfmerge  P-SFMERGE lines        (merges installed)
#   own      P963-SF-OWN-IMAGE      (0.84.18: the platter held this node's own
#                                    image and the fork was kept -- the fix arm
#                                    firing on the shape the merge used to take)
#   relbase  P963-SF-RELEASE-BASE   (0.84.18: base captured at an EX release)
#   ccfail   mxfs-CCfail lines      (a failing check stamped by the suite)
# and the criterion's own verdict line.  A lap FAILS when the criterion fails
# or any node printed a P-SFM-READD; the harness stops at the first failing
# lap and keeps both nodes' windows.  MODE=control sets sf_own_image=0 on both
# nodes first (the pre-0.84.18 behaviour on the same build) and PASSES when the
# defect reproduces inside LAPS; MODE=fix (default) leaves the knob on and
# PASSES only when every lap is clean AND the fix arm fired at least once
# across the laps (a silent instrument and a clean system are the same
# observation).  The knobs are restored at the end and on abort.
#
# Usage: tests/d0963_cc_laps.sh <label> [LAPS=20]        (MODE=fix|control)
# Exit 0 = the mode's expectation met, 1 = not met, 2 = ABORT.
#
# derived time budget: one cache_coherency lap through run.sh is 9-16 s of
# criterion plus ~12 s of preflight/marker/collect (measured 20-28 s per lap on
# 0.84.17); 20 laps = 560 s, bounded at 900 s.  run.sh enforces the criterion's
# own 60 s budget and is never wrapped in a timeout here.
set -u
LABEL=${1:?label}
LAPS=${2:-20}
MODE=${MODE:-fix}
case "$MODE" in fix|control) ;; *) echo "ABORT: MODE must be fix or control"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0963cc_${MODE}_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" </dev/null 2>/dev/null | filt; }
fld() { echo "$1" | grep -ao "$2=[0-9]*" | head -1 | cut -d= -f2; }
restore() { for n in $A $B; do rs 20 "$n" "echo 0 > $P/sfm_dbg; test -w $P/sf_own_image && echo 1 > $P/sf_own_image" >/dev/null; done; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0963_cc_laps label=$LABEL mode=$MODE laps=$LAPS sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

KNOB=$([ "$MODE" = control ] && echo 0 || echo 1)
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) k=\$(test -w $P/sfm_dbg && echo 1 || echo 0) own=\$(test -w $P/sf_own_image && echo 1 || echo 0)" | tr -d '\n')
    echo "  INFO $n $st"
    [[ "$st" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV ($st)"; exit 2; }
    [[ "$st" == *"mnt=1"* ]]  || { echo "ABORT: $n not mounted ($st)"; exit 2; }
    [[ "$st" == *"k=1"* ]]    || { echo "ABORT: $n has no writable sfm_dbg knob"; exit 2; }
    [[ "$st" == *"own=1"* ]]  || { echo "ABORT: $n has no sf_own_image knob (build older than 0.84.18)"; exit 2; }
    rs 20 "$n" "echo 1 > $P/sfm_dbg; echo $KNOB > $P/sf_own_image; echo 0 > $P/sf_own_image_hits; echo 0 > $P/sf_release_base; echo 0 > $P/sf_own_image_recorded; echo knobs=\$(cat $P/sfm_dbg),\$(cat $P/sf_own_image)" | tr -d '\n' | sed "s/^/  INFO $n /"; echo
done

hit=""
own_total=0
for r in $(seq 1 "$LAPS"); do
    MK="D0963CC-$LABEL-$$-r$r"
    for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
    ./run.sh 2 tcp cache_coherency > "$OUT/run_lap$r.log" 2>&1
    rrc=$?
    verdict=$(grep -a '^  \(PASS\|FAIL\|FLAKY\|INFRA\)  cache_coherency' "$OUT/run_lap$r.log" | head -1 | sed 's/^ *//')
    v=""
    for n in $A $B; do
        vv=$(rs 60 "$n" "dmesg | awk '/$MK/{f=1} f' > /tmp/d0963cc_win.txt
            echo V node=$n readd=\$(grep -ac 'P-SFM-READD' /tmp/d0963cc_win.txt) drop=\$(grep -ac 'P-SFM-DROP' /tmp/d0963cc_win.txt) sfmerge=\$(grep -ac 'P-SFMERGE' /tmp/d0963cc_win.txt) own=\$(grep -ac 'P963-SF-OWN-IMAGE' /tmp/d0963cc_win.txt) relbase=\$(grep -ac 'P963-SF-RELEASE-BASE' /tmp/d0963cc_win.txt) stalegen=\$(grep -ac 'P174-STALEGEN-ADOPT' /tmp/d0963cc_win.txt) selfahead=\$(grep -ac 'P34F-RELOAD-SELFAHEAD-SKIP' /tmp/d0963cc_win.txt) ccfail=\$(grep -ac 'mxfs-CCfail' /tmp/d0963cc_win.txt) shut=\$(grep -ac 'Shutting down filesystem' /tmp/d0963cc_win.txt) own_hits=\$(cat $P/sf_own_image_hits) recorded=\$(cat $P/sf_own_image_recorded) relbase_n=\$(cat $P/sf_release_base)
            grep -a 'P-SFM-READD\|mxfs-CCfail' /tmp/d0963cc_win.txt | head -3 | cut -c1-220")
        v="$v"$'\n'"$vv"
    done
    echo "  --- lap $r at +$(el)s: rc=$rrc ${verdict:-no verdict line}"
    echo "$v" | grep -a . | sed 's/^/     /'
    { echo "rc=$rrc"; echo "$verdict"; echo "$v"; } > "$OUT/lap$r.txt"
    [ -n "$verdict" ] || { echo "ABORT: lap $r produced no cache_coherency verdict (see $OUT/run_lap$r.log)"; restore; exit 2; }
    readd=0; ccfail=0; shut=0; own=0
    for n in $A $B; do
        line=$(echo "$v" | grep -a "^V node=$n")
        readd=$(( readd + $(fld "$line" readd) ))
        ccfail=$(( ccfail + $(fld "$line" ccfail) ))
        shut=$(( shut + $(fld "$line" shut) ))
        own=$(( own + $(fld "$line" own) ))
    done
    own_total=$(( own_total + own ))
    if [[ "$verdict" == FAIL* ]] || [ "$readd" != 0 ] || [ "$ccfail" != 0 ] || [ "$shut" != 0 ]; then
        hit=r$r
        echo "  FAIL lap $r: verdict=[$verdict] readd=$readd ccfail=$ccfail shutdowns=$shut — a removed entry survived or the criterion failed"
        for n in $A $B; do
            rs 60 "$n" "dmesg | awk '/$MK/{f=1} f'" > "$OUT/dmesg_${n}_lap$r.txt"
        done
        break
    fi
    echo "  PASS lap $r: criterion passed, readd=0, own-image hits this lap=$own"
done
restore
if [ "$MODE" = control ]; then
    if [ -n "$hit" ]; then
        echo "=== d0963_cc_laps $LABEL (control, sf_own_image=0): REPRODUCED at $hit wall=$(el)s out=$OUT ==="
        exit 0
    fi
    echo "=== d0963_cc_laps $LABEL (control, sf_own_image=0): NOT REPRODUCED in $LAPS laps wall=$(el)s out=$OUT ==="
    exit 1
fi
if [ -n "$hit" ]; then
    echo "=== d0963_cc_laps $LABEL (fix): FAILED at $hit — the fix did not hold wall=$(el)s out=$OUT ==="
    exit 1
fi
if [ "$own_total" -eq 0 ]; then
    echo "=== d0963_cc_laps $LABEL (fix): $LAPS clean laps but the fix arm NEVER FIRED (own-image hits=0) — vacuous, not a verification wall=$(el)s out=$OUT ==="
    exit 1
fi
echo "=== d0963_cc_laps $LABEL (fix): $LAPS clean laps, own-image hits=$own_total wall=$(el)s out=$OUT ==="
exit 0
