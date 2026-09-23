#!/bin/bash
# d0944_death_rejoin_ab.sh — after a log-shutdown death, does the survivor's
# foreign replay admit the victim's slice, and if not, WHICH refusal is it?
#
# D-0944.  A refused slice is terminal: the victim's domain is quarantined
# cluster-wide, and when that domain contains AG 0 the root inode is unreadable
# and the victim cannot mount again (mount_rc=32, P240-QUAR-AG-EIO agno=0).
# sess567 measured the rate at 3 of 7 laps and attributed it to images that
# carried no authority at all.  0.75.110 removed that population on the
# producer (unpub 6662 -> 0, tests/d0944_unpub_owned_meta_ab.sh), and a lap
# still failed — so the rate has more than one cause and each has to be named
# rather than counted.
#
# THE REFUSAL IS NOT ONE THING.  P273-SHADOW-EVAL breaks the survivor's verdict
# into its reasons, and they are different defects:
#   classless/untagged/badst   the producer shipped no enforceable authority
#                              (what 0.75.110 addresses)
#   notheld / stale_epoch      the token is VALID but the fence-time manifest
#                              says the victim did not hold that resource, or
#                              held a different epoch of it, at death
#   wrong_lineage / manerr     the manifest names a different binding
#   winc / fowner              incarnation or owner mismatch
# This harness runs the same death lap under both arms of the knob and reports
# that vector per lap, so a change of RATE is never reported without the change
# of REASON that would explain it.
#
# Each lap needs both nodes mounted; a lap whose victim failed to rejoin leaves
# it unmounted, so the driver re-preps before any lap that is not ready.  A prep
# is recorded in the per-lap line, because a lap behind a fresh mkfs and a lap
# on an aged filesystem are not the same test.
#
# derived time budget: prep measured 50 s (bounded 300 s), death lap measured 76 s
# (bounded 260 s by its own step bounds).  Worst case 310 s per lap; a lap that
# needs no prep is 76 s.
#
# Usage: tests/d0944_death_rejoin_ab.sh <label> <0|1> [LAPS=3]
set -u
LABEL=${1:?label}
ARM=${2:?arm: 0 = pre-fix, 1 = fix}
LAPS=${3:-3}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0944death_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0944_death_rejoin_ab label=$LABEL arm=$ARM laps=$LAPS sv=$SV $(date -u +%FT%TZ) ==="
ok=0; bad=0; vac=0; s=$(date +%s)
for i in $(seq 1 "$LAPS"); do
    mounted=$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')
    knob=$(rs 20 "$A" "cat /sys/module/mxfs/parameters/unpub_publish_owned_meta 2>/dev/null || echo x")
    # THE BUILD IS PART OF READINESS.  A lap that reuses a mount running an
    # older module is not this build's lap: the harness fails its own
    # 'both nodes mounted with the tree build' precondition and returns in
    # seconds, and a driver that only asks 'are they mounted?' then reports six
    # laps that never ran, with identical numbers scraped from the PREVIOUS
    # lap's dmesg.  Measured: twelve such laps in 102 s after a rebuild.
    nodesv=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null || echo none"; done | sort -u | tr -d '\n')
    prepped=no
    if [ "$mounted" != "11" ] || [ "$knob" != "$ARM" ] || [ "$nodesv" != "$SV" ]; then
        p0=$(date +%s)
        MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS="unpub_publish_owned_meta=$ARM" \
            timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_$i.log" 2>&1
        prc=$?
        prepped="rc=$prc/$(( $(date +%s) - p0 ))s"
        [ $prc != 0 ] && { echo "LAP $i PREP-FAIL $prepped"; bad=$((bad+1)); continue; }
    fi
    # The knob IS the arm.  A prep that silently drops the modarg turns the
    # control arm into a second treatment arm, so read it back every lap.
    knob=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/parameters/unpub_publish_owned_meta"; done | tr -d '\n')
    if [ "$knob" != "$ARM$ARM" ]; then
        echo "LAP $i KNOB-FAIL got=$knob want=$ARM$ARM"; bad=$((bad+1)); continue
    fi

    timeout 260 tests/agmeta_shutdown_retire.sh "${LABEL}l$i" > "$OUT/lap_$i.log" 2>&1
    lrc=$?
    ev=$(grep -ao 'evidence=[^ ]*' "$OUT/lap_$i.log" | tail -1 | cut -d= -f2)
    # The verdict comes from the harness's own REJOIN line, anchored.  A bare
    # 'mount_rc=[0-9]*' also matches INSIDE 'umount_rc=0' on the UNLOAD line
    # that precedes it, and that line comes first — so every lap read as
    # mount_rc=0, including the three that had failed at 32.  Read it from the
    # node's evidence file when there is one, and never unanchored.
    mrc=$(sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p' \
          "${ev:-/dev/null}/rejoin_$A.txt" 2>/dev/null | head -1)
    [ -z "$mrc" ] && mrc=$(sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p' \
                           "$OUT/lap_$i.log" | head -1)
    # The refusal is printed on the SURVIVOR, not in the harness's stdout — and
    # it must be read from THIS LAP'S WINDOW.  dmesg is a kernel ring buffer:
    # it survives the module reload a prep performs, so an unwindowed count is
    # cumulative over every lap since the node last booted and reports the same
    # number lap after lap (measured: atomic_skips=19 identical on six laps, all
    # of it from earlier laps).  The harness stamps AGSHUT-<label> into kmsg at
    # its start; cut there.
    MKW="AGSHUT-${LABEL}l$i"
    rs 40 "$B" "dmesg | sed -n '/$MKW/,\$p' | grep -a 'P273-SHADOW-EVAL' | tail -1" > "$OUT/shadow_$i.txt" 2>/dev/null
    rs 40 "$B" "dmesg | sed -n '/$MKW/,\$p' | grep -ac 'ATOMIC-SKIP'" > "$OUT/skips_$i.txt" 2>/dev/null
    rs 40 "$B" "dmesg | sed -n '/$MKW/,\$p' | grep -a 'P227-FR-TORN-UNPUBLISHED' | tail -1" > "$OUT/torn_$i.txt" 2>/dev/null
    rs 40 "$A" "dmesg | sed -n '/$MKW/,\$p' | grep -ac 'RELEASE-POISONED ino-free'" > "$OUT/inofreegate_$i.txt" 2>/dev/null
    rs 40 "$A" "dmesg | sed -n '/$MKW/,\$p' | grep -ac 'RELEASE-POISONED ag='" > "$OUT/aggate_$i.txt" 2>/dev/null
    vec=$(sed 's/^.*P273-SHADOW-EVAL/P273/' "$OUT/shadow_$i.txt" | \
          grep -ao 'buf=[0-9]*\|classless=[0-9]*\|untagged=[0-9]*\|badst=[0-9]*\|notheld=[0-9]*\|staleep=[0-9]*\|wlineage=[0-9]*\|manerr=[0-9]*\|winc=[0-9]*\|fowner=[0-9]*\|WOULD_APPLY=[0-9]*' | tr '\n' ' ')
    skip=$(tr -dc '0-9' < "$OUT/skips_$i.txt" 2>/dev/null)
    torn=$(grep -ao 'refused [0-9]* committed' "$OUT/torn_$i.txt" 2>/dev/null | head -1)
    # A LAP THAT DID NOT KILL ANYTHING DECIDES NOTHING.  The harness asserts
    # its own non-vacuity ("the injected log error shut A's filesystem down");
    # without that PASS there was no death, so the slice was never replayed and
    # this lap belongs in neither column.  Counting one as a success is how a
    # broken rig reports a fixed defect.
    if grep -aq 'PASS the injected log error shut' "$OUT/lap_$i.log"; then
        valid=yes
        if [ "${mrc:-x}" = 0 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi
    else
        valid=NO-DEATH
        vac=$((vac+1))
    fi
    ifg=$(tr -dc '0-9' < "$OUT/inofreegate_$i.txt" 2>/dev/null)
    agg=$(tr -dc '0-9' < "$OUT/aggate_$i.txt" 2>/dev/null)
    echo "LAP $i arm=$ARM prep=$prepped valid=$valid harness_rc=$lrc mount_rc=${mrc:-none} atomic_skips=${skip:-?} ${torn:-no-refusal} poisongate[ino-free=${ifg:-?} ag=${agg:-?}]"
    echo "     $vec"
    [ -n "$ev" ] && echo "     evidence=$ev"
done
echo "D0944-DEATH label=$LABEL arm=$ARM laps=$LAPS valid=$((ok+bad)) rejoin_ok=$ok rejoin_bad=$bad vacuous=$vac wall=$(( $(date +%s) - s ))s evidence=$OUT"
