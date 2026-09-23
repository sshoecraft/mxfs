#!/bin/bash
# d0941_cc_loop.sh — loop the cache_coherency board row and harvest, per lap,
# the kernel evidence that discriminates WHY a peer's dirent stayed visible.
#
# WHAT THIS ROW'S FAILURE ACTUALLY IS -- the framing this header carried first
# was wrong and is kept corrected rather than deleted, because the wrong one is
# the natural reading and someone will arrive at it again.
#
# It was filed as "a node's view of a shared directory lags its peer across a
# barrier".  It is not.  The directory view is CORRECT and the LOOKUP fails: a
# node holds a stale in-core shell for an inode number the peer recycled,
# poisons it, cannot retire it, and returns -ESTALE for a file that exists and
# whose dirent resolves.  `ls` drops the failed names, so the peer's directory
# reads short -- 128 became 104, and exactly 24 names had hit
# P34H-POISON-UNRETIRED.
#
# The reference blocking retirement is the poisoning itself: setting the flag
# also takes an igrab and hands it to a revocation work item that drops it only
# once it runs.  Measured, poison to revocation is 2.9 ms at best and 68 ms at
# worst; the retry loop spent 23 MICROSECONDS across four attempts with no delay
# at all.  It was not a race that was sometimes lost.
#
# So the per-lap counters below are a RATIO, not a list of symptoms:
#   poison_n > 0 with unretired == 0 and lkerr116 == 0   the fix working
#   unretired tracking poison_n                          the defect
#   poison_n == 0                                        the lap proved NOTHING
#
# The last line is the one that matters most.  Natural poisons need a
# cross-incarnation reload with the cluster buffer protected, which happened in
# ONE lap out of eighteen here and in none of three purpose-built reproducers.
# Set POISON_NTH to make them happen (see the knob block below); a green lap
# with poison_n=0 is silence, not evidence.
#
# The other counters are kept because they were how the wrong framing was RULED
# OUT, and re-ruling it out costs nothing:
#   P134-IDENTICAL-BUFSTALE  the reload's "disk == in-core" verdict issued on a
#                            buffer BEHIND the coherent medium.  Before 0.75.98
#                            this compared only mode and generation -- neither
#                            of which moves when a peer changes dirents -- so it
#                            could not fire for this defect at all, and its
#                            silence in every earlier run proved nothing.
#   P3-REFUSE-OLDER-DISK     the reload refused a disk image below our in-core
#                            version and kept our fork.
#   P-RELOAD-IDENTICAL       the reload decided nothing changed.
#   P68-EVDECIDE undurable=1 a cached dir data block KEPT because it was not
#                            durable.
#   P127-DIRMISS             the opposite direction, collected so a lap failing
#                            the other way is not misread as this defect.
#
# the budget rule (derived): the row's manifest budget is 60 s; run.sh adds ~15 s startup
# and ~12 s of per-test fan-out, so a lap is ~87 s and the per-lap bound is 130 s
# (that budget plus margin for a slow mount check, not a round number).  The
# evidence pull is two ssh calls per node bounded at 45 s each.  LAPS=6 => a
# ceiling near 18 min; a lap that overruns 130 s is recorded FAIL, never widened.
#
# Usage: tests/d0941_cc_loop.sh <label> [LAPS=6]
set -u
LABEL=${1:?label}
LAPS=${2:-6}
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
MNT=${MXFS_MOUNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0941_$LABEL
mkdir -p "$OUT"

filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
echo "=== d0941_cc_loop label=$LABEL laps=$LAPS tree_sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

# Precondition: both nodes mounted AND running the tree's build.  A lap run
# against a stale module measures the previous build and its evidence is a lie
# about which code produced it, so this is fatal rather than a warning.
bad=0
for n in $A $B; do
    info=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)")
    echo "  INFO $n $info"
    echo "$info" | grep -q "sv=$SV" || { echo "  PRECOND $n srcversion != tree ($SV)"; bad=1; }
    echo "$info" | grep -q "mounted=1" || { echo "  PRECOND $n not mounted"; bad=1; }
done
[ "$bad" = 0 ] || { echo "RESULT: INFRA label=$LABEL precondition not met"; exit 2; }

# Optional knobs, applied live on both nodes and READ BACK.  Both are 0644, so
# the control and the fixed behaviour can be measured in ONE boot with no
# re-prep between them -- which matters, because a prep would also reset every
# other piece of accumulated state and make the two arms incomparable.
# Readback is not ceremony: a knob that silently failed to apply turns the
# control arm into a second copy of the treatment arm and the A/B into nothing.
for knob_pair in "dbg_poison_nth:${POISON_NTH:-}" "poison_retire_wait:${RETIRE_WAIT:-}"; do
    knob=${knob_pair%%:*}; val=${knob_pair#*:}
    [ -n "$val" ] || continue
    for n in $A $B; do
        rs 20 "$n" "echo $val > /sys/module/mxfs/parameters/$knob" >/dev/null
        got=$(rs 20 "$n" "cat /sys/module/mxfs/parameters/$knob")
        echo "  KNOB $n $knob=$got (wanted $val)"
        [ "$got" = "$val" ] || { echo "RESULT: INFRA label=$LABEL $n $knob readback=$got wanted=$val"; exit 2; }
    done
done

pass=0; fail=0; infra=0
for lap in $(seq 1 "$LAPS"); do
    mark="D0941-$LABEL-lap$lap-$(date -u +%H%M%S)"
    for n in $A $B; do rs 20 "$n" "echo $mark > /dev/kmsg" >/dev/null; done

    t0=$(date +%s)
    timeout 130 ./run.sh 2 tcp cache_coherency > "$OUT/lap${lap}_run.log" 2>&1
    rc=$?
    wall=$(( $(date +%s) - t0 ))

    # run.sh prints the row verdict as a leading word, not a bracketed tag:
    #   "  PASS  cache_coherency  (nodes_pass=2/2 ... ) [9s/60s]"
    # An earlier version of this line looked for "[PASS]" and matched nothing,
    # so six clean laps were recorded as NO_TERMINAL_RECORD.  A verdict parse
    # that silently fails reads as a capture failure and would have been
    # diagnosed as a rig problem, so it is anchored to the row name here.
    verdict=$(sed -n 's/^ *\(PASS\|FAIL\|SKIP\) *cache_coherency .*/\1/p' \
              "$OUT/lap${lap}_run.log" | tail -1)
    [ -n "$verdict" ] || verdict="NO_TERMINAL_RECORD(rc=$rc)"
    detail=$(grep -a ' cache_coherency ' "$OUT/lap${lap}_run.log" | tail -1)

    # Per-node kmsg window for THIS lap only: everything the node logged after
    # its own marker.  Taking the whole ring instead would fold in the previous
    # lap's probe lines and produce exactly the false correlation this defect
    # has already survived once.
    for n in $A $B; do
        rs 45 "$n" "dmesg | awk '/$mark/{f=1} f'" > "$OUT/lap${lap}_${n}_kmsg.txt" 2>/dev/null
    done

    line="lap=$lap verdict=$verdict wall=${wall}s rc=$rc"
    for n in $A $B; do
        k="$OUT/lap${lap}_${n}_kmsg.txt"
        line="$line | $n bufstale=$(grep -ac 'P134-IDENTICAL-BUFSTALE' "$k")"
        line="$line refuse_older=$(grep -ac 'P3-REFUSE-OLDER-DISK' "$k")"
        line="$line reload_ident=$(grep -ac 'P-RELOAD-IDENTICAL' "$k")"
        line="$line evkept=$(grep -a 'P68-EVDECIDE' "$k" | grep -ac 'undurable=1')"
        line="$line dirmiss=$(grep -ac 'P127-DIRMISS' "$k")"
        # The two decisions that keep an in-core image over a peer's: the
        # cluster buffer was never staled, and the coherent re-read was
        # obtained and then refused.  Both are ungated pr_warns.
        line="$line protect=$(grep -ac 'P91-RELOAD-PROTECT' "$k")"
        line="$line selfahead=$(grep -ac 'P34E-FRESHSRC-SELFAHEAD-SKIP' "$k")"
        line="$line freshsrc=$(grep -ac 'P34D-RELOAD-FRESHSRC' "$k")"
        # D-0941: poison_n is the true count (an unratelimited counter at the
        # poison site); unretired and lkerr116 are the defect itself.  The
        # verdict is the RATIO -- poisons happening with zero unretired shells
        # is the fix working, and zero poisons means the lap proved nothing.
        line="$line inject=$(grep -ac 'P566-POISON-INJECT' "$k")"
        line="$line poison_n=$(grep -ac 'P566-POISON-N' "$k")"
        line="$line unretired=$(grep -ac 'P34H-POISON-UNRETIRED' "$k")"
        line="$line lkerr116=$(grep -a 'P-LKERR' "$k" | grep -ac 'err=-116')"
    done
    echo "$line" | tee -a "$OUT/laps.txt"
    echo "    ROW $detail" | tee -a "$OUT/laps.txt"

    case "$verdict" in
        PASS) pass=$((pass+1)) ;;
        FAIL) fail=$((fail+1))
              # Name the failing assertion(s): the board line only prints a
              # count, and which NAME survived is what points at the mechanism.
              grep -aE 'FAIL|failed' "$OUT/lap${lap}_run.log" | head -20 \
                  > "$OUT/lap${lap}_failing_checks.txt"
              echo "    FAILING: $(head -5 "$OUT/lap${lap}_failing_checks.txt" | tr '\n' ' ')" ;;
        *) infra=$((infra+1)) ;;
    esac
done

echo "RESULT: label=$LABEL laps=$LAPS pass=$pass fail=$fail infra=$infra sv=$SV evidence=$OUT"
[ "$fail" = 0 ] && [ "$infra" = 0 ]
