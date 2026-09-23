#!/bin/bash
# d0945_chokepoint_positive_control.sh — can the choke-point probe fire at all?
#
# 0.75.115 added dlm_note_release_while_poisoned() at mxfs_dlm_unlock_gen and
# mxfs_dlm_send_unconditional_release, the two primitives every release funnels
# through, so that a release performed while this node's session is POISONED is
# named with its call site.  Its purpose is to answer, by measurement, the
# question D-0945 could otherwise only answer by reading every caller: which
# release paths still owe a refusal?
#
# Ten death laps produced ZERO P945-RELEASE-WHILE-POISONED lines.
#
# THAT NUMBER IS WORTH NOTHING UNTIL THE PROBE IS SHOWN TO BE ABLE TO FIRE.
# A silent instrument and a clean system are the same observation, and this is
# the SECOND time in this campaign that exact ambiguity has come up: the poison
# gate itself logged only on refusal, so "did not refuse" and "was never
# reached" were indistinguishable, which is why D-0945 sat unreproduced for a
# session.  Repeating the mistake one layer down would be indefensible.
#
# THE POSITIVE CONTROL, and why this particular one is exact.
# poison_gate_ino_free is a 0644 module parameter.  With it at 1,
# mxfs_v5_dlm_inode_unlock_free consults v5_tcp_release_gate, gets -ESHUTDOWN
# and RETURNS — so it never reaches mxfs_dlm_unlock_gen, and the choke-point
# probe correctly stays silent.  Set it to 0 and that same call falls through
# into mxfs_dlm_unlock_gen *while the session is poisoned*, which is precisely
# the condition the choke point exists to detect.
#
# So this run has a defined right answer in BOTH directions, which is what makes
# it a control rather than another measurement:
#
#   gate=1  ->  P945-INO-FREE-RELEASE gated=1, a refusal line, and NO
#               choke-point line (the wrapper returned before the primitive).
#   gate=0  ->  P945-INO-FREE-RELEASE gated=0, NO refusal line, and a
#               choke-point line naming fn=unlock_gen and the caller.
#
# If gate=0 produces no choke-point line, the instrument is dead and the ten
# laps' zero census means nothing — that is the finding, and it must be reported
# as such rather than filed as "all release paths are gated".
#
# It also reproduces D-0945's original defect ON DEMAND, which that record still
# owes: with the gate off, this is the exact ungated free that surrendered a
# durable grant and cost the cluster its mount.
#
# THE KNOB IS RESTORED even when the run fails or is interrupted — leaving a
# node with its poison gate disabled would silently arm the very defect this
# harness studies for every later run on this rig.
#
# THE SURVIVOR'S VERDICT IS PART OF THE MEASUREMENT.  The defect's cost is paid
# on the survivor: its fence-time manifest does not hold the released inode, its
# replay answers notheld to a VALID token, skips the transaction and quarantines
# the AGs.  So every attempt also reads B's log from the same marker: the
# P273-SHADOW-EVAL vector, ATOMIC-SKIP, P227-FR-TORN-UNPUBLISHED, P240-QUAR-AG-EIO
# and P163-RECOVERY-COMPLETE.  With the gate on, all of those must be clean.
#
# TIMING, measured on s582a: the periodic reclaim landed the ungated release
# 2.65 s after the shutdown, and the survivor had sealed the fence 0.2 s
# earlier (the withdrawal is explicit, so the fence needs no timeout: about
# 2.4 s from shutdown to seal on this rig), so the master refused it as a
# release from a sealed owner (P-TAUTH-SEALED-RELEASE-REFUSED).  In the natural
# laps the reclaim came 1.2 s after the shutdown, before the seal, and the
# master accepted it -- that is the defect.  So the reclaim is forced
# (drop_caches runs the inode shrinker) immediately after the trigger, which
# puts the release inside the window the victim-side gate exists to close;
# s582b measured it there (sealed-owner refusals 0, the manifest sealed one
# entry short).  The count of sealed-owner refusals is reported per arm so the
# record can say which line of defence answered.
#
# derived time budget per attempt: 2-node prep bounded 137 s (measured 50 s),
# prime 5 s, trigger 10 s, forced reclaim + bounded wait 50 s, survivor replay
# wait bounded 60 s (seal measured ~30 s after the shutdown, replay 6 s), reads
# 10 s: 272 s.  Two arms x ATTEMPTS=2 bounds the run at 1090 s.
#
# Usage: tests/d0945_chokepoint_positive_control.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
MNT=/mnt/shared
SSH=tools/mxfs_sshpass.sh
GATE=/sys/module/mxfs/parameters/poison_gate_ino_free
# THE TRIGGER.  See the block comment below: the ordinary injected log-error
# death never frees an inode while poisoned, so it cannot exercise this path.
DIALLOC_SHUT=/sys/module/mxfs/parameters/dbg_dialloc_shutdown
MNTD=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0945ctl_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

restore() { rs 25 "$A" "echo 1 > $GATE 2>/dev/null; echo 0 > $DIALLOC_SHUT 2>/dev/null; echo restored_gate=\$(cat $GATE 2>/dev/null) trigger=\$(cat $DIALLOC_SHUT 2>/dev/null)"; }
trap 'echo "  INFO restoring the poison gate: $(restore)"' EXIT INT TERM

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0945_chokepoint_positive_control label=$LABEL sv=$SV $(date -u +%FT%TZ) ==="

# The probe must EXIST in the running build, or the whole run is a tautology.
have=$(strings mxfs.ko | grep -c 'P945-RELEASE-WHILE-POISONED')
echo "  INFO tree module carries the choke-point probe: $have"
[ "$have" -ge 1 ] || { echo "RESULT: FAIL the built module has no P945-RELEASE-WHILE-POISONED string — nothing to control for"; exit 2; }

# EACH ARM MUST GET A NON-VACUOUS LAP, so each arm is retried.
# The free path is reached on only about one death lap in three (measured: 2 of
# 6, then 1 of 10), so a single lap per arm decides nothing most of the time --
# the first run of this harness burned both arms on vacuous laps and then, worse,
# reported PASS.  ATTEMPTS bounds the retry; a bound is not a safety net, it is
# the point at which the run reports that it could not answer the question.
ATTEMPTS=${ATTEMPTS:-4}
fails=0; decided1=no; decided0=no
for gate in 1 0; do
    set_rc=$(rs 25 "$A" "echo $gate > $GATE 2>/dev/null; echo rc=\$? now=\$(cat $GATE)")
    echo "--- arm gate=$gate ($set_rc) ---"
    case "$set_rc" in
        *"now=$gate"*) ;;
        *) echo "  FAIL could not set $GATE to $gate ($set_rc)"; fails=$((fails+1)); continue ;;
    esac

  for att in $(seq 1 "$ATTEMPTS"); do
    # READINESS FIRST.  agmeta_shutdown_retire.sh requires BOTH nodes mounted and
    # a death lap leaves its victim unmounted when the rejoin fails, so without
    # this the next lap dies on its own precondition and is scored as if it had
    # answered nothing -- which is how the gate=0 arm was lost on the first run.
    # A SHUT-DOWN FILESYSTEM IS STILL IN /proc/mounts.  Counting mounts alone
    # called a dead mount "ready", so every attempt after the first ran against
    # a filesystem that could not create anything -- which is why their `left=1`
    # says the one-shot injector was never even consumed.  Probe with a real
    # create; only a filesystem that can still allocate an inode is ready.
    mounted=$(for n in $A $B; do rs 25 "$n" "touch $MNT/.d0945probe 2>/dev/null && rm -f $MNT/.d0945probe 2>/dev/null && echo -n 1 || echo -n 0"; done | tr -d '\n')
    if [ "$mounted" != "11" ]; then
        echo "  INFO nodes not writable (probe='$mounted', 1=create succeeded) — prepping before the lap"
        timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_g${gate}_$att.log" 2>&1
        echo "  INFO prep rc=$? ; re-arming the gate"
        rs 25 "$A" "echo $gate > $GATE 2>/dev/null" >/dev/null
    fi

    # THE ORDINARY INJECTED DEATH CANNOT EXERCISE THIS PATH -- measured, not
    # assumed.  Across 16 death laps the free-while-poisoned event occurred
    # exactly 3 times, and all 3 coincide EXACTLY with the 3 D-0946 double
    # allocations (s573fixl3, s573fixl6, s575fixl7); every lap whose injected
    # log error actually fired (left<4, op_errs>0) reached it zero times.  The
    # reason is mechanical: D-0945's free is the create-failure path reclaiming
    # the inode xfs_dialloc had just handed out (P88-PUBOB-RECLAIM shutdown=1),
    # so it needs a CREATE THAT FAILS WITH THE TRANSACTION DIRTY -- which is
    # what a log-error injection at iclog write does not produce.  Eight laps
    # driven that way returned INCONCLUSIVE for exactly this reason.
    #
    # dbg_dialloc_shutdown is that shape on demand: xfs_inode.c:2923 forces
    # error=-EFSCORRUPTED with the transaction already dirtied by xfs_dialloc,
    # which its own probe text calls "the exact signature of the natural
    # stale-inode dialloc corruption".  It is one-shot (a cmpxchg consumes the
    # arm) and gated to multi-node mounts, so it fires for exactly one create.
    lap=$OUT/lap_gate${gate}_$att.log
    # WINDOW EVERY READ.  An unwindowed `dmesg | tail` reports the PREVIOUS
    # attempt's P-CR3-CANCEL as this one's -- it did exactly that here, showing
    # cr3=1 on attempts whose own `left=1` proves the injector never fired.
    MK="D0945CTL-g${gate}a${att}-$(date +%s%N)"
    for n in $A $B; do rs 25 "$n" "echo '$MK' > /dev/kmsg 2>/dev/null" >/dev/null; done
    # THE FREE THIS DEFECT IS ABOUT IS A RECLAIM, NOT A CREATE.  Read from the
    # natural laps (s573fixl3/l6): the inode freed while poisoned was the
    # PREVIOUS incarnation of a number unlinked seconds before the failed
    # create -- its inactivation committed the ifree and deferred the
    # destaging (P128-INACT-DEFER: the in-core inode stays cached with its
    # grant, reclaimable), and 1.2 s after the shutdown the periodic reclaim
    # worker reclaimed that cached copy (P88-PUBOB-RECLAIM nlink=0 shutdown=1
    # comm=kworker), which is the free-release path.  Eight control attempts
    # were vacuous because this workload only ever CREATED: no deferred-free
    # inode was cached at the shutdown, so nothing could be reclaimed while
    # poisoned.  Prime one here, right before the trigger, and then wait out
    # the reclaim period (xfs_syncd_centisecs, 30 s) rather than the
    # withdrawal.
    # The primed inode is named (ls -i before the unlink) so the poisoned
    # free can be tied to IT, and its deferred state is confirmed from the
    # log (P128-INACT-DEFER for that number: ifree committed, grant cached)
    # rather than assumed from the unlink having returned.
    rs 60 "$A" "mkdir -p $MNTD/d0945ctl && : > $MNTD/d0945ctl/prime_$att && sync -f $MNTD && echo PRIME_INO=\$(ls -i $MNTD/d0945ctl/prime_$att | awk '{print \$1}') && rm -f $MNTD/d0945ctl/prime_$att && sync -f $MNTD && sleep 1 && echo PRIMED" > "$lap" 2>&1
    prime_ino=$(grep -ao 'PRIME_INO=[0-9]*' "$lap" | head -1 | cut -d= -f2)
    prime_def=$(rs 25 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'P128-INACT-DEFER ino=${prime_ino:-0} '")
    echo "  INFO primed ino=${prime_ino:-none} (create+unlink+sync) deferred-free confirmed in log: ${prime_def:-0} at $(date -u +%T)"
    arm=$(rs 25 "$A" "echo 1 > $DIALLOC_SHUT 2>/dev/null; echo armed=\$(cat $DIALLOC_SHUT)")
    echo "  INFO gate=$gate attempt $att/$ATTEMPTS trigger $arm"
    rs 120 "$A" "for i in 1 2 3 4 5 6 7 8; do : > $MNTD/d0945ctl/t\$i 2>/dev/null; done; sync -f $MNTD 2>/dev/null; echo TRIGGER_DONE left=\$(cat $DIALLOC_SHUT) mounted=\$(grep -c ' $MNTD mxfs ' /proc/mounts)" >> "$lap" 2>&1
    echo "  INFO $(grep -a 'TRIGGER_DONE' "$lap" | head -1)"
    # Force the reclaim NOW, before the survivor can seal the fence (see the
    # header: the periodic worker arrived after the seal on s582a).  drop_caches
    # runs the superblock shrinker, which reclaims the cached deferred-free
    # inode; on a shut-down filesystem that is the same reclaim the periodic
    # worker performs.  Then wait for the free-path probe, bounded by the
    # reclaim period in case the shrinker did not take it, and read the window.
    rs 100 "$A" "sync; echo 2 > /proc/sys/vm/drop_caches; for i in \$(seq 1 50); do dmesg | sed -n '/$MK/,\$p' | grep -aq 'P945-INO-FREE-RELEASE\|P945-RELEASE-WHILE-POISONED' && break; sleep 1; done; dmesg | sed -n '/$MK/,\$p'" >> "$lap" 2>&1

    # THE SURVIVOR.  Wait for its recovery of A's slice to finish, then read
    # the verdict from the same marker.  A recovery that has not completed
    # inside the bound is reported as such, never scored clean.
    surv=$OUT/survivor_gate${gate}_$att.log
    rs 90 "$B" "for i in \$(seq 1 60); do dmesg | sed -n '/$MK/,\$p' | grep -aq 'P163-RECOVERY-COMPLETE\|P241-RECOV-TERMINAL' && break; sleep 1; done; dmesg | sed -n '/$MK/,\$p'" > "$surv" 2>&1
    s_lines=$(wc -l < "$surv")
    s_done=$(grep -ac 'P163-RECOVERY-COMPLETE' "$surv")
    s_term=$(grep -ac 'P241-RECOV-TERMINAL' "$surv")
    s_skip=$(grep -ac 'ATOMIC-SKIP' "$surv")
    s_torn=$(grep -ac 'P227-FR-TORN-UNPUBLISHED' "$surv")
    s_quar=$(grep -ac 'P240-QUAR-AG' "$surv")
    s_sealref=$(grep -ac 'P-TAUTH-SEALED-RELEASE-REFUSED' "$surv")
    s_notheld=$(grep -a 'P273-SHADOW-EVAL' "$surv" | grep -ao 'notheld=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
    echo "  SURVIVOR gate=$gate lines=$s_lines recovery_complete=$s_done terminal=$s_term notheld=${s_notheld:-none} atomic_skips=$s_skip torn=$s_torn quarantine=$s_quar sealed_owner_refusals=$s_sealref"

    win=$OUT
    chok=$(grep -ah 'P945-RELEASE-WHILE-POISONED' "$lap" 2>/dev/null | sort -u)
    inof=$(grep -ah 'P945-INO-FREE-RELEASE' "$lap" 2>/dev/null | sort -u)
    # grep -c prints its 0 AND exits 1, so an `|| echo 0` here doubles the
    # zero ("0\n0"), which is what s582a/b printed.
    refu=$(grep -ahc 'P-TCP-RELEASE-POISONED ino-free=' "$lap" 2>/dev/null)
    cr3=$(grep -ahc 'P-CR3-CANCEL' "$lap" 2>/dev/null)
    echo "  INFO trigger fired (P-CR3-CANCEL lines): $cr3"
    nchok=$( [ -n "$chok" ] && echo "$chok" | wc -l || echo 0)
    ninof=$( [ -n "$inof" ] && echo "$inof" | wc -l || echo 0)
    { echo "gate=$gate chokepoint=$nchok inofree=$ninof refusals=$refu"; echo "$chok"; echo "$inof"; } > "$OUT/measure_gate$gate.txt"
    echo "  MEASURE gate=$gate chokepoint_lines=$nchok inofree_lines=$ninof refusals=$refu primed_ino=${prime_ino:-none} primed_ino_freed_while_poisoned=$(grep -ac "P945-INO-FREE-RELEASE ino=${prime_ino:-0} " "$lap") evidence=$win"
    [ -n "$chok" ] && echo "$chok" | head -6 | cut -c1-190 | sed 's/^/      /'
    [ -n "$inof" ] && echo "$inof" | head -3 | cut -c1-190 | sed 's/^/      /'

    # VACUITY FIRST.  If no inode was freed while poisoned, this lap exercised
    # nothing and neither arm's expectation applies to it.
    if [ "$ninof" = 0 ]; then
        echo "  INFO gate=$gate attempt $att did NOT reach the free path while poisoned — retrying"
        continue
    fi

    if [ "$gate" = 1 ]; then
        [ "$nchok" = 0 ] || { echo "  FAIL gate=1 produced $nchok choke-point line(s); the wrapper should have returned before the primitive"; fails=$((fails+1)); }
        [ "${refu:-0}" -ge 1 ] || { echo "  FAIL gate=1 produced no ino-free refusal line"; fails=$((fails+1)); }
        # The fix's whole point: with the release refused at the victim, the
        # survivor's manifest still holds the grant and its replay is clean.
        # An empty survivor capture is a failed read, not a clean survivor.
        [ "$s_lines" -ge 1 ] || { echo "  FAIL gate=1 survivor capture is EMPTY — nothing was read from $B"; fails=$((fails+1)); }
        [ "$s_done" -ge 1 ] || { echo "  FAIL gate=1 survivor did not report P163-RECOVERY-COMPLETE inside the bound (terminal=$s_term)"; fails=$((fails+1)); }
        [ "${s_notheld:-1}" = 0 ] || { echo "  FAIL gate=1 survivor replay answered notheld=${s_notheld:-none} — the manifest did not hold a grant the slice needed"; fails=$((fails+1)); }
        [ "$s_skip" = 0 ] && [ "$s_torn" = 0 ] && [ "$s_quar" = 0 ] || { echo "  FAIL gate=1 survivor skipped/refused/quarantined (skips=$s_skip torn=$s_torn quarantine=$s_quar)"; fails=$((fails+1)); }
        [ "$s_sealref" = 0 ] || { echo "  FAIL gate=1 the master saw $s_sealref release(s) from the sealed owner — something left the victim despite the gate"; fails=$((fails+1)); }
    else
        if [ "$nchok" -ge 1 ]; then
            echo "  PASS INSTRUMENT LIVE — with the gate off, the ungated free reached the primitive and the choke point named it"
            if [ "$s_sealref" -ge 1 ]; then
                echo "  INFO gate=0 the release reached the master AFTER the seal and the sealed-owner check refused it ($s_sealref) — the master's second line of defence answered, not the victim gate"
            else
                echo "  INFO gate=0 the release reached the master BEFORE the seal (sealed-owner refusals=0) — the grant left the manifest; this is the defect's own timing"
            fi
        else
            echo "  FAIL INSTRUMENT DEAD — the gate was off, the free path ran while poisoned, and the choke point said nothing."
            echo "       The zero census over the death laps therefore proves NOTHING about which release paths are gated."
            fails=$((fails+1))
        fi
    fi
    if [ "$gate" = 1 ]; then decided1=yes; else decided0=yes; fi
    break
  done
done

echo "  INFO final gate state: $(restore)"
# A RUN THAT DECIDED NOTHING IS NOT A PASS.
# The first cut of this harness printed PASS after BOTH arms came back vacuous,
# because it only counted assertion failures and a vacuous arm raises none.
# "No evidence against" is not "verified" -- reporting it as PASS is precisely
# how a defect gets written off, so an undecided arm is its own non-zero result.
if [ "$decided1" != yes ] || [ "$decided0" != yes ]; then
    echo "RESULT: INCONCLUSIVE label=$LABEL gate1_decided=$decided1 gate0_decided=$decided0 attempts=$ATTEMPTS evidence=$OUT"
    echo "  READ: the free-while-poisoned path was not reached in every arm, so the"
    echo "        instrument is NEITHER proven live NOR proven dead. The zero"
    echo "        choke-point census still means nothing. Re-run with more ATTEMPTS."
    exit 3
fi
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
