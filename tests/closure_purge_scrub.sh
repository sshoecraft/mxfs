#!/bin/bash
# closure_purge_scrub.sh — D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356
# verification (sess363 RULE-5 ruling, landed sess374 / 0.14.3).
#
# THE DEFECT (measured sess356, live-reproduced sess360 on 0.14.1): when a
# foreign-slice replay is REFUSED, the victim's domain is quarantined
# cluster-wide — correctly.  But the victim ALSO still holds on-disk DLM
# grants on resources the refusal says nothing about; the root inode's EX from
# an AG-scoped refusal is the measured case.  Those grants freeze forever with
# no owner: `touch /mnt/shared/anything` on a survivor goes D-state in
# caw_wait_for_grant, polls to DLM -110, and the cluster shuts down (sess356:
# 4 clean umounts took -110, then the fleet).
#
# THE FIX has two halves, and this test exercises BOTH:
#   PUBLISHER — the refusal publisher, still holding the recovery lease, scans
#               the CAW slot table and strips the victim's state from every
#               slot whose resource is PROVABLY outside the quarantined AG
#               mask.  Evidence: P299-CLOSURE-PURGE ... purged=N (N>0) and
#               P299-CLOSURE-STRIP lines on the replayer.
#   SURVIVOR  — any node BLOCKED on victim-owned out-of-closure state repairs
#               that slot on demand, with no lease.  Evidence:
#               P299-SCRUB-STRIP on a survivor.
# Either half unblocking the probe is a pass for the DEFECT; the run reports
# which one did it, because they have different failure modes.
#
# WHY THE AG MASK MATTERS: shape 1 forges an AG-mask refusal, and its default
# mask is ag0 — which is where the root inode lives, so under the default the
# root EX is IN closure and correctly STAYS frozen.  This test forges a mask
# that EXCLUDES ag0 (freplay_force_ag_mask, default 0x2 = ag1), which is the
# only configuration under which the fix has anything to do.
#
# Usage: tests/closure_purge_scrub.sh <N> <victim> [ag_mask_hex]
#   N          node count (test1..testN); knob armed on all survivors
#   victim     hostname to virsh destroy (must be in range, not test1)
#   ag_mask    forged refused-AG bitmask (default 0x2 = ag1).  MUST NOT
#              include bit 0 or the test cannot discriminate.
#
# Env:
#   SCRUB_ONLY=1   arm closure_skip_publisher_purge on every survivor, so the
#                  publisher half is suppressed and ONLY the survivor demand
#                  scrub can repair.  This is the half that must work when the
#                  publisher dies mid-scan or was itself the node that died
#                  (ruling hazard 7); without this flag the publisher always
#                  wins the race and the scrub gets no coverage.
#   VICTIM_LOAD=s  seconds of un-synced root-dir churn on the victim before the
#                  kill (default 6).  This is what leaves the victim holding a
#                  HOT root-dir EX at death — the exact grant sess360 measured
#                  stranded.  A victim that syncs and idles may have handed
#                  its grants away, and then the run proves only that the
#                  machinery is reachable, not that it repairs a live block.
#
# RULE 0 budget: the probe is one `touch` in the root dir.  Native XFS does
# that in milliseconds; MXFS pays one DLM round trip.  PROBE_BUDGET (default
# 20s) is the assertion — a probe that takes longer has NOT been unblocked,
# and the test FAILS even if it eventually completes.
#
# The test leaves the FS with a durable quarantine on the victim's domain —
# re-prep (./run.sh N caw prep_cluster) before any other board test.
# Exit 0 = all assertions PASS.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: closure_purge_scrub.sh <N> <victim> [ag_mask_hex]}"
VICTIM="${2:?usage: closure_purge_scrub.sh <N> <victim> [ag_mask_hex]}"
AGMASK="${3:-0x2}"
MNT=/mnt/shared
# HB confirm window ~62s + fence + replay + publish + import lap slack.
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"
PROBE_BUDGET="${PROBE_BUDGET:-20}"
VICTIM_LOAD="${VICTIM_LOAD:-6}"
SCRUB_ONLY="${SCRUB_ONLY:-0}"
# sess376 (for D-CLOSURE-REMOTE-WAITER-NO-REPAIR-BEFORE-PUBLICATION-376):
# PUBLISHER DEATH *BEFORE* PUBLICATION.  Ruling hazard 7 covered the publisher
# dying AFTER it published; this is its twin.  The window is normally 418ms
# (measured sess376: P299-CLOSURE-SCAN ENTRY 14028.136 -> PUBLISHED 14028.554),
# far too short to hit by hand, so the timing knob widens it: the scan pauses at
# the first candidate slot (who=1 restricts it to the scan, never a waiter's
# demand scrub) and the publisher is destroyed while parked there.  Nothing
# about the fix is disabled — only the scan's own clock is stretched.
KILLPUB="${KILLPUB:-0}"
KILLPUB_MS="${KILLPUB_MS:-60000}"

[ "$VICTIM" = "${PROBE_HOST:-test1}" ] && { echo "FAIL: victim and probe host are the same node — set PROBE_HOST"; exit 1; }
INCLOSURE="${INCLOSURE:-0}"
if [ $(( AGMASK & 1 )) -ne 0 ] && [ "$INCLOSURE" != "1" ]; then
    echo "FAIL: ag_mask $AGMASK includes ag0 — the root inode would be IN"
    echo "      closure and the out-of-closure purge would correctly do"
    echo "      nothing.  Pick a mask without bit 0, or set INCLOSURE=1 to"
    echo "      deliberately measure the IN-closure arm instead."
    exit 1
fi
if [ "$INCLOSURE" = "1" ] && [ $(( AGMASK & 1 )) -eq 0 ]; then
    echo "FAIL: INCLOSURE=1 needs a mask that INCLUDES ag0 (the probe's AG)"
    exit 1
fi

T0=$(date -u +%FT%TZ)
echo "=== closure_purge_scrub: N=$N victim=$VICTIM ag_mask=$AGMASK @ $T0 ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

# 1. Arm the one-shot refusal knob + the forged AG mask on every survivor.
#    Only the elected replayer consumes it; the rest are disarmed at the end.
echo "--- arming freplay_force_refusal=1 ag_mask=$AGMASK on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo $SCRUB_ONLY > /sys/module/mxfs/parameters/closure_skip_publisher_purge;
                 echo $(( KILLPUB ? 1 : 0 )) > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                 echo 1 > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                 echo -1 > /sys/module/mxfs/parameters/caw_inject_closure_pause_slot;
                 echo $KILLPUB_MS > /sys/module/mxfs/parameters/caw_inject_closure_pause_ms;
                 echo $(( KILLPUB ? 1 : 0 )) > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal;
                     cat /sys/module/mxfs/parameters/freplay_force_ag_mask" 2>/dev/null \
        | tr '\n' ' ' | tr -d '[:space:]')
    want="1$(( AGMASK ))"
    [ "$v" = "$want" ] && armed=$((armed+1))
done
if [ "$armed" -ne "${#survivors[@]}" ]; then
    echo "FAIL: knob armed on $armed/${#survivors[@]} survivors — aborting, no kill issued"
    exit 1
fi
echo "knob CONFIRMED armed on all $armed survivors"

# 2. Make the victim the ROOT-DIR EX holder, and leave it holding.  This is
#    the grant the defect strands: MXFS caches the EX after the operation, so
#    the victim still owns it on the wire when it dies.  Root lives in ag0,
#    which the forged mask excludes — so it is provably OUT of closure.
PROBE_SEED="${PROBE_HOST:-test1}"
[ "$PROBE_SEED" = "$VICTIM" ] && PROBE_SEED=test2
echo "--- victim takes a HOT root-dir EX (${VICTIM_LOAD}s of un-synced churn)"
"$SSH" "$VICTIM" "nohup bash -c '
    end=\$((SECONDS + ${VICTIM_LOAD} + 120))
    i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1))
        echo hot > $MNT/.closure374-victim.\$i
        rm -f $MNT/.closure374-victim.\$((i-3))
    done
' >/tmp/closure374load.log 2>&1 &" >/dev/null 2>&1
sleep "$VICTIM_LOAD"
lcnt=$("$SSH" "$PROBE_SEED" "ls -a $MNT/ 2>/dev/null | grep -c closure374-victim" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "${lcnt:-0}" -gt 0 ] || { echo "FAIL: victim root-dir churn never landed"; exit 1; }
echo "victim holds a hot root-dir EX (${lcnt} churn files visible from test1)"

PROBE_HOST="${PROBE_HOST:-test1}"
[ "$PROBE_HOST" = "$VICTIM" ] && PROBE_HOST=test2

# 3. Kill the victim.
date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

# 3b. THE BLOCKED PROBER, launched IMMEDIATELY.  This is the operation the
#     defect makes impossible: it contends for the root-dir authority the dead
#     victim still owns, and it starts while the victim is still being fenced,
#     so it is genuinely waiting across the whole recovery window.  On the
#     unfixed build this is the D-state waiter that polls to DLM -110 and
#     takes the node down with it.  It records its own wall time so the run
#     can tell "was never blocked" from "was blocked and got released".
BLOCK_BUDGET=$(( RECOVERY_WAIT + 60 ))
"$SSH" "$PROBE_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.closure374-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/closure374probe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1
echo "blocked prober launched on $PROBE_HOST (budget ${BLOCK_BUDGET}s)"

# 3c. FAN-OUT PROBERS (sess376, for D-CLOSURE-REMOTE-WAITER-NO-REPAIR-BEFORE-
#     PUBLICATION-376).  PROBE_HOST is frequently the recovery-lease owner
#     itself, and the publisher's own waiters can demand-scrub the moment it
#     seeds its local hint — measured at wait age 1ms.  Every OTHER node has to
#     wait for the verdict to be PUBLISHED and imported, which happens AFTER
#     the publisher's full-table purge scan.  These probers measure how long a
#     REMOTE waiter actually blocks, against MXFS_CAW_WAIT_TIMEOUT_MS=120000.
PROBE_FANOUT="${PROBE_FANOUT:-0}"
fanout_hosts=()
if [ "$PROBE_FANOUT" -gt 0 ]; then
    for h in "${survivors[@]}"; do
        [ "$h" = "$PROBE_HOST" ] && continue
        fanout_hosts+=("$h")
        [ "${#fanout_hosts[@]}" -ge "$PROBE_FANOUT" ] && break
    done
    for h in "${fanout_hosts[@]}"; do
        "$SSH" "$h" "nohup bash -c '
            s=\$(date +%s)
            timeout $BLOCK_BUDGET touch $MNT/.closure374-fan-$h; rc=\$?
            echo \"FAN_PROBE host=$h rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/closure374fan.out
        ' >/dev/null 2>&1 &" >/dev/null 2>&1 &
    done
    wait
    echo "fan-out probers launched on ${#fanout_hosts[@]} remote survivors: ${fanout_hosts[*]}"
fi

PUB2=""
if [ "$KILLPUB" = "1" ]; then
    # Wait for SOME node to be parked inside its purge scan, pre-publication,
    # then destroy it.  A node that has logged P299-INJECT-PAUSE has already
    # claimed the recovery lease, imported its own terminal verdict locally,
    # and entered the scan -- and has NOT published, because publication is the
    # statement that follows the scan.
    PUB1=""
    for a in $(seq 1 30); do
        sleep 5
        for h in "${survivors[@]}"; do
            ( c=$("$SSH" "$h" "dmesg | grep -c 'P299-INJECT-PAUSE'" 2>/dev/null | tr -d '[:space:]')
              echo "${c:-0}" > "/tmp/cps_pause.$h" ) &
        done
        wait
        for h in "${survivors[@]}"; do
            c=$(cat "/tmp/cps_pause.$h" 2>/dev/null)
            [ "${c:-0}" -ge 1 ] && { PUB1="$h"; break; }
        done
        [ -n "$PUB1" ] && break
    done
    if [ -z "$PUB1" ]; then
        echo "PRECONDITION-NOT-MET: no node ever parked inside its purge scan —"
        echo "  the pause never fired, so the mid-scan death cannot be staged."
        exit 2
    fi
    pubpub=$("$SSH" "$PUB1" "dmesg | grep -c 'terminal outcome PUBLISHED'" 2>/dev/null | tr -d '[:space:]')
    echo "publisher parked mid-scan: $PUB1 (published-so-far=${pubpub:-0}; want 0)"
    if [ "${pubpub:-0}" -ne 0 ]; then
        echo "PRECONDITION-NOT-MET: $PUB1 had already published before the pause —"
        echo "  this arm requires the death to land BEFORE publication."
        exit 2
    fi
    date -u "+KILL PUBLISHER $PUB1 (mid-scan, pre-publication) @ %FT%TZ"
    sudo virsh -c qemu:///system destroy "$PUB1" || { echo "FAIL: virsh destroy $PUB1"; exit 1; }
    PUB2="$PUB1"
    survivors2=()
    for h in "${survivors[@]}"; do [ "$h" = "$PUB1" ] || survivors2+=("$h"); done
    survivors=("${survivors2[@]}")
    # the fan-out list must lose it too, or its probe is collected from a
    # destroyed VM and reported as "still running"
    fan2=()
    for h in "${fanout_hosts[@]}"; do [ "$h" = "$PUB1" ] || fan2+=("$h"); done
    fanout_hosts=("${fan2[@]}")
    [ "$PROBE_HOST" = "$PUB1" ] && PROBE_HOST="${survivors[0]}"
    PROBE_FANOUT="${#fanout_hosts[@]}"
fi

# 4. Wait out fence + recovery + refusal + publish + repair.
echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+purge..."
sleep "$RECOVERY_WAIT"

# 5a. Collect the blocked prober.
bp=$("$SSH" "$PROBE_HOST" "cat /tmp/closure374probe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
echo "--- blocked prober: ${bp:-<still running>}"
bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
bp_s=$(echo "$bp" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)

# 5a-2. Collect the fan-out probers and report the WORST remote wait.
if [ "${PROBE_FANOUT:-0}" -gt 0 ]; then
    fmax=0; fworst=""; fhung=0
    for h in "${fanout_hosts[@]}"; do
        l=$("$SSH" "$h" "cat /tmp/closure374fan.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep FAN_PROBE | tail -1)
        if [ -z "$l" ]; then fhung=$((fhung+1)); echo "  fan $h: <still running>"; continue; fi
        echo "  fan $l"
        e=$(echo "$l" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
        r=$(echo "$l" | grep -o 'rc=[0-9]*' | cut -d= -f2)
        [ "${r:-1}" -ne 0 ] && fhung=$((fhung+1))
        [ "${e:-0}" -gt "$fmax" ] && { fmax=$e; fworst=$h; }
    done
    echo "--- REMOTE-WAITER MARGIN: worst remote wait ${fmax}s on ${fworst:-none};"
    echo "    non-zero/unfinished probers=$fhung; DLM wait timeout is 120s"
fi

# 5b. A FRESH probe, after the repair.  Bounded by PROBE_BUDGET; a timeout is
#     a FAIL, not a retry (RULE 0).
echo "--- fresh probe: root-dir write on $PROBE_HOST, budget ${PROBE_BUDGET}s"
p0=$(date +%s)
if "$SSH" "$PROBE_HOST" "timeout $PROBE_BUDGET touch $MNT/.closure374-probe" >/dev/null 2>&1; then
    probe_rc=0
else
    probe_rc=1
fi
probe_s=$(( $(date +%s) - p0 ))

pass=1
echo "probe: rc=$probe_rc elapsed=${probe_s}s (budget ${PROBE_BUDGET}s)"

# 6. Harvest survivor dmesg (cleared at arm time, so all of it is this test's).
D=$(mktemp -d)
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$D/$h.dmesg" 2>/dev/null &
done
wait

# 6a-pre. INCLOSURE mode: the OTHER arm of the sess357 ruling.  Here ag0 IS in
#     the quarantined domain, so the victim's root grant is SUPPOSED to stay
#     frozen.  The ruling's part (1) says the DLM must then reject NEW waits
#     immediately with a distinct terminal-quarantine error AND CANCEL EXISTING
#     ones the same way — not let them run to the DLM timeout.  sess356
#     measured the unfixed behavior: 4 clean unmounters wedged ~5min on the
#     root-ino EX, took DLM -110, and withdrew DIRTY.  So in this mode:
#       blocked prober MUST fail (frozen is correct) but FAST, and
#       no survivor may withdraw or shut down.
if [ "$INCLOSURE" = "1" ]; then
    echo "--- INCLOSURE verdict (ruling part 1: reject new waits, cancel existing)"
    echo "blocked prober: rc=${bp_rc:-<hung>} elapsed=${bp_s:-?}s"
    if [ -z "${bp_rc:-}" ]; then
        echo "FAIL: the in-closure waiter never returned at all"
        pass=0
    elif [ "$bp_rc" -eq 0 ]; then
        echo "FAIL: an IN-closure root write SUCCEEDED — the quarantine is not"
        echo "      containing the refused domain"
        pass=0
    elif [ "${bp_s:-999}" -gt 90 ]; then
        echo "FAIL: the in-closure waiter took ${bp_s}s to fail — it ran to the"
        echo "      DLM timeout instead of being cancelled with a terminal-"
        echo "      quarantine error.  This is the sess356 wedge shape."
        pass=0
    else
        echo "in-closure waiter refused after ${bp_s}s (rc=$bp_rc) — cancelled, not timed out"
    fi
    echo "fresh in-closure probe: rc=$probe_rc elapsed=${probe_s}s (want rc!=0, fast)"
    [ "$probe_rc" -ne 0 ] || { echo "FAIL: a fresh IN-closure write succeeded"; pass=0; }
    shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)
    echo "survivors with shutdown/withdraw (want 0): $shutdowns"
    [ "$shutdowns" -eq 0 ] || { echo "FAIL: survivor withdrew — the sess356 cascade"; pass=0; }
    mounted=0
    for h in "${survivors[@]}"; do
        m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
        [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
    done
    echo "survivors still mounted (want ${#survivors[@]}): $mounted"
    [ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }
    for h in "${survivors[@]}"; do
        "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                     echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                 echo 0 > /sys/module/mxfs/parameters/closure_skip_publisher_purge;
                     echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
    done
    wait
    echo "--- evidence"
    grep -h "terminal outcome PUBLISHED" "$D"/*.dmesg | head -2
    grep -h "P240-QUAR-IMPORT" "$D"/*.dmesg | head -2
    grep -h "P299-CLOSURE-PURGE" "$D"/*.dmesg | head -2
    "$SSH" "$PROBE_HOST" "dmesg | grep -E 'DLM.*-110|P-ACQ-STUCK|quarantin' | tail -5" 2>/dev/null
    echo "dmesg harvest kept in $D"
    [ "$pass" -eq 1 ] && { echo "=== closure_purge_scrub INCLOSURE PASS @ $(date -u +%FT%TZ) ==="; exit 0; }
    echo "=== closure_purge_scrub INCLOSURE FAIL @ $(date -u +%FT%TZ) ==="
    exit 1
fi

# 6a-killpub. PUBLISHER DIED MID-SCAN, BEFORE PUBLICATION (sess376).
#     The refusing replayer IS the node that was destroyed, so its dmesg is
#     gone with it and the standard "refusers==1 / published domain" guard
#     cannot apply.  What has to hold is CONTAINMENT: recovery is taken over,
#     nothing is stranded past the DLM wait timeout, and no survivor withdraws.
if [ "$KILLPUB" = "1" ]; then
    echo "--- assertions (KILLPUB: publisher destroyed mid-scan, pre-publication)"
    echo "destroyed publisher: $PUB2"
    claims=$(grep -h "P236-RECOV-CLAIMED\|execution lease acquired" "$D"/*.dmesg 2>/dev/null | wc -l)
    claimers=$(grep -l "P236-RECOV-CLAIMED\|execution lease acquired" "$D"/*.dmesg 2>/dev/null | wc -l)
    echo "recovery claims by SURVIVING nodes after the publisher died (want >=1): $claims on $claimers node(s)"
    [ "$claims" -ge 1 ] || { echo "FAIL: no surviving node took over recovery — the victim's slice is orphaned"; pass=0; }
    shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)
    echo "survivors with shutdown/withdraw (want 0): $shutdowns"
    if [ "$shutdowns" -ne 0 ]; then
        echo "FAIL: survivor shutdowns — the cascade this fix exists to stop"
        grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg
        pass=0
    fi
    dlm110=$(grep -h "DLM.*-110\|acquisition timed out" "$D"/*.dmesg 2>/dev/null | wc -l)
    echo "DLM -110 / wait timeouts anywhere (want 0): $dlm110"
    [ "$dlm110" -eq 0 ] || { echo "FAIL: a waiter reached the DLM wait timeout"; pass=0; }
    fan_bad=0; fan_max=0
    for h in "${fanout_hosts[@]}"; do
        l=$("$SSH" "$h" "cat /tmp/closure374fan.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep FAN_PROBE | tail -1)
        if [ -z "$l" ]; then echo "  fan $h: <still running>"; fan_bad=$((fan_bad+1)); continue; fi
        e=$(echo "$l" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
        r=$(echo "$l" | grep -o 'rc=[0-9]*' | cut -d= -f2)
        echo "  fan $l"
        [ "${r:-1}" -eq 0 ] || fan_bad=$((fan_bad+1))
        [ "${e:-0}" -gt "$fan_max" ] && fan_max=$e
    done
    echo "remote waiters: failed/unfinished=$fan_bad worst_wait=${fan_max}s (DLM timeout 120s)"
    [ "$fan_bad" -eq 0 ] || { echo "FAIL: a remote waiter was never released"; pass=0; }
    [ "$fan_max" -lt 120 ] || { echo "FAIL: a remote waiter exceeded the 120s DLM wait timeout"; pass=0; }
    mounted=0
    for h in "${survivors[@]}"; do
        m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
        [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
    done
    echo "survivors still mounted (want ${#survivors[@]}): $mounted"
    [ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }
    for h in "${survivors[@]}"; do
        "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                     echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                     echo 0 > /sys/module/mxfs/parameters/closure_skip_publisher_purge;
                     echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
    done
    wait
    echo "--- evidence"
    grep -h "P299-INJECT-PAUSE\|P236-RECOV-CLAIMED\|terminal outcome PUBLISHED\|P299-CLOSURE-PURGE" "$D"/*.dmesg |
        sed 's/^\[[^]]*\] *//' | head -6
    echo "dmesg harvest kept in $D"
    [ "$pass" -eq 1 ] && { echo "=== closure_purge_scrub KILLPUB PASS @ $(date -u +%FT%TZ) ==="; exit 0; }
    echo "=== closure_purge_scrub KILLPUB FAIL @ $(date -u +%FT%TZ) ==="
    exit 1
fi

# 6a. SETUP GUARD, evaluated before any verdict about the fix.  The published
#     domain must be the one we forged and must exclude ag0; if it is not, the
#     probe is measuring quarantine containment (an immediate EIO on an
#     in-closure resource — CORRECT behavior) rather than a frozen grant, and
#     the run says nothing about this defect either way.  sess374 hit exactly
#     this: the forged 0x2 was OR'd with the replay's own refused 0x81.
pub_mask=$(grep -h "terminal outcome PUBLISHED" "$D"/*.dmesg 2>/dev/null |
           grep -o "ag_mask=0x[0-9a-f]*" | head -1 | cut -d= -f2)
echo "published domain: ${pub_mask:-<none>} (forged $AGMASK)"
if [ -z "$pub_mask" ]; then
    echo "INCONCLUSIVE: no published AG-mask domain found — nothing to verify"
    exit 2
fi
if [ $(( pub_mask & 1 )) -ne 0 ]; then
    echo "INCONCLUSIVE: the published domain $pub_mask INCLUDES ag0, so the"
    echo "      root inode is in closure and is SUPPOSED to stay frozen."
    echo "      The probe's failure is correct containment, not this defect."
    exit 2
fi

if [ "$probe_rc" -ne 0 ]; then
    echo "FAIL: root-dir write on $PROBE_HOST did not complete inside the"
    echo "      budget — the victim's out-of-closure root grant is STILL"
    echo "      frozen.  This is the defect, unfixed."
    pass=0
fi
if [ -z "${bp_rc:-}" ]; then
    echo "FAIL: the blocked prober never finished — it is still waiting on the"
    echo "      victim's out-of-closure grant.  This is the defect."
    pass=0
elif [ "$bp_rc" -ne 0 ]; then
    echo "FAIL: the blocked prober returned rc=$bp_rc after ${bp_s}s — it was"
    echo "      never released."
    pass=0
else
    echo "blocked prober released after ${bp_s}s (rc=0)"
fi

refusers=$(grep -l "slice replay refused" "$D"/*.dmesg 2>/dev/null | wc -l)
publishes=$(grep -h "terminal outcome PUBLISHED" "$D"/*.dmesg 2>/dev/null | wc -l)
purge_lines=$(grep -h "P299-CLOSURE-PURGE" "$D"/*.dmesg 2>/dev/null)
strip_n=$(grep -h "P299-CLOSURE-STRIP" "$D"/*.dmesg 2>/dev/null | wc -l)
scrub_n=$(grep -h "P299-SCRUB-STRIP" "$D"/*.dmesg 2>/dev/null | wc -l)
scrub_abort=$(grep -h "P299-SCRUB-ABORT" "$D"/*.dmesg 2>/dev/null | wc -l)
incomplete=$(grep -h "P299-CLOSURE-INCOMPLETE\|grant purge INCOMPLETE" "$D"/*.dmesg 2>/dev/null | wc -l)
refroze=$(grep -h "P299-CLOSURE-REFROZE" "$D"/*.dmesg 2>/dev/null | wc -l)
recovered_pub=$(grep -h "published as recovered\|slice recovery complete" "$D"/*.dmesg 2>/dev/null | wc -l)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)
purged_total=$(echo "$purge_lines" | grep -o "purged=[0-9]*" | cut -d= -f2 | paste -sd+ - | bc 2>/dev/null)
purged_total=${purged_total:-0}

echo "--- assertions"
echo "refusing replayers (want 1): $refusers"
[ "$refusers" -eq 1 ] || { echo "FAIL: expected exactly 1 refusing replayer"; pass=0; }
echo "terminal publishes (want >=1): $publishes"
[ "$publishes" -ge 1 ] || { echo "FAIL: refusal was never published"; pass=0; }
echo "publisher purge: purged=$purged_total strips=$strip_n | survivor scrub strips=$scrub_n"
if [ "$SCRUB_ONLY" = "1" ]; then
    skips=$(grep -h "P299-CLOSURE-SKIP" "$D"/*.dmesg 2>/dev/null | wc -l)
    echo "SCRUB_ONLY: publisher-purge suppressions (want >=1): $skips"
    [ "$skips" -ge 1 ] || { echo "FAIL: SCRUB_ONLY set but the publisher purge was not suppressed"; pass=0; }
    [ "$purged_total" -eq 0 ] || { echo "FAIL: SCRUB_ONLY set but the publisher purged $purged_total anyway"; pass=0; }
    echo "SCRUB_ONLY: survivor scrub strips (want >=1): $scrub_n"
    [ "$scrub_n" -ge 1 ] || { echo "FAIL: the survivor demand scrub never repaired anything"; pass=0; }
fi
if [ "$purged_total" -eq 0 ] && [ "$scrub_n" -eq 0 ]; then
    echo "FAIL: NEITHER half of the fix revoked anything.  If the probe"
    echo "      passed, it passed for some other reason and proves nothing"
    echo "      about this defect."
    pass=0
fi
echo "scrub aborts (want 0): $scrub_abort"
[ "$scrub_abort" -eq 0 ] || { echo "FAIL: a scrub gate could not be evaluated"; pass=0; }
echo "purge refroze/incomplete (want 0): refroze=$refroze incomplete=$incomplete"
if [ "$refroze" -ne 0 ] || [ "$incomplete" -ne 0 ]; then
    echo "FAIL: the publisher purge did not run to completion"
    pass=0
fi
echo "slot published-as-recovered lines (want 0): $recovered_pub"
[ "$recovered_pub" -eq 0 ] || { echo "FAIL: refused slice was published as recovered — the HB sector must never be zeroed on a refusal"; pass=0; }
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
if [ "$shutdowns" -ne 0 ]; then
    echo "FAIL: survivor shutdowns — the cascade this fix exists to stop"
    grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg
    pass=0
fi

# 7. Every survivor still mounted.
mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }

# 8. Disarm.
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                 echo 0 > /sys/module/mxfs/parameters/closure_skip_publisher_purge;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
done
wait

echo "--- evidence"
grep -h "slice replay refused\|terminal outcome PUBLISHED" "$D"/*.dmesg | head -3
grep -h "P299-CLOSURE-SCAN\|P299-CLOSURE-PURGE\|P299-CLOSURE-GATE\|P299-CLOSURE-MISMATCH" "$D"/*.dmesg | head -6
grep -h "P299-CLOSURE-STRIP" "$D"/*.dmesg | head -5
grep -h "P299-SCRUB-STRIP\|P299-SCRUB-ABORT\|P299-CLOSURE-SKIP" "$D"/*.dmesg | head -5

echo "dmesg harvest kept in $D"
if [ "$pass" -eq 1 ]; then
    echo "=== closure_purge_scrub PASS (ag_mask=$AGMASK) @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_purge_scrub FAIL (ag_mask=$AGMASK) @ $(date -u +%FT%TZ) ==="
exit 1
