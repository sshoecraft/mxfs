#!/bin/bash
# clean_depart_lineage_race.sh — #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-
# PHANTOM-RECOVERY-526 closure races 6 and 7 (sess349 GPT ruling, revised
# sess355 GPT ruling after the suspension choreography was measured
# arithmetically impossible for race 7 — see ccmemory
# ccloop-c7ee71c6-sess354-race67-p225-barrier-collision).
#
# Race 6 (CYCLES=1): observer A misses B's ACTIVE->EMPTY->ACTIVE transition
# entirely (both the clean release and the re-claim land inside one monitor
# interval).  A must prove the predecessor departed cleanly from the
# SUCCESSOR's provenance chain (P163-CLEAN-DEPART-LINEAGE, disklock.c) and
# retire it WITHOUT death/fence/recovery.
# Race 7 (CYCLES=2): same, but TWO full tenancies elapse while A is blind —
# tests the range arithmetic (tracked seq S at the LOWER end of
# [S'-chain, S'-1]).
#
# MODE=blind (default, races 6 AND 7): set mxfs.monitor_blind=1 on A —
#   A's disklock peer-observation pass is suppressed while its own
#   heartbeat keeps publishing (P163T-BLIND-ACK/-SKIP/-CLEAR probes,
#   0.13.4).  A never looks stale, so B's remounts hit no P225 barrier and
#   A is at zero fencing risk — no suspend-window arithmetic at all.
#   Validity: ACK seen before choreography, CLEAR reason=user (an
#   auto-clear = INVALID run), skips>=CYCLES, hb_ok>=1.
# MODE=suspend (race 6 corroboration only, CYCLES=1): virsh suspend A,
#   umount B, launch B's mount DETACHED (it blocks ~62s in the P225
#   SETTLE-VERIFY barrier because suspended A reads as a stale authority),
#   resume A as soon as B's slot is re-ACTIVE on disk (~12-20s, must stay
#   <40s — real death threshold is 64s, measured sess354), then wait for
#   the mount to finish (SETTLE-ALIVE once A's hb advances).
#
# PASS (all must hold):
#   1. choreography valid (mode-specific, above),
#   2. on-disk: exactly B's hb slot changed epoch; ACTIVE after; prov
#      seq advanced by CYCLES and chain covers the gap,
#   3. A logs >=1 P163-CLEAN-DEPART-LINEAGE for B's slot since T0,
#   4. A logs ZERO "no longer responding" and ZERO "has restarted
#      (detected epoch change" -> fire_dead for any slot since T0,
#   5. zero "no longer responding" on EVERY node since T0,
#   6. A and B both still mounted + writable, no shutdown/withdraw.
#
# Usage: [MODE=blind|suspend] tests/clean_depart_lineage_race.sh [CYCLES] [A] [B] [OBS]
#
# RULE 0 budget (blind): 2 slotdumps 4s + ACK poll <=8s + CYCLES x
# (umount 1s + mount 5-12s) <=26s + clear+lineage poll <=30s + sweep 20s +
# health 5s ~= 95s.  External timeout: 150s.
# RULE 0 budget (suspend): + detached-mount poll <=30s + mount-completion
# wait <=90s ~= 180s.  External timeout: 240s.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

MODE="${MODE:-blind}"
CYCLES="${1:-1}"
A="${2:-test2}"
B="${3:-test3}"
OBS="${4:-test1}"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared
DUMP="/src/mxfs/tools/caw_slotdump"
VIRSH="sudo virsh -c qemu:///system"
BLIND_PARAM=/sys/module/mxfs/parameters/monitor_blind

if [ "$MODE" = "suspend" ] && [ "$CYCLES" -ne 1 ]; then
    echo "FAIL: MODE=suspend supports CYCLES=1 only (race 7 is arithmetically"
    echo "      impossible under suspension: P225 barrier 62s >= death 64s)"
    exit 1
fi

fail=0
echo "=== clean_depart_lineage_race: MODE=$MODE CYCLES=$CYCLES A=$A B=$B OBS=$OBS ==="

# 0. Preconditions: all three roles mounted.
for h in "$A" "$B" "$OBS"; do
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] || { echo "FAIL: $h not mounted"; exit 1; }
done
if [ "$MODE" = "suspend" ]; then
    $VIRSH domstate "$A" 2>/dev/null | grep -q running || {
        echo "FAIL: libvirt domain $A not running"; exit 1; }
else
    bp=$("$SSH" "$A" "cat $BLIND_PARAM" 2>/dev/null | tr -d ' \r\n')
    [ "$bp" = "0" ] || { echo "FAIL: $A monitor_blind=$bp at start (want 0; is 0.13.4 deployed?)"; exit 1; }
fi

hb_snap() {  # $1 = outfile
    "$SSH" "$OBS" "$DUMP $DEV --max 1" 2>/dev/null | grep '^hb\[' > "$1"
}

td=$(mktemp -d)
hb_snap "$td/before"
nb=$(wc -l < "$td/before")
[ "$nb" -ge 3 ] || { echo "FAIL: baseline slotdump returned $nb hb rows"; exit 1; }

# T0 is backdated 5s: the VM journal clocks skew 1-2s from this host
# (measured sess355 — an ACK stamped 1s before a same-instant T0 and was
# excluded by --since forever).  Runs are >=20s apart, so 5s cannot leak
# a previous run's events into this run's asserts.
T0=$(date -u -d '5 seconds ago' +%FT%TZ)

if [ "$MODE" = "blind" ]; then
    # ---- BLIND choreography ------------------------------------------------
    echo "--- T0=$T0; blinding $A's monitor (hb keeps beating)"
    "$SSH" "$A" "echo 1 > $BLIND_PARAM" 2>/dev/null \
        || { echo "FAIL: could not set monitor_blind on $A"; exit 1; }
    ack=0; dl=$((SECONDS + 8))
    while [ "$SECONDS" -lt "$dl" ]; do
        "$SSH" "$A" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -q P163T-BLIND-ACK" \
            2>/dev/null && { ack=1; break; }
        sleep 1
    done
    [ "$ack" -eq 1 ] || { echo "FAIL: no P163T-BLIND-ACK on $A within 8s"; \
        "$SSH" "$A" "echo 0 > $BLIND_PARAM" 2>/dev/null; exit 1; }
    echo "--- $A acked blind; cycling $B x$CYCLES"

    cyc_fail=0
    for c in $(seq 1 "$CYCLES"); do
        "$SSH" "$B" "timeout 60 umount $MNT" >/dev/null 2>&1 \
            || { echo "FAIL: cycle $c umount on $B"; cyc_fail=1; break; }
        "$SSH" "$B" "timeout 90 mount -t mxfs $DEV $MNT" >/dev/null 2>&1 \
            || { echo "FAIL: cycle $c mount on $B"; cyc_fail=1; break; }
    done

    # Validity: still blind (no auto-clear happened mid-choreography).
    bp=$("$SSH" "$A" "cat $BLIND_PARAM" 2>/dev/null | tr -d ' \r\n')
    clr=$("$SSH" "$A" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -c P163T-BLIND-CLEAR" 2>/dev/null | tr -d ' \r\n')
    "$SSH" "$A" "echo 0 > $BLIND_PARAM" 2>/dev/null
    [ "$cyc_fail" -eq 0 ] || exit 1
    if [ "$bp" != "1" ] || [ "${clr:-0}" != "0" ]; then
        echo "INVALID: blind auto-cleared mid-run (param=$bp clears=$clr) — rerun"
        exit 1
    fi
    # Wait for the explicit clear and check its provenance + counters.
    cline=""; dl=$((SECONDS + 8))
    while [ "$SECONDS" -lt "$dl" ]; do
        cline=$("$SSH" "$A" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep P163T-BLIND-CLEAR | tail -1" 2>/dev/null)
        [ -n "$cline" ] && break
        sleep 1
    done
    echo "clear: $cline"
    skips=$(echo "$cline" | sed -nE 's/.*skips=([0-9]+).*/\1/p')
    hbok=$(echo "$cline" | sed -nE 's/.*hb_ok=([0-9]+).*/\1/p')
    if echo "$cline" | grep -q "reason=user" \
       && [ "${skips:-0}" -ge "$CYCLES" ] && [ "${hbok:-0}" -ge 1 ]; then
        echo "PASS-1: blind window valid (reason=user skips=$skips hb_ok=$hbok)"
    else
        echo "INVALID: blind window (want reason=user skips>=$CYCLES hb_ok>=1) — rerun"
        exit 1
    fi
else
    # ---- SUSPEND choreography (race 6 corroboration) -----------------------
    echo "--- T0=$T0; suspending $A"
    SUSP_T0=$SECONDS
    $VIRSH suspend "$A" >/dev/null || { echo "FAIL: virsh suspend $A"; exit 1; }

    "$SSH" "$B" "timeout 60 umount $MNT" >/dev/null 2>&1 \
        || { echo "FAIL: umount on $B"; $VIRSH resume "$A" >/dev/null; exit 1; }
    # Detached mount: it will block ~62s in the P225 SETTLE-VERIFY barrier
    # (suspended A reads as a stale authority); B's slot goes re-ACTIVE on
    # disk early (DLM claim), which is our cue to resume A.
    "$SSH" "$B" "nohup timeout 180 mount -t mxfs $DEV $MNT >/tmp/cdlr_mount.log 2>&1 & echo LAUNCHED" \
        2>/dev/null | grep -q LAUNCHED \
        || { echo "FAIL: detached mount launch on $B"; $VIRSH resume "$A" >/dev/null; exit 1; }

    # Poll for B's slot re-ACTIVE with advanced seq (epoch changed).
    reactive=0; dl=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$dl" ]; do
        hb_snap "$td/mid"
        nchanged=0
        while read -r line; do
            slot=$(echo "$line" | sed -E 's/^hb\[([0-9]+)\].*/\1/')
            e_b=$(grep "^hb\[$slot\]" "$td/before" | sed -E 's/.* epoch=([0-9]+).*/\1/')
            e_a=$(echo "$line" | sed -E 's/.* epoch=([0-9]+).*/\1/')
            fl=$(echo "$line" | sed -nE 's/.*flags=([0-9]+).*/\1/p')
            if [ -n "$e_b" ] && [ "$e_b" != "$e_a" ] && [ "$fl" = "1" ]; then
                nchanged=$((nchanged + 1))
            fi
        done < "$td/mid"
        [ "$nchanged" -ge 1 ] && { reactive=1; break; }
        sleep 2
    done
    $VIRSH resume "$A" >/dev/null || { echo "FAIL: virsh resume $A — RESUME IT BY HAND"; exit 1; }
    SUSP_WALL=$((SECONDS - SUSP_T0))
    echo "--- $A resumed; suspend window ${SUSP_WALL}s (must be <40; death threshold 64s)"
    [ "$reactive" -eq 1 ] || { echo "FAIL: $B slot never re-ACTIVE within 30s"; exit 1; }
    if [ "$SUSP_WALL" -ge 40 ]; then
        echo "INVALID: suspend window ${SUSP_WALL}s >= 40s safety margin — rerun"
        exit 1
    fi
    # Wait for B's detached mount to complete (barrier resolves SETTLE-ALIVE).
    mdone=0; dl=$((SECONDS + 90))
    while [ "$SECONDS" -lt "$dl" ]; do
        m=$("$SSH" "$B" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
        [ "$m" = "Y" ] && { mdone=1; break; }
        sleep 3
    done
    if [ "$mdone" -eq 1 ]; then
        echo "PASS-1: suspend window ${SUSP_WALL}s valid; $B mount completed"
    else
        echo "FAIL: $B detached mount did not complete within 90s of resume:"
        "$SSH" "$B" "tail -3 /tmp/cdlr_mount.log" 2>/dev/null
        exit 1
    fi
fi

# 2. On-disk verification: B's slot (and only B's) changed epoch.
hb_snap "$td/after"
changed=""
while read -r line; do
    slot=$(echo "$line" | sed -E 's/^hb\[([0-9]+)\].*/\1/')
    e_b=$(grep "^hb\[$slot\]" "$td/before" | sed -E 's/.* epoch=([0-9]+).*/\1/')
    e_a=$(echo "$line" | sed -E 's/.* epoch=([0-9]+).*/\1/')
    [ -n "$e_b" ] && [ "$e_b" != "$e_a" ] && changed="$changed $slot"
done < "$td/after"
changed=$(echo "$changed" | xargs)
if [ "$(echo "$changed" | wc -w)" -ne 1 ]; then
    echo "FAIL: expected exactly 1 slot with changed epoch (B), got: '$changed'"
    fail=1
    BSLOT=$(echo "$changed" | awk '{print $1}')
else
    BSLOT="$changed"
    echo "B occupies hb slot $BSLOT"
fi
BSLOT=${BSLOT:-?}

b_line=$(grep "^hb\[$BSLOT\]" "$td/before" || true)
a_line=$(grep "^hb\[$BSLOT\]" "$td/after" || true)
echo "before: $b_line"
echo "after:  $a_line"
s0=$(echo "$b_line" | sed -nE 's/.*seq=([0-9]+).*/\1/p')
s1=$(echo "$a_line" | sed -nE 's/.*seq=([0-9]+).*/\1/p')
c1=$(echo "$a_line" | sed -nE 's/.*chain=([0-9]+).*/\1/p')
fl=$(echo "$a_line" | sed -nE 's/.*flags=([0-9]+).*/\1/p')
if [ -z "$s0" ] || [ -z "$s1" ] || [ -z "$c1" ]; then
    echo "FAIL: could not parse prov seq/chain from slotdump"
    fail=1
else
    d=$((s1 - s0))
    if [ "$fl" = "1" ] && [ "$d" -eq "$CYCLES" ] && [ "$c1" -ge "$CYCLES" ]; then
        echo "PASS-2: on-disk ACTIVE, seq advanced by $d (=CYCLES), chain=$c1 covers d"
    else
        echo "FAIL: on-disk flags=$fl seq_delta=$d (want $CYCLES) chain=$c1 (want >=$CYCLES)"
        fail=1
    fi
fi

# 3+4. Journal asserts on A: poll up to 30s for the lineage retire.
# (slotdump zero-pads slot numbers; the kernel log does not)
case "$BSLOT" in (*[!0-9]*) ;; (*) BSLOT=$((10#$BSLOT));; esac
lin=0; dl=$((SECONDS + 30))
while [ "$SECONDS" -lt "$dl" ]; do
    lin=$("$SSH" "$A" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -c 'P163-CLEAN-DEPART-LINEAGE slot=$BSLOT '" 2>/dev/null | tr -d ' \r\n')
    case "$lin" in (*[!0-9]*|'') lin=0;; esac
    [ "$lin" -ge 1 ] && break
    sleep 3
done
alog=$("$SSH" "$A" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -E 'P163-CLEAN-DEPART|no longer responding|has restarted|P237-SLOT-REOCCUPIED|P163-RECOVERY-PENDING|Filesystem has been shut down|MXFS.*withdraw'" 2>/dev/null)
if [ "$lin" -ge 1 ]; then
    echo "PASS-3: $A logged P163-CLEAN-DEPART-LINEAGE slot=$BSLOT x$lin:"
    echo "$alog" | grep "P163-CLEAN-DEPART-LINEAGE" | head -3
else
    echo "FAIL: $A logged NO P163-CLEAN-DEPART-LINEAGE for slot $BSLOT since $T0"
    echo "$alog" | head -10
    fail=1
fi
bad=$(echo "$alog" | grep -cE "no longer responding|has restarted \(detected epoch change|P163-RECOVERY-PENDING"); bad=${bad:-0}
if [ "$bad" -eq 0 ]; then
    echo "PASS-4: zero death/restart-reclaim/recovery-pending on $A"
else
    echo "FAIL: $A took a death path x$bad:"
    echo "$alog" | grep -E "no longer responding|has restarted|P163-RECOVERY-PENDING" | head -5
    fail=1
fi

# 5. Cluster-wide false-death sweep.
N="${N:-32}"
for i in $(seq 1 "$N"); do
    h="test$i"
    "$SSH" "$h" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -c 'no longer responding'" > "$td/fd_$h" 2>/dev/null &
done
wait
fd_total=0
for i in $(seq 1 "$N"); do
    h="test$i"
    fd=$(tr -d ' \r\n' < "$td/fd_$h" 2>/dev/null); fd=${fd:-0}
    case "$fd" in (*[!0-9]*|'') fd=0;; esac
    if [ "$fd" -gt 0 ]; then
        echo "FAIL: $h declared $fd false death(s) since $T0"
        fd_total=$((fd_total + fd)); fail=1
    fi
done
[ "$fd_total" -eq 0 ] && echo "PASS-5: zero false-death declarations across $N nodes"

# 6. A and B health.
for h in "$A" "$B"; do
    hw=$("$SSH" "$h" "mountpoint -q $MNT && echo ok > $MNT/.cdlr_$h && sync $MNT/.cdlr_$h 2>/dev/null && echo W_OK" 2>/dev/null | tr -d ' \r\n')
    if [ "$hw" = "W_OK" ]; then
        echo "PASS-6: $h mounted+writable"
    else
        echo "FAIL: $h health write=$hw"
        fail=1
    fi
done

rm -rf "$td"
if [ "$fail" -eq 0 ]; then
    echo "=== clean_depart_lineage_race MODE=$MODE CYCLES=$CYCLES PASS ==="
    exit 0
fi
echo "=== clean_depart_lineage_race MODE=$MODE CYCLES=$CYCLES FAIL ==="
exit 1
