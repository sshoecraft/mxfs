#!/bin/bash
# mass_umount_stall_probe.sh — D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B
# RULE-4 step 2 instrumentation run.
#
# Simultaneously unmounts EVERY node of a mounted fleet (the sess378 shape:
# 32-way, no survivor — the worst case, in which the last node standing has
# NO live peer that could be holding the lock it is waiting for), measures
# each node's umount wall ON THE NODE, and collects the DLM stall markers
# that discriminate the two live hypotheses:
#
#   H-A  LEAKED ACQUIRING.  i_dlm_state==ACQUIRING with i_dlm_acq_inflight==0:
#        the setter exited without transitioning.  The only reclaim for this
#        (P-ACQ-ORPHAN-RECLAIM) lives in bast_notify and therefore cannot fire
#        once no peer is left to send a BAST, so every local waiter parks in
#        mxfs_dlm_ilock_begin's 3s poll loop until something unrelated clears
#        it.  Signature: P73-WAITSTALL state=4 acq_inflight=0.
#
#   H-B  GENUINELY SLOW ACQUIRE.  A real caw_lock is in flight the whole time.
#        Signature: P73-WAITSTALL state=4 acq_inflight>0, and/or a
#        P139-LOCKTOTAL with a large total_ms and retries>0 on the same ino.
#
# RULE 0: native XFS umount of a quiescent fs is <1s.  The budget asserted
# here is 5s per node (2x native, with generous infra slack).  The 330s
# per-node `timeout` is NOT the budget — it exists only so a wedge cannot
# hang the harness; any node over BUDGET_S is reported as a RULE 0 FAIL with
# its measured wall.
#
# Usage: tests/mass_umount_stall_probe.sh [N] [BUDGET_S]
#   N         fleet size currently prepped and mounted (default 32)
#   BUDGET_S  per-node umount budget in seconds (default 5)
#
# Leaves the whole fleet UNMOUNTED (module still loaded).  Re-prep with
# ./run.sh N caw prep_cluster before any board test.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:-32}"
BUDGET_S="${2:-5}"
MNT=/mnt/shared
HARD_S="${HARD_S:-330}"

T0=$(date -u +%FT%TZ)
OUT=$(mktemp -d)
echo "=== mass_umount_stall_probe: N=$N budget=${BUDGET_S}s/node @ $T0 ==="
echo "--- evidence dir: $OUT"

# 0. Precondition: every node mounted.  A node that is already unmounted
#    would silently shrink the storm and understate the stall.
notmounted=""
for i in $(seq 1 "$N"); do
    h="test$i"
    ( m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y || echo N" 2>/dev/null | tr -d ' \r\n')
      echo "$m" > "$OUT/pre.$h" ) &
done
wait
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$(cat "$OUT/pre.$h" 2>/dev/null)" = "Y" ] || notmounted="$notmounted $h"
done
if [ -n "$notmounted" ]; then
    echo "ABORT: not mounted:$notmounted — fleet is not prepped"
    exit 2
fi
echo "precondition OK: all $N nodes mounted"

# 0b. sess380 PER-LBA OFFERED-LOAD WATCH (D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379).
#     WATCH_SLOT=<idx> arms mxfs's caw_watch_slot counters on EVERY node, so the
#     storm's total command load on that one sector can be summed across the
#     fleet afterwards.  That number is what separates the two live mechanisms:
#       O(N)   ~= one command per node  -> the target's per-command service time
#                on a CAW'd sector is itself seconds, and no amount of backoff
#                helps; only not sharing the sector does.
#       O(N^2) ~= hundreds              -> the un-backed-off optimistic-CAS retry
#                loop is the amplifier, and removing/limiting the retries is a
#                real fix.
#     Get the index from `caw_slotdump <dev> --type inode | grep ' ino=<N> '`
#     (it is stable for the life of a filesystem but changes across mkfs, since
#     the hash covers the volume UUID).
WATCH_PARM=/sys/module/mxfs/parameters
WATCH_COUNTERS="caw_watch_reads caw_watch_read_totms caw_watch_read_maxms \
caw_watch_spans caw_watch_caws caw_watch_caw_totms caw_watch_caw_maxms \
caw_watch_miscmp caw_watch_err"
if [ -n "${WATCH_SLOT:-}" ]; then
    echo "--- arming caw_watch_slot=$WATCH_SLOT on all $N nodes"
    for i in $(seq 1 "$N"); do
        "$SSH" "test$i" "
            for c in $WATCH_COUNTERS; do echo 0 > $WATCH_PARM/\$c; done
            echo $WATCH_SLOT > $WATCH_PARM/caw_watch_slot
            cat $WATCH_PARM/caw_watch_slot" > "$OUT/watcharm.test$i" 2>&1 &
    done
    wait
    bad=""
    for i in $(seq 1 "$N"); do
        # The ssh wrapper prepends a login banner on stderr, so take the LAST
        # all-digits line rather than the whole capture.
        got=$(grep -xE '[0-9]+' "$OUT/watcharm.test$i" 2>/dev/null | tail -1)
        [ "$got" = "$WATCH_SLOT" ] || bad="$bad test$i"
    done
    if [ -n "$bad" ]; then
        echo "ABORT: caw_watch_slot did not arm on:$bad — the build on those"
        echo "       nodes predates the sess380 counters; the measurement would"
        echo "       silently undercount.  Deploy the current build first."
        exit 2
    fi
    echo "armed and zeroed on all $N nodes"
fi

# 1. Clear each node's kernel ring so the marker sweep sees only this storm.
for i in $(seq 1 "$N"); do
    "$SSH" "test$i" "dmesg --clear" >/dev/null 2>&1 &
done
wait

# 2. The storm.  Each node times its OWN umount so the number is the node's
#    wall, not the ssh fan-out's.
echo "--- unmounting $DEPART_N of $N nodes (stagger=${STAGGER_S:-0}s)"
WALL_T0=$SECONDS
# STAGGER_S>0 spreads the departures instead of firing them together.  It is
# the CONTROL arm: if a staggered fleet unmounts in ~0.1s/node while a
# simultaneous one takes 60s+, the stall is caused by the CONCURRENCY of the
# departures (the shared-LUN work each one issues), not by unmount itself.
#
# DEPART_N=K unmounts only test1..testK and leaves the rest mounted, holding
# the OBSERVER count at N while varying the number of SIMULTANEOUS departures.
# That separates "how many nodes leave at once" from "how many nodes are
# watching them leave" — the two factors in the O(N^2) clean-departure
# FUA-confirm hypothesis.
DEPART_N="${DEPART_N:-$N}"
for i in $(seq 1 "$DEPART_N"); do
    h="test$i"
    ( [ "${STAGGER_S:-0}" != "0" ] && sleep "$(echo "($i - 1) * ${STAGGER_S}" | bc)"
      "$SSH" "$h" "s=\$(date +%s.%N); timeout $HARD_S umount $MNT; rc=\$?; e=\$(date +%s.%N); echo \"WALL \$(echo \"\$e - \$s\" | bc) RC \$rc\"" \
        > "$OUT/umount.$h" 2>&1 ) &
done

# 2a. OBSERVER PROBE (sess379).  A node that is NOT departing times two stats
#     throughout the storm: the mount ROOT (whose CAW slot is the LBA every
#     departing node both CAWs — P109-CLR-RELEASE-ALL type=I id=128 — and
#     FUA-reads) and a SEPARATE file with a DIFFERENT slot.  This separates the
#     two candidate mechanisms:
#       per-LBA  root stat stalls, other-file stat does not  -> the target is
#                serialising COMPARE AND WRITE against overlapping reads on ONE
#                slot, and the fix is to stop N nodes converging on it.
#       global   both stall -> the LUN as a whole is saturated and the fix is
#                admission control on departures.
if [ "$DEPART_N" -lt "$N" ]; then
    OBS="test$N"
    "$SSH" "$OBS" "touch $MNT/.mus_probe 2>/dev/null" >/dev/null 2>&1
    ( "$SSH" "$OBS" "
        end=\$(( \$(date +%s) + 90 )); wr=0; wo=0; n=0
        while [ \$(date +%s) -lt \$end ]; do
            a=\$(date +%s%N); stat -c %i $MNT >/dev/null 2>&1; b=\$(date +%s%N)
            d=\$(( (b - a) / 1000000 )); [ \$d -gt \$wr ] && wr=\$d
            a=\$(date +%s%N); stat -c %i $MNT/.mus_probe >/dev/null 2>&1; b=\$(date +%s%N)
            d=\$(( (b - a) / 1000000 )); [ \$d -gt \$wo ] && wo=\$d
            n=\$((n+1)); sleep 0.05
        done
        echo \"OBS worst_root_ms=\$wr worst_other_ms=\$wo pairs=\$n\"" \
      > "$OUT/observer" 2>&1 ) &

    # sess380: the CONCLUSIVE per-LBA control the sess379 RULE-5 review
    # prescribed — direct READ(16)+FUA to the hot slot and to a cold LBA on the
    # same device and nexus, alternating, with dispatch-to-completion timing.
    # A stat() control cannot do this because two stats can differ in whether
    # they issue a SCSI command at all.  LBA_PROBE_HOT is the hot slot's LBA
    # (slot index + the slot table's base LBA; read it off the target's own
    # `lba` field, or compute base = known_lba - known_slot_index).
    # This is also the measurement that scores the defect's acceptance bar:
    # no operation on a shared resource may exceed 2x the same operation on an
    # uncontended one.
    if [ -n "${LBA_PROBE_HOT:-}" ]; then
        ( "$SSH" "$OBS" "bash /src/mxfs/tests/lba_probe.sh ${LBA_PROBE_DEV:-/dev/sda} $LBA_PROBE_HOT ${LBA_PROBE_COLD:-$((LBA_PROBE_HOT + 20000))} ${LBA_PROBE_SECS:-60}" \
          > "$OUT/lbaprobe" 2>&1 ) &
    fi
fi

# 2b. Stack sampling while the storm is in flight.  The 0/60/120s
#     quantization of the walls says a 60s timeout is being hit (and hit
#     twice by some nodes), but none of the DLM stall markers fire — so the
#     blocking site is NOT the ilock park loop and NOT an inode caw_lock.
#     Only the blocked task's own stack names it.  /proc/<pid>/comm and
#     /proc/<pid>/stack are safe to read on a wedged node; /proc/<pid>/cmdline
#     and /maps are NOT (they take mmap_lock) — never add them here.
for when in ${SAMPLE_AT:-25 75}; do
    ( sleep "$when"
      for i in $(seq 1 "$N"); do
          "$SSH" "test$i" '
            for c in /proc/[0-9]*/comm; do
                p=${c%/comm}
                [ "$(cat "$c" 2>/dev/null)" = "umount" ] || continue
                echo "### pid=${p#/proc/} state=$(awk "{print \$3}" "$p/stat" 2>/dev/null) wchan=$(cat "$p/wchan" 2>/dev/null)"
                cat "$p/stack" 2>/dev/null
            done
            echo "### D-state tasks:"
            for s in /proc/[0-9]*/stat; do
                st=$(awk "{print \$3}" "$s" 2>/dev/null)
                [ "$st" = "D" ] || continue
                p=${s%/stat}
                echo "--- pid=${p#/proc/} comm=$(cat "$p/comm" 2>/dev/null)"
                cat "$p/stack" 2>/dev/null
            done' > "$OUT/stack.${when}s.test$i" 2>/dev/null &
      done
      wait ) &
done
wait
STORM_WALL=$((SECONDS - WALL_T0))
echo "--- storm complete in ${STORM_WALL}s (aggregate)"

# 3. Per-node walls, worst first.
echo
echo "=== per-node umount wall (budget ${BUDGET_S}s) ==="
: > "$OUT/walls"
for i in $(seq 1 "$DEPART_N"); do
    h="test$i"
    line=$(grep -o 'WALL [0-9.]* RC [0-9-]*' "$OUT/umount.$h" 2>/dev/null | tail -1)
    w=$(echo "$line" | awk '{print $2}')
    rc=$(echo "$line" | awk '{print $4}')
    [ -n "$w" ] || { w=-1; rc=noresult; }
    printf '%s %s %s\n' "$w" "$h" "$rc" >> "$OUT/walls"
done
sort -grk1 "$OUT/walls" | awk -v b="$BUDGET_S" '
    { over = ($1 > b) ? "OVER-BUDGET" : "ok";
      printf "  %-8s wall=%8.2fs rc=%-4s %s\n", $2, $1, $3, over;
      if ($1 > b) n++; if ($1 > mx) mx = $1; s += $1; c++ }
    END { printf "  ---- max=%.2fs mean=%.2fs over_budget=%d/%d\n", mx, s/c, n+0, c }'
NOVER=$(awk -v b="$BUDGET_S" '$1 > b' "$OUT/walls" | wc -l)
MAXW=$(sort -grk1 "$OUT/walls" | head -1 | awk '{print $1}')

# 3b. sess380: harvest the per-LBA offered-load counters.
if [ -n "${WATCH_SLOT:-}" ]; then
    for i in $(seq 1 "$N"); do
        "$SSH" "test$i" "
            for c in $WATCH_COUNTERS; do
                printf '%s ' \"\$(cat $WATCH_PARM/\$c 2>/dev/null)\"
            done; echo" > "$OUT/watch.test$i" 2>&1 &
    done
    wait
    echo
    echo "=== PER-LBA OFFERED LOAD on slot $WATCH_SLOT (sess380) ==="
    printf '  %-8s %7s %7s %7s %7s %7s %7s %7s %7s %5s %s\n' \
        node reads rd_tot rd_max spans caws caw_tot caw_max miscmp err role
    : > "$OUT/watchsum"
    for i in $(seq 1 "$N"); do
        set -- $(grep -xE '[0-9][0-9 ]*' "$OUT/watch.test$i" 2>/dev/null | tail -1)
        [ $# -eq 9 ] || { printf '  %-8s NO DATA\n' "test$i"; continue; }
        role=observer; [ "$i" -le "$DEPART_N" ] && role=departed
        printf '  %-8s %7s %7s %7s %7s %7s %7s %7s %7s %5s %s\n' \
            "test$i" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$role"
        echo "$1 $2 $3 $4 $5 $6 $7 $8 $9 $role" >> "$OUT/watchsum"
    done
    awk '
      { rd+=$1; rdt+=$2; if ($3>rdmx) rdmx=$3; sp+=$4;
        cw+=$5; cwt+=$6; if ($7>cwmx) cwmx=$7; mc+=$8; er+=$9; n++ }
      END {
        printf "  ---- FLEET n=%d  reads=%d spans=%d CAWs=%d MISCOMPARE=%d err=%d\n",
               n, rd, sp, cw, mc, er;
        printf "  ---- total commands on this ONE sector = %d  (reads+spans+CAWs)\n",
               rd + sp + cw;
        if (cw > 0)
            printf "  ---- CAS amplification = %.2f commands per successful CAW (%d/%d)\n",
                   (rd + sp + cw) / (cw - mc > 0 ? cw - mc : 1), rd + sp + cw,
                   (cw - mc > 0 ? cw - mc : 1);
        printf "  ---- worst single command: read %d ms, CAW %d ms\n", rdmx, cwmx;
        if (rdt + cwt > 0)
            printf "  ---- summed service time on this sector = %.1f s across the fleet\n",
                   (rdt + cwt) / 1000.0;
      }' "$OUT/watchsum"
fi

# 4. Marker sweep: the discriminator.
echo
if [ -s "$OUT/observer" ]; then
    echo
    echo "=== OBSERVER PROBE (non-departing $OBS, during the storm) ==="
    sed 's/^/  /' "$OUT/observer"
fi
if [ -s "$OUT/lbaprobe" ]; then
    echo
    echo "=== PAIRED LBA PROBE (direct READ(16)+FUA, hot vs cold, same nexus) ==="
    sed 's/^/  /' "$OUT/lbaprobe"
fi

echo "--- collecting DLM stall markers"
for i in $(seq 1 "$N"); do
    "$SSH" "test$i" "dmesg 2>/dev/null | grep -E 'P73-WAITSTALL|P139-LOCKTOTAL|P34-ACQ-SLOW|P-ACQ-ORPHAN-RECLAIM|P-DEMWAIT-REDRIVE|P79-STALEBAST|P140-RECLAIM-COMMIT|P302-FUA-READ-DEADLINE|P303-VERIFY-BREAKER|P-FUA-READ-RETRY|P108-REACQUIRE|P106-STALE-EX|P-TCPEX-REACQ'" \
        > "$OUT/marks.test$i" 2>/dev/null &
done
wait

ws_total=0; ws_acq=0; ws_acq_inflight0=0; ws_acq_inflightN=0
for i in $(seq 1 "$N"); do
    f="$OUT/marks.test$i"
    n=$(grep -c 'P73-WAITSTALL' "$f" 2>/dev/null); n=${n:-0}
    ws_total=$((ws_total + n))
    a=$(grep 'P73-WAITSTALL' "$f" 2>/dev/null | grep -c 'state=4'); a=${a:-0}
    ws_acq=$((ws_acq + a))
    z=$(grep 'P73-WAITSTALL' "$f" 2>/dev/null | grep 'state=4' | grep -c 'acq_inflight=0'); z=${z:-0}
    ws_acq_inflight0=$((ws_acq_inflight0 + z))
    ws_acq_inflightN=$((ws_acq_inflightN + a - z))
done

echo
echo "=== DISCRIMINATOR ==="
echo "  P73-WAITSTALL lines total ............ $ws_total"
echo "  ... with state=4 (ACQUIRING) ......... $ws_acq"
echo "  ....... acq_inflight=0  (H-A leaked) . $ws_acq_inflight0"
echo "  ....... acq_inflight>0  (H-B slow) ... $ws_acq_inflightN"
echo
echo "--- sample P73-WAITSTALL state=4 lines (up to 12):"
cat "$OUT"/marks.test* 2>/dev/null | grep 'P73-WAITSTALL' | grep 'state=4' | head -12 | sed 's/^/  /'
echo
echo "--- P139-LOCKTOTAL over 5000ms (up to 12):"
cat "$OUT"/marks.test* 2>/dev/null | grep 'P139-LOCKTOTAL' | \
    awk 'match($0, /total_ms=[0-9]+/) { v = substr($0, RSTART+9, RLENGTH-9) + 0; if (v > 5000) print }' | head -12 | sed 's/^/  /'
echo
echo "--- P34-ACQ-SLOW over 5000ms (up to 12):"
cat "$OUT"/marks.test* 2>/dev/null | grep 'P34-ACQ-SLOW' | \
    awk 'match($0, /dur_ms=[0-9]+/) { v = substr($0, RSTART+7, RLENGTH-7) + 0; if (v > 5000) print }' | head -12 | sed 's/^/  /'
echo
echo "=== BLOCKED umount STACKS (distinct shapes, with node counts) ==="
for when in ${SAMPLE_AT:-25 75}; do
    echo "--- t+${when}s"
    for i in $(seq 1 "$N"); do
        f="$OUT/stack.${when}s.test$i"
        [ -s "$f" ] || continue
        # one signature per node: the umount task's wchan + its top mxfs/xfs frame
        awk '/^### pid=/ { inu = 1; wch = $0; sub(/.*wchan=/, "", wch); next }
             /^### D-state/ { inu = 0; next }
             inu && /\[<0>\]/ { f = $2; sub(/\+.*/, "", f);
                                if (!shown) { print wch "|" f; shown = 1 } }' "$f"
    done | sort | uniq -c | sort -rn | sed 's/^/  /'
done
echo
echo "--- full stack of the slowest node's umount task (t+25s):"
SLOW=$(sort -grk1 "$OUT/walls" | head -1 | awk '{print $2}')
sed -n '1,40p' "$OUT/stack.25s.$SLOW" 2>/dev/null | sed 's/^/  /'
echo
echo "=== sess379 verify-governor markers (fleet totals) ==="
for m in P302-FUA-READ-DEADLINE P303-VERIFY-BREAKER P-FUA-READ-RETRY P108-REACQUIRE P106-STALE-EX P-TCPEX-REACQ P-ACQ-ORPHAN-RECLAIM; do
    printf '  %-26s %s\n' "$m" "$(cat "$OUT"/marks.test* 2>/dev/null | grep -c "$m")"
done
echo "--- sample P303-VERIFY-BREAKER (up to 6):"
cat "$OUT"/marks.test* 2>/dev/null | grep 'P303-VERIFY-BREAKER' | head -6 | sed 's/^/  /'

echo
if [ "$NOVER" -eq 0 ]; then
    echo "=== mass_umount_stall_probe PASS — every node unmounted within ${BUDGET_S}s (max=${MAXW}s) ==="
    echo "evidence: $OUT"
    exit 0
fi
echo "=== mass_umount_stall_probe FAIL (RULE 0) — $NOVER/$N node(s) over ${BUDGET_S}s, max=${MAXW}s ==="
echo "evidence: $OUT"
exit 1
