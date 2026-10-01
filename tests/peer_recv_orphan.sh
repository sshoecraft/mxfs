#!/bin/bash
#
# peer_recv_orphan.sh — form the cluster on TCP, unload the module, and a
# VERDICT on whether a peer's receive thread was left to nobody.
#
# WHY.  An unload after eight nodes had mounted together on TCP listed a thread
# nothing had joined: fn=mxfs_peer_recv_fn, created by the accept path, its
# function returned.  A thread in that state is what panicked 15 guests in one
# day before the module's exit learned to stop it.  Both directions connect to
# one peer whenever two nodes sight each other together, and the setup lost a
# handle in two ways:
#   - the outbound setup installed its socket over an inbound connection that
#     had been accepted during its handshake and had ended since (the peer
#     discarded its own outbound socket), writing over that connection's
#     socket and, with its store, over the handle of the thread that read it;
#   - either setup stored its handle after it had dropped the lock that
#     installed its socket, so the other one could run between the two.
#
# WHAT ONE LAP DOES:
#  1. clears every node's kernel ring and preps the fleet (run.sh prep_cluster)
#     with the module parameter peer_recv_start_delay_ms=<delay_ms>, which
#     holds the outbound setup's window open that long (0: natural timing):
#     node 1 mounts, then the others mount together
#  2. waits SETTLE_S (default 15) for both directions' setups to finish
#  3. reads each node's ring: connections taken down (P-PEER-REPLACED: which
#     setup took it down, which had installed it, the age of its handle),
#     handles stored over a stored one (P-PEER-RECV-OVERWRITE), and the
#     control build's line
#  4. unmounts every node, clears the ring, unloads the module, waits SETTLE2_S
#     (default 5: a thread left asleep in freed text wakes within 100 ms) and
#     reads the unload: threads listed at the exit's end, each one the exit
#     had to stop and its function, any fault
#
# A LAP EXERCISED THE CAUSE when the fleet counts at least one of:
#   - an outbound install that found a connection to take down
#     (P-PEER-REPLACED by=connect-install);
#   - an inbound setup that took down an outbound one with no handle stored
#     yet, or within OVERLAP_MS (default 50) of its store (by=accept
#     inst_by=connect): it met the outbound window;
#   - a handle stored over another (the control build's way to show either).
# Laps are repeated, up to MAX_LAPS (default 1), until one exercised it.
#
# VERDICT PASS needs every lap run to be clean and at least one to have
# exercised the cause.  A clean lap: the prep succeeded and on every node the
# same boot before and after the unload, mxfs unloaded, no handle stored over
# another, no thread listed at the exit's end, no P-THREAD-REAP line, no
# kernel fault in the ring; and nothing naming a fault in the panic channel.
# VACUOUS: every lap clean and none exercised the cause.
#
# The nodes are left with the module unloaded; the next prep loads it.
#
# Budget (derived), per lap: prep 330 (its own bound; measured 66-93 s) +
# settle 15 + read 30 + per node in parallel (unmount 75 + rmmod 30 +
# settle 5 + read 30) = 515 s.  Caller bound MAX_LAPS x 515 s; a lap
# measured 90-92 s.
#
# Usage: [MAX_LAPS=n] tests/peer_recv_orphan.sh <configuration> <delay_ms> [label]
# Evidence: tests/evidence/peer_recv_orphan/<UTC>_<label>/lap<i>/
# Exit 0 iff the verdict is PASS; 2 when the measurement could not be made;
# 3 when it was made and exercised nothing.
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
CONFIG=$(python3 "$(dirname "$0")/../tools/configuration.py" parse "${1:?usage: peer_recv_orphan.sh <configuration> <delay_ms> [label]}") || exit 2; N=${CONFIG%%/*}; DLM=${CONFIG#*/}
DELAY="${2:?usage: peer_recv_orphan.sh <configuration> <delay_ms> [label]}"
LABEL="${3:-peer}"
MAX_LAPS="${MAX_LAPS:-1}"
SETTLE_S="${SETTLE_S:-15}"
SETTLE2_S="${SETTLE2_S:-5}"
OVERLAP_MS="${OVERLAP_MS:-50}"
case "$N$DELAY$MAX_LAPS" in *[!0-9]*) echo "nodes, delay_ms and MAX_LAPS are numbers" >&2; exit 2 ;; esac
NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done
TOP="$HERE/tests/evidence/peer_recv_orphan/$(date -u +%Y%m%dT%H%M%SZ)_$LABEL"
mkdir -p "$TOP"
S="$TOP/summary.txt"
FAULTS='BUG:|Oops|Kernel panic|general protection|kernel NULL pointer|soft lockup|hard LOCKUP|scheduling while atomic|rcu_preempt self-detected|Fatal exception'
NETCON="$HERE/tests/evidence/netconsole.log"
P=/sys/module/mxfs/parameters

say() { echo "[$(date -u +%T)] $*" | tee -a "$S"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>/dev/null | grep -a -v -E '^Warning: Permanently|Unauthorized access|authorized user, disconnect|System is booting up|^$'; }
g() { sed -n "s/^$2=//p" "$1" | head -n 1; }

WANT=$(modinfo -F srcversion "$HERE/mxfs.ko" 2>/dev/null)
[ -n "$WANT" ] || { say "ABORT: no mxfs.ko in the tree to name the build"; exit 2; }
SHA=$(sha256sum "$HERE/mxfs.ko" | cut -c1-16)
say "nodes=[${NODES[*]}] dlm=$DLM delay_ms=$DELAY max_laps=$MAX_LAPS settle=${SETTLE_S}s overlap_ms=$OVERLAP_MS build=$WANT sha256=$SHA evidence=$TOP"

T_EXERCISED=0; T_OVERWRITES=0; T_LEAKED=0; T_LEAKED_RECV=0; CONTROL=0
LAP_VERDICT=

one_lap() {  # one_lap <i>: sets LAP_VERDICT to CLEAN, BAD or ABORT and adds to the totals
    local i=$1 EV="$TOP/lap$1" h pids prc t0 netoff netfaults=0 lapok=1
    local x_install=0 x_window=0 overwrites=0 leaked=0 leaked_recv=0 replaced=0
    mkdir -p "$EV"
    netoff=$(stat -c %s "$NETCON" 2>/dev/null || echo 0)

    # --- 1. the ring cleared, then the fleet prepped
    pids=()
    for h in "${NODES[@]}"; do ( on "$h" 20 "dmesg -C; echo CLEARED=1" > "$EV/clear_$h.txt" ) & pids+=($!); done
    wait "${pids[@]}"
    t0=$(date +%s)
    MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS="peer_recv_start_delay_ms=$DELAY" \
        ./run.sh "$CONFIG" prep_cluster > "$EV/prep.log" 2>&1
    prc=$?
    say "lap $i: prep rc=$prc wall=$(( $(date +%s) - t0 ))s"
    if [ "$prc" != 0 ]; then
        say "lap $i: the prep failed, so no cluster formed (see $EV/prep.log)"
        LAP_VERDICT=ABORT
        return
    fi

    # --- 2. both directions' setups finish
    sleep "$SETTLE_S"

    # --- 3. what the setups did, per node
    pids=()
    for h in "${NODES[@]}"; do
        ( on "$h" 30 "echo BOOT0=\$(cat /proc/sys/kernel/random/boot_id)
            echo LOADED0=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)
            echo DELAY_SET=\$(cat $P/peer_recv_start_delay_ms 2>/dev/null)
            echo MOUNTED=\$(grep -c ' mxfs ' /proc/mounts)
            echo REPLACED=\$(dmesg | grep -a -c 'P-PEER-REPLACED')
            echo OVERWRITES=\$(dmesg | grep -a -c 'P-PEER-RECV-OVERWRITE')
            echo REPEATS=\$(dmesg | grep -a -c 'P-PEER-TEARDOWN-REPEAT')
            echo UNLOCKED=\$(dmesg | grep -a -c 'P-PEER-RECV-UNLOCKED')
            echo '== the setups as the ring has them, fields only'
            dmesg | grep -a 'P-PEER-' | sed -e 's/^\\[[^]]*\\] *//' -e 's/ — .*//' | cut -c1-240" > "$EV/ring_$h.txt" ) & pids+=($!)
    done
    wait "${pids[@]}"

    # --- 4. the unload, per node
    pids=()
    for h in "${NODES[@]}"; do
        ( on "$h" 150 "for m in \$(grep ' mxfs ' /proc/mounts | cut -d' ' -f2); do timeout 60 umount \$m; done
            echo MOUNTS=\$(grep -c ' mxfs ' /proc/mounts)
            dmesg -C
            timeout 30 rmmod mxfs; echo RMMOD_RC=\$?
            sleep $SETTLE2_S
            echo BOOT1=\$(cat /proc/sys/kernel/random/boot_id)
            echo LOADED1=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)
            echo LIVE_END=\$(dmesg | grep -a 'P-THREAD-LIVE-SUM when=exit-end' | tail -n 1 | sed -n 's/.* live=\\([0-9]*\\) .*/\\1/p')
            echo COUNTS=\$(dmesg | grep -a 'P-THREAD-LIVE-SUM when=exit-end' | tail -n 1 | grep -a -o -E '(created|joined|join_gaveup)=[0-9]+' | tr '\\n' ' ')
            echo REAPS=\$(dmesg | grep -a -c 'P-THREAD-REAP pid=')
            echo REAPS_RECV=\$(dmesg | grep -a 'P-THREAD-REAP pid=' | grep -a -c 'fn=mxfs_peer_recv_fn')
            echo FAULTS=\$(dmesg | grep -a -c -E '$FAULTS')
            echo '== the unload as the ring has it, fields only'
            dmesg | grep -a 'P-THREAD-' | sed -e 's/^\\[[^]]*\\] *//' -e 's/ — .*//' | cut -c1-240" > "$EV/unload_$h.txt" ) & pids+=($!)
    done
    wait "${pids[@]}"

    # --- 5. the lap's reading
    if [ -r "$NETCON" ]; then
        tail -c +$(( netoff + 1 )) "$NETCON" > "$EV/netconsole_lap.txt" 2>/dev/null
        netfaults=$(grep -a -c -E "$FAULTS" "$EV/netconsole_lap.txt")
    else
        say "lap $i: panic channel $NETCON is not readable, so a guest panic would not have been seen"
        lapok=0
    fi
    [ "$netfaults" = 0 ] || lapok=0
    for h in "${NODES[@]}"; do
        local r="$EV/ring_$h.txt" u="$EV/unload_$h.txt" boot0 boot1 l0 l1 xi xw ow rp le re rr ok=1
        boot0=$(g "$r" BOOT0); boot1=$(g "$u" BOOT1); l0=$(g "$r" LOADED0); l1=$(g "$u" LOADED1)
        xi=$(grep -a 'P-PEER-REPLACED' "$r" | grep -a -c ' by=connect-install ')
        xw=$(grep -a 'P-PEER-REPLACED' "$r" | grep -a ' by=accept inst_by=connect ' | grep -a ' sock=1 ' | sed -n 's/.* since_start_ms=\(-\{0,1\}[0-9]*\).*/\1/p' | awk -v m="$OVERLAP_MS" '$1 <= m { n++ } END { print n + 0 }')
        ow=$(g "$r" OVERWRITES); rp=$(g "$r" REPLACED); le=$(g "$u" LIVE_END); re=$(g "$u" REAPS); rr=$(g "$u" REAPS_RECV)
        x_install=$(( x_install + xi )); x_window=$(( x_window + xw ))
        overwrites=$(( overwrites + ${ow:-0} )); replaced=$(( replaced + ${rp:-0} ))
        leaked=$(( leaked + ${re:-0} )); leaked_recv=$(( leaked_recv + ${rr:-0} ))
        [ "$(g "$r" UNLOCKED)" = 0 ] || CONTROL=1
        [ -n "$boot0" ] && [ "$boot0" = "$boot1" ] || ok=0
        [ "$l0" = "$WANT" ] || ok=0
        [ -z "$l1" ] || ok=0
        [ "$(g "$r" DELAY_SET)" = "$DELAY" ] || ok=0
        [ "$(g "$r" MOUNTED)" = 1 ] || ok=0
        [ "$(g "$u" MOUNTS)" = 0 ] || ok=0
        [ "$(g "$u" RMMOD_RC)" = 0 ] || ok=0
        [ "${ow:-x}" = 0 ] || ok=0
        [ "${le:-x}" = 0 ] || ok=0
        [ "${re:-x}" = 0 ] || ok=0
        [ "$(g "$u" FAULTS)" = 0 ] || ok=0
        [ $ok = 1 ] || lapok=0
        say "lap $i node $h: $([ $ok = 1 ] && echo ok || echo BAD) same_boot=$([ -n "$boot0" ] && [ "$boot0" = "$boot1" ] && echo 1 || echo 0) build=${l0:-none} loaded_after=${l1:-none} delay_set=$(g "$r" DELAY_SET) mounted=$(g "$r" MOUNTED) taken_down=${rp:-?} by_outbound_install=$xi inbound_met_outbound_window=$xw overwrites=${ow:-?} teardown_repeats=$(g "$r" REPEATS) rmmod_rc=$(g "$u" RMMOD_RC) live_at_exit_end=${le:-?} reaped=${re:-?} reaped_peer_recv=${rr:-?} $(g "$u" COUNTS) fault_lines=$(g "$u" FAULTS)"
    done
    local exercised=$(( x_install + x_window + overwrites ))
    say "lap $i fleet: $([ $lapok = 1 ] && echo clean || echo BAD) connections_taken_down=$replaced by_outbound_install=$x_install inbound_met_outbound_window=$x_window handles_overwritten=$overwrites exercised=$exercised threads_left_to_the_exit=$leaked of_them_peer_recv=$leaked_recv panic_channel_faults=$netfaults control_build=$CONTROL"
    T_EXERCISED=$(( T_EXERCISED + exercised )); T_OVERWRITES=$(( T_OVERWRITES + overwrites ))
    T_LEAKED=$(( T_LEAKED + leaked )); T_LEAKED_RECV=$(( T_LEAKED_RECV + leaked_recv ))
    [ $lapok = 1 ] && LAP_VERDICT=CLEAN || LAP_VERDICT=BAD
}

verdict=VACUOUS; rc=3; ran=0
for i in $(seq 1 "$MAX_LAPS"); do
    one_lap "$i"
    ran=$i
    case $LAP_VERDICT in
        ABORT) verdict=ABORT; rc=2; break ;;
        BAD)   verdict=FAIL; rc=1; break ;;
    esac
    if [ "$T_EXERCISED" -gt 0 ]; then verdict=PASS; rc=0; break; fi
done
case $verdict in
    VACUOUS) say "VERDICT VACUOUS: $ran clean lap(s) and in none did a setup meet the other direction's, so nothing here exercised the store" ;;
    *) say "VERDICT $verdict ($N nodes on $DLM, delay ${DELAY} ms, $ran lap(s))" ;;
esac
echo "RESULT $verdict peer_recv_orphan $N/$DLM delay_ms=$DELAY laps=$ran exercised=$T_EXERCISED overwrites=$T_OVERWRITES left_to_exit=$T_LEAKED peer_recv=$T_LEAKED_RECV control_build=$CONTROL evidence=$TOP"
exit $rc
