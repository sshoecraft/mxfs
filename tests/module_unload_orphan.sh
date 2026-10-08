#!/bin/bash
#
# module_unload_orphan.sh — unload the module with threads nothing joined,
# and a VERDICT on whether the node survived the unload.
#
# WHY.  15 guest kernels panicked in one day of rig work on an instruction
# fetch at an unmapped module address, in a thread named mxfs-worker, with
# mxfs no longer loaded: a thread whose function had returned and which no
# join had stopped was asleep in the module's text when an unload freed it.
# The module's exit now stops every thread still listed.  Which site leaves a
# thread unjoined is not known, so this makes threads in exactly that state
# (the test-only parameter test_orphan_threads) and unloads.
#
# WHAT IT DOES, on each node named:
#  1. requires the module loaded, of this tree's build, and takes the node's
#     MXFS mount down if it has one
#  2. writes ORPHANS (default 2) to test_orphan_threads and reads it back
#  3. rmmod mxfs
#  4. waits SETTLE_S (default 5: a thread left asleep in freed text wakes
#     within 100 ms, so five seconds is fifty chances to fault)
#  5. reads the node: its boot, whether mxfs is gone, and from its kernel
#     ring the lines of the unload (P-THREAD-LIVE, P-THREAD-LIVE-SUM,
#     P-THREAD-REAP) and any fault
#
# VERDICT PASS needs, on every node: the same boot before and after, mxfs
# unloaded, the exit's last summary counting ORPHANS threads live, ORPHANS
# P-THREAD-REAP lines, every one of them with fn_returned=1, no kernel fault
# in the ring, and nothing naming a fault in the panic channel.
#
# The nodes are left with the module unloaded; the next prep loads it.
#
# Budget (derived): per node, ssh and unmount 75 + rmmod 30 + settle 5 +
# read 30; the nodes run in parallel.
#
# Usage: tests/module_unload_orphan.sh <node>[,<node>...] [label]
# Evidence: tests/evidence/module_unload_orphan/<UTC>_<label>/
# Exit 0 iff the verdict is PASS; 2 when the measurement could not be made.
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
NCSV="${1:?usage: module_unload_orphan.sh <node>[,<node>...] [label]}"
LABEL="${2:-orphan}"
ORPHANS="${ORPHANS:-2}"
SETTLE_S="${SETTLE_S:-5}"
MNT="${MXFS_MNT:-/mnt/shared}"
IFS=, read -r -a NODES <<<"$NCSV"
EV="$HERE/tests/evidence/module_unload_orphan/$(date -u +%Y%m%dT%H%M%SZ)_$LABEL"
mkdir -p "$EV"
S="$EV/summary.txt"
FAULTS='BUG:|Oops|Kernel panic|general protection|kernel NULL pointer|soft lockup|hard LOCKUP|scheduling while atomic|rcu_preempt self-detected|Fatal exception'
NETCON="$HERE/tests/evidence/netconsole.log"
P=/sys/module/mxfs/parameters

say() { echo "[$(date -u +%T)] $*" | tee -a "$S"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>/dev/null | grep -a -v -E '^Warning: Permanently|Unauthorized access|authorized user, disconnect|System is booting up|^$'; }

WANT=$(modinfo -F srcversion "$HERE/mxfs.ko" 2>/dev/null)
[ -n "$WANT" ] || { say "ABORT: no mxfs.ko in the tree to name the build"; exit 2; }
say "nodes=[${NODES[*]}] orphans=$ORPHANS settle=${SETTLE_S}s build=$WANT evidence=$EV"
NETCON_OFF=$(stat -c %s "$NETCON" 2>/dev/null || echo 0)

# --- 1-4. on every node, in parallel, each with its own record
for h in "${NODES[@]}"; do
    ( on "$h" 150 "echo BOOT0=\$(cat /proc/sys/kernel/random/boot_id)
        echo LOADED0=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)
        for m in \$(grep ' mxfs ' /proc/mounts | cut -d' ' -f2); do timeout 60 umount \$m; done
        echo MOUNTS=\$(grep -c ' mxfs ' /proc/mounts)
        dmesg -C
        echo $ORPHANS > $P/test_orphan_threads; echo SET_RC=\$?
        echo MADE=\$(cat $P/test_orphan_threads 2>/dev/null)
        timeout 30 rmmod mxfs; echo RMMOD_RC=\$?
        sleep $SETTLE_S
        echo BOOT1=\$(cat /proc/sys/kernel/random/boot_id)
        echo LOADED1=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)
        echo LIVE_END=\$(dmesg | grep -a 'P-THREAD-LIVE-SUM when=exit-end' | tail -n 1 | sed -n 's/.* live=\\([0-9]*\\) .*/\\1/p')
        echo LIVE_LINES=\$(dmesg | grep -a -c 'P-THREAD-LIVE when=exit-end')
        echo REAPS=\$(dmesg | grep -a -c 'P-THREAD-REAP pid=')
        echo REAPS_RETURNED=\$(dmesg | grep -a 'P-THREAD-REAP pid=' | grep -a -c 'fn_returned=1')
        echo REAP_WAITS=\$(dmesg | grep -a -c 'P-THREAD-REAP-WAIT')
        echo FAULTS=\$(dmesg | grep -a -c -E '$FAULTS')
        echo '== the unload as the ring has it, fields only'
        dmesg | grep -a 'P-THREAD-' | sed -e 's/^\\[[^]]*\\] *//' -e 's/ -- .*//' | cut -c1-200" > "$EV/node_$h.txt" ) &
done
wait

# --- 5. the verdict
verdict=PASS
NETFAULTS=0
if [ -r "$NETCON" ]; then
    tail -c +$(( NETCON_OFF + 1 )) "$NETCON" > "$EV/netconsole_lap.txt" 2>/dev/null
    NETFAULTS=$(grep -a -c -E "$FAULTS" "$EV/netconsole_lap.txt")
    say "panic channel during the test: $(wc -c < "$EV/netconsole_lap.txt") bytes, $NETFAULTS line(s) naming a kernel fault, $(grep -a -c 'P-THREAD-REAP pid=' "$EV/netconsole_lap.txt") P-THREAD-REAP line(s)"
else
    say "panic channel: $NETCON is not readable, so a guest panic would not have been seen"
    verdict=FAIL
fi
[ "$NETFAULTS" = 0 ] || verdict=FAIL
for h in "${NODES[@]}"; do
    f="$EV/node_$h.txt"
    g() { sed -n "s/^$1=//p" "$f" | head -n 1; }
    boot0=$(g BOOT0); boot1=$(g BOOT1); l0=$(g LOADED0); l1=$(g LOADED1)
    ok=1
    [ -n "$boot0" ] && [ "$boot0" = "$boot1" ] || ok=0
    [ "$l0" = "$WANT" ] || ok=0
    [ -z "$l1" ] || ok=0
    [ "$(g MOUNTS)" = 0 ] || ok=0
    [ "$(g SET_RC)" = 0 ] && [ "$(g MADE)" = "$ORPHANS" ] || ok=0
    [ "$(g RMMOD_RC)" = 0 ] || ok=0
    [ "$(g LIVE_END)" = "$ORPHANS" ] && [ "$(g LIVE_LINES)" = "$ORPHANS" ] || ok=0
    [ "$(g REAPS)" = "$ORPHANS" ] && [ "$(g REAPS_RETURNED)" = "$ORPHANS" ] || ok=0
    [ "$(g FAULTS)" = 0 ] || ok=0
    [ $ok = 1 ] || verdict=FAIL
    say "node $h: $([ $ok = 1 ] && echo ok || echo BAD) same_boot=$([ -n "$boot0" ] && [ "$boot0" = "$boot1" ] && echo 1 || echo 0) build_before=${l0:-none} loaded_after=${l1:-none} mounts=$(g MOUNTS) set_rc=$(g SET_RC) made=$(g MADE) rmmod_rc=$(g RMMOD_RC) live_at_exit_end=$(g LIVE_END) live_lines=$(g LIVE_LINES) reaped=$(g REAPS) reaped_with_function_returned=$(g REAPS_RETURNED) reap_waits=$(g REAP_WAITS) fault_lines=$(g FAULTS)"
done
say "VERDICT $verdict (${#NODES[@]} node(s), $ORPHANS unjoined thread(s) each)"
echo "RESULT $verdict module_unload_orphan nodes=${NODES[*]} orphans=$ORPHANS evidence=$EV"
[ "$verdict" = PASS ]
