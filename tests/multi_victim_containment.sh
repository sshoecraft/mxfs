#!/bin/bash
#
# multi_victim_containment.sh — several nodes power-cut at once under write
# load, and a VERDICT on whether the rest of the cluster contained it.
#
# WHY.  The suite's death rows (crash_audit, fence_during_write,
# crash_consistency) kill one node.  The failure this measures needs more
# than one: on a 32-node fleet a wedge of several nodes was fenced, replayed
# and purged correctly by the survivors, and the survivors then shut down one
# after another behind locks the dead nodes had held, until none was left.
# tests/incident474_load_kill.sh reproduces the kill under load and leaves the
# judging to whoever reads the journals; this is the same load and the same
# kill with the judging done, so a release can cite it.
#
# WHAT IT DOES
#  1. forms the cluster: MXFS_FORCE_PREP=1 ./run.sh <configuration> prep_cluster
#  2. starts the load on every node (the loop of incident474_load_kill.sh:
#     build a tree, rsync it into the node's own directory, sync, remove) and
#     confirms from node 1 that it is landing in the shared filesystem
#  3. starts a write probe on every survivor, run on the node itself so no
#     ssh latency is in the measurement: once a second an fsync'd write into
#     the probe's own file, logged with its time and result
#  4. power-cuts the victims (virsh destroy), VICTIM_GAP seconds apart
#  5. lets the load run out (LOAD_S), then reads every survivor
#  6. takes every survivor's mount down and runs chk_mxfs on the LUN
#  7. starts the victims again, so the rig is whole for whatever runs next
#
# THREE OPTIONS, all off unless asked for:
#  VICTIM_RECLAIM_MS=<ms>  each victim runs the superblock's shrinker (2 into
#     drop_caches) once every <ms>, from before the kills until it goes.  A
#     grant on a removed inode leaves through that inode's reclaim, and a
#     victim that dies within seconds of one has that tenure's images in its
#     unreplayed window: the case the replayer judges by the eviction's
#     clean-release marker.  One 8-node TCP lap in six met it unaided, and
#     its slice was refused.  MEASURED (queue j30a, four laps): this option
#     does not make that case.  The shrinker's entry into the filesystem
#     pushes the whole log tail forward before it reclaims an inode, so each
#     pass empties the window; no slice of the four held an image of an ended
#     tenure.  It stays as the instrument for a victim whose window is short.
#  VICTIM_EVICT=1  the exerciser for that case.  Each victim runs, instead of
#     the load, a loop of its own under its load directory, with its log
#     tail PINNED.  The pin is the module's own test parameter
#     dbg_ail_pin_ino (an inode whose log item the tail pusher never
#     flushes): the victim makes a file, names it to the parameter and
#     changes its mode, so that item is the oldest in its log from then on.
#     The loop: make a directory, give it three files whose names are long
#     enough to put it in block format, remove it, run the shrinker, rest
#     VICTIM_EVICT_PAUSE_MS (default 100).  The shrinker reclaims the removed
#     directory at once, which ends its tenure, and with the tail pinned its
#     push moves nothing.  A victim then dies with the images of every
#     directory it removed and reclaimed inside its unreplayed window.  Its
#     log head and tail are followed to lsn_<victim>.txt, ten samples a
#     second, so the window it died with is in the evidence.
#     WHY THE PIN (measured, queue k31a lap 2): without it the tail stood 3
#     to 6 blocks behind the head in every sample of both victims, an idle
#     log's distance.  This filesystem writes a change home within
#     milliseconds of logging it, so a lightly loaded victim dies with a
#     window of one record whatever it evicted, and that lap's slices were
#     admitted whole on the build that leaves the eviction unmarked.
#  ACQ_DELAY_MS=<ms>  with VICTIM_EVICT=1: each victim sets the module's test
#     parameter dbg_publish_acq_delay_ms, which holds the acquire that
#     publishes a directory (its first EX modify after a create served from
#     the inode cache) that long between its snapshot of the certificate's
#     generation and its request.  A release of the same inode then meets
#     that acquire in flight on every cycle instead of once in several laps.
#     What the victim printed about it is on its summary line: releases held
#     back for an acquire in flight, EX handed to a caller with no proving
#     certificate, and the control build's line.
#  PEER_READ_MS=<ms>  with VICTIM_EVICT=1: node 1 lists every victim's
#     exerciser directory once every <ms>, from the start of the load for
#     120 s.  A listing is a shared request for a directory the victim holds
#     exclusively, so the victim is asked to release it again and again
#     while it re-creates it: the release the delayed acquire has to meet.
#     (The lap that refused a slice met it through this harness's own find,
#     once.)
#  PROVER_HOLD_MS=<ms>  every survivor but node 1 sets the module's test
#     parameters dbg_fence_crash_cut=5 and dbg_fence_crash_hold_ms, so the
#     node that proves a victim's exclusion waits that long between its
#     certificate and its manifest, once.  It is set just before the last
#     kill, so with VICTIM_GAP above the 66 s a death takes to be declared
#     the first victim's proof does not spend it.  With VICTIM_GAP=75 the
#     first victim's recovery completes near +70 s, the sweep of its bucket
#     starts 30 s after that, inside the 62 s the last victim is dead and
#     not yet declared.  Node 1 holds the lowest slot and is
#     the elected replayer: it asks for the recovery lease inside that wait
#     and is refused, which one lap in several met unaided.  What follows the
#     refusal is on every survivor's instrument line (replay instances
#     entered, replays refused, the reap worker's arms and duties).  Keep it
#     well under the 62 s a node may be silent: the wait is on the prover's
#     heartbeat thread.
#  REAP_WAIT_MS=<ms>  node 1 sets the module's test parameter
#     dbg_reap_wait_dead_ms just before the last kill: its reap worker's next
#     run (30 s after the first victim's recovery) waits until a node has
#     died and been recovered, at most <ms>, as a duty that needs a grant of
#     the dying node does.  Node 1 also waits 3 s before its own fencing
#     intent (dbg_fence_crash_cut=1), so another survivor proves the last
#     exclusion and, with PROVER_HOLD_MS, node 1's replay is refused while
#     its reap worker stands there.  Two laps with the prover's wait alone
#     met the refusal and a free worker, and the retry ran.
#  KILL_MODE=withdraw  the victims are not power-cut: each forces its
#     filesystem down with its log unflushed (tests/mxfs_shutdown.sh) and
#     stays up, which is what the nodes of the 32-node incident did behind
#     their wedge.  The verdict is the same one: the survivors must fence and
#     replay them and lose nothing of their own.  The victims are powered off
#     before the checker runs and started again at the end.
#
# VERDICT PASS needs every one of:
#  - every survivor still has the filesystem mounted and logged no shutdown
#    of it (XFS's own message, and the module's withdrawal line), and is
#    still the boot it was when the cluster formed
#  - no guest kernel sent a fault to this host's panic channel
#    (tests/evidence/netconsole.log) during the lap: a node that panics
#    reboots, and the last lines of its followed journal are lost with it
#  - every survivor's probe wrote again within WRITE_BUDGET_S of the last
#    kill, and was still writing when the window ended
#  - no survivor logged a kernel fault (the patterns of the suite's
#    kernel_health row)
#  - every survivor's load loop, which shares a parent directory with the
#    victims, met no error and no silence longer than WRITE_BUDGET_S: it may
#    wait for a victim's recovery, it may not be refused
#  - no survivor logged a quarantine of a victim's domain or an operation
#    refused because of one, and the cluster logged a completed recovery for
#    every victim.  A refusal is judged by its reason and its time: the
#    namespace gate prints one line for three reasons, and only a quarantine
#    or a blocked recovery (quar_flag, quar_map, rblk) after the first kill is
#    the victims' doing.  A lookup of a directory another node has removed
#    and made again is refused as a stale incarnation on a healthy cluster
#    (an 8-node CAW lap was failed on ten of those, this harness's own find
#    at +7 s, six seconds before it killed anything); those are counted and
#    printed, not judged.
#  - chk_mxfs exits 0 on the LUN once the survivors have unmounted
#
# The first run of this harness (8/net/mesh/direct, two victims, 0.90.25) is why the load
# and the quarantine are judged: its probes, each writing a file of its own,
# never stalled, and chk_mxfs exited 0, while one victim's slice replay had
# been refused, its allocation group quarantined on all six survivors, and
# every cycle of every load loop failed with an I/O error from then on.  A
# probe that shares nothing with the victims measures nothing about them, and
# the checker does not read a refused slice as an error.
#
# Budgets (derived).  One dead node is declared dead at +60-66 s and the
# measured survivor writes again at +72-101 s (tests/tcp_peer_freeze_death.sh
# at four members, both transports, 0.90.24); that harness allows 120 s for
# the death and 60 s more for the fence and the replay.  Victims killed
# together share the dead window and replay one after another, so
# WRITE_BUDGET_S = 120 + 60 per victim.  LOAD_S must outlast that, so it is
# WRITE_BUDGET_S + 60.  The unmount is bounded at 120 s per node (a clean
# unmount on TCP with peers mounted measured 35-80 s), chk_mxfs at the 180 s
# budget of the suite's chk_clean row.
#
# Usage: tests/multi_victim_containment.sh <configuration> <victim>[,<victim>...] [label]
#   configuration  e.g. 8/net/mesh/direct: its node count names the nodes
#                  (test1..testN)
#   victims  rig nodes to power-cut; node 1 is the probe host and may not be one
# Evidence: tests/evidence/multi_victim/<UTC>_<N-class-method-attach>_<label>/ (summary.txt
#   holds the verdict and one line per survivor; klog_<node>.txt.gz holds
#   every node's kernel log from the moment the cluster formed, the victims'
#   up to the power cut, and is what the log counts in the verdict are read
#   from; load_<node>.txt holds the node's load loop as it ran: one line per
#   failed command with its second and exit status, the commands' own error
#   text, and the cycle file; netconsole_lap.txt holds what the panic channel
#   received during the lap)
# Exit 0 iff the verdict is PASS; 2 when the measurement could not be made.
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
CONFIG=$(python3 tools/configuration.py parse "${1:?usage: multi_victim_containment.sh <configuration> <victim>[,<victim>...] [label]}") || exit 2
N=${CONFIG%%/*}
SLUG=${CONFIG//\//-}
VCSV="${2:?usage: multi_victim_containment.sh <configuration> <victim>[,<victim>...] [label]}"
LABEL="${3:-mvc}"
IFS=, read -r -a VICTIMS <<<"$VCSV"
NV=${#VICTIMS[@]}
VICTIM_GAP="${VICTIM_GAP:-2}"
# how the victims leave, and whether they reclaim until they do (the header
# says what each is for)
KILL_MODE="${KILL_MODE:-power}"
case "$KILL_MODE" in power|withdraw) ;; *) echo "KILL_MODE must be power or withdraw (got '$KILL_MODE')" >&2; exit 2 ;; esac
VICTIM_RECLAIM_MS="${VICTIM_RECLAIM_MS:-0}"
case "$VICTIM_RECLAIM_MS" in ''|*[!0-9]*) echo "VICTIM_RECLAIM_MS must be a count of milliseconds (got '$VICTIM_RECLAIM_MS')" >&2; exit 2 ;; esac
VICTIM_EVICT="${VICTIM_EVICT:-0}"
case "$VICTIM_EVICT" in 0|1) ;; *) echo "VICTIM_EVICT must be 0 or 1 (got '$VICTIM_EVICT')" >&2; exit 2 ;; esac
VICTIM_EVICT_PAUSE_MS="${VICTIM_EVICT_PAUSE_MS:-100}"
case "$VICTIM_EVICT_PAUSE_MS" in ''|*[!0-9]*) echo "VICTIM_EVICT_PAUSE_MS must be a count of milliseconds (got '$VICTIM_EVICT_PAUSE_MS')" >&2; exit 2 ;; esac
ACQ_DELAY_MS="${ACQ_DELAY_MS:-0}"
case "$ACQ_DELAY_MS" in ''|*[!0-9]*) echo "ACQ_DELAY_MS must be a count of milliseconds (got '$ACQ_DELAY_MS')" >&2; exit 2 ;; esac
PEER_READ_MS="${PEER_READ_MS:-0}"
case "$PEER_READ_MS" in ''|*[!0-9]*) echo "PEER_READ_MS must be a count of milliseconds (got '$PEER_READ_MS')" >&2; exit 2 ;; esac
PROVER_HOLD_MS="${PROVER_HOLD_MS:-0}"
case "$PROVER_HOLD_MS" in ''|*[!0-9]*) echo "PROVER_HOLD_MS must be a count of milliseconds (got '$PROVER_HOLD_MS')" >&2; exit 2 ;; esac
REAP_WAIT_MS="${REAP_WAIT_MS:-0}"
case "$REAP_WAIT_MS" in ''|*[!0-9]*) echo "REAP_WAIT_MS must be a count of milliseconds (got '$REAP_WAIT_MS')" >&2; exit 2 ;; esac
WRITE_BUDGET_S="${WRITE_BUDGET_S:-$(( 120 + 60 * NV ))}"
LOAD_S="${LOAD_S:-$(( WRITE_BUDGET_S + 60 ))}"
MNT="${MXFS_MNT:-/mnt/shared}"
DEV="${MXFS_DEV:-$(python3 tools/configuration.py get "$CONFIG" device)}"
EV="$HERE/tests/evidence/multi_victim/$(date -u +%Y%m%dT%H%M%SZ)_${SLUG}_$LABEL"
mkdir -p "$EV"
S="$EV/summary.txt"
FAULTS='BUG:|Oops|Kernel panic|general protection|kernel NULL pointer|soft lockup|hard LOCKUP|scheduling while atomic|rcu_preempt self-detected'
SHUT='Filesystem has been shut down|xfs_do_force_shutdown|P-WITHDRAW'
# a victim whose slice replay ended in a refusal: its domain is quarantined on
# every survivor and what touches it is refused until an operator repairs it
QUAR='P240-QUAR-IMPORT|P241-RECOV-TERMINAL|P-RBLK-TERMINAL'
REFUSED='P240-RBLK-EIO-ABORT|P240-QUAR-NSOP-REFUSE'
NETCON="$HERE/tests/evidence/netconsole.log"

# refusals in a followed log, from epoch $2 on, as "judged stale": the lines
# whose reason is a quarantine or a blocked recovery, and the namespace
# gate's stale-incarnation lines, which are not the victims' doing
refusals() {
    awk -v tk="$2" '
        $1 + 0 < tk { next }
        /P240-RBLK-EIO-ABORT/ { j++; next }
        /P240-QUAR-NSOP-REFUSE/ {
            if ($0 ~ / rblk=[1-9]/ || $0 ~ / quar_flag=[1-9]/ || $0 ~ / quar_map=[1-9]/) j++
            else s++
        }
        END { printf "%d %d\n", j + 0, s + 0 }' "$1"
}

say() { echo "[$(date -u +%T)] $*" | tee -a "$S"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>/dev/null | grep -a -v -E '^Warning: Permanently|Unauthorized access|authorized user, disconnect|System is booting up|^$'; }
# An exit after the load has started ends the load on every node first.  The
# loops are nohup'd and bound only by their own end or the stop file, so an
# ABORT that leaves them running hands them to the next lap in a queue: its
# prep remounts within two minutes and the old loop's rm -rf then runs beside
# the new loop's rsync on the same directory (queue x36b lap 2: every load
# error was that, and four survivors could not unmount).
stop_load() {
    local i pids=()
    for i in $(seq 1 "$N"); do
        on "test$i" 20 "touch /tmp/mvc_load.stop" >/dev/null &
        pids+=($!)
    done
    wait "${pids[@]}"
}

SURVIVORS=()
for i in $(seq 1 "$N"); do
    h="test$i"
    case ",$VCSV," in *",$h,"*) ;; *) SURVIVORS+=("$h") ;; esac
done
for v in "${VICTIMS[@]}"; do
    [[ "$v" =~ ^test([0-9]+)$ ]] && [ "${BASH_REMATCH[1]}" -ge 2 ] && [ "${BASH_REMATCH[1]}" -le "$N" ] \
        || { echo "victim '$v' is not one of test2..test$N" >&2; exit 2; }
done
[ "${#SURVIVORS[@]}" -ge 2 ] || { echo "fewer than two survivors: nothing to contain" >&2; exit 2; }
say "N=$N configuration=$CONFIG victims=[${VICTIMS[*]}] survivors=[${SURVIVORS[*]}] kill_mode=$KILL_MODE victim_reclaim_ms=$VICTIM_RECLAIM_MS victim_evict=$VICTIM_EVICT acq_delay_ms=$ACQ_DELAY_MS peer_read_ms=$PEER_READ_MS write_budget=${WRITE_BUDGET_S}s load=${LOAD_S}s evidence=$EV"

# --- 1. the cluster
MXFS_FORCE_PREP=1 ./run.sh "$CONFIG" prep_cluster > "$EV/prep.log" 2>&1
prc=$?
grep -a -E 'PREP FAIL|PREP OK|converge|srcversion' "$EV/prep.log" | tail -n 4 | cut -c1-200 | tee -a "$S"
[ $prc = 0 ] || { say "ABORT: prep_cluster rc=$prc (see $EV/prep.log); nothing measured"; exit 2; }
T0=$(date +%s)
say "cluster formed; module $(on test1 20 'cat /sys/module/mxfs/srcversion') T0=$T0"
# where the panic channel's log ends now: what it receives from here on is
# this lap's
NETCON_OFF=$(stat -c %s "$NETCON" 2>/dev/null || echo 0)
# the boot every survivor is on, so a node that went down and came back
# during the lap is named as that and not as a node that lost its mount
for h in "${SURVIVORS[@]}"; do
    ( on "$h" 20 'cat /proc/sys/kernel/random/boot_id' | tail -n 1 > "$EV/boot_$h.txt" ) &
done
wait

# --- 1b. every node's kernel log, followed from T0 into the evidence directory
# A node's journal does not keep a lap: on a chatty transport the death window
# had rotated out before the read at the end (the first laps of this harness
# counted 0 deaths and 0 recoveries for that reason alone), and a victim's log
# dies with the victim.  So every node streams its kernel log to this host
# from T0, as plain text the oracle can read while the stream is still open;
# a victim's file holds what it logged up to the power cut.  The follower is
# detached from this shell, because the bare waits below must not wait for
# it, and it ends at its own bound if step 6 does not end it first.  The
# bound is the rest of the lap at its worst: load confirm 30 + probes 5 +
# kills + window + read 60 + unmount 140 + chk 200.
FOLLOW_S=$(( 30 + 5 + (VICTIM_GAP + 1) * NV + LOAD_S + 25 + 60 + 140 + 200 ))
for i in $(seq 1 "$N"); do
    h="test$i"
    ( setsid timeout "$FOLLOW_S" "$SSH" "$h" "journalctl -k -f --since @$T0 -o short-unix --no-pager" </dev/null > "$EV/klog_$h.txt" 2>/dev/null &
      echo $! > "$EV/klog_$h.pid" )
done
# an evicting victim's log head and tail, followed the same way: the last
# sample before it goes is the window the replayer is handed
if [ "$VICTIM_EVICT" = 1 ]; then
    for v in "${VICTIMS[@]}"; do
        ( setsid timeout "$FOLLOW_S" "$SSH" "$v" "while :; do echo \"\$(date +%s.%N) \$(cat /sys/fs/mxfs/*/log/log_head_lsn /sys/fs/mxfs/*/log/log_tail_lsn 2>/dev/null | tr '\n' ' ')\"; sleep 0.1; done" </dev/null > "$EV/lsn_$v.txt" 2>/dev/null &
          echo $! > "$EV/lsn_$v.pid" )
    done
fi

# --- 2. the load, on every node; an evicting victim runs its own loop instead
PS=$(awk -v m="$VICTIM_EVICT_PAUSE_MS" 'BEGIN { printf "%.3f", m / 1000 }')
for i in $(seq 1 "$N"); do
    if [ "$VICTIM_EVICT" = 1 ]; then
        case ",$VCSV," in *",test$i,"*)
            ( on "test$i" 30 "mkdir -p $MNT/.mvc_load/node$i $MNT/.mvc_probe; nohup bash -c '
                H=$MNT/.mvc_load/node$i
                D=\$H/evict
                L=\$(printf %0240d 0)
                rm -f /tmp/mvc_load.stop /tmp/mvc_evict.cycles
                : > \$H/pin; sync
                stat -c %i \$H/pin > /sys/module/mxfs/parameters/dbg_ail_pin_ino
                chmod 600 \$H/pin
                echo $ACQ_DELAY_MS > /sys/module/mxfs/parameters/dbg_publish_acq_delay_ms
                cyc=0
                while [ ! -e /tmp/mvc_load.stop ]; do
                    cyc=\$((cyc+1))
                    mkdir \$D && : > \$D/a\$L && : > \$D/b\$L && : > \$D/c\$L
                    rm -rf \$D
                    echo 2 > /proc/sys/vm/drop_caches
                    echo \"\$(date +%s.%N) \$cyc\" >> /tmp/mvc_evict.cycles
                    sleep $PS
                done
            ' >/tmp/mvc_load.log 2>&1 &" ) &
            continue ;;
        esac
    fi
    ( on "test$i" 30 "mkdir -p $MNT/.mvc_load/node$i $MNT/.mvc_probe; nohup bash -c '
        SRC=/tmp/mvc_src; D=$MNT/.mvc_load/node$i
        rm -rf \$SRC; mkdir -p \$SRC
        for d in 1 2 3 4 5 6 7 8 9 10; do
            mkdir -p \$SRC/d\$d
            for f in \$(seq 1 40); do seq 1 20 | sed \"s/^/node$i-d\$d-f\$f-/\" > \$SRC/d\$d/file\$f; done
        done
        end=\$((SECONDS + $LOAD_S + $VICTIM_GAP * $NV + 30)); cyc=0; err=0
        rm -f /tmp/mvc_load.cycles /tmp/mvc_load.done /tmp/mvc_load.err /tmp/mvc_load.stop
        while [ \$SECONDS -lt \$end ] && [ ! -e /tmp/mvc_load.stop ]; do
            cyc=\$((cyc+1))
            rsync -a --no-compress \$SRC/ \$D/ >/dev/null 2>>/tmp/mvc_load.err || { rc=\$?; err=\$((err+1)); echo \"FAILED \$(date +%s) cycle=\$cyc rsync rc=\$rc\" >> /tmp/mvc_load.err; }
            sync
            rm -rf \$D 2>>/tmp/mvc_load.err || { rc=\$?; err=\$((err+1)); echo \"FAILED \$(date +%s) cycle=\$cyc rm rc=\$rc\" >> /tmp/mvc_load.err; }
            echo \"\$(date +%s) \$err\" >> /tmp/mvc_load.cycles
        done
        echo cycles=\$cyc,errors=\$err > /tmp/mvc_load.done
    ' >/tmp/mvc_load.log 2>&1 &" ) &
done
wait
cnt=0
for t in $(seq 1 30); do
    cnt=$(on test1 15 "find $MNT/.mvc_load -type f 2>/dev/null | wc -l" | tail -1 | tr -d '[:space:]')
    [ -n "$cnt" ] && [ "$cnt" -gt 100 ] && break
    sleep 1
done
[ "${cnt:-0}" -gt 100 ] || { say "ABORT: the load never appeared under $MNT/.mvc_load (files=${cnt:-?}); no node was killed"; stop_load; exit 2; }
say "load confirmed: $cnt files visible from test1"

# --- 3. the write probes, on every survivor
for h in "${SURVIVORS[@]}"; do
    ( on "$h" 30 "rm -f /tmp/mvc_probe.log; nohup bash -c '
        end=\$((SECONDS + $LOAD_S + $VICTIM_GAP * $NV + 20))
        while [ \$SECONDS -lt \$end ] && [ ! -e /tmp/mvc_load.stop ]; do
            if timeout 10 dd if=/dev/zero of=$MNT/.mvc_probe/$h bs=4k count=1 conv=fsync status=none 2>/dev/null; then
                echo \"\$(date +%s) ok\"
            else
                echo \"\$(date +%s) fail\"
            fi >> /tmp/mvc_probe.log
            sleep 1
        done
    ' >/dev/null 2>&1 &" ) &
done
wait

# --- 3a. node 1 lists the victims' exerciser directories
if [ "$VICTIM_EVICT" = 1 ] && [ "$PEER_READ_MS" -gt 0 ]; then
    RD=$(awk -v m="$PEER_READ_MS" 'BEGIN { printf "%.3f", m / 1000 }')
    DIRS=""
    for v in "${VICTIMS[@]}"; do DIRS="$DIRS $MNT/.mvc_load/node${v#test}/evict"; done
    ( on test1 30 "rm -f /tmp/mvc_read.count; nohup bash -c 'end=\$((SECONDS + 120)); n=0; while [ \$SECONDS -lt \$end ]; do for d in $DIRS; do ls -la \$d >/dev/null 2>&1; done; n=\$((n+1)); echo \$n > /tmp/mvc_read.count; sleep $RD; done' >/dev/null 2>&1 &" )
    say "peer reads started on test1: a listing of [$DIRS ] every ${PEER_READ_MS} ms for 120 s"
fi

# --- 3b. the victims reclaim until they go
if [ "$VICTIM_RECLAIM_MS" -gt 0 ]; then
    RS=$(awk -v m="$VICTIM_RECLAIM_MS" 'BEGIN { printf "%.3f", m / 1000 }')
    for v in "${VICTIMS[@]}"; do
        ( on "$v" 30 "nohup bash -c 'while [ ! -e /tmp/mvc_load.stop ]; do echo 2 > /proc/sys/vm/drop_caches; sleep $RS; done' >/dev/null 2>&1 &" ) &
    done
    wait
    say "reclaim started on [${VICTIMS[*]}]: the superblock's shrinker every ${VICTIM_RECLAIM_MS} ms until the node goes"
fi

sleep 5

# --- 4. the kills
TK=0
TK1=$(date +%s)     # the first kill is about to be issued: refusals are judged from here
for v in "${VICTIMS[@]}"; do
    # the prover's wait is set before the LAST kill only: the parameter is
    # spent by the first proof a node makes, and the last victim's is the one
    # a sweep of an earlier victim's bucket can be waiting behind
    if [ "$PROVER_HOLD_MS" -gt 0 ] && [ "$v" = "${VICTIMS[$(( NV - 1 ))]}" ]; then
        for h in "${SURVIVORS[@]}"; do
            [ "$h" = test1 ] && continue
            ( on "$h" 20 "echo $PROVER_HOLD_MS > /sys/module/mxfs/parameters/dbg_fence_crash_hold_ms; echo -1 > /sys/module/mxfs/parameters/dbg_fence_crash_slot; echo 5 > /sys/module/mxfs/parameters/dbg_fence_crash_cut; echo \"$h cut=\$(cat /sys/module/mxfs/parameters/dbg_fence_crash_cut) hold_ms=\$(cat /sys/module/mxfs/parameters/dbg_fence_crash_hold_ms)\"" > "$EV/prover_hold_$h.txt" ) &
        done
        wait
        say "prover hold set on $(cat "$EV"/prover_hold_*.txt 2>/dev/null | grep -c 'cut=5') of $(( ${#SURVIVORS[@]} - 1 )) survivors other than test1 before the kill of $v: ${PROVER_HOLD_MS} ms between the certificate and the manifest, once per node"
    fi
    if [ "$REAP_WAIT_MS" -gt 0 ] && [ "$v" = "${VICTIMS[$(( NV - 1 ))]}" ]; then
        on test1 20 "echo $REAP_WAIT_MS > /sys/module/mxfs/parameters/dbg_reap_wait_dead_ms; echo 3000 > /sys/module/mxfs/parameters/dbg_fence_crash_hold_ms; echo -1 > /sys/module/mxfs/parameters/dbg_fence_crash_slot; echo 1 > /sys/module/mxfs/parameters/dbg_fence_crash_cut; echo \"test1 reap_wait_ms=\$(cat /sys/module/mxfs/parameters/dbg_reap_wait_dead_ms) cut=\$(cat /sys/module/mxfs/parameters/dbg_fence_crash_cut)\"" > "$EV/reap_wait_test1.txt"
        say "reap worker wait set before the kill of $v: $(tr '\n' ' ' < "$EV/reap_wait_test1.txt")"
    fi
    if [ "$KILL_MODE" = withdraw ]; then
        # the filesystem forced down with its log unflushed; the node stays
        # up, and its load and its reclaim end at the stop file
        timeout 30 tests/mxfs_shutdown.sh "$v" "$MNT" 2 </dev/null > "$EV/withdraw_$v.txt" 2>&1
        rc=$?
        grep -q -F 'GOINGDOWN(2) sent' "$EV/withdraw_$v.txt" || rc=1
        on "$v" 20 "touch /tmp/mvc_load.stop" >/dev/null
    else
        timeout 60 virsh -c qemu:///system destroy "$v" >/dev/null 2>&1
        rc=$?
    fi
    TK=$(date +%s)
    say "KILL $v ($KILL_MODE) rc=$rc at +$(( TK - T0 ))s"
    [ $rc = 0 ] || { say "ABORT: $v could not be taken down ($KILL_MODE); the measurement is not the one asked for"; stop_load; exit 2; }
    sleep "$VICTIM_GAP"
done

# --- 5. the window, then every survivor read
[ "$PEER_READ_MS" -gt 0 ] && say "peer reads made by test1 so far: $(on test1 15 'cat /tmp/mvc_read.count 2>/dev/null' | tail -n 1)"
say "waiting out the load window (${LOAD_S}s from the last kill)"
sleep $(( LOAD_S - ( $(date +%s) - TK ) + 25 ))
TE=$(date +%s)
verdict=PASS
for h in "${SURVIVORS[@]}"; do
    # the node answers for its mount, its load and its probe; what its kernel
    # logged is counted from the followed log, which holds the whole lap
    ( on "$h" 60 "echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)
        echo LOAD=\$(cat /tmp/mvc_load.done 2>/dev/null)
        echo LOADERR=\$(tail -n 1 /tmp/mvc_load.cycles 2>/dev/null | cut -d' ' -f2)
        echo LOADSTALL=\$(awk -v tk=$TK '\$1 >= tk { if (p && \$1 - p > g) g = \$1 - p } { p = \$1 } END { print g + 0 }' /tmp/mvc_load.cycles 2>/dev/null)
        echo BOOT=\$(cat /proc/sys/kernel/random/boot_id)
        echo PROBE_BEGIN; cat /tmp/mvc_probe.log 2>/dev/null; echo PROBE_END" > "$EV/survivor_$h.txt"
      # the load loop as it ran: which command failed, when, and what it said
      on "$h" 60 "echo '== failed commands and their error text (/tmp/mvc_load.err, last 64 KB)'; tail -c 65536 /tmp/mvc_load.err 2>/dev/null
        echo '== the loop shell (/tmp/mvc_load.log, last 16 KB)'; tail -c 16384 /tmp/mvc_load.log 2>/dev/null
        echo '== cycles: second, errors so far (/tmp/mvc_load.cycles)'; cat /tmp/mvc_load.cycles 2>/dev/null" > "$EV/load_$h.txt"
      k="$EV/klog_$h.txt"
      read -r judged stale <<<"$(refusals "$k" "$TK1")"
      { echo "KLOG_LINES=$(wc -l < "$k")"
        echo "SHUT=$(grep -a -c -E "$SHUT" "$k")"
        echo "FAULTS=$(grep -a -c -E "$FAULTS" "$k")"
        echo "DEAD=$(grep -a -c 'declaring dead' "$k")"
        echo "RECOVERED=$(grep -a -c 'P163-RECOVERY-COMPLETE' "$k")"
        echo "QUAR=$(grep -a -c -E "$QUAR" "$k")"
        echo "REFUSED_OPS=${judged:-x}"
        echo "REFUSED_STALE=${stale:-x}"
        echo "REFUSED_ALL=$(grep -a -c -E "$REFUSED" "$k")"
        grep -a -E "$SHUT|$FAULTS" "$k" | head -n 20 | cut -c1-300 | sed 's/^/KLOG /'
      } >> "$EV/survivor_$h.txt" ) &
done
wait
# what the panic channel received during the lap.  The harness cuts power, it
# never crashes a kernel, so any fault here is a node's own.
NETFAULTS=0
if [ -r "$NETCON" ]; then
    tail -c +$(( NETCON_OFF + 1 )) "$NETCON" > "$EV/netconsole_lap.txt" 2>/dev/null
    NETFAULTS=$(grep -a -c -E "$FAULTS" "$EV/netconsole_lap.txt")
    say "panic channel during the lap: $(wc -c < "$EV/netconsole_lap.txt") bytes, $NETFAULTS line(s) naming a kernel fault"
else
    say "panic channel: $NETCON is not readable, so a guest panic during the lap would not have been seen"
    verdict=FAIL
fi
[ "$NETFAULTS" = 0 ] || verdict=FAIL
for h in "${SURVIVORS[@]}"; do
    f="$EV/survivor_$h.txt"
    mounted=$(sed -n 's/^MOUNTED=//p' "$f"); shut=$(sed -n 's/^SHUT=//p' "$f"); faults=$(sed -n 's/^FAULTS=//p' "$f")
    # from the probe log: the first write that succeeded after the last kill
    # was followed by no failure, the longest silence after the last kill, and
    # how long before the read the last success was
    read -r resumed stall last_ok fails <<<"$(sed -n '/^PROBE_BEGIN/,/^PROBE_END/p' "$f" | awk -v tk="$TK" -v te="$TE" '
        $2 == "ok" || $2 == "fail" {
            if ($1 >= tk) {
                if ($2 == "fail") { nf++; res = "" }
                else if (res == "") res = $1 - tk
                if (prev && $1 - prev > gap) gap = $1 - prev
            }
            if ($2 == "ok") lastok = $1
            prev = $1
        }
        END { printf "%s %d %s %d\n", (res == "" ? "never" : res), gap, (lastok ? te - lastok : "never"), nf }')"
    ok=1
    [ "$mounted" = 1 ] || ok=0
    [ "${shut:-x}" = 0 ] || ok=0
    [ "${faults:-x}" = 0 ] || ok=0
    boot0=$(tr -d '[:space:]' < "$EV/boot_$h.txt" 2>/dev/null); boot1=$(sed -n 's/^BOOT=//p' "$f")
    if [ -z "$boot0" ] || [ "$boot0" != "$boot1" ]; then
        ok=0
        say "survivor $h: it is not the boot it was when the cluster formed (then '${boot0:-unread}', now '${boot1:-unread}'): it went down during the lap"
    fi
    [ "$resumed" != never ] && [ "$resumed" -le "$WRITE_BUDGET_S" ] && [ "$stall" -le "$WRITE_BUDGET_S" ] || ok=0
    [ "$last_ok" != never ] && [ "$last_ok" -le 60 ] || ok=0
    # the load is the part of the workload that shares a directory with the
    # victims: it may wait for their recovery, it may not be refused
    quar=$(sed -n 's/^QUAR=//p' "$f"); refused=$(sed -n 's/^REFUSED_OPS=//p' "$f")
    loaderr=$(sed -n 's/^LOADERR=//p' "$f"); loadstall=$(sed -n 's/^LOADSTALL=//p' "$f")
    [ "${quar:-x}" = 0 ] && [ "${refused:-x}" = 0 ] || ok=0
    [ "${loaderr:-x}" = 0 ] || ok=0
    [ -n "$loadstall" ] && [ "$loadstall" -le "$WRITE_BUDGET_S" ] || ok=0
    rec=$(sed -n 's/^RECOVERED=//p' "$f"); RECOVERED_ALL=$(( ${RECOVERED_ALL:-0} + ${rec:-0} ))
    # a node whose log was not followed has had nothing counted: its zeros
    # are a capture failure, never a clean result
    klines=$(sed -n 's/^KLOG_LINES=//p' "$f")
    [ "${klines:-0}" -gt 0 ] || { ok=0; say "survivor $h: its kernel log was not captured (klog_lines=${klines:-none}); the counts below are not a measurement"; }
    [ $ok = 1 ] || verdict=FAIL
    say "survivor $h: $([ $ok = 1 ] && echo ok || echo BAD) klog_lines=${klines:-0} mounted=$mounted shutdown_lines=$shut fault_lines=$faults quarantine_lines=$quar refused_ops=$refused stale_lookups_not_judged=$(sed -n 's/^REFUSED_STALE=//p' "$f") load_errors=$loaderr load_longest_stall=${loadstall}s probe_wrote_again=+${resumed}s probe_longest_silence=${stall}s probe_failures=$fails last_write=${last_ok}s_before_read dead_lines=$(sed -n 's/^DEAD=//p' "$f") recovered_lines=$rec load=$(sed -n 's/^LOAD=//p' "$f")"
done
# every victim's recovery has to have completed somewhere in the cluster; the
# line is a debug probe, so none at all on a module loaded without them says
# nothing was measured rather than that nothing completed
if [ "${RECOVERED_ALL:-0}" -lt "$NV" ]; then
    say "recoveries completed cluster-wide: ${RECOVERED_ALL:-0} of $NV victims"
    verdict=FAIL
fi
# What the changes under test print: counted and printed, never judged.  The
# replayer's evaluation of each victim's slice, the acquires that met a master
# they could not reach, and what each victim did before it went.
for h in "${SURVIVORS[@]}"; do
    k="$EV/klog_$h.txt"
    grep -a 'P273-SHADOW-EVAL' "$k" | grep -a -v -E 'state=(unevaluated|no_txns)' | while IFS= read -r line; do
        say "replay evaluation on $h at +$(( ${line%%.*} - T0 ))s: $(echo "$line" | grep -a -o -E '\b(victim_slot|buf|notheld|WOULD_APPLY|REDUNDANT_CLEAN|txn|all_apply|none|relmarks)=[0-9]+' | tr '\n' ' ')"
    done
    say "instruments on $h: unreachable_master_wait=$(grep -a -c 'P-ACQ-UNREACHABLE-MASTER-WAIT' "$k") unreachable_master_noqueue=$(grep -a -c 'P-ACQ-UNREACHABLE-MASTER-NOQUEUE' "$k") ladder_end=$(grep -a -c 'P-ACQ-LADDER-END' "$k") ladder_end_notconn_whole_budget=$(grep -a 'P-ACQ-LADDER-END' "$k" | grep -a 'rc=-107' | grep -a -c 'budget=60') err_notconn=$(grep -a -c 'err=-107' "$k") redundant_skip=$(grep -a -c 'P227-FR-REDUNDANT-SKIP' "$k") atomic_skip=$(grep -a -c 'P227-FR-ATOMIC-SKIP' "$k") terminal=$(grep -a -c 'P241-RECOV-TERMINAL' "$k") base_overlap=$(grep -a -c 'P-SFBASE-OVERLAP' "$k") withdraw_seen=$(grep -a -c 'P163-WITHDRAW-SEEN' "$k") eviction_markers=$(grep -a -c 'P-RELMARK-EVICT' "$k") eviction_markers_not_rc0=$(grep -a 'P-RELMARK-EVICT' "$k" | grep -a -c -v ' rc=0 ') releases_held_for_an_acquire=$(grep -a -c 'P15-REL-ACQ-INFLIGHT' "$k") ex_with_no_certificate=$(grep -a -c 'P-ACQ-UNCERTIFIED' "$k")"
    say "recovery on $h: prover_held=$(grep -a -c 'P-DBG-FENCE-CUT cut=5 .*parking' "$k") lease_busy=$(grep -a -c 'P236-FENCE-ATTEMPT-BUSY' "$k") replay_refused=$(grep -a -c 'foreign replay slot=.*NOT replayed' "$k") replay_instances=$(grep -a -c 'P-FREPLAY-ENTER' "$k") recoveries=$(grep -a -c 'P163-RECOVERY-COMPLETE' "$k") reap_arms=$(grep -a -c 'P89-REAP-SCHED ' "$k") reap_arms_for_a_replay=$(grep -a 'P89-REAP-SCHED ' "$k" | grep -a -c 'why=freplay') reap_arms_that_met_a_running_worker=$(grep -a 'P89-REAP-SCHED ' "$k" | grep -a -c 'busy=RUNNING') reap_worker_entries=$(grep -a -c 'P89-REAP-DUTY duty=enter' "$k") reap_worker_exits=$(grep -a -c 'P89-REAP-DUTY duty=exit' "$k") reap_last_duty=$(grep -a 'P89-REAP-DUTY' "$k" | tail -n 1 | grep -a -o 'duty=[a-z-]*') replay_retries_by_the_timer=$(grep -a -c 'P-FREPLAY-RETRY owed=1' "$k") retry_timer_disabled_control_build=$(grep -a -c 'P-FREPLAY-RETRY-DISABLED' "$k") reap_worker_test_waits=$(grep -a -c 'P-DBG-REAP-WAIT budget' "$k") reap_worker_test_wait_end=$(grep -a 'P-DBG-REAP-WAIT-END' "$k" | grep -a -o 'waited_ms=[0-9]* death_seen=[0-9]' | tr ' ' ,) preintent_waits=$(grep -a -c 'P-DBG-FENCE-CUT cut=1 .*parking' "$k")"
done
for v in "${VICTIMS[@]}"; do
    k="$EV/klog_$v.txt"
    say "victim $v: klog_lines=$(wc -l < "$k") tenures_ended_by_eviction=$(grep -a -c 'P975-TENURE-END-EVICT' "$k") eviction_markers=$(grep -a -c 'P-RELMARK-EVICT ' "$k") eviction_markers_not_rc0=$(grep -a 'P-RELMARK-EVICT ' "$k" | grep -a -c -v ' rc=0 ') eviction_markers_from_a_rearm=$(grep -a 'P-RELMARK-EVICT ' "$k" | grep -a -c ' src=rearm ') peer_release_owed_after_a_rearm=$(grep -a -c 'P-RELMARK-OWED site=bast-rearm' "$k") marker_disabled_control_build=$(grep -a -c 'P-RELMARK-EVICT-DISABLED' "$k") withdraw_stamp=$(grep -a -c 'P163-WITHDRAW-STAMP' "$k") publish_acquires_delayed=$(grep -a -c 'P-DBG-PUBLISH-ACQ-DELAY' "$k") releases_held_for_an_acquire=$(grep -a -c 'P15-REL-ACQ-INFLIGHT' "$k") ex_with_no_certificate=$(grep -a -c 'P-ACQ-UNCERTIFIED' "$k") installs_refused_gen_moved=$(grep -a 'P-ACQ-UNCERTIFIED' "$k" | grep -a -c ' try=5 ') classless_captures_at_ex=$(grep -a -c 'P241-AUTHTRY' "$k") release_ignores_acquire_control_build=$(grep -a -c 'P-REL-IGNORES-ACQ' "$k") last_eviction=$(grep -a 'P975-TENURE-END-EVICT' "$k" | tail -n 1 | awk -v t="$TK1" '{ printf "%.1fs_before_the_first_kill", t - $1 }')"
    # the window an evicting victim went with: its last sample that holds
    # both positions, as the node printed them (cycle:block)
    if [ "$VICTIM_EVICT" = 1 ]; then
        say "victim $v: log window at its last sample: $(awk -v t0="$T0" 'NF >= 3 { l = $0 } END { n = split(l, a, " "); if (n >= 3) { split(a[2], h, ":"); split(a[3], t, ":"); printf "head=%s tail=%s blocks_behind=%s at +%.1fs (%d samples)", a[2], a[3], (h[1] == t[1] ? h[2] - t[2] : "other_cycle"), a[1] - t0, NR } else printf "none of %d samples holds both", NR }' "$EV/lsn_$v.txt" 2>/dev/null)"
    fi
done
if [ "$KILL_MODE" = withdraw ]; then
    # a withdrawn victim is up with a filesystem that is shut down: powered
    # off before the checker reads the LUN, started again at the end
    for v in "${VICTIMS[@]}"; do timeout 60 virsh -c qemu:///system destroy "$v" >/dev/null 2>&1; done
fi

# --- 6. every survivor unmounted, then the checker
# The load and the probe are ended first.  Their own ends count the gap
# between the kills once per victim from their start, so with a long gap they
# outlast the read above, and an unmount under a running cycle answers busy
# at once (two laps at a gap of 75 s: six unmounts rc=32 in 0 s on a healthy
# cluster).  A cycle is a few seconds; 60 s is its bound.
for h in "${SURVIVORS[@]}"; do
    ( on "$h" 80 "touch /tmp/mvc_load.stop; for i in \$(seq 1 60); do [ -e /tmp/mvc_load.done ] && break; sleep 1; done; sleep 2; echo LOAD_ENDED=\$([ -e /tmp/mvc_load.done ] && echo 1 || echo 0); echo LOAD_FINAL=\$(cat /tmp/mvc_load.done 2>/dev/null); echo '== failed commands (/tmp/mvc_load.err, last 16 KB)'; tail -c 16384 /tmp/mvc_load.err 2>/dev/null" > "$EV/loadstop_$h.txt" ) &
done
wait
say "load ended before the unmount on $(cat "$EV"/loadstop_*.txt 2>/dev/null | grep -c 'LOAD_ENDED=1') of ${#SURVIVORS[@]} survivors"
# the load's count of failed commands at its END, and what the followed log
# holds by now: the read in step 5 is taken while the load still runs, and a
# lap whose last cycles failed (names of freed inodes in a survivor's own
# directory, 140 s after that read) passed every line of it
for h in "${SURVIVORS[@]}"; do
    k="$EV/klog_$h.txt"
    fin=$(sed -n 's/^LOAD_FINAL=.*errors=//p' "$EV/loadstop_$h.txt")
    nofile=$(grep -a 'P26-IGET-FAIL' "$k" | grep -a -c 'err=-2')
    rou=$(grep -a -c 'P-READ-OVER-UNDESTAGED' "$k")
    roudir=$(grep -a 'P-READ-OVER-UNDESTAGED' "$k" | grep -a -c -E 'ops=[a-z_0-9]*dir')
    say "load at its end on $h: failed_commands=${fin:-unread} names_of_absent_inodes=$nofile platter_reads_over_unwritten_content=$rou of_them_directory_blocks=$roudir"
    [ "${fin:-x}" = 0 ] && [ "$nofile" = 0 ] || verdict=FAIL
done
for h in "${SURVIVORS[@]}"; do
    ( on "$h" 140 "t0=\$SECONDS; timeout 120 umount $MNT; echo UMOUNT_RC=\$? wall=\$((SECONDS - t0))s left=\$(grep -c ' $MNT mxfs ' /proc/mounts)" > "$EV/umount_$h.txt" ) &
done
wait
left=0
for h in "${SURVIVORS[@]}"; do
    grep -q 'left=0' "$EV/umount_$h.txt" || { left=$(( left + 1 )); say "unmount $h: $(tr '\n' ' ' < "$EV/umount_$h.txt")"; }
done
if [ $left = 0 ]; then
    on test1 200 "timeout 180 /src/mxfs/tools/chk_mxfs -v $DEV; echo CHK_RC=\$?" > "$EV/chk.txt"
    crc=$(sed -n 's/^CHK_RC=//p' "$EV/chk.txt")
    say "chk_mxfs rc=${crc:-none} ($(grep -a -c -i error "$EV/chk.txt") line(s) naming an error; full output $EV/chk.txt)"
    [ "${crc:-x}" = 0 ] || verdict=FAIL
else
    say "chk_mxfs not run: $left survivor(s) could not unmount within 120 s"
    verdict=FAIL
fi

# the followers ended and their logs packed, before the victims boot again
for i in $(seq 1 "$N"); do
    p=$(cat "$EV/klog_test$i.pid" 2>/dev/null)
    [ -n "$p" ] && kill "$p" 2>/dev/null
    p=$(cat "$EV/lsn_test$i.pid" 2>/dev/null)
    [ -n "$p" ] && kill "$p" 2>/dev/null
done
sleep 2
gzip -f "$EV"/klog_test*.txt
say "kernel logs kept: $(ls "$EV"/klog_test*.txt.gz 2>/dev/null | wc -l) of $N nodes ($(du -ch "$EV"/klog_test*.txt.gz 2>/dev/null | tail -n 1 | cut -f1) packed)"

# --- 7. the rig made whole
for v in "${VICTIMS[@]}"; do timeout 60 virsh -c qemu:///system start "$v" >/dev/null 2>&1; done
scripts/lab_power.sh up "rig:$N" > "$EV/rig_up.log" 2>&1 || say "the rig did not come back whole (see $EV/rig_up.log)"

say "VERDICT $verdict ($CONFIG, ${NV} victim(s) [${VICTIMS[*]}], ${#SURVIVORS[@]} survivors, write budget ${WRITE_BUDGET_S}s)"
# the line tests/lap_queue.sh reads back
echo "RESULT $verdict multi_victim_containment $CONFIG victims=${VICTIMS[*]} recoveries=${RECOVERED_ALL:-0}/$NV evidence=$EV"
[ "$verdict" = PASS ]
