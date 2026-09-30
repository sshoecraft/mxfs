#!/bin/bash
#
# sf_base_overlap.sh — two captures of one directory's shortform merge base at
# once, held open, and a VERDICT on whether the node survived them.
#
# WHY.  A survivor of a two-node power cut at 8 nodes on TCP hit the
# allocator's double-free check under the release drain's capture of a
# directory's merge base (mxfs_dir_sf_capture_base).  The base was read, freed
# and replaced with no lock, by callers that hold no lock in common.  The
# window is a few instructions wide, so a plain load meets it about once in
# several hours of rig time; the module parameter sf_base_race_delay_us sleeps
# inside every capture and holds it open.
#
# WHAT IT DOES
#  1. forms the cluster: MXFS_FORCE_PREP=1 ./run.sh N <dlm> prep_cluster
#  2. sets sf_base_race_delay_us on every node and zeroes the two counters
#     (sf_base_captures, sf_base_overlaps)
#  3. runs the load of tests/multi_victim_containment.sh on every node for
#     LOAD_S seconds: every node builds a tree in a directory of its own under
#     ONE shared parent and removes it, so the parent's exclusive grant moves
#     from node to node (a release drain on the node that gives it up) while
#     that node's own next mkdir or rmdir in the parent refreshes the same
#     directory
#  4. reads every node: its boot, its mount, its load, the two counters, what
#     its kernel logged, and what the panic channel received
#  5. sets the parameter back to 0, unmounts every node, runs chk_mxfs
#
# VERDICT
#  PASS     no node went down or logged a kernel fault or a shutdown, the
#           panic channel received no fault, no load loop met an error,
#           chk_mxfs exited 0, AND at least one overlap was counted: the
#           cause was exercised and the nodes survived it
#  VACUOUS  all of the above but no overlap was counted anywhere: nothing
#           here exercised two captures at once, so nothing was verified
#  FAIL     anything else
#
# Budget (derived).  prep 300 (the rig's own bound) + load confirm 30 +
# LOAD_S + load end and read 130 + unmount 140 + chk 200 + followers 5.  LOAD_S defaults to
# 120: the parent's grant moves several times a second under this load at 8
# nodes, so two minutes are hundreds of release drains per node.
#
# Usage: tests/sf_base_overlap.sh <N> <dlm> <delay_us> [label]
# Evidence: tests/evidence/sf_base_overlap/<UTC>_<N><dlm>_<label>/
# Exit 0 iff the verdict is PASS; 2 when the measurement could not be made.
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
N="${1:?usage: sf_base_overlap.sh <N> <dlm> <delay_us> [label]}"
DLM="${2:?usage: sf_base_overlap.sh <N> <dlm> <delay_us> [label]}"
DELAY="${3:?usage: sf_base_overlap.sh <N> <dlm> <delay_us> [label]}"
LABEL="${4:-sfb}"
case "$DLM" in tcp|cawd|caw|cawp) ;; *) echo "dlm must be tcp|cawd|caw|cawp (got '$DLM')" >&2; exit 2 ;; esac
case "$DELAY" in ''|*[!0-9]*) echo "delay_us must be a count of microseconds (got '$DELAY')" >&2; exit 2 ;; esac
LOAD_S="${LOAD_S:-120}"
# DIR_WRITE_DELAY_MS=<ms>: every node sets dbg_dir_write_delay_ms, so the AIL
# pusher's writes of directory blocks and inode clusters lag the log by that
# much on every cycle (the state one cycle in about 3000 met unaided, and
# ended holding names of freed inodes).  Judged per node from the followed
# log: names whose inode lookup answered ENOENT (P26-IGET-FAIL err=-2), and
# the three always-on lines that name a platter image taken over the node's
# own logged changes.
DIR_WRITE_DELAY_MS="${DIR_WRITE_DELAY_MS:-0}"
case "$DIR_WRITE_DELAY_MS" in ''|*[!0-9]*) echo "DIR_WRITE_DELAY_MS must be a count of milliseconds (got '$DIR_WRITE_DELAY_MS')" >&2; exit 2 ;; esac
MNT="${MXFS_MNT:-/mnt/shared}"
DEV="${MXFS_DEV:-/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0}"
EV="$HERE/tests/evidence/sf_base_overlap/$(date -u +%Y%m%dT%H%M%SZ)_${N}${DLM}_$LABEL"
mkdir -p "$EV"
S="$EV/summary.txt"
FAULTS='BUG:|Oops|Kernel panic|general protection|kernel NULL pointer|soft lockup|hard LOCKUP|scheduling while atomic|rcu_preempt self-detected'
SHUT='Filesystem has been shut down|xfs_do_force_shutdown|P-WITHDRAW'
NETCON="$HERE/tests/evidence/netconsole.log"
P=/sys/module/mxfs/parameters

say() { echo "[$(date -u +%T)] $*" | tee -a "$S"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>/dev/null | grep -a -v -E '^Warning: Permanently|Unauthorized access|authorized user, disconnect|System is booting up|^$'; }

NODES=()
for i in $(seq 1 "$N"); do NODES+=("test$i"); done
say "N=$N dlm=$DLM delay_us=$DELAY load=${LOAD_S}s evidence=$EV"

# --- 1. the cluster
MXFS_FORCE_PREP=1 ./run.sh "$N" "$DLM" prep_cluster > "$EV/prep.log" 2>&1
prc=$?
grep -a -E 'PREP FAIL|PREP OK|converge|srcversion' "$EV/prep.log" | tail -n 4 | cut -c1-200 | tee -a "$S"
[ $prc = 0 ] || { say "ABORT: prep_cluster rc=$prc (see $EV/prep.log); nothing measured"; exit 2; }
T0=$(date +%s)
say "cluster formed; module $(on test1 20 'cat /sys/module/mxfs/srcversion') T0=$T0"
NETCON_OFF=$(stat -c %s "$NETCON" 2>/dev/null || echo 0)
for h in "${NODES[@]}"; do
    ( on "$h" 20 'cat /proc/sys/kernel/random/boot_id' | tail -n 1 > "$EV/boot_$h.txt" ) &
done
wait

# every node's kernel log, followed from T0 (a node that panics takes the
# last lines of its journal with it; the panic channel holds those)
FOLLOW_S=$(( 30 + LOAD_S + 130 + 140 + 200 ))
for h in "${NODES[@]}"; do
    ( setsid timeout "$FOLLOW_S" "$SSH" "$h" "journalctl -k -f --since @$T0 -o short-unix --no-pager" </dev/null > "$EV/klog_$h.txt" 2>/dev/null &
      echo $! > "$EV/klog_$h.pid" )
done

# --- 2. the parameter, and the counters from zero
for h in "${NODES[@]}"; do
    ( on "$h" 20 "echo $DELAY > $P/sf_base_race_delay_us; echo 0 > $P/sf_base_captures; echo 0 > $P/sf_base_overlaps; echo $DIR_WRITE_DELAY_MS > $P/dbg_dir_write_delay_ms 2>/dev/null; echo SET=\$(cat $P/sf_base_race_delay_us); echo WRITE_DELAY=\$(cat $P/dbg_dir_write_delay_ms 2>/dev/null)" > "$EV/set_$h.txt" ) &
done
wait
unset_n=0
for h in "${NODES[@]}"; do
    grep -q "^SET=$DELAY\$" "$EV/set_$h.txt" || { unset_n=$(( unset_n + 1 )); say "parameter not set on $h: $(tr '\n' ' ' < "$EV/set_$h.txt")"; }
done
[ $unset_n = 0 ] || { say "ABORT: sf_base_race_delay_us could not be set on $unset_n node(s); the module does not carry the instrument"; exit 2; }
if [ "$DIR_WRITE_DELAY_MS" -gt 0 ]; then
    wd_n=$(cat "$EV"/set_test*.txt | grep -c "^WRITE_DELAY=$DIR_WRITE_DELAY_MS\$")
    say "directory write delay set on $wd_n of $N nodes: ${DIR_WRITE_DELAY_MS} ms"
    [ "$wd_n" = "$N" ] || { say "ABORT: dbg_dir_write_delay_ms could not be set on every node; the module does not carry the parameter"; exit 2; }
fi

# --- 3. the load, on every node
for i in $(seq 1 "$N"); do
    ( on "test$i" 30 "mkdir -p $MNT/.sfb_load/node$i; nohup bash -c '
        SRC=/tmp/sfb_src; D=$MNT/.sfb_load/node$i
        rm -rf \$SRC; mkdir -p \$SRC
        for d in 1 2 3 4 5 6 7 8 9 10; do
            mkdir -p \$SRC/d\$d
            for f in \$(seq 1 40); do seq 1 20 | sed \"s/^/node$i-d\$d-f\$f-/\" > \$SRC/d\$d/file\$f; done
        done
        end=\$((SECONDS + $LOAD_S)); cyc=0; err=0
        rm -f /tmp/sfb_load.cycles /tmp/sfb_load.done /tmp/sfb_load.err /tmp/sfb_load.stop
        while [ \$SECONDS -lt \$end ] && [ ! -e /tmp/sfb_load.stop ]; do
            cyc=\$((cyc+1))
            rsync -a --no-compress \$SRC/ \$D/ >/dev/null 2>>/tmp/sfb_load.err || { rc=\$?; err=\$((err+1)); echo \"FAILED \$(date +%s) cycle=\$cyc rsync rc=\$rc\" >> /tmp/sfb_load.err; }
            sync
            rm -rf \$D 2>>/tmp/sfb_load.err || { rc=\$?; err=\$((err+1)); echo \"FAILED \$(date +%s) cycle=\$cyc rm rc=\$rc\" >> /tmp/sfb_load.err; }
            echo \"\$(date +%s) \$err\" >> /tmp/sfb_load.cycles
        done
        echo cycles=\$cyc,errors=\$err > /tmp/sfb_load.done
    ' >/tmp/sfb_load.log 2>&1 &" ) &
done
wait
cnt=0
for t in $(seq 1 30); do
    cnt=$(on test1 15 "find $MNT/.sfb_load -type f 2>/dev/null | wc -l" | tail -1 | tr -d '[:space:]')
    [ -n "$cnt" ] && [ "$cnt" -gt 100 ] && break
    sleep 1
done
[ "${cnt:-0}" -gt 100 ] || say "the load is not visible from test1 after 30 s (files=${cnt:-?}); the window is measured as it is"
say "load running: ${cnt:-0} files visible from test1; waiting out the window (${LOAD_S}s)"
sleep $(( LOAD_S + 10 ))

# --- 4. every node read
verdict=PASS
OVERLAPS=0; CAPTURES=0
# The load is ended first and waited for.  With every capture asleep for the
# delay a cycle outlasts the window, and the control lap read its nodes and
# unmounted them with the last cycle still running: every unmount answered
# busy at once and the checker never ran.  The delay goes back to 0 here, so
# the last cycle ends at its own pace: 60 s is three times a whole cycle of
# this load at 8 nodes.
for h in "${NODES[@]}"; do
    ( on "$h" 130 "echo 0 > $P/sf_base_race_delay_us 2>/dev/null; echo 0 > $P/dbg_dir_write_delay_ms 2>/dev/null; touch /tmp/sfb_load.stop
        for t in \$(seq 1 60); do [ -e /tmp/sfb_load.done ] && break; sleep 1; done
        echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)
        echo LOAD=\$(cat /tmp/sfb_load.done 2>/dev/null)
        echo LOADERR=\$(tail -n 1 /tmp/sfb_load.cycles 2>/dev/null | cut -d' ' -f2)
        echo BOOT=\$(cat /proc/sys/kernel/random/boot_id)
        echo CAPTURES=\$(cat $P/sf_base_captures 2>/dev/null)
        echo OVERLAPS=\$(cat $P/sf_base_overlaps 2>/dev/null)
        echo '== failed commands (/tmp/sfb_load.err, last 16 KB)'; tail -c 16384 /tmp/sfb_load.err 2>/dev/null" > "$EV/node_$h.txt"
      k="$EV/klog_$h.txt"
      { echo "KLOG_LINES=$(wc -l < "$k")"
        echo "SHUT=$(grep -a -c -E "$SHUT" "$k")"
        echo "FAULTS=$(grep -a -c -E "$FAULTS" "$k")"
        echo "OVERLAP_LINES=$(grep -a -c 'P-SFBASE-OVERLAP' "$k")"
        echo "NOENT_NAMES=$(grep -a 'P26-IGET-FAIL' "$k" | grep -a -c 'err=-2')"
        echo "READ_OVER_UNWRITTEN=$(grep -a -c 'P-READ-OVER-UNDESTAGED' "$k")"
        echo "READ_OVER_UNWRITTEN_DIR=$(grep -a 'P-READ-OVER-UNDESTAGED' "$k" | grep -a -c -E 'ops=[a-z_0-9]*dir')"
        echo "MERGE_READDS=$(grep -a -c 'P-SFM-READD-ALWAYS' "$k")"
        echo "MERGE_READDS_NO_PEER=$(grep -a 'P-SFM-READD-ALWAYS' "$k" | grep -a -c 'peer_mod=0')"
        echo "FROMDISK_OVER_DIRTY=$(grep -a -c 'P-FROMDISK-OVER-DIRTY-DIR' "$k")"
        echo "WRITE_DELAYS=$(grep -a -c 'P-DBG-DIR-WRITE-DELAY' "$k")"
      } >> "$EV/node_$h.txt" ) &
done
wait
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
for h in "${NODES[@]}"; do
    f="$EV/node_$h.txt"
    mounted=$(sed -n 's/^MOUNTED=//p' "$f"); shut=$(sed -n 's/^SHUT=//p' "$f"); faults=$(sed -n 's/^FAULTS=//p' "$f")
    loaderr=$(sed -n 's/^LOADERR=//p' "$f"); klines=$(sed -n 's/^KLOG_LINES=//p' "$f")
    cap=$(sed -n 's/^CAPTURES=//p' "$f"); ovl=$(sed -n 's/^OVERLAPS=//p' "$f")
    boot0=$(tr -d '[:space:]' < "$EV/boot_$h.txt" 2>/dev/null); boot1=$(sed -n 's/^BOOT=//p' "$f")
    ok=1
    [ "$mounted" = 1 ] || ok=0
    [ "${shut:-x}" = 0 ] || ok=0
    [ "${faults:-x}" = 0 ] || ok=0
    [ "${loaderr:-x}" = 0 ] || ok=0
    [ "${klines:-0}" -gt 0 ] || ok=0
    if [ -z "$boot0" ] || [ "$boot0" != "$boot1" ]; then
        ok=0
        say "node $h: it is not the boot it was when the cluster formed (then '${boot0:-unread}', now '${boot1:-unread}'): it went down during the lap"
    fi
    case "${ovl:-}" in ''|*[!0-9]*) ;; *) OVERLAPS=$(( OVERLAPS + ovl )) ;; esac
    case "${cap:-}" in ''|*[!0-9]*) ;; *) CAPTURES=$(( CAPTURES + cap )) ;; esac
    noent=$(sed -n 's/^NOENT_NAMES=//p' "$f")
    [ "${noent:-x}" = 0 ] || ok=0
    [ $ok = 1 ] || verdict=FAIL
    say "node $h: $([ $ok = 1 ] && echo ok || echo BAD) klog_lines=${klines:-0} mounted=$mounted shutdown_lines=$shut fault_lines=$faults load_errors=$loaderr captures=${cap:-unread} overlaps=${ovl:-unread} overlap_lines=$(sed -n 's/^OVERLAP_LINES=//p' "$f") load=$(sed -n 's/^LOAD=//p' "$f")"
    say "images on $h: names_of_absent_inodes=${noent:-unread} platter_reads_over_unwritten=$(sed -n 's/^READ_OVER_UNWRITTEN=//p' "$f") of_them_directory_blocks=$(sed -n 's/^READ_OVER_UNWRITTEN_DIR=//p' "$f") merge_readds=$(sed -n 's/^MERGE_READDS=//p' "$f") merge_readds_under_one_tenure=$(sed -n 's/^MERGE_READDS_NO_PEER=//p' "$f") disk_images_over_dirty_dirs=$(sed -n 's/^FROMDISK_OVER_DIRTY=//p' "$f") write_delays=$(sed -n 's/^WRITE_DELAYS=//p' "$f")"
done
say "captures cluster-wide: $CAPTURES, of them begun while another capture of the same directory was in progress: $OVERLAPS"

# --- 5. the parameter back, every node unmounted, the checker
for h in "${NODES[@]}"; do
    ( on "$h" 140 "echo 0 > $P/sf_base_race_delay_us 2>/dev/null; t0=\$SECONDS; timeout 120 umount $MNT; echo UMOUNT_RC=\$? wall=\$((SECONDS - t0))s left=\$(grep -c ' $MNT mxfs ' /proc/mounts)" > "$EV/umount_$h.txt" ) &
done
wait
left=0
for h in "${NODES[@]}"; do
    grep -q 'left=0' "$EV/umount_$h.txt" || { left=$(( left + 1 )); say "unmount $h: $(tr '\n' ' ' < "$EV/umount_$h.txt")"; }
done
if [ $left = 0 ]; then
    on test1 200 "timeout 180 /src/mxfs/tools/chk_mxfs -v $DEV; echo CHK_RC=\$?" > "$EV/chk.txt"
    crc=$(sed -n 's/^CHK_RC=//p' "$EV/chk.txt")
    say "chk_mxfs rc=${crc:-none} ($(grep -a -c -i error "$EV/chk.txt") line(s) naming an error; full output $EV/chk.txt)"
    [ "${crc:-x}" = 0 ] || verdict=FAIL
else
    say "chk_mxfs not run: $left node(s) could not unmount within 120 s"
    verdict=FAIL
fi
for h in "${NODES[@]}"; do
    p=$(cat "$EV/klog_$h.pid" 2>/dev/null)
    [ -n "$p" ] && kill "$p" 2>/dev/null
done
sleep 2
gzip -f "$EV"/klog_test*.txt
scripts/lab_power.sh up "rig:$N" > "$EV/rig_up.log" 2>&1 || say "the rig did not come back whole (see $EV/rig_up.log)"

[ "$verdict" = PASS ] && [ "$OVERLAPS" = 0 ] && verdict=VACUOUS
say "VERDICT $verdict ($N/$DLM, delay ${DELAY}us, ${LOAD_S}s of load, captures=$CAPTURES overlaps=$OVERLAPS)"
echo "RESULT $verdict sf_base_overlap $N/$DLM delay_us=$DELAY captures=$CAPTURES overlaps=$OVERLAPS evidence=$EV"
[ "$verdict" = PASS ]
