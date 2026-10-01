#!/bin/bash
#
# join_during_unmount.sh — a peer's mount that lands while the lone member is
# unmounting must hang neither the unmount nor the mount.
#
# The hazard (0.90.14, 4/net/mesh/direct chk_clean): the lone member's join worker froze
# the mount for the single→multi transition with freeze_super, which takes
# s_umount; an unmount in progress holds s_umount through its whole teardown
# and joins that worker inside it.  The worker waited for the unmount, the
# unmount for the worker (hung task: mxfs-worker in freeze_super, umount
# holding the lock).  0.90.16 takes s_umount with a trylock and holds a
# superblock reference across the freeze; this test drives the race.
#
# Each lap: A mounts alone and writes a little; then B mounts while A, after a
# random delay, unmounts.  Both must return inside their budgets: A's umount
# 60 s (a lone member's unmount measures 1-3 s here, so 60 s is a hang, not a
# slow unmount), B's mount 100 s (the cold-mount budget chk_clean allows a
# remount).  B then unmounts.
#
# The window is a few milliseconds wide — between the sighting and the
# freeze's lock — and 20 laps of random delays never landed in it (0 hits).
# So the module's test knob dbg_join_prefreeze_delay_ms holds A's join worker
# for HOLD_MS right before the freeze, and A's umount starts inside that hold
# (delay drawn from 0..HOLD_MS/2 after B's mount begins): the worker then
# meets an unmount that already holds s_umount, which is exactly the shape
# that deadlocked.  A lap "hit the window" when A's kernel log gained a
# freeze attempt (P-JOIN-FREEZE or P-JOIN-FREEZE-BUSY) during it; a run in
# which no lap hit the window established nothing and FAILs as VACUOUS rather
# than passing.  Any "blocked for more than" hung-task report on either node
# during the run FAILs it, as does a module use count that does not return to
# its pre-run value (a leaked superblock reference).
#
# Usage: [LAPS=20] [HOLD_MS=3000] tests/join_during_unmount.sh [A] [B]
#   A and B default to test1 test2; MXFS_DEV and MXFS_MOUNT as run.sh (the
#   by-path rig LUN, /mnt/shared).  Both nodes must have the module loaded and
#   the LUN formatted (MXFS_FORCE_PREP=1 ./run.sh 2/net/mesh/direct prep_cluster does
#   both); the test unmounts them first.
#   Evidence: tests/evidence/join_during_unmount/<stamp>/.  Exit 0 only on PASS.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
A="${1:-test1}"
B="${2:-test2}"
LAPS="${LAPS:-20}"
HOLD_MS="${HOLD_MS:-3000}"
KNOB=/sys/module/mxfs/parameters/dbg_join_prefreeze_delay_ms
DEV="${MXFS_DEV:-/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
SSH="$HERE/tools/mxfs_sshpass.sh"
UMOUNT_S=60
MOUNT_S=100
EV="$HERE/tests/evidence/join_during_unmount/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date -u +%T)] $*"; }
on() {  # <node> <timeout-s> <cmd>
    local n=$1 t=$2; shift 2
    timeout "$t" "$SSH" "$n" "$@" </dev/null 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"
    return "${PIPESTATUS[0]}"
}
now_ms() { date +%s%3N; }

say "A=$A B=$B dev=$DEV mnt=$MNT laps=$LAPS evidence=$EV"
for n in "$A" "$B"; do
    on "$n" 30 "lsmod | grep -q '^mxfs ' && echo module_ok; [ -b $DEV ] && echo dev_ok; cat /sys/module/mxfs/srcversion" > "$EV/pre_$n.log"
    grep -q module_ok "$EV/pre_$n.log" || { say "RESULT FAIL: mxfs not loaded on $n"; exit 1; }
    grep -q dev_ok "$EV/pre_$n.log" || { say "RESULT FAIL: $DEV absent on $n"; exit 1; }
    say "$n srcversion=$(tail -1 "$EV/pre_$n.log")"
    on "$n" 90 "grep -q ' $MNT ' /proc/mounts && timeout $UMOUNT_S umount $MNT; grep -c ' $MNT ' /proc/mounts; true" > "$EV/preumount_$n.log"
    [ "$(tail -1 "$EV/preumount_$n.log")" = 0 ] || { say "RESULT FAIL: could not unmount $MNT on $n before the run"; exit 1; }
done
# hung-task and join-freeze counters, before; and the module's use count with
# nothing mounted, which a leaked superblock reference (a freeze's reference
# never dropped) would leave raised at the end
hung0_a=$(on "$A" 20 "dmesg | grep -c 'blocked for more than'"); hung0_a=${hung0_a:-0}
hung0_b=$(on "$B" 20 "dmesg | grep -c 'blocked for more than'"); hung0_b=${hung0_b:-0}
modref() { on "$1" 20 "awk '\$1==\"mxfs\"{print \$3}' /proc/modules"; }
ref0_a=$(modref "$A"); ref0_b=$(modref "$B")
say "module use count with nothing mounted: $A=$ref0_a $B=$ref0_b"
# hold A's join worker before its freeze for HOLD_MS; cleared on exit
on "$A" 20 "[ -w $KNOB ] && echo $HOLD_MS > $KNOB && echo knob=\$(cat $KNOB)" > "$EV/knob.log"
grep -q "knob=$HOLD_MS" "$EV/knob.log" || { say "RESULT FAIL: $KNOB is not settable on $A (module built without the test knob?)"; exit 1; }
trap 'on "$A" 20 "echo 0 > $KNOB" >/dev/null' EXIT
say "join worker pre-freeze hold on $A: ${HOLD_MS} ms; A's umount starts 0..$((HOLD_MS / 2)) ms after B's mount begins"

fails=0; hits=0; max_um=0; max_mt=0
for ((lap = 1; lap <= LAPS; lap++)); do
    L="$EV/lap$lap"; mkdir -p "$L"
    # A alone, with something dirty to land
    t0=$(now_ms)
    on "$A" $MOUNT_S "mount -t mxfs $DEV $MNT && echo a_mounted; mkdir -p $MNT/jdu && dd if=/dev/urandom of=$MNT/jdu/lap$lap bs=64k count=16 conv=fsync 2>/dev/null && echo a_wrote" > "$L/a_mount.log"
    if ! grep -q a_wrote "$L/a_mount.log"; then
        say "lap $lap: FAIL A could not mount alone and write ($(( $(now_ms) - t0 )) ms)"; fails=$((fails + 1)); continue
    fi
    freeze0=$(on "$A" 20 "dmesg | grep -c -E 'P-JOIN-FREEZE( |-BUSY|-FAIL)'"); freeze0=${freeze0:-0}
    # B mounts while A unmounts after a random delay
    ( tb=$(now_ms); on "$B" $MOUNT_S "mount -t mxfs $DEV $MNT; echo b_mount_rc=\$?"; echo "b_ms=$(( $(now_ms) - tb ))" ) > "$L/b_mount.log" &
    bpid=$!
    delay_ms=$((RANDOM % (HOLD_MS / 2 + 1)))
    sleep "$((delay_ms / 1000)).$(printf '%03d' "$((delay_ms % 1000))")"
    ta=$(now_ms)
    on "$A" $((UMOUNT_S + 15)) "timeout $UMOUNT_S umount $MNT; echo a_umount_rc=\$?; echo a_left=\$(grep -c ' $MNT ' /proc/mounts)" > "$L/a_umount.log"
    um_ms=$(( $(now_ms) - ta ))
    wait "$bpid"
    freeze1=$(on "$A" 20 "dmesg | grep -c -E 'P-JOIN-FREEZE( |-BUSY|-FAIL)'"); freeze1=${freeze1:-0}
    b_rc=$(sed -n 's/^b_mount_rc=//p' "$L/b_mount.log" | tail -1); b_ms=$(sed -n 's/^b_ms=//p' "$L/b_mount.log" | tail -1)
    a_rc=$(sed -n 's/^a_umount_rc=//p' "$L/a_umount.log" | tail -1); a_left=$(sed -n 's/^a_left=//p' "$L/a_umount.log" | tail -1)
    hit=$(( freeze1 - freeze0 ))
    [ "$hit" -gt 0 ] && hits=$((hits + 1))
    [ "$um_ms" -gt "$max_um" ] && max_um=$um_ms
    [ "${b_ms:-0}" -gt "$max_mt" ] && max_mt=${b_ms:-0}
    lapfail=""
    [ "${a_rc:-1}" = 0 ] && [ "${a_left:-1}" = 0 ] || lapfail="$lapfail A-umount(rc=${a_rc:-none} left=${a_left:-?} ${um_ms}ms)"
    [ "${b_rc:-1}" = 0 ] || lapfail="$lapfail B-mount(rc=${b_rc:-none} ${b_ms:-?}ms)"
    say "lap $lap: delay=${delay_ms}ms A-umount=${um_ms}ms rc=${a_rc:-none} left=${a_left:-?} B-mount=${b_ms:-?}ms rc=${b_rc:-none} freeze_attempts=$hit${lapfail:+ FAIL:$lapfail}"
    [ -z "$lapfail" ] || fails=$((fails + 1))
    # B leaves; a mount B could not complete is not left half-way either
    on "$B" 90 "grep -q ' $MNT ' /proc/mounts && timeout $UMOUNT_S umount $MNT; echo b_left=\$(grep -c ' $MNT ' /proc/mounts)" > "$L/b_umount.log"
    grep -q 'b_left=0' "$L/b_umount.log" || { say "lap $lap: FAIL B could not unmount afterwards"; fails=$((fails + 1)); }
    if [ "${a_left:-1}" != 0 ] || ! grep -q 'b_left=0' "$L/b_umount.log"; then
        say "a node is stuck mounted; stopping the run (stacks in $L)"
        for n in "$A" "$B"; do
            on "$n" 40 "for p in /proc/[0-9]*; do c=\$(cat \$p/comm 2>/dev/null) || continue; st=\$(awk '{print \$3}' \$p/stat 2>/dev/null); case \"\$st:\$c\" in D:*|*:umount|*:mount|*:mxfs*|*:xfsaild*) echo \"== pid \${p#/proc/} comm=\$c state=\$st\"; cat \$p/stack 2>/dev/null;; esac; done; dmesg | tail -60" > "$L/stacks_$n.log"
        done
        break
    fi
done
hung1_a=$(on "$A" 20 "dmesg | grep -c 'blocked for more than'"); hung1_a=${hung1_a:-0}
hung1_b=$(on "$B" 20 "dmesg | grep -c 'blocked for more than'"); hung1_b=${hung1_b:-0}
hung=$(( hung1_a - hung0_a + hung1_b - hung0_b ))
on "$A" 30 "dmesg | grep -E 'P-JOIN-FREEZE|P-JOIN-PREPARE-RETRY|P-JOIN-INSTALLED|blocked for more than' | tail -80" > "$EV/a_join_lines.log"

ref1_a=$(modref "$A"); ref1_b=$(modref "$B")
m="laps=$LAPS fails=$fails window_hits=$hits max_umount_ms=$max_um max_mount_ms=$max_mt hung_tasks=$hung modref=$A:$ref0_a->$ref1_a,$B:$ref0_b->$ref1_b"
if [ "$fails" -gt 0 ] || [ "$hung" -gt 0 ]; then
    say "RESULT FAIL ($m)"; exit 1
elif [ "$ref1_a" != "$ref0_a" ] || [ "$ref1_b" != "$ref0_b" ]; then
    say "RESULT FAIL ($m): the module's use count did not return to its pre-run value with nothing mounted — a superblock reference was leaked"; exit 1
elif [ "$hits" -eq 0 ]; then
    say "RESULT FAIL VACUOUS ($m): no lap reached a join freeze attempt during A's unmount, so the race was not exercised"; exit 1
fi
say "RESULT PASS ($m)"
exit 0
