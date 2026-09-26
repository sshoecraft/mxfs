#!/bin/bash
#
# tcp_peer_freeze_death.sh — freeze one node of a 2-node TCP cluster and
# measure whether the survivor declares it dead, fences it and writes again.
#
# The shape comes from the vSphere pair: vstest2 stopped being scheduled
# (a hung guest answers nothing and closes nothing), vstest1 logged "TCP peer
# disconnected — deferring death 40000 ms; EX frozen" 10 s later, and then
# neither "did not reconnect … declaring dead" nor "grace expired but peer
# socket is ACTIVE" in the next 495 s; its P-D8-TICK line, which the same
# worker prints every 30 s, also stopped.  When the peer came back the
# reconnect cancelled the still-pending death; the lease layer expired it at
# 836 s with no incarnation, so no fence ran and the survivor's mount went to
# EIO.  The 2/tcp suite never freezes a node: fault_netpartition drops only
# the DLM's TCP port while lease and disk heartbeats keep flowing.
#
# virsh suspend is that shape without vSphere: the guest's vCPUs stop, its
# sockets stay open, its disk heartbeat stops advancing.
#
# The survivor is instrumented over ssh streams from clyde:
#   - dmesg -w
#   - once a second, the death worker's nr_switches from /proc/<pid>/sched:
#     it wakes every 500 ms, so a looping worker adds ~2/s; a flat count
#     means it is not running its loop, which its stack alone cannot show
#   - every 5 s, a bounded write to the mount: when EX is usable again
#
# Pass: "did not reconnect … declaring dead" within DEATH_BUDGET_S of the
# freeze, and a survivor write succeeding within WRITE_BUDGET_S.  The window
# runs WATCH_S either way, so a death that never comes is measured, not
# waited out.
#
# Budgets: disconnect detection measured 10.8 s on vSphere + the 40 s grace
# = ~51 s, doubled -> DEATH_BUDGET_S=120; fence + replay of an idle 2-node
# slice is seconds, so the write bar is death + 60 s -> WRITE_BUDGET_S=180.
# prep_cluster measured 39 s on the QNAP LUN; run.sh enforces its own budget.
#
# Usage: tests/tcp_peer_freeze_death.sh [victim] [survivor] [watch_seconds]
#   Victim and survivor are VM names.  PREP=rig (default) forms the cluster
#   with ./run.sh 2 tcp prep_cluster on test1/test2.  PREP=<platform>, a
#   data/platforms.json key, uses that platform's verification pair from the
#   lab file (tools/mxfs_lab.sh; survivor = its first node, victim = its
#   second, unless named) as a user installs it: the packaged module, in-guest
#   iSCSI to the lab's shared LUN, mkfs.mxfs from the survivor, mount
#   -o peer=<the other node> at /mnt/mxfs; every other node on the LUN is
#   unmounted first so the LUN is free.
#   A VM that is a libvirt domain is frozen with virsh suspend; one that is
#   not (a QEMU guest started outside libvirt) through QMP stop/cont on its
#   monitor socket, <qemu monitor_dir>/<name>/<name>.monitor from the lab
#   file, which is what virsh suspend sends underneath.
#   Leaves the victim resumed and the cluster as it ended, for inspection.
#
# TRANSPORT=caw runs the same freeze on the CAW transport (the name is
# historical: the harness began on TCP).  PREP=rig forms the cluster with
# ./run.sh 2 cawd; a platform pair loads its packaged module and sets
# force_transport=0 before mounting, and each mount must announce
# transport=CAW.  On CAW there is no TCP socket to lose: the survivor sees the
# victim's disk heartbeat stop, declares it dead (P236-FENCE-INTENT), fences it
# with SCSI PR and replays its journal slice (P163-RECOVERED); the death line
# is the fence intent.  The budgets hold as derived: the CAW dead window is
# ~62 s (heartbeat staleness, measured on the rig) + the fence and an idle
# slice's replay in seconds, inside DEATH_BUDGET_S=120 and WRITE_BUDGET_S=180.
# The TCP death worker's scheduling trace is not taken on CAW.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
WATCH_S="${3:-300}"
DEATH_BUDGET_S=120
WRITE_BUDGET_S=180
PREP="${PREP:-rig}"
TRANSPORT="${TRANSPORT:-tcp}"
case "$TRANSPORT" in
    tcp) TNAME=TCP; RIGDLM=tcp; FT=1
         DEATH_RE="did not reconnect within|has left the cluster" ;;
    # "is no longer responding (heartbeat expired" is the heartbeat monitor's
    # WARN-level declaration and prints on every build.  P236-FENCE-INTENT is
    # a debug probe: a packaged module loaded without dyndbg never prints it,
    # so on every platform pair the death read as "never" while the fence
    # certified at +62 s and the survivor wrote at +65 s (0.90.7, all four).
    caw) TNAME=CAW; RIGDLM=cawd; FT=0
         DEATH_RE="is no longer responding \(heartbeat expired|P236-FENCE-INTENT|declar(ed|ing) dead" ;;
    *) echo "TRANSPORT must be tcp or caw" >&2; exit 2 ;;
esac
if [ "$PREP" = rig ]; then
    PACKAGED=0; MNT=/mnt/shared
    V="${1:-test2}"; S="${2:-test1}"; LUN=${MXFS_LUN:-}
else
    PACKAGED=1; MNT=/mnt/mxfs
    PAIR=$(lab_pair "$PREP") || exit 2
    read -r PA PB <<< "$PAIR"
    V="${1:-$PB}"; S="${2:-$PA}"
    PORTAL=$(lab_need storage portal) || exit 2
    TGT=$(lab_need storage target) || exit 2
    LUN=${MXFS_LUN:-$(lab_need storage lun)} || exit 2   # MXFS_LUN: another target (e.g. the LIO bench LUN)
fi

SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
# the pair's name is part of the directory: tests/full_verify.sh runs every
# platform's pair at once, and three started in one second shared a directory
EV="$HERE/tests/evidence/tcp_peer_freeze_death/$(date +%Y%m%dT%H%M%S)_${PREP}_$TRANSPORT"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; exit 1; }
addr() { lab_addr "$1"; }
# QMP on a non-libvirt guest's monitor socket: qmp NAME COMMAND prints the reply
qmp() {
    local dir
    dir=$(lab_need qemu monitor_dir) || return 1
    python3 - "$dir/$1/$1.monitor" "$2" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()
for cmd in ("qmp_capabilities", sys.argv[2]):
    f.write(json.dumps({"execute": cmd}) + "\n")
    f.flush()
    while True:
        r = json.loads(f.readline())
        if "event" not in r:
            break
print(json.dumps(r))
EOF
}
is_domain() { $VIRSH domstate "$1" >/dev/null 2>&1; }
vm_running() { if is_domain "$1"; then $VIRSH domstate "$1" | grep -q running; else qmp "$1" query-status | grep -q '"running": true'; fi; }
vm_freeze() { if is_domain "$1"; then $VIRSH suspend "$1" >/dev/null; else qmp "$1" stop | grep -q '"return"'; fi; }
vm_thaw() { if is_domain "$1"; then $VIRSH resume "$1" >/dev/null; else qmp "$1" cont | grep -q '"return"'; fi; }
on() { local h t=$2; h=$(addr "$1"); shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"; return "${PIPESTATUS[0]}"; }

say "victim=$V survivor=$S transport=$TRANSPORT watch=${WATCH_S}s evidence=$EV"
vm_running "$V" || fail "$V is not running"

# --- 1. a fresh 2-node cluster on the shared LUN
if [ "$PREP" = rig ]; then
    (cd "$HERE" && ./run.sh 2 $RIGDLM prep_cluster) > "$EV/prep_cluster.log" 2>&1 || { tail -20 "$EV/prep_cluster.log"; fail "prep_cluster"; }
else
    # free the LUN: no other node may hold it while it is reformatted; one
    # that does not answer is not running, so it holds nothing
    for h in $(lab_lun_nodes); do
        case " $S $V " in *" $h "*) continue ;; esac
        on $h 5 true >/dev/null 2>&1 || continue
        on $h 90 "[ -f /root/freeze_busy.pid ] && kill \$(cat /root/freeze_busy.pid) 2>/dev/null; rm -f /root/freeze_busy.pid
            for i in 1 2 3; do grep -q \" /mnt/shared mxfs \" /proc/mounts || break; timeout 20 umount /mnt/shared || sleep 2; done
            grep -c ' mxfs ' /proc/mounts; true" > "$EV/rig_umount_$h.txt"
        [ "$(tail -1 "$EV/rig_umount_$h.txt")" = 0 ] || fail "$h still has MXFS mounted"
    done
    for h in $S $V; do
        on $h 60 "
            # /proc/mounts, not mountpoint(1): a fenced node's withdrawn mount
            # answers stat() with EIO, so mountpoint calls it unmounted
            grep -q \" $MNT mxfs \" /proc/mounts && timeout 30 umount $MNT
            iscsiadm -m session 2>/dev/null | grep -qF $TGT || iscsiadm -m node -T $TGT -p $PORTAL --login >/dev/null 2>&1 || { iscsiadm -m discovery -t st -p $PORTAL >/dev/null && iscsiadm -m node -T $TGT -p $PORTAL --login >/dev/null; }
            for i in 1 2 3 4 5 6 7 8 9 10; do [ -b $LUN ] && break; sleep 1; done
            [ -b $LUN ] && echo lun_ok
            lsmod | grep -q '^mxfs' || modprobe mxfs
            echo $FT > /sys/module/mxfs/parameters/force_transport
            cat /sys/module/mxfs/version /sys/module/mxfs/srcversion; uname -r
        " | tee "$EV/prep_$h.txt"
        grep -q lun_ok "$EV/prep_$h.txt" || fail "$h: the shared LUN is not present"
    done
    on $S 120 "mkfs.mxfs -f $LUN 2>&1 | tail -2; echo mkfs_rc=\${PIPESTATUS[0]}" | tee "$EV/format.txt"
    grep -q 'mkfs_rc=0' "$EV/format.txt" || fail "mkfs.mxfs"
    on $S 60 "mkdir -p $MNT && mount -t mxfs -o peer=$(addr $V) $LUN $MNT; echo mount_rc=\$?" | tee "$EV/mount_$S.txt"
    on $V 120 "mkdir -p $MNT && mount -t mxfs -o peer=$(addr $S) $LUN $MNT; echo mount_rc=\$?" | tee "$EV/mount_$V.txt"
fi
for h in $S $V; do
    on $h 20 "mountpoint -q $MNT && echo mounted; cat /sys/module/mxfs/srcversion; grep MEMBERSHIP /dev/null; dmesg | grep MXFS-MEMBERSHIP | tail -1; dmesg | grep P-DOMAIN-ADMITTED | tail -1 | grep -o 'transport=[A-Z]*'" | tee "$EV/node_$h.txt"
    grep -q mounted "$EV/node_$h.txt" || fail "$h not mounted after prep_cluster"
    grep -qx "transport=$TNAME" "$EV/node_$h.txt" || fail "$h is not on transport=$TNAME"
done

# --- 2. both nodes write, so the victim holds grants and journal content
on $V 60 "mkdir -p $MNT/freeze && for i in \$(seq 1 20); do dd if=/dev/urandom of=$MNT/freeze/v\$i bs=64k count=4 conv=fsync status=none; done; echo victim_writes_ok" | tee "$EV/victim_writes.txt"
on $S 60 "for i in \$(seq 1 20); do dd if=/dev/urandom of=$MNT/freeze/s\$i bs=64k count=4 conv=fsync status=none; done; ls $MNT/freeze | wc -l" | tee "$EV/survivor_writes.txt"
# the victim keeps a write in flight when it freezes: an open EX it never releases
on $V 10 "nohup setsid bash -c 'while :; do dd if=/dev/urandom of=$MNT/freeze/busy bs=64k count=16 conv=fsync status=none; done' >/dev/null 2>&1 < /dev/null & echo \$! > /root/freeze_busy.pid; echo busy_started"

# --- 3. survivor instruments
BG=""
DW=""
if [ "$TRANSPORT" = tcp ]; then
    DW=$(on $S 20 "for p in /proc/[0-9]*; do grep -q v5_tcp_death_worker_fn \$p/stack 2>/dev/null && { echo \${p#/proc/}; break; }; done")
    [ -n "$DW" ] || fail "death worker thread not found on $S"
    say "survivor death worker pid=$DW"
fi
# -W follows only messages printed from now on: replaying the ring (-w) let a
# death line left by an earlier run satisfy the death check at +0 s.
on $S $(( WATCH_S + 120 )) "dmesg -W" > "$EV/dmesg_$S.log" &
BG="$BG $!"
if [ -n "$DW" ]; then
    on $S $(( WATCH_S + 120 )) "while :; do echo \"\$(date +%s.%N) \$(cut -d' ' -f1 /proc/uptime) \$(awk '/^nr_switches/{print \$3}' /proc/$DW/sched) \$(cut -d' ' -f3 /proc/$DW/stat)\"; sleep 1; done" > "$EV/deathworker_$S.log" &
    BG="$BG $!"
fi
# the target's registrations, read by the survivor every 2 s: when (if ever)
# the frozen victim's key leaves the target decides whether PREEMPT can fence it
KEYDEV=$MNT; [ $PACKAGED = 1 ] && KEYDEV=$LUN
on $S $(( WATCH_S + 120 )) "d=\$(findmnt -n -o SOURCE $MNT); [ $PACKAGED = 1 ] && d=$LUN; while :; do echo \"\$(date +%s.%N) \$(sg_persist --in --read-keys \$d 2>&1 | tr -s ' \n' ' ')\"; sleep 2; done" > "$EV/prkeys_$S.log" &
BG="$BG $!"
sleep 3

# --- 4. freeze
T0=$(date +%s)
vm_freeze "$V" || fail "could not freeze $V"
say "froze $V at T0"
death_at=""; write_at=""; i=0
while [ $(( $(date +%s) - T0 )) -lt "$WATCH_S" ]; do
    i=$((i+1))
    e=$(( $(date +%s) - T0 ))
    if on $S 8 "timeout 5 dd if=/dev/zero of=$MNT/freeze/probe$i bs=4k count=1 conv=fsync status=none && echo W_OK" | grep -q W_OK; then
        echo "+${e}s write ok" >> "$EV/survivor_write_probe.log"
        [ -n "$death_at" ] && [ -z "$write_at" ] && write_at=$e
    else
        echo "+${e}s write BLOCKED/FAILED" >> "$EV/survivor_write_probe.log"
    fi
    if [ -z "$death_at" ] && grep -q -E "$DEATH_RE" "$EV/dmesg_$S.log"; then
        death_at=$e; say "death declared by +${e}s"
    fi
    sleep 5
done
say "--- window over: death_at=${death_at:-never} first_write_after_death=${write_at:-never}"

# --- 5. resume the victim and collect
BUSY_BEFORE=""
if [ "${REMOUNT_ON_RESUME:-0}" = 1 ]; then
    # The same host mounting again while the fenced incarnation's writes may
    # still be queued: a new incarnation registers a key on the same I_T
    # nexus, which would re-authorise that nexus.  The survivor records the
    # victim's in-flight file first; if any old write lands afterwards, the
    # file changes under a victim that never wrote it again.
    BUSY_BEFORE=$(on $S 30 "md5sum < $MNT/freeze/busy | cut -c1-32; stat -c %s $MNT/freeze/busy")
    say "busy file on the survivor before resume: $(echo $BUSY_BEFORE)"
fi
vm_thaw "$V" && say "$V resumed"
if [ "${REMOUNT_ON_RESUME:-0}" = 1 ]; then
    on $V 150 "t0=\$(date +%s.%N); umount -l $MNT; echo umount_l_rc=\$?; mount -t mxfs $( [ $PACKAGED = 1 ] && echo "-o peer=$(addr $S) $LUN" || echo "\$(findmnt -n -o SOURCE $MNT 2>/dev/null || echo /dev/sda)") $MNT; echo remount_rc=\$? after_s=\$(echo \"\$(date +%s.%N) - \$t0\" | awk '{print \$1 - \$3}'); grep ' $MNT ' /proc/mounts; dmesg | grep -E 'PRKEY-REGISTER|P305|QUARANTINE|P-BOOT|MEMBERSHIP|already mounted|EBUSY' | tail -8" | tee "$EV/victim_remount.txt"
    sleep 30
    BUSY_AFTER=$(on $S 30 "md5sum < $MNT/freeze/busy | cut -c1-32; stat -c %s $MNT/freeze/busy")
    say "busy file on the survivor 30 s after the victim's remount: $(echo $BUSY_AFTER)"
    [ "$(echo $BUSY_BEFORE)" = "$(echo $BUSY_AFTER)" ] && say "REMOUNT-CHECK busy file UNCHANGED" || say "REMOUNT-CHECK busy file CHANGED — an old write may have landed"
fi
sleep 20
# the busy writer outlives the fence and would hold the victim's mount busy
on $V 20 "kill \$(cat /root/freeze_busy.pid) 2>/dev/null; rm -f /root/freeze_busy.pid" >/dev/null
# Each background instrument is a subshell running timeout | grep; killing the
# subshell alone left timeout -> sshpass -> ssh running to their own timeout,
# ~95 s into whatever test ran next (a PR-IN on the LUN every 2 s among them).
# The whole tree goes, children read from /proc so no process-table scan runs.
kill_tree() {
    local p c
    for p in "$@"; do
        c=$(cat /proc/$p/task/*/children 2>/dev/null)
        kill "$p" 2>/dev/null
        [ -n "$c" ] && kill_tree $c
    done
}
kill_tree $BG
on $V 30 "dmesg | tail -80" > "$EV/dmesg_${V}_after_resume.log"
on $S 20 "grep ' mxfs ' /proc/mounts; ls $MNT/freeze | wc -l" > "$EV/survivor_state_at_end.txt"

[ -n "$DW" ] && python3 - "$EV/deathworker_$S.log" <<'EOF' | tee "$EV/deathworker_rate.txt"
import sys
rows = [l.split() for l in open(sys.argv[1]) if len(l.split()) >= 3 and l.split()[2].isdigit()]
flat, run = 0, 0
for a, b in zip(rows, rows[1:]):
    if b[2] == a[2]:
        run += float(b[0]) - float(a[0]); flat = max(flat, run)
    else:
        run = 0
if len(rows) > 1:
    rate = (int(rows[-1][2]) - int(rows[0][2])) / (float(rows[-1][0]) - float(rows[0][0]))
    print("death worker: %d samples, %.2f switches/s overall, longest flat stretch %.1f s" % (len(rows), rate, flat))
EOF
grep -h -E "TCP peer .* (disconnected|reconnected)|did not reconnect|grace expired|has left the cluster|P309-DEATH|P238-FENCE|P236-FENCE|P-PR-FENCE|P163-RECOVERED|PREEMPT|foreign replay|RECOVERY-COMPLETE|P131-SELF-FENCE|P-D8-TICK" "$EV/dmesg_$S.log" | cut -c1-200

v=PASS
[ -n "$death_at" ] && [ "$death_at" -le "$DEATH_BUDGET_S" ] || v=FAIL
[ -n "$write_at" ] && [ "$write_at" -le "$WRITE_BUDGET_S" ] || v=FAIL
say "VERDICT $v ($TRANSPORT): death declared at +${death_at:-never}s (budget ${DEATH_BUDGET_S}s), survivor wrote at +${write_at:-never}s (budget ${WRITE_BUDGET_S}s)"
say "done: $EV"
[ "$v" = PASS ]
