#!/bin/bash
# pve_churn_fairness.sh — do both hosts of an MXFS-on-DRBD Proxmox pair make
# progress when they churn one shared directory together, and where does the
# slower host's time go?
#
# tests/pve_replay_gate_lag.sh's churn ran participant 0's loops 56-72 times as
# many iterations as participant 1's (nested pair, 0.90.81: 1400-1800 per loop
# against 0-25 in 40-55 s with eight loops per host; 2950 against 675 with one).
# This runs the same churn as an instrument:
#
#  1. Both hosts run CHURN loops in one directory, armed over ssh to start at
#     one wall-clock second T, ARM_S ahead, and to stop at T + WORK_S, so
#     neither host's launch is part of what is measured.  Loop k on either host
#     appends a line to the shared file shared.<k>.log, creates a file of its
#     own and renames it, removes the one it made 20 iterations before, and
#     every 25 iterations syncs the filesystem: the gate test's loop, with each
#     operation timed.
#  2. On each host a sampler reads, every 0.2 s, the state and the top of the
#     kernel stack of every loop task and of the command it is running (mv, rm,
#     sync), into tmpfs.
#
# Output: per host, the iterations of each loop and their total, each
# operation's latency percentiles, and the kernel stacks its loop tasks were
# sampled in, most frequent first.
#
# Verdict: FAIL when a loop reports an error, or when one host's iterations
# are fewer than half the other's (FAIR_MIN, 0.5): two hosts doing the same
# work on the same directory must make comparable progress.
#
# Usage: tests/pve_churn_fairness.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#              participant 0 is the lower address
#   CHURN      loops per host (default 4)
#   WORK_S     seconds of churn (default 40)
#   ARM_S      seconds between the arming and T (default 20)
#   FAIR_MIN   the least ratio of the slower host's iterations to the
#              faster's that passes (default 0.5)
#   MKDIR_ON   the participant that makes the shared directory, 0 or 1
#              (default 0): its maker starts out holding the directory's lock
#   PROBES=1   turn the lock-tenure probes on for the run and report, per
#              host and inode, how long each EX tenure was held and how many
#              operations it served (tools/tenure_report.py)
#
# Evidence: tests/evidence/pve_churn_fairness/<UTC stamp>-<participant 0>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_churn_fairness: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
CHURN=${CHURN:-4}
WORK_S=${WORK_S:-40}
ARM_S=${ARM_S:-20}
FAIR_MIN=${FAIR_MIN:-0.5}
MKDIR_ON=${MKDIR_ON:-0}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TAG=churnfair-$STAMP
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
EVID="$REPO/tests/evidence/pve_churn_fairness/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
D=$MNT/churnfair/$STAMP

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

for h in "$P0" "$P1"; do
    s=$(on "$h" "echo \"name=\$(hostname) mnt=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts | head -1) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)\"" 20)
    say "$h: $s"
    case "$s" in *"mnt=$MNT "*"role=Primary/Primary cs=Connected"*) ;; *) say "ABORT: $h is not a mounted, connected half of the pair"; exit 1 ;; esac
done

# One churn loop: <dir> <k> <T> <end> <tag>.  Each iteration's operations are
# timed in microseconds; the first error stops the loop and is recorded.
LOOP=$(cat <<'EOF'
d=$1; k=$2; T=$3; end=$4; tag=$5
h=$(hostname); i=0
e=/dev/shm/$tag.err.$k
echo $$ > /dev/shm/$tag.pid.$k
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$T"
exec 9>/dev/shm/$tag.ops.$k
endus=$((end * 1000000))
while [ "${EPOCHREALTIME/./}" -lt "$endus" ]; do
    i=$((i + 1))
    t0=${EPOCHREALTIME/./}
    # each operation's stderr (the shell's own open errors included: the 2>
    # is applied before the >> it would report on) goes into its ERR line
    echo "$h $i" 2>$e >> $d/shared.$k.log || { echo "ERR append $i $(tr '\n' ' ' <$e)" >&9; break; }
    t1=${EPOCHREALTIME/./}
    echo "$h $i" 2>$e > $d/$h.$k.$i || { echo "ERR create $i $(tr '\n' ' ' <$e)" >&9; break; }
    t2=${EPOCHREALTIME/./}
    mv $d/$h.$k.$i $d/$h.$k.$i.r 2>$e || { echo "ERR rename $i $(tr '\n' ' ' <$e)" >&9; break; }
    t3=${EPOCHREALTIME/./}
    if [ $i -gt 20 ]; then rm -f $d/$h.$k.$((i - 20)).r 2>$e || { echo "ERR remove $i $(tr '\n' ' ' <$e)" >&9; break; }; fi
    t4=${EPOCHREALTIME/./}
    t5=$t4
    if [ $((i % 25)) = 0 ]; then sync -f $d/shared.$k.log 2>$e || { echo "ERR sync $i $(tr '\n' ' ' <$e)" >&9; break; }; t5=${EPOCHREALTIME/./}; fi
    echo "$i $((t1 - t0)) $((t2 - t1)) $((t3 - t2)) $((t4 - t3)) $((t5 - t4))" >&9
done
echo $i > /dev/shm/$tag.count.$k
EOF
)
# The sampler: <tag> <T> <end>.  Every loop task and its child, state and the
# top of the kernel stack; /proc/<pid>/stat and /stack only.
SAMPLER=$(cat <<'EOF'
tag=$1; T=$2; end=$3
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$T"
while [ "$(date +%s)" -lt "$end" ]; do
    now=${EPOCHREALTIME}
    for pf in /dev/shm/$tag.pid.*; do
        p=$(cat "$pf" 2>/dev/null); k=${pf##*.}
        [ -n "$p" ] || continue
        for t in $p $(cat /proc/$p/task/$p/children 2>/dev/null); do
            st=$(awk '{ i = index($0, ") "); split(substr($0, i + 2), f, " "); print f[1] }' /proc/$t/stat 2>/dev/null)
            [ -n "$st" ] || continue
            echo "$now $k $t $(cat /proc/$t/comm 2>/dev/null) $st $(head -8 /proc/$t/stack 2>/dev/null | sed 's/^\[<[0-9a-f]*>\] //; s/+0x.*//' | tr '\n' ',')"
        done
    done
    sleep 0.2
done > /dev/shm/$tag.samples
EOF
)

case "$MKDIR_ON" in 0) MK=$P0 ;; 1) MK=$P1 ;; *) say "ABORT: MKDIR_ON must be 0 or 1"; exit 2 ;; esac
on "$MK" "mkdir -p $D && echo MADE" 30 | grep -q MADE || { say "ABORT: could not make $D"; exit 1; }
DIRINO=$(on "$MK" "stat -c %i $D" 20 | tail -1)
say "shared directory $D is inode $DIRINO, made on participant $MKDIR_ON ($MK)"
# PROBES=1: the lock-tenure probes for the run (dynamic debug, both hosts):
# P70-BP at every release (held_ms, ops in the tenure, grant-to-first-op and
# last-op-to-release), P483-DIRTENURE (creates per directory tenure), P6-FAIRQ
# (a request queued at the master behind an older waiter, with its age) and
# P-EX-TENURE-CAP (the directory tenure cap closing the fast path)
PROBE_FMTS="P70-BP P483-DIRTENURE P6-FAIRQ P-EX-TENURE-CAP P7S-BAST-FIRE P7B-BASTNOTIFY"
probes() {  # <host> +p|-p
    local f ino=0
    for f in $PROBE_FMTS; do
        on "$1" "echo 'module mxfs format \"$f\" $2' > /proc/dynamic_debug/control" 15
    done
    # P7S (the master firing a BAST) and P7B (the holder receiving one) print
    # for dbg_probe_ino only: the shared directory, so the run names its master
    [ "$2" = +p ] && ino=$DIRINO
    on "$1" "echo $ino > /sys/module/mxfs/parameters/dbg_probe_ino" 15
}
if [ "${PROBES:-0}" = 1 ]; then
    for h in "$P0" "$P1"; do
        probes "$h" +p
        on "$h" "echo '<5>mxfs-test: churnfair $TAG start' > /dev/kmsg" 15
    done
fi
T=$(( $(date +%s) + ARM_S ))
END=$(( T + WORK_S ))
say "arming $CHURN loops per host in $D for $(date -d @$T +%H:%M:%S) (T=$T), $WORK_S s"
for h in "$P0" "$P1"; do
    on "$h" "echo $(base64 -w0 <<<"$LOOP") | base64 -d > /dev/shm/$TAG.loop && echo $(base64 -w0 <<<"$SAMPLER") | base64 -d > /dev/shm/$TAG.sampler &&
        for k in \$(seq 1 $CHURN); do nohup setsid bash /dev/shm/$TAG.loop $D \$k $T $END $TAG > /dev/null 2>&1 < /dev/null & done &&
        nohup setsid bash /dev/shm/$TAG.sampler $TAG $T $END > /dev/null 2>&1 < /dev/null &
        echo ARMED" 30 | grep -q ARMED || { say "ABORT: could not arm $h"; exit 1; }
done
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$END"
say "T+$WORK_S: the loops are due to stop"

# A loop stops after the operation in flight at END; that operation is what
# this measures, so it is waited for, bounded: its longest op seen on the
# starved host was ~1.6 s an iteration (25 in 40 s), twice that per op, 30 s
# for a stuck one to show as missing counts rather than hang the collection.
for h in "$P0" "$P1"; do
    on "$h" "for i in \$(seq 1 30); do n=\$(ls /dev/shm/$TAG.count.* 2>/dev/null | wc -l); [ \"\$n\" -ge $CHURN ] && break; sleep 1; done; echo COUNTS=\$n" 45 > "$EVID/wait.$h"
    say "$h: $(cat "$EVID/wait.$h")"
done
for h in "$P0" "$P1"; do
    on "$h" "for k in \$(seq 1 $CHURN); do echo \"COUNT \$k \$(cat /dev/shm/$TAG.count.\$k 2>/dev/null)\"; done; for k in \$(seq 1 $CHURN); do sed \"s/^/OPS \$k /\" /dev/shm/$TAG.ops.\$k 2>/dev/null; done" 60 > "$EVID/ops.$h"
    on "$h" "cat /dev/shm/$TAG.samples 2>/dev/null" 60 > "$EVID/samples.$h"
    on "$h" "rm -f /dev/shm/$TAG.*; echo CLEAN" 20 >/dev/null
done
if [ "${PROBES:-0}" = 1 ]; then
    for h in "$P0" "$P1"; do
        probes "$h" -p
        on "$h" "journalctl -k -b --no-pager -o short-monotonic | sed -n '/mxfs-test: churnfair $TAG start/,\$p'" 120 > "$EVID/klog.$h"
    done
fi
on "$P0" "rm -rf $D; echo GONE" 120 >/dev/null

python3 -I - "$EVID" "$P0" "$P1" "$CHURN" "$FAIR_MIN" <<'PY' | tee -a "$EVID/log"
import collections, sys
evid, p0, p1, churn, fair_min = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
names = ("append", "create", "rename", "remove", "sync")
tot, errs = {}, []
for h in (p0, p1):
    counts, lat = {}, collections.defaultdict(list)
    for line in open(f"{evid}/ops.{h}"):
        f = line.split()
        if f[:1] == ["COUNT"] and len(f) == 3 and f[2].isdigit():
            counts[int(f[1])] = int(f[2])
        elif f[:1] == ["OPS"] and len(f) >= 3 and f[2] == "ERR":
            errs.append(f"{h} loop {f[1]}: {' '.join(f[3:])}")
        elif f[:1] == ["OPS"] and len(f) == 8:
            for n, v in zip(names, f[3:]):
                if n == "remove" and int(f[2]) <= 20:
                    continue
                if n == "sync" and int(f[2]) % 25:
                    continue
                lat[n].append(int(v) / 1000.0)
    tot[h] = sum(counts.values())
    missing = [k for k in range(1, churn + 1) if k not in counts]
    print(f"{h}: iterations {tot[h]} ({', '.join(f'loop {k} {counts[k]}' for k in sorted(counts))})"
          + (f"; loops with no count: {missing}" if missing else ""))
    for n in names:
        v = sorted(lat[n])
        if v:
            q = lambda p: v[min(len(v) - 1, int(len(v) * p))]
            print(f"  {n:7s} n={len(v):6d} p50={q(0.5):9.1f} p90={q(0.9):9.1f} p99={q(0.99):9.1f} max={v[-1]:9.1f} ms total={sum(v) / 1000:7.1f} s")
    st = collections.Counter()
    n = 0
    for line in open(f"{evid}/samples.{h}"):
        f = line.split(" ", 5)
        if len(f) < 5:
            continue
        n += 1
        stack = f[5].strip().rstrip(",") if len(f) == 6 else ""
        st[(f[3], f[4], ",".join(stack.split(",")[:4]))] += 1
    print(f"  {n} task samples; most frequent (samples, comm, state, top of stack):")
    for (c, s, k), m in st.most_common(14):
        print(f"    {m:5d}  {c:6s} {s}  {k[:200]}")
for e in errs:
    print(f"FAIL: loop error {e}")
a, b = tot[p0], tot[p1]
ratio = min(a, b) / max(a, b) if max(a, b) else 0.0
print(f"iterations {p0} {a}, {p1} {b}: the slower host made {ratio:.2f} of the faster's (pass at {fair_min})")
if errs or ratio < fair_min:
    print("FAIL")
    sys.exit(1)
print("PASS")
PY
rc=${PIPESTATUS[0]}
if [ "${PROBES:-0}" = 1 ]; then
    python3 "$REPO/tools/tenure_report.py" "$EVID" "$DIRINO" "$P0" "$P1" | tee -a "$EVID/log"
fi
say "evidence $EVID"
exit "$rc"
