#!/bin/bash
# pve_tree_walk.sh — what a tree walk of the MXFS mount costs on an
# MXFS-on-DRBD Proxmox pair, and what a walker waits on.  A walk stats every
# entry, as du, ls -lR, find and a backup's scan do.
#
# Measured 2026-10-06 on pve1/pve2 (0.90.81): `du -sh /mnt/shared` over 795
# entries took 15.5 s on one host, and with both hosts running it at once
# neither finished within 190 s.  Native XFS walks that in milliseconds.
#
# Each walk is `find DIR -printf '%s %p\n'` (one lstat per entry, du's work),
# line-buffered into a file in /dev/shm.  A sampler on the same host counts the
# entries done every SAMPLE_S and records the walker's wchan and the top of its
# kernel stack, so a walk that stops can be told from one that crawls.  Phases
# run in the order given; in "both" the two hosts' walks are armed to start at
# the same wall-clock second.
#
# Each walk is graded against WALK_BUDGET_S, and the instrument keeps sampling
# to OBSERVE_S whatever the grade, so a walk past its budget still shows
# whether it was progressing.  A walk past its budget is a FAIL even if it
# finishes before OBSERVE_S.
#
# The slow walks of 2026-10-06 came over files each host had just created and
# fsynced (the failover tests' loads); walked again once both hosts had read
# them, the same tree took 0.5 s on either host and on both at once.  The seed
# phase recreates that state: each host, at once, writes and fsyncs
# SEED_DIRS x SEED_FILES files of 4 KiB in a directory of its own under
# MNT/walkseed, and keeps them cached as their creator does.
#
# Usage: tests/pve_tree_walk.sh [phase ...]
#   seed   both hosts create their files at once (removed again when the run
#          ends); graded against SEED_BUDGET, with each create, write and
#          fsync timed
#   seed0 / seed1   participant 0 / participant 1 alone creates its files
#   touch0 / touch1 participant 0 / 1 creates one file in the seed's top
#          directory, which the other host holds for reading after a walk:
#          losing a directory it reads to a peer's write makes a host release
#          its idle read grants on files all at once (dir_ex_bast_sweep)
#   p0     participant 0 walks alone
#   p1     participant 1 walks alone
#   both   both walk at once
#   (default: p0 p0 p1 both — the second p0 is a walk over what the first left
#   cached; "seed both p0" walks a freshly created tree on both hosts at once)
# Env:
#   PVE_PAIR       "<addr> <addr>" (default "192.168.1.80 192.168.1.81")
#   MNT            the mount (default /mnt/shared)
#   DIR            what to walk (default MNT)
#   WALK_BUDGET_S  the grade (default 5: native XFS walks a cold tree of a
#                  thousand entries in well under a second; one cluster lock
#                  round trip per entry over gigabit, ~1-2 ms, is ~2 s for
#                  1000; twice that, rounded up)
#   OBSERVE_S      how long a walk is sampled before it is killed (default 120)
#   SAMPLE_S       sampling interval (default 0.5)
#   ARM_S          seconds ahead "both" is armed (default 10)
#   SEED_DIRS / SEED_FILES   the seed's shape per host (default 4 x 100)
# Evidence: tests/evidence/pve_tree_walk/<UTC stamp>-<addr>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_tree_walk: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
DIR=${DIR:-$MNT}
WALK_BUDGET_S=${WALK_BUDGET_S:-5}
OBSERVE_S=${OBSERVE_S:-120}
SAMPLE_S=${SAMPLE_S:-0.5}
ARM_S=${ARM_S:-10}
SEED_DIRS=${SEED_DIRS:-4}
SEED_FILES=${SEED_FILES:-100}
# Each seed file is a 4 KiB write and an fsync: ~25-60 ms each through DRBD on
# this pair's SATA disks, so 400 per host take ~10-25 s; twice the slow end.
SEED_BUDGET=${SEED_BUDGET:-60}
PHASES=("$@")
[ "${#PHASES[@]}" -gt 0 ] || PHASES=(p0 p0 p1 both)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_tree_walk/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi

for h in "$P0" "$P1"; do
    s=$(on "$h" "echo \"name=\$(hostname) mnt=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts | head -1) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) ntp=\$(timedatectl show -p NTPSynchronized --value 2>/dev/null)\"" 20)
    say "$h: $s"
    case "$s" in *"mnt=$MNT "*"role=Primary/Primary cs=Connected"*) ;; *) say "ABORT: $h is not a mounted, connected half of the pair"; exit 1 ;; esac
done

# The seed's creator: one process, so the sampler follows the task doing the
# work.  One line per file into the list, with what each step took.
SEEDPY='import os, sys, time
base, ndirs, nfiles = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for d in range(1, ndirs + 1):
    dd = f"{base}/d{d}"
    os.makedirs(dd, exist_ok=True)
    for f in range(1, nfiles + 1):
        t0 = time.monotonic_ns()
        fd = os.open(f"{dd}/f{f}", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        t1 = time.monotonic_ns()
        os.write(fd, os.urandom(4096))
        t2 = time.monotonic_ns()
        os.fsync(fd)
        t3 = time.monotonic_ns()
        os.close(fd)
        print(f"{dd}/f{f} create_us={(t1 - t0) // 1000} write_us={(t2 - t1) // 1000} fsync_us={(t3 - t2) // 1000}", flush=True)'
SEEDPY_B64=$(base64 -w0 <<<"$SEEDPY")

# The work and its sampler, run on a host as:
#   <T> <dir> <out prefix> <observe s> <sample s> walk
#   <T> <dir> <out prefix> <observe s> <sample s> seed <seed.py> <dirs> <files>
# A walk walks <dir>; a seed creates its files under <dir>/<hostname>.
WALKER=$(cat <<'EOF'
T=$1; d=$2; out=$3; obs=$4; every=$5; mode=$6
: > "$out.list"; : > "$out.samples"
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$T"
a=$(date +%s%N)
if [ "$mode" = seed ]; then
    timeout "$obs" python3 -I "$7" "$d/$(hostname)" "$8" "$9" > "$out.list" 2> "$out.err" &
else
    timeout "$obs" stdbuf -oL find "$d" -printf '%s %p\n' > "$out.list" 2> "$out.err" &
fi
tp=$!
while kill -0 "$tp" 2>/dev/null; do
    fp=$(cut -d' ' -f1 "/proc/$tp/task/$tp/children" 2>/dev/null)
    n=$(wc -l < "$out.list")
    w=$(cat "/proc/$fp/wchan" 2>/dev/null)
    k=$(head -6 "/proc/$fp/stack" 2>/dev/null | sed 's/^\[<[0-9a-f]*>\] //; s/+0x.*//' | tr '\n' ',')
    echo "$(date +%s%N) $n ${w:--} ${k:--}" >> "$out.samples"
    sleep "$every"
done
wait "$tp"; rc=$?
b=$(date +%s%N)
echo "WALK rc=$rc entries=$(wc -l < "$out.list") wall_ms=$(( (b - a) / 1000000 )) start_ns=$a"
EOF
)
WALKER_B64=$(base64 -w0 <<<"$WALKER")

# arm <host> <T> <tag> [seed]: start a walk (or, with "seed", the seed's
# creator) on <host> at <T>; its result lands in
# /dev/shm/mxfs-walk-<stamp>-<tag>.result
arm() {
    local h=$1 t=$2 tag=$3 p="/dev/shm/mxfs-walk-$STAMP-$3"
    local args="$DIR $p $OBSERVE_S $SAMPLE_S walk"
    [ "${4:-}" = seed ] && args="$MNT/walkseed/$STAMP $p $OBSERVE_S $SAMPLE_S seed $p.py $SEED_DIRS $SEED_FILES"
    on "$h" "echo $WALKER_B64 | base64 -d > $p.sh && echo $SEEDPY_B64 | base64 -d > $p.py && mkdir -p $MNT/walkseed/$STAMP && nohup setsid bash -c 'bash $p.sh $t $args > $p.result 2>&1' > /dev/null 2>&1 < /dev/null &
        echo ARMED" 30 | grep -q ARMED
}
# collect <host> <tag>: wait for the walk's result, then copy what it left
collect() {
    local h=$1 tag=$2 p="/dev/shm/mxfs-walk-$STAMP-$2" r
    r=$(on "$h" "for i in \$(seq 1 $(( OBSERVE_S + 60 ))); do grep -q '^WALK' $p.result 2>/dev/null && break; sleep 1; done; cat $p.result" $(( OBSERVE_S + 90 )))
    echo "$r" > "$EVID/$tag.result"
    on "$h" "cat $p.samples" 60 > "$EVID/$tag.samples"
    case "$tag" in *seed*) on "$h" "cat $p.list" 60 > "$EVID/$tag.list" ;; esac
    on "$h" "cat $p.err; rm -f $p.sh $p.py $p.list $p.err $p.samples $p.result" 30 > "$EVID/$tag.err"
    # the module's own lines while the walk ran, by tag only
    local s
    s=$(sed -n 's/.*start_ns=\([0-9]*\).*/\1/p' <<<"$r")
    [ -n "$s" ] && on "$h" "journalctl -k --since @$(( s / 1000000000 )) --no-pager -o cat | grep -a mxfs | grep -aoE 'P[0-9]*-[A-Z0-9-]+' | sort | uniq -c | sort -rn | head -20" 60 > "$EVID/$tag.klog_tags"
    echo "$r"
}
grade() {  # <tag> <host name> <result line> [budget s]
    local tag=$1 h=$2 r=$3 budget=${4:-$WALK_BUDGET_S} rc n ms verdict
    rc=$(sed -n 's/.*rc=\([0-9]*\).*/\1/p' <<<"$r"); n=$(sed -n 's/.*entries=\([0-9]*\).*/\1/p' <<<"$r"); ms=$(sed -n 's/.*wall_ms=\([0-9]*\).*/\1/p' <<<"$r")
    if [ -z "$ms" ]; then verdict="FAIL (no result)"
    elif [ "$rc" != 0 ]; then verdict="FAIL (rc=$rc: killed at ${OBSERVE_S}s or the work failed)"
    elif [ "$ms" -gt $(( budget * 1000 )) ]; then verdict="FAIL (over the ${budget}s budget)"
    else verdict=PASS; fi
    say "$tag $h: entries=${n:-?} wall=${ms:-?} ms -> $verdict"
    [ -s "$EVID/$tag.list" ] && python3 -I - "$EVID/$tag.list" <<'PYEOF' | tee -a "$EVID/log"
import statistics, sys
cols = {"create_us": [], "write_us": [], "fsync_us": []}
for line in open(sys.argv[1], errors="replace"):
    for f in line.split()[1:]:
        k, _, v = f.partition("=")
        if k in cols and v.isdigit():
            cols[k].append(int(v) / 1000)
for k, v in cols.items():
    if v:
        v.sort()
        print(f"    {k[:-3]:7s} n={len(v)} p50={statistics.median(v):.1f} ms p90={v[int(len(v) * 0.9)]:.1f} ms max={v[-1]:.1f} ms total={sum(v) / 1000:.1f} s")
PYEOF
    python3 -I - "$EVID/$tag.samples" "$budget" <<'PYEOF' | tee -a "$EVID/log"
import collections, sys
rows = []
for line in open(sys.argv[1], errors="replace"):
    f = line.split(" ", 3)
    if len(f) >= 3 and f[0].isdigit() and f[1].isdigit():
        rows.append((int(f[0]), int(f[1]), f[2], f[3].strip() if len(f) > 3 else "-"))
if not rows:
    print("    no samples"); sys.exit(0)
t0 = rows[0][0]
budget = float(sys.argv[2])
at_budget = max((n for t, n, _, _ in rows if (t - t0) / 1e9 <= budget), default=0)
print(f"    samples={len(rows)} entries at the budget={at_budget} last={rows[-1][1]} after {(rows[-1][0] - t0) / 1e9:.1f}s")
# progress per 5 s
per = collections.OrderedDict()
for t, n, _, _ in rows:
    per[int((t - t0) / 5e9)] = n
prev = 0
line = []
for k, n in per.items():
    line.append(f"{k * 5}s:+{n - prev}")
    prev = n
print("    entries done per 5 s: " + " ".join(line[:30]))
waits = collections.Counter((w, k[:150]) for _, _, w, k in rows)
print("    where it waited (samples, wchan, top of stack):")
for (w, k), c in waits.most_common(8):
    print(f"      {c:4d}  {w}  {k}")
PYEOF
    [ -s "$EVID/$tag.klog_tags" ] && { echo "    module log lines by tag since the walk began:"; sed 's/^/      /' "$EVID/$tag.klog_tags" | head -12; } | tee -a "$EVID/log"
    [ "$verdict" = PASS ]
}

SEEDED=0
unseed() {
    [ "$SEEDED" = 1 ] || return 0
    on "$P0" "rm -rf $MNT/walkseed/$STAMP" 120 > /dev/null
    SEEDED=0
}
trap unseed EXIT

FAILED=0
i=0
for ph in "${PHASES[@]}"; do
    i=$(( i + 1 ))
    case "$ph" in
        seed|seed0|seed1)
            hosts=("$P0" "$P1"); [ "$ph" = seed0 ] && hosts=("$P0"); [ "$ph" = seed1 ] && hosts=("$P1")
            T=$(( $(date +%s) + ARM_S ))
            say "== phase $i: ${hosts[*]} create $SEED_DIRS x $SEED_FILES files of 4 KiB, each fsynced, in $MNT/walkseed/$STAMP/<host>, armed for $(date -d @$T +%H:%M:%S)"
            SEEDED=1
            for h in "${hosts[@]}"; do
                arm "$h" "$T" "$i-$ph-$h" seed || { say "ABORT: could not arm $h"; exit 1; }
            done
            for h in "${hosts[@]}"; do collect "$h" "$i-$ph-$h" > "$EVID/$i-$ph-$h.r" & done
            wait
            for h in "${hosts[@]}"; do grade "$i-$ph-$h" "$h" "$(cat "$EVID/$i-$ph-$h.r")" "$SEED_BUDGET" || FAILED=1; done
            ;;
        touch0|touch1)
            h=$P0; [ "$ph" = touch1 ] && h=$P1
            say "== phase $i: $ph ($h) creates one file in $MNT/walkseed/$STAMP"
            r=$(on "$h" "mkdir -p $MNT/walkseed/$STAMP && a=\$(date +%s%N) && echo $i > $MNT/walkseed/$STAMP/touch.$i && echo TOUCH_MS=\$(( (\$(date +%s%N) - a) / 1000000 ))" 120)
            SEEDED=1
            say "$i-$ph $h: ${r:-no answer}"
            ;;
        p0|p1)
            h=$P0; [ "$ph" = p1 ] && h=$P1
            T=$(( $(date +%s) + 3 ))
            say "== phase $i: $ph ($h) walks $DIR alone"
            arm "$h" "$T" "$i-$ph" || { say "ABORT: could not arm $h"; exit 1; }
            r=$(collect "$h" "$i-$ph")
            grade "$i-$ph" "$h" "$r" || FAILED=1
            ;;
        both)
            T=$(( $(date +%s) + ARM_S ))
            say "== phase $i: both hosts walk $DIR at once, armed for $(date -d @$T +%H:%M:%S)"
            arm "$P0" "$T" "$i-both-p0" || { say "ABORT: could not arm $P0"; exit 1; }
            arm "$P1" "$T" "$i-both-p1" || { say "ABORT: could not arm $P1"; exit 1; }
            collect "$P0" "$i-both-p0" > "$EVID/$i-both-p0.r" &
            collect "$P1" "$i-both-p1" > "$EVID/$i-both-p1.r" &
            wait
            grade "$i-both-p0" "$P0" "$(cat "$EVID/$i-both-p0.r")" || FAILED=1
            grade "$i-both-p1" "$P1" "$(cat "$EVID/$i-both-p1.r")" || FAILED=1
            ;;
        *) say "unknown phase $ph"; exit 2 ;;
    esac
done
[ "$FAILED" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
say "evidence: $EVID"
exit "$FAILED"
