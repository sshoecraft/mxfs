#!/bin/bash
# pve_pair_write_bound.sh — what MXFS's own coordination writes cost on a
# two-host DRBD pair while both hosts write bulk data through MXFS, and what
# the DRBD write bound (pal/linux/mxfs_ioq.h) does about it.
#
# On DRBD every coordination update (the heartbeat, slot claims, recovery
# records) is a compare-and-swap emulated with ordinary writes in the same
# ordered stream as the guests' data, so its latency is set by how much data
# both hosts have queued ahead of it.  Without the bound, eight VM installs on
# two non-NCQ SATA SSD hosts held one 8-9 s and both authority leases expired.
#
# Both hosts at once, each writer writing its whole file, so every block the
# check reads was written (a time-limited writer leaves the tail of its laid-
# out file unwritten, and that reads back as zeros):
#   - DIO_JOBS O_DIRECT sequential writers at QD DIO_QD x BS (QEMU cache=none
#     at its heaviest), each on a FILE_MB file of the host's own;
#   - one buffered sequential writer (writeback: the other data path) over a
#     BUF_MB file BUF_LOOPS times;
#   every block filled with its own offset (fio verify_pattern %o), the same on
#   every pass.
# Meanwhile a private ftrace instance (function_graph) times every
# mxfs_pal_drbd_cas_emulate (one coordination update, whole) and every
# mxfs_drbd_reg_put (one bakery register write) on both hosts: nothing is
# written to the kernel log.  Afterwards each host checks its own files and
# the peer's, every block against its offset, and the kernel log since the
# start is searched for heartbeat stalls, authority closures and refusals.
#
# Usage: tests/pve_pair_write_bound.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81")
#   MNT        mount point (default /mnt/shared)
#   LOAD_S     seconds the writers may take (default 300: 1 GiB direct and
#              4 GiB buffered per host at the slowest pair's ~35 MB/s total
#              is ~150 s if each host gets half, twice over); past it is a
#              failure.  With FIO=0, how long to observe.
#   DIO_JOBS / DIO_QD / BS / FILE_MB   (default 4 / 16 / 1M / 256)
#   BUF_MB / BUF_LOOPS  the buffered writer's file and passes (default 512 / 8)
#   BOUND_KB / BOUND_REQS  set the module's drbd_inflight_kb / drbd_inflight_reqs
#              on both hosts for this run, restored after (default: unchanged)
#   KEEP=1     keep the written files (default: removed after the checks)
#   FIO=0      write nothing: only trace and search the logs, for LOAD_S seconds
#              or until the local file STOP_FILE appears — to watch a real
#              workload (VM installs) the same way
#
# Pass: every fio job ends without error, every block on both hosts reads back
# as written, no P278-HB-STALL / P290-AUTH-CLOSED / P131-SELF-FENCE /
# P-DRBD-IOQ-REFUSED / kernel warning in either log, and the slowest swap
# stays under 8 s (the heartbeat's own stall threshold, MXFS_HB_STALL_MS).
#
# Evidence: tests/evidence/pve_pair_write_bound/<UTC stamp>/ — per host the
# fio json, the raw trace, the kernel log since the start, the module's bound
# settings; summary.txt holds the verdict and the latency distribution.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_write_bound: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
LOAD_S=${LOAD_S:-300}
DIO_JOBS=${DIO_JOBS:-4}
DIO_QD=${DIO_QD:-16}
BS=${BS:-1M}
FILE_MB=${FILE_MB:-256}
BUF_MB=${BUF_MB:-512}
BUF_LOOPS=${BUF_LOOPS:-8}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_pair_write_bound/$STAMP"
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
TI=/sys/kernel/tracing/instances/mxfs_wbound
PARAMS=/sys/module/mxfs/parameters

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
FAIL=0
bad() { say "FAIL: $*"; FAIL=1; }

# Both hosts mounted, Primary/Primary, Connected, UpToDate, one build.
declare -A NAME BUILD
for h in "${PAIR[@]}"; do
    s=$(on "$h" "echo \"name=\$(hostname) mnt=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts | head -1) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) ds=\$(drbdadm dstate mxfs 2>/dev/null) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) ver=\$(cat /sys/module/mxfs/version 2>/dev/null) kb=\$(cat $PARAMS/drbd_inflight_kb 2>/dev/null) reqs=\$(cat $PARAMS/drbd_inflight_reqs 2>/dev/null) fio=\$(command -v fio)\"" 20)
    echo "$h $s" >> "$EVID/state_before.txt"
    case "$s" in
        *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*) ;;
        *) say "ABORT: $h is not up as half of the pair: ${s:-no answer}"; exit 1 ;;
    esac
    case "$s" in *"fio=/"*) ;; *) say "ABORT: $h has no fio"; exit 1 ;; esac
    NAME[$h]=$(sed -n 's/^name=\([^ ]*\).*/\1/p' <<<"$s")
    BUILD[$h]=$(sed -n 's/.* build=\([^ ]*\).*/\1/p' <<<"$s")
    say "$h ${NAME[$h]} $(sed -n 's/.*\(ver=.*\) fio=.*/\1/p' <<<"$s") build=${BUILD[$h]}"
done
[ "${BUILD[${PAIR[0]}]}" = "${BUILD[${PAIR[1]}]}" ] || { say "ABORT: the hosts run different builds"; exit 1; }

# The bound for this run, and what to put back.
declare -A OLD_KB OLD_REQS
for h in "${PAIR[@]}"; do
    OLD_KB[$h]=$(on "$h" "cat $PARAMS/drbd_inflight_kb" 10)
    OLD_REQS[$h]=$(on "$h" "cat $PARAMS/drbd_inflight_reqs" 10)
    if [ -n "${BOUND_KB:-}" ] || [ -n "${BOUND_REQS:-}" ]; then
        on "$h" "${BOUND_KB:+echo $BOUND_KB > $PARAMS/drbd_inflight_kb;} ${BOUND_REQS:+echo $BOUND_REQS > $PARAMS/drbd_inflight_reqs;} true" 10
    fi
    say "$h bound for this run: $(on "$h" "echo kb=\$(cat $PARAMS/drbd_inflight_kb) reqs=\$(cat $PARAMS/drbd_inflight_reqs)" 10)"
done
restore() {
    local h
    for h in "${PAIR[@]}"; do
        on "$h" "echo 0 > $TI/tracing_on 2>/dev/null; echo nop > $TI/current_tracer 2>/dev/null; rmdir $TI 2>/dev/null; echo ${OLD_KB[$h]:-4096} > $PARAMS/drbd_inflight_kb; echo ${OLD_REQS[$h]:-64} > $PARAMS/drbd_inflight_reqs" 20 >/dev/null
    done
}
trap restore EXIT

# The trace: a private instance, so nothing else's tracing is touched.
for h in "${PAIR[@]}"; do
    out=$(on "$h" "[ -d $TI ] && { echo nop > $TI/current_tracer; rmdir $TI; }
        mkdir $TI && echo 'mxfs_pal_drbd_cas_emulate mxfs_drbd_reg_put' > $TI/set_ftrace_filter \
        && echo 8192 > $TI/buffer_size_kb && echo function_graph > $TI/current_tracer \
        && echo funcgraph-tail > $TI/trace_options && echo 1 > $TI/tracing_on && echo TRACE_ON" 20)
    case "$out" in *TRACE_ON*) ;; *) say "ABORT: $h could not start the trace: $out"; exit 1 ;; esac
done

T0=$(date +%s)
FIO_COMMON="--verify=pattern --verify_pattern=%o --bs=$BS --rw=write --group_reporting=0 --output-format=json"
if [ "${FIO:-1}" = 0 ]; then
    say "observing only: up to ${LOAD_S}s${STOP_FILE:+, or until $STOP_FILE appears}"
    while [ $(( $(date +%s) - T0 )) -lt "$LOAD_S" ]; do
        [ -n "${STOP_FILE:-}" ] && [ -e "$STOP_FILE" ] && break
        sleep 5
    done
    say "observed for $(( $(date +%s) - T0 ))s"
fi
[ "${FIO:-1}" = 0 ] || say "load: per host $DIO_JOBS x O_DIRECT QD$DIO_QD x $BS over ${FILE_MB} MiB each + 1 buffered writer ${BUF_LOOPS} x ${BUF_MB} MiB; budget ${LOAD_S}s"
for h in "${PAIR[@]}"; do
    [ "${FIO:-1}" = 0 ] && break
    d="$MNT/wbound/$STAMP/${NAME[$h]}"
    on "$h" "mkdir -p $d && cd $d && rm -f /root/wbound-$STAMP.json /root/wbound-$STAMP.rc
        setsid bash -c 'fio $FIO_COMMON --do_verify=0 --output=/root/wbound-$STAMP.json \
            --name=dio --directory=$d --ioengine=libaio --direct=1 --iodepth=$DIO_QD --numjobs=$DIO_JOBS --size=${FILE_MB}M \
            --name=buf --directory=$d --ioengine=psync --direct=0 --numjobs=1 --size=${BUF_MB}M --loops=$BUF_LOOPS --end_fsync=1 & echo \$! > /root/wbound-$STAMP.pid; wait \$!; echo \$? > /root/wbound-$STAMP.rc' \
            >/dev/null 2>&1 </dev/null & echo STARTED" 20 | grep -q STARTED || bad "$h: the load did not start"
done
OVERRUN=0

# Wait for both loads, the buffered writer's final fsync included, within the
# budget; past it the run has failed.
for h in "${PAIR[@]}"; do
    [ "${FIO:-1}" = 0 ] && break
    while [ $(( $(date +%s) - T0 )) -lt "$LOAD_S" ]; do
        rc=$(on "$h" "cat /root/wbound-$STAMP.rc 2>/dev/null" 15)
        [ -n "$rc" ] && break
        sleep 5
    done
    if [ -z "$rc" ]; then
        bad "$h: the load did not finish within ${LOAD_S}s (budget exceeded); fio stopped, its files are not checked"
        on "$h" "kill \$(cat /root/wbound-$STAMP.pid) 2>/dev/null; sleep 5; cat /root/wbound-$STAMP.rc 2>/dev/null" 30 >/dev/null
        OVERRUN=1
    fi
    say "$h load done at +$(( $(date +%s) - T0 ))s rc=${rc:-none}"
    [ "${rc:-1}" = 0 ] || bad "$h: fio exited ${rc:-without a status}"
done

# Stop and keep the traces, the fio results and the kernel logs.
for h in "${PAIR[@]}"; do
    n=${NAME[$h]}
    on "$h" "echo 0 > $TI/tracing_on; cat $TI/trace" 120 > "$EVID/trace_$n.txt"
    on "$h" "echo nop > $TI/current_tracer; rmdir $TI" 20 >/dev/null
    [ "${FIO:-1}" = 0 ] || on "$h" "cat /root/wbound-$STAMP.json; rm -f /root/wbound-$STAMP.json /root/wbound-$STAMP.rc /root/wbound-$STAMP.pid" 30 > "$EVID/fio_$n.json"
    on "$h" "journalctl -k --no-pager -o short-iso --since @$T0" 60 > "$EVID/kernel_$n.log"
done

# Every block, on both hosts, from both hosts.
for h in "${PAIR[@]}"; do
    [ "${FIO:-1}" = 0 ] || [ "$OVERRUN" = 1 ] && break
    for g in "${PAIR[@]}"; do
        d="$MNT/wbound/$STAMP/${NAME[$g]}"
        out=$(on "$h" "cd $d && fio --verify=pattern --verify_pattern=%o --bs=$BS --rw=write --verify_only --output-format=terse \
            --name=dio --directory=$d --ioengine=libaio --direct=1 --iodepth=$DIO_QD --numjobs=$DIO_JOBS --size=${FILE_MB}M \
            --name=buf --directory=$d --ioengine=psync --direct=1 --numjobs=1 --size=${BUF_MB}M >/dev/null 2>/root/wbound-verify.err; echo VERIFY_RC=\$?; head -c 600 /root/wbound-verify.err; rm -f /root/wbound-verify.err" 600)
        rc=$(sed -n 's/^VERIFY_RC=\([0-9]*\).*/\1/p' <<<"$out")
        if [ "$rc" = 0 ]; then
            say "${NAME[$h]} reads every block ${NAME[$g]} wrote as written"
        else
            bad "${NAME[$h]} verifying ${NAME[$g]}'s files: rc=${rc:-none} $(tr '\n' ' ' <<<"$out" | cut -c1-400)"
        fi
    done
done
if [ "${KEEP:-0}" != 1 ] && [ "${FIO:-1}" != 0 ]; then
    on "${PAIR[0]}" "rm -rf $MNT/wbound/$STAMP" 120 >/dev/null
fi

# The numbers.
python3 -I - "$EVID" "$SUM" "${FIO:-1}" "${NAME[${PAIR[0]}]}" "${NAME[${PAIR[1]}]}" <<'PY' || FAIL=1
import json, re, sys
evid, summ, wrote, names = sys.argv[1], sys.argv[2], sys.argv[3] != "0", sys.argv[4:]
out = open(summ, "a")
def say(s):
    print(s); out.write(s + "\n")
bad = 0
# function_graph with funcgraph-tail: a duration on a leaf line "fn();" or on
# a closing brace "} /* fn */"; durations are in us.
dur = re.compile(r"(\d+\.\d+) us\s+\|\s+(?:\}\s+/\*\s+(\S+)|(\S+)\s+\[mxfs\]\(\);)")
for n in names:
    lat = {}
    lost = 0
    for line in open(f"{evid}/trace_{n}.txt", errors="replace"):
        if "LOST" in line:
            lost += 1
        m = dur.search(line)
        if not m:
            continue
        fn = (m.group(2) or m.group(3)).split()[0]
        lat.setdefault(fn, []).append(float(m.group(1)) / 1000.0)
    for fn in ("mxfs_pal_drbd_cas_emulate", "mxfs_drbd_reg_put"):
        v = sorted(lat.get(fn, []))
        if not v:
            say(f"{n} {fn}: no calls traced")
            if fn == "mxfs_pal_drbd_cas_emulate":
                bad = 1
            continue
        q = lambda p: v[min(len(v) - 1, int(p * len(v)))]
        say(f"{n} {fn}: n={len(v)} p50={q(.5):.1f}ms p90={q(.9):.1f}ms p99={q(.99):.1f}ms max={v[-1]:.1f}ms over1s={sum(x > 1000 for x in v)} over4s={sum(x > 4000 for x in v)}")
        if fn == "mxfs_pal_drbd_cas_emulate" and v[-1] >= 8000:
            say(f"FAIL: {n}: a swap took {v[-1]:.0f} ms, past the heartbeat's 8 s stall threshold")
            bad = 1
    if lost:
        say(f"{n}: the trace lost events on {lost} lines — the distribution above is incomplete")
    if wrote:
        try:
            j = json.load(open(f"{evid}/fio_{n}.json"))
            for job in j.get("jobs", []):
                w = job["write"]
                clat = w.get("clat_ns", {})
                pct = clat.get("percentile", {})
                say(f"{n} fio {job['jobname']}: err={job.get('error')} write {w['bw'] / 1024:.1f} MiB/s iops={w['iops']:.0f} clat p50={pct.get('50.000000', 0) / 1e6:.0f}ms p99={pct.get('99.000000', 0) / 1e6:.0f}ms max={clat.get('max', 0) / 1e6:.0f}ms")
                if job.get("error"):
                    bad = 1
        except Exception as e:
            say(f"FAIL: {n}: fio results unreadable: {e}")
            bad = 1
    klog = open(f"{evid}/kernel_{n}.log", errors="replace").read().splitlines()
    pats = {"P278-HB-STALL": 0, "P290-AUTH-CLOSED": 0, "P131-SELF-FENCE": 0, "P-DRBD-IOQ-REFUSED": 0,
            "WARNING:": 0, "BUG:": 0, "Oops": 0, "blocked for more than": 0, "I/O error": 0}
    for line in klog:
        for p in pats:
            if p in line:
                pats[p] += 1
    say(f"{n} kernel log since start: {len(klog)} lines, mxfs {sum('mxfs' in l for l in klog)}; " + " ".join(f"{p.strip(':')}={c}" for p, c in pats.items()))
    if any(pats.values()):
        bad = 1
        say(f"FAIL: {n}: the kernel log holds stalls, closures, refusals or warnings")
sys.exit(bad)
PY
if [ "$FAIL" = 0 ]; then say "PASS: evidence $EVID"; else say "FAIL: evidence $EVID"; fi
exit "$FAIL"
