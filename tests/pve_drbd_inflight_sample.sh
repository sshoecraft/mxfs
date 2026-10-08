#!/bin/bash
# pve_drbd_inflight_sample.sh — what a slow DRBD write is waiting for, on
# both hosts of a pair, sampled from DRBD's own request table.
#
# Under protocol C a write completes when this host's disk has it AND the peer
# has acknowledged it, after the peer's receiver wrote it (and, with wo:f,
# drained and flushed its epoch).  A coordination write (a heartbeat swap's
# register write) that takes seconds is waiting on one of: the activity log
# (an extent not in the AL costs a synchronous metadata transaction first),
# this host's disk, or the peer.  DRBD 8.4 keeps every request's timestamps in
# debugfs (resources/<res>/in_flight_summary: per request its age, when it
# entered the AL, was submitted locally, sent, acked, and its state), so a
# sample of it says which.
#
# Usage: tests/pve_drbd_inflight_sample.sh <seconds> [interval_s]
# Env:   PVE_PAIR "<addr> <addr>" (default "192.168.1.80 192.168.1.81")
#        RES      DRBD resource (default mxfs); EVID
# Read-only: it reads debugfs and nothing else.
#
# Output: per host, over the samples whose oldest application request was at
# least SLOW_MS (default 1000) old, what that request was waiting for, the
# worst ages, the AL wait queue, the oldest peer request and the unread
# receive buffer; raw samples in $EVID/<host>.raw.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
DUR=${1:?seconds}; IV=${2:-0.25}
RES=${RES:-mxfs}
SLOW_MS=${SLOW_MS:-1000}
read -r -a HOSTS <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
EVID=${EVID:-$REPO/tests/evidence/pve_drbd_inflight/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID" || exit 1
F=/sys/kernel/debug/drbd/resources/$RES/in_flight_summary
pids=()
for h in "${HOSTS[@]}"; do
    ( timeout $((DUR + 30)) "$SSHP" "$h" "end=\$((SECONDS + $DUR)); while [ \$SECONDS -lt \$end ]; do echo \"@@ \$(date +%s.%N)\"; cat $F; sleep $IV; done" \
        </dev/null 2>/dev/null | grep -avE '^Warning:|^Unauthorized|^If you|^$' > "$EVID/$h.raw" ) &
    pids+=($!)
done
wait "${pids[@]}"
python3 -I - "$SLOW_MS" "$EVID" "${HOSTS[@]}" <<'PY' | tee "$EVID/summary.txt"
import sys, collections
slow = int(sys.argv[1]); evid = sys.argv[2]
for h in sys.argv[3:]:
    samples = []
    cur = None
    sect = None
    for line in open(f"{evid}/{h}.raw", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("@@ "):
            cur = {"t": float(line[3:]), "app": [], "peer": [], "alwait": 0, "alwait_age": 0, "rcvbuf": 0, "md": []}
            samples.append(cur); sect = None; continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("oldest application requests"): sect = "app"; continue
        if s.startswith("oldest peer requests"): sect = "peer"; continue
        if s.startswith("application requests waiting for activity log"): sect = "alw"; continue
        if s.startswith("meta data IO"): sect = "md"; continue
        if s.startswith("socket buffer stats"): sect = "sock"; continue
        if s.startswith("oldest bitmap IO"): sect = "bm"; continue
        if s.startswith("unread receive buffer"):
            cur["rcvbuf"] = int(s.split(":")[1].split()[0]); continue
        f = s.split("\t")
        if sect == "app" and len(f) >= 13 and f[0].isdigit():
            # n dev vnr epoch sector size rw start inAL submit sent acked done state
            age = int(f[7]) if f[7].lstrip("-").isdigit() else 0
            cur["app"].append((age, f[6], int(f[5]) if f[5].isdigit() else 0, f[8], f[9], f[10], f[11], " ".join(f[13:])))
        elif sect == "peer" and len(f) >= 6 and f[0].isdigit():
            cur["peer"].append(int(f[5]) if f[5].isdigit() else 0)
        elif sect == "alw" and len(f) >= 4 and f[0].isdigit():
            cur["alwait_age"] = int(f[2]) if f[2].isdigit() else 0
            cur["alwait"] = int(f[3]) if f[3].isdigit() else 0
        elif sect == "md" and len(f) >= 5 and f[0].isdigit():
            cur["md"].append((int(f[3]) if f[3].isdigit() else 0, f[4]))
    n = len(samples)
    if not n:
        print(f"{h}: no samples"); continue
    span = samples[-1]["t"] - samples[0]["t"]
    def oldest_write(sm):
        w = [a for a in sm["app"] if a[1] == "W"]
        return max(w) if w else None
    slow_s = [(sm, oldest_write(sm)) for sm in samples]
    slow_s = [(sm, o) for sm, o in slow_s if o and o[0] >= slow]
    why = collections.Counter()
    for sm, o in slow_s:
        st = o[7]
        if o[3] == "-":
            why["waiting for the activity log (not yet in AL)"] += 1
            continue
        local_wait = "local: in-AL pending" in st or "local: pending" in st
        net_wait = o[6] == "-" and "net: -" not in st
        sent = o[5] != "-"
        if local_wait and net_wait:
            why["this host's disk AND the peer" + ("" if sent else " (not yet sent)")] += 1
        elif local_wait:
            why["this host's disk only (peer acked)"] += 1
        elif net_wait:
            why["the peer only (local disk done)" + ("" if sent else ", not yet sent")] += 1
        else:
            why["completing (both done): " + st[:50]] += 1
    maxw = max((oldest_write(sm) or (0,))[0] for sm in samples)
    print(f"{h}: {n} samples over {span:.0f} s; oldest write max {maxw} ms; samples with a write >= {slow} ms: {len(slow_s)}")
    for k, v in why.most_common():
        print(f"  {v:6d}  {k}")
    print(f"  AL wait queue: max {max(sm['alwait'] for sm in samples)} requests, max age {max(sm['alwait_age'] for sm in samples)} ms; "
          f"metadata IO max age {max((m[0] for sm in samples for m in sm['md']), default=0)} ms "
          f"({collections.Counter(m[1] for sm in samples for m in sm['md']).most_common(3)})")
    print(f"  oldest peer request max {max((max(sm['peer']) if sm['peer'] else 0) for sm in samples)} ms; "
          f"unread receive buffer max {max(sm['rcvbuf'] for sm in samples)} B")
    worst = sorted(slow_s, key=lambda x: -x[1][0])[:5]
    for sm, o in worst:
        print(f"  worst t={sm['t']:.1f} age={o[0]} size={o[2]} inAL={o[3]} submit={o[4]} sent={o[5]} acked={o[6]} {o[7][:110]}")
PY
