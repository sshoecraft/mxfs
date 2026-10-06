#!/bin/bash
# pve_create_latency.sh — how long does a VM disk allocation's metadata take on
# MXFS-on-DRBD while the pair's guests do I/O, and what does it wait on?
#
# On the physical pair a Proxmox VM create (qm create --scsi0 shared:1, a new
# images/<vmid> directory and a 1 GiB sparse raw file in it, made under
# Proxmox's 60 s cluster-wide storage lock) failed on 0.90.78 with
# "'storage-shared'-locked command timed out" while both hosts ran a VM-like
# load; idle, the same allocation takes about half a second.
#
# This runs that allocation's filesystem steps directly, ROUNDS times, on
# participant 1: mkdir of a new directory, create of a file in it, ftruncate to
# 1 GiB, close.  Each step is timed, and while a step runs its task's kernel
# stack is sampled every 100 ms (/proc/<pid>/task/<tid>/stack, root only), so a
# slow step says what it waited on.  The same steps run on the host's local
# storage (LOCAL, default /var/lib/vz) as the yardstick.  With LOAD=1 (default)
# both hosts first start the VM-like load of tests/pve_pair_failover.sh: fio
# O_DIRECT 4 KiB random 60/40 read/write at QD16 on a 1 GiB file of their own
# on the mount; LOAD=0 measures the idle pair.
#
# It grades nothing; it is an instrument.  Output: per step and storage, the
# median and worst time; for every step over SLOW_MS, the stack frames seen
# while it ran, by count.
#
# Usage: tests/pve_create_latency.sh
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), MNT (/mnt/shared),
#        LOCAL (/var/lib/vz), ROUNDS (20), LOAD (1), LOAD_S (90), SLOW_MS (1000)
# Evidence: tests/evidence/pve_create_latency/<UTC stamp>-<addr>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_create_latency: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
LOCAL=${LOCAL:-/var/lib/vz}
ROUNDS=${ROUNDS:-20}
LOAD=${LOAD:-1}
LOAD_S=${LOAD_S:-90}
SLOW_MS=${SLOW_MS:-1000}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_create_latency/$STAMP-${PAIR[0]}"
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

# The probe: runs on participant 1, prints one JSON line per step.
PROBE='import json, os, sys, threading, time
base, rounds = sys.argv[1], int(sys.argv[2])
tid = threading.get_native_id()
pid = os.getpid()
cur = {"op": None, "frames": {}}
stop = False
def sampler():
    while not stop:
        if cur["op"] is not None:
            try:
                with open("/proc/%d/task/%d/stack" % (pid, tid)) as fh:
                    top = [l.split()[1].split("+")[0] for l in fh.read().splitlines()[:8] if len(l.split()) > 1]
                key = " < ".join(top)
                cur["frames"][key] = cur["frames"].get(key, 0) + 1
            except OSError:
                pass
        time.sleep(0.1)
th = threading.Thread(target=sampler, daemon=True)
th.start()
def step(name, fn):
    cur["frames"] = {}
    cur["op"] = name
    t0 = time.monotonic()
    r = fn()
    dt = time.monotonic() - t0
    cur["op"] = None
    print(json.dumps({"op": name, "ms": round(dt * 1000, 1), "frames": cur["frames"]}), flush=True)
    return r
os.makedirs(base, exist_ok=True)
for i in range(rounds):
    d = os.path.join(base, "vm%d" % i)
    step("mkdir", lambda: os.mkdir(d))
    fd = step("create", lambda: os.open(os.path.join(d, "disk.raw"), os.O_CREAT | os.O_WRONLY, 0o600))
    step("ftruncate", lambda: os.ftruncate(fd, 1 << 30))
    step("close", lambda: os.close(fd))
    time.sleep(0.5)
stop = True'

if [ "$LOAD" = 1 ]; then
    for h in "$P0" "$P1"; do
        on "$h" "e=io_uring; fio --enghelp 2>/dev/null | grep -q io_uring || e=libaio
            mkdir -p $MNT/pvefail; rm -f /root/createlat_fio.json
            nohup setsid fio --name=vm --filename=$MNT/pvefail/load.\$(hostname) --size=1g --rw=randrw --rwmixread=60 \
                --bs=4k --iodepth=16 --ioengine=\$e --direct=1 --time_based --runtime=$LOAD_S \
                --output-format=json --output=/root/createlat_fio.json >/dev/null 2>/root/createlat_fio.err < /dev/null &
            for i in \$(seq 1 30); do fuser $MNT/pvefail/load.\$(hostname) >/dev/null 2>&1 && { echo LOAD_UP; exit 0; }; sleep 1; done; echo NO_LOAD" 60 | grep -q LOAD_UP \
            || { say "no load on $h"; exit 1; }
    done
    say "both hosts run fio O_DIRECT 4k randrw QD16 for ${LOAD_S}s; probing in 10 s"
    sleep 10
else
    say "no load: the idle pair"
fi

on "$P1" "cat > /dev/shm/createlat.py <<'EOS'
$PROBE
EOS
echo STAGED" 20 | grep -q STAGED || { say "could not stage the probe on $P1"; exit 1; }
for where in "$MNT/pvefail/createlat-$STAMP" "$LOCAL/createlat-$STAMP"; do
    tag=$(case "$where" in "$MNT"*) echo mxfs ;; *) echo local ;; esac)
    on "$P1" "python3 /dev/shm/createlat.py $where $ROUNDS; rm -rf $where" $(( ROUNDS * 120 + 60 )) > "$EVID/steps.$tag.jsonl"
    say "  $tag: $(grep -c '^{' "$EVID/steps.$tag.jsonl") steps measured"
done
on "$P1" "rm -f /dev/shm/createlat.py" 10 >/dev/null

python3 -I - "$EVID" "$SLOW_MS" <<'EOF' | tee -a "$EVID/log"
import json, statistics, sys
evid, slow = sys.argv[1], float(sys.argv[2])
for tag in ("mxfs", "local"):
    rows = []
    for line in open("%s/steps.%s.jsonl" % (evid, tag)):
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    for op in ("mkdir", "create", "ftruncate", "close"):
        ms = [r["ms"] for r in rows if r["op"] == op]
        if ms:
            print("%-5s %-9s n=%-3d median %8.1f ms  worst %8.1f ms  over %.0f ms: %d"
                  % (tag, op, len(ms), statistics.median(ms), max(ms), slow, sum(1 for m in ms if m > slow)))
    frames = {}
    for r in rows:
        if r["ms"] > slow:
            for k, v in r["frames"].items():
                frames[(r["op"], k)] = frames.get((r["op"], k), 0) + v
    for (op, k), v in sorted(frames.items(), key=lambda x: -x[1])[:12]:
        print("  %s slow-step samples %4d  %s" % (op, v, k[:300]))
EOF
if [ "$LOAD" = 1 ]; then
    for h in "$P0" "$P1"; do
        out=$(on "$h" "for i in \$(seq 1 $((LOAD_S + 30))); do [ -s /root/createlat_fio.json ] && break; sleep 1; done
            python3 -c 'import json; j=json.load(open(\"/root/createlat_fio.json\"))[\"jobs\"][0]
print(\"LOAD err=%d read_iops=%.0f write_iops=%.0f lat_max_ms=%.0f\" % (j[\"error\"], j[\"read\"][\"iops\"], j[\"write\"][\"iops\"], max(j[\"read\"][\"lat_ns\"][\"max\"], j[\"write\"][\"lat_ns\"][\"max\"]) / 1e6))'" $((LOAD_S + 60)) | grep '^LOAD ')
        say "  $h's load: ${out:-no result}"
    done
fi
say "evidence $EVID"
