#!/bin/bash
# wedge_load.sh — ambient-load generator for the 32/caw wedge hunt
# (ccloop c7ee71c6 sess13).  The original 11:11 hit had concurrent python
# probe storms (host load ~30) alongside the test chain; clean-rig laps have
# not reproduced.  This recreates that ingredient: a per-node python3
# create/write/read/truncate/unlink loop against a private dir plus a SHARED
# hot dir (cross-node BAST churn), self-killing after a deadline.
#
# Usage:  tests/wedge_load.sh start <secs>   # launch on all 32 nodes
#         tests/wedge_load.sh stop           # kill + clean everywhere
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile)}"
CMD="${1:?usage: wedge_load.sh start <secs> | stop}"

start() {
    local secs="${1:?start needs <secs>}"
    for i in $(seq 1 32); do
        (timeout 15 "$SSH" "test$i" "$PASS" "
            pkill -f wedge_load_py 2>/dev/null
            cat > /root/wedge_load_py.py <<'EOF'
import os, sys, time, random
n = sys.argv[1]; deadline = time.time() + float(sys.argv[2])
d = '/mnt/shared/.wedgeload/n%s' % n
h = '/mnt/shared/.wedgeload/hot'
for p in (d, h):
    try: os.makedirs(p, exist_ok=True)
    except Exception: pass
i = 0
while time.time() < deadline:
    try:
        p = '%s/f%d' % (d, i % 20)
        fd = os.open(p, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
        os.write(fd, os.urandom(random.randint(512, 8192)))
        os.close(fd)
        with open(p, 'rb') as f: f.read()
        hp = '%s/n%s_%d' % (h, n, i % 5)
        fd = os.open(hp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
        os.close(fd)
        try: os.unlink(hp)
        except OSError: pass
        i += 1
    except OSError:
        time.sleep(0.2)
EOF
            nohup python3 /root/wedge_load_py.py $i $secs >/dev/null 2>&1 &
            echo started" >/dev/null 2>&1) &
    done
    wait
    echo "wedge_load: started on 32 nodes for ${secs}s"
}

stop() {
    for i in $(seq 1 32); do
        (timeout 12 "$SSH" "test$i" "$PASS" \
            'pkill -f wedge_load_py 2>/dev/null; echo ok' >/dev/null 2>&1) &
    done
    wait
    echo "wedge_load: stopped everywhere"
}

case "$CMD" in
    start) start "${2:?}";;
    stop)  stop;;
    *) echo "usage: wedge_load.sh start <secs> | stop"; exit 2;;
esac
