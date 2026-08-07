#!/bin/bash
# caw_pr_nodefer_ab.sh [passes] [files_per_node] [participants]
#
# Paired A/B for the sess24 SHARED-CLASS TICKET BYPASS
# (mxfs.caw_pr_defer_max_ms, dlm/dlm_caw.c).
#
# WHY PAIRED, AND WHY THIS SHAPE
# ------------------------------
# state.md is emphatic that single-run deltas on this cluster are worthless: the
# criteria this fix targets sit on a pace cliff and normal run-to-run spread is
# ~2.8x.  So: N passes, ARMS ALTERNATED WITHIN each pass, on ONE cluster state.
# The parameter is module_param 0644, i.e. runtime-writable, so both arms run
# against the identical mount, identical cache warmth and identical peer set --
# no re-prep between arms, which is what made earlier A/Bs in this project
# non-comparable (a prep changes inode/AG layout and cache state).
#
# ARM UNBOUNDED = caw_pr_defer_max_ms=0, the pre-sess24 behaviour.
# ARM BOUND     = caw_pr_defer_max_ms=<ms> (default 50).
#
# The workload is the minimal reproducer for the defect: every node creates
# files in its OWN private subdirectory of ONE shared parent, so the ONLY
# cluster-contended resource is the parent directory's inode PR (read) lock.
# There is no shared dirent block, no shared file, no EX contention by design --
# if the fix is right, this workload should scale nearly flat in N.
#
# Reported per arm: per-create latency distribution (the mean is where the
# defect lives; p50 was already healthy pre-fix), plus the P138-WAIT census
# (total cluster grant wait, and the already-grantable ffw fraction of it).
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
PASSES="${1:-3}"
F="${2:-8}"
P="${3:-32}"
MNT=/mnt/shared
OUT=$(mktemp -d)
ARMS="${ARMS:-0 50}"          # 0 = unbounded (pre-sess24), 50 = the fix default
DEFARM="${DEFARM:-50}"

W=$(cat <<'EOS'
set -u
D="$1"; F="$2"; R="$3"; MARK="$4"
echo "$MARK rank=$R" > /dev/kmsg 2>/dev/null || true
mkdir -p "$D" 2>/dev/null
line="ABX r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"
prev=$(date +%s%N)
for i in $(seq 1 "$F"); do
    printf '%s' "$pat" > "$D/n${R}_$i"
    now=$(date +%s%N); echo "OP $i $(( (now - prev) / 1000000 ))"; prev=$now
done
EOS
)

setarm() {   # setarm <0|1>
    local v="$1" i
    for i in $(seq 1 "$P"); do
        ( "$SSH" "test$i" \
            "echo $v > /sys/module/mxfs/parameters/caw_pr_defer_max_ms" \
            >/dev/null 2>&1 ) &
    done
    wait
    # Verify the arm actually took on every node -- a silently-unwritable param
    # would make both arms identical and the A/B meaningless.
    local got bad=0
    for i in $(seq 1 "$P"); do
        got=$("$SSH" "test$i" "cat /sys/module/mxfs/parameters/caw_pr_defer_max_ms" 2>/dev/null | tr -d '\r\n ')
        [ "$got" = "$v" ] || { echo "  !! test$i reports caw_pr_defer_max_ms=[$got] want=$v"; bad=1; }
    done
    return $bad
}

onepass() {  # onepass <pass> <arm 0|1>
    local pass="$1" v="$2" i
    local stamp; stamp=$(date -u +%H%M%S)
    local mark="MXFS_ABX_${stamp}_p${pass}_a${v}"
    local tag="p${pass}_arm${v}"
    local od="$OUT/$tag"; mkdir -p "$od"
    local dirb="$MNT/.abx_${stamp}"
    "$SSH" test1 "mkdir -p '$dirb'" >/dev/null 2>&1
    for i in $(seq 1 "$P"); do
        ( "$SSH" "test$i" "bash -s '$dirb/r$i' '$F' '$i' '$mark'" <<< "$W" \
            > "$od/op$i.txt" 2>&1 ) &
    done
    wait
    for i in $(seq 1 "$P"); do
        ( "$SSH" "test$i" \
            "dmesg | awk '/$mark/{f=1} f' | grep -E 'P138-WAIT|P131-WAITLONG|P203-PR-NODEFER' | tail -4000" \
            > "$od/pr$i.txt" 2>/dev/null ) &
    done
    wait
    "$SSH" test1 "rm -rf '$dirb'" >/dev/null 2>&1
    echo "$tag"
}

echo "=== caw_pr_nodefer_ab: passes=$PASSES F=$F P=$P ==="
for pass in $(seq 1 "$PASSES"); do
    for v in $ARMS; do
        echo "--- pass $pass arm caw_pr_defer_max_ms=$v ---"
        if ! setarm "$v"; then
            echo "!! ARM DID NOT TAKE ON ALL NODES -- results not comparable"; exit 3
        fi
        onepass "$pass" "$v" >/dev/null
    done
done
setarm "$DEFARM" >/dev/null   # leave the cluster on the default

export ARMS
python3 - "$OUT" "$PASSES" "$P" <<'PY'
import sys, os, re, glob, statistics
from collections import Counter
out, PASSES, P = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
W138 = re.compile(r'P138-WAIT ino=(\d+) mode=(\d+) elapsed_ms=(\d+) ffw_ms=(\d+) ytd=(-?\d+)')
NOD  = re.compile(r'P203-PR-NODEFER ino=(\d+) mode=(\d+)')

def load(tag):
    od = os.path.join(out, tag)
    ops, waits, nodef = [], [], 0
    for p in glob.glob(os.path.join(od, "op*.txt")):
        for ln in open(p, errors='replace'):
            f = ln.split()
            if len(f) == 3 and f[0] == 'OP': ops.append(int(f[2]))
    for p in glob.glob(os.path.join(od, "pr*.txt")):
        for ln in open(p, errors='replace'):
            m = W138.search(ln)
            if m: waits.append(tuple(int(m.group(i)) for i in range(1, 6)))
            if NOD.search(ln): nodef += 1
    return ops, waits, nodef

def row(label, ops, waits, nodef):
    if not ops:
        print(f"  {label:14s} NO SAMPLES"); return None
    ops = sorted(ops)
    mean = statistics.fmean(ops)
    p50 = ops[len(ops)//2]
    p95 = ops[min(len(ops)-1, int(len(ops)*.95))]
    tw = sum(w[2] for w in waits)
    ff = sum(w[3] for w in waits)
    yd = sum(w[4] for w in waits)
    print(f"  {label:14s} creates={len(ops):5d}  mean={mean:7.1f}  p50={p50:5d}  "
          f"p95={p95:6d}  max={max(ops):6d} | grants={len(waits):4d} "
          f"wait={tw/1000.0:6.1f}s ffw={ff/1000.0:6.1f}s "
          f"({100.0*ff/tw if tw else 0:4.1f}%) defers={yd:5d} nodefer={nodef:4d}")
    return mean, p50, p95, max(ops), tw, ff, yd

print("\n=== per pass (arms alternate within one cluster state) ===")
ARMS=[int(x) for x in os.environ.get("ARMS","0 50").split()]
agg = {v: ([], [], 0) for v in ARMS}
for pss in range(1, PASSES + 1):
    print(f"pass {pss}:")
    for v in ARMS:
        ops, waits, nodef = load(f"p{pss}_arm{v}")
        row("UNBOUNDED" if v == 0 else f"BOUND {v}ms", ops, waits, nodef)
        a = agg[v]
        agg[v] = (a[0] + ops, a[1] + waits, a[2] + nodef)

print("\n=== pooled across all passes ===")
res = {}
for v in ARMS:
    ops, waits, nodef = agg[v]
    res[v] = row("UNBOUNDED" if v == 0 else f"BOUND {v}ms", ops, waits, nodef)

if res.get(ARMS[0]) and res.get(ARMS[-1]):
    o, n = res[ARMS[0]], res[ARMS[-1]]
    print(f"\n=== delta (BOUND {ARMS[-1]}ms vs UNBOUNDED) ===")
    for i, nm in ((0, "mean create ms"), (1, "p50 create ms"),
                  (2, "p95 create ms"), (3, "max create ms"),
                  (4, "total grant wait ms"), (5, "already-grantable ms"),
                  (6, "ticket deferrals")):
        a, b = o[i], n[i]
        chg = (100.0 * (b - a) / a) if a else 0.0
        arrow = "BETTER" if b < a else ("same" if b == a else "WORSE")
        print(f"  {nm:24s} {a:10.1f} -> {b:10.1f}   {chg:+7.1f}%  {arrow}")
PY
echo "=== raw in $OUT ==="
