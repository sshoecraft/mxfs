#!/bin/bash
# shared_dir_pace.sh <nodes> [files_per_node]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# tests/drc_phase_profile.sh attributed dir_reuse_coherency's 13.5s round wall
# at 32 nodes to two phases: create waves (~5.0s for only 4 files/node) and
# verify (~5.7s for ls + 128 cold lookups).  That is 1.24s per file CREATE,
# against a native-XFS cost of microseconds -- a RULE 0 violation by a factor of
# ~10^5, and the mechanism behind D-DIR-REUSE-COHERENCY-32-FLAKY (the criterion
# lands exactly on its 8-round pace floor at 32 nodes, so jitter reads as a
# coherent 32-node "wrong answer").
#
# But a mean is not a diagnosis.  Two very different costs produce the same
# mean, and they need opposite fixes:
#
#   PER-FILE     each create pays a full DLM/CAW round trip.
#                => doubling files_per_node doubles the wave.  Fix = batching.
#   PER-ROTATION the wave cost is one pass of the shared-dir EX tenure around
#                all N nodes; a node's own files are cheap once it holds the
#                tenure.  => doubling files_per_node barely moves the wave.
#                Fix = handoff latency, not batching.
#
# This harness measures BOTH, uncontended and contended, on the LIVE cluster,
# and reports per-op latency rather than a wall.  It deliberately does NOT go
# through run.sh: run.sh serialises itself with a flock and records into
# criteria.json, so a diagnostic sweep through it would deadlock and/or
# overwrite board cells with non-standard configurations.
#
# Arms:
#   A  SOLO-FRESH   rank 1 alone, fresh dir           -> floor cost, no contention
#   B  SOLO-AGED    rank 1 alone, dir already holding N*F peer entries
#   C  ALL-CONTEND  every node concurrently, same dir -> the criterion's shape
#   D  ALL-PRIVATE  every node concurrently, OWN dir  -> isolates shared-dir
#                   serialisation from raw per-node create cost under load
#   E  LOOKUP-COLD  every node drop_caches then stat every entry (verify phase)
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"
F="${2:-8}"
MNT=/mnt/shared
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)

# Per-node worker: creates F files with pure-bash content (zero forks, so the
# measured time is syscall + DLM, not process spawn -- the same reason
# dir_reuse_coherency abandoned `yes | head -c`).  Emits one nanosecond
# timestamp per create so we get a LATENCY DISTRIBUTION, not just a wall.
worker() {
cat <<'EOS'
set -u
D="$1"; F="$2"; TAG="$3"; R="$4"
mkdir -p "$D" 2>/dev/null
line="SDP $TAG r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"
prev=$(date +%s%N)
start=$prev
for i in $(seq 1 "$F"); do
    printf '%s' "$pat" > "$D/n${R}_${TAG}_$i"
    now=$(date +%s%N)
    echo "OP $i $(( (now - prev) / 1000000 ))"
    prev=$now
done
echo "WALL $(( ($(date +%s%N) - start) / 1000000 ))"
EOS
}
W=$(worker)

run_arm() {   # run_arm <label> <ranks_csv|ALL> <dir_expr> <tag>
    local label="$1" who="$2" dirx="$3" tag="$4" i
    local d="$OUT/$label"; mkdir -p "$d"
    local list
    if [ "$who" = ALL ]; then list=$(seq 1 "$N"); else list=$(echo "$who" | tr ',' ' '); fi
    for i in $list; do
        ( local dd="${dirx//RANK/$i}"
          "$SSH" "test$i" \
            "bash -s '$dd' '$F' '$tag' '$i'" <<< "$W" > "$d/n$i.txt" 2>&1 ) &
    done
    wait
    python3 - "$d" "$label" <<'PY'
import sys, os, statistics, glob
d, label = sys.argv[1], sys.argv[2]
ops, walls, nodes = [], [], 0
for p in sorted(glob.glob(os.path.join(d, "n*.txt"))):
    got = False
    for ln in open(p, errors='replace'):
        f = ln.split()
        if len(f) == 3 and f[0] == 'OP':
            ops.append(int(f[2])); got = True
        elif len(f) == 2 and f[0] == 'WALL':
            walls.append(int(f[1]))
    nodes += 1 if got else 0
if not ops:
    print(f"{label:14s} NO SAMPLES"); sys.exit(0)
ops.sort()
print(f"{label:14s} nodes={nodes:3d} creates={len(ops):5d} "
      f"per-create ms: mean={statistics.fmean(ops):8.1f} p50={ops[len(ops)//2]:7d} "
      f"p95={ops[min(len(ops)-1,int(len(ops)*.95))]:7d} max={max(ops):7d}   "
      f"node wall ms: p50={sorted(walls)[len(walls)//2] if walls else -1:7d} "
      f"max={max(walls) if walls else -1:7d}")
PY
}

echo "=== shared_dir_pace: N=$N files_per_node=$F stamp=$STAMP ==="
echo "--- native reference (rank1, local /root = node's own ext4/xfs root) ---"
run_arm nativeref 1 "/root/.sdp_$STAMP" nat

echo "--- A SOLO-FRESH: rank1 alone, fresh shared dir ---"
run_arm A_solofresh 1 "$MNT/.sdp_${STAMP}_a" solo

echo "--- C ALL-CONTEND: every node, ONE shared dir (the criterion's shape) ---"
run_arm C_contend ALL "$MNT/.sdp_${STAMP}_c" all

echo "--- B SOLO-AGED: rank1 alone again, into the now-populated dir C used ---"
run_arm B_soloaged 1 "$MNT/.sdp_${STAMP}_c" aged

echo "--- D ALL-PRIVATE: every node, its OWN dir (no shared-dir serialisation) ---"
run_arm D_private ALL "$MNT/.sdp_${STAMP}_d/rRANK" priv

echo "--- E LOOKUP-COLD: every node drop_caches, then stat every entry of C ---"
for i in $(seq 1 "$N"); do
  ( "$SSH" "test$i" "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null;
      d=$MNT/.sdp_${STAMP}_c
      t0=\$(date +%s%N)
      c=\$(ls \$d 2>/dev/null | wc -l)
      t1=\$(date +%s%N)
      miss=0
      for nm in \$(ls \$d 2>/dev/null); do [ -e \"\$d/\$nm\" ] || miss=\$((miss+1)); done
      t2=\$(date +%s%N)
      echo \"LSMS \$(( (t1-t0)/1000000 )) STATMS \$(( (t2-t1)/1000000 )) ENTRIES \$c MISS \$miss\"" \
      > "$OUT/E_$i.txt" 2>&1 ) &
done
wait
python3 - "$OUT" "$N" <<'PY'
import sys, os, statistics
out, N = sys.argv[1], int(sys.argv[2])
ls, st, ent, miss = [], [], [], 0
for i in range(1, N+1):
    p = os.path.join(out, f"E_{i}.txt")
    if not os.path.exists(p): continue
    for ln in open(p, errors='replace'):
        f = ln.split()
        if len(f) == 8 and f[0] == 'LSMS':
            ls.append(int(f[1])); st.append(int(f[3]))
            ent.append(int(f[5])); miss += int(f[7])
if not ls:
    print("E_lookupcold  NO SAMPLES"); sys.exit(0)
e = ent[0] if ent else 0
print(f"E_lookupcold   nodes={len(ls):3d} entries={e:5d} lookup_miss={miss} "
      f"| readdir ms p50={sorted(ls)[len(ls)//2]:6d} max={max(ls):6d} "
      f"| {e} stats ms p50={sorted(st)[len(st)//2]:6d} max={max(st):6d} "
      f"-> per-stat p50={(sorted(st)[len(st)//2]/e if e else 0):.2f} ms")
PY

echo "=== cleanup (rank1 removes the shared scratch dirs) ==="
"$SSH" test1 "rm -rf $MNT/.sdp_${STAMP}_a $MNT/.sdp_${STAMP}_c $MNT/.sdp_${STAMP}_d" >/dev/null 2>&1
for i in $(seq 1 "$N"); do
  ( "$SSH" "test$i" "rm -rf /root/.sdp_$STAMP" >/dev/null 2>&1 ) &
done
wait
echo "=== raw samples in $OUT ==="
