#!/bin/bash
# raw_fio_ceiling.sh — capture the shared LUN's RAW N-sharer write ceilings
# for one deployment condition (conditions.md rig), so fio_perf_vs_xfs can
# gate cluster write aggregates against what the TRANSPORT+DEVICE actually
# delivers to N concurrent sharers instead of against the 1-stream native-XFS
# baseline (which a shared device cannot match at N>1 by physics: measured
# tcp rig seqW 1-stream=1116MiB/s but 2-sharer raw ≈ 650 — mxfs at 651 was
# "58% FAIL" against the wrong yardstick while actually at device parity).
#
# ⚠ DESTRUCTIVE: writes RAW over the shared LUN (offset-split per node).
#   The filesystem on it is destroyed.  Run ONLY between rungs — the next
#   `MXFS_FORCE_PREP=1 ./run.sh N <cond> prep_cluster` re-mkfs's anyway.
#   Refuses to run if any node has /mnt/shared mounted (override RAWCEIL_FORCE=1).
#
# Usage: scripts/raw_fio_ceiling.sh <cond> [Nlist]
#   cond  = tcp | cawd | cawp | caw   (names the output file only)
#   Nlist = comma list, default "2,4,8,16,32"
# Output: /src/mxfs/.raw_fio_ceiling.<cond>.json
#   { "2": {"seqW_mib": 651, "randW_iops": 1100}, ... }
# RULE 3: measurement infrastructure lives in scripts/.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
COND="${1:?usage: raw_fio_ceiling.sh <cond> [Nlist]}"
NLIST="${2:-2,4,8,16,32}"
OUT="$REPO/.raw_fio_ceiling.${COND}.json"
DEV="${RAWCEIL_DEV:-/dev/sda}"   # guest-side shared LUN device on every rig
SIZE_MB="${RAWCEIL_SIZE_MB:-512}"

say() { echo "[rawceil] $*"; }

# Safety: no mounted FS on the LUN anywhere.
if [ "${RAWCEIL_FORCE:-0}" != 1 ]; then
    for i in $(seq 1 32); do
        m=$(timeout 6 "$SSH" "test$i" "$PASS" 'mountpoint -q /mnt/shared && echo M || true' 2>/dev/null)
        [ "$m" = M ] && { say "test$i still has /mnt/shared mounted — unmount or RAWCEIL_FORCE=1"; exit 1; }
    done
fi

# One concurrent N-sharer sample: writes "sw sw_ok rw rw_ok" to stdout.
# Legs share fio_perf's discipline (O_DIRECT QD32, run twice over the same
# stripe, report only the SECOND pass).  Volumes: seq = fio_perf's own
# 2048/N MB formula; rand scales 256/N (floor 8m) because the device's
# ~900-1400 aggregate 4k iops divide across N legs — a fixed-size rand leg
# takes N× longer as N grows and blows the 300s leg timeout (measured at
# N=4 with 256m legs).  Past ~30s of IO the steady iops is volume-blind.
sample_n() {
    local N="$1" sz sp rsz d i off v sw sw_ok rw rw_ok
    sz=$(( 2048 / N )); [ "$sz" -lt 64 ] && sz=64; [ "$sz" -gt 1024 ] && sz=1024
    sp=$(( 46 / N )); [ "$sp" -lt 1 ] && sp=1
    rsz=$(( 256 / N )); [ "$rsz" -lt 8 ] && rsz=8
    d=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        off=$(( 4 + (i - 1) * sp ))
        ( timeout 300 "$SSH" "test$i" "$PASS" \
            "for p in 1 2; do sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; fio --name=rc --filename=$DEV --offset=${off}G --rw=write --bs=1M --size=${sz}m --ioengine=libaio --direct=1 --iodepth=32 --output-format=json > /tmp/rawceil.json 2>/dev/null; done; python3 -c \"import json; j=json.load(open('/tmp/rawceil.json')); print(int(j['jobs'][0]['write']['bw_bytes']/1048576))\"" \
            2>/dev/null | tail -1 > "$d/sw_$i" ) &
    done
    wait
    sw=0; sw_ok=0
    for i in $(seq 1 "$N"); do
        v=$(cat "$d/sw_$i" 2>/dev/null | tr -dc 0-9)
        [ -n "$v" ] && [ "$v" -gt 0 ] && { sw=$((sw + v)); sw_ok=$((sw_ok + 1)); }
    done
    for i in $(seq 1 "$N"); do
        off=$(( 4 + (i - 1) * sp ))
        ( timeout 300 "$SSH" "test$i" "$PASS" \
            "for p in 1 2; do sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; fio --name=rc --filename=$DEV --offset=${off}G --rw=randwrite --bs=4k --size=${rsz}m --ioengine=libaio --direct=1 --iodepth=32 --output-format=json > /tmp/rawceil.json 2>/dev/null; done; python3 -c \"import json; j=json.load(open('/tmp/rawceil.json')); print(int(j['jobs'][0]['write']['iops']))\"" \
            2>/dev/null | tail -1 > "$d/rw_$i" ) &
    done
    wait
    rw=0; rw_ok=0
    for i in $(seq 1 "$N"); do
        v=$(cat "$d/rw_$i" 2>/dev/null | tr -dc 0-9)
        [ -n "$v" ] && [ "$v" -gt 0 ] && { rw=$((rw + v)); rw_ok=$((rw_ok + 1)); }
    done
    rm -rf "$d"
    # Scale up for legs that failed to launch (fio-on-shared-raw is flaky
    # under concurrency on some rigs): report the aggregate the OK sharers
    # achieved, scaled to N.
    if [ "$sw_ok" -gt 0 ] && [ "$sw_ok" -lt "$N" ]; then sw=$(( sw * N / sw_ok )); fi
    if [ "$rw_ok" -gt 0 ] && [ "$rw_ok" -lt "$N" ]; then rw=$(( rw * N / rw_ok )); fi
    echo "$sw $sw_ok $rw $rw_ok"
}

# The backing stack (VM -> LIO/SCST -> host file -> page cache -> writeback)
# has two throughput regimes — cache absorption (fast) and writeback
# throttling (slow) — and a single sample lands in either one at random:
# measured same-N seqW spread 254..1153MiB/s.  MEDIAN OF K samples is the
# yardstick; K=3 default (RAWCEIL_SAMPLES overrides).
K="${RAWCEIL_SAMPLES:-3}"
json="{"
first=1
for N in ${NLIST//,/ }; do
    say "N=$N sharers: $K fio_perf-shape samples (median)"
    sws=""; rws=""; swok=0; rwok=0
    for k in $(seq 1 "$K"); do
        read -r s so r ro <<<"$(sample_n "$N")"
        say "  sample $k: seqW=${s}MiB/s (${so}/$N legs) randW=${r}iops (${ro}/$N legs)"
        [ "$so" -gt 0 ] && sws="$sws $s" && [ "$so" -gt "$swok" ] && swok=$so
        [ "$ro" -gt 0 ] && rws="$rws $r" && [ "$ro" -gt "$rwok" ] && rwok=$ro
    done
    sw=$(echo "$sws" | tr ' ' '\n' | grep -v '^$' | sort -n | awk '{a[NR]=$1} END{print (NR? a[int((NR+1)/2)] : 0)}')
    rw=$(echo "$rws" | tr ' ' '\n' | grep -v '^$' | sort -n | awk '{a[NR]=$1} END{print (NR? a[int((NR+1)/2)] : 0)}')
    say "N=$N: MEDIAN seqW=${sw}MiB/s randW=${rw}iops (of${sws} /${rws})"
    [ "$first" = 1 ] || json="$json,"
    json="$json\"$N\":{\"seqW_mib\":$sw,\"randW_iops\":$rw,\"legs_sw\":$swok,\"legs_rw\":$rwok}"
    first=0
done
json="$json}"
# sess10 (ccloop 72513a13): MERGE into the existing file — a partial-N
# capture used to REPLACE the whole JSON, wiping every other N's ceiling
# (a 16-only recapture destroyed 2/4/8/32 and the 4/tcp vs row fell back
# to the 1-stream xfs baseline = false 38% FAIL).
if [ -s "$OUT" ]; then
    python3 - "$OUT" <<PYEOF
import json, sys
old = json.load(open(sys.argv[1]))
new = json.loads('''$json''')
old.update(new)
json.dump(old, open(sys.argv[1], "w"), indent=4)
PYEOF
    [ $? -eq 0 ] || echo "$json" | python3 -m json.tool > "$OUT"
else
    echo "$json" | python3 -m json.tool > "$OUT" || { echo "$json" > "$OUT"; }
fi
say "wrote $OUT (merged)"
