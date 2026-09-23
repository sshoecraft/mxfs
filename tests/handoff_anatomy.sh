#!/bin/bash
# handoff_anatomy.sh — sharding increment 0 (docs/dir-sharding.md, build order
# step 0): decompose ONE cross-node EX handoff of a contended directory inode
# into its sequence-proven parts, and count what each part costs on the hot
# CAW slot, so the only optimisations landed before sharding are the ones the
# measured sequence justifies (redundant-force skip, poller/read reduction,
# cached-copy validity by generation+epoch).
#
# WHY (sess436/437, D-32NODE-SHARED-DIR-CREATE-PACE / D-401)
#   32 nodes x 100 O_SYNC creates into ONE directory: 70-100 s (FAIL) vs 17 s
#   with a private directory per node.  The dir inode's EX lock rotates node to
#   node at a ~20 ms floor per handoff: ~6 ms adopt + dir re-read, ~10 ms
#   release (P138-BAST p50 10.4 ms at mht=0: sb/b2 = AIL drain + device flush
#   1.7 ms, sx = wire unlock 4.7 ms p50 / 15 ms p90), ~7 ms transfer.  sess380
#   measured 27 slot READs per create, 83% of them find_slot's probe walk, and
#   refuted wake-the-field / fastpoll / CAS-herd / backstop as the amplifier.
#   The chain-2/5 captures kept only P138 lines, so the unlock-contention,
#   wake, adopt and wait probes were never in the same capture as the release
#   stages.  This harness captures them ALL, fleet-wide, for one burst, plus
#   the per-LBA command counters and the P383 read-caller census.
#
# WHAT IT DOES
#   1. optional knobs on every node: inode_mht_ms (MHT quantum), caw_locktotal_ms
#      (P139 whole-acquire census floor, default 50 here so the census sees the
#      sub-800 ms tail sess380 found invisible)
#   2. mkdir from test1, resolve the dir's CAW slot off the platter, arm the
#      per-LBA watch counters + P383-SLOTREAD caller tag on every node
#   3. kmsg marker + UTC stamp on every node, then the burst: P nodes x F
#      creates (dd 4 KiB oflag=sync, the crash_consistency shape)
#   4. harvest with journalctl --since <stamp> (never a bounded dmesg sweep —
#      the ring wraps in minutes under this load, sess429 trap), the watch
#      counters, then disarm; analysis by tests/handoff_anatomy.py
#
# Usage: tests/handoff_anatomy.sh <label> [participants=32] [creates_per_node=100] [mht_ms=keep] [locktotal_ms=50]
# Output: tests/evidence/<UTC>_handoff_<label>/  (test*.log, counters, report.txt)
#
# budget: a measurement harness, not a criterion; the burst's own budget is the
# crash_consistency create phase (90 s at 32x100).  Bound the call at 300 s.
# the unkillable-wedge rule: no pgrep -f / ps; every ssh is bounded.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 2
SSH="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:?label}
P=${2:-32}
F=${3:-100}
MHT=${4:-keep}
LOCKTOTAL=${5:-50}
# sess445: optional extra module knobs, "name=value[,name=value...]", written
# on every node before the burst and echoed back into testN.gate (per-node
# evidence) — the A/B lever for successor-poll style changes on ONE build.
KNOBS=${6:-}
MNT=/mnt/shared
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve test1; DEV=$MXFS_DEV_RESOLVED
PARM=/sys/module/mxfs/parameters
COUNTERS="caw_watch_reads caw_watch_read_totms caw_watch_read_maxms \
caw_watch_spans caw_watch_caws caw_watch_caw_totms caw_watch_caw_maxms \
caw_watch_miscmp caw_watch_err"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/${STAMP}_handoff_$LABEL
mkdir -p "$OUT"
DIR="$MNT/.handoff_$LABEL"
MARK="HANDOFF-$LABEL-$(date -u +%H%M%S)"
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
TREE_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
echo "=== handoff_anatomy label=$LABEL P=$P F=$F mht=$MHT locktotal=$LOCKTOTAL sv=$TREE_SV out=$OUT $(date -u +%FT%TZ) ==="

# 0. srcgate + knobs (per-node evidence)
for i in $(seq 1 "$P"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED
        [ '$MHT' = keep ] || echo $MHT > $PARM/inode_mht_ms
        echo $LOCKTOTAL > $PARM/caw_locktotal_ms
        for kv in \$(echo '$KNOBS' | tr , ' '); do echo \${kv#*=} > $PARM/\${kv%%=*} || echo KNOB_FAIL=\$kv; done
        for kv in \$(echo '$KNOBS' | tr , ' '); do echo knob \${kv%%=*}=\$(cat $PARM/\${kv%%=*}); done
        echo mht=\$(cat $PARM/inode_mht_ms) locktotal=\$(cat $PARM/caw_locktotal_ms)" > "$OUT/test$i.gate" &
done; wait
bad=""
for i in $(seq 1 "$P"); do
    grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate" || bad="$bad test$i"
done
[ -z "$bad" ] || { echo "ABORT srcgate/mount:$bad"; exit 2; }
echo "--- srcgate OK on $P nodes: $(grep -h 'mht=\|^knob \|KNOB_FAIL' "$OUT"/test1.gate | tr '\n' ' ')"
grep -l KNOB_FAIL "$OUT"/test*.gate 2>/dev/null | head -3 | sed 's/^/KNOB_FAIL on: /'

# 1. the directory and its slot
sshq 20 test1 "mkdir -p '$DIR' && stat -c %i '$DIR'" > "$OUT/mkdir.txt"
INO=$(grep -xE '[0-9]+' "$OUT/mkdir.txt" | tail -1)
[ -n "$INO" ] || { echo "ABORT: mkdir/stat $DIR: $(cat "$OUT/mkdir.txt")"; exit 2; }
# touch it from two nodes so the inode lock binds a slot before the watch is armed
sshq 20 test2 "ls '$DIR' >/dev/null; touch '$DIR/.bind2'; sync '$DIR/.bind2'" >/dev/null
sshq 20 test3 "ls '$DIR' >/dev/null; touch '$DIR/.bind3'; sync '$DIR/.bind3'" >/dev/null
SLOT=$(sshq 30 test1 "$REPO/tools/caw_slotdump $DEV --type inode --max 200000 2>/dev/null | grep -E ' ino=$INO '" | grep -o 'slot=[0-9]*' | head -1 | cut -d= -f2)
[ -n "$SLOT" ] || { echo "ABORT: no live CAW slot bound to ino=$INO"; exit 2; }
echo "--- dir ino=$INO -> CAW slot $SLOT"

# 2. arm the watch (per-LBA counters + P383-SLOTREAD caller tag) on every node
for i in $(seq 1 "$P"); do
    ( sshq 20 "test$i" "[ -w $PARM/caw_watch_slot ] || { echo NOKNOB; exit 0; }
        for c in $COUNTERS; do echo 0 > $PARM/\$c; done
        echo $SLOT > $PARM/caw_watch_slot; cat $PARM/caw_watch_slot" > "$OUT/arm.$i" ) &
done; wait
bad=""
for i in $(seq 1 "$P"); do [ "$(grep -xE '[0-9]+' "$OUT/arm.$i" | tail -1)" = "$SLOT" ] || bad="$bad test$i"; done
[ -z "$bad" ] || { echo "ABORT: watch not armed on:$bad"; exit 2; }
echo "--- watch armed on $P nodes"

# 3. marker + burst
SINCE=$(date -u '+%Y-%m-%d %H:%M:%S')
for i in $(seq 1 "$P"); do sshq 10 "test$i" "echo $MARK > /dev/kmsg" >/dev/null & done; wait
W=$(cat <<'EOS'
set -u
D="$1"; F="$2"; R="$3"
start=$(date +%s%N)
for i in $(seq 1 "$F"); do dd if=/dev/urandom of="$D/node${R}_f$i" bs=4096 count=1 oflag=sync 2>/dev/null; done
echo "WALL $(( ($(date +%s%N) - start) / 1000000 ))"
EOS
)
TB=$(date +%s)
for i in $(seq 1 "$P"); do
    ( timeout 240 "$SSH" "test$i" "bash -s '$DIR' '$F' '$i'" <<< "$W" > "$OUT/op.$i" 2>&1 ) &
done; wait
BURST=$(( $(date +%s) - TB ))
echo "$MARK" > "$OUT/mark.txt"; echo "$SINCE" > "$OUT/since.txt"; echo "$INO" > "$OUT/ino.txt"; echo "$SLOT" > "$OUT/slot.txt"

# 4. harvest: counters (then disarm), full P-line journal since the stamp
for i in $(seq 1 "$P"); do
    ( sshq 25 "test$i" "for c in $COUNTERS; do printf '%s ' \"\$(cat $PARM/\$c 2>/dev/null)\"; done; echo
        echo -1 > $PARM/caw_watch_slot" > "$OUT/w.$i" ) &
done; wait
for i in $(seq 1 "$P"); do
    ( sshq 60 "test$i" "journalctl -k --since '$SINCE' --no-pager -o short-precise 2>/dev/null | grep -a 'mxfs: P138-\|mxfs: P381-\|mxfs: P382-\|mxfs: P6H-\|mxfs: P63-HANDOFF\|mxfs: P26-REBUILD\|mxfs: P139-\|mxfs: P383-\|mxfs: P297-\|mxfs: P36-MHT\|mxfs: P35-ACQBAST\|mxfs: P-DIRWR\|mxfs: P70-BP\|$MARK'" > "$OUT/test$i.log"; echo "rc=$? lines=$(wc -l < "$OUT/test$i.log")" > "$OUT/test$i.rc" ) &
done; wait
walls=$(for i in $(seq 1 "$P"); do grep -o 'WALL [0-9]*' "$OUT/op.$i" 2>/dev/null | awk '{print $2}'; done | sort -n)
nw=$(echo "$walls" | grep -c .)
echo "--- burst: $((P * F)) creates from $P nodes in ${BURST}s; per-node walls (n=$nw): p50=$(echo "$walls" | awk '{v[NR]=$1} END{print v[int(NR/2)+1]}')ms max=$(echo "$walls" | tail -1)ms"
echo "--- journals: $(cat "$OUT"/test*.rc | grep -c 'rc=0') of $P harvested; lines: $(cat "$OUT"/test*.log | wc -l)"
python3 tests/handoff_anatomy.py "$OUT" | tee "$OUT/report.txt"
sshq 60 test1 "rm -rf '$DIR'" >/dev/null
echo "=== handoff_anatomy $LABEL: done out=$OUT wall=$(( $(date +%s) - TB ))s ==="
