#!/bin/bash
# shared_dir_slot_cost.sh — how many SCSI commands does ONE shared-directory
# operation cost on the ONE CAW slot that serialises it?
#
# WHY THIS EXISTS (sess380, D-32NODE-SHARED-DIR-CREATE-PACE)
# ---------------------------------------------------------
# The pace defect is attributed: 32 nodes creating into one directory cost 8.3x
# more wall per node than into private directories, 74.5% of blocked samples sit
# in the CAW inode-grant wait, and the contended resource is ONE 512-byte slot
# that every participant COMPARE-AND-WRITEs.
#
# Two interim fixes were proposed and BOTH were refuted by measurement rather
# than by argument:
#   - "skip the unlock backoff when the miscompare was a pure peer
#     registration" — the classifier says only 0.2% of unlock miscompares are
#     that; 98.3% are MULTI-GENERATION, i.e. several unrelated writes landed
#     between our compare image and our re-read.
#   - "narrow the read-to-CAW window" — there is no I/O and no blocking call in
#     it; it is pure CPU.
#
# So the remaining question is not "who beats us" but "how much traffic does one
# logical operation put on that sector at all". That number is what sizes the
# real fix (a writer gate plus per-node reader records at independently
# writable locations): the gate design removes the REGISTRATION writes from the
# shared sector, so knowing what share of the traffic they are tells you the
# ceiling on the improvement before anyone writes on-disk format code.
#
# What it does: creates ONE directory, resolves the CAW slot it binds to, arms
# mxfs's per-LBA watch counters on that exact slot on every node, runs a
# concurrent create burst from N nodes into it, and reports the total command
# load on that one sector — reads, CAWs, MISCOMPAREs — per node and per create.
#
# Usage: tests/shared_dir_slot_cost.sh [participants] [creates_per_node]
#
# RULE 0: this is a measurement harness, not a criterion. It asserts nothing.
# The create burst's own budget is whatever create_scale_curve measures for the
# same shape; a wildly longer wall here means the cluster is unhealthy, not that
# the measurement is interesting.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

P="${1:-32}"
F="${2:-8}"
MNT=/mnt/shared
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
PARM=/sys/module/mxfs/parameters
COUNTERS="caw_watch_reads caw_watch_read_totms caw_watch_read_maxms \
caw_watch_spans caw_watch_caws caw_watch_caw_totms caw_watch_caw_maxms \
caw_watch_miscmp caw_watch_err"
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)
DIR="$MNT/.sdsc_$STAMP"

echo "=== shared_dir_slot_cost: P=$P F=$F dir=$DIR ==="

# 1. Create the directory from one node and let it settle, so the mkdir's own
#    contention is not inside the measured window.
"$SSH" test1 "mkdir -p '$DIR'" >/dev/null 2>&1
INO=$("$SSH" test1 "stat -c %i '$DIR'" 2>/dev/null | grep -xE '[0-9]+' | tail -1)
[ -n "$INO" ] || { echo "ABORT: could not stat $DIR"; exit 2; }

# 2. Resolve the slot the directory's inode lock binds to.  Read it off the
#    platter rather than recomputing the hash, so a probe displacement cannot
#    make us watch the wrong sector.
SLOT=$("$SSH" test1 "$REPO/tools/caw_slotdump $DEV --type inode --max 200000 2>/dev/null | grep -E ' ino=$INO '" 2>/dev/null |
       grep -o 'slot=[0-9]*' | head -1 | cut -d= -f2)
if [ -z "$SLOT" ]; then
    echo "ABORT: no live CAW slot bound to ino=$INO yet."
    echo "  The inode lock binds on first contended acquire; touch the dir from"
    echo "  two nodes and retry."
    exit 2
fi
echo "--- dir ino=$INO -> CAW slot $SLOT"

# 3. Arm the watch on every node and zero the counters.  Refuse to proceed if
#    any node lacks the knob: a silent partial arm understates the total, which
#    is the one number this harness exists to produce.
bad=""
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "
        [ -w $PARM/caw_watch_slot ] || { echo NOKNOB; exit 0; }
        for c in $COUNTERS; do echo 0 > $PARM/\$c; done
        echo $SLOT > $PARM/caw_watch_slot
        cat $PARM/caw_watch_slot" > "$OUT/arm.$i" 2>&1 ) &
done
wait
for i in $(seq 1 "$P"); do
    [ "$(grep -xE '[0-9]+' "$OUT/arm.$i" 2>/dev/null | tail -1)" = "$SLOT" ] || bad="$bad test$i"
done
if [ -n "$bad" ]; then
    echo "ABORT: caw_watch_slot did not arm on:$bad (build predates the sess380 counters)"
    exit 2
fi
echo "--- armed on all $P nodes"

# 4. The burst.
W=$(cat <<'EOS'
set -u
D="$1"; F="$2"; R="$3"
line="SDSC r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"
start=$(date +%s%N)
for i in $(seq 1 "$F"); do printf '%s' "$pat" > "$D/n${R}_$i"; done
echo "WALL $(( ($(date +%s%N) - start) / 1000000 ))"
EOS
)
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "bash -s '$DIR' '$F' '$i'" <<< "$W" > "$OUT/op.$i" 2>&1 ) &
done
wait

# 5. Harvest, then disarm.
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "for c in $COUNTERS; do printf '%s ' \"\$(cat $PARM/\$c 2>/dev/null)\"; done; echo
                       echo -1 > $PARM/caw_watch_slot" > "$OUT/w.$i" 2>&1 ) &
done
wait

walls=$(for i in $(seq 1 "$P"); do grep -o 'WALL [0-9]*' "$OUT/op.$i" 2>/dev/null | awk '{print $2}'; done | sort -n)
nw=$(echo "$walls" | grep -c .)
echo
echo "=== create burst: $((P * F)) creates into ONE directory from $P nodes ==="
echo "$walls" | awk -v n="$nw" '{v[NR]=$1} END{ if(!NR){print "  NO WALLS"; exit}
  printf "  per-node wall for %s creates: p50=%dms max=%dms\n", ENVIRON["F"], v[int(NR/2)+1], v[NR] }' F="$F"

: > "$OUT/sum"
for i in $(seq 1 "$P"); do
    set -- $(grep -xE '[0-9][0-9 ]*' "$OUT/w.$i" 2>/dev/null | tail -1)
    [ $# -eq 9 ] || continue
    echo "$1 $2 $3 $4 $5 $6 $7 $8 $9" >> "$OUT/sum"
done
echo
echo "=== command load on CAW slot $SLOT (ino $INO) ==="
awk -v tot="$((P * F))" '
  { rd+=$1; rdt+=$2; if($3>rdmx)rdmx=$3; sp+=$4; cw+=$5; cwt+=$6; if($7>cwmx)cwmx=$7; mc+=$8; er+=$9; n++ }
  END{ if(!n){print "  NO COUNTERS"; exit}
    cmds = rd + sp + cw;
    printf "  nodes reporting   %d\n", n;
    printf "  READ(16)+FUA      %6d   (%.2f per create)\n", rd, rd/tot;
    printf "  span reads        %6d\n", sp;
    printf "  COMPARE AND WRITE %6d   (%.2f per create)\n", cw, cw/tot;
    printf "    of which MISCOMPARE %5d  = %.0f%% of CAWs WASTED\n", mc, 100.0*mc/(cw?cw:1);
    printf "    landed              %5d   (%.2f per create)\n", cw-mc, (cw-mc)/tot;
    printf "  errors            %6d\n", er;
    printf "  TOTAL commands    %6d   (%.2f per create) on ONE 512B sector\n", cmds, cmds/tot;
    printf "  worst single cmd: read %dms  CAW %dms\n", rdmx, cwmx;
    printf "  summed service time on the sector: %.1fs across the fleet\n", (rdt+cwt)/1000.0;
  }' "$OUT/sum"

"$SSH" test1 "rm -rf '$DIR'" >/dev/null 2>&1
echo
echo "=== raw in $OUT ==="
