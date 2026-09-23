#!/bin/bash
# tests/readdir_peer_pace.sh <creator> <reader> [ndirs] [nfiles] [label]
#
# D-READDIR-PEER-CACHED-DIR-PACE measurement (sess472).  The record's root
# (0.11.245): xfs_readdir's stale-reload retry loop (200 x msleep(1) ~1.2 s)
# could never land because the reader holds ILOCK_SHARED; P212-RDRETRY-SKIP
# is the in-tree short-circuit.  This arm measures the user-visible cost the
# record names: the creator makes <ndirs> directories of <nfiles> files, the
# reader lists each one twice (cold: DLM acquire + fresh read; warm: cached).
# RESULT PASS   every cold readdir < 300 ms and every warm readdir < 50 ms
#               (native XFS lists a 200-entry dir in ~1 ms; 2x-native-XFS ceiling is
#               2x native plus one DLM round trip, generously 300 ms cold),
#               entry counts exact on every dir, no P48/P212 200-lap loop.
# RESULT FAIL   any readdir over its bound, a short listing, or a shutdown.
# budget: ndirs x nfiles creates (native ~ms each) + 2 x ndirs readdirs; the
# whole arm for 20 x 200 is < 60 s; bound 120 s.
set -u
cd /src/mxfs || exit 1
C=${1:?creator}; R=${2:?reader}; ND=${3:-20}; NF=${4:-200}; LABEL=${5:-rdpace}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_readdir_peer_pace_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
D=$MNT/.rdpace_$LABEL
MARK="RDPACE-$LABEL-$$"
echo "=== readdir_peer_pace creator=$C reader=$R ndirs=$ND nfiles=$NF out=$OUT $(date -u +%FT%TZ) ==="
for n in $C $R; do
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL rdpace: $MNT not mounted on $n"; exit 2; }
  rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
done
T0=$(date +%s)
rs 90 "$C" "mkdir -p $D && for d in \$(seq 1 $ND); do mkdir $D/d\$d && for i in \$(seq 1 $NF); do : > $D/d\$d/f\$i; done; done; sync; echo create_ok" | grep -q create_ok || { echo "RESULT FAIL rdpace: creator setup failed"; exit 2; }
echo "  INFO creates wall=$(( $(date +%s) - T0 ))s"
# reader: cold then warm listing of every dir, ms per readdir, entry count
o=$(rs 100 "$R" "cd $D || exit 1; for d in \$(seq 1 $ND); do for pass in cold warm; do s=\$(date +%s%N); n=\$(ls d\$d | wc -l); e=\$(date +%s%N); echo \"d\$d \$pass \$(( (e - s) / 1000000 )) \$n\"; done; done; echo reader_done")
echo "$o" > "$OUT/reader.txt"
rs 30 "$R" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$R.txt"
rs 30 "$C" "rm -rf $D" >/dev/null
echo "$o" | grep -q reader_done || { echo "RESULT FAIL rdpace: reader did not finish: $(echo "$o" | tail -2 | tr '\n' ' ')"; exit 1; }
cold_max=$(echo "$o" | awk '$2=="cold"{if($3>m)m=$3} END{print m+0}')
warm_max=$(echo "$o" | awk '$2=="warm"{if($3>m)m=$3} END{print m+0}')
cold_p50=$(echo "$o" | awk '$2=="cold"{print $3}' | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]+0}')
short=$(echo "$o" | awk -v nf="$NF" '($2=="cold"||$2=="warm") && $4!=nf' | wc -l)
loops=$(grep -ac 'P48-\|P212-RDRETRY' "$OUT/dmesg_$R.txt")
shut=$(grep -ac 'Filesystem has been shut down\|P-SESSION-POISON' "$OUT/dmesg_$R.txt")
echo "  INFO cold_max=${cold_max}ms cold_p50=${cold_p50}ms warm_max=${warm_max}ms short_listings=$short retry_loop_lines=$loops shutdown=$shut"
echo "$o" | awk '$2=="cold" && $3>300' | head -5 | sed 's/^/  SLOW /'
if [ "$cold_max" -lt 300 ] && [ "$warm_max" -lt 50 ] && [ "$short" = 0 ] && [ "$shut" = 0 ]; then
  echo "RESULT PASS rdpace: $ND dirs x $NF files cold_max=${cold_max}ms cold_p50=${cold_p50}ms warm_max=${warm_max}ms out=$OUT"; exit 0
fi
echo "RESULT FAIL rdpace: cold_max=${cold_max}ms (bound 300) warm_max=${warm_max}ms (bound 50) short=$short shutdown=$shut out=$OUT"; exit 1
