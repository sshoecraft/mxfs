#!/bin/bash
# cluster_slot_clobber_2node.sh — does one node's flush of an inode cluster
# publish a STALE image of a neighbouring slot the peer owns, and does that
# image survive on the platter?  (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY
# on the two-node TCP rig.)
#
# The physical write unit is the 16 KiB inode cluster (32 x 512 B inodes);
# the coherency protocol locks per inode.  A node that flushes one dirty
# slot writes every slot of its cached buffer, including slots a peer
# allocated or modified since this node last read the cluster.  Measured on
# the concurrent-create race (s528o, mxfs.dino_clobber_check=1):
# P-DINO-CLOBBER#1 on test1's xfsaild, in-core FREE image (changecount 0,
# mode 0) over the platter's allocated file (changecount 3) for inode
# 8388737 — the peer's later flush of that inode masked it.
#
# Shape, per lap (A=creator of the directory, B=peer):
#   1. A: mkdir D; create a0 in D and write it (A allocates the inode chunk
#      and holds the cluster buffer with every other slot FREE); sync.
#   2. B: create b1 in D, write B_PAYLOAD, fsync, close; B leaves b1 alone.
#      b1 comes from the same chunk (no AG rotor: D's AG), so its slot is a
#      neighbour of a0 in A's cached cluster buffer, where it is still FREE.
#   3. A: create a1 (same chunk), write, sync -> A's xfsaild writes the
#      cluster.  Each cluster write on A is checked against the platter by
#      dino_clobber_check (armed on A for the lap): P-DINO-CLOBBER names a
#      regression if A staged the FREE image of b1's slot.
#   4. B: drop_caches (evict b1's in-core inode), stat + cat b1 by path and
#      by inode number.  A clobber that LANDED shows here: ENOENT/ESTALE/
#      EFSCORRUPTED, an empty read, or a corruption line on B.
#   5. Both nodes: read b1 and a1 and compare with the writers' md5.
#
# Assertions: b1 readable on B after eviction with the written md5; a1
# readable on A and B; no corruption / from_disk failure on either node;
# both mounted.  Reported, not asserted: clobber_writes (P-DINO-CLOBBER on
# A) — a lap with 0 is INCONCLUSIVE for the durable question.
#
# budget: per lap ~6 s (three syncs + drop_caches + reads); N laps x 6 s +
# 10 s capture.  Default N=10 -> 70 s NOPREP.
#
# Usage: tests/cluster_slot_clobber_2node.sh <label> [N=10]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2), NOPREP=1.
set -u
LABEL=${1:?label}
N=${2:-10}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_clobber_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P-INODE-WEDGE\|P-WITHDRAW\|unrecoverable\|from_disk FAILED\|P-IGET-ENOENT'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'

echo "=== cluster_slot_clobber_2node label=$LABEL A=$A B=$B laps=$N sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -z "${NOPREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat $P/force_transport)" | tr -d '\n')"
done
ck "both nodes mounted on the tree's build" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
MK="CLOBBER-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
echo "  INFO arming dino_clobber_check on $A: $(rs 15 "$A" "echo 1 > $P/dino_clobber_check && cat $P/dino_clobber_check" | tr -d '\n')"

lap_bad=0; lap_incon=0
for i in $(seq 1 "$N"); do
    D=$MNT/clob_${LABEL}_$i
    # 1. A: dir + a0 (chunk allocation), sync
    a0=$(rs 30 "$A" "mkdir -p $D && echo a0-$i > $D/a0 && sync -f $MNT && stat -c %i $D/a0" | tail -1 | tr -d '\n')
    # 2. B: b1 written, fsynced, left alone
    b1=$(rs 30 "$B" "python3 - <<'EOF'
import os,sys,hashlib
p='$D/b1'; data=('B-payload-$i-'*40).encode()
fd=os.open(p,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o644); os.write(fd,data); os.fsync(fd); os.close(fd)
print(os.stat(p).st_ino, hashlib.md5(data).hexdigest(), len(data))
EOF" | tail -1)
    b1_ino=${b1%% *}; b1_md5=$(echo "$b1" | cut -d' ' -f2); b1_len=${b1##* }
    # 3. A: a1 in the same chunk, sync -> cluster write on A
    a1=$(rs 30 "$A" "echo a1-$i > $D/a1 && sync -f $MNT && stat -c %i $D/a1 && dmesg | sed -n '/$MK/,\$p' | grep -ac P-DINO-CLOBBER" | tr '\n' ' ')
    a1_ino=${a1%% *}; clob_so_far=${a1##* }
    # 4. B: evict and re-read b1
    rb=$(rs 40 "$B" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 - <<'EOF'
import os,hashlib
p='$D/b1'
try:
    st=os.stat(p); d=open(p,'rb').read()
    print('ino=%d size=%d md5=%s rc=0' % (st.st_ino, st.st_size, hashlib.md5(d).hexdigest()))
except OSError as e:
    print('rc=%d err=%s' % (e.errno, e.strerror))
EOF" | tail -1)
    # 5. A reads b1 after its own eviction; both read a1
    ra=$(rs 40 "$A" "echo 3 > /proc/sys/vm/drop_caches; md5sum < $D/b1 | cut -c1-32; cat $D/a1" | tr '\n' ' ')
    rba=$(rs 20 "$B" "cat $D/a1" | tr -d '\n')
    echo "  LAP $i a0=$a0 b1=$b1_ino a1=$a1_ino same_cluster=$(( (b1_ino / 32) == (a0 / 32) )) clobber_writes_so_far=$clob_so_far | B after evict: $rb | A: $ra | B reads a1: $rba" | tee -a "$OUT/laps.txt"
    case "$rb" in
        *"md5=$b1_md5 rc=0"*) ;;
        *) lap_bad=$((lap_bad+1)); echo "  BAD lap $i: b1 on $B after eviction: $rb (want md5=$b1_md5 size=$b1_len)" | tee -a "$OUT/laps.txt";;
    esac
    [ "${ra%% *}" = "$b1_md5" ] || { lap_bad=$((lap_bad+1)); echo "  BAD lap $i: b1 on $A after eviction md5=${ra%% *} want $b1_md5" | tee -a "$OUT/laps.txt"; }
    [ "$rba" = "a1-$i" ] || { lap_bad=$((lap_bad+1)); echo "  BAD lap $i: a1 on $B read '$rba'" | tee -a "$OUT/laps.txt"; }
done
echo "  INFO disarming dino_clobber_check on $A: $(rs 15 "$A" "echo 0 > $P/dino_clobber_check && cat $P/dino_clobber_check" | tr -d '\n')"
for n in $A $B; do
    rs 40 "$n" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs\|XFS' | grep -av '$NOISE'" > "$OUT/dmesg_full_$n.txt"
done
clob=$(grep -ac 'P-DINO-CLOBBER' "$OUT/dmesg_full_$A.txt")
grep -a 'P-DINO-CLOBBER' "$OUT/dmesg_full_$A.txt" | grep -ao 'P-DINO-CLOBBER#[0-9]*\|daddr=[0-9]*\|regress=[0-9]*\|comm=[^ ]*\|ino=[0-9]*\|disk cc=[0-9]*\|mem cc=[0-9]*\|mode=[0-9]*' | tr '\n' ' ' | fold -w 200 > "$OUT/clobber_fields.txt"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
echo "  CLOBBER-MEASURE $LABEL laps=$N clobber_writes_on_$A=$clob bad_reads=$lap_bad health_hits=$health"
[ "$clob" = 0 ] && echo "  INCONCLUSIVE: no stale-slot cluster write was detected on $A; the durable question was not exercised"
ck "integrity: every lap's peer file reads back intact on both nodes after eviction" "$lap_bad" "0"
ck "kernel health A+B (window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT clobber_writes=$clob"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT clobber_writes=$clob"; fi
exit $fails
