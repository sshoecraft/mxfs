#!/bin/bash
# sess474 chain 116: D-0133 (sb summary counters diverge from the AG headers
# after a CLEAN fleet unmount) — the instrumented measurement + fix lap on the
# 0.64.26 freeze (PROD_KO/PROD_SV):
#   xfs_initialize_perag_data sums the FRESH AGF/AGI buffers in cluster mode
#   and prints P-SB-RECOUNT-STALE for every per-AG summary that disagreed
#   (the proof of the mechanism); xfs_log_quiesce prints P-SB-SYNC-PRE /
#   -WRITE / -POST (durable counters around this node's recompute+cover).
# Shape (chain 115's, which produced the divergence on s473b/s473c): prep,
# the 2-node dirshard reuse laps (creator test1, peer test2), TIMESTAMPED
# fleet unmount (P-UNMOUNT-ORDER: per-node start/end epoch ns), then every
# node's dmesg P-SB-* / P30 lines (nodes stay up after umount), then chk.
# Two laps.  Verdict per lap: RECOUNT_STALE lines >= 1 on some node proves
# the mechanism (H1); chk errors=0 with inobt totals == sb icount/ifree
# proves the fix; a chk mismatch WITH zero stale lines refutes H1 (-> H2,
# the concurrent-quiesce race, read from the PRE/WRITE/POST + order).
# budget: prep 300 (86-118 measured); reuse 10 laps 150 (152 s for 20);
# umount 120; capture 60; chk 60.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s474c}
GATE=${GATE:-tests/evidence/sess469_chain108_inactcert_s474b.log}
LOG=tests/evidence/sess474_chain116_d0133_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-3}
REUSE_LAPS=${REUSE_LAPS:-10}
# sess474 (design-consult A+ verification bar): rotate the worker pair per lap so the
# final SB writer varies (an idle node on some laps, a worker on others).
WORKERS=${WORKERS:-"test1:test2 test5:test6 test30:test31"}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
XFS_DATA_OFFSET=${XFS_DATA_OFFSET:-793497600}   # chk_mxfs -v xfs_data_offset= for this mkfs geometry
DM=tests/evidence/sess474_chain116_dmesg_$LABEL
mkdir -p "$DM"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
install_ko() { # <ko> <sv>
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t; done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$2"
  [ "$sv" = "$2" ]
}
fleet_umount() { # <lap>
  local UM=$DM/umount_lap$1; mkdir -p "$UM"; local T1=$(date +%s)
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "s=\$(date +%s%N); if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; rc=\$?; else rc=0; fi; e=\$(date +%s%N); echo P-UNMOUNT-ORDER node=test$i start_ns=\$s end_ns=\$e rc=\$rc" 2>/dev/null | grep -a '^P-UNMOUNT-ORDER' | tail -1 > "$UM/um_test$i.txt" ) &
  done; wait
  echo "STAGE fleet_umount lap=$1 wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l 'rc=0' "$UM"/um_test*.txt | wc -l)/32"
  cat "$UM"/um_test*.txt | sort -t= -k4 -n | awk '{print "  " $0}'
}
probe_capture() { # <lap>
  local f n
  for i in $(seq 1 32); do
    n=test$i; f="$DM/sb_lap$1_$n.txt"
    ( timeout 40 $SSH "$n" "dmesg | grep -a 'P-SB-SYNC\|P-SB-RECOUNT\|P-SB-SUMMARY\|P30-QUIESCE-RECOUNT'" 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$' > "$f" ) &
  done; wait
  echo "STAGE probe_capture lap=$1 stale_lines=$(cat "$DM"/sb_lap$1_test*.txt | grep -ac P-SB-RECOUNT-STALE) nodes_with_stale=$(grep -alc P-SB-RECOUNT-STALE "$DM"/sb_lap$1_test*.txt | grep -v ':0' | wc -l) pre=$(cat "$DM"/sb_lap$1_test*.txt | grep -ac P-SB-SYNC-PRE) post=$(cat "$DM"/sb_lap$1_test*.txt | grep -ac P-SB-SYNC-POST)"
  for i in $(seq 1 32); do grep -a 'P-SB-SUMMARY-LOCK\|P-SB-RECOUNT-DONE\|P-SB-SYNC-WRITE\|P-SB-SYNC-POST\|P-SB-SUMMARY-UNLOCK' "$DM/sb_lap$1_test$i.txt" | tail -5 | sed "s/^/  test$i: /" | cut -c1-200; done
  # the final writer = the node whose unmount ended last; its WRITE must equal chk's totals
  last=$(cat "$DM"/umount_lap$1/um_test*.txt | sort -t= -k4 -n | tail -1 | grep -ao 'node=test[0-9]*' | cut -d= -f2)
  echo "  FINAL-WRITER lap=$1 node=$last write=[$(grep -a 'P-SB-SYNC-WRITE' "$DM/sb_lap$1_$last.txt" | tail -1 | grep -ao 'icount=[0-9]* ifree=[0-9]* fdblocks=[0-9]*')] lock_rc=[$(grep -a 'P-SB-SUMMARY-LOCK' "$DM/sb_lap$1_$last.txt" | tail -1 | grep -ao 'rc=-*[0-9]*')] lock_fail_nodes=$(grep -al 'P-SB-SUMMARY-LOCK slot=[0-9]* rc=-' "$DM"/sb_lap$1_test*.txt | wc -l) recount_err_nodes=$(grep -al 'P-SB-RECOUNT-DONE slot=[0-9]* err=-' "$DM"/sb_lap$1_test*.txt | wc -l)"
  cat "$DM"/sb_lap$1_test*.txt | grep -a P-SB-RECOUNT-STALE | head -12 | cut -c1-260 | sed 's/^/  /'
}
{
  echo "=== sess474 chain116 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) LAPS=$LAPS REUSE_LAPS=$REUSE_LAPS ==="
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  set -- $WORKERS
  for L in $(seq 1 $LAPS); do
    pair=${1:-test1:test2}; [ $# -gt 0 ] && shift; W1=${pair%%:*}; W2=${pair##*:}
    lap 300 "prep lap=$L" ./run.sh 32 caw prep_cluster
    lap 150 "dirshard_reuse_peer_list $W1 $W2 $REUSE_LAPS lap=$L" tests/dirshard_reuse_peer_list.sh $W1 $W2 "$REUSE_LAPS"
    # sess474 (GPT A+ bar): the sb sector outside icount/ifree/fdblocks/crc/lsn
    # must be byte-identical before and after the fleet unmount.
    sleep 5; tests/mxfs_sb_bytecmp.sh snap "$IMG" "$DM/sb_pre_lap$L.bin" "$XFS_DATA_OFFSET"
    fleet_umount $L
    tests/mxfs_sb_bytecmp.sh snap "$IMG" "$DM/sb_post_lap$L.bin" "$XFS_DATA_OFFSET"
    probe_capture $L
    tests/mxfs_sb_bytecmp.sh cmp "$L" "$DM/sb_pre_lap$L.bin" "$DM/sb_post_lap$L.bin"
    T0=$(date +%s); timeout 60 tools/chk_mxfs -v "$IMG" > "$DM/chk_lap$L.txt" 2>&1; rc=$?
    echo "STAGE chk lap=$L rc=$rc wall=$(( $(date +%s) - T0 ))s errors=$(grep -ac 'ERROR' "$DM/chk_lap$L.txt") $(grep -a 'ERROR\|icount=' "$DM/chk_lap$L.txt" | head -3 | tr '\n' ';' | cut -c1-300)"
    echo "  SB-CHK-MATCH lap=$L chk_offset=$(grep -ao 'xfs_data_offset=[0-9]*' "$DM/chk_lap$L.txt" | head -1) used_offset=$XFS_DATA_OFFSET chk=[$(grep -ao 'icount=[0-9]*, ifree=[0-9]*' "$DM/chk_lap$L.txt" | head -1)] post=[$(python3 -c "import struct,sys;x=open(sys.argv[1],'rb').read();print('icount=%d, ifree=%d'%struct.unpack('>QQ',x[128:144]))" "$DM/sb_post_lap$L.bin")]"
  done
  echo "RESULTS: $(grep -a '^STAGE chk\|^STAGE probe_capture\|^  FINAL-WRITER\|^  SB-BYTECMP\|^  SB-CHK-MATCH' "$LOG" | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
