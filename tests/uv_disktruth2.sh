#!/bin/bash
# uv_disktruth2.sh — 2-node TCP adaptation of uv_disktruth.sh (sess48 ccloop).
#
# Reproduces the test_unlink_visibility divergence on a BLOCK-format shared dir,
# then DISAMBIGUATES read-side-stale vs durable-clobber via a peer-EX poke:
#
#   after-poke node1=0 AND node2=0  => READ-SIDE STALE: store clean, BAST refresh
#   after-poke node1>0 AND node2>0  => DURABLE CLOBBER: stale base durably written
#   after-poke node1>0 AND node2=0  => REREAD STALE: per-initiator read gap
#
# Assumes the 2-node cluster is already mounted (run.sh prep).  RULE 3: in-tree.
set -u
cd "$(dirname "$0")/.."
NODES=(test1 test2)
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
DIR=$MNT/.mxfs_test/uvdt2
NPER=30
ITERS=${1:-8}

ssh_node() { timeout "${3:-40}" sshpass -f "$PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "root@$1" "$2" 2>/dev/null | grep -avE 'Warning|Unauthorized|authorized user'; }
count_on() { ssh_node "$1" "ls $DIR 2>/dev/null | grep -cE '^node[0-9]+_file'" 15 | tr -d ' '; }
surv_on()  { ssh_node "$1" "ls $DIR 2>/dev/null | grep -E '^node[0-9]+_file' | sort | tr '\n' ','" 15; }

for it in $(seq 1 "$ITERS"); do
  echo "===== ITER $it ====="
  ssh_node test1 "rm -rf $DIR; mkdir -p $DIR; sync" 25

  # concurrent create (host barrier)
  pids=()
  for idx in 0 1; do n=${NODES[$idx]}; id=$((idx+1))
    ssh_node "$n" "for i in \$(seq 1 $NPER); do echo x > $DIR/node${id}_file\$i; done; sync" 60 & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p"; done

  # concurrent delete-own (host barrier) — the contended phase
  pids=()
  for idx in 0 1; do n=${NODES[$idx]}; id=$((idx+1))
    ssh_node "$n" "for i in \$(seq 1 $NPER); do rm -f $DIR/node${id}_file\$i; done; sync" 60 & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p"; done
  sleep 2

  c1=$(count_on test1); c2=$(count_on test2)
  echo "  pre-poke:  test1=$c1  test2=$c2"
  if [ "${c1:-0}" = "0" ] && [ "${c2:-0}" = "0" ]; then
    echo "  (converged, no divergence this iter)"; continue
  fi
  echo "    test1 survivors: $(surv_on test1)"
  echo "    test2 survivors: $(surv_on test2)"

  # PEER POKE: whichever node sees 0 takes EX (touch+sync) to BAST the outlier.
  poker=test2; outlier=test1
  if [ "${c1:-0}" = "0" ]; then poker=test1; outlier=test2; fi
  echo "  POKE: $poker takes EX (touch+sync) to BAST $outlier"
  ssh_node "$poker" "touch $DIR/POKE; sync; rm -f $DIR/POKE; sync" 25
  sleep 1
  pc1=$(count_on test1); pc2=$(count_on test2)
  echo "  post-poke: test1=$pc1  test2=$pc2"

  # RAW DISK TRUTH: read the dir's block-0 from the LUN on both initiators.
  # owner ino + daddr discovered from dmesg DIR-STALE-SKIP/P16 if present.
  echo "  --- verdict ---"
  if [ "${pc1:-1}" = "0" ] && [ "${pc2:-1}" = "0" ]; then
    echo "  >>> READ-SIDE STALE (store clean, peer-EX BAST refreshed the outlier)"
  elif [ "${pc1:-0}" != "0" ] && [ "${pc2:-0}" != "0" ]; then
    echo "  >>> DURABLE CLOBBER (both nodes incl fresh-EX poker see survivors on disk)"
  else
    echo "  >>> REREAD STALE (outlier reread stale though poker is clean)"
  fi
  echo "  (leaving DIR live for raw-read; stop here)"
  exit 0
done
echo "no divergence in $ITERS iters"
