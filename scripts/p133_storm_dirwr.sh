#!/bin/bash
# p133_storm_errcap.sh — sess133 diagnostic variant of the workload-A mkdir
# storm (zero_silent_loss).  Identical storm shape to
# sess88_workload_a_modeN_baseline.sh (fresh mkfs+mount, every node creates
# <dpn> uniquely-named dirs in ONE shared dir), but each node records every
# mkdir/touch FAILURE with its exit status and errno text to a node-local
# file, which is gathered at the end.  Distinguishes "mkdir returned an error"
# (visible failure at create time) from true silent dirent loss (created OK
# but absent from the global view).
#
# Usage: p133_storm_errcap.sh <module> <dpn>
set -u
MODULE="${1:-/src/mxfs/mxfs.ko}"
DPN="${2:-100}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
DEV=/dev/sda
MNT=/mnt/shared
ALL=(test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16)
NODES=()
for n in "${ALL[@]}"; do
  timeout 6 "$SSH" "$n" "$PASS" 'echo UP' 2>/dev/null | grep -q UP && NODES+=("$n")
done
N=${#NODES[@]}
[ "$N" -ge 2 ] || { echo "fewer than 2 nodes up"; exit 1; }
NODE0="${NODES[0]}"
echo "=== p133 errcap storm: nodes=$N dpn=$DPN ==="

run() { timeout "${3:-120}" "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

# sess68: VERIFIED pre-mkfs barrier.  mkfs MUST NOT run while any node still
# has mxfs loaded — a live CAW heartbeat racing mkfs's WRITE SAME slot-table
# zero is the canonical SCST wedge trigger (sess14).  Retry rmmod up to 6x and
# abort rather than mkfs into a live cluster (the old code ignored rmmod
# failure and proceeded).
stuck=""
for try in $(seq 1 6); do
  stuck=""
  for n in "${NODES[@]}"; do
    st=$(run "$n" "umount $MNT 2>/dev/null; umount -l $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; lsmod | grep -c '^mxfs'" 40 | tr -dc '0-9')
    [ "${st:-1}" != "0" ] && stuck="$stuck $n"
  done
  [ -z "$stuck" ] && break
  echo "pre-mkfs barrier try $try: mxfs still loaded on:$stuck"
  sleep 5
done
[ -n "$stuck" ] && { echo "PRE-MKFS BARRIER FAILED — mxfs still loaded on:$stuck (refusing to mkfs into a live cluster)"; exit 1; }
out=$(run "$NODE0" "
  /src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1; modprobe libcrc32c
  insmod $MODULE dirwr=1 2>/dev/null
  sg_persist --out --register-ignore --param-sark=0x5eed $DEV >/dev/null 2>&1
  sg_persist --out --clear --param-rk=0x5eed $DEV >/dev/null 2>&1
  echo y | /src/mxfs/tools/mkfs_mxfs $DEV >/tmp/m.log 2>&1 && echo MKFS_OK
  mount -t mxfs $DEV $MNT && echo MOUNT_OK" 150)
echo "$out" | grep -q MOUNT_OK || { echo "form $NODE0 FAILED: $out"; exit 1; }
for n in "${NODES[@]:1}"; do
  ( run "$n" "/src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1; modprobe libcrc32c; insmod $MODULE dirwr=1 2>/dev/null; mount -t mxfs $DEV $MNT && echo OK" 120 | grep -q OK || echo "join $n FAIL" ) &
done
wait

TD="$MNT/wa_iter1"
run "$NODE0" "mkdir -p $TD; sync" 30 >/dev/null

for idx in "${!NODES[@]}"; do
  n="${NODES[$idx]}"; id=$((idx+1))
  ( run "$n" "rm -f /tmp/p133_fail.txt; touch /tmp/p133_fail.txt
      for j in \$(seq 1 $DPN); do
        d=$TD/node${id}_dir\$j
        err=\$(mkdir \$d 2>&1); rc=\$?
        if [ \$rc -ne 0 ]; then echo \"MKDIR_FAIL j=\$j rc=\$rc err=\$err\" >> /tmp/p133_fail.txt; continue; fi
        err=\$(touch \$d/m 2>&1); rc=\$?
        [ \$rc -ne 0 ] && echo \"TOUCH_FAIL j=\$j rc=\$rc err=\$err\" >> /tmp/p133_fail.txt
      done; sync; echo NODE${id}_DONE fails=\$(grep -c . /tmp/p133_fail.txt)" 300 ) &
done
wait

echo "=== per-node failure records ==="
total_fail=0
for idx in "${!NODES[@]}"; do
  n="${NODES[$idx]}"; id=$((idx+1))
  f=$(run "$n" "cat /tmp/p133_fail.txt 2>/dev/null" 20)
  c=$(echo -n "$f" | grep -c .)
  total_fail=$((total_fail + c))
  [ "$c" -gt 0 ] && { echo "--- $n (node$id): $c failures"; echo "$f" | head -20; }
done
echo "total_create_failures=$total_fail"

expected=$((N*DPN))
post=$(run "$NODE0" "find $TD -mindepth 1 -maxdepth 1 -type d -name 'node*_dir*' 2>/dev/null | wc -l" 90 | tr -dc '0-9')
post=${post:-0}
echo "expected=$expected visible=$post create_failures=$total_fail"
echo "true_silent_loss=$((expected - post - total_fail))"
