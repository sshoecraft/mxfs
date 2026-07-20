#!/bin/bash
# sess88_workload_a_modeN_baseline.sh — canonical "workload-A" shared-directory
# mkdir storm for the zero_silent_loss criterion (recreated for the v5 cluster;
# the original mxfs.1 sess88 script was not inherited).
#
# Usage: sess88_workload_a_modeN_baseline.sh <module> <dpn> <iters> <mode>
#   <module> path to mxfs.ko   <dpn> dirs-per-node   <iters>   <mode> (logged; 1=skip_merge)
#
# Each iter: fresh-mount the cluster, then EVERY node concurrently creates <dpn>
# uniquely-named dirs (node${id}_dir${j}) + a marker file in a SHARED directory.
# After all nodes finish, node1 counts the globally-visible dirs (before AND after
# drop_caches) vs expected = nodes*dpn.  A created dir that is not visible is
# "silent dirent loss" (the cross-node coherency bug).  Distinct names => no
# concurrent same-name (Mode A) collision; this measures cross-node VISIBILITY of
# distinct committed entries.
#
# Emits the summary the criterion parses:
#   fs_silent=<total-missing-across-all-iters>
#   iters_with_fs_silent_loss=<n>/<iters>
set -u
MODULE="${1:-/src/mxfs/mxfs.ko}"
DPN="${2:-100}"
ITERS="${3:-3}"
MODE="${4:-1}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
DEV=/dev/sdb            # QNAP iSCSI LUN (sda is the legacy SCST passthrough)
MNT=/mnt/shared
# This harness runs the workload-A storm on the QNAP hardware iSCSI target with
# TCP DLM (no CAW), to separate FS-logic bugs from clyde-SCST infra fragility.
INSMOD_OPTS="${INSMOD_OPTS:-force_transport=1}"; export INSMOD_OPTS
# v5 cluster = test1..test16; use as many as are reachable, min 2.
ALL=(test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16)
NODES=()
for n in "${ALL[@]}"; do
  timeout 6 "$SSH" "$n" "$PASS" 'echo UP' 2>/dev/null | grep -q UP && NODES+=("$n")
done
N=${#NODES[@]}
[ "$N" -ge 2 ] || { echo "fs_silent=999999"; echo "iters_with_fs_silent_loss=0/$ITERS reason=fewer-than-2-nodes"; exit 1; }
NODE0="${NODES[0]}"
echo "=== workload-A: nodes=$N dpn=$DPN iters=$ITERS mode=$MODE ==="

run() { timeout "${3:-120}" "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

mount_cluster() {
  for n in "${NODES[@]}"; do run "$n" "umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; true" 40 >/dev/null; done
  # Barrier: every node must really be umounted + module unloaded before
  # NODE0 zeroes the slot table.  mkfs's serialized zeroing racing live CAW
  # heartbeat traffic is the SCST starvation trigger (sess14/15 wedge), and
  # a still-mounted node would see its FS yanked out from under it.
  for n in "${NODES[@]}"; do
    clean=0
    for try in 1 2 3 4 5 6; do
      if run "$n" "! grep -q ' $MNT ' /proc/mounts && ! grep -q '^mxfs ' /proc/modules && echo CLEAN" 20 | grep -q CLEAN; then clean=1; break; fi
      run "$n" "umount -f $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; true" 40 >/dev/null
      sleep 5
    done
    [ "$clean" = "1" ] || { echo "teardown $n FAILED — mount/module still live, refusing to mkfs"; return 1; }
  done
  # Every step reports loudly — sess17: iter1 form failed with "unknown
  # filesystem type" while dmesg showed a successful mount, and the silenced
  # sg_persist/mkfs steps made the failure unreconstructable post-hoc.
  out=$(run "$NODE0" "
    /src/mxfs/tools/prep_qnap_node.sh >/tmp/p.log 2>&1 && echo PREP_OK_FORM || { echo PREP_FAIL_FORM; tail -2 /tmp/p.log; }
    modprobe libcrc32c
    # sess18 trap: prep_tcm_node_scst.sh already insmods the module param-less;
    # a second insmod fails File-exists SILENTLY and INSMOD_OPTS params are
    # swallowed.  Force a fresh load so params always apply.
    lsmod | grep -q '^mxfs ' && rmmod mxfs 2>/dev/null
    insmod $MODULE ${INSMOD_OPTS:-} 2>/dev/null
    sg_persist --out --register-ignore --param-sark=0x5eed $DEV 2>&1 | grep -i 'conflict\|fail' | sed 's/^/PR_REGISTER: /'
    sg_persist --out --clear --param-rk=0x5eed $DEV 2>&1 | grep -i 'conflict\|fail' | sed 's/^/PR_CLEAR: /'
    echo y | /src/mxfs/tools/mkfs_mxfs $DEV >/tmp/m.log 2>&1 && echo MKFS_OK || { echo MKFS_FAIL_rc=\$?; tail -3 /tmp/m.log; }
    mount -t mxfs $DEV $MNT && echo MOUNT_OK || {
      echo MOUNT_FAIL_rc=\$?
      echo FORM-DIAG-LSMOD: \$(lsmod | grep mxfs | head -1)
      dmesg | tail -6 | sed 's/^/FORM-DIAG-DMESG: /'
      sg_persist -r $DEV 2>&1 | tail -2 | sed 's/^/FORM-DIAG-PR: /'
    }" 150)
  echo "$out" | grep -q MOUNT_OK || { echo "form $NODE0 FAILED: $out"; return 1; }
  for n in "${NODES[@]:1}"; do
    ( run "$n" "/src/mxfs/tools/prep_qnap_node.sh >/tmp/p.log 2>&1; modprobe libcrc32c; lsmod | grep -q '^mxfs ' && rmmod mxfs 2>/dev/null; insmod $MODULE ${INSMOD_OPTS:-} 2>/dev/null; mount -t mxfs $DEV $MNT && echo OK" 120 | grep -q OK || echo "join $n FAIL" ) &
  done
  wait
  return 0
}

total_silent=0
iters_with_loss=0
iters_completed=0
infra_iters=0
for I in $(seq 1 "$ITERS"); do
  t_iter0=$(date +%s)
  echo "--- iter $I/$ITERS --- start=$(date -u +%H:%M:%S)"
  # A mount_cluster failure is INFRA, never silent dirent loss (sess17: the
  # old +N*DPN here booked 4800 fake losses on a run that collected no data).
  # One retry — transient post-reset state (stale PR, slow rmmod) gets a
  # second chance; a persistent failure marks the iter infra-failed.
  if ! mount_cluster; then
    echo "  iter $I: mount_cluster failed — retrying once"
    if ! mount_cluster; then
      echo "  iter $I: INFRA FAIL (mount_cluster failed twice)"
      infra_iters=$((infra_iters+1)); continue
    fi
  fi
  # Count only nodes that ACTUALLY mounted (a join failure must not be
  # mis-counted as silent dirent loss).
  MOUNTED=()
  for n in "${NODES[@]}"; do
    run "$n" "mount | grep -q $MNT && echo M" 15 | grep -q M && MOUNTED+=("$n")
  done
  M=${#MOUNTED[@]}
  if [ "$M" -lt 2 ]; then
    echo "  iter $I: only $M/$N nodes mounted — INFRA FAIL"
    infra_iters=$((infra_iters+1)); continue
  fi
  t_mounted=$(date +%s)
  TD="$MNT/wa_iter$I"
  run "$NODE0" "mkdir -p $TD; sync" 30 >/dev/null
  # every MOUNTED node creates its dpn dirs in parallel
  for idx in "${!MOUNTED[@]}"; do
    n="${MOUNTED[$idx]}"; id=$((idx+1))
    # Record every mkdir/touch error verbatim — an errored create is NOT
    # silent FS loss (it is a different bug class) and must be tellable
    # apart from created-then-vanished at verify time.
    ( run "$n" ": > /tmp/wa_fail.$I; for j in \$(seq 1 $DPN); do mkdir $TD/node${id}_dir\$j 2>>/tmp/wa_fail.$I || echo MKDIRFAIL node${id}_dir\$j rc=\$? >> /tmp/wa_fail.$I; touch $TD/node${id}_dir\$j/m 2>>/tmp/wa_fail.$I || echo TOUCHFAIL node${id}_dir\$j rc=\$? >> /tmp/wa_fail.$I; done; sync" 300 >/dev/null ) &
  done
  wait
  expected=$((M*DPN))
  # sess59: count ONLY find's stdout (stderr -> /dev/null inside the remote
  # cmd) so a traversal error message's digits cannot inflate the count, and
  # emit an unambiguous COUNT= sentinel so an empty/garbled return is told
  # apart from a real 0 or a hang.  An empty post here is a node0-find HANG or
  # a node0 unreachability — itself a structural break, NOT N*DPN fake loss.
  pre=$(run "$NODE0" "echo COUNT=\$(find $TD -mindepth 1 -maxdepth 1 -type d -name 'node*_dir*' 2>/dev/null | wc -l)" 90 | sed -n 's/.*COUNT=\([0-9][0-9]*\).*/\1/p' | head -1)
  run "$NODE0" "sync; echo 3 > /proc/sys/vm/drop_caches" 30 >/dev/null
  post=""
  for vtry in 1 2 3; do
    post=$(run "$NODE0" "echo COUNT=\$(find $TD -mindepth 1 -maxdepth 1 -type d -name 'node*_dir*' 2>/dev/null | wc -l)" 90 | sed -n 's/.*COUNT=\([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$post" ] && break
    echo "  iter $I: verify find empty (try $vtry/3) — node0 find hang or unreachable; retrying"
    sleep 5
  done
  if [ -z "$post" ]; then
    echo "  iter $I: VERIFY HANG (node0 find produced no COUNT after 3 tries) — STRUCTURAL break, marking iter as loss"
    total_silent=$((total_silent+expected)); iters_with_loss=$((iters_with_loss+1)); continue
  fi
  pre=${pre:-0}
  silent=$((expected - post))
  [ "$silent" -lt 0 ] && silent=0
  if [ "$silent" -gt 0 ]; then
    # Failure-time forensics, while the FS is still mounted and the iter's
    # namespace still exists (the next iter re-mkfs's the device).
    echo "  iter $I FORENSICS: enumerating missing names"
    run "$NODE0" "find $TD -mindepth 1 -maxdepth 1 -type d -name 'node*_dir*' -printf '%f\n'" 60 | tr -d '\r' | sort > /tmp/wa_actual.$I
    for idx in "${!MOUNTED[@]}"; do id=$((idx+1)); for j in $(seq 1 "$DPN"); do echo "node${id}_dir$j"; done; done | sort > /tmp/wa_expect.$I
    comm -23 /tmp/wa_expect.$I /tmp/wa_actual.$I | while read -r miss; do
      cid=${miss#node}; cid=${cid%%_*}
      creator="${MOUNTED[$((cid-1))]}"
      cfail=$(run "$creator" "grep -i '${miss}\$\|${miss} \|${miss}/' /tmp/wa_fail.$I 2>/dev/null | head -2" 15)
      cview=$(run "$creator" "test -d $TD/$miss && echo CREATOR_SEES || echo CREATOR_MISSING" 15)
      echo "    MISSING $miss creator=$creator $cview creator_errs=[${cfail:-none}]"
    done
    for idx in "${!MOUNTED[@]}"; do
      n="${MOUNTED[$idx]}"
      ferr=$(run "$n" "wc -l < /tmp/wa_fail.$I 2>/dev/null" 15 | tr -cd '0-9')
      [ -n "$ferr" ] && [ "$ferr" != "0" ] && { echo "    NODE $n create errors ($ferr):"; run "$n" "head -5 /tmp/wa_fail.$I" 15 | sed 's/^/      /'; }
    done
  fi
  t_done=$(date +%s)
  echo "  iter $I: expected=$expected pre_drop=$pre post_drop=$post silent=$silent mount_s=$((t_mounted-t_iter0)) storm_verify_s=$((t_done-t_mounted)) iter_wall_s=$((t_done-t_iter0))"
  total_silent=$((total_silent + silent))
  iters_completed=$((iters_completed+1))
  [ "$silent" -gt 0 ] && iters_with_loss=$((iters_with_loss+1))
done

echo "fs_silent=$total_silent"
echo "iters_with_fs_silent_loss=$iters_with_loss/$ITERS"
echo "iters_completed=$iters_completed/$ITERS infra_iters=$infra_iters"
# Incomplete iters = no verdict; the criterion must not pass on a run that
# didn't measure all its iterations.
[ "$total_silent" = "0" ] && [ "$iters_completed" = "$ITERS" ] && exit 0 || exit 1
