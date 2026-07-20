#!/bin/bash
# scst_scale.sh — TCP DLM (force_transport=1) scaling sweep on the clyde SCST
# shared LUN (/dev/sda, vendor SCST_FIO).  Find the wall: run the workload-A
# mkdir storm at 1 -> 2 -> 4 -> 8 -> 16 nodes and report, per step, exactly
# what breaks (silent dirent loss, mount/join failures, FS shutdown).
#
# This is the SCST-substrate counterpart to scripts/qnap_scale.sh.  It is used
# because the QNAP appliance iSCSI target crashes under the 16-node storm
# (sess72, run 14d31183).  Transport is TCP DLM either way; only the backing
# LUN differs (clyde SCST instead of the QNAP).  Reuses the proven lib.sh
# cluster helpers (fresh_cluster_mount: NFS-ensure + fresh insmod-with-opts +
# stale-PR clear + mkfs-with-MKFS_OK-check + mount + join + verify-all-mounted).
#
# Usage: scst_scale.sh [dpn] [steps...]    default dpn=100 steps="1 2 4 8 16"
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"

# 100 mkdir is milliseconds on native XFS; allow generous per-node ssh budget
# for the storm so a slow-but-progressing FS undercounts as SILENT-LOSS only
# when it truly loses entries, not when one ssh call is killed mid-loop.
export MXFS_SSH_TIMEOUT=200

DPN="${1:-100}"; shift 2>/dev/null || true
STEPS=("$@"); [ ${#STEPS[@]} -gt 0 ] || STEPS=(1 2 4 8 16)
ALL=("${DEFAULT_NODES[@]}")

echo "=== SCST TCP DLM scaling sweep: dpn=$DPN steps='${STEPS[*]}' DEV=$MXFS_DEV opts='force_transport=1 fua_disable=0' ==="
for N in "${STEPS[@]}"; do
  NODES=("${ALL[@]:0:$N}"); NODE0="${NODES[0]}"
  echo "--- N=$N nodes=${NODES[*]} ---"

  # Clean slate on ALL 16 (a non-participant left holding the LUN would corrupt
  # the next mkfs); virsh-resets any wedged node.
  teardown_all "${ALL[*]}"
  for n in "${NODES[@]}"; do ssh_node_quiet "$n" "dmesg -C"; done

  # Fresh TCP-DLM cluster: NODE0 mkfs+mount, the rest join.  Returns nonzero
  # if mkfs fails (no stale-FS reuse) or any node fails to mount.
  if ! INSMOD_OPTS="force_transport=1 fua_disable=0" fresh_cluster_mount "$NODE0" "${NODES[@]:1}"; then
    echo "  N=$N RESULT: FORM-FAIL (mkfs/mount/join failed under TCP DLM)"
    continue
  fi

  TD="$MXFS_MOUNT/scale_$N"
  ssh_node_quiet "$NODE0" "mkdir -p $TD; sync"

  # Storm: each node makes DPN dirs in the shared dir.
  for idx in "${!NODES[@]}"; do
    n="${NODES[$idx]}"; id=$((idx+1))
    ( ssh_node_quiet "$n" "for j in \$(seq 1 $DPN); do mkdir $TD/n${id}_d\$j 2>/dev/null; done; sync" ) &
  done
  wait

  # Verify on NODE0: drop caches first so the count comes from on-disk (FUA)
  # state, not NODE0's page cache.
  ssh_node_quiet "$NODE0" "sync; echo 3 > /proc/sys/vm/drop_caches"
  found=$(ssh_node "$NODE0" "find $TD -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l" | tr -cd '0-9')
  found=${found:-0}
  expected=$((N*DPN)); silent=$((expected-found)); [ "$silent" -lt 0 ] && silent=0

  # FS shutdown / reservation conflict on any participant
  sd=0
  for n in "${NODES[@]}"; do
    ssh_node "$n" "dmesg 2>/dev/null | grep -qiE 'shut down|reservation conflict' && echo X" | grep -q X && sd=$((sd+1))
  done

  verdict=PASS
  [ "$silent" -gt 0 ] && verdict=SILENT-LOSS
  [ "$sd" -gt 0 ] && verdict=SHUTDOWN
  echo "  N=$N RESULT: $verdict mounted=$N/$N expected=$expected found=$found silent=$silent shutdown_nodes=$sd"
done
teardown_all "${ALL[*]}" >/dev/null 2>&1
echo "=== sweep done ==="
