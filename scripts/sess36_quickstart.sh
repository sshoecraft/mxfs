#!/bin/bash
# Sess36 quickstart — runs the diagnostic experiments documented in
# notes/sess36_storage_diagnostic_plan.md, in the recommended order.
#
# This is RUNNABLE from a clean session start.  Each phase prints
# results.  Stop after a phase whose result is conclusive — no need
# to run later phases.
#
# Per RULE 3: persistent script lives in source tree.
#
# Usage:
#   sess36_quickstart.sh                    # E2 + E1 + simple diagnostics
#   sess36_quickstart.sh --baseline         # 10-run baseline characterization
#   sess36_quickstart.sh --ramdisk          # E5: setup ramdisk backstore (DESTRUCTIVE — needs user auth)

set -u
SCRIPTS=/src/mxfs/scripts

case "${1:-default}" in
  --baseline)
    echo "=== Sess36 baseline: 10 runs ==="
    for i in 1 2 3 4 5 6 7 8 9 10; do
      printf "%-3d: " "$i"
      timeout 600 "$SCRIPTS/sess35_capture.sh" 2 >/dev/null 2>&1 || true
      latest=$(ls -tr /home/steve/.mxfs/results | tail -1)
      grep -E 'P-H17|directory count' "/home/steve/.mxfs/results/$latest/test_concurrent_mkdir/node1.log" 2>/dev/null | tr '\n' ' ' | head -c 200
      echo
    done
    ;;
  --ramdisk)
    cat <<EOF
=== Sess36 E5: ramdisk backstore experiment ===

This will replace the iblock backstore (/dev/sda → Samsung 870 EVO)
with a ramdisk (/dev/ram0). DESTRUCTIVE to existing LIO config.

REQUIRED USER AUTHORIZATION before proceeding. The current LIO setup
is shared across the dev host and may be in use for other things.

Steps (commented out for safety — uncomment when authorized):

# sudo modprobe brd rd_nr=1 rd_size=$((1024*1024))   # 1GB ramdisk
# # remove existing iblock + tcm_loop config (need to back up first)
# # create new iblock backstore on /dev/ram0
# # wire to tcm_loop
# # restart VMs (which need to see the new /dev/sda)

# After setup, run:
#   $SCRIPTS/sess35_capture.sh 2
# 10 times. Compare to baseline.

Do NOT run this script-mode without explicit user authorization.
EOF
    ;;
  *)
    echo "=== Sess36 quickstart (E2 + simple diagnostics) ==="
    echo
    echo "[1] Verify cluster state"
    SSH=/src/mxfs/tools/mxfs_sshpass.sh
    PF=/tmp/.mxfs_pass
    for h in 192.168.120.186 192.168.120.182; do
      $SSH "$h" "$PF" 'mount | grep /mnt/shared || echo NOT_MOUNTED' 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s/^/    /"
    done
    echo
    echo "[2] Confirm sess35 baseline still reproduces"
    timeout 600 "$SCRIPTS/sess35_capture.sh" 2 2>&1 | tail -5
    latest=$(ls -tr /home/steve/.mxfs/results | tail -1)
    grep -E 'P-H17|directory count' "/home/steve/.mxfs/results/$latest/test_concurrent_mkdir/node1.log" 2>/dev/null
    echo
    echo "[3] Host-side verification of cliff (post-test)"
    LBA=$(grep -oE 'lba=[0-9]+' "/home/steve/.mxfs/results/$latest/test_concurrent_mkdir/node1.log" 2>/dev/null | head -1 | cut -d= -f2)
    LBA=${LBA:-8388408}
    echo "    LBA $LBA on /dev/sda:"
    sudo dd if=/dev/sda bs=512 count=1 skip="$LBA" iflag=direct status=none 2>&1 | xxd | head -2 | sed "s/^/    /"
    echo
    echo "[4] Findings to read next:"
    echo "    /src/mxfs/notes/sess35_findings.md (sess35 evidence trail)"
    echo "    /src/mxfs/notes/sess36_storage_diagnostic_plan.md (E1-E5 plan)"
    echo "    ~/.claude/projects/-src-mxfs/memory/sess35_lessons.md"
    ;;
esac
