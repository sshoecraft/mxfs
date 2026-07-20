#!/bin/bash
# prefix_dirreuse.sh — clean-reboot 8 nodes, run the suite PREFIX up to and
# including dir_reuse_coherency (NO fault/fence/soak tests that reboot nodes),
# so dir_reuse's in-suite failure dmesg survives for capture. sess30.
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
SCR=/src/mxfs/tests/tcp/drc_cap; mkdir -p "$SCR"
LOG="$SCR/prefix_run.log"
MOD="dir_evict_prior_tenure=1 dir_tenure_evict=1"
for n in $(seq 1 8); do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
sleep 7
for n in $(seq 1 8); do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
for w in $(seq 1 40); do up=0; for n in $(seq 1 8); do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
echo "=== prefix nodes_up=$up $(date -u) ===" | tee "$LOG"
MXFS_EXTRA_MODARGS="$MOD" timeout 1200 /src/mxfs/run.sh 8 tcp \
  precond_readiness cache_coherency strong_consistency posix_multi mmap_coherency \
  zero_silent_loss dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired \
  crash_consistency dir_reuse_coherency > "$LOG" 2>&1
echo "=== prefix done $(date -u) ===" >> "$LOG"
grep -E "  (PASS|FAIL)  " "$LOG"
