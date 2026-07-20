#!/bin/bash
# Run tests/cluster/test_concurrent_mkdir.sh against the prepped + mounted cluster.
# This is the canonical sess34 test runner.  Per RULE 3 it lives in the source tree.
# Usage: run_concurrent_mkdir.sh <n>
#
# Prereq: cluster_reset_n.sh + cluster_mkfs_mount.sh have run successfully.

set -u
N="${1:?node count required}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass

# Clean prior test artifacts on the shared FS so iterations don't accumulate.
"$SSH" 192.168.120.186 "$PF" 'sudo rm -rf /mnt/shared/.mxfs_test /mnt/shared/.mxfs_barriers /mnt/shared/.mxfs_results 2>/dev/null; sync' 2>&1 | grep -v "^Warning\|^Unauth\|^If you" >/dev/null

export MXFS_TESTS_DIR=/src/mxfs/tests
export MXFS_SSH_TOOL=/src/mxfs/tools/mxfs_sshpass.sh
export MXFS_PASS_FILE="$PF"

cd /src/mxfs
./tests/run_tests.sh \
  --nodes "$N" \
  --device /dev/sda \
  --pass-file "$PF" \
  --test test_concurrent_mkdir 2>&1 \
  | grep -E "P-H17|P-H22|Total directory|find:.*No such|FAIL|PASS|Time:|assertion"
