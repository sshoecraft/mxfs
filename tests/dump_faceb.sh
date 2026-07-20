#!/bin/bash
# sess73: after a Face B (dir-block lost-update) failure, dump every dir-coherency
# detector from all 4 nodes' dmesg.  catch_rename_fail.sh clears dmesg each iter and
# stops on FAIL, so the failing iter's events are intact.  RULE 3: lives in the tree.
set -u
cd /src/mxfs
NODES="${NODES:-test1 test2 test3 test4}"
PASS=/tmp/.mxfs_pass
for n in $NODES; do
    echo "============================ $n ============================"
    timeout 15 bash tools/mxfs_sshpass.sh "$n" "$PASS" \
        'dmesg | grep -aE "P-SFDIR-FASTEX|P63-INSTR|DIR-STALE-SKIP|P-EVICT-DONE|P-EVICT-SKIP|P-SF-DURABLE-FAIL|P-H18-INVAL|P-RELOAD-IOPS-REWIRE|P-RELOAD-TYPEFLIP" | tail -60' \
        2>/dev/null | grep -aviE 'Warning: Permanently|Unauthorized access|authorized user'
done
