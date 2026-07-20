#!/bin/bash
# Run 8/tcp dir_reuse at given MHT; on FAIL, dump failure signature from the
# (still-booted) cluster BEFORE returning. sess2 ccloop.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
MHT="${1:-1500}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
r=$(MXFS_EXTRA_MODARGS="inode_mht_ms=$MHT" bash tests/tcp/drc_reliab_iter.sh 8 2>&1 | grep -oE 'ITER_RESULT=(PASS|FAIL)')
echo "$r"
[ "$r" = "ITER_RESULT=PASS" ] && exit 0
echo "=== FAILURE SIGNATURE (mht=$MHT) ==="
for n in test1 test2 test3 test4 test5 test6 test7 test8; do
  printf "%s: " "$n"
  timeout 10 $SSH "$n" $PASS '
    echo -n "rdir="; ls /mnt/shared/.dir_reuse_coherency 2>/dev/null | grep -c .
    echo -n " DABUF="; dmesg | grep -c P14-DABUF-HOLE
    echo -n " shutdown="; dmesg | grep -c "Shutting down filesystem"
    echo -n " declared-dead="; dmesg | grep -ciE "declaring|declared dead|node.*dead|membership.*lost"
    echo -n " lastfail="; tail -1 /root/drc_failrounds.txt 2>/dev/null | cut -c1-80
    echo
  ' 2>/dev/null
done
