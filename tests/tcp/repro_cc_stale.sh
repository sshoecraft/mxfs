#!/bin/bash
# repro_cc_stale.sh — standalone reproducer for the crash_consistency
# reader-stale-empty-content failure (test1 reads a peer's small synced file
# as EMPTY after drop_caches).  Runs the cc write/sync/barrier/drop/verify
# sequence directly over ssh on test1+test2 WITHOUT the MQTT harness, capturing
# the exact failing files + on-disk stat + dmesg P-traces on first failure.
#
# Usage: tests/tcp/repro_cc_stale.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MNT=/mnt/shared
ITERS="${1:-10}"
NF="${2:-50}"
CLEAN='grep -vE "^Warning:|^Unauthorized|^If you"'
run() { bash "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.cc_repro_$it"
    # write phase, both nodes in parallel
    for R in 1 2; do
        run "test$R" "
          mkdir -p $D 2>/dev/null
          for i in \$(seq 1 $NF); do
            f=$D/node${R}_f\$i
            dd if=/dev/urandom of=\$f bs=4096 count=\$(( (\$i % 8) + 1 )) oflag=sync 2>/dev/null
          done
          sync
          for i in \$(seq 1 $NF); do
            md5sum $D/node${R}_f\$i 2>/dev/null | awk '{print \$1}' > $D/node${R}_f\$i.md5
          done
          sync
        " &
    done
    wait
    sleep 1
    # cold reload + verify on test1 (reads node2's files)
    out=$(run "test1" "
      sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 1
      fails=0
      for n in 1 2; do
        for i in \$(seq 1 $NF); do
          exp=\$(cat $D/node\${n}_f\$i.md5 2>/dev/null)
          act=\$(md5sum $D/node\${n}_f\$i 2>/dev/null | awk '{print \$1}')
          if [ \"\$exp\" != \"\$act\" ]; then
            echo \"MISMATCH node\${n}_f\$i exp=[\$exp] act=[\$act] md5size=\$(stat -c%s $D/node\${n}_f\$i.md5 2>/dev/null) datasize=\$(stat -c%s $D/node\${n}_f\$i 2>/dev/null)\"
            fails=\$((fails+1))
          fi
        done
      done
      echo \"FAILS=\$fails\"
    ")
    nf=$(echo "$out" | sed -n 's/.*FAILS=\([0-9]*\).*/\1/p')
    echo "iter $it: FAILS=$nf"
    if [ "${nf:-0}" != "0" ]; then
        echo "$out" | grep MISMATCH | head -20
        echo "--- test1 dmesg tail ---"
        run "test1" "dmesg | grep -iE 'P-FUA|P-RELOAD|stale|shutdown|EFSCORRUPT|imap_to_bp' | tail -15"
        echo "--- test2 dmesg tail ---"
        run "test2" "dmesg | grep -iE 'P-FUA|P-RELOAD|stale|shutdown|EFSCORRUPT|imap_to_bp' | tail -15"
        echo "STOPPING on first failure (iter $it)"
        exit 1
    fi
    run "test1" "rm -rf $D 2>/dev/null; sync"
done
echo "ALL $ITERS iters clean"
