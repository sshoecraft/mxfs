#!/bin/bash
# fg_tds_repeat.sh — run tcp_dlm_scaling REPEATEDLY against the ALREADY-MOUNTED,
# warmed FS (NO re-mkfs, NO reboot) for a FAST repro loop of the tcp_dlm_scaling
# residual faces (iunlink-corruption shutdown + dirent leak/resurrection).
#
# WHY: `./run.sh 2 tcp tcp_dlm_scaling` re-mkfs's the LUN every invocation, which
# wipes the accumulated AG/inode-reuse churn the bug needs (that is why a fresh
# standalone run always PASSES).  This driver reuses the warm FS.  Prereq: a full
# `./run.sh 2 tcp` (or fg_one_run) has already prepped+warmed the cluster.
#
#   bash tests/tcp/fg_tds_repeat.sh <iters>
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
ITERS="${1:-10}"
N1=192.168.120.186; N2=192.168.120.182
SSH="$REPO/tools/mxfs_sshpass.sh"
BROKER="${MXFS_COORD_BROKER:-192.168.1.149}"
MNT=/mnt/shared
SCRIPT=/src/mxfs/tests/tcp/tcp_dlm_scaling.sh
ROUNDS="${TCP_SCALING_ROUNDS:-150}"
WINDOW="${TCP_SCALING_WINDOW:-120}"
sshc() { timeout "${1}" sshpass -f "$P" ssh -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 root@"$2" "$3" 2>/dev/null; }

pass=0; ran=0
for it in $(seq 1 "$ITERS"); do
    # confirm both still mounted (a shutdown leaves it unusable until reboot)
    m=0; for h in "$N1" "$N2"; do sshc 8 "$h" 'mount|grep -q "on /mnt/shared type mxfs"' && m=$((m+1)); done
    [ "$m" -eq 2 ] || { echo "iter $it: ABORT — only $m/2 mounted (a node shut down); reboot needed"; break; }
    sshc 15 "$N1" "rm -rf $MNT/.tcp_dlm_scaling/* 2>/dev/null; sync"
    prefix="mxfs/fgtds/$$/$it"
    tmpd=$(mktemp -d); pids=(); i=0
    for n in test1 test2; do
        i=$((i+1))
        ( timeout 200 "$SSH" "$n" "$P" \
            "MXFS_NODES=2 MXFS_RANK=$i MXFS_DLM=tcp MXFS_COORD_BROKER=$BROKER \
             MXFS_COORD_PREFIX=$prefix COORD_TIMEOUT=90 \
             TCP_SCALING_ROUNDS=$ROUNDS TCP_SCALING_WINDOW=$WINDOW \
             bash $SCRIPT '$MNT'" > "$tmpd/$n" 2>&1 ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    ran=$((ran+1))
    r1=$(grep -E '^RESULT:' "$tmpd/test1" | tail -1)
    r2=$(grep -E '^RESULT:' "$tmpd/test2" | tail -1)
    s1=$(awk '{print $2}' <<<"$r1"); s2=$(awk '{print $2}' <<<"$r2")
    if [ "$s1" = PASS ] && [ "$s2" = PASS ]; then
        pass=$((pass+1)); echo "iter $it: PASS"
    else
        echo "iter $it: FAIL  t1=$s1 t2=$s2"
        echo "    t1 reason: $(echo "$r1" | sed -n 's/.*reason=//p' | cut -c1-120)"
        echo "    t2 reason: $(echo "$r2" | sed -n 's/.*reason=//p' | cut -c1-120)"
        for h in "$N1" "$N2"; do
            nm=$([ "$h" = "$N1" ] && echo node1 || echo node2)
            hit=$(sshc 15 "$h" "dmesg | grep -E 'P53-IUNLINK-MISMATCH|Shutting down|iunlink_item_precommit|TDS-LEFTOVER' | tail -4")
            [ -n "$hit" ] && { echo "    $nm dmesg:"; echo "$hit" | sed 's/^/      /'; }
        done
    fi
    rm -rf "$tmpd"
done
echo "===== TDS-REPEAT: $pass/$ran passed (warm-FS, ${ROUNDS}r) ====="
