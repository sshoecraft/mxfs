#!/bin/bash
# sess12 (ccloop 4eef1f39): RULE-4 experiment — does forcing AG-meta reads FUA
# eliminate the concurrent-create AG free-space double-allocation corruption?
# Proven root (build C69013B3): bnobt/cntbt lost-update in agno=2 with
# fua_fresh=0 buf_gen=0 -> allocator reads stale cached free-space btree after
# acquiring AG-DLM -> overlapping block alloc -> on-disk cntbt CRC corruption ->
# AGF corruption -> shutdown.  If fua_always=1 stops it, the stale-cached AG-meta
# read is the confirmed root.  Same workload as repro_double_alloc.sh.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

NODES_LIST=(test1 test2 test3 test4)
N=${#NODES_LIST[@]}
M="$MXFS_MOUNT"
ITERS="${1:-25}"
FUA="${2:-1}"   # 0 = baseline, 1 = fua_always

echo "=== teardown + fresh mkfs/mount (instr=0, fua_always=$FUA) ==="
teardown_all "${NODES_LIST[*]}"
INSMOD_OPTS="instr=0" fresh_cluster_mount "${NODES_LIST[0]}" "${NODES_LIST[@]:1}" \
    || { echo MOUNT_FAIL; exit 1; }

echo "=== setting fua_always=$FUA on all nodes via sysfs ==="
for n in "${NODES_LIST[@]}"; do
    ssh_node_quiet "$n" "echo $FUA > /sys/module/mxfs/parameters/fua_always; cat /sys/module/mxfs/parameters/fua_always"
    ssh_node_quiet "$n" "dmesg -C"
done

fails=0
for it in $(seq 1 "$ITERS"); do
    CV="$M/.mxfs_test/cvrepro_$it"
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        ssh_node "$n" "mkdir -p $CV 2>/dev/null; echo 'hello from node $i' > $CV/node$i.txt; sync" >/dev/null &
    done
    wait
    sleep 1

    anymiss=0
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        miss=$(ssh_node "$n" "for j in \$(seq 1 $N); do [ -f $CV/node\$j.txt ] || echo -n \"n\$j \"; done" 2>/dev/null | tr -d '[:space:]')
        [ -n "$miss" ] && { anymiss=1; echo "iter $it: node$i MISSING [$miss]"; }
    done
    corrupt=0
    for n in "${NODES_LIST[@]}"; do
        c=$(ssh_node_quiet "$n" "dmesg | grep -aciE 'EFSCORRUPTED|metadata I/O error|badmagic|Corruption|error 117|error 74|Shutting down'" 2>/dev/null | tr -dc '0-9')
        [ -n "$c" ] && [ "$c" != "0" ] && { corrupt=1; echo "iter $it: node($n) CORRUPTION count=$c"; }
    done
    if [ "$anymiss" = "0" ] && [ "$corrupt" = "0" ]; then
        echo "iter $it: clean"
    else
        fails=$((fails+1))
        echo "=== iter $it: ISSUE (miss=$anymiss corrupt=$corrupt) ==="
        for n in "${NODES_LIST[@]}"; do
            ssh_node_quiet "$n" "dmesg | grep -aiE 'EFSCORRUPTED|error 74|error 117|agf_verify|allocbt|bnobt-WRITE|Shutting down' | tail -3" 2>/dev/null | sed "s/^/[$n] /"
        done
        break
    fi
done
echo "=== DONE fua_always=$FUA: $fails failing iter(s) of up to $ITERS ==="
