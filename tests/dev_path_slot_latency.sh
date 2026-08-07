#!/bin/bash
# dev_path_slot_latency.sh [iters] [node]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# crash_consistency scales cleanly 2x per node-count doubling -- 1n=2s, 2n=5s,
# 4n=8s, 8n=16s, 16n=32s -- so 32n should land near 64s against a 90s budget.
# Recorded results at 32 nodes, SAME DLM protocol and SAME workload, differing
# only in which block device the shared LUN is reached through:
#
#     /dev/sda                 (direct iSCSI, single path)  CAW  PASS  66s
#     /dev/disk/by-path/...    (direct iSCSI, single path)  CAW  PASS  65s
#     /dev/mapper/mpatha       (dm-multipath over sda+sdb)  CAW  FAIL >90s
#     /dev/sda                 (direct)                     TCP  PASS  37s
#
# cawp vs caw is the same CAW protocol with only mpatha-vs-sda changed, so the
# 66s -> >90s step is attributable to the device path, not the lock protocol.
# That reframes D-CRASH-CONSISTENCY-32-BUDGET: it is not (only) a DLM scaling
# defect, it is dm-multipath in the CAW/FUA command path.
#
# Corroboration already in the tree: tools/caw_verify carries the flag
#     --retry-ua: retry on UNIT ATTENTION (needed on dm-multipath)
# i.e. MXFS already knows multipath makes CAW return UNIT ATTENTION, and every UA
# costs a full extra SCSI round trip on the DLM hot path.
#
# This measures the READ(16)+FUA slot-poll latency -- the exact command
# read_slot() issues, and 14.2% of the sampled stall time -- through each device
# path to the SAME LUN.  READS ONLY: the CAW write path would have to target a
# real slot sector on a live filesystem, and corrupting the LUN to measure it is
# not a trade worth making.  If reads alone are materially slower through
# mpatha, that is sufficient to account for the budget overrun, because the
# acquire loop polls with these reads.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
ITERS="${1:-200}"
NODE="${2:-test1}"

# LBA 131087 is the slot LBA the dlm_lock_correctness criterion already reads
# (see its "fua=ok caw=ok lba=131087" measured line), so it is a known-valid,
# read-safe slot sector rather than a guess into live filesystem data.
LBA="${LBA:-131087}"

echo "=== slot-poll READ(16)+FUA latency by device path (node=$NODE lba=$LBA iters=$ITERS) ==="
"$SSH" "$NODE" "
set -u
for dev in /dev/mapper/mpatha /dev/sda /dev/sdb; do
    [ -e \"\$dev\" ] || { echo \"\$dev MISSING\"; continue; }
    # warm one command so first-command setup is not charged to the sample
    /src/mxfs/tools/caw_verify --retry-ua read \"\$dev\" $LBA >/dev/null 2>&1
    ua=0; fail=0
    t0=\$(date +%s%N)
    for i in \$(seq 1 $ITERS); do
        out=\$(/src/mxfs/tools/caw_verify read \"\$dev\" $LBA 2>&1) || fail=\$((fail+1))
        case \"\$out\" in
            *UNIT*ATTENTION*|*'Unit Attention'*|*unit_attention*) ua=\$((ua+1)) ;;
        esac
    done
    t1=\$(date +%s%N)
    tot=\$(( (t1 - t0) / 1000000 ))
    printf '%-22s %5d reads  total=%6dms  per_read=%7.3fms  ua=%-4d fail=%d\n' \
        \"\$dev\" $ITERS \"\$tot\" \"\$(echo \"\$tot $ITERS\" | awk '{printf \"%.3f\", \$1/\$2}')\" \"\$ua\" \"\$fail\"
done
echo '--- multipath topology ---'
multipath -ll 2>/dev/null | sed 's/^/  /' | head -10
" 2>/dev/null | grep -vE "^Warning|^Unauthorized|^If you|^$"
