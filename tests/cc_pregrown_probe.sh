#!/bin/bash
# cc_pregrown_probe.sh — DECISIVE discriminator for the 2/tcp durable dirent
# lost-update: is it the shortform->block FORMAT TRANSITION window, or a
# steady-state block-format bug?
#
# Each iter: test1 PRE-GROWS a fresh dir to BLOCK format single-node (NF_PRE
# files, sync) so the dir is already block-format + durable BEFORE any
# concurrent access.  THEN both nodes concurrently create NF files each into it.
# Finally drop caches + recount on test1.
#
#   If pre-grown dirs DON'T lose entries (clean over many iters) => the loss is
#   the sf->block TRANSITION (a node RMWs a stale shortform base over a peer's
#   block conversion).  Fix = acquire-side format reconcile.
#   If pre-grown dirs STILL lose => steady-state block-format concurrent-create
#   bug (independent of the transition).
#
# Usage: cc_pregrown_probe.sh [iters] [nfiles] [nf_pre]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-15}"; NF="${2:-50}"; NF_PRE="${3:-40}"
r(){ local n="$1"; shift; timeout 60 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mk='D="$1";R="$2";A="$3";B="$4";for i in $(seq $A $B);do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null;done;sync'

losses=0
for it in $(seq 1 "$ITERS"); do
    D="$MNT/.ccp_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    # PRE-GROW to block format, single node, durable.
    r test1 "bash -c '$mk' x $D 1 1 $NF_PRE" >/dev/null
    fmt=$(r test1 "stat -c%s $D" | tr -dc '0-9')   # dir i_size; >sf inline => block
    # CONCURRENT phase: both nodes add a disjoint range (test1 continues, test2 fresh).
    r test1 "bash -c '$mk' x $D 1 $((NF_PRE+1)) $((NF_PRE+NF))" >/dev/null &
    r test2 "bash -c '$mk' x $D 2 1 $NF" >/dev/null &
    wait
    r test2 "sync" >/dev/null
    exp=$(( (NF_PRE+NF) + NF ))   # test1: NF_PRE+NF ; test2: NF
    cnt=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f* 2>/dev/null | wc -l" | tr -dc '0-9')
    short=""
    if [ "${cnt:-0}" -lt "$exp" ]; then
        # re-read from LUN to confirm durable (not just cache)
        cnt2=$(r test1 "echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f* 2>/dev/null | wc -l" | tr -dc '0-9')
        short=" >>> SHORT durable=$cnt2/$exp"
        losses=$((losses+1))
    fi
    echo "iter $it: dirsize=$fmt all=${cnt:-?}/$exp${short}"
done
echo "=== pregrown: $losses/$ITERS iters lost entries ==="
