#!/bin/bash
# cc_dirvis_probe.sh — decisive reproducer + CASE-A/CASE-B discriminator for the
# crash_consistency shared-dir entry-visibility lag (the 2/tcp blocker).
#
# Both nodes concurrently create $NF files into ONE shared dir, test2 syncs,
# test1 drops caches and READDIR-counts.  If test1 is short:
#   PROBE-1: test1 forces a dir-DLM EX acquire (touch a probe file in the dir)
#            then re-counts.  Restored  => CASE A (stale read on test1; LUN had
#            the entries; fix = read-side coherency).  Still short => CASE B
#            (entries not durable on LUN; fix = writer durability).
#   PROBE-2: after the probe, test2 re-counts its OWN files (sanity: it always
#            sees them).
# Loops until a short count is seen or $ITERS exhausted.  RULE 3: lives in-tree.
#
# Usage: cc_dirvis_probe.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-40}"; NF="${2:-50}"
r() { local n="$1"; shift; timeout 30 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.ccp_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    # concurrent create from BOTH nodes into the shared dir
    r test1 "for i in \$(seq 1 $NF); do echo n1f\$i > $D/node1_f\$i; done; sync" >/dev/null &
    r test2 "for i in \$(seq 1 $NF); do echo n2f\$i > $D/node2_f\$i; done; sync" >/dev/null &
    wait
    # test2 final sync to push its dir mods to the LUN
    r test2 "sync" >/dev/null
    # test1 cold readdir
    cnt=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f* 2>/dev/null | wc -l")
    cnt=$(echo "$cnt" | tr -dc '0-9')
    exp=$((2*NF))
    echo "iter $it: test1 cold readdir count=$cnt expected=$exp"
    if [ "${cnt:-0}" -lt "$exp" ]; then
        echo "  >>> SHORT on test1. Discriminating CASE A vs B..."
        # which entries missing
        miss=$(r test1 "for i in \$(seq 1 $NF); do [ -e $D/node2_f\$i ] || echo node2_f\$i; [ -e $D/node1_f\$i ] || echo node1_f\$i; done | tr '\n' ' '")
        echo "      missing-on-test1: $miss"
        # PROBE-1: force test1 dir-EX acquire (create in the dir) then re-count
        r test1 "echo probe > $D/probe_test1; sync" >/dev/null
        cnt2=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f* 2>/dev/null | wc -l")
        cnt2=$(echo "$cnt2" | tr -dc '0-9')
        echo "      PROBE-1 after test1 dir-EX acquire: count=$cnt2 (expected $exp)"
        if [ "${cnt2:-0}" -ge "$exp" ]; then
            echo "      => CASE A (stale read on test1; LUN had entries; dir-EX acquire fixed it). FIX=read coherency."
        else
            echo "      => CASE B (still short after acquire; entries NOT durable on LUN). FIX=writer durability."
        fi
        # test2 sanity
        cnt3=$(r test2 "ls $D/node2_f* 2>/dev/null | wc -l")
        echo "      test2 sees own files: $(echo "$cnt3"|tr -dc '0-9')/$NF"
        # dmesg dir-coherency traces both nodes
        for n in test1 test2; do
            echo "      --- $n dmesg (dir traces) ---"
            r "$n" "dmesg | grep -iE 'P9-SFREFRESH|P-SFDIR|P62-RELOAD|dir_gen|P-DIRFASTEX|P34D' | tail -6" | sed 's/^/        /'
        done
        echo "=== stopping at first short count for analysis ==="
        exit 0
    fi
done
echo "=== no short count in $ITERS iters ==="
