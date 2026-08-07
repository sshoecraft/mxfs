#!/bin/bash
#
# authority_stats_sweep.sh [N] — sweep the per-node inode_authority debugfs
# stats and the authority warn probes (P246/P247/P248 AUTH family) from dmesg
# across the first N test nodes (default 32), and print a cluster-wide sum of
# the relinquish counters.  Nodes are queried in parallel (~10s for 32).
#
# Usage: tests/authority_stats_sweep.sh [N]
#
# The counters are module-global (static atomic64_t in xfs_mxfs_dlm.c), so a
# node that reloaded mxfs.ko (fault tests reboot nodes) restarts from zero —
# the sweep prints per-node srcversion so a reset is visible instead of
# silently deflating the sum.
#
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"
OUTDIR=$(mktemp -d)

for i in $(seq 1 "$N"); do
    (
        $SSH "test$i" '
            sv=$(cat /sys/module/mxfs/srcversion 2>/dev/null || echo NOMOD)
            f=$(ls /sys/kernel/debug/mxfs/*/inode_authority 2>/dev/null | head -1)
            if [ -n "$f" ]; then
                rel=$(sed -n "/^relinquish/,/^unpublished_noted/p" "$f" | awk "
                    /revoke/{r=\$2} /release_begin/{rb=\$2} /release_clean/{rc=\$2}
                    /phantom_loss/{ph=\$2} /backstop/{bs=\$2} /pub_live/{pl=\$2}
                    END{print r, rb, rc, ph, bs, pl}")
            else
                rel="- - - - - -"
            fi
            w=$(dmesg 2>/dev/null | grep -c "P246-AUTH-LATE-REVOKE")
            w2=$(dmesg 2>/dev/null | grep -c "P247-AUTH-PHANTOM-LOSS")
            w3=$(dmesg 2>/dev/null | grep -c "P248-RETAIN-CERT-ANOMALY")
            w4=$(dmesg 2>/dev/null | grep -c "P246-AUTH-PUB-LIVE")
            echo "$sv $rel $w/$w2/$w3 publive_warn=$w4"
        ' > "$OUTDIR/test$i" 2>/dev/null
    ) &
done
wait

declare -A SUM
FIELDS="revoke release_begin release_clean phantom_loss backstop pub_live"
for f in $FIELDS; do SUM[$f]=0; done

printf '%-8s %-24s %8s %8s %8s %8s %8s %8s  %s\n' \
    NODE SRCVER revoke rbegin rclean phantom backstop publive "WARNS(P246/P247/P248)"

for i in $(seq 1 "$N"); do
    host="test$i"
    out="$(cat "$OUTDIR/$host" 2>/dev/null)"
    if [ -z "$out" ]; then
        printf '%-8s %s\n' "$host" "UNREACHABLE"
        continue
    fi
    set -- $out
    sv="$1"; rv="$2"; rb="$3"; rc="$4"; ph="$5"; bs="$6"; pl="$7"; warns="$8"; plw="$9"
    printf '%-8s %-24s %8s %8s %8s %8s %8s %8s  %s %s\n' \
        "$host" "$sv" "$rv" "$rb" "$rc" "$ph" "$bs" "$pl" "$warns" "$plw"
    for f_v in "revoke=$rv" "release_begin=$rb" "release_clean=$rc" \
               "phantom_loss=$ph" "backstop=$bs" "pub_live=$pl"; do
        f="${f_v%%=*}"; v="${f_v##*=}"
        case "$v" in ''|*[!0-9]*) ;; *) SUM[$f]=$(( SUM[$f] + v )) ;; esac
    done
done

echo
echo "=== cluster sum (nodes reachable, counters are module-lifetime) ==="
for f in $FIELDS; do printf '  %-14s %s\n' "$f" "${SUM[$f]}"; done
