#!/bin/bash
# fleet_set_params.sh — set runtime mxfs module params on every node of the
# rig, in the given order, and read each one back (per-node rc + output).
#
# Usage: tests/fleet_set_params.sh "<name=val> [<name=val> ...]" [nodes=32] [outfile]
#
# Example (the enforcement-armed board, sess404):
#   tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 \
#       tests/evidence/<dir>/knobs.txt
#
# Order matters: foreign_replay_token_enforce's setter fails closed (EINVAL)
# unless its F2 prerequisite target_cache_protected=1 (or fua_disable=0) is
# already in place, so list the prerequisite first.  A refused setter shows as
# SETFAIL=<name> for that node and the script exits 2.
#
# budget: each ssh is bounded (40 s); the whole fleet runs in parallel.
# the unkillable-wedge rule: no pgrep -f / ps; per-node rc files; nothing unbounded.
# the source-tree rule: lives in tests/.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
PARAMS=${1:?"name=val ..."}; NODES=${2:-32}; OUTF=${3:-}
SSH=tools/mxfs_sshpass.sh
CMD=""
for kv in $PARAMS; do
    k=${kv%%=*}; v=${kv#*=}
    CMD="$CMD echo $v > /sys/module/mxfs/parameters/$k 2>/dev/null || echo SETFAIL=$k; echo $k=\$(cat /sys/module/mxfs/parameters/$k 2>/dev/null);"
done
D=$(mktemp -d)
for i in $(seq 1 "$NODES"); do
    ( timeout 40 $SSH test$i "$CMD echo ver=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) m=\$(grep -c ' mxfs ' /proc/mounts)" >"$D/t$i" 2>/dev/null; echo $? >"$D/rc$i" ) &
done
wait
for i in $(seq 1 "$NODES"); do
    echo "test$i rc=$(cat "$D/rc$i") $(grep -av '^Unauthorized\|^Warning:\|^If you' "$D/t$i" | tr '\n' ' ')"
done > "$D/knobs.txt"
[ -n "$OUTF" ] && cp "$D/knobs.txt" "$OUTF"
cat "$D/knobs.txt"
echo "params: $(grep -oE '(SETFAIL=[a-z_]+|[a-z_]+=[0-9]+)' "$D/knobs.txt" | grep -vE '^(ver|m)=' | sort | uniq -c | tr '\n' ' ')"
echo "mounted: $(grep -c 'm=1' "$D/knobs.txt")/$NODES  rc0: $(grep -c ' rc=0 ' "$D/knobs.txt")/$NODES"
if grep -q SETFAIL "$D/knobs.txt"; then echo "FAIL: setter refused on some node(s)"; exit 2; fi
exit 0
