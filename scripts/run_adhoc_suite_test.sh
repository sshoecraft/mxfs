#!/bin/bash
# run_adhoc_suite_test.sh — launch a tests/suite/ script on the CURRENTLY
# PREPPED cluster with the same env contract run.sh uses, WITHOUT touching
# criteria.json/manifest.  For RULE-4 diagnostic tests that must not become
# matrix rows (adding a manifest row retroactively un-greens every completed
# board by growing its row count).
#
# Usage: scripts/run_adhoc_suite_test.sh <N> <dlm> <testname> [timeout_s]
#   Env passthrough: MXFS_TEST_ENV="K=V K2=V2" like run.sh.
# Requires: cluster already prepped for N/dlm (marker not checked — caller's
# responsibility); test script at tests/suite/<testname>.sh (NFS-visible).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile 2>/dev/null || echo /tmp/.mxfs_pass)}"
N="${1:?usage: run_adhoc_suite_test.sh <N> <dlm> <test> [timeout_s]}"
DLM="${2:?}"
NAME="${3:?}"
TT="${4:-300}"
BROKER="${MXFS_COORD_BROKER:-192.168.1.149}"
RUN_ID="adhoc$(date -u +%H%M%S)"
PREFIX="mxfs/coord/${RUN_ID}/${NAME}"
CT="${COORD_TIMEOUT:-120}"
MNT="${MXFS_MNT:-/mnt/shared}"
DEV="${MXFS_DEV:-/dev/sda}"
SCRIPT="/src/mxfs/tests/suite/${NAME}.sh"
[ -f "$REPO/tests/suite/${NAME}.sh" ] || { echo "no such test: $NAME"; exit 2; }

# Rank->host map: default test1..testN, or MXFS_NODE_LIST (comma/space list of
# hostnames/IPs) for external rigs (Proxmox pve1/pve2, bare metal), matching
# run.sh's node-list mechanism.
if [ -n "${MXFS_NODE_LIST:-}" ]; then
    IFS=', ' read -r -a NODES <<< "$MXFS_NODE_LIST"
else
    mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
fi

tmpd=$(mktemp -d /tmp/adhoc_${NAME}_XXXX)
echo "=== adhoc $NAME @ ${N}/${DLM} (run_id=$RUN_ID, logs $tmpd, nodes=${NODES[*]}) ==="
pids=()
for i in $(seq 1 "$N"); do
    ( timeout "$TT" "$SSH" "${NODES[$((i-1))]}" "$PASS" \
        "MXFS_NODES=$N MXFS_RANK=$i MXFS_DLM=$DLM MXFS_DEV='$DEV' \
         MXFS_EXPECT_FSTYPE=mxfs MXFS_FS_LABEL=$DLM \
         MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PREFIX COORD_TIMEOUT=$CT \
         ${MXFS_TEST_ENV:-} \
         bash $SCRIPT '$MNT'" 2>&1 \
        | grep -vE '^Warning:|^Unauthorized|^If you' > "$tmpd/test$i" ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || true; done

npass=0
for i in $(seq 1 "$N"); do
    line=$(grep -E '^RESULT:' "$tmpd/test$i" | tail -1)
    if [ -z "$line" ]; then
        echo "  test$i: NO_TERMINAL_RECORD (tail: $(tail -1 "$tmpd/test$i" 2>/dev/null | cut -c1-140))"
    else
        st=$(awk '{print $2}' <<<"$line")
        [ "$st" = PASS ] && npass=$((npass+1)) || echo "  test$i: $line" | cut -c1-400
    fi
done
echo "=== $NAME: ${npass}/${N} PASS ==="
[ "$npass" = "$N" ]
