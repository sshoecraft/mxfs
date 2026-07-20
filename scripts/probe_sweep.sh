#!/bin/bash
# probe_sweep.sh — post-run cluster-wide sweep of the 0.10.65+ xfs_buf
# integrity probes and fatal kernel signatures.  Run after every criteria
# run (RULE 4 evidence step): a PASS with any probe hit is NOT clean —
# the probe stack names the residual poisoner.
#
# Usage: scripts/probe_sweep.sh <N>
#   Sweeps test1..testN dmesg rings for:
#     P-SEMA-OVERUP / P-SEMA-DUALLOCK  (b_sema poisoning — 0.10.66 root class)
#     P-WRCNT-RESUBMIT                 (double buffer submit)
#     P-BLI-DOUBLEDONE                 (double xfs_buf_item_done claim)
#     SYSCALL_HANG                     (drc hang detector)
#     'Shutting down filesystem' / 'Internal error' / BUG: / Oops
#   Prints per-node counts and a cluster total; exit 0 iff all zero.
#
# Note: dmesg ring only (journalctl rate-limits/rotates — sess3 46efd8b6).
# Ring survives everything except a node reboot; sweep BEFORE recycling VMs.

set -u
N="${1:?usage: probe_sweep.sh <N>}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"

PAT='P-SEMA-OVERUP|P-SEMA-DUALLOCK|P-WRCNT-RESUBMIT|P-BLI-DOUBLEDONE|P-NOINO-RELFENCE-WEDGE|P-NOINO-DRAIN-STUCK|SYSCALL_HANG|Shutting down filesystem|Internal error|BUG:|Oops'

td=$(mktemp -d)
for i in $(seq 1 "$N"); do
    ( timeout 25 "$SSH" "test$i" "$PASS" \
        "dmesg 2>/dev/null | grep -cE '$PAT'; echo ---; dmesg 2>/dev/null | grep -E '$PAT' | head -5" \
        2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you' > "$td/test$i" ) &
done
wait

total=0 unreachable=""
for i in $(seq 1 "$N"); do
    f="$td/test$i"
    cnt=$(head -1 "$f" 2>/dev/null | tr -d '\r\n ')
    if ! [[ "$cnt" =~ ^[0-9]+$ ]]; then
        unreachable="$unreachable test$i"
        continue
    fi
    total=$(( total + cnt ))
    if [ "$cnt" -gt 0 ]; then
        echo "test$i: $cnt hit(s)"
        sed -n '3,7p' "$f" | sed 's/^/    /'
    fi
done
rm -rf "$td"

[ -n "$unreachable" ] && echo "UNREACHABLE (no count):$unreachable"
echo "probe_sweep: nodes=1..$N total_hits=$total"
if [ "$total" -eq 0 ] && [ -z "$unreachable" ]; then
    echo "probe_sweep: CLEAN"
    exit 0
fi
exit 1
