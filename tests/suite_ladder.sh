#!/bin/bash
# suite_ladder.sh — run K consecutive full-suite iterations (tests/suite_iter.sh)
# for one configuration, logging each verdict.  sess12(a9a03929): the
# 4/net/mesh/direct 100% bar needs a consecutive-PASS streak; drive it unattended.
#
# Usage: tests/suite_ladder.sh <iters> [configuration, default 4/net/mesh/direct]
set -u
K="${1:?usage: suite_ladder.sh <iters> [configuration]}"
CONFIG=$(python3 "$(dirname "$0")/../tools/configuration.py" parse "${2:-4/net/mesh/direct}") || exit 2; N=${CONFIG%%/*}; DLM=${CONFIG#*/}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$REPO"
LOG="/tmp/suite_ladder_$(date -u +%Y%m%dT%H%M%SZ).log"
echo "ladder: $K iters of $N/$DLM, build $(modinfo mxfs.ko | awk '/srcversion/{print $2}')" | tee -a "$LOG"
for k in $(seq 1 "$K"); do
    echo "=== ladder iter $k/$K start $(date -u +%H:%M:%SZ) ===" | tee -a "$LOG"
    bash tests/suite_iter.sh "$CONFIG" > "/tmp/suite_iter_out_$k.log" 2>&1
    P=$(grep -cE "^  PASS" "/tmp/suite_iter_out_$k.log")
    F=$(grep -E "^  FAIL" "/tmp/suite_iter_out_$k.log" | tr '\n' ';')
    echo "iter $k: PASS=$P FAIL=[${F:-none}]" | tee -a "$LOG"
done
echo "=== ladder done $(date -u +%H:%M:%SZ) ===" | tee -a "$LOG"
