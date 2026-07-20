#!/bin/bash
# run_tooling.sh — run the Category-2 tooling/device/infra checks (separate from
# the FS suite). Same generalized runner, pointed at the tooling manifest,
# tooling script dir, and tooling results file.
#
# Usage:  tests/tooling/run_tooling.sh <N> [node1 node2 ...]
# View:   ./showstat.sh tooling
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
exec env MXFS_MANIFEST="$REPO/tests/tooling/manifest" \
         MXFS_SUITE_DIR="tests/tooling" \
         MXFS_RESULTS="$REPO/.tooling_results.json" \
         "$REPO/tests/suite/run_suite.sh" "$@"
