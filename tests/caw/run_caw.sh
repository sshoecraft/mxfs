#!/bin/bash
# run_caw.sh — run the Category-3-CAW tests.
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
exec env MXFS_MANIFEST="$REPO/tests/caw/manifest" MXFS_SUITE_DIR="tests/caw" \
         MXFS_RESULTS="$REPO/.caw_results.json" \
         "$REPO/tests/suite/run_suite.sh" "$@"
