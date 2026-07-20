#!/bin/bash
# run_tcp.sh — run the Category-4-TCP tests.
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
exec env MXFS_MANIFEST="$REPO/tests/tcp/manifest" MXFS_SUITE_DIR="tests/tcp" \
         MXFS_RESULTS="$REPO/.tcp_results.json" \
         "$REPO/tests/suite/run_suite.sh" "$@"
