#!/bin/bash
# Build and run the include/mxfs/mxfs_dirshard.h format self-test (user mode,
# no kernel): exercises the pure manifest/block check + cookie helpers.
# sess464 D-32NODE-SHARED-DIR-CREATE-PACE stage 1.
set -e
R=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=$(mktemp -d)
gcc -Wall -Wextra -Werror -I "$R/include" -o "$OUT/dirshard_format_selftest" "$R/tests/selftest/dirshard_format_selftest.c"
"$OUT/dirshard_format_selftest"
