#!/bin/bash
# One-shot sess34 reproduction: full reset → prep → mkfs → mount → run test.
# Usage: sess34_repro.sh <n>   — defaults to N=2 if omitted.
#
# This is the canonical sess34 repro recipe.  Per RULE 3 it lives in source tree
# so future sessions don't have to retype the 30-line bash incantation each iter.

N="${1:-2}"
SCRIPTS=/src/mxfs/scripts

set -e
"$SCRIPTS/cluster_reset_n.sh" "$N"
"$SCRIPTS/cluster_mkfs_mount.sh" "$N"
"$SCRIPTS/run_concurrent_mkdir.sh" "$N"
