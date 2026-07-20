#!/bin/bash
# bartest.sh — exercise N distinct-tag coord barriers back-to-back to find the
# barrier-rendezvous flakiness seen in cache_coherency (cwr_verify hang).
source /src/mxfs/tests/suite/coord.sh
for tag in cv_write cv_verify cwr_write cwr_verify rv_create rv_rename rv_verify uv; do
    t0=$SECONDS
    if coord_barrier "$tag"; then
        echo "RANK${MXFS_RANK} $tag OK ($((SECONDS-t0))s)"
    else
        echo "RANK${MXFS_RANK} $tag FAIL ($((SECONDS-t0))s)"
    fi
done
