#!/bin/bash
# tests/host_tmp_clean.sh — reclaim host /tmp from run.sh artifact leakage.
#
# run.sh materializes a /tmp/run_<criterion>_<UTCstamp> directory per criterion
# invocation (~5GB each: per-node logs + payload copies) and never prunes them.
# A few boards' worth fills the 1.8T root fs (observed 100% full, session 23:
# ~60 dirs from 2+ days of runs; host tooling then fails ENOSPC).  /tmp is
# wiped on reboot by design (RULE 3), so nothing here is durable evidence —
# ledger evidence lives in tests/logs/.
#
# Deletes:
#   - /tmp/run_*        older than KEEP_HOURS (default 6)
#   - /tmp/tmp.*        mktemp litter older than KEEP_HOURS
# Prints freed space.  Safe to run any time; current runs are younger than
# the cutoff and untouched.
#
# usage: host_tmp_clean.sh [KEEP_HOURS]
set -u
KEEP_HOURS="${1:-6}"
MMIN=$((KEEP_HOURS * 60))

before=$(df -m / | awk 'NR==2{print $4}')
find /tmp -maxdepth 1 \( -name 'run_*' -o -name 'tmp.*' \) \
     -mmin "+${MMIN}" -exec rm -rf {} + 2>/dev/null
after=$(df -m / | awk 'NR==2{print $4}')
echo "host_tmp_clean: freed $((after - before)) MiB (root avail now ${after} MiB, cutoff ${KEEP_HOURS}h)"
