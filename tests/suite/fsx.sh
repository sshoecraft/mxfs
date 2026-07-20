#!/bin/bash
# fsx — file-system exerciser: long randomized read/write/mmap/truncate/
# fallocate sequences with after-every-op data verification. Catches data
# corruption and mmap-vs-read/write coherency bugs. Agnostic: $1 = mount point.
#
# Uses the vendored fsx binary on NFS (tools/fsx, built once on clyde from the
# vendored fsx.c — host and VMs are identical, so one binary serves all nodes).

SUITE_TEST_NAME=fsx
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
HERE="$(dirname "$(readlink -f "$0")")"
source "$HERE/lib.sh"
FSX="$HERE/tools/fsx"

[ -x "$FSX" ] || {
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=fsx binary missing at $FSX"; exit 1; }

W="$MNT/.suite_fsx.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || {
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=cannot mkdir $W"; exit 1; }
trap 'rm -rf "$W" /tmp/fsx.$$.* 2>/dev/null' EXIT

# run_fsx <ops> [extra args]  — fsx exits nonzero on any verify miscompare
run_fsx() { "$FSX" -N "$1" ${2:-} "$W/fsxfile_$1" >/tmp/fsx.$$.$1.log 2>&1; }

ck "fsx 100k mixed ops"          run_fsx 100000
ck "fsx 50k blocksize 8k -r4096" run_fsx 50000 "-r 4096 -w 4096"

finish
