#!/bin/bash
# fio_verify — data-integrity round-trips via fio with crc32c verification.
# Agnostic: takes only the mount point ($1). No coordination.
#
# fio writes each block with a crc32c header, then re-reads and verifies. A
# torn/lost/misdirected write surfaces as a verify miscompare (nonzero exit).

SUITE_TEST_NAME=fio_verify
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

command -v fio >/dev/null 2>&1 || {
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=fio not installed"; exit 1; }

W="$MNT/.suite_fio_verify.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || {
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=cannot mkdir $W"; exit 1; }
trap 'rm -rf "$W" 2>/dev/null' EXIT

# run_fio <name> <rw> <bs>  — write w/ crc32c then verify; pass iff rc==0
run_fio() {
    fio --name="$1" --directory="$W" --rw="$2" --bs="$3" --size=64m \
        --ioengine=libaio --direct=1 --iodepth=16 \
        --verify=crc32c --verify_fatal=1 --do_verify=1 \
        --output-format=terse --minimal >/dev/null 2>&1
}

ck "randwrite+crc verify"  run_fio rwv  randwrite 4k
ck "seqwrite+crc verify"   run_fio swv  write     1m
ck "randrw+crc verify"     run_fio rrv  randrw    8k

finish
