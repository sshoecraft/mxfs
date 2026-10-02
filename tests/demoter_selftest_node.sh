#!/bin/bash
# demoter_selftest_node.sh — run the in-kernel demoter claim-slot race test
# (mxfs.demoter_slot_selftest) on ONE idle rig node, with a module built from
# a scratch copy of the tree so a board running against the tree's mxfs.ko is
# not disturbed.  The test races detached inode objects and needs no mount.
#
# Usage: tests/demoter_selftest_node.sh <node> [ROUNDS]
#   SELFTEST_S (default 20)       seconds per arm
#   WINDOWS    (default "0 200")  demoter_test_window_us per arm
#   LEGACY     (default 0)        1 = also run every arm with demoter_legacy_clobber=1
#   KO         (default: build)   an mxfs.ko to load instead of building one
#
# Budget: build ~60-90 s (scratch rsync + make), load ~5 s, each arm
# SELFTEST_S + a few seconds of teardown.  Prints one line per arm and a
# final VERDICT; exits nonzero on any FAIL, refcount/WARN/BUG/Oops line, or
# a missing self-test line.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NODE="${1:?usage: demoter_selftest_node.sh <node> [rounds]}"
ROUNDS="${2:-1}"
SELFTEST_S="${SELFTEST_S:-20}"
WINDOWS="${WINDOWS:-0 200}"
LEGACY="${LEGACY:-0}"
SSH="$REPO/tools/mxfs_sshpass.sh"
fail=0

say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

if [ -z "${KO:-}" ]; then
    B=$(mktemp -d)
    rsync -a --exclude .git --exclude tests/evidence --exclude '.ccloop' "$REPO/" "$B/" 2>/dev/null
    rc=$?
    if [ $rc -ne 0 ] && [ $rc -ne 23 ]; then say "ABORT: rsync rc=$rc"; exit 3; fi
    if ! (cd "$B" && make modules >"$B/build.log" 2>&1); then
        say "ABORT: build failed, log $B/build.log"; exit 3
    fi
    KO="$B/mxfs.ko"
fi
SV=$(modinfo -F srcversion "$KO")
say "module $KO srcversion $SV"

scp_out=$(timeout 30 "$SSH" "$NODE" "true" 2>&1) || { say "ABORT: $NODE unreachable: $scp_out"; exit 3; }
# copy through the ssh chokepoint: base64 keeps it one command
timeout 60 "$SSH" "$NODE" "base64 -d > /root/mxfs.ko.selftest" < <(base64 -w0 "$KO") >/dev/null 2>&1 \
    || { say "ABORT: copy to $NODE failed"; exit 3; }
load=$(timeout 60 "$SSH" "$NODE" "
    for m in \$(awk '\$3==\"mxfs\"{print \$2}' /proc/mounts); do timeout 30 umount \$m || echo UMOUNT_FAIL \$m; done
    if [ -d /sys/module/mxfs ]; then timeout 30 rmmod mxfs || echo RMMOD_FAIL; fi
    timeout 30 insmod /root/mxfs.ko.selftest && cat /sys/module/mxfs/srcversion" 2>&1 | tr -d '\r' | tail -3)
case "$load" in *"$SV"*) say "$NODE loaded $SV" ;; *) say "ABORT: load on $NODE: $load"; exit 3 ;; esac

T0=$(timeout 10 "$SSH" "$NODE" "date '+%Y-%m-%d %H:%M:%S'" 2>/dev/null | tr -d '\r' | tail -1)
legs="0"; [ "$LEGACY" = 1 ] && legs="0 1"
for r in $(seq 1 "$ROUNDS"); do
  for lg in $legs; do
    for w in $WINDOWS; do
        out=$(timeout $((SELFTEST_S + 30)) "$SSH" "$NODE" "
            echo $lg > /sys/module/mxfs/parameters/demoter_legacy_clobber
            echo $w > /sys/module/mxfs/parameters/demoter_test_window_us
            echo $SELFTEST_S > /sys/module/mxfs/parameters/demoter_slot_selftest; echo rc=\$?
            echo 0 > /sys/module/mxfs/parameters/demoter_legacy_clobber
            echo 0 > /sys/module/mxfs/parameters/demoter_test_window_us
            dmesg | grep -o 'P-DEMOTER-SLOT-SELFTEST.*' | tail -1" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
        say "round=$r legacy=$lg window_us=$w: ${out:-NO OUTPUT}"
        case "$out" in *P-DEMOTER-SLOT-SELFTEST*) ;; *) fail=1 ;; esac
        # legacy mode steals live claims by design; its arm is graded on
        # kernel health alone
        if [ "$lg" = 0 ]; then case "$out" in *verdict=PASS*) ;; *) fail=1 ;; esac; fi
    done
  done
done
bad=$(timeout 20 "$SSH" "$NODE" "journalctl -k --no-pager --since '$T0' | grep -cE 'WARNING: CPU|BUG:|refcount_t|Oops|blocked for more than|use-after-free'" 2>/dev/null | tr -d '\r' | tail -1)
say "$NODE kernel bad-line count since $T0: ${bad:-unknown}"
[ "${bad:-x}" = 0 ] || fail=1
say "VERDICT $([ $fail = 0 ] && echo PASS || echo FAIL) node=$NODE srcversion=$SV"
exit $fail
