#!/bin/bash
#
# full_verify.sh — everything a version must pass before it can be published
#
# Usage: tests/full_verify.sh VERSION [STALL_LAPS]
#
# In order, each step logged into tests/evidence/full_verify_<VERSION>.log with
# its own "=== rc=N: <step> ===" line:
#   1. a build from a clean copy of the tree (no objects), warnings counted;
#      the userspace tools, the user-mode tests (tests/tauth) and the extern
#      declaration audit
#   2. the 2-node TCP suite on the rig (./run.sh 2 tcp)
#   3. the release packages (scripts/release.sh), unless dist/VERSION holds them
#   4. every platform's packaged round: ubuntu2404, pve9 on both claimed
#      kernels, rhel9, debian13
#   5. on the rhel9 pair: the hung-node test and the SELinux sVirt test, then
#      STALL_LAPS laps of tests/svirt_stall_laps.sh (default 0)
#   6. the debian13 hung-node test
#
# Stops only when the build or the packages fail: every later step needs them.
# A failing test step is logged and the rest still run, so one run shows every
# failure.  Each harness enforces its own budget; nothing here widens one.
#
# Before any step that formats the shared LUN, every MXFS mount on the platform
# pairs is taken down: a pair left mounted by the step before makes the next
# prep refuse mkfs.
#
set -u

V="${1:?usage: full_verify.sh VERSION [STALL_LAPS]}"
LAPS="${2:-0}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
L="$HERE/tests/evidence/full_verify_$V.log"
: > "$L"
SSH="$HERE/tools/mxfs_sshpass.sh"

run() {
    echo "=== $* ===" >> "$L"
    "$@" >> "$L" 2>&1
    local rc=$?
    echo "=== rc=$rc: $* ===" >> "$L"
    echo "rc=$rc  $*"
    return $rc
}

unmount_pairs() {
    local h
    for h in alma9-1 alma9-2 debian13-1 debian13-2 pve9-1 pve9-2; do
        (timeout 75 "$SSH" "$(tools/mxfs_lab.sh addr $h 2>/dev/null || echo $h)" \
            'for m in $(grep " mxfs " /proc/mounts | cut -d" " -f2); do timeout 60 umount $m; done; echo left=$(grep -c " mxfs " /proc/mounts)' \
            </dev/null 2>/dev/null | grep left= | sed "s/^/$h /") &
    done
    wait
}

# --- 1. clean build, tools, user-mode tests, audit
B=$(mktemp -d) || exit 1
timeout 300 rsync -a --exclude .git --exclude dist --exclude tests/evidence \
    --exclude '*.o' --exclude '*.ko' --exclude '.*.cmd' ./ "$B/"
( cd "$B" && timeout 540 make modules -j"$(nproc)" > "$B/build.log" 2>&1 )
brc=$?
echo "clean_build_rc=$brc version=$(modinfo -F version "$B/mxfs.ko" 2>/dev/null) srcversion=$(modinfo -F srcversion "$B/mxfs.ko" 2>/dev/null) warnings=$(grep 'warning:' "$B/build.log" | grep -vc 'compiler differs\|Clock skew')" | tee -a "$L"
grep -E 'warning:|error:' "$B/build.log" | grep -v 'compiler differs\|Clock skew' | head -20 | tee -a "$L"
[ $brc = 0 ] || { echo "clean build failed; stopping" | tee -a "$L"; exit 1; }
( cd "$B" && timeout 120 make -C tools > "$B/tools.log" 2>&1; echo "tools_rc=$? tool_warn=$(grep -ci warning "$B/tools.log")"
  timeout 240 make -C tests/tauth clean test > "$B/tauth.log" 2>&1; echo "tauth_rc=$? $(grep -aoE '=== tauth_test: fails=[0-9]+' "$B/tauth.log")" ) | tee -a "$L"
timeout 120 python3 scripts/extern_decl_audit.py >> "$L" 2>&1; echo "extern_audit_rc=$?" | tee -a "$L"

# --- 2. the 2-node TCP suite on the rig
unmount_pairs | tee -a "$L"
run ./run.sh 2 tcp
echo "suite_pass=$(grep -cE '^\s+PASS' "$L") suite_fail=$(grep -cE '^\s+(FAIL|TIMEOUT)' "$L")" | tee -a "$L"

# --- 3. packages
if [ ! -d "dist/$V" ]; then
    run scripts/release.sh || { echo "release.sh failed; stopping" | tee -a "$L"; exit 1; }
fi

# --- 4-6. platform rounds and the pair tests
unmount_pairs | tee -a "$L"
run tests/packaged_round.sh ubuntu2404 "$V"
unmount_pairs | tee -a "$L"
KERNEL=6.17.2-1-pve run tests/packaged_round.sh pve9 "$V"
unmount_pairs | tee -a "$L"
KERNEL=7.0.14-19-pve run tests/packaged_round.sh pve9 "$V"
unmount_pairs | tee -a "$L"
run tests/packaged_round.sh rhel9 "$V"
PREP=rhel9 run tests/tcp_peer_freeze_death.sh
run tests/selinux_svirt_mxfs.sh "$(tools/mxfs_lab.sh addr alma9-1)"
unmount_pairs | tee -a "$L"
[ "$LAPS" -gt 0 ] && run tests/svirt_stall_laps.sh "$V" "$LAPS"
unmount_pairs | tee -a "$L"
run tests/packaged_round.sh debian13 "$V"
PREP=debian13 run tests/tcp_peer_freeze_death.sh
unmount_pairs | tee -a "$L"

grep -E "=== rc=|RESULT|VERDICT|both nodes on kernel|suite_pass|clean_build_rc|tools_rc|tauth_rc|extern_audit_rc|all .* laps passed|STALL|STOP" "$L" | cut -c1-200
