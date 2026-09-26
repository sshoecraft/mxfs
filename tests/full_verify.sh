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
#   2. both released 2-node suites on the rig: ./run.sh 2 tcp, then
#      ./run.sh 2 cawd, alone on the host (they grade pace, and a loaded host
#      has failed them before)
#   3. the release packages (scripts/release.sh), unless dist/VERSION holds them
#   4. every platform's packaged round on EACH transport (TRANSPORT=tcp, caw):
#      ubuntu2404, pve9 on both claimed kernels, rhel9, debian13
#   5. every platform's hung-node test on each transport, and on the rhel9
#      pair the SELinux sVirt test, then STALL_LAPS laps of
#      tests/svirt_stall_laps.sh (default 0)
#
# Steps 4-5 run the four platforms in parallel, each platform's own steps in
# order: every pair verifies on a LUN of its own
# (scripts/scst_platform_targets.sh, lab file ~/.config/mxfslab/lab.<platform>),
# so no pair's format touches another's.  Each platform's steps also go to
# tests/evidence/full_verify_<VERSION>_<platform>.log and are copied into the
# main log when it finishes.
#
# Stops only when the build or the packages fail: every later step needs them.
# A failing test step is logged and the rest still run, so one run shows every
# failure.  Each harness enforces its own budget; nothing here widens one.
#
# Before each platform step the pair's MXFS mounts are taken down: a pair left
# mounted by the step before (the hung-node test ends remounted) makes the next
# round refuse mkfs.
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

unmount_pairs() {  # [node...] — default: every platform pair node
    local h
    for h in ${*:-alma9-1 alma9-2 debian13-1 debian13-2 pve9-1 pve9-2}; do
        (timeout 75 "$SSH" "$(tools/mxfs_lab.sh addr $h 2>/dev/null || echo $h)" \
            'for m in $(grep " mxfs " /proc/mounts | cut -d" " -f2); do timeout 60 umount $m; done; echo left=$(grep -c " mxfs " /proc/mounts)' \
            </dev/null 2>/dev/null | grep left= | sed "s/^/$h /") &
    done
    wait
}

# platform <key> <steps...>: one platform's steps in order against its own
# lab file, logged to its own file.  A step is "[VAR=value ...] command args".
platform() {
    local key=$1 lab="$HOME/.config/mxfslab/lab.$1" pl="$HERE/tests/evidence/full_verify_${V}_$1.log" pair step
    shift
    : > "$pl"
    [ -r "$lab" ] || { echo "=== rc=2: $key: no lab file $lab (scripts/scst_platform_targets.sh setup) ===" >> "$pl"; return; }
    pair=$(MXFS_LAB=$lab tools/mxfs_lab.sh pair "$key")
    for step in "$@"; do
        MXFS_LAB=$lab unmount_pairs $pair >> "$pl"
        echo "=== $key: $step ===" >> "$pl"
        env MXFS_LAB="$lab" bash -c "$step" >> "$pl" 2>&1
        echo "=== rc=$?: $key: $step ===" >> "$pl"
    done
    MXFS_LAB=$lab unmount_pairs $pair >> "$pl"
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

# --- 2. both released 2-node suites on the rig
run ./run.sh 2 tcp
echo "suite_tcp_pass=$(grep -cE '^\s+PASS' "$L") suite_tcp_fail=$(grep -cE '^\s+(FAIL|TIMEOUT)' "$L")" | tee -a "$L"
n0=$(wc -l < "$L")
run ./run.sh 2 cawd
echo "suite_cawd_pass=$(tail -n +$n0 "$L" | grep -cE '^\s+PASS') suite_cawd_fail=$(tail -n +$n0 "$L" | grep -cE '^\s+(FAIL|TIMEOUT)')" | tee -a "$L"

# --- 3. packages
if [ ! -d "dist/$V" ]; then
    run scripts/release.sh || { echo "release.sh failed; stopping" | tee -a "$L"; exit 1; }
fi

# --- 4-5. platform rounds and the pair tests, one platform per LUN, in parallel
PR=tests/packaged_round.sh
FZ=tests/tcp_peer_freeze_death.sh
platform ubuntu2404 "TRANSPORT=tcp $PR ubuntu2404 $V" "TRANSPORT=caw $PR ubuntu2404 $V" \
    "TRANSPORT=tcp PREP=ubuntu2404 $FZ" "TRANSPORT=caw PREP=ubuntu2404 $FZ" &
P1=$!
platform pve9 "KERNEL=6.17.2-1-pve TRANSPORT=tcp $PR pve9 $V" "KERNEL=6.17.2-1-pve TRANSPORT=caw $PR pve9 $V" \
    "KERNEL=7.0.14-19-pve TRANSPORT=tcp $PR pve9 $V" "KERNEL=7.0.14-19-pve TRANSPORT=caw $PR pve9 $V" \
    "TRANSPORT=tcp PREP=pve9 $FZ" "TRANSPORT=caw PREP=pve9 $FZ" &
P2=$!
platform rhel9 "TRANSPORT=tcp $PR rhel9 $V" "TRANSPORT=caw $PR rhel9 $V" \
    "TRANSPORT=tcp PREP=rhel9 $FZ" "TRANSPORT=caw PREP=rhel9 $FZ" \
    "tests/selinux_svirt_mxfs.sh $(tools/mxfs_lab.sh addr alma9-1)" \
    $( [ "$LAPS" -gt 0 ] && echo "tests/svirt_stall_laps.sh $V $LAPS" ) &
P3=$!
platform debian13 "TRANSPORT=tcp $PR debian13 $V" "TRANSPORT=caw $PR debian13 $V" \
    "TRANSPORT=tcp PREP=debian13 $FZ" "TRANSPORT=caw PREP=debian13 $FZ" &
P4=$!
for p in $P1 $P2 $P3 $P4; do wait $p; done
for k in ubuntu2404 pve9 rhel9 debian13; do
    cat "$HERE/tests/evidence/full_verify_${V}_$k.log" >> "$L"
    grep -a '^=== rc=' "$HERE/tests/evidence/full_verify_${V}_$k.log"
done

grep -E "=== rc=|RESULT|VERDICT|both nodes on kernel|suite_tcp_|suite_cawd_|clean_build_rc|tools_rc|tauth_rc|extern_audit_rc|all .* laps passed|STALL|STOP" "$L" | cut -c1-200
