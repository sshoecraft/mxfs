#!/bin/bash
#
# full_verify.sh — everything a version must pass before it can be published
#
# Usage: [NODES=N] tests/full_verify.sh VERSION [STALL_LAPS]
#
# NODES (default 2) is the cluster size the release claims: the rig suites run
# at that node count, and every platform's verification set (the lab file's
# `nodes` line) must hold that many nodes, since a claim for N nodes is
# verified on N nodes of each platform and nothing smaller.
#
# In order, each step logged into tests/evidence/full_verify_<VERSION>.log with
# its own "=== rc=N: <step> ===" line:
#   1. a build from a clean copy of the tree (no objects), warnings counted;
#      the userspace tools, the user-mode tests (tests/tauth) and the extern
#      declaration audit
#   2. both released suites on the rig at NODES: ./run.sh N tcp, then
#      ./run.sh N cawd, alone on the host (they grade pace, and a loaded host
#      has failed them before)
#   3. the release packages (scripts/release.sh), unless dist/VERSION holds them
#   4. every platform's packaged round on EACH transport (TRANSPORT=tcp, caw):
#      ubuntu2404, pve9 on both claimed kernels, rhel9, debian13
#   5. every platform's hung-node test on each transport, and on the rhel9
#      set the SELinux sVirt test, then STALL_LAPS laps of
#      tests/svirt_stall_laps.sh (default 0)
#
# Steps 4-5 run the platforms of a group in parallel, each platform's own
# steps in order, and the groups one after another: every set verifies on a
# LUN of its own (scripts/scst_platform_targets.sh, lab file
# ~/.config/mxfslab/lab.<platform>), so no set's format touches another's.
# Each platform's steps also go to
# tests/evidence/full_verify_<VERSION>_<platform>.log and are copied into the
# main log when it finishes.
#
# PLATFORM_GROUPS (default "ubuntu2404,pve9,rhel9,debian13": one group, all
# four at once) names the groups, commas inside a group and spaces between
# groups.  POWER=1 (default 0) powers the sets with scripts/lab_power.sh so
# that only what a step needs is up: the rig alone for the suites, then each
# group's sets alone for their steps, and the rig again at the end.  Both
# exist for a host that cannot hold every guest at once: at eight nodes the
# rig and the four sets are forty guests, 112 GiB of configured memory against
# this host's 94, so the 8-node verification runs
#   POWER=1 PLATFORM_GROUPS="pve9 debian13 rhel9 ubuntu2404"
# one platform at a time.  Memory would allow two sets at once (48 GiB, then
# 64 GiB), but the packaged round's install is a DKMS compile on every node
# under a per-guest budget (tests/packaged_round.sh): two 8-node sets compile
# on 64 vCPUs of this 56-core host at once, and on 0.90.36 six of eight rhel9
# nodes overran the 660 s install budget beside ubuntu2404's compile.  One set
# is 32 vCPUs.  The suites grade pace, so with POWER=1 they also run with
# every platform guest off.
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

V="${1:?usage: [NODES=N] full_verify.sh VERSION [STALL_LAPS]}"
LAPS="${2:-0}"
NODES="${NODES:-2}"
[[ "$NODES" =~ ^[0-9]+$ ]] && [ "$NODES" -ge 2 ] || { echo "NODES must be an integer >= 2 (got '$NODES')" >&2; exit 2; }
POWER="${POWER:-0}"
ALL_PLATFORMS="ubuntu2404 pve9 rhel9 debian13"
PLATFORM_GROUPS="${PLATFORM_GROUPS:-ubuntu2404,pve9,rhel9,debian13}"
[ "$(echo "$PLATFORM_GROUPS" | tr ', ' '\n\n' | awk 'NF' | sort | tr '\n' ' ')" = "debian13 pve9 rhel9 ubuntu2404 " ] \
    || { echo "PLATFORM_GROUPS must name each of [$ALL_PLATFORMS] exactly once (got '$PLATFORM_GROUPS')" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
L="$HERE/tests/evidence/full_verify_$V.log"
: > "$L"
SSH="$HERE/tools/mxfs_sshpass.sh"
echo "=== full_verify $V nodes=$NODES power=$POWER groups=[$PLATFORM_GROUPS] $(date -u +%FT%TZ) ===" | tee -a "$L"
# every platform's set must be the claimed size before anything runs: a
# smaller set would verify a smaller claim
for k in ubuntu2404 pve9 rhel9 debian13; do
    lab="$HOME/.config/mxfslab/lab.$k"
    [ -r "$lab" ] || { echo "no lab file $lab (scripts/scst_platform_targets.sh setup)" | tee -a "$L"; exit 2; }
    n=$(MXFS_LAB=$lab tools/mxfs_lab.sh nodes "$k" 2>/dev/null | wc -w)
    [ "$n" -ge "$NODES" ] || { echo "$k: its verification set has $n node(s), the claim needs $NODES" | tee -a "$L"; exit 2; }
done

run() {
    echo "=== $* ===" >> "$L"
    "$@" >> "$L" 2>&1
    local rc=$?
    echo "=== rc=$rc: $* ===" >> "$L"
    echo "rc=$rc  $*"
    return $rc
}

all_platform_nodes() {  # every node named by a platform lab file
    local k
    for k in ubuntu2404 pve9 rhel9 debian13; do
        MXFS_LAB="$HOME/.config/mxfslab/lab.$k" tools/mxfs_lab.sh nodes "$k" 2>/dev/null
    done | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' '
}
unmount_pairs() {  # [node...] — default: every platform node
    local h
    for h in ${*:-$(all_platform_nodes)}; do
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
    pair=$(MXFS_LAB=$lab tools/mxfs_lab.sh nodes "$key")
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
timeout 60 python3 scripts/inode_flag_bits_audit.py >> "$L" 2>&1; echo "inode_flag_audit_rc=$?" | tee -a "$L"

# --- 2. both released suites on the rig at the claimed node count
if [ "$POWER" = 1 ]; then
    # shellcheck disable=SC2086  # one argument per platform
    run scripts/lab_power.sh down $ALL_PLATFORMS
    run scripts/lab_power.sh up "rig:$NODES"
fi
run ./run.sh "$NODES" tcp
echo "suite_tcp_pass=$(grep -cE '^\s+PASS' "$L") suite_tcp_fail=$(grep -cE '^\s+(FAIL|TIMEOUT)' "$L")" | tee -a "$L"
n0=$(wc -l < "$L")
run ./run.sh "$NODES" cawd
echo "suite_cawd_pass=$(tail -n +$n0 "$L" | grep -cE '^\s+PASS') suite_cawd_fail=$(tail -n +$n0 "$L" | grep -cE '^\s+(FAIL|TIMEOUT)')" | tee -a "$L"
# the board is the verdict, not the run's own PASS lines: a row FLAKY or SKIP
# on the board is not a pass, and the board is what tools/criteria.py reads
run python3 tools/criteria.py "$NODES" tcp
run python3 tools/criteria.py "$NODES" cawd

# --- 3. packages
if [ ! -d "dist/$V" ]; then
    run scripts/release.sh || { echo "release.sh failed; stopping" | tee -a "$L"; exit 1; }
fi

# --- 4-5. platform rounds and the set tests, one platform per LUN: a group's
# platforms in parallel, the groups one after another
PR=tests/packaged_round.sh
FZ=tests/tcp_peer_freeze_death.sh
steps_of() {  # <platform>: that platform's steps, in order
    local s
    case "$1" in
        ubuntu2404|debian13)
            s=("TRANSPORT=tcp $PR $1 $V" "TRANSPORT=caw $PR $1 $V"
               "TRANSPORT=tcp PREP=$1 $FZ" "TRANSPORT=caw PREP=$1 $FZ") ;;
        pve9)
            s=("KERNEL=6.17.2-1-pve TRANSPORT=tcp $PR pve9 $V" "KERNEL=6.17.2-1-pve TRANSPORT=caw $PR pve9 $V"
               "KERNEL=7.0.14-19-pve TRANSPORT=tcp $PR pve9 $V" "KERNEL=7.0.14-19-pve TRANSPORT=caw $PR pve9 $V"
               "TRANSPORT=tcp PREP=pve9 $FZ" "TRANSPORT=caw PREP=pve9 $FZ") ;;
        rhel9)
            s=("TRANSPORT=tcp $PR rhel9 $V" "TRANSPORT=caw $PR rhel9 $V"
               "TRANSPORT=tcp PREP=rhel9 $FZ" "TRANSPORT=caw PREP=rhel9 $FZ"
               "PREP=rhel9 tests/selinux_svirt_mxfs.sh")
            # one step, whatever it holds: an unquoted expansion here made
            # three steps of the command and its two arguments
            [ "$LAPS" -gt 0 ] && s+=("tests/svirt_stall_laps.sh $V $LAPS") ;;
    esac
    platform "$1" "${s[@]}"
}
for g in $PLATFORM_GROUPS; do
    gs=${g//,/ }
    if [ "$POWER" = 1 ]; then
        # only this group's sets hold the host's memory while they verify
        off="rig:$NODES"
        for k in $ALL_PLATFORMS; do case " $gs " in *" $k "*) ;; *) off="$off $k" ;; esac; done
        # shellcheck disable=SC2086  # one argument per set
        run scripts/lab_power.sh down $off
        # shellcheck disable=SC2086
        run scripts/lab_power.sh up $gs
    fi
    pids=()
    for k in $gs; do steps_of "$k" & pids+=($!); done
    for p in "${pids[@]}"; do wait "$p"; done
    # shellcheck disable=SC2086
    [ "$POWER" = 1 ] && run scripts/lab_power.sh down $gs
done
[ "$POWER" = 1 ] && run scripts/lab_power.sh up "rig:$NODES"
for k in $ALL_PLATFORMS; do
    cat "$HERE/tests/evidence/full_verify_${V}_$k.log" >> "$L"
    grep -a '^=== rc=' "$HERE/tests/evidence/full_verify_${V}_$k.log"
done

grep -E "=== rc=|RESULT|VERDICT|both nodes on kernel|suite_tcp_|suite_cawd_|clean_build_rc|tools_rc|tauth_rc|extern_audit_rc|inode_flag_audit_rc|all .* laps passed|STALL|STOP" "$L" | cut -c1-200
