#!/bin/bash
#
# release_rig_gates.sh — the rig's share of a release's verification, one gate
# after another and nothing beside them: tests/drbd_release_verify.sh, then the
# release matrix's boards in two stages of disjoint rig groups
# (tests/boards_stage_chain.sh).  The platform rounds (tests/full_verify.sh
# STEPS=build,packages,platforms) are not here: they need the public text and
# the defect queue final first.
#
# Run alone.  A board beside the DRBD verification made the DRBD link's
# PingAck time out 17 s after the outage test's reboot, the peer was fenced,
# and the run failed on the host's load rather than on the build.
#
# Usage: [PRE_STAGES="<stage> ..."] tests/release_rig_gates.sh VERSION [LABEL]
#   PRE_STAGES  board stages run first (tests/boards_stage_chain.sh syntax), e.g.
#               repeats of rows whose recent window holds failures of a build
#               since fixed: a cell stays FLAKY until its last 11 runs are clean
#   Release stages (the 16-node group contains the 2-, 4- and 8-node ones):
#     A  2/net/mesh/direct@g2 4/net/mesh/direct@g4 2/disk/caw/direct@g2b 8/disk/caw/direct@g8
#     B  16/disk/caw/direct@g16 4/disk/caw/direct@g4b
# Output: tests/evidence/release_rig_gates_<VERSION>.out; each release board's
# VERDICT line, and last
#   RELEASE_RIG_GATES PASS|FAIL version=<V> srcversion=<S> drbd=<PASS|FAIL> boards_green=<n>/6
# tests/boards_stage_chain.sh exits 0 whatever its boards found, so the boards
# are graded here from each one's own log.
# Launch detached (nohup setsid ... &); a board killed mid-row finalizes
# that row ABORTED.
set -u
V=${1:?usage: tests/release_rig_gates.sh VERSION [LABEL]}
LABEL=${2:-gates$(date -u +%m%d%H%M)}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 1
O="tests/evidence/release_rig_gates_$V.out"
SV=$(modinfo -F srcversion mxfs.ko 2>/dev/null)
say() { echo "[$(date -u +%FT%TZ)] $*" >> "$O"; }
: > "$O"
say "release_rig_gates version=$V module_version=$(modinfo -F version mxfs.ko 2>/dev/null) srcversion=$SV label=$LABEL"

read -r -a PRE <<<"${PRE_STAGES:-}"
if [ "${#PRE[@]}" -gt 0 ]; then
    tests/boards_stage_chain.sh "${LABEL}p" "${PRE[@]}" > "tests/evidence/release_rig_gates_${V}_pre.console" 2>&1
    grep -aE 'Total:' "tests/evidence/boards_stage_${LABEL}p.out" | sed 's/^/pre: /' >> "$O"
fi

tests/drbd_release_verify.sh "$V" > "tests/evidence/release_rig_gates_${V}_drbd.console" 2>&1
drbd=$(tail -1 "tests/evidence/drbd_release_verify_$V.out")
say "drbd: $drbd"

A="2/net/mesh/direct@g2,4/net/mesh/direct@g4,2/disk/caw/direct@g2b,8/disk/caw/direct@g8"
B="16/disk/caw/direct@g16,4/disk/caw/direct@g4b"
tests/boards_stage_chain.sh "$LABEL" "$A" "$B" > "tests/evidence/release_rig_gates_${V}_boards.console" 2>&1
green=0
i=0
for stage in "$A" "$B"; do
    i=$((i + 1))
    for spec in ${stage//,/ }; do
        cfg=${spec%@*}; grp=${spec#*@}
        log="tests/evidence/board_${cfg//\//-}_${grp}_${LABEL}s$i.log"
        verdict=$(grep -a 'VERDICT' "$log" 2>/dev/null | tail -1)
        # run.sh prints the stored board after any exit, so a run that never
        # formed its cluster (no pool LUN, a node held off) still ends in the
        # last build's verdict; only a run that exited 0 measured anything
        rc=$(grep -aoE '^=== rc=[0-9]+ run\.sh' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+')
        say "$cfg@$grp: run rc=${rc:-none} ${verdict:-no VERDICT line in $log}"
        [ "${rc:-1}" = 0 ] && [[ "$verdict" == *"every criterion green for $cfg"* ]] && green=$((green + 1))
        grep -aE '^[0-9]+ +\| ' "$log" 2>/dev/null | grep -avE '\| PASS ' | sed "s|^|  $cfg: |" >> "$O"
    done
done

v=FAIL
case "$drbd" in "DRBD_RELEASE_VERIFY PASS version=$V "*) [ "$green" = 6 ] && v=PASS ;; esac
dv=FAIL; case "$drbd" in "DRBD_RELEASE_VERIFY PASS "*) dv=PASS ;; esac
echo "RELEASE_RIG_GATES $v version=$V srcversion=$SV drbd=$dv boards_green=$green/6" >> "$O"
