#!/bin/bash
# sess583_chain_controls.sh — the CONTROL legs that D-0928 and D-0929 still owe
# before either may close.
#
# WHY THESE AND NOT MORE LAPS OF THE GHOST PROBE.  The whole-cluster-restart
# chain (tests/sess570_chain_ghost.sh) went 6/6 on 0.75.85 and is the positive
# evidence for both records: the frozen crash-leftover records are declared
# dead, the purged-key fence certifies as kind 21, the slices are recovered and
# both nodes mount.  What that chain CANNOT show is that the same changes did
# not break the ordinary cases, and both records name those cases explicitly:
#
#   D-0928 — "a live peer that claims a slot and stalls for a while must not be
#   declared dead any faster than before (the threshold is unchanged: 31 equal
#   samples), and a slot that goes EMPTY or foreign-gen while never live must
#   not fire a death."  The inactive arm now reaches check_dead for never-live
#   monitored slots too, so a clean-departed or re-mkfs'd slot is exactly where
#   a regression would show, as 'no longer responding' against a slot that
#   nobody should be mourning.
#
#   D-0929 — cluster_restart_nomkfs x2 and tcp_2node_death_chain 1 lap.
#
# A death fired against a healthy or cleanly-departed slot is a WORSE defect
# than the one being fixed: it fences a live node.  So this chain asserts the
# absence of that signal on every leg, not just the exit codes.
#
# EVERY LEG RE-PREPS.  These harnesses assume a mounted, converged cluster, and
# a leg chained onto a failed one measures a shape it never set up — the
# failure mode that made s570b report a near-pass over a table it had emptied.
#
# the budget rule (derived from each harness's own stated bound, not rounded):
#   prep_cluster                48 s measured, bound 300
#   cluster_restart_nomkfs      healthy ~60 s, its own bound 200   (x2)
#   sameboot_remount            7 cycles <= 25 s, its own bound 200
#   tcp_2node_death_chain       its own chain bound 555 (includes its prep)
#   => 300 + 2*(300+200) + (300+200) + 555 = 2355 s.  A leg that hits its own
#   bound is a FAILURE, not a slow pass, and is reported as one.
#
# Usage: tests/sess583_chain_controls.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_controls_$LABEL
mkdir -p "$OUT"
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== sess583_chain_controls label=$LABEL sv=$SV $(date -u +%FT%TZ) ==="
echo "=== evidence $OUT"
fails=0

# waitboot — a prep started while a node is still booting fails with
#   PREP FAIL: bad nodes: test2(build="System is booting up. Unprivileged users
#   are not permitted to log in yet...")
# because the build check reads pam_nologin's banner where it expects a
# srcversion.  Any leg that follows a death lap restarts a VM, so this is the
# normal case here, not the exception — measured s583c, where both
# cluster_restart_nomkfs legs were lost to it and the chain reported two FAILs
# for a filesystem that was never asked to do anything.
waitboot() {
    local n w=0
    for n in ${MXFS_NODE_LIST//,/ }; do
        until [ "$(timeout 15 tools/mxfs_sshpass.sh "$n" \
                    'test -e /run/nologin && echo booting || echo ready' \
                    2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] \
              || [ $w -ge 24 ]; do
            w=$((w+1)); sleep 5
        done
    done
    [ $w = 0 ] || echo "    (waited ${w} poll(s) for nodes to finish booting)"
}

prep() {  # <tag>
    local t=$(date +%s) rc
    waitboot
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_$1.log" 2>&1
    rc=$?
    echo "STAGE $1 prep rc=$rc wall=$(( $(date +%s) - t ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep_$1.log" | cut -c1-140)"
    return $rc
}

leg() {  # <tag> <bound> <cmd...>
    local tag="$1" bound="$2"; shift 2
    local t=$(date +%s) rc
    prep "$tag" || { echo "  FAIL $tag prep"; fails=$((fails+1)); return 1; }
    timeout "$bound" "$@" > "$OUT/$tag.log" 2>&1
    rc=$?
    local w=$(( $(date +%s) - t ))
    echo "STAGE $tag rc=$rc wall=${w}s bound=${bound}s"
    grep -a 'RESULT\|^  FAIL\|FAIL ' "$OUT/$tag.log" | sed 's/^/    /' | head -12
    if [ "$rc" = 124 ]; then
        echo "    FAIL $tag HIT ITS BOUND (${bound}s) — a timeout is a failure, not a slow pass"
    fi
    [ $rc = 0 ] || fails=$((fails+1))
    return 0
}

leg nomkfs1 200 tests/cluster_restart_nomkfs.sh "${LABEL}n1"
leg nomkfs2 200 tests/cluster_restart_nomkfs.sh "${LABEL}n2"
leg sameboot 200 tests/sameboot_remount.sh "${LABEL}s"
# tcp_2node_death_chain preps itself; give it its own stated 555 s and no
# extra prep of ours in front of it.
t=$(date +%s)
timeout 555 tests/tcp_2node_death_chain.sh "${LABEL}d" 1 > "$OUT/deathchain.log" 2>&1
rc=$?
echo "STAGE deathchain rc=$rc wall=$(( $(date +%s) - t ))s bound=555s"
grep -a 'RESULT\|^  FAIL' "$OUT/deathchain.log" | sed 's/^/    /' | head -12
[ "$rc" = 124 ] && echo "    FAIL deathchain HIT ITS BOUND — a timeout is a failure"
[ $rc = 0 ] || fails=$((fails+1))

# ---- The D-0928 regression assertion, across EVERY leg's captured output.
# 'no longer responding' is the death declaration.  On these legs every slot is
# either live or CLEANLY departed, so any occurrence is a false death — the
# regression the widened check_dead could introduce, and a worse defect than
# the one it fixed.
echo "--- D-0928 false-death sweep (every leg, all logs in this run only)"
fd=0
for f in "$OUT"/*.log; do
    n=$(grep -ac 'no longer responding' "$f" 2>/dev/null)
    [ "${n:-0}" = 0 ] || { echo "    $(basename "$f"): $n x 'no longer responding'"; fd=$((fd + n)); }
done
if [ "$fd" = 0 ]; then
    echo "  PASS zero false deaths across all control legs (0)"
else
    echo "  FAIL $fd death declaration(s) on legs where every slot is live or cleanly departed"
    fails=$((fails+1))
fi

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails evidence=$OUT"
[ $fails = 0 ]
