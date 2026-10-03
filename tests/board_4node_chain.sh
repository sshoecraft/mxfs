#!/bin/bash
#
# board_4node_chain.sh — the 4-node release boards, each preceded by the
# native-XFS fio yardstick this rig needs for its fio_perf_vs_xfs row.
#
# Usage: tests/board_4node_chain.sh <label> <configuration>[:<test>[,<test>...]][@<group>] [...]
#   configuration is <nodes>/<class>/<method>/<attach>, e.g. 4/net/mesh/direct
#   (docs/attachment-methods.md).  An optional @<group> runs that board on a
#   rig group (./run.sh <configuration> --group <group>, the lab file's `group`
#   line) instead of test1..testN; when every argument names a group the boards
#   run SIDE BY SIDE, each on its own nodes and its own pool LUN
#   (tools/lun_pool.sh), and the chain waits for all of them.  An optional :<test> runs
#   that one row (./run.sh <configuration> <test>) instead of the whole board, for a
#   row an earlier board left unmeasured, or a comma-separated list of rows
#   for one lap that re-forms the cluster once and runs them together — the
#   shape a flake window needs: a row whose newest genuine failure sits at
#   window index k (0 = the live run) reads PASS again only after 11-k more
#   runs of that row, and every lap here is one such run.  The two-node
#   boards are the same chain given 2/... configurations.
#   For each argument, in order:
#   1. if /src/mxfs/.xfs_fio_baseline.<class-method-attach>.<rigtag>.json is missing, capture
#      it: a single-node native-XFS prep on a pool LUN borrowed for test1
#      (./run.sh 1/xfs prep_cluster) and ./run.sh 1/xfs fio_perf writing that
#      file.  Without it the board's fio_perf_vs_xfs row SKIPs
#      ("no-baseline-for-<rigtag>"), and a SKIP is not a pass.  The rig tag is
#      asked of the LUN itself (tools/mxfs_rig_tag.sh), never read from a
#      device name.  The capture holds the whole rig, so side-by-side boards
#      capture every missing yardstick first, one after another, and only
#      then start.
#   2. the whole board: ./run.sh <configuration> (or the rows named).
#   Every run.sh enforces its own per-row budget from tests/suite/manifest, so
#   nothing here wraps one in a timeout.  For the reader: the yardstick is
#   prep (300 s) + fio_perf (120 s), and a 4/net/mesh/direct board's rows sum to ~3530 s
#   of budget while measured walls are far shorter (most rows take seconds).
#
# Logs: tests/evidence/xfs_baseline_<class-method-attach>_<label>.log,
#       tests/evidence/board_<N-class-method-attach>[_<test>]_<label>.log (the
#       run, then the board read back with tools/criteria.py <configuration>).
# Exit 0 iff every board's read-back says the bar is met.
#
# Launch it detached (nohup setsid ... &) with its output in a file: a chain
# started as a tool's background task is killed with the session that started
# it, and a board killed mid-row finalizes that row ABORTED.
#
set -u
USAGE="usage: board_4node_chain.sh <label> <configuration>[:<test>[,<test>...]][@<group>] [...]"
LABEL="${1:?$USAGE}"
shift
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
EV="$HERE/tests/evidence"
mkdir -p "$EV"
# the tree as the nodes see it over NFS: the yardstick file is written by the
# node running fio_perf and read by the node running fio_perf_vs_xfs
NODETREE=/src/mxfs

# The rig the boards run on is the pool's (data/rigs.json "pool": true): every
# LUN a board borrows is one of its LUNs, so they share one rig tag.
TAG=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print(" ".join(k for k,v in d.items() if isinstance(v,dict) and v.get("pool")))' data/rigs.json)
[ "$(wc -w <<<"$TAG")" = 1 ] || { echo "data/rigs.json must name exactly one pool rig (got '$TAG')" >&2; exit 2; }

# yardstick <shape>: the native-XFS yardstick for that shape, captured on a
# pool LUN borrowed for test1 when missing.  0 iff it is present afterwards.
yardstick() {
    local dlm=$1 base L line dev
    base="$NODETREE/.xfs_fio_baseline.$dlm.$TAG.json"
    if [ -s "$base" ]; then
        echo "$(date -u +%FT%TZ) $dlm: yardstick present: $base"
        return 0
    fi
    L="$EV/xfs_baseline_${dlm}_$LABEL.log"
    echo "$(date -u +%FT%TZ) $dlm: capturing the native-XFS yardstick for rig $TAG -> $base (log $L)"
    {
        line=$(tools/lun_pool.sh alloc --owner $$ --what "board_4node_chain $LABEL yardstick" --size 20G test1) \
            || { echo "no pool LUN for test1"; }
        dev=$(sed -n 's/.* dev=\([^ ]*\).*/\1/p' <<<"$line")
        if [ -n "$dev" ]; then
            echo "=== $(date -u +%FT%TZ) ./run.sh 1/xfs prep_cluster (MXFS_DEV=$dev) ==="
            MXFS_DEV=$dev ./run.sh 1/xfs prep_cluster
            echo "=== rc=$? prep_cluster 1 xfs ($(date -u +%FT%TZ)) ==="
            echo "=== ./run.sh 1/xfs fio_perf (XFS_BASELINE=$base) ==="
            MXFS_DEV=$dev MXFS_TEST_ENV="XFS_BASELINE=$base" ./run.sh 1/xfs fio_perf
            echo "=== rc=$? fio_perf 1 xfs ($(date -u +%FT%TZ)) ==="
            ls -la "$base" 2>&1
            cat "$base" 2>/dev/null; echo
        fi
    } > "$L" 2>&1
    if [ -s "$base" ]; then
        # the node writes it as root over NFS, so this user may not read it
        echo "$(date -u +%FT%TZ) $dlm: yardstick captured: $( { sudo -n cat "$base" 2>/dev/null || cat "$base" 2>/dev/null || echo "(present, not readable as $(id -un))"; } | tr -d '\n')"
        return 0
    fi
    echo "$(date -u +%FT%TZ) $dlm: yardstick NOT captured (see $L); the board's fio_perf_vs_xfs row will SKIP"
    return 1
}

# board <cfg> <rows> <group>: one board (or the rows named), its log, its
# read-back.  0 iff the read-back says the bar is met.
board() {
    local cfg=$1 row=$2 group=$3 rows L g rrc
    rows="${row//,/ }"
    g=${group:+--group $group}
    L="$EV/board_${cfg//\//-}${row:+_${row//,/_}}${group:+_$group}_$LABEL.log"
    echo "$(date -u +%FT%TZ) $cfg: ./run.sh $cfg $g $rows (log $L)"
    {
        if [ -n "$row" ]; then
            # a filtered run refuses a stale marker instead of re-prepping
            # (measured 2026-09-28: 'cluster is prepped for 4/net/mesh/direct ... Run
            # ./run.sh 4/net/mesh/direct prep_cluster first'), so the row is preceded by
            # the prep row, which always re-forms the cluster
            echo "=== $(date -u +%FT%TZ) ./run.sh $cfg $g prep_cluster ==="
            # shellcheck disable=SC2086  # an empty $g must vanish
            MXFS_FORCE_PREP=1 ./run.sh "$cfg" $g prep_cluster
            echo "=== rc=$? run.sh $cfg $g prep_cluster ($(date -u +%FT%TZ)) ==="
        fi
        echo "=== $(date -u +%FT%TZ) ./run.sh $cfg $g $rows ==="
        # shellcheck disable=SC2086  # an empty $g or $rows must vanish, not be an argument
        ./run.sh "$cfg" $g $rows
        rrc=$?
        echo "=== rc=$rrc run.sh $cfg $g $rows ($(date -u +%FT%TZ)) ==="
        python3 tools/criteria.py "$cfg"
    } > "$L" 2>&1
    grep -E '^(Total:|VERDICT:)' "$L" | tail -2 | sed "s|^|$(date -u +%FT%TZ) $cfg: |"
    # The read-back is the STANDING board, so a run.sh that refused to start
    # (measured: every board of a release chain stopped by the host preflight,
    # rc=3) still reads green from the previous release's rows.
    if [ "$rrc" != 0 ]; then
        echo "$(date -u +%FT%TZ) $cfg: run.sh rc=$rrc — this board did not run to completion; the verdict above is not this run's"
        return 1
    fi
    grep -q 'VERDICT: every criterion green' "$L"
}

CFGS=(); ROWS=(); BGROUPS=(); grouped=0
for arg in "$@"; do
    g=""
    case "$arg" in *@*) g=${arg##*@}; arg=${arg%@*}; grouped=$((grouped + 1)) ;; esac
    cfg=${arg%%:*}
    row=""
    [ "$arg" = "$cfg" ] || row=${arg#*:}
    cfg=$(python3 tools/configuration.py parse "$cfg") || exit 2
    CFGS+=("$cfg"); ROWS+=("$row"); BGROUPS+=("$g")
done
[ "$grouped" = 0 ] || [ "$grouped" = "${#CFGS[@]}" ] \
    || { echo "either every argument names a group (side by side) or none does (one after another)" >&2; exit 2; }

rc_all=0
if [ "$grouped" = 0 ]; then
    for i in "${!CFGS[@]}"; do
        yardstick "$(python3 tools/configuration.py get "${CFGS[$i]}" shape)" || rc_all=1
        board "${CFGS[$i]}" "${ROWS[$i]}" "" || rc_all=1
    done
    exit $rc_all
fi
for dlm in $(for c in "${CFGS[@]}"; do python3 tools/configuration.py get "$c" shape; done | sort -u); do
    yardstick "$dlm" || rc_all=1
done
pids=()
for i in "${!CFGS[@]}"; do
    board "${CFGS[$i]}" "${ROWS[$i]}" "${BGROUPS[$i]}" &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || rc_all=1; done
exit $rc_all
