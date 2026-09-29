#!/bin/bash
#
# board_4node_chain.sh — the 4-node release boards, each preceded by the
# native-XFS fio yardstick this rig needs for its fio_perf_vs_xfs row.
#
# Usage: [NODES=N] tests/board_4node_chain.sh <label> <dlm>[:<test>[,<test>...]] [dlm[:test] ...]
#   dlm is a run.sh condition (tcp|cawd|caw|cawp); an optional :<test> runs
#   that one row (./run.sh N <dlm> <test>) instead of the whole board, for a
#   row an earlier board left unmeasured, or a comma-separated list of rows
#   for one lap that re-forms the cluster once and runs them together — the
#   shape a flake window needs: a row whose newest genuine failure sits at
#   window index k (0 = the live run) reads PASS again only after 11-k more
#   runs of that row, and every lap here is one such run.  NODES (default 4)
#   is the cluster size; the two-node boards are the same chain at NODES=2.
#   For each argument, in order:
#   1. if /src/mxfs/.xfs_fio_baseline.<dlm>.<rigtag>.json is missing, capture
#      it: a single-node native-XFS prep on the rig LUN (./run.sh 1 xfs
#      prep_cluster) and ./run.sh 1 xfs fio_perf writing that file.  Without
#      it the board's fio_perf_vs_xfs row SKIPs ("no-baseline-for-<rigtag>"),
#      and a SKIP is not a pass.  The rig tag is asked of the LUN itself
#      (tools/mxfs_rig_tag.sh), never read from a device name.
#   2. the whole board: ./run.sh N <dlm> (or the rows named).
#   Every run.sh enforces its own per-row budget from tests/suite/manifest, so
#   nothing here wraps one in a timeout.  For the reader: the yardstick is
#   prep (300 s) + fio_perf (120 s), and a 4/tcp board's rows sum to ~3530 s
#   of budget while measured walls are far shorter (most rows take seconds).
#
# Logs: tests/evidence/xfs_baseline_<dlm>_<label>.log,
#       tests/evidence/board_N<dlm>[_<test>]_<label>.log (the run, then the
#       board read back with tools/criteria.py N <dlm>).
# Exit 0 iff every board's read-back says the bar is met.
#
# Launch it detached (nohup setsid ... &) with its output in a file: a chain
# started as a tool's background task is killed with the session that started
# it, and a board killed mid-row finalizes that row ABORTED.
#
set -u
LABEL="${1:?usage: [NODES=N] board_4node_chain.sh <label> <dlm>[:<test>[,<test>...]] [dlm[:test] ...]}"
shift
[ $# -ge 1 ] || { echo "usage: [NODES=N] board_4node_chain.sh <label> <dlm>[:<test>[,<test>...]] [dlm[:test] ...]" >&2; exit 2; }
NODES="${NODES:-4}"
[[ "$NODES" =~ ^[0-9]+$ ]] && [ "$NODES" -ge 1 ] || { echo "NODES must be a positive integer (got '$NODES')" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
EV="$HERE/tests/evidence"
mkdir -p "$EV"
# the rig LUN as every node names it (run.sh's tcp/cawd default); the xfs
# baseline condition defaults to /dev/sda, which is not guaranteed to be it
BP=/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0
# the tree as the nodes see it over NFS: the yardstick file is written by the
# node running fio_perf and read by the node running fio_perf_vs_xfs
NODETREE=/src/mxfs
rc_all=0
for arg in "$@"; do
    dlm=${arg%%:*}
    row=""
    [ "$arg" = "$dlm" ] || row=${arg#*:}
    case "$dlm" in tcp|cawd|caw|cawp) ;; *) echo "dlm must be tcp|cawd|caw|cawp (got '$dlm')" >&2; exit 2 ;; esac
    tag=$(MXFS_RIG_TAG_FRESH=1 MXFS_DEV=$BP timeout 60 tools/mxfs_rig_tag.sh "$BP" 2>/dev/null || true)
    if [ -z "$tag" ]; then
        echo "$(date -u +%FT%TZ) $dlm: the rig tag could not be resolved from $BP; no yardstick, no board"
        rc_all=1
        continue
    fi
    base="$NODETREE/.xfs_fio_baseline.$dlm.$tag.json"
    if [ ! -s "$base" ]; then
        L="$EV/xfs_baseline_${dlm}_$LABEL.log"
        echo "$(date -u +%FT%TZ) $dlm: capturing the native-XFS yardstick for rig $tag -> $base (log $L)"
        {
            echo "=== $(date -u +%FT%TZ) ./run.sh 1 xfs prep_cluster (MXFS_DEV=$BP) ==="
            MXFS_DEV=$BP ./run.sh 1 xfs prep_cluster
            echo "=== rc=$? prep_cluster 1 xfs ($(date -u +%FT%TZ)) ==="
            echo "=== ./run.sh 1 xfs fio_perf (XFS_BASELINE=$base) ==="
            MXFS_DEV=$BP MXFS_TEST_ENV="XFS_BASELINE=$base" ./run.sh 1 xfs fio_perf
            echo "=== rc=$? fio_perf 1 xfs ($(date -u +%FT%TZ)) ==="
            ls -la "$base" 2>&1
            cat "$base" 2>/dev/null; echo
        } > "$L" 2>&1
        if [ -s "$base" ]; then
            # the node writes it as root over NFS, so this user may not read it
            echo "$(date -u +%FT%TZ) $dlm: yardstick captured: $( { sudo -n cat "$base" 2>/dev/null || cat "$base" 2>/dev/null || echo "(present, not readable as $(id -un))"; } | tr -d '\n')"
        else
            echo "$(date -u +%FT%TZ) $dlm: yardstick NOT captured (see $L); the board's fio_perf_vs_xfs row will SKIP"
            rc_all=1
        fi
    else
        echo "$(date -u +%FT%TZ) $dlm: yardstick present: $base"
    fi
    rows="${row//,/ }"
    L="$EV/board_${NODES}${dlm}${row:+_${row//,/_}}_$LABEL.log"
    echo "$(date -u +%FT%TZ) $dlm: ./run.sh $NODES $dlm $rows (log $L)"
    {
        if [ -n "$row" ]; then
            # a filtered run refuses a stale marker instead of re-prepping
            # (measured 2026-09-28: 'cluster is prepped for 4/tcp ... Run
            # ./run.sh 4 tcp prep_cluster first'), so the row is preceded by
            # the prep row, which always re-forms the cluster
            echo "=== $(date -u +%FT%TZ) ./run.sh $NODES $dlm prep_cluster ==="
            MXFS_FORCE_PREP=1 ./run.sh "$NODES" "$dlm" prep_cluster
            echo "=== rc=$? run.sh $NODES $dlm prep_cluster ($(date -u +%FT%TZ)) ==="
        fi
        echo "=== $(date -u +%FT%TZ) ./run.sh $NODES $dlm $rows ==="
        # shellcheck disable=SC2086  # an empty $rows must vanish, not be an argument
        ./run.sh "$NODES" "$dlm" $rows
        echo "=== rc=$? run.sh $NODES $dlm $rows ($(date -u +%FT%TZ)) ==="
        python3 tools/criteria.py "$NODES" "$dlm"
    } > "$L" 2>&1
    grep -E '^(Total:|VERDICT:)' "$L" | tail -2 | sed "s/^/$(date -u +%FT%TZ) $dlm: /"
    grep -q 'VERDICT: every criterion green' "$L" || rc_all=1
done
exit $rc_all
