#!/bin/bash
#
# boards_stage_chain.sh — run stages of release boards one after another,
# detached, each stage side by side on its own rig groups.  For boards whose
# groups share nodes (the 16-node groups contain the 2-, 4- and 8-node ones):
# those cannot be started together, so each such set is a stage of its own.
#
# Usage: tests/boards_stage_chain.sh LABEL STAGE [STAGE ...]
#   STAGE  a comma-separated list of <configuration>[:<row>,...]@<group>, e.g.
#          "2/net/mesh/direct@g2,4/disk/caw/direct@g4b"; rows inside one board
#          are separated with '+' here ("2/net/mesh/mpath:path_flap+chk_clean@g2")
#
# Before each stage every group it names is powered up (scripts/lab_power.sh);
# then tests/board_4node_chain.sh <LABEL>s<i> runs the stage.  run.sh enforces
# each row's own budget, so nothing here wraps a stage in a timeout.
#
# Output: tests/evidence/boards_stage_<LABEL>.out — each stage ends with
# "STAGE_RC <i> <rc>", then every board's non-PASS rows, and the last line is
# BOARDS_STAGES_DONE.
#
# Launch it detached (nohup setsid ... &): a chain started as a tool's
# background task dies with the session that started it, and a board killed
# mid-row finalizes that row ABORTED.
#
set -u
LABEL="${1:?usage: tests/boards_stage_chain.sh LABEL STAGE [STAGE ...]}"
shift
[ $# -ge 1 ] || { echo "no stage given" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
O="tests/evidence/boards_stage_$LABEL.out"
cfgs=()
i=0
for stage in "$@"; do
    i=$((i + 1))
    boards=(); sets=()
    for b in ${stage//,/ }; do
        b=${b//+/,}
        g=${b##*@}
        boards+=("$b"); sets+=("group:$g")
        c=${b%%@*}; cfgs+=("${c%%:*}")
    done
    # WAIT_STAGE=<i> WAIT_LOGS="<board log> ...": before stage <i>, wait until
    # each named board log holds its run's final "=== rc=N run.sh" line — for
    # boards another chain started on nodes this stage needs.  A board's rows
    # sum to about an hour of budget; past WAIT_S (default 7200) the stage is
    # not started on top of a live run.
    if [ "${WAIT_STAGE:-}" = "$i" ]; then
        t0=$(date +%s); held=""
        for wl in ${WAIT_LOGS:-}; do
            until grep -aq '^=== rc=[0-9]* run.sh' "$wl" 2>/dev/null; do
                [ $(($(date +%s) - t0)) -lt "${WAIT_S:-7200}" ] || { held=$wl; break; }
                sleep 20
            done
        done
        if [ -n "$held" ]; then
            echo "=== $(date -u +%FT%TZ) stage $i NOT STARTED: $held has no final rc line after ${WAIT_S:-7200} s ===" >> "$O"
            echo "STAGE_RC $i 99" >> "$O"
            continue
        fi
    fi
    {
        echo "=== $(date -u +%FT%TZ) stage $i: ${boards[*]} ==="
        scripts/lab_power.sh up "${sets[@]}"
        echo "POWER_RC $i $?"
        tests/board_4node_chain.sh "${LABEL}s$i" "${boards[@]}"
        echo "STAGE_RC $i $?"
    } >> "$O" 2>&1
done
{
    for c in $(printf '%s\n' "${cfgs[@]}" | sort -u); do
        echo "== $c $(python3 tools/criteria.py "$c" 2>/dev/null | grep -a '^Total' | cut -c1-90)"
        python3 tools/criteria.py "$c" 2>/dev/null | grep -aE '^[0-9]+ +\|' | grep -avE '\| PASS ' | cut -c1-200
    done
    echo "BOARDS_STAGES_DONE $(date -u +%FT%TZ)"
} >> "$O" 2>&1
