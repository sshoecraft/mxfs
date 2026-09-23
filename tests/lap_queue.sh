#!/bin/bash
# tests/lap_queue.sh — run a list of rig laps in order, detached, each under
# the bound its OWN header derives, one console per lap and one summary line
# per lap a driver reads back.
#
# WHY IT EXISTS.  The rig is serial: every lap here re-preps the fleet, and
# several destroy and reboot both domains, so two cannot overlap.  A campaign
# that has four or five unrun laps queued therefore either leaves the rig idle
# between them while a session does something else, or is driven by hand one
# call at a time.  The per-arm sweeps in this directory
# (fence_crash_cuts_sweep.sh, fence_partition_sweep.sh,
# authority_handoff_phase_sweep.sh) each solve that for ONE harness by
# hard-coding it; this is the same loop with the harness and its bound read
# from a queue file instead, so a mixed queue needs no new sweep script.
#
# THE BOUND IS NOT THIS SCRIPT'S TO CHOOSE.  Every lap in this tree derives its
# own caller bound in its header, from measured infrastructure plus the
# workload's native-XFS equivalent, and prints it there.  The queue file
# carries that number and nothing else; this script never invents one, never
# rounds one, and never retries or re-runs a lap that overran.  An overrun is
# the lap's failure and is recorded as rc=124 with whatever RESULT line the
# console holds.
#
# A LAP'S VERDICT DOES NOT STOP THE QUEUE.  Each lap's own prep restores the
# fleet, so a FAIL, ABORT or VACUOUS is recorded and the next lap starts.  What
# DOES stop the queue is a lap that could not be started at all (no such file,
# not executable): that is a queue-file defect, not a measurement, and running
# the rest of the queue past it would bury it.
#
# THE QUEUE FILE.  One lap per line, blank lines and lines beginning with '#'
# ignored:
#
#     <bound-seconds> <command...>
#
# e.g.
#
#     1200 tests/admitted_write_parked_across_fence.sh s130a
#     950  tests/post_closure_renewal_at_peer.sh s130b
#     1000 tests/nonfallible_transition_stall.sh s130c
#
# The command is run from the tree root with the environment this script was
# started with, so per-lap env goes in the command itself (`SITE=data ...`).
#
# THE LOG.  tests/evidence/lapq_<label>.log gets
#     QUEUE START label=<l> laps=<n> <utc>
#     QUEUE lap=<n> rc=<rc> wall=<s>s <the lap's RESULT line, or none> console=<path>
#     QUEUE DONE laps=<n> pass=<n> wall=<s>s <utc>
#
# Usage: nohup setsid tests/lap_queue.sh <label> <queue-file> \
#            > tests/evidence/lapq_<label>.out 2>&1 &
set -u
LABEL=${1:?label}
QFILE=${2:?queue-file}
cd "$(dirname "$0")/.." || exit 2
[ -r "$QFILE" ] || { echo "no such queue file: $QFILE" >&2; exit 2; }
LOG=tests/evidence/lapq_$LABEL.log
s0=$(date +%s); n=0; pass=0

# Read the whole queue first and refuse it as a whole if any entry is
# unrunnable.  Discovering that on lap 4, after three laps and an hour of rig
# time, would be a queue-file defect paid for in measurements.
LAPS=()
while IFS= read -r line || [ -n "$line" ]; do
    stripped=${line#"${line%%[![:space:]]*}"}
    case $stripped in ''|'#'*) continue ;; esac
    case $stripped in
        *[[:space:]]*) ;;
        *) echo "queue line is a bound with no command: [$line]" >&2; exit 2 ;;
    esac
    bound=${stripped%%[[:space:]]*}
    cmd=${stripped#*[[:space:]]}
    cmd=${cmd#"${cmd%%[![:space:]]*}"}
    case $bound in
        ''|*[!0-9]*) echo "queue line has no numeric bound: [$line]" >&2; exit 2 ;;
    esac
    # the script is the first word of the command that is not VAR=value
    script=$cmd
    while :; do
        case $script in
            [A-Za-z_]*=*) script=${script#* } ;;
            *) break ;;
        esac
    done
    script=${script%% *}
    [ -x "$script" ] || { echo "queue line names a script that is not executable: [$script] from [$line]" >&2; exit 2; }
    LAPS+=("$bound	$cmd")
done < "$QFILE"
[ "${#LAPS[@]}" -gt 0 ] || { echo "queue file has no laps: $QFILE" >&2; exit 2; }

echo "QUEUE START label=$LABEL laps=${#LAPS[@]} $(date -u +%FT%TZ)" >> "$LOG"
for entry in "${LAPS[@]}"; do
    n=$((n+1)); s=$(date +%s)
    bound=${entry%%	*}
    cmd=${entry#*	}
    con=tests/evidence/lapq_${LABEL}_$n.console
    echo "QUEUE lap=$n starting bound=${bound}s cmd=[$cmd] $(date -u +%FT%TZ)" >> "$LOG"
    timeout "$bound" bash -c "$cmd" > "$con" 2>&1
    rc=$?
    r=$(grep -a '^RESULT' "$con" | tail -1 | cut -c1-300)
    echo "QUEUE lap=$n rc=$rc wall=$(( $(date +%s) - s ))s ${r:-no RESULT line} console=$con" >> "$LOG"
    [ "$rc" = 0 ] && pass=$((pass+1))
done
echo "QUEUE DONE laps=$n pass=$pass wall=$(( $(date +%s) - s0 ))s $(date -u +%FT%TZ)" >> "$LOG"
