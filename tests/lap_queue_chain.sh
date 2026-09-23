#!/bin/bash
# tests/lap_queue_chain.sh — wait for a running lap queue to finish, then start
# the next one.  The rig is serial and a lap re-preps the whole fleet, so two
# queues must never overlap; this is the gate that enforces that and nothing
# else.
#
# WHY IT IS A SEPARATE FILE AND NOT AN OPTION ON lap_queue.sh.  The chaining
# need arises exactly while a queue is RUNNING, and bash re-reads a script file
# by byte offset as it executes: inserting lines into tests/lap_queue.sh while
# an instance of it is driving a three-hour queue shifts every offset after the
# insertion and can make that instance resume mid-file.  A new file cannot do
# that to a running one.
#
# THE WAIT IS BOUNDED AND THE BOUND IS NOT THIS SCRIPT'S TO INVENT.  It is the
# SUM OF THE PRECEDING QUEUE'S OWN LAP BOUNDS: every lap there runs under a
# timeout, so that sum is the longest that queue can possibly take, and a wait
# that outlives it is waiting for something that can no longer arrive.
# Reaching the bound is a REFUSAL, never a start — beginning a lap while
# another queue may still be driving the fleet would run two at once, which
# every harness in this directory is written on the assumption cannot happen.
# A refusal leaves the rig alone and says so; it never widens itself.
#
# THE PRECEDING QUEUE MUST ACTUALLY BE THE ONE NAMED.  The log is appended to,
# so a stale 'QUEUE DONE' from an earlier run of the same label would let this
# start immediately while the current one is still going.  The line this waits
# for must therefore come AFTER the newest 'QUEUE START', and that is what is
# tested.
#
# Usage: nohup setsid tests/lap_queue_chain.sh \
#            <after-log> <after-bound-s> <label> <queue-file> \
#            > tests/evidence/lapq_<label>.out 2>&1 &
set -u
# No apostrophe in any of these messages.  The word after ':?' goes through
# quote removal, so a lone ' in it opens a quote that runs on into the NEXT
# line and swallows the assignment there: written as "the running queue's log"
# this consumed the AFTER_BOUND line entirely and the script died on an unbound
# variable it appeared to set two lines earlier.
AFTER_LOG=${1:?the log of the queue to wait for, tests/evidence/lapq_LABEL.log}
AFTER_BOUND=${2:?the sum of the lap bounds in that queue, in seconds}
LABEL=${3:?label for the queue to start}
QFILE=${4:?queue file for the queue to start}
cd "$(dirname "$0")/.." || exit 2
case $AFTER_BOUND in
    ''|*[!0-9]*) echo "the after-bound must be a number of seconds: [$AFTER_BOUND]" >&2; exit 2 ;;
esac
[ -r "$QFILE" ] || { echo "no such queue file: $QFILE" >&2; exit 2; }

# The queue file is validated by lap_queue.sh itself, which refuses a queue
# whose entries are not all runnable BEFORE it starts any of them.  Discovering
# a bad queue file three hours from now, after the wait, would waste the whole
# gap; so run that validation here too, on a queue of zero laps it cannot
# start, by checking the same two things for each line.
n=0
while IFS= read -r line || [ -n "$line" ]; do
    stripped=${line#"${line%%[![:space:]]*}"}
    case $stripped in ''|'#'*) continue ;; esac
    case $stripped in
        *[[:space:]]*) ;;
        *) echo "queue line is a bound with no command: [$line]" >&2; exit 2 ;;
    esac
    bound=${stripped%%[[:space:]]*}
    cmd=${stripped#*[[:space:]]}
    # the same strip lap_queue.sh does: a bound padded with two spaces
    # ("950  tests/...") otherwise leaves the command starting with a blank,
    # the VAR=value skip below never matches, and the script name reads as
    # empty — refused here as unrunnable while lap_queue.sh would run it.
    cmd=${cmd#"${cmd%%[![:space:]]*}"}
    case $bound in
        ''|*[!0-9]*) echo "queue line has no numeric bound: [$line]" >&2; exit 2 ;;
    esac
    script=$cmd
    while :; do
        case $script in
            [A-Za-z_]*=*) script=${script#* } ;;
            *) break ;;
        esac
    done
    script=${script%% *}
    [ -x "$script" ] || { echo "queue line names a script that is not executable: [$script] from [$line]" >&2; exit 2; }
    n=$((n+1))
done < "$QFILE"
[ "$n" -gt 0 ] || { echo "queue file has no laps: $QFILE" >&2; exit 2; }
echo "chain: $QFILE holds $n runnable lap(s); waiting for $AFTER_LOG to finish (bound ${AFTER_BOUND}s)" >&2

# 'QUEUE DONE' counts only if it is newer than the newest 'QUEUE START': the
# log is append-only across runs of the same label.
done_after_start() {
    awk '/^QUEUE START/ { d = 0 } /^QUEUE DONE/ { d = 1 } END { exit d ? 0 : 1 }' "$AFTER_LOG" 2>/dev/null
}
w0=$(date +%s)
until done_after_start; do
    if [ $(( $(date +%s) - w0 )) -ge "$AFTER_BOUND" ]; then
        echo "REFUSED: $AFTER_LOG has written no 'QUEUE DONE' in ${AFTER_BOUND}s, which is the longest that queue can run under its own lap bounds.  The fleet may still be in use, so nothing is started here; find out what that queue is doing." >&2
        exit 2
    fi
    sleep 30
done
echo "chain: $AFTER_LOG reached QUEUE DONE after $(( $(date +%s) - w0 ))s — starting $LABEL" >&2
exec tests/lap_queue.sh "$LABEL" "$QFILE"
