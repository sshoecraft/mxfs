#!/bin/bash
# tools/rebuild_after_queue.sh — wait for a running lap queue to finish, then
# rebuild the module and check the probe gate.  It does NOT launch anything.
#
# WHY IT EXISTS.  A lap queue is launched detached (`nohup setsid`), so it
# outlives the session that started it, and every lap re-preps the fleet by
# deploying /src/mxfs/mxfs.ko.  A `make modules` while one is running therefore
# hands a DIFFERENT module to the remaining laps and splits the sweep across two
# srcversions — which is invisible in the results and invalidates every lap
# after the relink.  So the rebuild has to wait, and waiting by hand costs a
# session's attention for however long the queue has left.
#
# WHY IT STOPS AT THE GATE.  Launching the next queue is a decision, not a step:
# if the probe gate fails, the module does not contain the code the next queue
# is built to measure and every lap in it would be vacuous by construction.
# This script therefore ends by printing the gate's verdict and exiting with it,
# and the caller decides.  It must never launch a queue itself.
#
# Usage:
#   tools/rebuild_after_queue.sh <queue-log> [probe ...]
#
#   tools/rebuild_after_queue.sh tests/evidence/lapq_s133.log \
#       P290-AUTH-REFUSED-DATA P312-IOMAP-REVALIDATED
#
# Exit: 0 the queue finished, the build succeeded and every named probe is in
#         mxfs.ko;  1 the gate failed;  2 the build failed;  3 the queue did not
#         finish inside its bound.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 2
QLOG=${1:?queue log, e.g. tests/evidence/lapq_s133.log}
shift
PROBES=("$@")

# The bound is the queue's OWN remaining work plus a margin for the last lap's
# cleanup, read from the queue file rather than chosen: every unfinished lap's
# bound is in it.  A queue that overruns that is a queue that is stuck, and
# waiting longer is not the answer — it exits 3 and says so.
QFILE=${QLOG%.log}.queue
if [ -r "$QFILE" ]; then
    done_n=$(grep -ac '^QUEUE lap=[0-9]* rc=' "$QLOG" 2>/dev/null); done_n=${done_n:-0}
    REMAIN=$(grep -vE '^\s*#|^\s*$' "$QFILE" | awk -v d="$done_n" 'NR>d {s+=$1} END {print s+0}')
    BOUND=$((REMAIN + 300))
else
    echo "no queue file beside $QLOG; cannot derive a bound from the queue's own laps" >&2
    exit 2
fi
echo "=== rebuild_after_queue: waiting for $QLOG (laps done=$done_n, remaining bound=${REMAIN}s, wait bound=${BOUND}s) $(date -u +%FT%TZ)"

waited=0
while ! grep -qa '^QUEUE DONE' "$QLOG" 2>/dev/null; do
    [ "$waited" -ge "$BOUND" ] && {
        echo "=== the queue has not printed QUEUE DONE after ${waited}s, which is past the sum of its own remaining laps' bounds."
        echo "=== It is stuck, not slow.  Not rebuilding: read $QLOG and the last lap's console."
        tail -3 "$QLOG"
        exit 3
    }
    sleep 30
    waited=$((waited + 30))
done
echo "=== queue finished after ${waited}s of waiting:"
tail -2 "$QLOG"

if [ "${WAIT_ONLY:-0}" = 1 ]; then
    # Watch-only.  A lap queue is launched detached so it survives the session
    # that started it, and a detached process is invisible to anything watching
    # this one — so the caller needs a LOCAL process that outlives nothing but
    # the queue itself.  This is that process: it waits, reports, and builds
    # nothing.
    echo "=== WAIT_ONLY: not building.  The queue is finished."
    exit 0
fi

echo "=== make modules $(date -u +%FT%TZ)"
BLOG=tests/evidence/build_$(date -u +%Y%m%dT%H%M%SZ).log
make modules > "$BLOG" 2>&1
brc=$?
echo "=== build rc=$brc log=$BLOG"
if [ "$brc" != 0 ]; then
    tail -25 "$BLOG"
    exit 2
fi
echo "=== srcversion now: $(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')"

[ "${#PROBES[@]}" -eq 0 ] && { echo "=== no probes named; nothing gated"; exit 0; }
echo "=== probe gate: ${PROBES[*]}"
tools/probe_audit.sh --gate "${PROBES[@]}"
grc=$?
echo "=== GATE rc=$grc  (0 = every named probe is in the built module)"
exit "$grc"
