#!/bin/bash
# fio_perf_vs_xfs — mxfs single-node fio throughput vs the native-XFS baseline,
# as its own distinct pass/fail (separate from fio_perf's own "did it measure
# something" check). Does NOT re-run fio: reads fio_perf's own bench.json entry
# from THIS run plus the baseline captured at $REPO/.xfs_fio_baseline.json
# (refreshed by fio_perf.sh when run under the native-XFS condition, run.sh
# DLM=xfs). FAILs if mxfs WRITE throughput drops below FIO_MIN_PCT% of native
# XFS (reads are cache-bound and informational only — same methodology as
# tests/tooling/fio_vs_xfs_baseline.sh). Must run AFTER fio_perf in the
# manifest so its bench.json entry for this condition already exists.
SUITE_TEST_NAME=fio_perf_vs_xfs
NODES="${MXFS_NODES:-1}"
DLM="${MXFS_DLM:-tcp}"
BENCH="${MXFS_BENCH:-/src/mxfs/bench.json}"
# sess8 (ccloop 72513a13): per-CONDITION baseline preferred.  The four
# conditions.md rigs present physically different devices (LIO/tcm_loop vs
# SCST direct/passthrough/mpath) with wildly different write paths — native
# XFS itself measures 457MiB/936iops on the tcp rig vs 2064MiB/44281iops on
# the CAW rig.  Comparing a rig's mxfs against another rig's XFS baseline is
# meaningless (1/tcp measured randW "2%" against the CAW-rig file while the
# same-rig xfs comparison was 107%).  Capture per rig with
#   MXFS_TEST_ENV="XFS_BASELINE=/src/mxfs/.xfs_fio_baseline.<cond>.json" \
#     ./run.sh 1 xfs fio_perf
# and this test picks the condition file up automatically.
BASE="${XFS_BASELINE:-/src/mxfs/.xfs_fio_baseline.json}"
[ -z "${XFS_BASELINE:-}" ] && [ -s "/src/mxfs/.xfs_fio_baseline.${DLM}.json" ] \
    && BASE="/src/mxfs/.xfs_fio_baseline.${DLM}.json"
MIN_PCT="${FIO_MIN_PCT:-70}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }

[ -s "$BASE" ] || { emit SKIP no-baseline "no $BASE yet -- run ./run.sh 1 xfs first"; exit 0; }
[ -s "$BENCH" ] || { emit SKIP no-bench "no $BENCH -- fio_perf must run before this test"; exit 0; }

read -r mxsw mxsr mxrw mxrr <<<"$(python3 - "$BENCH" "$NODES" "$DLM" <<'PY'
import json, sys
bench, nodes, dlm = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    d = json.load(open(bench))
    entries = [v for v in d.values() if v.get("test") == "fio_perf" and v.get("nodes") == nodes and v.get("dlm") == dlm]
    entries.sort(key=lambda v: v.get("ts", ""))
    latest = entries[-1]["fio"]
    print(latest["seq_write_1m"]["bw_mib"], latest["seq_read_1m"]["bw_mib"],
          latest["rand_write_4k"]["iops"], latest["rand_read_4k"]["iops"])
except Exception:
    print("0 0 0 0")
PY
)"
read -r xsw xsr xrw xrr <<<"$(python3 - "$BASE" <<'PY'
import json, sys
try:
    b = json.load(open(sys.argv[1]))
    print(b["seq_write_1m"]["bw_mib"], b["seq_read_1m"]["bw_mib"],
          b["rand_write_4k"]["iops"], b["rand_read_4k"]["iops"])
except Exception:
    print("0 0 0 0")
PY
)"

[ "${mxsw:-0}" -gt 0 ] 2>/dev/null || { emit SKIP no-fio_perf-entry "no matching fio_perf bench.json entry for ${NODES}n/${DLM}"; exit 0; }

pct(){ { [ "${2:-0}" -gt 0 ] 2>/dev/null && echo $(( $1*100/$2 )); } || echo 0; }

# sess8 (ccloop 72513a13): at N>1 the WRITE yardstick is the RAW N-sharer
# ceiling of this rig's transport+device (scripts/raw_fio_ceiling.sh,
# captured per condition between rungs), NOT the 1-stream xfs baseline.  A
# shared device cannot deliver its 1-stream bandwidth to N concurrent
# sharers (tcp rig: 1-stream xfs seqW=1116MiB/s, raw 2-sharer ~650 — mxfs at
# 651 was failing "58%" while sitting at device parity).  randW compares
# cleanly against the 1-stream baseline (iops cap is stream-count-invariant
# on these rigs) but the ceiling file's value is used when present for the
# same-rig honesty.  N=1 keeps the xfs baseline for both.
# sess10 (ccloop 72513a13): N=1 uses the ceiling too when captured.  The
# 1-stream FS-level xfs baseline is a SINGLE sample on a device whose seqW
# swings 254-1153MiB/s by cache-absorption-vs-writeback regime (the raw
# ceiling script's own measurement) — a single mxfs sample vs a single xfs
# sample flips 59%<->111% on pure regime luck.  The 1-sharer raw ceiling is
# median-of-K over the same shape, so it's the stable same-rig yardstick at
# every N.  randW keeps the baseline compare unless the ceiling has it.
ceil_sw=0; ceil_rw=0
CEIL="/src/mxfs/.raw_fio_ceiling.${DLM}.json"
if [ -s "$CEIL" ]; then
    read -r ceil_sw ceil_rw <<<"$(python3 - "$CEIL" "$NODES" <<'PY'
import json, sys
try:
    c = json.load(open(sys.argv[1])).get(sys.argv[2], {})
    print(int(c.get("seqW_mib", 0)), int(c.get("randW_iops", 0)))
except Exception:
    print("0 0")
PY
)"
fi
eff_xsw="${xsw:-0}"; eff_xrw="${xrw:-0}"; wsrc="xfs-baseline"
if [ "${ceil_sw:-0}" -gt 0 ]; then eff_xsw="$ceil_sw"; wsrc="raw-ceiling"; fi
if [ "${ceil_rw:-0}" -gt 0 ]; then eff_xrw="$ceil_rw"; fi

psw=$(pct "$mxsw" "${eff_xsw:-0}"); psr=$(pct "$mxsr" "${xsr:-0}")
prw=$(pct "$mxrw" "${eff_xrw:-0}"); prr=$(pct "$mxrr" "${xrr:-0}")
# Gate (PASS/FAIL) stays WRITE-only by design: reads are cache-bound and not
# a meaningful mxfs-vs-xfs signal (same methodology as
# tests/tooling/fio_vs_xfs_baseline.sh). Read percentages are still reported
# below for visibility, just excluded from `worst`.
worst=$(printf '%s\n' "$psw" "$prw" | sort -n | head -1)
measured="seqW=${psw}% seqR=${psr}% randW=${prw}% randR=${prr}% worst(write)=${worst}% (threshold>=${MIN_PCT}%, wsrc=${wsrc})"

{ [ "${worst:-0}" -ge "$MIN_PCT" ]; } 2>/dev/null \
    && emit PASS "$measured" \
    || emit FAIL "$measured" "mxfs write worst ${worst}% < ${MIN_PCT}% of ${wsrc} ($BASE)"
