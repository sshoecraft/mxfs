#!/bin/bash
# tests/capture_fault_gate.sh — does every adopted harness REJECT a failed
# measurement, rather than avoid one?
#
# The capture contract (docs/harness-capture-contract.md, ledger
# D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS) is verified by rejection:
# a real ssh failure at a real acquisition point must end the lap as ABORT
# with the injection proven in the evidence and NO verdict printed after it.
# tests/lib/rig.sh injects that with MXFS_FAULT_RSX_NTH=<n>: the n-th
# measurement of the lap is issued to a host that does not resolve, and the
# library prints a STAGE FAULT line on stderr when the injection is reached.
#
# For every entry of the gate manifest this runs the harness once with the
# fault armed and requires, from the lap's own log:
#   - exit status 2 (ABORT), never 0 (a PASS from no measurement) and never
#     1 (a FAIL fabricated from the failed capture);
#   - the STAGE FAULT line (the injection was reached: a harness whose first
#     measurement never goes through rsx would "pass" this gate vacuously);
#   - a RESULT: ABORT line;
#   - ZERO assertion lines ("  PASS"/"  FAIL") after the STAGE FAULT line.
# With --healthy it then runs the same entry without the fault and requires
# exit status 0: the boundary must not refuse a healthy measurement either
# (--healthy-only runs just that lap, for a manifest whose fault side has
# its evidence).  The healthy line quotes the lap's DEVICE line: the harness
# resolved its device by identity (tests/lib/rig.sh mxfs_dev_resolve).
# A healthy lap that exits 3 with zero FAIL lines is the harness's own
# VACUOUS / INCONCLUSIVE (its trigger was not reached; nothing refused,
# nothing fabricated): recorded as VACUOUS, counted apart, not BROKEN.
# An entry that misses any of these is BROKEN and the gate exits 1.
#
# Manifest (tests/capture_gate.manifest): one entry per line,
#     <harness> | <fault lap timeout s> | <healthy lap timeout s> | <env> | <args after the label>
# The timeouts are the harness's own caller bound (its header derives it);
# a lap that overruns is recorded with rc=124 and is BROKEN, never re-run.
# <env> is the environment for both laps (NOPREP=1 to reuse the live mount)
# or '-' for none.
#
# Usage: tests/capture_fault_gate.sh <label> [--healthy|--healthy-only] [--only <harness>] [manifest]
set -u
LABEL=${1:?label}; shift
HEALTHY=0; FAULT=1; ONLY=; MANIFEST=tests/capture_gate.manifest
while [ $# -gt 0 ]; do
    case $1 in
        --healthy) HEALTHY=1 ;;
        --healthy-only) HEALTHY=1; FAULT=0 ;;   # the fault side already has its evidence for this manifest
        --only) ONLY=$2; shift ;;
        *) MANIFEST=$1 ;;
    esac
    shift
done
cd "$(dirname "$0")/.." || exit 2
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_capture_gate_$LABEL
mkdir -p "$OUT"
[ -r "$MANIFEST" ] || { echo "ABORT: gate manifest $MANIFEST is not readable"; exit 2; }
echo "=== capture_fault_gate label=$LABEL manifest=$MANIFEST healthy=$HEALTHY out=$OUT $(date -u +%FT%TZ) ==="
broken=0; vacuous=0; entries=0; s0=$(date +%s)

# the assertion lines printed AFTER the injection line, counted from the
# same log the harness wrote (stderr and stdout interleaved as they came)
verdicts_after_fault() { awk '/STAGE FAULT:/{f=1; next} f && /^  (PASS|FAIL) /{n++} END{print n+0}' "$1"; }

while IFS= read -r line; do
    case $line in ''|'#'*) continue ;; esac
    IFS='|' read -r h tf th env args <<< "$line"
    h=$(echo "$h" | tr -d ' '); tf=$(echo "$tf" | tr -d ' '); th=$(echo "$th" | tr -d ' '); env=$(echo "$env" | sed 's/^ *//;s/ *$//'); args=$(echo "$args" | sed 's/^ *//;s/ *$//')
    [ -z "$ONLY" ] || [ "$h" = "$ONLY" ] || continue
    [ -x "tests/$h.sh" ] || { echo "GATE $h: BROKEN (tests/$h.sh is not executable or missing)"; broken=$((broken+1)); continue; }
    case $tf in ''|*[!0-9]*) echo "GATE $h: BROKEN (no fault-lap timeout in the manifest)"; broken=$((broken+1)); continue ;; esac
    [ "$env" = '-' ] && env=
    entries=$((entries+1))
    tag=${h//[^A-Za-z0-9_]/_}
    # a harness whose label is not its first positional (`<A> <B> [laps]
    # [label]`) names the label's place with {label} in its args
    fargs="$LABEL-$tag-fault $args"; hargs="$LABEL-$tag-ok $args"
    case $args in *'{label}'*) fargs=${args//\{label\}/$LABEL-$tag-fault}; hargs=${args//\{label\}/$LABEL-$tag-ok} ;; esac
    # ---- fault lap: the FIRST measurement fails ----
    if [ "$FAULT" = 1 ]; then
    s=$(date +%s)
    # shellcheck disable=SC2086
    # stdin closed: the harness runs inside this loop's `read` over the
    # manifest, and a legacy ssh helper without `< /dev/null` drains the
    # manifest as its own input — a chunk of four entries then ran ONE (s58g)
    timeout "$tf" env MXFS_FAULT_RSX_NTH=1 $env "tests/$h.sh" $fargs < /dev/null > "$OUT/${tag}_fault.log" 2>&1
    rc=$?
    wall=$(( $(date +%s) - s ))
    fl=$(grep -ac 'STAGE FAULT:' "$OUT/${tag}_fault.log")
    ab=$(grep -ac '^RESULT: ABORT' "$OUT/${tag}_fault.log")
    va=$(verdicts_after_fault "$OUT/${tag}_fault.log")
    st=OK
    [ "$rc" = 2 ] && [ "$fl" -ge 1 ] && [ "$ab" -ge 1 ] && [ "$va" = 0 ] || st=BROKEN
    echo "GATE $h fault: rc=$rc wall=${wall}s fault_line=$fl abort=$ab verdicts_after_fault=$va -> $st"
    [ "$st" = OK ] || { broken=$((broken+1)); grep -a '^ABORT:\|^RESULT\|STAGE FAULT' "$OUT/${tag}_fault.log" | head -4 | sed 's/^/      /' | cut -c1-220; }
    fi
    # ---- healthy lap ----
    if [ "$HEALTHY" = 1 ]; then
        s=$(date +%s)
        # shellcheck disable=SC2086
        timeout "${th:-$tf}" env $env "tests/$h.sh" $hargs < /dev/null > "$OUT/${tag}_ok.log" 2>&1
        rc=$?
        wall=$(( $(date +%s) - s ))
        fails=$(grep -ac '^  FAIL ' "$OUT/${tag}_ok.log")
        res=$(grep -a '^RESULT' "$OUT/${tag}_ok.log" | tail -1 | cut -c1-120)
        # the DEVICE line is the device record's migration proof: the harness
        # resolved its device by identity (absent for a harness that touches
        # no device by path, which is then said)
        dev=$(grep -a -m1 '^DEVICE node=' "$OUT/${tag}_ok.log" | cut -c1-140)
        # exit 3 is the harness's own VACUOUS / INCONCLUSIVE: every check it
        # made held, no capture was refused and no verdict was fabricated,
        # but its trigger was not reached (d0532_relog_live_holder's
        # concurrent case is unreachable for a user holder by its header).
        # That is a measured shape, not a boundary failure: recorded as
        # VACUOUS with its RESULT line, counted apart from OK, never BROKEN.
        st=OK; [ "$rc" = 0 ] || { [ "$rc" = 3 ] && [ "$fails" = 0 ] && st=VACUOUS || st=BROKEN; }
        echo "GATE $h healthy: rc=$rc wall=${wall}s fails=$fails result=[$res] device=[${dev:-none}] -> $st"
        [ "$st" = VACUOUS ] && vacuous=$((vacuous+1))
        [ "$st" != BROKEN ] || { broken=$((broken+1)); grep -a '^ABORT:\|^  FAIL\|^RESULT' "$OUT/${tag}_ok.log" | head -4 | sed 's/^/      /' | cut -c1-220; }
    fi
done < "$MANIFEST"
echo "RESULT: $( [ "$broken" = 0 ] && echo PASS || echo FAIL ) label=$LABEL entries=$entries broken=$broken vacuous=$vacuous wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ "$broken" = 0 ]
