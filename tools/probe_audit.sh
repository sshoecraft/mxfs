#!/bin/bash
# tools/probe_audit.sh — which of the diagnostic probes written in the source
# are actually IN the module the nodes load, and which the compiler deleted.
#
# WHY IT EXISTS.  MXFS decides verdicts by grepping the kernel log for probes:
# string literals of the form P<digits>-<NAME>.  A probe that is in the source
# but NOT in the built module can never appear in a log, and every harness that
# counts it reads that silence as "the thing did not happen".  That is not a
# hypothetical failure mode — it happened.
#
# The authority gate has five call sites, one per class of submission: "log",
# "dio", "dio-zoned", "meta" and "data".  The "data" site lived inside
# xfs_writeback_submit() in pal/linux/xfs_aops.c, a function referenced ONLY by
# the 6.17-and-later iomap_writeback_ops.  The module builds for
# 6.8.0-101-generic, which takes the other arm of the version split, so nothing
# referenced that function, the compiler dropped it, and the gate shipped with
# four arms instead of five:
#
#     P290-AUTH-REFUSED-LOG    1
#     P290-AUTH-REFUSED-DIO    1
#     P290-AUTH-REFUSED-META   1
#     P290-AUTH-REFUSED-DATA   0      <- and nothing said so
#
# Reading the source could not catch it: the call site is right there, with a
# correct comment, and the `#if` is sixty lines further down around a struct
# initialiser rather than around the function.  Asking the BINARY catches it in
# one call.  That is what this is.
#
# WHAT IT DOES NOT DO.  It does not adjudicate.  A probe can be legitimately
# absent — its file may not be in the Kbuild object list, or it may sit behind
# a feature that is off.  The report says which probes are missing and where
# each is written, so the absence can be READ rather than guessed.  Only the
# --gate form has a verdict, and only over probes the caller names.
#
# USAGE
#   tools/probe_audit.sh                         full report, exit 0
#   tools/probe_audit.sh -m <module.ko>          audit a different module
#   tools/probe_audit.sh --gate P290-X P291-Y    exit 1 if any NAMED probe is
#                                                missing from the module
#   tools/probe_audit.sh --build-log <file>      also report every
#                                                "defined but not used" warning
#                                                in that build log, which is the
#                                                compiler naming the same hazard
#                                                for code that carries no probe
#
# THE BUILD-LOG MODE IS THE OTHER HALF.  A probe sweep only finds holes whose
# dead code happens to contain a probe string.  A static function the compiler
# dropped is reported by gcc itself as "defined but not used" — so capture the
# build and read it:
#     make modules 2>&1 | tee /tmp/build.log
#     tools/probe_audit.sh --build-log /tmp/build.log
set -u
cd "$(dirname "$0")/.." || exit 2

MOD=mxfs.ko
BUILDLOG=
GATE=0
GATED=()
while [ $# -gt 0 ]; do
    case $1 in
        -m|--module)    MOD=${2:?module path}; shift 2 ;;
        --build-log)    BUILDLOG=${2:?build log path}; shift 2 ;;
        --gate)         GATE=1; shift
                        while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do
                            GATED+=("$1"); shift
                        done ;;
        -h|--help)      sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)              echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -r "$MOD" ] || { echo "no readable module at $MOD — build it first" >&2; exit 2; }

# The directories compiled INTO mxfs.ko.  tools/ is deliberately absent: those
# are user-space binaries and their probes are not expected in the module.
SRCDIRS="xfs dlm pal mxfs_clayer"
# THE PROBE NAMES ARE NOT ALL P<digits>-<NAME>, AND A PATTERN THAT ASSUMES SO
# MISSES WHOLE FAMILIES SILENTLY.  Three shapes are in use and all three carry
# decisions: P290-AUTH-REFUSED-DATA (digits), P15H-STRANDED-RELEASE and
# P34F-RELOAD-SELFAHEAD-SKIP (digits then a letter), and P-PR-FENCE,
# P-HB-INJECT-PAUSE, P-AILPIN-HOLD (no digits at all).  The first version of
# this tool matched only the first shape, and the probe it therefore could not
# see — P15H-STRANDED-RELEASE — turned out to be TCP's only escape from a
# stranded DLM grant, deleted by the compiler because its threshold was tested
# against a uint8_t.  A detector's blind spot is not a clean result.
PAT='P[0-9]*[A-Z]?-[A-Z][A-Z0-9-]+'

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ONLY WHAT IS INSIDE A STRING LITERAL COUNTS.  A probe name written in a
# comment is not a probe — and worse, a comment that WRAPS one ("the
# P113-DRAIN-" / "WEDGE spin") yields a truncated token that matches nothing in
# the module and reports a probe as missing when the real one is there.  So
# each line is cut at its first double quote and only the remainder is
# searched.  That keeps continuation lines of a multi-line literal, which begin
# with a quote, and drops comment prose, which has none.
# shellcheck disable=SC2086
grep -rhE '"' --include=*.c --include=*.h $SRCDIRS mxfs.c 2>/dev/null \
    | sed 's/^[^"]*"//' \
    | grep -oE "$PAT" | sort -u > "$TMP/src"
strings -a "$MOD" | grep -oE "$PAT" | sort -u > "$TMP/mod"
comm -23 "$TMP/src" "$TMP/mod" > "$TMP/raw"

# A CANDIDATE THAT IS A STRICT PREFIX OF A PROBE THE MODULE HAS IS AN
# EXTRACTION ARTIFACT, NOT A MISSING PROBE, and leaving it in costs a real
# investigation each time.  Two things produce it.  A comment naming a probe
# family in prose — "(P-AGIFC release audit)" — yields the bare token while the
# live probes are P-AGIFC-RELEASE-*.  And a pr_warn whose literal is split
# across source lines AT a dash — "MXFS mount recovery: P-BARRIER-SLICE-" then
# "COUNT ..." — yields the truncated half, while the compiler concatenates the
# two and the full name is in the binary.  Both were investigated by hand once;
# neither should be again.
: > "$TMP/missing"
while read -r cand; do
    [ -n "$cand" ] || continue
    if grep -q "^$cand." "$TMP/mod"; then
        echo "$cand" >> "$TMP/prefixed"
    else
        echo "$cand" >> "$TMP/missing"
    fi
done < "$TMP/raw"
nart=$( [ -r "$TMP/prefixed" ] && wc -l < "$TMP/prefixed" || echo 0 )

nsrc=$(wc -l < "$TMP/src"); nmod=$(wc -l < "$TMP/mod")
nmiss=$(wc -l < "$TMP/missing")
echo "=== probe audit: $MOD ($(modinfo "$MOD" 2>/dev/null | sed -n 's/^srcversion: *//p')) ==="
echo "    source ($SRCDIRS mxfs.c): $nsrc distinct probes"
echo "    built module:             $nmod distinct probes"
echo "    in the source and NOT in the module: $nmiss"
[ "${nart:-0}" -gt 0 ] && echo "    (plus $nart extraction artifact(s) suppressed: each is a strict prefix of a probe the module does have — a comment naming a family, or a literal split across lines at a dash)"

if [ "$nmiss" -gt 0 ]; then
    echo
    echo "--- each missing probe, and where it is written ---"
    while read -r p; do
        [ -n "$p" ] || continue
        echo "  $p"
        # shellcheck disable=SC2086
        grep -rn "$p" --include=*.c --include=*.h $SRCDIRS mxfs.c 2>/dev/null \
            | sed 's/^/      /' | head -8
    done < "$TMP/missing"
    echo
    echo "    A missing probe is not automatically a defect, and this tool does"
    echo "    not claim it is.  Read each site: the file may not be in the"
    echo "    Kbuild object list, or the code may sit behind a feature that is"
    echo "    off.  What it must never be is unexamined, because every harness"
    echo "    that counts one of these reads its absence as a measurement."
fi

if [ -n "$BUILDLOG" ]; then
    echo
    if [ -r "$BUILDLOG" ]; then
        n=$(grep -c 'defined but not used' "$BUILDLOG")
        echo "--- 'defined but not used' in $BUILDLOG: $n ---"
        grep -n 'defined but not used' "$BUILDLOG" | sed 's/^/    /'
        echo "    Each one is the compiler saying it dropped that function."
        echo "    A dropped function containing a decision — a gate, a refusal,"
        echo "    a check — is that decision missing from the shipped module."
        echo
        # THE OTHER WAY A DECISION LEAVES THE BINARY.  A function can be kept
        # and one of its BRANCHES deleted, which no "unused function" warning
        # mentions.  It happens when a comparison cannot come out the way the
        # author meant — most often a negative sentinel sharing a conditional
        # with an unsigned-returning helper, where the usual arithmetic
        # conversions turn -1 into a large positive before it is ever assigned.
        # Measured here: mxfs_pal_io_budget_remaining_ms returned
        # `(d <= 0) ? -1 : jiffies_to_msecs(d)`, so its caller's
        # `if (budget_ms < 0)` was provably false and the compiler deleted the
        # arm, the -ETIME return inside it and the log line beside it.  These
        # warnings need -Wtype-limits, which -Wextra implies:
        #     make modules KCFLAGS="-Wextra" 2>&1 | tee build.log
        m=$(grep -Ec 'comparison is always (false|true)|due to limited range' \
            "$BUILDLOG")
        echo "--- always-false/always-true comparisons in $BUILDLOG: $m ---"
        grep -nE 'comparison is always (false|true)|due to limited range' \
            "$BUILDLOG" | sed 's/^/    /'
        if [ "$m" = 0 ]; then
            echo "    NOTE: zero here means nothing unless the build was made"
            echo "    with -Wtype-limits (or -Wextra).  A log built without it"
            echo "    cannot report this class at all, and its silence is the"
            echo "    flag's absence rather than the code's cleanliness."
        fi
    else
        echo "--- no readable build log at $BUILDLOG ---"
    fi
fi

if [ "$GATE" = 1 ]; then
    echo
    bad=0
    for p in "${GATED[@]:-}"; do
        [ -n "$p" ] || continue
        if grep -qx "$p" "$TMP/mod"; then
            echo "  GATE OK      $p is in $MOD"
        else
            echo "  GATE MISSING $p is NOT in $MOD"
            bad=$((bad+1))
        fi
    done
    if [ "$bad" -gt 0 ]; then
        echo "GATE: $bad named probe(s) are not in the built module."
        exit 1
    fi
    echo "GATE: every named probe is in the built module."
fi
exit 0
