#!/bin/bash
# tests/pr_aptpl_probe.sh — is PERSIST THROUGH POWER LOSS supported, and is it
# ACTIVE, on the LUN this rig fences with?
#
# The fence crash matrix's target-restart entries (the ruling at
# docs/rulings/fence-crash-matrix-cuts.md, "Target restart") open with the one
# thing every restart lap has to establish before it means anything:
#
#     "The lap must show that APTPL is supported and active (not merely
#      requested) ... and that without APTPL the loss of exclusion fails closed
#      for ordinary clustered writes as well as recovery writes."
#
# Supported and active are DIFFERENT BITS and a target answers them separately.
# PERSISTENT RESERVE IN / REPORT CAPABILITIES carries both: PTPL_C says the
# target CAN persist its PR database across a power loss, PTPL_A says a
# registration has actually turned that on.  A target that is capable but not
# activated loses every registration and the reservation when it restarts, and
# the whole fencing argument on this rig rests on state that will not be there.
#
# This probe is READ ONLY.  It issues PR IN commands only — REPORT CAPABILITIES,
# READ KEYS, READ RESERVATION — and an INQUIRY for the target's identity.  It
# registers nothing, reserves nothing, preempts nothing and restarts nothing,
# so it is safe to run on a live mounted cluster and is the prerequisite step of
# the restart laps rather than one of them.
#
# The verdict is deliberately fail-closed on the second bit: capable-but-off is
# a FAIL, not a note, because it is the configuration in which a target restart
# silently unfences every victim this cluster ever proved.
#
# Budget (derived): prep is not needed — the probe reads a device the nodes
# already have.  Three PR IN commands and an INQUIRY, ~1 s each over ssh, plus
# the device resolve: ~30 s.  Caller bound 90 s.
#
# Usage: tests/pr_aptpl_probe.sh <label> [node]
# Exit 0 PASS (supported and active), 1 FAIL, 2 ABORT/INFRA.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
N=${2:-${MXFS_NODE_LIST%%,*}}
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_aptpl_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
echo "=== pr_aptpl_probe label=$LABEL node=$N $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

mxfs_dev_resolve "$N"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
echo "STAGE device $MXFS_DEV on $N at +$(el)s"

# One capture, one trailer.  sg_persist prints the capabilities as a block of
# named flags; the identity comes from INQUIRY so the record says WHICH target
# answered, and the current PR state is taken in the same breath so a later
# reader can see what would be lost.
measure "$N" 60 "$OUT/cap.txt" '^APTPL_END$' "the PR capabilities on $N" \
    "sg_inq $MXFS_DEV 2>&1 | grep -a 'Vendor identification\|Product identification\|Product revision' | sed 's/^/INQ /'; \
     sg_persist -i -c $MXFS_DEV 2>&1 | sed 's/^/CAP /'; \
     sg_persist -i -k $MXFS_DEV 2>&1 | sed 's/^/KEYS /'; \
     sg_persist -i -r $MXFS_DEV 2>&1 | sed 's/^/RESV /'; \
     echo APTPL_END"

# sg_persist spells the two bits out in its report; read each by its own name
# rather than by position, and treat "the line is not there" as unknown (which
# is not the same as zero and must not be scored as one).
bit() {   # <name> -> 1 | 0 | unknown
    local v
    v=$(grep -a "^CAP .*\b$1\b" "$OUT/cap.txt" | head -1 | grep -aoE "$1[^0-9]*[01]" | grep -aoE '[01]$')
    echo "${v:-unknown}"
}
PTPL_C=$(bit PTPL_C)
PTPL_A=$(bit PTPL_A)
TGT=$(grep -a '^INQ' "$OUT/cap.txt" | sed 's/^INQ *//' | tr '\n' ' ' | tr -s ' ' | cut -c1-140)
NKEYS=$(grep -acE '^KEYS *0x[0-9a-f]+' "$OUT/cap.txt")
RESV=$(grep -a '^RESV' "$OUT/cap.txt" | grep -a 'scope:.*type:' | head -1 | sed 's/.*type: *//')
grep -aiq 'RESV.*no reservation' "$OUT/cap.txt" && RESV="none"
echo "STAGE target: ${TGT:-unidentified}"
echo "STAGE PTPL_C(capable)=$PTPL_C PTPL_A(activated)=$PTPL_A registrations=$NKEYS reservation=${RESV:-unreadable}"
grep -a '^CAP' "$OUT/cap.txt" | sed 's/^CAP */    /' | cut -c1-160 | head -20

if [ "$PTPL_C" = unknown ] || [ "$PTPL_A" = unknown ]; then
    echo "ABORT: REPORT CAPABILITIES did not name PTPL_C and PTPL_A, so neither bit was measured — the restart laps have no prerequisite"
    echo "RESULT: ABORT label=$LABEL stage=capabilities evidence=$OUT"; exit 2
fi
ck "the target can persist its PR database through a power loss (PTPL_C)" "$PTPL_C" 1
# capable but not activated is the dangerous configuration, and it is the one
# a probe that stopped at PTPL_C would call healthy
ck "persistence is ACTIVE, not merely available (PTPL_A)" "$PTPL_A" 1
ckge "the LUN carries at least one registration to persist" "$NKEYS" 1

if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL ptpl_c=$PTPL_C ptpl_a=$PTPL_A keys=$NKEYS resv=${RESV:-?} fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "  A target that is capable but not activated loses every registration and the"
echo "  reservation when it restarts.  Every fence this cluster has proved rests on"
echo "  that state, so the restart laps must be run against the failure-closed"
echo "  requirement (no unreserved window, ordinary clustered writes refused) and"
echo "  not against the assumption that the PR database comes back."
echo "RESULT: FAIL label=$LABEL ptpl_c=$PTPL_C ptpl_a=$PTPL_A keys=$NKEYS resv=${RESV:-?} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
