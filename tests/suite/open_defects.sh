#!/bin/bash
# open_defects — ZERO unresolved credible defects (RULE 6), made visible.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess21, user directive)
#   The board read 20/20 green through: a soft lockup that killed a node for
#   522 s and starved all 31 peers; an ILOCK assertion failure on 3 of 4 nodes;
#   and a mkdir(2) that returned success with the entry existing on no node.
#
#   Behavioural criteria alone cannot carry that weight.  The ones that catch
#   INTERMITTENT defects go green whenever a run gets lucky — dirent_durability
#   reproduces its defect roughly 1 run in 10, and dirent_publish_integrity's
#   precursor fires 0-1 times per run.  "This run did not reproduce it" is not
#   "fixed", but a green cell says the latter.
#
#   So the readiness answer needs one DETERMINISTIC gate: a ledger of known-open
#   defects that fails while any remain.  That is exactly RULE 6 ("zero accepted
#   known defects") expressed as a criterion instead of as prose nobody runs.
#
# Ledger: tests/criteria/OPEN_DEFECTS.json (reachable on every node — the test
# rig NFS-mounts /src).  An entry leaves the ledger only under RULE 6's two
# dispositions: DISPROVED, or FIXED_AND_VERIFIED.
#
# DO NOT delete entries, weaken this check, or drop the criterion to make the
# board green.  A green board that is not true is the failure mode this whole
# file exists to prevent.
SUITE_TEST_NAME=open_defects
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"

LEDGER=/src/mxfs/tests/criteria/OPEN_DEFECTS.json

if [ ! -r "$LEDGER" ]; then
    # Unreadable ledger is NOT a pass: it means the readiness question is
    # unanswerable on this node, which is a failure of the gate itself.
    echo "RESULT: FAIL | test=open_defects | nodes=$NODES | measured=ledger=missing | reason=cannot read $LEDGER (is /src mounted?) — unverifiable is not a pass"
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    read -r n_open n_total ids <<EOF
$(python3 - "$LEDGER" <<'PY'
import json, re, sys
# RULE 6 recognises exactly two closure dispositions (plus the historical
# "RESOLVED" spelling).  sess43: this used to test `status != "RESOLVED"`,
# so every entry legitimately closed as "FIXED AND VERIFIED" or "DISPROVED"
# was still counted as unresolved — the gate reported open=26 of=31 when the
# ledger held 11 OPEN.  That direction is fail-SAFE (it can never manufacture
# a false green) but it makes the readiness number meaningless and hides real
# progress, so it must still be correct.  Normalisation folds spelling
# variants ("FIXED AND VERIFIED", "FIXED-VERIFIED", "fixed_and_verified");
# ANY status not on the closed list — including a typo or a new invented
# label — counts as OPEN, so a defect can never be closed by accident.
CLOSED = {"RESOLVED", "FIXEDANDVERIFIED", "FIXEDVERIFIED", "DISPROVED"}
d = json.load(open(sys.argv[1]))
defects = d.get("defects", [])
def norm(s):
    return re.sub(r"[^A-Z0-9]", "", str(s).upper())
open_ = [x for x in defects if norm(x.get("status", "OPEN")) not in CLOSED]
ids = ",".join("%s(%s)" % (x.get("id", "?"), x.get("severity", "?")) for x in open_) or "-"
print(len(open_), len(defects), ids)
PY
)
EOF
else
    # No python3: count status lines that are not a RULE-6 closure.  Coarser,
    # but it must never silently report zero just because the parser is
    # unavailable — and it must match the python branch's closure set
    # (sess43: it previously matched only RESOLVED and so over-counted).
    n_total=$(grep -c '"status"' "$LEDGER")
    n_open=$(grep '"status"' "$LEDGER" \
             | grep -cviE 'RESOLVED|DISPROVED|FIXED[ _-]?AND[ _-]?VERIFIED|FIXED[ _-]?VERIFIED')
    ids="(python3 unavailable — counted by grep)"
fi
n_open=${n_open:-1}; n_total=${n_total:-0}

st=PASS; reason=""
if [ "$n_open" -gt 0 ]; then
    st=FAIL
    reason="$n_open unresolved defect(s) in the RULE 6 ledger: $ids"
fi
echo "RESULT: $st | test=open_defects | nodes=$NODES | measured=open=$n_open of=$n_total ids=[$ids] | reason=$reason"
[ "$st" = PASS ]
