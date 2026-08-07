#!/bin/bash
# .ccloop/state.sh — the FORWARD half of the ccloop handoff.
#
# ccloop's summarize.py produces the BACKWARD half (what the previous session
# did: its tool counts, files edited, last bash commands, last text turn).
# Nothing in that describes the project as it is NOW, so before this hook
# existed a fresh session's only answer to "what should I work on" was
# "continue whatever the last session was holding".
#
# Measured cost of that gap over ccloop run c7ee71c6 (34 sessions, Jul 28 ->
# Aug 3): median 65 turns and ~128K of context before the first Edit/Write,
# with 29% of each session's file reads being files the PREVIOUS session had
# already read.  ~80K of that 128K was re-derivation, not boot.
#
# state.md used to fill this role by hand and proved the point by freezing on
# 2026-07-31 at 0.11.302 while the tree ran on to 0.11.397 — 13 sessions and
# 95 versions of drift.  Everything below is therefore DERIVED at prompt-build
# time from the authoritative files, never hand-maintained:
#
#   VERSION, mxfs.ko            -> build identity
#   .last_run.json + criteria.json -> board tally and non-passing cells
#   tests/criteria/OPEN_DEFECTS.json -> RULE 6 ledger, severity-ordered
#   CHANGELOG.md                -> what most recently shipped
#
# Contract (see ccloop/state.py): stdout is embedded in the session prompt
# under "## Current project state"; cwd is CCLOOP_PROJECT_ROOT; stdout is
# truncated at CCLOOP_STATE_HOOK_MAX_BYTES (default 8000) with a VISIBLE
# marker; CCLOOP_STATE_HOOK_TIMEOUT defaults to 30s.  So: stay local, stay
# fast, stay well under 8000 bytes.  NEVER ssh the fleet from here — a 32-node
# poll cannot finish in the timeout and would gate every session start on rig
# health.
#
# Keep this script DERIVED.  If you find yourself typing a fact into it, that
# fact belongs in CLAUDE.md (if it is permanent) or in the ledger (if it is
# about a defect).  A hand-written constant here will go stale exactly the way
# state.md did.

cd "${CCLOOP_PROJECT_ROOT:-/src/mxfs}" || exit 1

CRIT=criteria.json
LEDGER=tests/criteria/OPEN_DEFECTS.json

# ---------------------------------------------------------------- build ----
ver=$(cat VERSION 2>/dev/null || echo '?')
src=$(modinfo mxfs.ko 2>/dev/null | awk '/^srcversion/{print $2}')
echo "### Build"
printf 'tree VERSION **%s**' "$ver"
[ -n "$src" ] && printf '  |  mxfs.ko srcversion `%s`' "$src"
if [ -s .last_run.json ]; then
    printf '  |  last rig run: %s nodes / %s @ %s' \
        "$(jq -r '.nodes // "?"' .last_run.json)" \
        "$(jq -r '.dlm   // "?"' .last_run.json)" \
        "$(jq -r '.iso   // "?"' .last_run.json)"
fi
echo; echo
echo "The srcversion above is what THIS TREE builds, not necessarily what the"
echo "fleet is running. Confirm deployment before trusting a measurement."
echo

# ---------------------------------------------------------------- board ----
if [ -s "$CRIT" ] && [ -s .last_run.json ]; then
    N=$(jq -r '.nodes // empty' .last_run.json)
    D=$(jq -r '.dlm   // empty' .last_run.json)
    B=$(case "$D" in cawd|cawp) echo caw;; *) echo "$D";; esac)
    echo "### Board — last conditions (${N}/${D})"
    jq -r --arg N "$N" --arg D "$D" --arg B "$B" '
      ($N|tonumber) as $nn |
      [ .categories[] | select(.transport=="any" or .transport==$B) | .category as $c |
        .tests[] | select(.min_nodes <= $nn and ((.max_nodes // 0) == 0 or .max_nodes >= $nn))
        | {c:$c, n:.name, s:(.runs[$N+"/"+$D].status // "PENDING"),
           m:(.runs[$N+"/"+$D].measured // "")} ]
      | (map(select(.s=="PASS"))|length) as $p
      | (map(select(.s!="PASS"))) as $bad
      | "\($p) PASS, \($bad|length) not-passing, \(length) applicable"
      , (if ($bad|length)>0 then "not passing:" else empty end)
      , ($bad[] | "  - \(.n) [\(.s)] \(.m[0:110])")
    ' "$CRIT" 2>/dev/null
    echo
    echo "\`open_defects\` is a POLICY cell: red BY DESIGN under RULE 6 while the"
    echo "ledger below is non-empty. It is not a regression and not a test fault."
    echo "\`NO_TERMINAL_RECORD\` means the harness captured no verdict — that is a"
    echo "capture failure, NOT a filesystem fault. Do not diagnose the FS from it."
    echo
fi

# --------------------------------------------------------------- ledger ----
if [ -s "$LEDGER" ]; then
    echo "### RULE 6 ledger — open defects, severity order"
    python3 - "$LEDGER" <<'PY' 2>/dev/null
import json, re, sys
CLOSED = {"RESOLVED", "FIXEDANDVERIFIED", "FIXEDVERIFIED", "DISPROVED"}
norm = lambda s: re.sub(r"[^A-Z0-9]", "", str(s).upper())
d = json.load(open(sys.argv[1]))
ds = d.get("defects", [])
op = [x for x in ds if norm(x.get("status", "OPEN")) not in CLOSED]
rank = {"critical": 0, "high": 1, "major": 2, "medium": 3, "minor": 4}
sev = lambda x: str(x.get("severity") or "unset").split()[0].lower()
op.sort(key=lambda x: rank.get(sev(x), 5))
ncrit = sum(1 for x in op if sev(x) == "critical")
print(f"{len(op)} open of {len(ds)} ledgered — {ncrit} critical. "
      f"Work these in order unless you state why not.\n")
for i, x in enumerate(op, 1):
    print(f"{i}. [{sev(x)}] {x.get('id','?')}")
    nxt = x.get("next") or x.get("next_step") or x.get("next_steps") or ""
    if isinstance(nxt, list):
        nxt = " ".join(map(str, nxt))
    nxt = " ".join(str(nxt).split())
    if nxt:
        print(f"   next: {nxt[:190]}")
print("\nRULE 6: an entry closes ONLY as DISPROVED or FIXED AND VERIFIED. "
      "'Cannot reproduce', a clean run, or a workaround are NOT dispositions. "
      "Full evidence per defect: tests/criteria/OPEN_DEFECTS.json (325KB — "
      "read the ONE entry you are working, never the whole file).")
PY
    echo
fi

# ------------------------------------------------------------- shipped ----
if [ -s CHANGELOG.md ]; then
    echo "### Most recently shipped"
    grep -m3 -E '^## [0-9]' CHANGELOG.md | sed 's/^## /- /'
    echo
fi

# ------------------------------------------------------------ pointers ----
cat <<'EOF'
### Before you measure anything
- RULE 0 budgets (a timeout IS a failure): `tests/criteria/TIMEOUT_BUDGETS.md`
- Deploy the fleet: `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` (72-137s).
  A module reload RESETS runtime knobs.
- Board a criterion: `./run.sh <nodes> <dlm> <test>`; read it with `./showstat.sh`.
- Phase walls: `dmesg | grep mxfs-CCph` (crash) / `mxfs-DRCph` (dir_reuse).
- Use MXFS tools on MXFS devices (`tools/chk_mxfs -v`), never xfs_db/xfs_info —
  the on-disk envelope offsets them and they return garbage.
EOF
