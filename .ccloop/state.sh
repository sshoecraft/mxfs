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
#   .last_run.json + tools/criteria.py -> the last run's board, non-passing rows
#   tools/defects.py            -> the defect queue, severity-ordered
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
if [ -s .last_run.json ]; then
    N=$(jq -r '.nodes // empty' .last_run.json)
    D=$(jq -r '.dlm   // empty' .last_run.json)
    echo "### Board — last conditions (${N}/${D}), rows not PASS"
    # The board is data/criteria.json, read only through tools/criteria.py.
    # PASS rows are dropped to stay inside the byte budget; the Total and
    # VERDICT lines still count them.
    timeout 20 python3 tools/criteria.py --no-colour "$N" "$D" 2>&1 \
        | grep -vE '^[0-9]+ +\|[^|]*\| PASS ' | grep -v '^=== '
    echo
    echo "FLAKY and SKIP are not passes: a release needs every row PASS."
    echo "\`NO_TERMINAL_RECORD\` means the harness captured no verdict — that is a"
    echo "capture failure, NOT a filesystem fault. Do not diagnose the FS from it."
    echo
fi

# ---------------------------------------------------------------- queue ----
# The whole queue is ~18KB, over the hook's byte budget, so: its totals, what
# blocks the last run's configuration, and the top of the severity order.
echo "### Defect queue — severity order (full: tools/defects.py -d)"
timeout 20 python3 tools/defects.py 2>/dev/null | tail -3
if [ -n "${N:-}" ] && [ -n "${D:-}" ]; then
    echo
    echo "Blocking a ${N}/${D} release:"
    timeout 20 python3 tools/defects.py "$N" "$D" --release 2>/dev/null | cut -c1-170
fi
echo
echo "Top of the queue:"
timeout 20 python3 tools/defects.py 2>/dev/null | head -12 | cut -c1-170
echo
echo "A defect leaves the queue ONLY as DISPROVED or FIXED AND VERIFIED, through"
echo "\`tools/defects.py remove <id> --why\`. 'Cannot reproduce', a clean run, or a"
echo "workaround are NOT dispositions. One entry in full: \`tools/defects.py show <id>\`."
echo

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
- Board a criterion: `./run.sh <nodes> <dlm> <test>`; read it with `tools/criteria.py <nodes> <dlm>`.
- Phase walls: `dmesg | grep mxfs-CCph` (crash) / `mxfs-DRCph` (dir_reuse).
- Use MXFS tools on MXFS devices (`tools/chk_mxfs -v`), never xfs_db/xfs_info —
  the on-disk envelope offsets them and they return garbage.
EOF
