#!/bin/bash
# chk_clean — the whole-volume structural audit: chk_mxfs must find no errors.
#
# WHY THIS RUNS AT EVERY NODE COUNT, NOT JUST ONE.
#
# This was applicable only at N=1, because gen_criteria.py defaults max_nodes
# to 1 for the entire tooling category on the grounds that "all tooling is
# single-node device ops".  A whole-volume structural audit is not that.  It is
# MORE meaningful after a clustered run than after a single-node one: the
# divergences it looks for -- inobt against finobt, AGI freecount against both,
# a block that is inside an allocated inode chunk and also on the free list --
# are produced by concurrent multi-node allocation and by nothing else.
#
# The consequence of the old cap was that no clustered condition had ever run
# the checker.  A 2-node board could print "every criterion passed" over 28
# rows in which nothing had read a btree and compared it to another, and every
# structural defect this project has chased was invisible to it.  A gate that
# cannot see the failure class it exists for is worse than no gate, because it
# is quoted as evidence.
#
# THE AUDIT MUST RUN COLD, AND THAT IS THE WHOLE DESIGN.
#
# chk_mxfs compares btrees against each other.  Read a LIVE mount and in-flight
# allocation shows up as a disagreement between two trees sampled microseconds
# apart -- the check would announce corruption on a healthy filesystem, which
# is the one outcome that would make it worthless.  So every node unmounts, ONE
# node audits, and then every node mounts again.
#
# The rendezvous is coord_barrier (MQTT), never an on-filesystem barrier: this
# test unmounts the filesystem it would otherwise be coordinating through.
#
# A node that cannot remount at the end is a FAILURE of this test and is
# reported as one.  Leaving the fleet unmounted after an audit would silently
# poison every row that runs after it.
SUITE_TEST_NAME=chk_clean
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
RANK="${MXFS_RANK:-1}"
DEV="${MXFS_DEV:-/dev/sda}"
CHK="${CHK_MXFS:-/src/mxfs/tools/chk_mxfs}"
# native-XFS baseline (run.sh DLM=xfs, N=1 only): xfs_repair -n (dry-run check)
# instead of chk_mxfs -- this is the one case where using an xfs_* tool is
# CORRECT (the device really is native XFS here, not mxfs's envelope format;
# see CLAUDE.md's "use mxfs tools, not xfs tools" note, which is about mxfs
# devices specifically).
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"

emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }

# Coordination only; NOT lib.sh, whose finish/ck machinery would emit a second
# RESULT line over this script's own.
#
# THE RENDEZVOUS CAP HAS TO BE SET HERE, and it is the one thing sourcing
# coord.sh without lib.sh costs.  coord_eff_timeout() clamps a wait to the
# reporting deadline lib.sh computes -- with lib.sh absent there is no
# deadline, so the cap falls back to COORD_TIMEOUT's 120 s default, which is
# most of this test's whole 180 s budget.  A stalled barrier would then be
# SIGKILLed by the harness before it could report the stall, which is exactly
# the no-terminal-record failure the deadline machinery exists to prevent.
# 45 s is derived: every node's step before the first barrier is an unmount,
# measured at ~5 s.
: "${COORD_TIMEOUT:=45}"
export COORD_TIMEOUT
COORD="$(dirname -- "${BASH_SOURCE[0]}")/../suite/coord.sh"
# shellcheck source=/dev/null
[ -f "$COORD" ] && source "$COORD"
command -v coord_barrier >/dev/null 2>&1 || coord_barrier() { return 0; }

remount() {
    local t=xfs
    [ "$FSTYPE" = xfs ] || t=mxfs
    mountpoint -q "$MNT" && return 0
    # 100 s, not the 180 s a cold mount is allowed elsewhere: this has to fit
    # inside the test's own budget with the audit already spent, and a mount
    # that needs longer than this is a finding, not something to wait out.
    timeout 100 mount -t "$t" "$DEV" "$MNT" 2>/dev/null
}

# ---- everyone: quiesce and get out of the way ------------------------------
sync 2>/dev/null
if mountpoint -q "$MNT"; then
    timeout 60 umount "$MNT" 2>/dev/null
    if mountpoint -q "$MNT"; then
        emit FAIL "umount=stuck rank=$RANK" "node could not unmount before the audit"
        exit 1
    fi
fi

if ! coord_barrier "chk_clean_quiesced"; then
    remount
    emit FAIL "barrier=quiesce rank=$RANK" "not every node reached the pre-audit rendezvous, so the device was not cold"
    exit 1
fi

# ---- rank 1 only: the audit ------------------------------------------------
rc=0; errs=0; alias_line=""; icount=""
if [ "$RANK" = 1 ]; then
    out=$(mktemp)
    if [ "$FSTYPE" = xfs ]; then
        xfs_repair -n "$DEV" > "$out" 2>&1; rc=$?
    elif [ ! -x "$CHK" ]; then
        coord_barrier "chk_clean_audited"
        remount
        emit FAIL setup "chk tool missing $CHK"
        exit 1
    else
        "$CHK" -v "$DEV" > "$out" 2>&1; rc=$?
    fi
    errs=$(grep -ciE 'error|corrupt|bad magic|inconsistent' "$out" 2>/dev/null)
    # The cross-tree aliasing check and the COLD superblock inode count are the
    # two numbers worth carrying onto the board.  sb_icount is kept lazily by
    # MXFS and written only at unmount, so this -- with every node out -- is the
    # only place in a run where reading it means anything.
    alias_line=$(grep -a 'Chunk/free-space aliasing' "$out" | head -1 | sed 's/^ *//;s/ \+/ /g')
    icount=$(sed -n 's/.*Superblock icount: *//p' "$out" | tail -1 | tr -d ' \r')
    # The cold icount is reported, never treated as ground truth: it is a
    # lazily-kept summary and the LAST unmount is what wrote it, so a stale or
    # node-local value can survive into a cold read.  It is a cross-check
    # against the btree-derived counts, not an oracle.
    #
    # COVERAGE.  A checker that printed nothing, died before reporting, or
    # never ran the cross-tree audit has established nothing -- and "no error
    # string appeared in the output" must never be read as "the volume is
    # clean".  These are the positive signs that the audit actually examined
    # this volume; without them the verdict below is INDETERMINATE, which fails
    # the gate for a different reason than corruption does.
    outbytes=$(wc -c < "$out" 2>/dev/null || echo 0)
    # THE COVERAGE WITNESS (design-consult ruling docs/rulings/audit-gate-
    # allocation-coverage-witness.md).  A clustered audit's CLEAN is a release
    # claim only when the alloc_witness row that ran immediately before it
    # proved the workload carved on both nodes at overlapping times inside
    # the AG partition the allocator is designed around, emptied a chunk and
    # reused it in place with no chunk release, moved the finobt on existing
    # chunks, and the cohort it retained is still allocated on the platter
    # the checker just walked with every target chunk matching its recorded
    # occupants and the superblock inode counts equal to the inobt sums.  The
    # witness lives in this tree (over NFS), never on the audited filesystem,
    # keyed by the run id the coordination prefix carries (so both rows must
    # run in ONE run.sh invocation); its fsid must be this platter's.
    # Single-node runs make no clustered claim and keep the structural verdict.
    witness_line=""
    if [ "$FSTYPE" != xfs ] && [ "$NODES" -ge 2 ]; then
        run_id=$(printf '%s' "${MXFS_COORD_PREFIX:-}" | awk -F/ '{print $3}')
        tree="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
        geo=$(mktemp)
        "$CHK" --geometry "$DEV" > "$geo" 2>&1
        platter_uuid=$(sed -n 's/^ *UUID: *//p' "$out" | head -1 | tr -d ' \r')
        witness_line=$(python3 "$tree/tests/tooling/alloc_witness_verdict.py" \
            "$tree/tests/evidence/alloc_witness/${run_id:-norun}" "$out" "$geo" "${run_id:-norun}" "$platter_uuid" 2>&1 | tail -1)
        rm -f "$geo"
        case "$witness_line" in release=*) ;; *) witness_line="release=INDETERMINATE reason=verdict helper failed: $witness_line" ;; esac
    fi
    # Keep the audit output where it survives a node reboot.  /tmp on these
    # nodes is wiped by the resets this rig performs constantly, and on a
    # corruption verdict this file is the only forensic record there is.
    EVID="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/evidence"
    mkdir -p "$EVID" 2>/dev/null
    chkout="$EVID/chk_clean_${NODES}node_$(date -u +%Y%m%dT%H%M%SZ).log"
    cp -f "$out" "$chkout" 2>/dev/null || chkout="(evidence copy failed)"
    rm -f "$out"
fi

coord_barrier "chk_clean_audited"

# ---- the verdict, decided BEFORE anything mounts again ---------------------
#
# Three outcomes, deliberately kept apart.  CORRUPT: the audit completed and
# found a structural violation.  INDETERMINATE: the audit established nothing
# -- it printed nothing, or it never reported the cross-tree check and the cold
# inode count -- which is a different failure from corruption and must never be
# aggregated as clean.  CLEAN: the audit completed, reported its cross-tree
# result, and found nothing.  A gate whose "could not check" is
# indistinguishable from "checked and fine" is the failure this whole row
# exists to stop being quoted as evidence.
#
# On CORRUPT this node does NOT remount.  Mounting replays the log and rewrites
# metadata, so remounting the volume the audit just condemned destroys the
# state that proves the verdict.  Coming back up is an obligation of the
# SUCCESS path, not an obligation to erase a failure.
#
# The limit, stated rather than papered over: preserving the IMAGE fleet-wide
# needs a verdict channel this harness does not have -- the other ranks decide
# for themselves and will remount -- so what is preserved here is the audit
# output plus this node staying out.  On a shared LUN that is partial
# preservation, and a corruption verdict should be treated as a reason to stop
# the run, not to carry on to the next row.
verdict=CLEAN
release=structural-only
if [ "$RANK" = 1 ]; then
    if [ "$rc" -ne 0 ] || [ "${errs:-0}" -gt 0 ]; then
        verdict=CORRUPT
    elif [ "${outbytes:-0}" -lt 1 ] || [ -z "$alias_line" ] || [ -z "$icount" ]; then
        verdict=INDETERMINATE
    fi
    # The release verdict is conjunctive: CORRUPT whatever the coverage; CLEAN
    # only when the structural audit is CLEAN and the witness confirms
    # coverage; VACUOUS when the audit is clean but a coverage floor was not
    # met with complete measurements; INDETERMINATE when the witness or the
    # audit established nothing.  Only release CLEAN passes the gate.
    if [ -n "$witness_line" ]; then
        wrel=$(printf '%s' "$witness_line" | grep -oE '^release=[A-Z]+' | cut -d= -f2)
        case "$verdict" in
        CORRUPT)        release=CORRUPT ;;
        INDETERMINATE)  release=INDETERMINATE ;;
        *)              release=${wrel:-INDETERMINATE} ;;
        esac
    fi
fi

# ---- everyone: come back, unless coming back would destroy the evidence ----
remounted=0
if [ "$RANK" = 1 ] && [ "$verdict" = CORRUPT ]; then
    :
else
    remount
    mountpoint -q "$MNT" && remounted=1
fi

# Every node must report the audit's verdict, so rank>1 needs it too; but a
# node that did not audit must never claim to have.  Ranks other than 1 assert
# only what they can see themselves -- that they unmounted and came back.
if [ "$RANK" = 1 ]; then
    m="verdict=$verdict release=$release rc=$rc errors=${errs:-0} remounted=$remounted icount=${icount:-?} ${alias_line:-aliasing=not-reported} evidence=${chkout:-none} ${witness_line:+${witness_line%% reason=*}}"
    wreason=$(printf '%s' "$witness_line" | sed -n 's/.* reason=//p')
    case "$verdict" in
    CORRUPT)
        emit FAIL "$m" "the cold audit found a structural violation; this node was left unmounted so a remount does not rewrite the image that proves it" ;;
    INDETERMINATE)
        emit FAIL "$m" "the audit established nothing — no output, or the cross-tree check and cold inode count were never reported; not checked is not clean" ;;
    *)
        if [ "$remounted" != 1 ]; then
            emit FAIL "$m" "the audit was clean but this node could not remount; the fleet is degraded"
        elif [ "$release" = VACUOUS ]; then
            emit FAIL "$m" "the audit was clean but the coverage witness shows the workload did not exercise what the audit claims to cover: $wreason"
        elif [ "$release" = INDETERMINATE ]; then
            emit FAIL "$m" "the audit was clean but no trustworthy coverage witness exists for this run, so the CLEAN is not a release claim: $wreason"
        else
            emit PASS "$m"
        fi ;;
    esac
else
    if [ "$remounted" = 1 ]; then
        emit PASS "rank=$RANK role=quiesced remounted=1"
    else
        emit FAIL "rank=$RANK role=quiesced remounted=0" "node could not remount after the audit"
    fi
fi
exit 0
