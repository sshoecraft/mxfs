#!/bin/bash
# run.sh — conditions-runner.  Prep the cluster for a (node-count, transport)
# condition, run EVERY applicable test under that condition, aggregate per-node
# results, and record them into criteria.json (single source of truth) keyed by
# "<N>/<dlm>".  Also writes .last_run.json (this run's summary).
#
# Usage:  ./run.sh <N> <dlm> [test ...]
#   <N>    participating node count (nodes test1..testN)
#   <dlm>  transport: tcp | caw
#   [test] optional explicit test names to run (default: all applicable)
#
# Applicability of a matrix test at (N, dlm):
#   - category transport is "any" OR == dlm, AND
#   - min_nodes <= N <= (max_nodes==0 ? infinity : max_nodes), AND
#   - a script exists for it (else PENDING, not recorded).
#
# Coordination:
#   - coord=none            -> run on test1 only (single mount; records result).
#   - coord=barrier/ordered/fault -> launch on ALL N nodes in parallel with a
#     per-test MQTT coord namespace; aggregate (PASS iff every node PASSes).
#
# Layering (docs/test_suite_design.md): this is the HARNESS.  It owns node set,
# transport prep (config layer via tests/setup/*), MQTT broker/identity, and
# aggregation.  Test scripts stay agnostic — they see only a mount point + the
# opaque coord_* calls.

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$REPO"

N="${1:?usage: run.sh <N> <dlm> [test ...]}"
DLM="${2:?usage: run.sh <N> <dlm> [test ...]}"
shift 2 || true
ONLY=("$@")                                   # explicit test subset (optional)

case "$DLM" in tcp|caw|cawd|cawp|xfs) ;; *) echo "dlm must be tcp|caw|cawd|cawp|xfs (got '$DLM')"; exit 2 ;; esac
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] || { echo "N must be a positive integer"; exit 2; }
# ---------------------------------------------------------------------------
# Deployment conditions (conditions.md): the <dlm> axis doubles as the rig/
# condition axis, so criteria.json cells stay keyed "<N>/<dlm>" and each of
# the four deployment conditions gets its own column:
#   tcp  = condition 1: TCP DLM / commodity block (LIO tcm_loop rig,
#          /dev/mxfs-shared wired into VM XML -> guest /dev/sda, LIO-ORG).
#   cawp = condition 2: CAW via FC-fabric-sim passthrough (SCST per-node
#          targets, host by-path dev wired into VM XML -> guest /dev/sda).
#   cawd = condition 3: CAW via direct in-guest iSCSI (single portal .1,
#          raw single-path sdX; stable by-path symlink used as MXFS_DEV).
#   caw  = condition 4: CAW over dm-multipath (dual portal + multipathd ->
#          /dev/mapper/mpatha).  Every historical "N/caw" cell was recorded
#          on this rig, so the name keeps its meaning.
# BASE_TRANSPORT is what the module/prep layer consumes (tcp|caw|xfs); the
# full $DLM string keys criteria.json cells, the cluster marker, and bench
# labels.  Category applicability matches on the BASE transport (a "caw"
# category test applies to all three CAW conditions).
# ---------------------------------------------------------------------------
case "$DLM" in
    cawd|cawp) BASE_TRANSPORT=caw ;;
    *)         BASE_TRANSPORT="$DLM" ;;
esac
transport_matches() {  # <category-transport> -> 0 iff applicable under $DLM
    [ "$1" = any ] || [ "$1" = "$BASE_TRANSPORT" ]
}
# xfs = native-XFS single-node timing baseline (no mxfs.ko, no DLM, no cluster
# — XFS isn't clustered). Only meaningful at N=1; used to derive RULE 0 time
# budgets for the mxfs conditions (see tests/suite/manifest header).
[ "$DLM" = xfs ] && [ "$N" -ne 1 ] && { echo "dlm=xfs is a single-node baseline — N must be 1 (got $N)"; exit 2; }
# Tests that are pure FS-content/perf correctness (agnostic to mxfs internals),
# PLUS the device/mount-lifecycle tooling tests that have a direct native-XFS
# tool equivalent (mkfs.xfs, xfs_repair, xfs_growfs, plain mount/umount) --
# each of those scripts branches internally on MXFS_EXPECT_FSTYPE=xfs.
# Everything else (module-specific: dkms_install; tests that already embed
# their OWN internal xfs-vs-mxfs A/B and therefore need mxfs.ko to run at all:
# single_node_paired, fio_vs_xfs_baseline; every multi-node/coordinated test)
# has no meaningful xfs-mode invocation -- those get an explicit SKIP below
# rather than being silently left PENDING forever.
XFS_APPLICABLE=(precond_readiness posix_single fsx fio_verify integrity_filetypes fio_perf fault_enospc soak
                mkfs_timing chk_clean online_resize cluster_ops_timing fault_io_error dir_reuse_coherency
                cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss
                dlm_fairness scaling_curve dlm_scaling rsync_paired crash_consistency)
xfs_applicable() { local t; for t in "${XFS_APPLICABLE[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }
# Explicit SKIP (not silent PENDING) under DLM=xfs: no native-XFS equivalent.
XFS_NO_EQUIVALENT=(dkms_install single_node_paired fio_vs_xfs_baseline fio_perf_vs_xfs)
xfs_no_equivalent() { local t; for t in "${XFS_NO_EQUIVALENT[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }

SSH="$REPO/tools/mxfs_sshpass.sh"
# Node SSH password: resolved from the lab secrets store (~/.config/mxfslab/secrets
# via tools/mxfs_secrets.sh), which materializes the sshpass passfile. Falls back to
# a pre-existing /tmp/.mxfs_pass if the store is absent. MXFS_PASS still overrides.
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile 2>/dev/null || echo /tmp/.mxfs_pass)}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
# Per-condition default shared-LUN device (MXFS_DEV always overrides):
#   caw  -> the multipathd-assembled map (2 paths).
#   cawd -> the stable by-path node for the single-portal login; identical on
#           every node regardless of sdX ordering.
#   cawp/tcp -> the XML-wired guest disk (virsh target dev=sda).
#   xfs  -> whatever LUN the live rig presents at sda (baseline only).
case "$DLM" in
    caw)  DEV_DEFAULT=/dev/mapper/mpatha ;;
    cawd) DEV_DEFAULT="/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0" ;;
    *)    DEV_DEFAULT=/dev/sda ;;
esac
DEV="${MXFS_DEV:-$DEV_DEFAULT}"
# Cells are keyed "<N>/<dlm>" with no rig dimension, so running the same
# condition against a DIFFERENT rig overwrites the board in place.  Point
# MXFS_CRIT at a separate file to keep a second rig's results off the primary
# board (e.g. MXFS_CRIT=$REPO/criteria.pve.json for the Proxmox nodes).
CRIT="${MXFS_CRIT:-$REPO/criteria.json}"
LAST="$REPO/.last_run.json"
# ---------------------------------------------------------------------------
# Cluster-state marker (2026-07-14): records what (nodes, dlm, build) the
# cluster is CURRENTLY formed for. A filtered invocation (specific test names)
# skips prep entirely if the marker matches, and hard-errors if it doesn't —
# a mismatch means "you're asking for a different condition than what's
# actually live," and silently re-forming would both mask that mistake and
# burn a full teardown/reform+converge cycle (seen firsthand: repeated
# same-condition single-test reruns each paying a fresh ~100s+ convergence
# wait for a cluster that was already correctly formed). An unfiltered
# invocation (no test names = "fully validate this condition") always preps
# and refreshes the marker regardless of its prior content.
MARKER="$REPO/.cluster_marker.json"
# srcversion identifies the BUILD, not just the DLM/N — a rebuilt mxfs.ko
# needs reform even at the same node count/transport (mirrors prep_cluster's
# own existing build-mismatch check). xfs mode has no module, so it gets a
# fixed sentinel instead.
if [ "$DLM" = xfs ]; then
    WANT_SRCVER="xfs-no-module"
else
    WANT_SRCVER=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion:/{print $2}')
fi
marker_read() {  # sets MK_NODES / MK_DLM / MK_SRCVER / MK_NODELIST (empty if no marker file)
    MK_NODES=""; MK_DLM=""; MK_SRCVER=""; MK_NODELIST=""
    [ -s "$MARKER" ] || return 0
    MK_NODES=$(jq -r '.nodes // empty' "$MARKER" 2>/dev/null)
    MK_DLM=$(jq -r '.dlm // empty' "$MARKER" 2>/dev/null)
    MK_SRCVER=$(jq -r '.srcversion // empty' "$MARKER" 2>/dev/null)
    MK_NODELIST=$(jq -r '.node_list // empty' "$MARKER" 2>/dev/null)
}
marker_write() {  # nodes dlm srcver — node_list records WHICH hosts were prepped
    local nl; nl=$(IFS=,; echo "${NODES[*]}")
    jq -n --argjson n "$1" --arg d "$2" --arg s "$3" --arg nl "$nl" --arg t "$(date -u +%FT%TZ)" \
        '{nodes:$n, dlm:$d, srcversion:$s, node_list:$nl, iso:$t}' > "$MARKER" 2>/dev/null
}
# A marker match is a claim about LIVE cluster state, so verify it live: the
# marker file survives reboots, other campaigns' module reloads, and rig
# switches (MXFS_NODE_LIST), all of which invalidate the prep silently.
# (2026-07-25: a physrig-session marker matched a VM-fleet invocation and 5
# tests were recorded PASS against a stale build — hence this check.)
marker_live_ok() {
    [ "$DLM" = xfs ] && return 0
    local cn live
    for cn in "${NODES[@]}"; do
        live=$(ssh_node "$cn" "cat /sys/module/mxfs/srcversion 2>/dev/null; mountpoint -q /mnt/shared && echo MOUNTED" | tr '\n' ' ')
        live=$(echo $live)   # squeeze/trim whitespace (ssh banner filtering can pad)
        case "$live" in
            "$WANT_SRCVER MOUNTED"*) ;;
            *) echo "    marker stale: $cn live='$live' want='$WANT_SRCVER MOUNTED'"; return 1 ;;
        esac
    done
    return 0
}
marker_matches() {
    [ "$MK_NODES" = "$N" ] && [ "$MK_DLM" = "$DLM" ] && [ "$MK_SRCVER" = "$WANT_SRCVER" ] \
        && [ "$MK_NODELIST" = "$(IFS=,; echo "${NODES[*]}")" ] && marker_live_ok
}
BROKER="${MXFS_COORD_BROKER:-192.168.1.149}"
# Per-test wall budget for coordinated launches (RULE 0: a timeout IS a FAIL).
# coord_barrier waits up to COORD_TIMEOUT (120s); give the launch headroom.
COORD_TIMEOUT="${COORD_TIMEOUT:-120}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"

# Node set: defaults to the project's own test1..testN fleet, but can be
# pointed at arbitrary hosts (e.g. a Proxmox pair, or any other cluster not
# using the test1..testN naming/DNS convention) via MXFS_NODE_LIST -- a
# space- or comma-separated list of hostnames/IPs, exactly $N entries.
if [ -n "${MXFS_NODE_LIST:-}" ]; then
    mapfile -t NODES < <(echo "$MXFS_NODE_LIST" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d')
    [ "${#NODES[@]}" -eq "$N" ] || {
        echo "ERROR: MXFS_NODE_LIST has ${#NODES[@]} entries, N=$N requires exactly $N"
        exit 2
    }
else
    mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
fi
NODE1="${NODES[0]}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"

[ -s "$CRIT" ] || { echo "ERROR: $CRIT missing (run scripts/gen_criteria.py)"; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq required"; exit 1; }

# sess3 (ccloop 46efd8b6): EXCLUSIVE run lock.  Stale ccloop sessions survive
# the relay and keep launching run.sh from their afterlife — a rival instance
# power-cycles "extra" nodes / re-preps the shared LUN MID-RUN and fabricates
# failures (membership splits, mass reboots, EIO-dead mounts).  Two run.sh
# instances must NEVER overlap: fail fast and name the holder so the operator
# kills it (see memory infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START).
RUNLOCK=/tmp/mxfs_run.lock
# sess41: run.sh leaks ~5GB of /tmp/run_* artifacts per criterion invocation;
# two days of boards filled the 1.8T root fs to 100% (ENOSPC mid-board,
# session 23).  Prune anything older than 6h before taking the lock.
[ -x "$(dirname "$0")/tests/host_tmp_clean.sh" ] && \
    "$(dirname "$0")/tests/host_tmp_clean.sh" 6 >/dev/null 2>&1 || true
exec 9>"$RUNLOCK"
if ! flock -n 9; then
    # Holder triage.  A LIVE competing run.sh => hard fail, never stomp a run
    # in flight.  But children of a KILLED run.sh inherit fd 9 and keep the
    # flock alive from PPID 1 (sshpass/timeout pinned on a dead node) — with
    # no run.sh among the living, reap the orphans and take the lock.
    # (PID 2596127's whole rung burned refusing an orphan-held lock, and the
    # old `fuser | tail -2` truncation hid the true holders behind run.sh's
    # own fuser-pipeline children.)
    live=""
    for p in $(pgrep -x run.sh); do
        [ "$p" = "$$" ] && continue
        c=$(ps -o comm= -p "$p" 2>/dev/null); [ -z "$c" ] && continue
        live="$live $p"
    done
    if [ -z "$live" ]; then
        holders=$( exec 9>&-; fuser "$RUNLOCK" 2>/dev/null )
        orphans=""
        for p in $holders; do [ "$p" != "$$" ] && orphans="$orphans $p"; done
        if [ -n "$orphans" ]; then
            echo "WARN: $RUNLOCK held only by orphans of a dead run.sh — reaping:$orphans"
            ps -o pid,ppid,etime,args -p $orphans 2>/dev/null | sed 's/^/    /'
            kill -TERM $orphans 2>/dev/null; sleep 2; kill -KILL $orphans 2>/dev/null; sleep 1
        fi
    fi
    if ! flock -n 9; then
        echo "ERROR: another run.sh holds $RUNLOCK — refusing to stomp its cluster:"
        ( exec 9>&-; fuser -v "$RUNLOCK" 2>&1 ) | sed 's/^/    /'
        echo "  (kill the holder — likely a stale ccloop session's leftover — then retry)"
        exit 3
    fi
fi
echo "$$ $(date -u +%FT%TZ) run.sh $N $DLM ${ONLY[*]:-}" >&9

# The REMOTE command's exit status must survive.  As a bare pipeline this
# returned grep's status instead (no pipefail here), so any check whose remote
# command is silent by design -- `mount | grep -q ...` at the two readiness
# gates below -- resolved on whether ssh printed a login banner rather than on
# what the remote actually did: test1's /etc/issue.net carries blank lines that
# outlive the filter (grep -v emits them => always 0, gate inert), Proxmox has
# no banner (nothing survives => always 1, gate always fails).  PIPESTATUS[0]
# keeps the filter streaming (line 828 pipes a multi-MB base64 tar through
# here, so buffering the output in a variable is not an option).
ssh_node() {
    local rc
    "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'
    rc=${PIPESTATUS[0]}
    return "$rc"
}

# sess11 (ccloop c7ee71c6): foreign-kernel fleets (physrig: 6.17.2-1-pve vs
# clyde's 6.8 repo build) — the artifact under test is the NODE-INSTALLED
# module, so the marker identity must be its srcversion, not the repo .ko's
# (same doctrine as prep_cluster's build-ref resolution at ~line 540; without
# this the marker written after a physrig prep never matches marker_live_ok
# and every row invocation demands a re-prep).
if [ "$DLM" != xfs ]; then
    _repo_vermagic=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^vermagic:/{print $2}')
    _node_krel=$(ssh_node "$NODE1" "uname -r" 2>/dev/null | tr -d '\r\n ')
    if [ -n "$_node_krel" ] && [ -n "$_repo_vermagic" ] && [ "$_repo_vermagic" != "$_node_krel" ]; then
        _node_srcv=$(ssh_node "$NODE1" "modinfo -F srcversion mxfs 2>/dev/null" 2>/dev/null | tr -d '\r\n ')
        if [ -n "$_node_srcv" ]; then
            WANT_SRCVER="$_node_srcv"
            echo "--- foreign-kernel fleet: build ref = node-installed mxfs $WANT_SRCVER (repo ko is $_repo_vermagic, nodes run $_node_krel) ---"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Record one test's aggregated result into criteria.json under "<N>/<dlm>".
# elapsed/budget are seconds (integers; "" if not timed, e.g. SKIP markers).
# RULE 0 (CLAUDE.md): a timeout IS a test failure, even with zero correctness
# errors. If the functional result was PASS but elapsed exceeded budget, this
# overrides status to FAIL here — the harness-level time gate, independent of
# whatever set_script_timeout/hard-kill already did.
#
# RULE0_CALIBRATE=1 (env, set by the caller): this is a MEASUREMENT run to
# establish a budget that doesn't exist yet -- there is nothing to enforce, so
# skip the override entirely (see the matching tt inflation in run_coord/
# run_none) and tag the record so it reads as unenforced calibration data, not
# a real pass.
# ---------------------------------------------------------------------------
record() {  # name status measured reason [elapsed] [budget]
    local name="$1" status="$2" measured="$3" reason="$4" elapsed="${5:-}" budget="${6:-}"
    if [ "${RULE0_CALIBRATE:-0}" = 1 ] && [ -n "$elapsed" ]; then
        reason="[CALIBRATION: budget not enforced, elapsed=${elapsed}s]${reason:+ }$reason"
    elif [ "$status" = PASS ] && [ -n "$elapsed" ] && [ -n "$budget" ] \
       && [ "$elapsed" -gt "$budget" ] 2>/dev/null; then
        status=FAIL
        reason="RULE-0 budget exceeded: elapsed=${elapsed}s > budget=${budget}s (functional checks passed)${reason:+; }$reason"
    fi
    # sess23 (ccloop c7ee71c6) — KEEP A FLAKE HISTORY.
    #
    # A cell used to hold ONLY its latest result, so an intermittent criterion
    # went green the moment a run got lucky and the previous failure vanished.
    # Measured this session: `dirent_durability` FAILED once with
    # durable_loss=3 and then PASSed 18 consecutive times — and the board
    # showed nothing but the last PASS. For the critical defects that reproduce
    # ~1 run in 10, that makes a green cell meaningless and an A/B arm
    # worthless.
    #
    # So each write PUSHES the outgoing verdict onto a bounded per-cell history
    # (last 10, newest first). showstat annotates any green cell whose history
    # contains a recent FAIL, so "PASS, but 1 of the last 12 runs FAILED" is
    # visible instead of hidden. This is recorded for EVERY criterion, not just
    # the known-flaky ones — the point is to discover which ones are flaky.
    #
    # sess43: the history entry MUST carry `reason` too.  The node-side
    # finish() names every failing check in reason= (FAILED[] descriptions),
    # and the aggregator records it on the live cell — but the history push
    # dropped it, so the moment the next run overwrote the cell the evidence
    # was gone.  That single omission is why D-DIR-REUSE-COHERENCY sat
    # "UNROOTED: which check failed is not yet captured" and why the Aug-1
    # 23:32 cache_coherency/zsl failures could not be attributed from the
    # record: the answer had been written down and then discarded.
    local cond="${N}/${DLM}" tmp; tmp=$(mktemp)
    jq --arg k "$name" --arg c "$cond" --arg s "$status" \
       --arg m "$measured" --arg r "$reason" --arg t "$(date -u +%FT%TZ)" \
       --argjson e "${elapsed:-null}" --argjson b "${budget:-null}" \
       '.categories[].tests |= map(if .name==$k then
           ( ( (.runs[$c].history // []) as $h
             | (if ((.runs[$c].status // "") | . == "" or . == "PENDING") then $h
                else ([{status:.runs[$c].status, iso:.runs[$c].iso,
                        measured:.runs[$c].measured,
                        reason:((.runs[$c].reason // "")[0:400])}] + $h)[0:10] end) ) as $nh
           | .runs[$c]={status:$s,measured:$m,reason:$r,iso:$t,
                        elapsed_s:$e,budget_s:$b,history:$nh} )
         else . end)' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
}


# ---------------------------------------------------------------------------
# sess23 (ccloop c7ee71c6) — RECONVERGENCE GATE BETWEEN CRITERIA.
#
# `crash_consistency` deliberately `virsh destroy`s a node.  It used to RETURN
# as soon as its own checks passed, while the killed node was still rejoining.
# Two separate falsehoods followed:
#   1. its own verdict read FAIL nodes_pass=9/16 with checks=354 passed=354
#      failed=0 — i.e. every check it ran passed, but peers that had not
#      rejoined yet were scored as failing nodes; and
#   2. every criterion ordered after it inherited the same half-formed cluster
#      (kernel_health FAIL 15/16 with hits=0 kinds=[] — it detected nothing,
#      one node just never reported).
# Three untrustworthy cells per sweep, none of them a real fault.
#
# Per GPT (RULE 5 consult): the destructive criterion OWNS its postcondition —
# it may not be recorded PASS until the cluster has reconverged — and the
# driver ALSO gates the next criterion, as defence against any test leaving
# the cluster unhealthy.  Waiting cannot mask a genuine failure to rejoin,
# because failing to reconverge inside the deadline IS the red assertion: we
# overwrite the destructive test's own result with FAIL, and mark everything
# after it BLOCKED rather than running it against a broken cluster.
DESTRUCTIVE_TESTS=" crash_consistency fence_during_write fault_netpartition "

wait_converged() {   # <deadline_seconds> -> 0 converged, 1 did not
    local dl=$(( SECONDS + ${1:-120} )) stable=0 cgd n all
    [ "$N" -gt 1 ] || return 0
    while [ "$SECONDS" -lt "$dl" ]; do
        cgd=$(mktemp -d)
        for n in "${NODES[@]}"; do
            # LIVENESS first, beacon second.  The membership beacon is a dmesg
            # line and dmesg is a RING: on a node that has been up a while it
            # scrolls out, and then "no beacon" is indistinguishable from "not
            # converged".  That is exactly the trap this project has been
            # burned by before (never judge a condition by a bare dmesg grep) —
            # it made a perfectly healthy 16/16-mounted, writable cluster read
            # as RECONVERGENCE FAILED because ONE node's beacon had aged out.
            # So: a node counts as converged when it is mounted AND its
            # filesystem answers, and — only if a beacon is still in the ring —
            # that beacon agrees the cluster is N.  A beacon that DISAGREES is
            # still a hard fail (real split-brain), which is the case that
            # matters; an absent beacon is simply no evidence either way.
            ( ssh_node "$n" "mountpoint -q '$MNT' && ls '$MNT' >/dev/null 2>&1 && { ac=\$(dmesg | awk '/DLM initialized/{m=\"\"} /MXFS-MEMBERSHIP/{m=\$0} END{print m}' | grep -oE 'active_count=[0-9]+' | cut -d= -f2); echo \"ALIVE:\${ac:-none}\"; }" 2>/dev/null | tr -d '\r\n ' > "$cgd/$n" ) &
        done
        wait
        all=1
        local over=0
        for n in "${NODES[@]}"; do
            case "$(cat "$cgd/$n" 2>/dev/null)" in
                "ALIVE:$N"|"ALIVE:none") ;;      # healthy, or no beacon left in the ring
                ALIVE:*)
                    # sess43: a beacon ABOVE N is the normal aftermath of any
                    # fault-injecting test.  A node that dies and rejoins takes
                    # a NEW node_id, and the lease keeps the dead identity for
                    # MXFS_LEASE_TIMEOUT_DEFAULT_MS = 600000 ms (TEN MINUTES,
                    # lease.h:58) — far longer than this gate's window.  The
                    # old code read that as disagreement and BLOCKED every
                    # remaining criterion in the chunk on a fully healthy
                    # cluster (measured at 32/caw after crash_consistency:
                    # beacon 33, disk table exactly 32 correct members, beacon
                    # back to 32 on schedule).  Defer the verdict to the
                    # authoritative on-disk heartbeat table below; a count
                    # BELOW N is still an immediate fail.
                    local ac; ac=$(cat "$cgd/$n" 2>/dev/null | cut -d: -f2)
                    if [ "${ac:-0}" -gt "$N" ] 2>/dev/null; then over=1; else all=0; fi ;;
                *) all=0 ;;                      # unmounted/unresponsive
            esac
        done
        rm -rf "$cgd"
        # Only when some beacon over-counts: ask the disk.  Exactly N live
        # heartbeat writers = healthy (the excess is a lease-aging identity);
        # more than N = genuine split-brain and still a hard fail.
        if [ "$all" = 1 ] && [ "$over" = 1 ]; then
            local hbl; hbl=$(bash "$REPO/tests/hb_live_count.sh" "${NODES[0]}" "$DEV" 4 2>/dev/null)
            if [ "$hbl" = "$N" ]; then
                echo "    (beacon over-counts — disk heartbeat table shows exactly $N live members; lease is aging a dead identity, not split-brain)"
            else
                all=0
            fi
        fi
        if [ "$all" = 1 ]; then
            stable=$((stable+1))
            [ "$stable" -ge 3 ] && return 0
        else
            stable=0
        fi
        sleep 2
    done
    return 1
}

# Parse one RESULT line's "key=value | key=value" field.
field() { awk -F' \\| ' -v key="$1" \
    '{for(i=1;i<=NF;i++){n=index($i,"=");if(n&&substr($i,1,n-1)==key)print substr($i,n+1)}}'; }

# ---------------------------------------------------------------------------
# Cluster prep for this condition (config layer).
# ---------------------------------------------------------------------------
# Teardown snippet run ON a node: unmount + unload mxfs, print MXFS_CLEAN on
# success or MXFS_STILL_LOADED if the module survives every attempt.  fuser -km
# kills leftover test processes holding the mount (a plain umount then works);
# without the kill a busy mount silently survives and the node keeps running
# the OLD filesystem while the LUN is re-mkfs'd under it (sess5/sess6 2-caw
# formation failure: stale mount passed the readiness check, announced under
# the old FS uuid, and the new cluster never saw it).
TEARDOWN='
    for t in 1 2 3 4 5; do
        mountpoint -q MNTPT || break
        fuser -km MNTPT 2>/dev/null; sleep 1
        umount MNTPT 2>/dev/null && break
        timeout 20 umount -f MNTPT 2>/dev/null && break
        sleep 1
    done
    mountpoint -q MNTPT && umount -l MNTPT 2>/dev/null
    sleep 1
    for t in 1 2 3 4 5; do
        lsmod | grep -q "^mxfs " || break
        rmmod mxfs 2>/dev/null && break
        sleep 2
    done
    if lsmod | grep -q "^mxfs "; then echo MXFS_STILL_LOADED; else echo MXFS_CLEAN; fi'

# Power-cycle a wedged node (virsh destroy+start) and wait for ssh + the shared
# device to come back.  Recovery of TEST VMs only (never the host — RULE 2).
power_cycle_node() {  # <node>  -> 0 once node is reachable and DEV present
    local n="$1" dl
    # This recovery is libvirt-only: it assumes the node IS a VM in the local
    # test fleet whose domain name equals the node name.  Under MXFS_NODE_LIST
    # the nodes are external (IPs / real hosts) and no such domain exists, so
    # virsh silently no-ops and we would report a "power-cycle" that never
    # happened -- then march on and mount whatever wedged state was already
    # there (seen 2026-07-20 against Proxmox: pve2 had a withdrawn, shut-down
    # FS that never released; prep "recovered" it and the cluster split 2-vs-1).
    # Refuse loudly instead: an external node needs a real operator decision.
    if [ -n "${MXFS_NODE_LIST:-}" ]; then
        echo "    CANNOT auto-recover $n: MXFS_NODE_LIST nodes are external —"
        echo "    virsh has no domain for them and power-cycling is not this"
        echo "    harness's call.  Clear it by hand, then re-run:"
        echo "      umount -f $MNT (or -l); rmmod mxfs   # check 'dmesg | grep P-WITHDRAW'"
        echo "    A shut-down/withdrawn FS holds the module and will NOT release."
        return 1
    fi
    echo "    power-cycling $n (virsh destroy+start)"
    virsh -c qemu:///system destroy "$n" >/dev/null 2>&1
    sleep 2
    virsh -c qemu:///system start "$n" >/dev/null 2>&1
    dl=$(( SECONDS + 180 ))
    while [ "$SECONDS" -lt "$dl" ]; do
        if timeout 8 "$SSH" "$n" "$PASS" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP; then
            # sess1 (ccloop 26c41354): a rebooted VM loses /src (NFS is
            # deliberately NOT an fstab automount) and its boot self-heal often
            # re-logs only ONE iSCSI portal, so /dev/mapper/mpatha never
            # assembles.  Without this, prep dies later with "prep_fs.sh /
            # prep_node.sh: No such file" or this DEV wait times out.  Restore
            # /src + the CONDITION-appropriate device path before waiting for
            # $DEV: caw (mpath) needs both portals + multipath assembly; cawd
            # (direct) needs a clean single-portal login (logout+delete stale
            # records first — leftover mpath-era .2 records would otherwise
            # create a second path and multipathd would swallow the raw sdX);
            # cawp/tcp/xfs devices are XML-wired and appear at boot on their
            # own.
            local restore_iscsi=''
            case "$DLM" in
                caw)  restore_iscsi='
                    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
                    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
                    iscsiadm -m node --login >/dev/null 2>&1
                    iscsiadm -m session --rescan >/dev/null 2>&1
                    multipath >/dev/null 2>&1' ;;
                cawd) restore_iscsi='
                    iscsiadm -m node -u >/dev/null 2>&1
                    iscsiadm -m node -o delete >/dev/null 2>&1
                    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
                    iscsiadm -m node --login >/dev/null 2>&1
                    iscsiadm -m session --rescan >/dev/null 2>&1' ;;
            esac
            timeout 70 "$SSH" "$n" "$PASS" "
                mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
                $restore_iscsi" >/dev/null 2>&1
            local dl2=$(( SECONDS + 90 ))
            local retry_mp=''
            [ "$DLM" = caw ] && retry_mp='multipath >/dev/null 2>&1'
            while [ "$SECONDS" -lt "$dl2" ]; do
                timeout 8 "$SSH" "$n" "$PASS" "[ -e '$DEV' ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && return 0
                timeout 20 "$SSH" "$n" "$PASS" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; $retry_mp" >/dev/null 2>&1
                sleep 3
            done
            echo "    WARN: $n booted but $DEV never appeared"
            return 1
        fi
        sleep 3
    done
    echo "    WARN: $n did not answer ssh within 180s of power cycle"
    return 1
}

prep_cluster() {
    echo "--- prep: $N node(s) [${NODES[*]}] transport=$DLM ---"

    # 0. Tear down leftover mxfs on running test VMs OUTSIDE this run's set.
    #    A downward ladder transition (4/caw -> 2/caw) otherwise leaves
    #    test(N+1..) mounted + heartbeating on the LUN we are about to
    #    re-mkfs: they join the new cluster's discovery (active_count
    #    inflates past N so the converge gate can never pass) and later
    #    P131-self-fence when they notice the re-mkfs (sess5 evidence).
    #    This is entirely about this project's own libvirt test1..testN
    #    fleet (virsh list/destroy/start against qemu:///system) -- with an
    #    external node list (MXFS_NODE_LIST) there is no local fleet to
    #    check, and running this against unrelated hosts by IP would be
    #    meaningless at best (virsh's list never matches an IP) so just
    #    skip it rather than pay the virsh round-trip for nothing.
    if [ -z "${MXFS_NODE_LIST:-}" ]; then
    local v extras=() epids=() dirty=""
    for v in $(virsh -c qemu:///system list --name 2>/dev/null | grep -E '^test[0-9]+$'); do
        case " ${NODES[*]} " in *" $v "*) ;; *) extras+=("$v") ;; esac
    done
    if [ "${#extras[@]}" -gt 0 ]; then
        for v in "${extras[@]}"; do
            ( timeout 100 "$SSH" "$v" "$PASS" "${TEARDOWN//MNTPT/$MNT}" > "/tmp/.mxfs_td.$v" 2>/dev/null ) &
            epids+=($!)
        done
        for v in "${epids[@]}"; do wait "$v"; done
        for v in "${extras[@]}"; do
            grep -q MXFS_CLEAN "/tmp/.mxfs_td.$v" 2>/dev/null || dirty="$dirty $v"
            rm -f "/tmp/.mxfs_td.$v"
        done
        if [ -n "$dirty" ]; then
            # A leftover node that won't release mxfs keeps heartbeating onto
            # the LUN and corrupts the new cluster — power it off/on.  No need
            # to wait for extras to boot; they only must stop writing.
            echo "--- prep: leftover node(s) still hold mxfs:$dirty — power-cycling ---"
            epids=()
            for v in $dirty; do
                ( virsh -c qemu:///system destroy "$v" >/dev/null 2>&1
                  sleep 1
                  virsh -c qemu:///system start "$v" >/dev/null 2>&1 ) &
                epids+=($!)
            done
            for v in "${epids[@]}"; do wait "$v"; done
        fi
    fi
    fi

    # 1. Clean slate on the participating nodes so the LUN is free to
    #    reformat — and VERIFY it took.  A silently-failed teardown here left
    #    test2 running the previous run's mount in sess5 (the readiness check
    #    below can't tell a stale same-build mount from a fresh one).
    local n pids=() td; td=$(mktemp -d)
    for n in "${NODES[@]}"; do
        ( timeout 150 "$SSH" "$n" "$PASS" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done
                         mountpoint -q /src && echo SRC_OK || echo SRC_MISSING
                         ${TEARDOWN//MNTPT/$MNT}
                         mkdir -p /etc/systemd/journald.conf.d
                         printf '[Journal]\nRuntimeMaxUse=400M\nRateLimitBurst=0\nRateLimitIntervalSec=0\n' > /etc/systemd/journald.conf.d/mxfs-test.conf
                         systemctl restart systemd-journald 2>/dev/null
                         sysctl -w kernel.printk='1 4 1 1' >/dev/null 2>&1
                         true" > "$td/$n" 2>&1 ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    local esc=()
    for n in "${NODES[@]}"; do
        grep -q MXFS_CLEAN "$td/$n" 2>/dev/null && grep -q SRC_OK "$td/$n" 2>/dev/null && continue
        echo "--- prep: $n did not release mxfs / lost /src (or unreachable) — escalating ---"
        esc+=("$n")
    done
    if [ "${#esc[@]}" -gt 0 ]; then
        # Power-cycle ALL wedged nodes in parallel — the old per-node serial
        # loop took ~40s/node (a fully-dirty 32-node cluster = 20+ min of
        # power-cycling alone, blowing every prep budget before tests began).
        pids=()
        for n in "${esc[@]}"; do
            ( power_cycle_node "$n" > "$td/pc.$n" 2>&1 ) &
            pids+=($!)
        done
        local pcfail="" i=0
        for n in "${esc[@]}"; do
            wait "${pids[$i]}" || pcfail="$pcfail $n"
            i=$((i+1))
            cat "$td/pc.$n" 2>/dev/null
        done
        if [ -n "$pcfail" ]; then
            echo "PREP FAIL: unusable after power cycle:$pcfail"
            rm -rf "$td"; return 1
        fi
    fi
    rm -rf "$td"

    # 1b. sess9 (ccloop 72513a13): ensure /src on EVERY node before any
    # /src-sourced script runs.  A node that (re)booted outside prep's own
    # power_cycle path (crash tests, manual virsh, guest panic) arrives with
    # /src unmounted (NFS is deliberately NOT an fstab automount — see
    # ccmemory feedback-src-nfs-not-fstab-automount) and prep then dies at
    # step 3/4 with "prep_node.sh: No such file" — hit twice today
    # (test17/23, then test10/12/25/31 at the 32/tcp rung).
    local sp_tmpd sp_bad="" sp_n
    local -a sp_pids=()
    sp_tmpd=$(mktemp -d)
    for sp_n in "${NODES[@]}"; do
        ( timeout 40 "$SSH" "$sp_n" "$PASS" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; mountpoint -q /src && echo SRC_OK" 2>/dev/null \
              | grep -q SRC_OK || echo bad > "$sp_tmpd/$sp_n" ) &
        sp_pids+=($!)
    done
    for sp_n in "${sp_pids[@]}"; do wait "$sp_n"; done
    for sp_n in "${NODES[@]}"; do [ -f "$sp_tmpd/$sp_n" ] && sp_bad="$sp_bad $sp_n"; done
    rm -rf "$sp_tmpd"
    if [ -n "$sp_bad" ]; then
        echo "PREP FAIL: /src unmountable on:$sp_bad"
        return 1
    fi

    # 2. Format the shared LUN once (node1).
    local out
    out=$(ssh_node "$NODE1" "MXFS_DEV='$DEV' bash /src/mxfs/tests/setup/prep_fs.sh")
    echo "$out" | grep -q FS_PREP_OK || { echo "PREP FAIL (mkfs): $out"; return 1; }

    # sess10 (ccloop c7ee71c6): ship the build host's ko md5 so prep_node.sh
    # can defeat NFS stale-page module images (mixed old/new ko pages after an
    # in-place relink under clock skew — proven frankenstein module on test25).
    local KO_MD5; KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')

    # 3. Form the cluster on node1 (load module w/ transport + mount).
    out=$(ssh_node "$NODE1" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' MXFS_EXTRA_MODARGS='${MXFS_EXTRA_MODARGS:-}' bash /src/mxfs/tests/setup/prep_node.sh $BASE_TRANSPORT")
    echo "$out" | grep -q NODE_PREP_OK || { echo "PREP FAIL (form $NODE1): $out"; return 1; }

    # 4. Join the remaining nodes in parallel.
    pids=()
    local tmpd; tmpd=$(mktemp -d)
    for n in "${NODES[@]:1}"; do
        ( ssh_node "$n" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' MXFS_EXTRA_MODARGS='${MXFS_EXTRA_MODARGS:-}' bash /src/mxfs/tests/setup/prep_node.sh $BASE_TRANSPORT" > "$tmpd/$n" 2>&1 ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done

    # 5. Verify readiness: every node has mxfs mounted at $MNT AND is running
    #    the EXACT build we just deployed.  A stale/wedged leftover mount from a
    #    prior run can satisfy the mount check while running an OLD module (a
    #    failed prep_node rmmod leaves the old mount up) — that silently runs the
    #    test on mismatched builds and yields an INVALID result.  Assert the
    #    loaded srcversion matches the build under test on every node.
    #
    #    The reference build depends on where the nodes get their module (see
    #    tests/setup/prep_node.sh step 1a).  Same-kernel fleet (the test VMs):
    #    it is the NFS-shared repo .ko, so compare against that.  Different
    #    kernel (Proxmox VE 9 on 6.17.2-1-pve vs this host's 6.8.0-101-generic):
    #    the nodes load their own DKMS build and the dev host's .ko is simply
    #    not the artifact under test -- comparing against it would fail every
    #    run by construction.  The invariant that actually matters is unchanged
    #    and still asserted: every node runs the SAME build, and that build is
    #    the one currently INSTALLED on the node (which is what catches the
    #    stale-leftover-mount-on-an-old-module case this check exists for).
    local want_srcv ko_vermagic node_krel
    want_srcv=$(modinfo /src/mxfs/mxfs.ko 2>/dev/null | awk '/^srcversion:/{print $2}')
    ko_vermagic=$(modinfo /src/mxfs/mxfs.ko 2>/dev/null | awk '/^vermagic:/{print $2}')
    node_krel=$(ssh_node "$NODE1" "uname -r" 2>/dev/null | tr -d '\r\n ')
    if [ -n "$node_krel" ] && [ "$ko_vermagic" != "$node_krel" ]; then
        want_srcv=$(ssh_node "$NODE1" "modinfo -F srcversion mxfs 2>/dev/null" 2>/dev/null | tr -d '\r\n ')
        echo "--- build ref: node-installed module ${want_srcv:-<none>}" \
             "(repo .ko is vermagic $ko_vermagic, nodes run $node_krel) ---"
        [ -n "$want_srcv" ] || { echo "PREP FAIL: no installed mxfs module on $NODE1 to reference"; rm -rf "$tmpd"; return 1; }
    fi
    local bad=""
    for n in "${NODES[@]}"; do
        ssh_node "$n" "mount | grep -q ' on $MNT type mxfs'" >/dev/null 2>&1 || { bad="$bad $n(unmounted)"; continue; }
        if [ -n "$want_srcv" ]; then
            local got_srcv
            got_srcv=$(ssh_node "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null | tr -d '\r\n ')
            [ "$got_srcv" = "$want_srcv" ] || bad="$bad $n(build=$got_srcv!=$want_srcv)"
        fi
    done
    if [ -n "$bad" ]; then
        echo "PREP FAIL: bad nodes:$bad"
        for n in $bad; do n="${n%%(*}"; [ -f "$tmpd/$n" ] && { echo "  --- $n ---"; sed 's/^/    /' "$tmpd/$n"; }; done
        rm -rf "$tmpd"; return 1
    fi
    rm -rf "$tmpd"
    echo "--- prep OK: mxfs mounted on all $N node(s), build $want_srcv ---"

    # sess45 (ccloop 4cb2d0a2): CLUSTER-CONVERGENCE GATE.  A barrier-coordinated
    # workload must not start before the mxfs cluster has converged to N members:
    # during the 1->N formation ramp, nodes hold DIVERGENT active-node views, so
    # master = nodes[hash%count] differs across nodes -> two nodes grant EX for
    # the same dir -> divergent RMW -> durable mass dirent loss (8/tcp dir_reuse
    # MASS split-brain, sess39/sess45).  A real clustered FS forms membership
    # before serving I/O; this gate establishes that precondition.  Wait until
    # EVERY node's LATEST "MXFS-MEMBERSHIP active_count" beacon == N and stays
    # there for a short stability window.  Multi-node only; best-effort with a
    # bounded timeout so a genuine membership bug cannot hang the harness.
    if [ "$N" -gt 1 ]; then
        local cg_t0=$SECONDS
        local cg_deadline=$(( SECONDS + 90 + 5 * N ))
        local cg_stable=0 cg_ok=0
        while [ "$SECONDS" -lt "$cg_deadline" ]; do
            # sess5 (ccloop a864): PARALLEL per-node reads.  The old serial loop
            # did 32 back-to-back SSH round-trips per snapshot (~20-25s) at N=32,
            # so few snapshots fit the 250s window and any settle-flap reset the
            # 3-consecutive-stable counter — the gate FAILED on an already-
            # converged 32-node cluster (all nodes active_count=32 in the dump).
            # Parallel reads make each snapshot ~1-2s (same correctness: still
            # requires EVERY node == N for 3 consecutive reads).
            local allN=1 n
            local cgd; cgd=$(mktemp -d)
            for n in "${NODES[@]}"; do
                # Anchor to the CURRENT module incarnation.  dmesg is a log, not
                # live state, and the ring survives rmmod/insmod: on a rig whose
                # nodes are not power-cycled between runs (any external node
                # list -- Proxmox, bare metal), the newest MXFS-MEMBERSHIP line
                # can belong to a PREVIOUS incarnation that really did converge.
                # Reading it unanchored would false-PASS this gate on a cluster
                # that never formed -- exactly the split-brain the gate exists to
                # prevent.  Every transport logs "... DLM initialized ..." at
                # init (dlm/v5_mount.c:1078 TCP, :1255 CAW), so reset at each one
                # and keep only beacons emitted after the last: no beacon yet for
                # this incarnation reads as empty (not converged), never as a
                # stale success.  If a build ever stops printing that marker the
                # awk degrades to "last beacon in the ring" = the old behaviour.
                ( ssh_node "$n" "dmesg | awk '/DLM initialized/{m=\"\"} /MXFS-MEMBERSHIP/{m=\$0} END{print m}' | grep -oE 'active_count=[0-9]+' | cut -d= -f2" 2>/dev/null | tr -d '\r\n ' > "$cgd/$n" ) &
            done
            wait
            for n in "${NODES[@]}"; do
                [ "$(cat "$cgd/$n" 2>/dev/null)" = "$N" ] || { allN=0; break; }
            done
            rm -rf "$cgd"
            if [ "$allN" = 1 ]; then
                cg_stable=$(( cg_stable + 1 ))
                if [ "$cg_stable" -ge 3 ]; then cg_ok=1; break; fi
            else
                cg_stable=0
            fi
            sleep 2
        done
        if [ "$cg_ok" = 1 ]; then
            echo "--- converged: all $N nodes report active_count=$N (stable, $(( SECONDS - cg_t0 ))s) ---"
        else
            # HARD gate (sess6): proceeding unconverged runs the whole suite
            # on a split-brain cluster — 17 garbage FAILs and possible on-disk
            # damage.  Fail loudly with each node's view for diagnosis.
            echo "PREP FAIL: cluster did NOT converge to $N members within $(( 90 + 5 * N ))s:"
            for n in "${NODES[@]}"; do
                echo "    $n: $(ssh_node "$n" "dmesg | awk '/DLM initialized/{m=\"\"} /MXFS-MEMBERSHIP/{m=\$0} END{print (m==\"\") ? \"(no beacon this incarnation)\" : m}'" 2>/dev/null | tr -d '\r')"
            done
            return 1
        fi
    fi
}

# ---------------------------------------------------------------------------
# Prep the native-XFS single-node timing baseline (DLM=xfs, N=1 only): no
# mxfs.ko, no DLM, no cluster membership — just mkfs.xfs + a plain mount on
# NODE1, so the FS-agnostic single-node battery (posix_single/fsx/fio_verify/
# integrity_filetypes/fio_perf/fault_enospc/precond_readiness) can be timed
# against real native XFS to derive RULE 0 budgets for the mxfs conditions.
# ---------------------------------------------------------------------------
prep_cluster_xfs() {
    echo "--- prep: 1 node [xfs baseline: $NODE1] ---"
    local out
    out=$(ssh_node "$NODE1" "
        mountpoint -q '$MNT' && { fuser -km '$MNT' 2>/dev/null; umount '$MNT' 2>/dev/null; }
        lsmod | grep -q '^mxfs ' && { umount '$MNT' 2>/dev/null; rmmod mxfs 2>/dev/null; }
        mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
        # Clear stale SCSI PR left by the prior CAW cluster run (see
        # tests/setup/prep_fs.sh 3b) — otherwise mkfs.xfs fails 'Device or
        # resource busy' against a still-reserved LUN.
        command -v sg_persist >/dev/null 2>&1 && {
            sg_persist --out --register-ignore --param-sark=0x5eed '$DEV' >/dev/null 2>&1
            sg_persist --out --clear --param-rk=0x5eed '$DEV' >/dev/null 2>&1
        }
        mkfs.xfs -f '$DEV' >/tmp/xfs_mkfs.log 2>&1 && echo MKFS_OK
        mount '$DEV' '$MNT' && echo MOUNT_OK
    ")
    echo "$out" | grep -q MKFS_OK  || { echo "PREP FAIL (mkfs.xfs): $out"; return 1; }
    echo "$out" | grep -q MOUNT_OK || { echo "PREP FAIL (mount xfs): $out"; return 1; }
    ssh_node "$NODE1" "mount | grep -q ' on $MNT type xfs'" >/dev/null 2>&1 \
        || { echo "PREP FAIL: $NODE1 not mounted xfs at $MNT"; return 1; }
    echo "--- prep OK: native xfs mounted on $NODE1 ---"
}

# ---------------------------------------------------------------------------
# Run a single-mount (coord=none) test on node1.
# ---------------------------------------------------------------------------
run_none() {  # name cat budget
    local name="$1" cat="$2" real_budget="${3:-300}"
    local script="/src/mxfs/tests/$cat/$name.sh"
    local fstype=mxfs; [ "$DLM" = xfs ] && fstype=xfs
    # RULE0_CALIBRATE=1: this is a first-time measurement run with no real
    # budget yet -- inflate the KILL-timeout only, so a genuinely slow (but
    # not hung) test can finish and produce a number instead of getting
    # killed before we ever learn what it should be. real_budget (the
    # manifest's actual target) stays UNINFLATED for record()/display --
    # showing the calibration-inflated ceiling as if it were the intended
    # budget is misleading (looks like a broken/absurd number, e.g. 5600s
    # for a test that should budget at 280s).
    local kill_budget="$real_budget"
    [ "${RULE0_CALIBRATE:-0}" = 1 ] && kill_budget=$(( kill_budget * 20 ))
    local out raw line rc t0 t1 elapsed attempt
    t0=$(date +%s)
    # 2026-07-20 (RULE 4): "out=$(timeout ... | grep ...); rc=$?" captured
    # grep's exit status, not timeout's -- a killed ssh (rc=124) with empty
    # output makes grep itself exit 1, so the timeout branch below never
    # fired and every kill_budget-expiry got mislabeled "no-result". Capture
    # rc straight off timeout/ssh (no pipe in between) and filter afterward.
    #
    # Empty output with a NON-124 rc is an ssh/connection-layer hiccup, not a
    # functional test failure: lib.sh's finish() unconditionally emits a
    # RESULT: line for any test that actually started running, pass or fail.
    # Proven transient 2026-07-20: 2/tcp precond_readiness "no-result" once,
    # immediately after the fresh xfs-baseline-detour prep's reformat/remount
    # churn on the same node, then instant PASS on a manual same-state retry
    # seconds later. Bounded retry (kill_budget still applies PER attempt, so
    # a genuinely wedged node still hits the timeout branch and FAILs; a
    # merely-flaky-connection node gets a few quick, cheap re-attempts).
    for attempt in 1 2 3; do
        raw=$(timeout "$kill_budget" "$SSH" "$NODE1" "$PASS" \
            "MXFS_NODES=$N MXFS_RANK=1 MXFS_DLM=$DLM MXFS_DEV='$DEV' MXFS_EXPECT_FSTYPE=$fstype MXFS_FS_LABEL=$DLM bash $script '$MNT'" \
            2>&1)
        rc=$?
        out=$(echo "$raw" | grep -vE '^Warning:|^Unauthorized|^If you')
        [ "$rc" -eq 124 ] && break
        line=$(echo "$out" | grep -E '^RESULT:' | tail -1)
        [ -n "$line" ] && break
        [ "$attempt" -lt 3 ] && sleep 2
    done
    t1=$(date +%s); elapsed=$(( t1 - t0 ))
    if [ "$rc" -eq 124 ]; then
        record "$name" FAIL "elapsed>${kill_budget}s" "script wall-clock timeout (kill_budget=${kill_budget}s)" "$elapsed" "$real_budget"
        echo "  FAIL  $name (timeout >${kill_budget}s)"; return
    fi
    if [ -z "$line" ]; then record "$name" FAIL "no-result" "no RESULT line from $NODE1 after $attempt attempts" "$elapsed" "$real_budget"; echo "  FAIL  $name (no result)"; return; fi
    local status; status=$(awk '{print $2}' <<<"$line")
    record "$name" "$status" "$(echo "$line"|field measured)" "$(echo "$line"|field reason)" "$elapsed" "$real_budget"
    printf "  %-5s %s  (%ss/%ss)\n" "$status" "$name" "$elapsed" "$real_budget"
}

# ---------------------------------------------------------------------------
# Run a coordinated test on ALL N nodes; aggregate (all must PASS).
# ---------------------------------------------------------------------------
run_coord() {  # name cat budget scale
    local name="$1" cat="$2" def_budget="${3:-300}" scale="${4:-flat}"
    local script="/src/mxfs/tests/$cat/$name.sh"
    local prefix="mxfs/coord/$RUN_ID/$name"
    # Clear any stale retained state for this namespace.
    timeout 5 mosquitto_sub -h "$BROKER" -t "$prefix/#" --remove-retained -W 2 >/dev/null 2>&1

    # Workload-derived per-test budget (RULE 0: budgets are workload-derived, not
    # a blanket round number). def_budget comes from the manifest's BUDGET_S
    # column (tests/suite/manifest header documents the flat/linear SCALE
    # semantics + per-test evidence for which shape applies). dir_reuse_coherency
    # keeps its own bespoke per-transport override below regardless of scale,
    # since its coefficient differs by DLM transport (not expressible in one
    # manifest column).
    local tt="$def_budget"
    [ "$scale" = linear ] && [ "$N" -gt 1 ] && tt=$(( def_budget * N ))
    local ct="$COORD_TIMEOUT"
    case "$name" in
        dir_reuse_coherency)
            # 2026-07-18 (ccloop 72513a13 sess2) BUDGET BAR RESET — user
            # directive: no test may take an hour; 32 users reading/writing
            # must see seconds-to-minutes.  The old bespoke 140*N caw /
            # 100*N tcp override (60*N -> 90*N -> 140*N history) widened the
            # budget every time the measured wall grew — the exact
            # anti-pattern RULE 0 forbids.  A clean EX handoff measures
            # ~13ms (P138 stage split); a round-robin dir workload at 32
            # nodes should therefore pace rounds in ~1s, not 10-40s.  The
            # manifest's flat 120s budget is now authoritative at EVERY N;
            # the per-op durable-publish pace tax it exposes is the product
            # bug being fixed (dirop_durable_caw batching), not budget
            # material.
            #
            # COORD_TIMEOUT ordering (2026-07-25, ccloop c7ee71c6 sess6):
            # hang-threshold (N*10, floor 20 — the script's
            # DRC_HANG_THRESHOLD_S) < ct < tt (kill box).  The old floor-150
            # exceeded tt=120, so a genuine barrier stall was KILLED at 120s
            # before the 150s barrier timeout could write its
            # BARRIER_TIMEOUT record — three straight wedged runs produced
            # zero terminal records (NO_TERMINAL_RECORD) and burned a
            # session chasing a "silent" wedge that the barrier layer had
            # detected but was never allowed to report.  ct sits 20s above
            # the hang threshold (rank1's run_bounded reports first) and
            # 15s under the kill box (peers' BARRIER_TIMEOUT records land).
            # N>=12 makes hang-threshold itself exceed the flat 120s budget
            # — that infeasibility is owned by the round-pace defect (per-op
            # durable-publish tax), not by this formula.
            ct=$(( N * 12 ))
            [ "$ct" -lt $(( N * 10 + 20 )) ] && ct=$(( N * 10 + 20 ))
            [ "$ct" -gt $(( tt - 15 )) ] && ct=$(( tt - 15 ))
            [ "$ct" -lt 30 ] && ct=30
            ;;
    esac
    # RULE0_CALIBRATE=1: measurement run, no real budget to enforce yet --
    # inflate the KILL-timeout only (applied AFTER any per-test override
    # above, so it multiplies whatever tt ended up being) so a slow-but-not-
    # hung first measurement survives to produce a number. real_budget (the
    # manifest/formula target computed above) stays UNINFLATED for
    # record()/display -- showing the calibration-inflated kill-ceiling as
    # if it were the intended budget is misleading (e.g. dir_reuse_coherency
    # at 2/caw: real target is 140*2=280s, but the kill-ceiling is 5600s --
    # displaying "256s/5600s" reads as an absurd/broken budget when the real
    # comparison is 256s/280s).
    local real_budget="$tt"
    [ "${RULE0_CALIBRATE:-0}" = 1 ] && tt=$(( tt * 20 ))

    local fstype=mxfs; [ "$DLM" = xfs ] && fstype=xfs
    local tmpd; tmpd=$(mktemp -d) pids=() i=0
    local t0 t1 elapsed

    # PRE-ASSERT (2026-07-16): every participating node must still have the
    # cluster FS mounted before a coordinated test launches.  A prior test
    # that breaks formation state (the caw dlm_lock_correctness unmount bug:
    # node1 silently lost its mount, every later same-formation coord test
    # ran rank1 against the bare mountpoint directory — invisible to peers,
    # "sticky" until reform) otherwise turns into hours of un-attributable
    # coherency FAILs.  Runs before t0 so it never counts against the test's
    # RULE-0 budget.
    # ccloop c7ee71c6 sess12: mountpoint+fstype alone passes a SHUTDOWN
    # ZOMBIE (fs_shut=1 but still in the mount table — test14 after the
    # 32/caw spurious shutdown).  A zombie at a coord barrier then stalls
    # every healthy node to the row budget (the all-32 NO_TERMINAL_RECORD
    # cache_coherency rerun).  Require a live readdir of the mount root:
    # a shutdown FS fences it (P-SHUTDOWN-FENCE → EIO) while a healthy
    # node's converge is bounded (P95B/C ≈2s worst case).
    # ccloop c7ee71c6 sess24 — NODE-FAULT PRE-ASSERT.
    #
    # The mount/readdir check below is necessary but NOT sufficient: a node that
    # is permanently DEADLOCKED passes it.  D-BAST-WRITEBACK-ABBA-DEADLOCK was
    # captured live on test27 with mxfs mounted, `ls` answering, mkdir/write/
    # fsync/unlink all working, no BUG/WARNING and no filesystem shutdown -- yet
    # `sync` could never complete (mxfs_dlm_bast_process held the inode lock
    # waiting on a folio lock; writeback held that folio lock waiting on the
    # inode lock).  loadavg 20.4, 21 tasks in D state, unchanged PIDs over many
    # minutes.
    #
    # Barrier criteria need EVERY rank, so one such node makes the board read
    # `FAIL nodes_pass=0/N states:NO_TERMINAL_RECORD=N`.  That happened to SEVEN
    # criteria at once (cache_coherency, strong_consistency, posix_multi,
    # mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership) while 31 of
    # 32 nodes were healthy -- a board indistinguishable from total filesystem
    # collapse, produced by one wedged node.  dir_reuse_coherency passed
    # throughout, which is what proved the filesystem itself was fine.
    #
    # So the pre-assert now also requires, per node, a `sync` that COMPLETES in
    # bounded time -- the exact operation the deadlock makes impossible, and one a
    # healthy node finishes in milliseconds.  A node failing it is reported as a
    # NODE FAULT, never as a correctness failure of the filesystem.
    #
    # THE PREDICATE IS THE SYNC, NOT THE D-STATE SCAN.  The first cut of this gate
    # also convicted any D-state mxfs/writeback task, and immediately produced a
    # FALSE BLOCK: test26 was blocked for `mxfs-worker[mxfs_pal_cond_timedwait]`,
    # which is simply a worker sitting in the normal, bounded CAW acquire poll.
    # Blocking a healthy cluster is as damaging as the red it was meant to
    # prevent, so D-state details are now collected ONLY as attribution for a node
    # that has already failed the sync bound.
    #
    # Deliberately NOT keyed on loadavg either: high load has many innocent causes
    # and would fail healthy nodes under legitimate work.
    local pa_bad="" pa_pids=() pa_n pa_faults=""
    local pa_d="/tmp/.mxfs_paf.$$"; mkdir -p "$pa_d"
    for pa_n in "${NODES[@]}"; do
        ( timeout 15 "$SSH" "$pa_n" "$PASS" \
            "mountpoint -q '$MNT' && mount | grep -q ' on $MNT type $fstype ' && timeout 10 ls '$MNT'/. >/dev/null 2>&1" \
            >/dev/null 2>&1 ) &
        pa_pids+=($!)
    done
    i=0
    for pa_n in "${NODES[@]}"; do
        wait "${pa_pids[$i]}" || pa_bad="$pa_bad $pa_n"
        i=$((i+1))
    done
    # SYNC-LIVENESS PASS (separate from the mount pre-assert on purpose).
    #
    # It cannot be folded into the probe above: a wedged `sync` sits in
    # UNINTERRUPTIBLE sleep, so `timeout 12 sync` never returns, the outer ssh is
    # killed, and the node then lands in the mount/readdir bucket with the
    # misleading reason "mxfs not mounted/readable" -- which is exactly what the
    # first attempt at this gate reported for test27.  Run it as its own pass and
    # treat "no verdict came back" as the wedge, because for this probe silence IS
    # the positive result.
    #
    # Each node writes SYNCOK only if sync completed.  Anything else -- partial
    # output, killed ssh, nothing at all -- means it did not.
    local pa_sp=() pa_sn
    for pa_sn in "${NODES[@]}"; do
        ( timeout 20 "$SSH" "$pa_sn" "$PASS" \
            "timeout 12 sync && echo SYNCOK" > "$pa_d/$pa_sn" 2>/dev/null ) &
        pa_sp+=($!)
    done
    for pa_sn in "${NODES[@]}"; do wait; done 2>/dev/null
    for pa_sn in "${NODES[@]}"; do
        grep -q SYNCOK "$pa_d/$pa_sn" 2>/dev/null && continue
        # Attribution for the wedge, best-effort and non-blocking: read the
        # D-state MXFS/writeback tasks. Collected only for a node ALREADY
        # convicted by the sync bound -- a D-state mxfs worker on its own is
        # normal (mxfs_pal_cond_timedwait is just the bounded CAW acquire poll),
        # and convicting on it FALSE-BLOCKED healthy test26 on the first attempt.
        local pa_diag
        pa_diag=$(timeout 20 "$SSH" "$pa_sn" "$PASS" \
            "for dp in \$(ps -eo stat,pid --no-headers 2>/dev/null | awk '\$1 ~ /^D/ {print \$2}'); do
                 dc=\$(cat /proc/\$dp/comm 2>/dev/null)
                 case \"\$dc\" in
                     *mxfs*|flush-*|sync|*xfsaild*)
                         echo \$dc[\$(cat /proc/\$dp/wchan 2>/dev/null)] ;;
                 esac
             done" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
        pa_faults="$pa_faults ${pa_sn}:sync-wedged[${pa_diag:-no-diag}]"
    done
    rm -rf "$pa_d"
    if [ -n "$pa_faults" ]; then
        record "$name" BLOCKED "node-fault" \
            "NODE FAULT (not a filesystem verdict):$pa_faults — a node cannot complete sync and/or has an MXFS/writeback task wedged in D state. See D-BAST-WRITEBACK-ABBA-DEADLOCK. Every barrier criterion would report NO_TERMINAL_RECORD on ALL nodes because one rank can never reach a barrier; BLOCKED so that is not recorded as a correctness failure. Recover the node (virsh destroy+start) and re-run." \
            0 "$real_budget"
        echo "  BLOCK $name  (node fault:$pa_faults)"
        rm -rf "$tmpd"
        return 1
    fi
    if [ -n "$pa_bad" ]; then
        record "$name" FAIL "pre-assert" \
            "PRE-ASSERT: $fstype not mounted/readable on$pa_bad — a prior test broke cluster formation state (unmounted or shutdown zombie); reform required" \
            0 "$real_budget"
        echo "  FAIL  $name  (pre-assert: $fstype not mounted/readable on$pa_bad)"
        rm -rf "$tmpd"
        return 1
    fi
    i=0

    t0=$(date +%s)
    for n in "${NODES[@]}"; do
        i=$((i+1))
        # Reusable diagnostic hook: MXFS_STRACE_RANK=<i> [MXFS_STRACE_OUT=<path>]
        # wraps just that rank's worker in strace (-e trace=%file) to catch
        # the exact pathname syscall/errno a specific test rank hits. Inert
        # unless MXFS_STRACE_RANK is set — safe to leave in dispatch.
        local runcmd="bash $script '$MNT'"
        if [ -n "${MXFS_STRACE_RANK:-}" ] && [ "$i" = "${MXFS_STRACE_RANK}" ]; then
            runcmd="strace -ff -ttt -T -s 256 -e trace=%file -o ${MXFS_STRACE_OUT:-/tmp/drc_strace} -- $runcmd"
        fi
        ( timeout "$tt" "$SSH" "$n" "$PASS" \
            "MXFS_NODES=$N MXFS_RANK=$i MXFS_DLM=$DLM MXFS_DEV='$DEV' \
             MXFS_EXPECT_FSTYPE=$fstype MXFS_FS_LABEL=$DLM \
             MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$prefix COORD_TIMEOUT=$ct \
             ${MXFS_TEST_ENV:-} \
             $runcmd" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you' > "$tmpd/$n" ) &
        pids+=($!)
    done
    local rc=0
    for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
    t1=$(date +%s); elapsed=$(( t1 - t0 ))

    # Aggregate: PASS iff every node printed RESULT: PASS.  Beyond the raw
    # pass count, tally which TERMINAL STATE each non-passing node hit — a
    # single hung syscall cascading into peers reporting ABORTED_BY_PEER (or
    # BARRIER_TIMEOUT, if a peer's own hang-detection didn't catch it first)
    # must not read the same as N independent correctness failures (GPT
    # consult 2026-07-11; see ccmemory
    # gpt-consult-dir_reuse32-architectural-review).
    local npass=0 fail_reason="" saw_noresult=0 n line status rank1_measured="" faildist=""
    # sess23: also keep the FIRST FAILING node's measured= values.  The cell
    # used to show rank 1's numbers regardless of verdict, so a FAIL displayed a
    # PASSING node's counts (state.md: "nodes_pass=31/32 states:FAIL=1 next to
    # measured= values taken from a passing node").  Live cost: a real
    # dir_reuse_coherency failure reported checks=51 passed=50 failed=1 with NO
    # indication of WHICH check failed, even though the node-side finish() had
    # named it in its reason — the aggregate simply threw the failing node's
    # numbers away.
    local fail_measured=""
    local -A state_count
    for n in "${NODES[@]}"; do
        line=$(grep -E '^RESULT:' "$tmpd/$n" | tail -1)
        if [ -z "$line" ]; then
            status="NO_TERMINAL_RECORD"; saw_noresult=1
            fail_reason="$fail_reason $n:$status:no-result(tail:$(tail -1 "$tmpd/$n" 2>/dev/null))"
        else
            status=$(awk '{print $2}' <<<"$line")
            if [ "$status" = PASS ]; then
                npass=$((npass+1))
            else
                fail_reason="$fail_reason $n:$status:$(echo "$line"|field reason)"
            fi
            # rank 1 is NODES[0]; its own measured= payload (e.g. fio_perf's
            # AGGREGATE seqW/seqR/randW/randR figures) is real per-test detail
            # that the generic nodes_pass=N/N summary below would otherwise
            # discard entirely.
            [ "$n" = "${NODES[0]}" ] && rank1_measured=$(echo "$line" | field measured)
            if [ "$status" != PASS ] && [ -z "$fail_measured" ]; then
                fail_measured="$n:$(echo "$line" | field measured)"
            fi
            # sess43: the per-node FAILED-CHECK COUNT distribution.  Showing
            # only first_fail + rank1 hid whether a failure was uniform
            # ("every node failed the same 1 check" = a shared/coordinated
            # object) or concentrated ("one node failed 16" = that node's
            # own artifacts).  Those two shapes need opposite
            # investigations, and the Aug-1 23:32 cache_coherency incident
            # could not be told apart afterwards because only test1's
            # numbers survived.  Recorded as a compact histogram.
            if [ "$status" != PASS ]; then
                local nf
                nf=$(echo "$line" | field measured | sed -n 's/.*failed=\([0-9]*\).*/\1/p')
                [ -n "$nf" ] && faildist="$faildist $nf"
            fi
        fi
        state_count["$status"]=$(( ${state_count["$status"]:-0} + 1 ))
    done
    # RULE-0 cascade guard (sess8 a9a03929, run104): a timed-out node-side test
    # SURVIVES the local `timeout` (killing the ssh client does not kill the
    # remote bash), and keeps hammering the FS through every subsequent test —
    # run104: dir_reuse still at r18@1018s poisoned fence/fault/soak/tds into
    # 0/8 cascade FAILs.  The timeout stays a FAIL for THIS test (RULE 0); this
    # just kills the leftovers so the NEXT test's result is valid.
    if [ "$saw_noresult" -eq 1 ]; then
        local kn
        for kn in "${NODES[@]}"; do
            # pkill the script, then fuser -k -m the mount: the script's
            # CHILDREN (a mid-flight rm -rf) survive the pkill and keep
            # hammering the FS (run108: test7's leftover rm died on an AG
            # acquire rc=-110 -> error-path shutdown -> poisoned fence/
            # fault/tds).  Between suite tests nothing legitimate holds
            # files under $MNT, so the -m kill is safe.
            #
            # sess45 (D-CRASH-CONSISTENCY-32-NOTERMINAL-354): ALSO capture the
            # node's LAST kmsg phase marker at kill time.  A NO_TERMINAL node's
            # captured stdout tail is unreliable (ssh block-buffering loses
            # unflushed output when the kill lands — both recorded all-32
            # NOTERMINAL events show tail:<empty> on every node), but the
            # suite's `mxfs-CCph rank=N PHASE=x` /dev/kmsg markers are flushed
            # instantly.  The last marker names the phase each node was IN
            # when the budget fired — the difference between "stuck at launch",
            # "slow in datawrite" and "slow in cold verify", which need three
            # different investigations.
            ( ssh_node "$kn" "pkill -f '$script' 2>/dev/null; dmesg | grep -o 'mxfs-CCph rank=[0-9]* PHASE=[a-z0-9-]*' | tail -1 > /tmp/ccph_last 2>/dev/null; sleep 1; fuser -k -m $MNT >/dev/null 2>&1; cat /tmp/ccph_last 2>/dev/null; true" 2>/dev/null | tail -1 > "$tmpd/$kn.ccph" ) &
        done
        wait
        echo "    (killed leftover $name processes on all nodes after timeout)"
        # Compact last-phase census across nodes -> appended to the reason so
        # the criteria history self-diagnoses the stuck phase distribution.
        local pc_phase pc_summary=""
        local -A pc_count
        for kn in "${NODES[@]}"; do
            pc_phase=$(sed -n 's/.*PHASE=//p' "$tmpd/$kn.ccph" 2>/dev/null | head -1)
            [ -z "$pc_phase" ] && pc_phase="none"
            pc_count["$pc_phase"]=$(( ${pc_count["$pc_phase"]:-0} + 1 ))
        done
        for pc_phase in "${!pc_count[@]}"; do
            pc_summary="$pc_summary${pc_summary:+,}${pc_phase}=${pc_count[$pc_phase]}"
        done
        [ -n "$pc_summary" ] && fail_reason="$fail_reason last_phase_census[$pc_summary]"
    fi
    # Clean up retained state.  sess24: also sweep this test's own subtree with a
    # real idle window -- the old `-W 2` frequently returned before the broker had
    # delivered everything, which is how 120k messages accumulated.
    timeout 20 mosquitto_sub -h "$BROKER" -t "$prefix/#" --remove-retained -W 6 >/dev/null 2>&1

    local agg measured statebrk="" st
    for st in "${!state_count[@]}"; do
        [ "$st" = PASS ] && continue
        statebrk="$statebrk${statebrk:+,}${st}=${state_count[$st]}"
    done
    measured="nodes_pass=$npass/$N"
    [ -n "$statebrk" ] && measured="$measured states:$statebrk"
    # sess43: stamp the HOST load with every result.  These 32 guests share
    # one hypervisor, and pace-sensitive criteria are modulated by it:
    # dir_reuse_coherency measured 8-10 rounds/100s at host load 11-17 and
    # 5-7 rounds on the SAME build hours later at load 28-30 (guest load
    # stayed <1 but steal climbed) — enough to cross its 8-round floor by
    # itself.  Without this stamp a pace result cannot be compared against
    # another, and A/B arms run under drifting load are worthless.
    local hload
    hload=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
    [ -n "$hload" ] && measured="$measured hostload=$hload"
    # Prefer the FAILING node's numbers when the aggregate is a failure — those
    # are the ones a human needs; rank 1's are only meaningful on a clean run.
    if [ "$npass" -ne "$N" ] && [ -n "$fail_measured" ]; then
        measured="$measured first_fail[$fail_measured]"
        [ -n "$rank1_measured" ] && measured="$measured rank1[$rank1_measured]"
        # failed-check histogram across the failing nodes: "1x31,16x1" reads
        # as "31 nodes failed 1 check, one node failed 16".
        if [ -n "$faildist" ]; then
            local hist
            hist=$(printf '%s\n' $faildist | sort -n | uniq -c \
                   | awk '{printf "%s%sx%s", (NR>1?",":""), $2, $1}')
            [ -n "$hist" ] && measured="$measured faildist[$hist]"
        fi
    elif [ -n "$rank1_measured" ]; then
        measured="$measured $rank1_measured"
    fi
    if [ "$npass" -eq "$N" ]; then
        agg=PASS
    else
        agg=FAIL
        fail_reason="${fail_reason## }"
    fi
    record "$name" "$agg" "$measured" "${fail_reason:0:400}" "$elapsed" "$real_budget"
    printf "  %-5s %s  (%s) [%ss/%ss]\n" "$agg" "$name" "$measured" "$elapsed" "$real_budget"
    if [ "$agg" != PASS ]; then
        # sess10(a9a03929): capture every node's CURRENT-BOOT kernel log at
        # the failure — VM destroy at the next cycle loses the runtime
        # journal, which is how r8's forensics were nearly lost (recovered
        # only via the test's own /root snapshots).
        # sess3 (ccloop 46efd8b6): dmesg FIRST, journalctl only as fallback.
        # journald rotates in ~85s under probe volume AND rate-limits kmsg
        # ingestion, so `journalctl -k` LOST the 'XFS ... Shutting down
        # filesystem' alert 2.5 min after it fired — two sessions hunted a
        # "silent" shutdown that was only silent in the artifacts.  The 16M
        # dmesg ring retains everything.
        local cn
        for cn in "${NODES[@]}"; do
            ssh_node "$cn" "dmesg -T 2>/dev/null || journalctl -k -b 0 --no-pager" \
                > "$tmpd/kernlog_$cn" 2>/dev/null &
        done
        wait
        # sess13: pull the drc raw-block bins + dmesg snapshots (written to
        # /root/drc_blkdump_* at RDMISS) into the artifact BEFORE the next VM
        # recycle wipes them — the iter4 round-3 forensics were lost exactly
        # this way (journald also rotates in ~85s under probe volume, so the
        # kernlog pull above misses early rounds).  base64 shields the tar
        # stream from ssh_node's line filter.
        for cn in "${NODES[@]}"; do
            ssh_node "$cn" "cd /root 2>/dev/null && ls -d drc_* >/dev/null 2>&1 && tar -cf - drc_* 2>/dev/null | base64" \
                | base64 -d 2>/dev/null | tar -xf - -C "$tmpd" --transform "s,^,${cn}_," 2>/dev/null &
        done
        wait
        echo "    logs: $tmpd"
        cp -r "$tmpd" "/tmp/run_${name}_${RUN_ID}" 2>/dev/null
    fi
    rm -rf "$tmpd"
}

# Emit one TSV line per matrix test: cat \t transport \t name \t coord \t min \t max \t budget \t scale
mapfile -t ROWS < <(jq -r '.categories[] | .category as $c | .transport as $tr |
    .tests[] | [$c,$tr,.name,.coord,(.min_nodes|tostring),(.max_nodes|tostring),
                ((.budget_s//300)|tostring),(.budget_scale//"flat")] | @tsv' "$CRIT")

ran=0; skipped=0; pending=0
in_only() { [ "${#ONLY[@]}" -eq 0 ] && return 0; local x; for x in "${ONLY[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# applicable: is this matrix row going to be run under (N, DLM, ONLY)?
applicable() {  # cat tr name coord minn maxn
    local cat="$1" tr="$2" name="$3" minn="$5" maxn="$6"
    # prep_cluster is handled specially before this loop (marker check /
    # forced prep), never dispatched as a normal test -- exclude it here so
    # reset_pending's PENDING-marker lifecycle doesn't touch it.
    [ "$name" = "prep_cluster" ] && return 1
    in_only "$name" || return 1
    transport_matches "$tr" || return 1
    [ "$N" -ge "$minn" ] || return 1
    [ "$maxn" -eq 0 ] || [ "$N" -le "$maxn" ] || return 1
    [ -f "$REPO/tests/$cat/$name.sh" ] || return 1
    [ "$DLM" = xfs ] && ! xfs_applicable "$name" && return 1
    return 0
}

# BEFORE anything runs (and before cluster prep), mark the ENTIRE set of tests
# this invocation will run as PENDING with a "running <run_id>" marker — the
# full suite for a full run, or just the named subset for a partial run.
# ./showstat then shows ⏳ PENDING for every to-be-run test from the moment the
# run starts until each one finishes, instead of leaving last run's PASS/FAIL
# on screen.
#
# PENDING is a LIVE-RUN state only.  A cell must never stay PENDING once no
# run.sh is executing: a run that started a test and died before recording
# (wedge, timeout kill, operator kill) FAILED that test.  Three pieces enforce
# this lifecycle:
#   1. reset_pending writes {status:PENDING, reason:"running <run_id>"} markers
#      (not cell deletion — a deleted cell rendered PENDING forever).
#   2. finalize_pending (EXIT trap) converts any of THIS run's still-PENDING
#      markers to FAIL when run.sh exits for any trap-able reason (normal end,
#      `timeout` TERM, ^C).  On a completed run every test already recorded
#      over its marker, so it is a no-op.
#   3. fail_stale_pending heals markers left by a kill -9 (trap never ran): the
#      flock above serializes runs, so at startup EVERY pre-existing
#      running-marker belongs to a dead run — convert them all to FAIL.
fail_stale_pending() {
    local tmp; tmp=$(mktemp)
    jq --arg t "$(date -u +%FT%TZ)" \
       '.categories[].tests |= map(.runs |= with_entries(
            if (.value.status=="PENDING" and ((.value.reason//"")|startswith("executing "))) then
                .value = {status:"ABORTED", measured:"",
                          reason:("run was killed while this test was executing (marker: "+.value.reason+")"),
                          iso:$t}
            elif (.value.status=="PENDING" and ((.value.reason//"")|startswith("running "))) then
                .value = {status:"NOT_RUN", measured:"",
                          reason:("run was killed before reaching this test (marker: "+.value.reason+")"),
                          iso:$t}
            else . end))' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
}
reset_pending() {
    local cond="${N}/${DLM}" names=() tmp row cat tr name coord minn maxn budget scale
    for row in "${ROWS[@]}"; do
        IFS=$'\t' read -r cat tr name coord minn maxn budget scale <<<"$row"
        applicable "$cat" "$tr" "$name" "$coord" "$minn" "$maxn" && names+=("$name")
    done
    [ "${#names[@]}" -gt 0 ] || return 0
    local jlist; jlist=$(printf '%s\n' "${names[@]}" | jq -R . | jq -s .)
    tmp=$(mktemp)
    # sess23: PRESERVE the flake history across the PENDING overwrite.  This is
    # where the previous REAL verdict is lost — reset_pending replaces the whole
    # cell — so push it onto history HERE, and carry the array forward into the
    # marker.  Without this the history only ever recorded "PENDING" and the
    # FLAKY annotation could never fire (measured: dir_reuse_coherency FAILED
    # 1 check on all 32 nodes then PASSed, and the board still read plain green).
    jq --arg c "$cond" --argjson ns "$jlist" --arg id "$RUN_ID" --arg t "$(date -u +%FT%TZ)" \
       '.categories[].tests |= map(if (.name as $n | $ns | index($n)) then
           ( ( (.runs[$c].history // []) as $h
             | (if ((.runs[$c].status // "") | . == "" or . == "PENDING") then $h
                else ([{status:.runs[$c].status, iso:.runs[$c].iso,
                        measured:.runs[$c].measured,
                        reason:((.runs[$c].reason // "")[0:400])}] + $h)[0:10] end) ) as $nh
           | .runs[$c]={status:"PENDING",measured:"",reason:("running "+$id),
                        iso:$t,history:$nh} )
         else . end)' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
    echo "--- marked ${#names[@]} test(s) PENDING for ${cond}: ${names[*]} ---"
}
# sess23 (ccloop c7ee71c6) — DO NOT SCORE UNRUN WORK AS A PRODUCT FAILURE.
#
# The old lifecycle converted EVERY still-PENDING marker of a dying run to
# FAIL "aborted".  That conflates two completely different facts:
#   * a test that was EXECUTING when the run died — genuinely suspicious, it
#     may have wedged the node, so it must not read as green; and
#   * a test the run never reached at all — which says nothing whatever about
#     the filesystem.
# A truncated sweep therefore painted the board red and was indistinguishable
# at a glance from a broken filesystem (live example: a 16/caw board showed 5
# reds, of which THREE were "aborted" tests that never executed and two had
# `checks=354 passed=354 failed=0` / `hits=0 kinds=[]`, i.e. zero failing
# checks).  That destroys the board's only job — being believable.
#
# So the marker now distinguishes the two, and mark_executing() stamps the one
# test actually in flight:
#   reason "running <id>"   -> never reached      -> NOT_RUN
#   reason "executing <id>" -> in flight when we died -> ABORTED
# Neither is PASS, so neither can make the board green (showstat only greens a
# cell on a real PASS, and reports NOT_RUN/ABORTED in their own columns).
mark_executing() {  # <test-name>
    local cond="${N}/${DLM}" tmp; tmp=$(mktemp)
    jq --arg k "$1" --arg c "$cond" --arg id "$RUN_ID" \
       '.categories[].tests |= map(if .name==$k and (.runs[$c].status=="PENDING")
            then (.runs[$c].reason = ("executing "+$id)) else . end)' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
}
finalize_pending() {
    local tmp; tmp=$(mktemp)
    jq --arg id "$RUN_ID" --arg t "$(date -u +%FT%TZ)" \
       '.categories[].tests |= map(.runs |= with_entries(
            if (.value.status=="PENDING" and .value.reason==("executing "+$id)) then
                .value = {status:"ABORTED", measured:"",
                          reason:"run died while this test was executing — result unknown, re-run it",
                          iso:$t}
            elif (.value.status=="PENDING" and .value.reason==("running "+$id)) then
                .value = {status:"NOT_RUN", measured:"",
                          reason:"sweep ended before reaching this test — not a result",
                          iso:$t}
            else . end))' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
}
# ---------------------------------------------------------------------------
# Cluster prep decision (2026-07-14): see the MARKER comment near the top of
# this file for the rationale.
# ---------------------------------------------------------------------------
marker_read
pc_budget=$(jq -r '.categories[].tests[] | select(.name=="prep_cluster") | (.budget_s // 300)' "$CRIT")

# `./run.sh N dlm prep_cluster` — explicit forced prep: always (re)forms
# regardless of marker state, records it, updates the marker, exits without
# running any other tests.
if [ "${#ONLY[@]}" -eq 1 ] && [ "${ONLY[0]}" = "prep_cluster" ]; then
    t0=$(date +%s)
    if [ "$DLM" = xfs ]; then prep_cluster_xfs; else prep_cluster; fi; rc=$?
    t1=$(date +%s); elapsed=$(( t1 - t0 ))
    if [ "$rc" -eq 0 ]; then
        marker_write "$N" "$DLM" "$WANT_SRCVER"
        record "prep_cluster" PASS "elapsed=${elapsed}s (fresh prep)" "" "$elapsed" "$pc_budget"
        echo "=== prep_cluster OK @ ${N}/${DLM} (${elapsed}s) — marker updated ==="
    else
        record "prep_cluster" FAIL "elapsed=${elapsed}s" "prep failed" "$elapsed" "$pc_budget"
        echo "ABORT: cluster prep failed"
    fi
    exit "$rc"
fi

if [ "${#ONLY[@]}" -gt 0 ]; then
    # Filtered run (specific test names): reuse the cluster ONLY if it's
    # already correctly formed for this exact (nodes, dlm, build) -- never
    # silently re-form on a mismatch. A mismatch usually means you meant a
    # different condition than what's actually live; silently reforming both
    # masks that and burns a full teardown/reform+converge cycle (the
    # convergence gate alone is 90+5*N) for no reason.
    if marker_matches; then
        echo "--- cluster already prepped for ${N}/${DLM} (srcver=$WANT_SRCVER) — skipping prep ---"
        record "prep_cluster" PASS "skipped (marker matched ${N}/${DLM})" "" 0 "$pc_budget"
    else
        echo "ERROR: cluster is prepped for ${MK_NODES:-<none>}/${MK_DLM:-<none>} (srcver=${MK_SRCVER:-<none>}), you requested ${N}/${DLM} (srcver=$WANT_SRCVER)."
        echo "  Run './run.sh $N $DLM' (no test filter) or './run.sh $N $DLM prep_cluster' first."
        exit 1
    fi
else
    # Unfiltered (no test names given): always fully (re)validate this
    # condition -- the deliberate "make it so" invocation.
    t0=$(date +%s)
    if [ "$DLM" = xfs ]; then prep_cluster_xfs; else prep_cluster; fi
    rc=$?
    t1=$(date +%s); elapsed=$(( t1 - t0 ))
    if [ "$rc" -ne 0 ]; then
        record "prep_cluster" FAIL "elapsed=${elapsed}s" "prep failed" "$elapsed" "$pc_budget"
        echo "ABORT: cluster prep failed"; exit 1
    fi
    marker_write "$N" "$DLM" "$WANT_SRCVER"
    record "prep_cluster" PASS "elapsed=${elapsed}s (fresh prep)" "" "$elapsed" "$pc_budget"
fi

# ---------------------------------------------------------------------------
# COORD BROKER HYGIENE (ccloop c7ee71c6 sess24)
#
# WHY THIS EXISTS -- it caused a whole-suite FALSE RED cascade.
#
# Every barrier-coordinated criterion publishes RETAINED MQTT messages under
# mxfs/coord/<RUN_ID>/<test>/... .  The per-test cleanup below only ever removed
# the CURRENT run's own prefix, so every prior RUN_ID's retained state stayed on
# the broker forever.  Measured this session: 120,447 retained messages under
# mxfs/coord.  coord_barrier subscribes with a wildcard, so once the backlog is
# that large every barrier crawls, no node reaches finish(), and the board fills
# with `FAIL nodes_pass=0/N states:NO_TERMINAL_RECORD=N` at exactly the budget.
#
# That is indistinguishable, on the board, from a filesystem that has stopped
# working: cache_coherency, strong_consistency, posix_multi, mmap_coherency,
# zero_silent_loss, dlm_fairness and dlm_membership all went red together on a
# cluster that was provably healthy (32/32 mounted, ls answering, no BUG/WARN,
# and the node scripts ran correctly by hand).
#
# So two things, both required:
#   1. GC THE WHOLE NAMESPACE, not just our own prefix.  The flock above
#      serialises runs, so no concurrent run's live state can be destroyed.
#   2. ASSERT the backlog is gone afterwards.  Infrastructure degradation must
#      never be able to present as a filesystem defect -- if the broker cannot
#      be brought to a clean state, the run ABORTS here rather than manufacturing
#      reds. Same principle as the destructive-test reconvergence gate.
coord_broker_hygiene() {
    local left
    if ! command -v mosquitto_sub >/dev/null 2>&1; then
        echo "ERROR: mosquitto_sub missing — barrier criteria cannot be coordinated"
        exit 1
    fi
    # Liveness first: a broker we cannot reach at all is an infrastructure fault,
    # not a filesystem verdict.
    if ! timeout 10 mosquitto_pub -h "$BROKER" -t "mxfs/coord/.hygiene/$RUN_ID"             -m 1 -q 1 >/dev/null 2>&1; then
        echo "ERROR: coord broker $BROKER unreachable (mqtt 1883) — every barrier"
        echo "       criterion would report NO_TERMINAL_RECORD. Fix the broker, do"
        echo "       NOT read those as filesystem failures."
        exit 1
    fi
    # Sweep every run's leftovers.  NOTE: mosquitto_sub -W is an ABSOLUTE exit
    # timer, not an idle window -- a single `-W 300` sweep would add 300s to every
    # run even on a clean broker (it did; that is why this loops instead).  Probe
    # cheaply, and only keep sweeping while there is actually something to remove.
    local round
    for round in 1 2 3 4 5 6 7 8 9 10; do
        left=$(timeout 12 mosquitto_sub -h "$BROKER" -t 'mxfs/coord/#' -v -W 4 \
               2>/dev/null | grep -c . || true)
        left=${left:-0}
        [ "$left" -le 200 ] && break
        echo "--- coord broker: sweeping $left retained mxfs/coord message(s) (round $round) ---"
        timeout 70 mosquitto_sub -h "$BROKER" -t 'mxfs/coord/#' \
            --remove-retained -W 60 >/dev/null 2>&1
    done
    if [ "$left" -gt 200 ]; then
        echo "ERROR: coord broker still holds $left retained mxfs/coord messages"
        echo "       after a full sweep. Barriers will crawl and every barrier"
        echo "       criterion will read NO_TERMINAL_RECORD. Aborting rather than"
        echo "       recording infrastructure failure as filesystem defects."
        echo "       Manual: mosquitto_sub -h $BROKER -t 'mxfs/coord/#' --remove-retained -W 300"
        exit 1
    fi
    [ "$left" = 0 ] || echo "--- coord broker: $left retained message(s) left after sweep (under threshold) ---"
}
coord_broker_hygiene

fail_stale_pending
reset_pending
trap finalize_pending EXIT
trap 'exit 143' TERM INT

echo "=== run @ ${N}/${DLM} (run_id=$RUN_ID) ==="

for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r cat tr name coord minn maxn budget scale <<<"$row"
    # prep_cluster is handled specially above, before this loop -- never
    # dispatch it as a normal test even if it appears in an explicit ONLY list.
    [ "$name" = "prep_cluster" ] && continue
    in_only "$name" || continue
    # transport applicability
    transport_matches "$tr" || continue
    # node-count applicability
    [ "$N" -ge "$minn" ] || { continue; }
    [ "$maxn" -eq 0 ] || [ "$N" -le "$maxn" ] || { continue; }
    # xfs baseline: only tests with a real native-XFS equivalent actually run.
    # The handful with NO equivalent get an explicit SKIP (not silent PENDING)
    # so showstat shows a deliberate, documented state instead of an eternal
    # "not run yet". Everything else under xfs (multi-node/coordinated tests)
    # is simply not applicable and stays PENDING like any other unrun test.
    if [ "$DLM" = xfs ]; then
        if xfs_no_equivalent "$name"; then
            record "$name" SKIP "n/a" "no native-XFS equivalent under the xfs baseline condition"
            printf "  SKIP  %s (no native-XFS equivalent)\n" "$name"
            continue
        fi
        xfs_applicable "$name" || continue
    fi
    script="$REPO/tests/$cat/$name.sh"
    if [ ! -f "$script" ]; then
        printf "  PEND  %s (no script in tests/%s)\n" "$name" "$cat"; pending=$((pending+1)); continue
    fi
    # soak's actual duration is caller-controlled (SOAK_SECONDS, default 30 for
    # a smoke run; a real ship-gate soak sets it to hours) -- a static manifest
    # budget can never be right for both, so compute it from the SAME env var
    # the test itself reads, instead of a fixed guess.
    if [ "$name" = soak ]; then budget=$(( ${SOAK_SECONDS:-30} + 30 )); fi
    # sess23: a criterion after a destructive one must not run on a cluster
    # that has not reconverged — see the wait_converged comment above.
    if [ "${BLOCK_REST:-0}" = 1 ]; then
        record "$name" BLOCKED "" "not run: the cluster did not reconverge after a destructive criterion"
        printf "  BLOCK %s (cluster unhealthy — see the destructive test above)\n" "$name"
        continue
    fi
    mark_executing "$name"
    case "$coord" in
        none) run_none "$name" "$cat" "$budget" ;;
        *)    run_coord "$name" "$cat" "$budget" "$scale" ;;
    esac
    case "$DESTRUCTIVE_TESTS" in
        *" $name "*)
            if wait_converged $(( 120 + 5 * N )); then
                echo "    (reconverged: all $N nodes report active_count=$N)"
            else
                echo "    RECONVERGENCE FAILED after $name — cluster did not return to $N members"
                record "$name" FAIL "recovery_postcondition=FAILED" \
                       "the cluster did not reconverge to $N members within $(( 120 + 5 * N ))s after this destructive test; every later criterion is BLOCKED rather than measured on a half-formed cluster"
                BLOCK_REST=1
            fi ;;
    esac
    ran=$((ran+1))
    # sess2(ccloop 26c41354): optional inter-test SETTLE — RULE-4 diagnostic for
    # the 16-node cumulative-degradation cascade (individual tests PASS, but the
    # 3rd+ test in a back-to-back suite FAILs as prior tests' destage/drain
    # backlog competes for the single shared LUN).  Sync all nodes + a short
    # drain wait so each test's dirty metadata lands and idle cached locks
    # expire before the next test.  Gated by MXFS_SETTLE_MS (default 0 = current
    # back-to-back behavior; the criteria harness stays unchanged unless set).
    if [ "${MXFS_SETTLE_MS:-0}" -gt 0 ]; then
        for n in "${NODES[@]}"; do ( timeout 25 "$SSH" "$n" "$PASS" "sync" >/dev/null 2>&1 ) & done
        wait
        sleep "$(awk "BEGIN{print ${MXFS_SETTLE_MS}/1000}")"
    fi
done

# Summary -> .last_run.json
jq -n --argjson n "$N" --arg dlm "$DLM" --arg id "$RUN_ID" \
   --argjson ran "$ran" --argjson pend "$pending" --arg t "$(date -u +%FT%TZ)" \
   '{run_id:$id, nodes:$n, dlm:$dlm, ran:$ran, pending:$pend, iso:$t}' > "$LAST"

echo "=== done: ran=$ran pending=$pending @ ${N}/${DLM} — see ./showstat.sh $N $DLM ==="
