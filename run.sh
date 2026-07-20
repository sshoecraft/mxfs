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
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
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
CRIT="$REPO/criteria.json"
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
marker_read() {  # sets MK_NODES / MK_DLM / MK_SRCVER (empty if no marker file)
    MK_NODES=""; MK_DLM=""; MK_SRCVER=""
    [ -s "$MARKER" ] || return 0
    MK_NODES=$(jq -r '.nodes // empty' "$MARKER" 2>/dev/null)
    MK_DLM=$(jq -r '.dlm // empty' "$MARKER" 2>/dev/null)
    MK_SRCVER=$(jq -r '.srcversion // empty' "$MARKER" 2>/dev/null)
}
marker_write() {  # nodes dlm srcver
    jq -n --argjson n "$1" --arg d "$2" --arg s "$3" --arg t "$(date -u +%FT%TZ)" \
        '{nodes:$n, dlm:$d, srcversion:$s, iso:$t}' > "$MARKER" 2>/dev/null
}
marker_matches() { [ "$MK_NODES" = "$N" ] && [ "$MK_DLM" = "$DLM" ] && [ "$MK_SRCVER" = "$WANT_SRCVER" ]; }
BROKER="${MXFS_COORD_BROKER:-192.168.1.149}"
# Per-test wall budget for coordinated launches (RULE 0: a timeout IS a FAIL).
# coord_barrier waits up to COORD_TIMEOUT (120s); give the launch headroom.
COORD_TIMEOUT="${COORD_TIMEOUT:-120}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"

mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
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

ssh_node() { "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

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
    local cond="${N}/${DLM}" tmp; tmp=$(mktemp)
    jq --arg k "$name" --arg c "$cond" --arg s "$status" \
       --arg m "$measured" --arg r "$reason" --arg t "$(date -u +%FT%TZ)" \
       --argjson e "${elapsed:-null}" --argjson b "${budget:-null}" \
       '.categories[].tests |= map(if .name==$k then (.runs[$c]={status:$s,measured:$m,reason:$r,iso:$t,elapsed_s:$e,budget_s:$b}) else . end)' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
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

    # 3. Form the cluster on node1 (load module w/ transport + mount).
    out=$(ssh_node "$NODE1" "MXFS_DEV='$DEV' MXFS_EXTRA_MODARGS='${MXFS_EXTRA_MODARGS:-}' bash /src/mxfs/tests/setup/prep_node.sh $BASE_TRANSPORT")
    echo "$out" | grep -q NODE_PREP_OK || { echo "PREP FAIL (form $NODE1): $out"; return 1; }

    # 4. Join the remaining nodes in parallel.
    pids=()
    local tmpd; tmpd=$(mktemp -d)
    for n in "${NODES[@]:1}"; do
        ( ssh_node "$n" "MXFS_DEV='$DEV' MXFS_EXTRA_MODARGS='${MXFS_EXTRA_MODARGS:-}' bash /src/mxfs/tests/setup/prep_node.sh $BASE_TRANSPORT" > "$tmpd/$n" 2>&1 ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done

    # 5. Verify readiness: every node has mxfs mounted at $MNT AND is running
    #    the EXACT build we just deployed.  A stale/wedged leftover mount from a
    #    prior run can satisfy the mount check while running an OLD module (a
    #    failed prep_node rmmod leaves the old mount up) — that silently runs the
    #    test on mismatched builds and yields an INVALID result.  Assert the
    #    loaded srcversion matches the local .ko on every node.
    local want_srcv
    want_srcv=$(modinfo /src/mxfs/mxfs.ko 2>/dev/null | awk '/^srcversion:/{print $2}')
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
                ( ssh_node "$n" "dmesg | grep -oE 'MXFS-MEMBERSHIP local=[0-9]+ active_count=[0-9]+' | tail -1 | grep -oE 'active_count=[0-9]+' | cut -d= -f2" 2>/dev/null | tr -d '\r\n ' > "$cgd/$n" ) &
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
                echo "    $n: $(ssh_node "$n" "dmesg | grep -oE 'MXFS-MEMBERSHIP local=[0-9]+ active_count=[0-9]+' | tail -1" 2>/dev/null | tr -d '\r')"
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
            # COORD_TIMEOUT formula unchanged: barrier waits must exceed
            # DRC_HANG_THRESHOLD_S's scaled value so peers don't
            # BARRIER_TIMEOUT before rank1's own run_bounded gives up on a
            # genuine hang.
            ct=$(( N * 12 ))
            [ "$ct" -lt 150 ] && ct=150
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
    local pa_bad="" pa_pids=() pa_n
    for pa_n in "${NODES[@]}"; do
        ( timeout 15 "$SSH" "$pa_n" "$PASS" \
            "mountpoint -q '$MNT' && mount | grep -q ' on $MNT type $fstype '" \
            >/dev/null 2>&1 ) &
        pa_pids+=($!)
    done
    i=0
    for pa_n in "${NODES[@]}"; do
        wait "${pa_pids[$i]}" || pa_bad="$pa_bad $pa_n"
        i=$((i+1))
    done
    if [ -n "$pa_bad" ]; then
        record "$name" FAIL "pre-assert" \
            "PRE-ASSERT: $fstype not mounted on$pa_bad — a prior test broke cluster formation state; reform required" \
            0 "$real_budget"
        echo "  FAIL  $name  (pre-assert: $fstype not mounted on$pa_bad)"
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
    local npass=0 fail_reason="" saw_noresult=0 n line status rank1_measured=""
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
            ( ssh_node "$kn" "pkill -f '$script' 2>/dev/null; sleep 1; fuser -k -m $MNT >/dev/null 2>&1; true" >/dev/null 2>&1 ) &
        done
        wait
        echo "    (killed leftover $name processes on all nodes after timeout)"
    fi
    # Clean up retained state.
    timeout 5 mosquitto_sub -h "$BROKER" -t "$prefix/#" --remove-retained -W 2 >/dev/null 2>&1

    local agg measured statebrk="" st
    for st in "${!state_count[@]}"; do
        [ "$st" = PASS ] && continue
        statebrk="$statebrk${statebrk:+,}${st}=${state_count[$st]}"
    done
    measured="nodes_pass=$npass/$N"
    [ -n "$statebrk" ] && measured="$measured states:$statebrk"
    [ -n "$rank1_measured" ] && measured="$measured $rank1_measured"
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
            if (.value.status=="PENDING" and ((.value.reason//"")|startswith("running "))) then
                .value = {status:"FAIL", measured:"aborted",
                          reason:("run died before recording a result (marker: "+.value.reason+")"),
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
    jq --arg c "$cond" --argjson ns "$jlist" --arg id "$RUN_ID" --arg t "$(date -u +%FT%TZ)" \
       '.categories[].tests |= map(if (.name as $n | $ns | index($n)) then (.runs[$c]={status:"PENDING",measured:"",reason:("running "+$id),iso:$t}) else . end)' \
       "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"
    echo "--- marked ${#names[@]} test(s) PENDING for ${cond}: ${names[*]} ---"
}
finalize_pending() {
    local tmp; tmp=$(mktemp)
    jq --arg id "$RUN_ID" --arg t "$(date -u +%FT%TZ)" \
       '.categories[].tests |= map(.runs |= with_entries(
            if (.value.status=="PENDING" and .value.reason==("running "+$id)) then
                .value = {status:"FAIL", measured:"aborted",
                          reason:"run aborted before this test recorded (wedge/timeout/kill)",
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
    case "$coord" in
        none) run_none "$name" "$cat" "$budget" ;;
        *)    run_coord "$name" "$cat" "$budget" "$scale" ;;
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
