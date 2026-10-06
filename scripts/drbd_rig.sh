#!/bin/bash
# drbd_rig.sh — 2/net/mesh/drbd on the rig: two test VMs, each with a pool LUN
# of its own as its local disk, DRBD dual-primary replicating the two, and
# MXFS on /dev/drbd0 mounted on both.  The design question this rig answers is
# in docs/attachment-methods.md ("DRBD dual-primary"): a shared filesystem with
# no shared storage array.
#
# Everything is real: two independent LUNs, DRBD 8.4 (the in-kernel module of
# the rig's Ubuntu 24.04 guests) on protocol C with allow-two-primaries and
# fencing resource-and-stonith, a fence authority on this host
# (tools/rig_fence_virsh.sh) with a libvirt hook holding a fenced node off, and
# MXFS admitted by its DRBD witness, fencing a dead peer by proof kind 25.
#
# Usage:
#   scripts/drbd_rig.sh all                 steps 1-7 in order; a refusal at 5 or 6 still
#                                              measures 7's raw DRBD legs, then exits 1
#   scripts/drbd_rig.sh up                  1-4 (+ the backing-LUN fio baseline): VMs, LUNs, DRBD
#   scripts/drbd_rig.sh mxfs                5: load mxfs, mkfs /dev/drbd0 on node 1, mount on both
#   scripts/drbd_rig.sh suite [test ...]    6: ./run.sh 2/net/mesh/drbd --group <g> [test ...]
#   scripts/drbd_rig.sh fio                 7: fio_perf on the mount (when mounted), then raw
#                                              /dev/drbd0 legs (DESTROYS the filesystem)
#   scripts/drbd_rig.sh fence-test          cut the replication link: node 1 must power node 2 off
#                                              and resume, then node 2 boots, resyncs and rejoins
#   scripts/drbd_rig.sh split-test          cut the link on both sides with no tiebreak delay: the
#                                              fence authority must leave exactly one node running
#   scripts/drbd_rig.sh death-test          destroy node 2 with MXFS mounted: node 1 must fence it,
#                                              certify, replay its slice and keep every fsynced file;
#                                              node 2 then rejoins and reads the same; cold chk clean
#   scripts/drbd_rig.sh self-death-test     the physical PVE pair's setup: no node fence (agent=self).
#                                              The node with the higher DRBD address dies under VM-like
#                                              loads on the survivor, which must exclude it, certify,
#                                              replay and keep every load free of I/O errors; the guard
#                                              then releases the dead node, which rejoins; cold chk clean
#   scripts/drbd_rig.sh outage-test         both nodes die at once; a bootstrap with its swaps refused writes
#                                              nothing, then the pair recovers with every fsynced file
#   scripts/drbd_rig.sh self-outage-test    both nodes die at once under the built-in authority (agent=self) and
#                                              come back through the boot program alone: the pair must recover
#                                              by itself (SELF_OUTAGE_HOLD_TICKET=1: one dies holding its swap lock;
#                                              SELF_OUTAGE_RESUME=1: the first mount fails after K's replay and resumes;
#                                              SELF_OUTAGE_PEER_PRIMARY=1: the first mount is refused, stepped down, retried)
#   scripts/drbd_rig.sh takeover-test [self|foreign]
#                                           a pair outage whose bootstrap owner fails after adopting
#                                           K: the term is taken over and finished (TAKEOVER_NOCAW_ARM=1
#                                           first refuses the contender's takeover-journal swaps)
#   scripts/drbd_rig.sh remount-test        clean unmount/remount cycles, a crash-cut retirement and a
#                                              whole-cluster restart, all on one filesystem
#   scripts/drbd_rig.sh resolve-test        passthrough never resolves /dev/drbd0 (or dm on it) to its
#                                              backing disk; a loop-device mount refuses and writes nothing
#   scripts/drbd_rig.sh reconfig            re-apply the resource file and fencing to the running pair
#   scripts/drbd_rig.sh hook-setup          install the libvirt hook that refuses an inhibited start
#   scripts/drbd_rig.sh fence-setup         authorise the rig fence key on this host (up does it)
#   scripts/drbd_rig.sh status              DRBD state, mounts and LUNs of both nodes
#   scripts/drbd_rig.sh down                unmount, take DRBD down, return both LUNs
#
# Env:
#   MXFS_GROUP        the rig group whose two nodes are used (default g2)
#   DRBD_RIG_NO_BASELINE=1   skip the backing-LUN fio legs in `up`
#
# Evidence: tests/evidence/drbd_rig/<UTC stamp>-<subcommand>/ (one log per step,
# fio.json with every leg).  Suite and fio_perf results go to a board of their
# own, tests/evidence/drbd_rig/criteria.trial.json: a trial configuration is
# never a column of data/criteria.json.
#
# LUNs.  A pool allocation binds one LUN to a node set, and one owner holds one
# allocation; DRBD wants one LUN per node.  So each node's LUN is owned by a
# holder process of its own (`tail --pid` on this script), which lives exactly
# as long as this invocation.  When it exits the allocations are kept, still
# bound, and the next invocation on the same node adopts them without a
# rebind (tools/lun_pool.sh).  A fresh bind logs the node out of every target,
# which pulls the disk out from under a running DRBD — so DRBD is always taken
# down on both nodes before any allocation.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO/tools/mxfs_lab.sh"
. "$REPO/tests/lib/runlock.sh"
SSH="$REPO/tools/mxfs_sshpass.sh"
POOL="$REPO/tools/lun_pool.sh"
CONFIG=2/net/mesh/drbd
SLUG=2-net-mesh-drbd
GROUP=${MXFS_GROUP:-g2}
RES=mxfs
DRBD_DEV=/dev/drbd0
DRBD_PORT=7789
MNT=/mnt/shared
LOG_SLICES=4    # 2N, as run.sh gives a 2-node cluster on a 20 GiB LUN

# Budgets, each from what the step should take on this rig.  The raw iSCSI
# ceiling of one pool LUN is ~180-270 MiB/s seqW (.raw_fio_ceiling.net-mesh-direct.json),
# so a 20 GiB initial sync should take ~80-115 s; twice that is the budget.
SYNC_BUDGET=240
CONNECT_BUDGET=30
APT_BUDGET=120      # one ~1 MB package and its dependencies from the Ubuntu mirror
FIO_LEG_S=20        # ramp 5 + runtime 15, time_based
FIO_LEG_BUDGET=60   # the leg, fio's setup and the ssh round trip, twice over

read -r -a NODES <<<"$("$REPO/tools/mxfs_lab.sh" group "$GROUP")"
[ "${#NODES[@]}" = 2 ] || { echo "drbd_rig: group $GROUP has ${#NODES[@]} nodes; DRBD dual-primary is exactly two"; exit 2; }
N1=${NODES[0]}; N2=${NODES[1]}

CMD=${1:-}; [ "$#" -gt 0 ] && shift
EVID="$REPO/tests/evidence/drbd_rig/$(date -u +%Y%m%dT%H%M%SZ)-${CMD:-none}"

say() { echo "[$(date +%H:%M:%S)] $*"; }
die() { say "FAIL: $*"; exit 1; }
# ssh_n <node> <command> [timeout]: the command's output, with sshpass noise dropped
ssh_n() { timeout "${3:-60}" "$SSH" "$(lab_addr "$1")" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'; }
# both <command> [timeout]: run on both nodes at once; output to $EVID/<step>.<node>, rc in .rc
# Every wait names its pids: a bare `wait` also waits for the LUN holders,
# which live until this script exits, so it never returns.
both() {
    local step=$1 cmd=$2 t=${3:-60} n pids=()
    for n in "${NODES[@]}"; do
        ( ssh_n "$n" "$cmd" "$t" > "$EVID/$step.$n"; echo "${PIPESTATUS[0]}" > "$EVID/$step.$n.rc" ) &
        pids+=($!)
    done
    wait "${pids[@]}"
}
evid() { mkdir -p "$EVID" || die "cannot create $EVID"; }

# The rig shared, both nodes and this configuration exclusive: the same files
# and modes run.sh takes (tests/lib/runlock.sh), but with the descriptors kept,
# so they can be closed before run.sh is started (it takes them itself) and
# are never inherited by a LUN holder that outlives the step.
LOCK_FDS=()
lock_one() {  # <file> <shared|exclusive> <what>
    local fd flag=-x
    [ "$2" = shared ] && flag=-s
    exec {fd}>>"$1" || return 1
    flock -n $flag "$fd" || { exec {fd}>&-; return 1; }
    [ "$2" = exclusive ] && : > "$1"
    echo "$$ $(date -u +%FT%TZ) $3" >> "$1"
    LOCK_FDS+=("$fd")
}
take_locks() {
    local what="drbd_rig.sh $CMD $CONFIG --group $GROUP" n
    need_no_snapshots
    lock_one "$RUNLOCK" shared "$what" || die "a whole-rig run holds $RUNLOCK: $(runlock_holder "$RUNLOCK")"
    for n in "${NODES[@]}"; do
        lock_one "/tmp/mxfs_node.$n.lock" exclusive "$what" \
            || die "$n is held by another run: $(runlock_holder "/tmp/mxfs_node.$n.lock")"
    done
    lock_one "/tmp/mxfs_config.$SLUG.lock" exclusive "$what" \
        || die "configuration $CONFIG is held by another run: $(runlock_holder "/tmp/mxfs_config.$SLUG.lock")"
}
release_locks() {
    local fd
    for fd in "${LOCK_FDS[@]}"; do exec {fd}>&-; done
    LOCK_FDS=()
}

# ── LUNs ────────────────────────────────────────────────────────────────────
declare -A LUN_DEV LUN_ID
HELD=0
HOLDERS=()
# The holders end with this script, at once: `tail --pid` notices its pid gone
# only on its next poll, up to a second later, and an invocation started
# straight after this one found its node still held by a live allocation.
end_holders() { [ "${#HOLDERS[@]}" -gt 0 ] && kill "${HOLDERS[@]}" 2>/dev/null; return 0; }
trap end_holders EXIT
hold_luns() {  # <fresh|adopt>: one live allocation per node, each owned by its own holder process
    local mode=$1 n h line fd
    [ "$HELD" = 1 ] && return 0
    for n in "${NODES[@]}"; do
        # adopt: only the allocation an earlier `up` left bound to this node.
        # A fresh bind logs the node out of every target, which would pull the
        # disk out from under a running DRBD.
        if [ "$mode" = adopt ] && ! "$POOL" lookup --nodes "$n" >/dev/null; then
            die "$n holds no pool LUN — run scripts/drbd_rig.sh up"
        fi
        ( for fd in "${LOCK_FDS[@]}"; do exec {fd}>&-; done; exec tail --pid=$$ -f /dev/null ) >/dev/null 2>&1 &
        h=$!
        HOLDERS+=("$h")
        line=$("$POOL" alloc --owner "$h" --what "drbd_rig $CONFIG $n" "$n") \
            || die "no pool LUN for $n (tools/lun_pool.sh status)"
        echo "$line" >> "$EVID/luns"
        LUN_DEV[$n]=$(sed -n 's/.* dev=\([^ ]*\).*/\1/p' <<<"$line")
        LUN_ID[$n]=$(sed -n 's/.* id=\([^ ]*\).*/\1/p' <<<"$line")
        [ -n "${LUN_DEV[$n]}" ] || die "unusable allocation for $n: $line"
        say "  $n: lun${LUN_ID[$n]} ${LUN_DEV[$n]}"
    done
    HELD=1
}

# ── node snippets ───────────────────────────────────────────────────────────
# Unmount mxfs (bounded: an unbounded umount that hangs in the kernel is a task
# nothing can kill), unload the module, take the resource down.
NODE_UNMOUNT='
    # A boot program an interrupted outage test left running would mount this
    # node on its own as soon as its peer mounts, in the middle of a later step.
    systemctl stop mxfs-rig-boot 2>/dev/null; systemctl reset-failed mxfs-rig-boot 2>/dev/null
    if mountpoint -q '"$MNT"'; then
        fuser -km '"$MNT"' 2>/dev/null; sleep 1
        timeout 30 umount '"$MNT"' 2>/dev/null || timeout 30 umount -f '"$MNT"' 2>/dev/null
    fi
    mountpoint -q '"$MNT"' && { echo STOP_FAIL still mounted; exit 1; }
    for t in 1 2 3 4 5; do lsmod | grep -q "^mxfs " || break; rmmod mxfs 2>/dev/null && break; sleep 2; done
    lsmod | grep -q "^mxfs " && { echo STOP_FAIL mxfs still loaded; exit 1; }'
NODE_STOP=$NODE_UNMOUNT'
    if [ -e /etc/drbd.d/'"$RES"'.res ] && lsmod | grep -q "^drbd "; then
        timeout 30 drbdadm down '"$RES"' >/dev/null 2>&1
    fi
    echo STOP_OK'
# DRBD's resource up on a node that has just booted.  The pool LUN logs back in
# at boot (node.startup=automatic), but open-iscsi.service can lose a race with
# iscsid for the node-database lock ("Could not open /run/lock/iscsi: File
# exists") and exit without logging in, which leaves DRBD no backing disk.  So
# wait for the disk the resource names, logging in again while it is absent.
LOGIN_BUDGET=30     # one login over the lab bridge takes well under a second
NODE_DRBD_UP='modprobe drbd || echo "DRBD_UP_FAIL modprobe drbd"
    ll=$(drbdadm sh-ll-dev '"$RES"' 2>/dev/null)
    for i in $(seq 1 '"$LOGIN_BUDGET"'); do
        [ -b "$ll" ] && break
        iscsiadm -m node --loginall=automatic >/dev/null 2>&1
        udevadm settle -t 5 >/dev/null 2>&1
        [ -b "$ll" ] || sleep 1
    done
    [ -b "$ll" ] || echo "DRBD_UP_FAIL backing disk ${ll:-unnamed} absent after '"$LOGIN_BUDGET"' login attempts"
    drbdadm up '"$RES"' 2>&1 | tail -1'

stop_nodes() {
    both stop "$NODE_STOP" 120
    local n
    for n in "${NODES[@]}"; do
        grep -aq '^STOP_OK' "$EVID/stop.$n" || die "$n would not release mxfs/DRBD: $(tail -1 "$EVID/stop.$n")"
    done
}

drbd_res() {  # the resource file, identical on both nodes
    local a1 a2
    a1=$(lab_addr "$N1"); a2=$(lab_addr "$N2")
    cat <<EOF
# written by scripts/drbd_rig.sh — 2/net/mesh/drbd
resource $RES {
    net {
        protocol C;
        allow-two-primaries yes;
        # A split stays disconnected until the authoritative side is chosen
        # explicitly: a heuristic that discards a replica can discard
        # acknowledged filesystem writes.
        after-sb-0pri disconnect;
        after-sb-1pri disconnect;
        after-sb-2pri disconnect;
        max-buffers 8000;
        max-epoch-size 8000;
        # A dead peer is noticed by a keep-alive it no longer answers.  With
        # writes in flight the first ping-int ends with peer data still
        # arriving, so the ping goes out only after a second one: detection
        # is up to 2 x ping-int + ping-timeout, and every write waits for it.
        # The default 10 s froze the survivor's I/O 21 s (self-death-test).
        ping-int 3;
    }
    disk {
        c-plan-ahead 0;
        resync-rate 1000M;
        al-extents 3389;
        # A Primary that loses its peer freezes all I/O until the handler
        # confirms the peer node is powered off (exit 7).  Without this, a
        # split replication link leaves both Primaries writing.
        fencing resource-and-stonith;
    }
    handlers {
        fence-peer "/usr/sbin/mxfs-drbd-fence-peer";
    }
    on $N1 {
        device $DRBD_DEV minor 0;
        disk "${LUN_DEV[$N1]}";
        address $a1:$DRBD_PORT;
        meta-disk internal;
    }
    on $N2 {
        device $DRBD_DEV minor 0;
        disk "${LUN_DEV[$N2]}";
        address $a2:$DRBD_PORT;
        meta-disk internal;
    }
}
EOF
}

# ── fio ─────────────────────────────────────────────────────────────────────
# One leg: fio_perf's discipline (O_DIRECT, libaio, QD32), time_based like
# scripts/raw_fio_ceiling.sh so the number is the sustained pipe and not burst
# absorption.  The device is resolved to its kernel name on the node: fio
# splits a filename on ':' and a by-path name would become several files.
FIO_SNIPPET='
    d=$(readlink -f DEV)
    [ -b "$d" ] || { echo "FIO_FAIL no block device DEV"; exit 1; }
    sync; echo 3 > /proc/sys/vm/drop_caches
    fio --name=leg --filename="$d" --offset=OFFG --size=SIZEm --rw=RW --bs=BS \
        --time_based --ramp_time=5 --runtime=15 --ioengine=libaio --direct=1 --iodepth=32 \
        --output-format=json > /root/drbd_rig_fio.json 2>/root/drbd_rig_fio.err \
        || { echo "FIO_FAIL rc=$? $(tail -1 /root/drbd_rig_fio.err)"; exit 1; }
    python3 -c "import json; j=json.load(open(\"/root/drbd_rig_fio.json\"))[\"jobs\"][0]; s=j[\"read\"] if j[\"read\"][\"io_bytes\"] else j[\"write\"]; print(\"FIO_OK mib=%.1f iops=%d lat_us=%.0f\" % (s[\"bw_bytes\"]/1048576.0, s[\"iops\"], s[\"lat_ns\"][\"mean\"]/1000.0))"'

fio_snippet() {  # <dev> <rw> <bs> <offset G> <size M>
    local s=${FIO_SNIPPET//DEV/$1}
    s=${s//RW/$2}; s=${s//BS/$3}; s=${s//OFF/$4}; s=${s//SIZE/$5}
    echo "$s"
}

# fio_legs <label> <dev-of-node-fn> <node>...: the four legs, the listed nodes at once
fio_legs() {
    local label=$1 devfn=$2 n i rw bs size off line agg_mib agg_iops pids; shift 2
    local nodes=("$@")
    for spec in "write 1M 1024" "randwrite 4k 256" "read 1M 1024" "randread 4k 256"; do
        read -r rw bs size <<<"$spec"
        i=0; pids=()
        for n in "${nodes[@]}"; do
            off=$(( 4 + i * 8 ))   # disjoint 8 GiB stripes; each leg's span is inside its own
            ( ssh_n "$n" "$(fio_snippet "$($devfn "$n")" "$rw" "$bs" "$off" "$size")" "$FIO_LEG_BUDGET" \
                > "$EVID/fio.$label.$rw.$n" ) &
            pids+=($!)
            i=$((i + 1))
        done
        wait "${pids[@]}"
        agg_mib=0; agg_iops=0
        for n in "${nodes[@]}"; do
            line=$(grep -a '^FIO_\(OK\|FAIL\)' "$EVID/fio.$label.$rw.$n" | tail -1)
            case "$line" in
                FIO_OK*) ;;
                *) say "  $label $rw on $n: ${line:-no result (budget ${FIO_LEG_BUDGET}s exceeded or unreachable)}"; return 1 ;;
            esac
            agg_mib=$(awk -v a="$agg_mib" -v l="$line" 'BEGIN{split(l,f," "); sub("mib=","",f[2]); printf "%.1f", a+f[2]}')
            agg_iops=$(( agg_iops + $(sed -n 's/.* iops=\([0-9]*\).*/\1/p' <<<"$line") ))
            echo "{\"label\":\"$label\",\"rw\":\"$rw\",\"bs\":\"$bs\",\"node\":\"$n\",\"nodes\":${#nodes[@]},$(sed 's/^FIO_OK //; s/\([a-z_]*\)=\([0-9.]*\)/"\1":\2/g; s/ /,/g' <<<"$line")}" >> "$EVID/fio.jsonl"
        done
        printf '[%s]   %-22s %-9s %-3s  %9s MiB/s  %8s IOPS  (%d node%s)\n' "$(date +%H:%M:%S)" "$label" "$rw" "$bs" \
            "$agg_mib" "$agg_iops" "${#nodes[@]}" "$([ ${#nodes[@]} = 1 ] || echo s)"
    done
}
backing_dev() { echo "${LUN_DEV[$1]}"; }
drbd_dev() { echo "$DRBD_DEV"; }
fio_json() {
    [ -s "$EVID/fio.jsonl" ] || return 0
    python3 -c 'import json,sys; json.dump([json.loads(l) for l in open(sys.argv[1])], open(sys.argv[2], "w"), indent=1)' \
        "$EVID/fio.jsonl" "$EVID/fio.json"
}

# ── steps ───────────────────────────────────────────────────────────────────
step_up() {
    local n t0 out
    say "step 1-2: nodes $N1 $N2 (group $GROUP)"
    "$REPO/scripts/lab_power.sh" up "${NODES[@]}" > "$EVID/power" 2>&1 || die "power up: $(tail -1 "$EVID/power")"
    say "  $(tail -1 "$EVID/power")"
    stop_nodes
    say "step 1/3: one pool LUN per node, logged in on that node alone"
    hold_luns fresh

    if [ "${DRBD_RIG_NO_BASELINE:-0}" != 1 ]; then
        say "baseline: fio on each backing LUN before DRBD owns it (destructive; DRBD's initial sync overwrites it)"
        fio_legs backing-1node backing_dev "$N1" || die "backing fio"
        fio_legs backing-2node backing_dev "${NODES[@]}" || die "backing fio"
    fi

    say "step 4: DRBD dual-primary on $DRBD_DEV"
    local res; res=$(drbd_res)
    echo "$res" > "$EVID/$RES.res"
    # drbd-utils from the distribution (userland 9.x drives the in-kernel 8.4
    # module through drbdadm-84).  drbd.service is disabled: a reboot must not
    # bring the resource back up on its own as Secondary with an old peer view.
    both install '
        if ! command -v drbdadm >/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends drbd-utils >/tmp/drbd_rig_apt.log 2>&1 \
                || { echo "INSTALL_FAIL $(tail -1 /tmp/drbd_rig_apt.log)"; exit 1; }
        fi
        systemctl disable --now drbd >/dev/null 2>&1
        modprobe drbd || { echo "INSTALL_FAIL modprobe drbd"; exit 1; }
        echo "INSTALL_OK drbd=$(cat /sys/module/drbd/version 2>/dev/null) utils=$(dpkg-query -W -f="\${Version}" drbd-utils 2>/dev/null)"' "$APT_BUDGET"
    for n in "${NODES[@]}"; do
        grep -aq '^INSTALL_OK' "$EVID/install.$n" || die "$n: $(tail -1 "$EVID/install.$n")"
    done
    say "  $(grep -a '^INSTALL_OK' "$EVID/install.$N1")"
    install_fencing

    # Fresh metadata on both disks, then up: they connect as Secondary/Inconsistent.
    both createmd "
        echo '$(base64 -w0 <<<"$res")' | base64 -d > /etc/drbd.d/$RES.res
        drbdadm sh-nop >/dev/null 2>&1 || { echo \"MD_FAIL config: \$(drbdadm sh-nop 2>&1 | tail -1)\"; exit 1; }
        drbdadm -- --force create-md $RES </dev/null >/tmp/drbd_rig_md.log 2>&1 \
            || { echo \"MD_FAIL \$(tail -1 /tmp/drbd_rig_md.log)\"; exit 1; }
        drbdadm up $RES >/tmp/drbd_rig_up.log 2>&1 || { echo \"MD_FAIL up: \$(tail -1 /tmp/drbd_rig_up.log)\"; exit 1; }
        echo MD_OK" 60
    for n in "${NODES[@]}"; do
        grep -aq '^MD_OK' "$EVID/createmd.$n" || die "$n: $(tail -1 "$EVID/createmd.$n")"
    done
    out=$(ssh_n "$N1" "for i in \$(seq 1 $CONNECT_BUDGET); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && { echo CONNECTED; exit 0; }; sleep 1; done; echo \"NOT_CONNECTED \$(drbdadm cstate $RES)\"" $((CONNECT_BUDGET + 15)))
    grep -q '^CONNECTED' <<<"$out" || die "the replication link did not connect in ${CONNECT_BUDGET}s: $out"
    say "  connected; full initial sync from $N1 (budget ${SYNC_BUDGET}s)"
    t0=$(date +%s)
    out=$(ssh_n "$N1" "drbdadm primary --force $RES 2>&1 | tail -1
        for i in \$(seq 1 $SYNC_BUDGET); do
            [ \"\$(drbdadm dstate $RES)\" = UpToDate/UpToDate ] && { echo SYNC_OK; exit 0; }
            sleep 1
        done
        echo \"SYNC_TIMEOUT \$(drbdadm dstate $RES) \$(grep -o 'sync.ed:.*' /proc/drbd | head -1)\"" $((SYNC_BUDGET + 20)))
    echo "$out" > "$EVID/sync"
    grep -q '^SYNC_OK' <<<"$out" || die "initial sync: budget exceeded is a failure: $(tail -1 <<<"$out")"
    local secs=$(( $(date +%s) - t0 ))
    say "  synced in ${secs}s ($(awk -v s="$secs" 'BEGIN{printf "%.0f", 20480/(s?s:1)}') MiB/s over 20 GiB)"
    out=$(ssh_n "$N2" "drbdadm primary $RES 2>&1 | tail -1; drbdadm role $RES")
    both role "drbdadm role $RES; drbdadm dstate $RES; drbdadm cstate $RES" 20
    for n in "${NODES[@]}"; do
        [ "$(sed -n 1p "$EVID/role.$n")" = Primary/Primary ] || die "$n role is $(tr '\n' ' ' < "$EVID/role.$n"), not Primary/Primary: $out"
    done
    say "  DRBD: Primary/Primary UpToDate/UpToDate Connected on both"
}

# Re-apply the resource file and the fencing pieces to a running pair, without
# new metadata or a resync: what a change to the handler, its path or the
# fence configuration needs.  MXFS is unmounted first; DRBD stays up.
step_reconfig() {
    local res n
    need_dual_primary
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    for n in "${NODES[@]}"; do grep -aq '^STOP_OK' "$EVID/stop.$n" || die "$n would not release mxfs: $(tail -1 "$EVID/stop.$n")"; done
    install_fencing
    res=$(drbd_res); echo "$res" > "$EVID/$RES.res"
    both adjust "
        echo '$(base64 -w0 <<<"$res")' | base64 -d > /etc/drbd.d/$RES.res
        drbdadm adjust $RES 2>&1 | tail -1
        drbdadm dump $RES 2>/dev/null | grep -o 'fence-peer[^;]*'" 40
    for n in "${NODES[@]}"; do
        grep -qE 'fence-peer[[:space:]]+"?/usr/sbin/mxfs-drbd-fence-peer' "$EVID/adjust.$n" || die "$n: handler not applied: $(tail -2 "$EVID/adjust.$n")"
    done
    need_dual_primary
    say "reconfig: resource and fencing re-applied on both nodes; Primary/Primary UpToDate/UpToDate Connected"
}

need_dual_primary() {
    local n
    both check "drbdadm role $RES 2>&1; drbdadm dstate $RES 2>&1; drbdadm cstate $RES 2>&1" 20
    for n in "${NODES[@]}"; do
        [ "$(tr '\n' ' ' < "$EVID/check.$n")" = "Primary/Primary UpToDate/UpToDate Connected " ] \
            || die "$n DRBD is [$(tr '\n' ' ' < "$EVID/check.$n")] — run scripts/drbd_rig.sh up"
    done
}

step_mxfs() {
    local out n
    need_dual_primary
    say "step 5: mxfs on $DRBD_DEV ($(modinfo -F srcversion "$REPO/mxfs.ko"))"
    # A cluster left mounted (by a suite run, say) is unmounted first: mkfs
    # refuses to format under a live heartbeat writer, and must.
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    for n in "${NODES[@]}"; do
        grep -aq '^STOP_OK' "$EVID/stop.$n" || die "$n would not release mxfs: $(tail -1 "$EVID/stop.$n")"
    done
    both src 'mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; mountpoint -q /src && echo SRC_OK' 40
    for n in "${NODES[@]}"; do grep -aq '^SRC_OK' "$EVID/src.$n" || die "$n: /src (NFS) not mounted"; done
    out=$(ssh_n "$N1" "MXFS_DEV=$DRBD_DEV MXFS_LOG_SLICES=$LOG_SLICES bash /src/mxfs/tests/setup/prep_fs.sh 2>&1" 60)
    echo "$out" > "$EVID/mkfs"
    grep -q '^FS_PREP_OK' <<<"$out" || die "mkfs on $N1: $(tail -1 <<<"$out")"
    say "  mkfs on $N1: $(grep -a '^chk_mxfs' <<<"$out" | head -1)"
    local KO_MD5; KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}')
    for n in "${NODES[@]}"; do
        ssh_n "$n" "dmesg -C; MXFS_DEV=$DRBD_DEV MXFS_KO_MD5=$KO_MD5 MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1" 150 > "$EVID/mount.$n"
        if ! grep -aq '^NODE_PREP_OK' "$EVID/mount.$n"; then
            # The kernel's reason, by its probe name, and the prep's.  Only the
            # refusal lines leave the node: a whole kernel log is not evidence
            # anyone reads, and the node keeps it.
            ssh_n "$n" "dmesg | grep -aE 'P303|P311|P-DOMAIN' | sed 's/^.*\\(P303\\|P311\\|P-DOMAIN\\)/\\1/' | cut -c1-240 | head -3" 20 > "$EVID/refusal.$n"
            say "  $n mount refused: $(grep -a 'NODE_PREP_FAIL' "$EVID/mount.$n" | tail -1)"
            [ -s "$EVID/refusal.$n" ] && sed 's/^/      kernel: /' "$EVID/refusal.$n"
            die "step 5: MXFS will not mount $DRBD_DEV on $n (evidence $EVID)"
        fi
        say "  $n: $(grep -a '^NODE_PREP_OK' "$EVID/mount.$n" | cut -c1-120)"
    done
}

need_mounted() {
    local n
    both mounted "mountpoint -q $MNT && awk '\$2 == \"$MNT\" {print \$1, \$3}' /proc/mounts" 20
    for n in "${NODES[@]}"; do
        [ "$(cat "$EVID/mounted.$n")" = "$DRBD_DEV mxfs" ] || return 1
    done
}

# A trial configuration is not a column of the release board, so its cells go
# to a board of their own, kept beside the evidence on the rig host.  It starts
# as a copy of the release board for the criteria rows themselves.
TRIAL_BOARD="$REPO/tests/evidence/drbd_rig/criteria.trial.json"
trial_board() {
    [ -s "$TRIAL_BOARD" ] || cp "$REPO/data/criteria.json" "$TRIAL_BOARD" || die "cannot create $TRIAL_BOARD"
}

step_suite() {
    trial_board
    need_dual_primary
    need_mounted || die "step 6: MXFS is not mounted on $DRBD_DEV on both nodes (scripts/drbd_rig.sh mxfs) — the suite has nothing to run on"
    say "step 6: ./run.sh $CONFIG --group $GROUP $* (on $DRBD_DEV; no pool LUN, no rewiring)"
    # The locks this process holds would refuse run.sh its own; run.sh takes
    # them itself, and the LUN holders keep both nodes' disks while it runs.
    MXFS_TRIAL=1 MXFS_DEV=$DRBD_DEV MXFS_LOG_SLICES=$LOG_SLICES \
        MXFS_CRIT="$TRIAL_BOARD" \
        "$REPO/run.sh" "$CONFIG" --group "$GROUP" "$@" 2>&1 | tee "$EVID/suite.log"
    return "${PIPESTATUS[0]}"
}

step_fio() {
    need_dual_primary
    if need_mounted; then
        trial_board
        say "step 7a: fio_perf on MXFS over DRBD (both nodes)"
        MXFS_TRIAL=1 MXFS_DEV=$DRBD_DEV MXFS_LOG_SLICES=$LOG_SLICES \
            MXFS_CRIT="$TRIAL_BOARD" \
            "$REPO/run.sh" "$CONFIG" --group "$GROUP" fio_perf > "$EVID/fio_perf.log" 2>&1
        say "  run.sh fio_perf rc=$? ($(grep -a -m3 -E 'seqW|seqR|randW|randR|PASS|FAIL' "$EVID/fio_perf.log" | tr '\n' ' ' | cut -c1-200))"
    else
        say "step 7a: MXFS is not mounted on both nodes; no filesystem fio"
    fi
    say "step 7b: raw $DRBD_DEV legs (destroys the filesystem; the next mxfs/suite reformats)"
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    for n in "${NODES[@]}"; do
        grep -aq '^STOP_OK' "$EVID/stop.$n" || die "$n would not release mxfs: $(tail -1 "$EVID/stop.$n")"
    done
    fio_legs drbd-1writer drbd_dev "$N1" || die "drbd fio"
    fio_legs drbd-2writers drbd_dev "${NODES[@]}" || die "drbd fio"
}

# ── node fencing ────────────────────────────────────────────────────────────
# The rig's node fence is the hypervisor: a guest powers its peer off through
# tools/rig_fence_virsh.sh, the forced command of one key on clyde that can
# destroy rig VMs (test<N>) and nothing else.  The key lives with the lab
# secrets, never in the tree.
FENCE_KEY="$HOME/.config/mxfslab/rig_fence_key"
FENCE_HOST=192.168.120.1
FENCE_DELAY=10   # the second node waits this long before fencing, so in a split the first one wins

fence_setup() {
    local pub line
    mkdir -p "$(dirname "$FENCE_KEY")" ~/.ssh
    [ -s "$FENCE_KEY" ] || ssh-keygen -q -t ed25519 -N '' -C mxfs-rig-fence -f "$FENCE_KEY" \
        || die "cannot create $FENCE_KEY"
    chmod 600 "$FENCE_KEY"
    pub=$(awk '{print $2}' "$FENCE_KEY.pub")
    if ! grep -qF "$pub" ~/.ssh/authorized_keys 2>/dev/null; then
        line="from=\"192.168.120.0/24\",command=\"$REPO/tools/rig_fence_virsh.sh\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $(cat "$FENCE_KEY.pub")"
        echo "$line" >> ~/.ssh/authorized_keys || die "cannot add the fence key to ~/.ssh/authorized_keys"
        chmod 600 ~/.ssh/authorized_keys
        say "fence-setup: rig fence key authorised on this host (forced command $REPO/tools/rig_fence_virsh.sh)"
    fi
}

# The libvirt hook that holds an inhibited node off whatever starts it, and
# refuses a saved-memory restore of a rig node (tools/libvirt_qemu_hook.sh).
# libvirtd reads the hooks directory when it starts, so a hook file that did
# not exist before needs one restart; running domains keep running across it.
HOOK=/etc/libvirt/hooks/qemu
FENCE_STATE_DIR="$HOME/.local/state/mxfs-rig-fence"
hook_setup() {
    local want="$EVID/libvirt_qemu_hook" fresh=0 before after
    sed "s|@STATE_DIR@|$FENCE_STATE_DIR|" "$REPO/tools/libvirt_qemu_hook.sh" > "$want" || die "cannot render the hook"
    if [ -e "$HOOK" ]; then
        cmp -s "$want" "$HOOK" && return 0
        grep -q 'libvirt_qemu_hook.sh' "$HOOK" || die "$HOOK exists and is not this rig's hook; refusing to overwrite it"
    else
        fresh=1
    fi
    sudo -n install -m 755 -o root -g root "$want" "$HOOK" || die "cannot install $HOOK"
    say "hook-setup: installed $HOOK"
    if [ "$fresh" = 1 ]; then
        before=$(virsh -c qemu:///system list --name | grep . | sort | tr '\n' ' ')
        sudo -n systemctl restart libvirtd || die "libvirtd restart failed"
        for i in $(seq 1 30); do virsh -c qemu:///system list --name >/dev/null 2>&1 && break; sleep 1; done
        after=$(virsh -c qemu:///system list --name | grep . | sort | tr '\n' ' ')
        [ "$before" = "$after" ] || die "running domains changed across the libvirtd restart: [$before] -> [$after]"
        say "hook-setup: libvirtd restarted to load it; running domains unchanged ($after)"
    fi
}

# A snapshot of a rig node is how an old incarnation comes back, and reverting
# a running domain to one passes no libvirt hook: the rig does not run beside one.
need_no_snapshots() {
    local n snaps
    for n in "${NODES[@]}"; do
        snaps=$(timeout 20 virsh -c qemu:///system snapshot-list --name "$n" 2>/dev/null | grep . | tr '\n' ' ')
        [ -z "$snaps" ] || die "$n has VM snapshots ($snaps): a DRBD rig node must have none (delete them first)"
    done
}

install_fencing() {
    hook_setup
    fence_setup
    local n peer delay key handler
    key=$(base64 -w0 < "$FENCE_KEY"); handler=$(base64 -w0 < "$REPO/tools/mxfs_drbd_fence_peer.sh")
    local witness; witness=$(base64 -w0 < "$REPO/tools/mxfs_drbd_witness.py")
    for n in "${NODES[@]}"; do
        if [ "$n" = "$N1" ]; then peer=$N2; delay=0; else peer=$N1; delay=$FENCE_DELAY; fi
        ssh_n "$n" "
            mkdir -p /etc/mxfs /var/lib/mxfs
            echo $key | base64 -d > /etc/mxfs/fence_key && chmod 600 /etc/mxfs/fence_key
            echo $handler | base64 -d > /usr/sbin/mxfs-drbd-fence-peer && chmod 755 /usr/sbin/mxfs-drbd-fence-peer && rm -f /usr/local/sbin/mxfs-drbd-fence-peer
            echo $witness | base64 -d > /usr/sbin/mxfs_drbd_witness.py && chmod 755 /usr/sbin/mxfs_drbd_witness.py
            printf 'agent=ssh\nhost=$FENCE_HOST\nuser=$USER\nkey=/etc/mxfs/fence_key\ndelay=$delay\nself $n\npeer $(lab_addr "$peer") $peer\n' > /etc/mxfs/drbd-fence.conf
            out=\$(timeout 30 ssh -i /etc/mxfs/fence_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $USER@$FENCE_HOST status $peer 2>&1 | tail -1)
            case \"\$out\" in 'STATE $peer '*) echo \"FENCECFG_OK \$out\" ;; *) echo \"FENCECFG_FAIL \$out\" ;; esac" 45 > "$EVID/fencecfg.$n"
        grep -aq '^FENCECFG_OK' "$EVID/fencecfg.$n" || die "$n cannot reach its node fence: $(tail -1 "$EVID/fencecfg.$n")"
    done
    say "  node fence: each node can power its peer off through $FENCE_HOST (delay: $N1 0 s, $N2 ${FENCE_DELAY} s)"
}

# Cut the replication link on node 2 and watch DRBD's fencing settle it: both
# Primaries freeze, node 1's handler powers node 2 off, node 1 resumes with its
# peer's disk Outdated.  Then node 2 is started again, resyncs from node 1 and
# is promoted, which is the rejoin a fenced node goes through.
FENCE_BUDGET=60    # DRBD notices the link loss (ping 10 s + timeout 6 s) and the handler fences (seconds)
REJOIN_BUDGET=120  # boot ~30 s, DRBD up, and a resync of only what changed while it was off
step_fence_test() {
    local out t0 secs
    need_dual_primary
    say "fence test: dropping the replication link on $N2"
    t0=$(date +%s)
    ssh_n "$N2" "iptables -I INPUT -p tcp --dport $DRBD_PORT -j DROP; iptables -I INPUT -p tcp --sport $DRBD_PORT -j DROP; echo CUT" 15 > "$EVID/cut"
    grep -q CUT "$EVID/cut" || die "could not cut the link on $N2"
    out=$(ssh_n "$N1" "
        for i in \$(seq 1 $FENCE_BUDGET); do
            if [ \"\$(drbdadm dstate $RES 2>/dev/null)\" = UpToDate/Outdated ]; then
                echo \"SURVIVOR_OK \$(drbdadm role $RES) \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"; exit 0
            fi
            sleep 1
        done
        echo \"SURVIVOR_TIMEOUT \$(drbdadm role $RES) \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"" $((FENCE_BUDGET + 15)))
    echo "$out" > "$EVID/survivor"
    secs=$(( $(date +%s) - t0 ))
    grep -q '^SURVIVOR_OK' <<<"$out" || die "fence test: $N1 did not settle in ${FENCE_BUDGET}s: $out"
    say "  $N1 settled in ${secs}s: ${out#SURVIVOR_OK }"
    out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$N2")
    case "$out" in "STATE $N2 shut off inhibit="*) ;; *) die "fence test: $N2 is not off and inhibited: $out" ;; esac
    [ "${out##*inhibit=}" != none ] || die "fence test: $N2 is off but not inhibited: $out"
    local ep=${out##*inhibit=}
    say "  $N2: shut off, inhibited (episode $ep)"
    # The survivor writes: its I/O resumed after the fence.
    out=$(ssh_n "$N1" "timeout 10 dd if=/dev/urandom of=$DRBD_DEV bs=1M count=8 seek=100 oflag=direct 2>&1 | tail -1; tail -2 /var/lib/mxfs/drbd-fence.$RES" 20)
    echo "$out" > "$EVID/survivor_write"
    grep -q 'copied' <<<"$out" || die "fence test: $N1 cannot write after the fence: $out"
    grep -q "result=STONITHED .*episode=$ep" <<<"$out" || die "fence test: no STONITHED record for episode $ep on $N1: $out"
    say "  $N1 writes after the fence; its fence record names episode $ep"
    # The fenced node stays down: the ordinary start path refuses it.
    if "$REPO/scripts/lab_power.sh" up "$N2" > "$EVID/inhibited_start" 2>&1; then
        die "fence test: lab_power started $N2 while it was inhibited"
    fi
    say "  lab_power refuses to start $N2: $(grep -a inhibited "$EVID/inhibited_start" | head -1 | cut -c1-100)"
    out=$("$REPO/tools/rig_fence_virsh.sh" release "$N2" "$ep" "$N1")
    [ "$out" = "RELEASED $N2 episode=$ep" ] || die "fence test: release: $out"

    say "  rejoin: starting $N2, DRBD resyncs it from $N1"
    t0=$(date +%s)
    "$REPO/scripts/lab_power.sh" up "$N2" > "$EVID/rejoin_power" 2>&1 || die "$N2 did not boot: $(tail -1 "$EVID/rejoin_power")"
    out=$(ssh_n "$N2" "$NODE_DRBD_UP
        for i in \$(seq 1 $REJOIN_BUDGET); do
            [ \"\$(drbdadm dstate $RES 2>/dev/null)\" = UpToDate/UpToDate ] && { drbdadm primary $RES 2>&1 | tail -1; echo \"REJOIN_OK \$(drbdadm role $RES)\"; exit 0; }
            sleep 1
        done
        echo \"REJOIN_TIMEOUT \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"" $((REJOIN_BUDGET + 20)))
    echo "$out" > "$EVID/rejoin"
    grep -q '^REJOIN_OK Primary/Primary' <<<"$out" || die "fence test: $N2 did not rejoin: $(tail -1 <<<"$out")"
    say "  $N2 rejoined in $(( $(date +%s) - t0 ))s: Primary/Primary UpToDate/UpToDate"
}

# The attachment's rejoin, for a node its survivor fenced: release the
# inhibit (the survivor's recovery is complete — the caller established that),
# boot the node, bring DRBD up so it resyncs from the survivor, promote it once
# UpToDate, and mount MXFS on it.
rejoin_node() {
    local node=$1 surv=$2 out ep
    out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$node")
    ep=${out##*inhibit=}
    if [ "$ep" != none ] && [ -n "$ep" ]; then
        out=$("$REPO/tools/rig_fence_virsh.sh" release "$node" "$ep" "$surv")
        [ "$out" = "RELEASED $node episode=$ep" ] || die "rejoin: release: $out"
        say "  released $node (episode $ep)"
    fi
    "$REPO/scripts/lab_power.sh" up "$node" > "$EVID/rejoin_power.$node" 2>&1 || die "$node did not boot"
    out=$(ssh_n "$node" "$NODE_DRBD_UP
        for i in \$(seq 1 $REJOIN_BUDGET); do
            [ \"\$(drbdadm dstate $RES 2>/dev/null)\" = UpToDate/UpToDate ] && { drbdadm primary $RES 2>&1 | tail -1; echo \"REJOIN_OK \$(drbdadm role $RES)\"; exit 0; }
            sleep 1
        done
        echo \"REJOIN_TIMEOUT \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"" $((REJOIN_BUDGET + 20)))
    grep -q '^REJOIN_OK Primary/Primary' <<<"$out" || die "rejoin: $node did not rejoin DRBD: $(tail -1 <<<"$out")"
    ssh_n "$node" "mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; MXFS_DEV=$DRBD_DEV MXFS_KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}') MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1" 180 > "$EVID/rejoin_mount.$node"
    grep -aq '^NODE_PREP_OK' "$EVID/rejoin_mount.$node" || die "rejoin: $node did not remount: $(grep -a FAIL "$EVID/rejoin_mount.$node" | tail -1)"
}

# A node dies with MXFS mounted and its journal slice dirty; the survivor must
# fence it at the DRBD layer, certify the exclusion (kind 25), replay its
# slice and complete the recovery, with every file either node had fsynced
# intact.  Then the dead node is released, started, resynced and remounted,
# which is the attachment's rejoin, and reads exactly what the survivor reads.
# A cold chk_mxfs closes it.
RECOVER_BUDGET=120  # heartbeat dead window 62 s + DRBD fence, witness, certificate, replay ~30 s
step_death_test() {
    local out t0 ep n1sum n2sum
    need_dual_primary
    need_mounted || die "death test: MXFS is not mounted on both nodes (scripts/drbd_rig.sh mxfs)"
    say "death test: fsynced files from both nodes, a writer left running on $N2"
    out=$(ssh_n "$N1" "mkdir -p $MNT/death/n1 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/death/n1/f\$i; done && sync -f $MNT && cd $MNT/death/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    n1sum=$(tail -1 <<<"$out")
    out=$(ssh_n "$N2" "mkdir -p $MNT/death/n2 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/death/n2/f\$i; done && sync -f $MNT && cd $MNT/death/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32
        nohup setsid bash -c 'i=0; while :; do i=\$((i+1)); echo \$i > $MNT/death/n2/live\$((i % 200)); done' >/dev/null 2>&1 < /dev/null &
        sleep 3; echo WRITER_UP" 60)
    n2sum=$(sed -n 1p <<<"$out")
    grep -q WRITER_UP <<<"$out" || die "death test: no writer on $N2: $out"
    [ ${#n1sum} = 32 ] && [ ${#n2sum} = 32 ] || die "death test: could not record checksums ($n1sum / $n2sum)"
    say "  n1 set $n1sum, n2 set $n2sum; destroying $N2 (a crash: no unmount, no warning)"
    ssh_n "$N1" "dmesg -C" 10 >/dev/null
    if [ "${DEATH_HOLD_TICKET:-0}" = 1 ]; then
        # the victim dies holding the swap lock: its ticket outlives it
        out=$(ssh_n "$N2" "echo 60000 > /sys/module/mxfs/parameters/dbg_drbd_cas_hold_ms
            for i in \$(seq 1 40); do dmesg | grep -q P-DBG-DRBD-CAS-HOLD && { echo HOLDING; exit 0; }; sleep 0.5; done; echo NOT_HOLDING" 40)
        grep -q HOLDING <<<"$out" || die "death test: $N2 never took the lock to hold it: $out"
        say "  $N2 holds the swap lock (test hold); destroying it now"
    fi
    t0=$(date +%s)
    timeout 60 virsh -c qemu:///system destroy "$N2" >/dev/null 2>&1 || die "death test: virsh destroy $N2 failed"

    out=$(ssh_n "$N1" "
        for i in \$(seq 1 $RECOVER_BUDGET); do
            dmesg | grep -q 'P163-RECOVERY-COMPLETE' && break
            sleep 1
        done
        dmesg | grep -aoE 'P238-DRBD-FENCE-[A-Z-]+|P236-FENCE-CERTIFIED|P-DRBD-CAS-PEER-FENCED|P-RMAN-SNAPSHOT |P163-RECOVERY-COMPLETE|P239-DRBD-EXCL-LAPSED|P238-FENCE-[A-Z-]+' | sort | uniq -c | tr '\n' ' '; echo
        dmesg | grep -q 'P163-RECOVERY-COMPLETE' && echo RECOVERED || echo NOT_RECOVERED" $((RECOVER_BUDGET + 20)))
    echo "$out" > "$EVID/death_recovery"
    ssh_n "$N1" "dmesg | grep -aE 'P238-DRBD|P236-FENCE|P-DRBD|P163|P239|P238-FENCE' | sed 's/^.*mxfs: //' | cut -c1-260" 20 > "$EVID/death_kernlog"
    grep -q '^RECOVERED' <<<"$(tail -1 <<<"$out")" || die "death test: $N1 did not complete recovery in ${RECOVER_BUDGET}s: $(head -1 <<<"$out")"
    say "  $N1 recovered $N2's slice in $(( $(date +%s) - t0 ))s: $(head -1 <<<"$out" | cut -c1-200)"
    grep -q 'P238-DRBD-FENCE-WITNESSED' "$EVID/death_kernlog" || die "death test: recovery completed without a DRBD witness"
    if [ "${DEATH_HOLD_TICKET:-0}" = 1 ]; then
        out=$(ssh_n "$N1" "dmesg | grep -ac 'P-DRBD-CAS-PEER-EXCLUDED'; dmesg | grep -ac 'P163-WITHDRAW-STAMP'" 20)
        [ "$(sed -n 1p <<<"$out")" -ge 1 ] 2>/dev/null || die "death test: the dead peer's ticket was not cleared by exclusion: $out"
        [ "$(sed -n 2p <<<"$out")" = 0 ] || die "death test: $N1 withdrew itself: $out"
        say "  the dead peer's ticket was cleared by exclusion (P-DRBD-CAS-PEER-EXCLUDED); $N1 did not withdraw"
    fi

    out=$(ssh_n "$N1" "cd $MNT/death/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/death/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32; touch $MNT/death/after && rm $MNT/death/after && echo FS_OK" 60)
    [ "$(sed -n 1p <<<"$out")" = "$n1sum" ] || die "death test: $N1's own files changed: $out"
    [ "$(sed -n 2p <<<"$out")" = "$n2sum" ] || die "death test: $N2's fsynced files are not intact on $N1: $out"
    grep -q FS_OK <<<"$out" || die "death test: $N1 cannot write after the recovery: $out"
    say "  every fsynced file of both nodes intact on $N1, which writes on"

    out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$N2")
    case "$out" in "STATE $N2 shut off inhibit="*) [ "${out##*inhibit=}" != none ] || die "death test: $N2 off but not inhibited" ;; *) die "death test: authority: $out" ;; esac
    t0=$(date +%s)
    rejoin_node "$N2" "$N1"
    out=$(ssh_n "$N2" "cd $MNT/death/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/death/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    [ "$(sed -n 1p <<<"$out")" = "$n1sum" ] && [ "$(sed -n 2p <<<"$out")" = "$n2sum" ] \
        || die "death test: the rejoined $N2 reads different data: $out"
    say "  $N2 rejoined and remounted in $(( $(date +%s) - t0 ))s, and reads both sets identically"

    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    out=$(ssh_n "$N1" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/death_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "death test: chk_mxfs after the recovery: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "  cold chk_mxfs clean"
}

# ── the pair's built-in authority (no node fence) ──────────────────────────
# The physical PVE pair runs with no node fence: /etc/mxfs/drbd-fence.conf
# absent or agent=self, and tools/mxfs_drbd_fence_self.py deciding every split
# by one fixed tie-break (the lower DRBD address wins).  The rig's node fence
# above never runs that code, so a defect on the survivor's side of it went
# unseen until the physical pair met it: the survivor never certified the
# exclusion, answered RECOVERY_BLOCKED for everything the dead node had
# mastered, and a VM whose image was among them got I/O errors.
#
# install_self_authority puts the authority on both nodes as `make install`
# does on a PVE host (this tree's program, handler and witness; agent=self),
# plus the root ssh trust between the nodes, under their names, that a Proxmox
# cluster already has and that the authority reads its release evidence over.
# The rig's node-fence configuration is kept as drbd-fence.conf.backup;
# install_fencing writes it again afterwards.
install_self_authority() {
    local n peer prog handler witness pub hostkey out
    prog=$(base64 -w0 < "$REPO/tools/mxfs_drbd_fence_self.py")
    handler=$(base64 -w0 < "$REPO/tools/mxfs_drbd_fence_peer.sh")
    witness=$(base64 -w0 < "$REPO/tools/mxfs_drbd_witness.py")
    both selfauth "
        echo $prog | base64 -d > /usr/sbin/mxfs-drbd-fence-self && chmod 755 /usr/sbin/mxfs-drbd-fence-self || { echo SELFAUTH_FAIL program; exit 1; }
        echo $handler | base64 -d > /usr/sbin/mxfs-drbd-fence-peer && chmod 755 /usr/sbin/mxfs-drbd-fence-peer || { echo SELFAUTH_FAIL handler; exit 1; }
        echo $witness | base64 -d > /usr/sbin/mxfs_drbd_witness.py && chmod 755 /usr/sbin/mxfs_drbd_witness.py || { echo SELFAUTH_FAIL witness; exit 1; }
        mkdir -p /etc/mxfs /var/lib/mxfs /root/.ssh && chmod 700 /root/.ssh
        if [ -e /etc/mxfs/drbd-fence.conf ] && ! grep -qx 'agent=self' /etc/mxfs/drbd-fence.conf; then
            cp -p /etc/mxfs/drbd-fence.conf /etc/mxfs/drbd-fence.conf.backup
        fi
        echo agent=self > /etc/mxfs/drbd-fence.conf
        [ -s /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C mxfs-rig-selfauth -f /root/.ssh/id_ed25519 || { echo SELFAUTH_FAIL keygen; exit 1; }
        command -v nft >/dev/null || { echo SELFAUTH_FAIL no nft; exit 1; }
        echo \"SELFAUTH_OK \$(cat /root/.ssh/id_ed25519.pub) HOSTKEY \$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)\"" 30
    for n in "${NODES[@]}"; do
        grep -aq '^SELFAUTH_OK' "$EVID/selfauth.$n" || die "self authority on $n: $(tail -1 "$EVID/selfauth.$n")"
    done
    for n in "${NODES[@]}"; do
        if [ "$n" = "$N1" ]; then peer=$N2; else peer=$N1; fi
        pub=$(sed -n 's/^SELFAUTH_OK \(.*\) HOSTKEY .*/\1/p' "$EVID/selfauth.$peer")
        hostkey=$(sed -n 's/^SELFAUTH_OK .* HOSTKEY \(.*\)$/\1/p' "$EVID/selfauth.$peer")
        [ -n "$pub" ] && [ -n "$hostkey" ] || die "self authority: no keys from $peer"
        out=$(ssh_n "$n" "
            touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
            grep -qF '$pub' /root/.ssh/authorized_keys || echo '$pub' >> /root/.ssh/authorized_keys
            touch /etc/ssh/ssh_known_hosts
            { grep -v '^$peer ' /etc/ssh/ssh_known_hosts; echo '$peer $hostkey'; } > /etc/ssh/ssh_known_hosts.new
            mv /etc/ssh/ssh_known_hosts.new /etc/ssh/ssh_known_hosts && echo TRUST_OK" 20)
        grep -q TRUST_OK <<<"$out" || die "ssh trust on $n: $out"
    done
    # each node reaches the other exactly as the authority's evidence read does
    for n in "${NODES[@]}"; do
        if [ "$n" = "$N1" ]; then peer=$N2; else peer=$N1; fi
        out=$(ssh_n "$n" "timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o HostKeyAlias=$peer root@$(lab_addr "$peer") hostname 2>&1 | tail -1" 30)
        [ "$out" = "$peer" ] || die "$n cannot reach $peer over ssh as the authority does: $out"
    done
    say "  built-in authority (agent=self) on both nodes; root ssh trust between $N1 and $N2"
}

# The rig's debug sites are all on (prep_node loads mxfs with dyndbg=+p): a
# loaded node fills its kernel ring in seconds, and a recovery line printed
# at minute two is gone by minute three.  For the self death test only the
# lines the verdict reads are left on, which is also closer to what a
# production log carries; so is the repeat limit a production module runs
# with (the verdict reads those lines for presence, never for a count).
SELF_TAGS='P163- P238- P236- P-DRBD- P239- P240- P-RBLK- P912-ACQ P-LKWAIT P958- P-ACQ-LADDER P960- P-TAUTH-IMPORT-RETAINED'
self_dyndbg() {  # <node> <narrow|all>
    local f cmd='c=/proc/dynamic_debug/control; l=/sys/module/mxfs/parameters/log_repeat_limit; '
    if [ "$2" = narrow ]; then
        cmd+='echo "module mxfs -p" > $c; '
        for f in $SELF_TAGS; do cmd+="echo 'module mxfs format \"$f\" +p' > \$c; "; done
        cmd+='[ -e $l ] && echo 1 > $l; '
    else
        cmd+='echo "module mxfs +p" > $c; [ -e $l ] && echo 0 > $l; '
    fi
    ssh_n "$1" "$cmd echo DYNDBG_OK" 20 | grep -q DYNDBG_OK
}

# One VM-like load on an image: O_DIRECT, io_uring as Proxmox 9 runs QEMU
# disks, 4 KiB random 60/40, QD16, time_based; an IOPS log at one-second
# resolution so the stall and the I/O after it can be read back.
self_load_cmd() {  # <image> <seconds> <tag>
    echo "date +%s%3N > /root/sdeath-$3.launch; fio --name=vm --filename=$1 --direct=1 --ioengine=io_uring --rw=randrw --rwmixread=60 --bs=4k --iodepth=16 --size=256M --time_based --runtime=$2 --log_avg_msec=1000 --write_iops_log=/root/sdeath-$3 --output-format=json --output=/root/sdeath-$3.json >/dev/null 2>/root/sdeath-$3.err; echo FIO_RC=\$?"
}
# Per load: fio's own error, its I/O count and longest latency, and from the
# IOPS log the longest stretch with no I/O completing and the I/O after it.
# wait_s is the launch to the first second with I/O: fio's own clock starts
# only once its file setup returns, and a stat or open blocked on a dead
# node's grants is spent there (0.90.58: 89.5 s, with first_s=1.0).
SELF_LOAD_SUMMARY='python3 -I - "$@" <<'"'"'PY'"'"'
import glob, json, sys
for tag in sys.argv[1:]:
    try:
        j = json.load(open("/root/sdeath-%s.json" % tag))["jobs"][0]
    except Exception as e:
        print("LOAD %s NO_RESULT %s %s" % (tag, e, open("/root/sdeath-%s.err" % tag).read().strip()[-160:].replace("\n", " | ")))
        continue
    r, w = j["read"], j["write"]
    t = []
    for f in glob.glob("/root/sdeath-%s_iops.*.log" % tag):
        for line in open(f):
            p = [x.strip() for x in line.split(",")]
            if len(p) >= 2 and p[1].isdigit() and int(p[1]) > 0:
                t.append(int(p[0]))
    t = sorted(set(t))
    # a stall is a second or more with no I/O completing; the one-second
    # cadence of the log itself jitters by a few ms and is not one
    gap, gap_end = 0, 0
    for a, b in zip(t, t[1:]):
        if b - a >= 2000 and b - a > gap:
            gap, gap_end = b - a, b
    after = sum(1 for x in t if x > gap_end) if gap_end else len(t)
    try:
        setup = (j["job_start"] - int(open("/root/sdeath-%s.launch" % tag).read())) / 1000.0
    except Exception:
        setup = -1
    print("LOAD %s error=%d read_ios=%d write_ios=%d lat_max_ms=%.0f wait_s=%.1f first_s=%.1f stall_s=%.1f stall_end_s=%.1f busy_s_after=%d last_s=%.1f" % (
        tag, j.get("error", 0), r["total_ios"], w["total_ios"],
        max(r["lat_ns"]["max"], w["lat_ns"]["max"]) / 1e6,
        (setup + t[0] / 1000.0) if t and setup >= 0 else -1, (t[0] / 1000.0) if t else -1,
        gap / 1000.0, gap_end / 1000.0, after, (t[-1] / 1000.0) if t else 0))
PY'

SELF_LOAD_S=200    # the kill at +20 s, the recovery budget, then a minute of I/O after it
TAKEOVER_LOAD_S=150  # started at the kill: the recovery budget, then 30 s of I/O after it
# The kill to P163-RECOVERY-COMPLETE, twice what it should take: DRBD notices
# within 2 x ping-int + ping-timeout (6.5 s), the handler excludes and
# disconnects (~1.2 s), the witness confirms and the heartbeat monitor declares
# the death (~2.5 s), certificate and election (~1.2 s), the slice replay
# (~4.7 s) and completion (~1.9 s): ~18 s.  Measured 17.0 s (0.90.59).
SELF_RECOVER_BUDGET=37
step_self_death_test() {
    local out t0 tk surv vict a1 a2 n i ssum vsum loads=() pids=() tags ep rel
    need_dual_primary
    need_mounted || die "self death test: MXFS is not mounted on both nodes (scripts/drbd_rig.sh mxfs)"
    a1=$(lab_addr "$N1"); a2=$(lab_addr "$N2")
    # participant 0, the survivor of every split, is the lower IPv4 address
    if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "$a1" "$a2"; then
        surv=$N1; vict=$N2
    else
        surv=$N2; vict=$N1
    fi
    install_self_authority
    say "self death test: survivor $surv (participant 0, the lower DRBD address), victim $vict"
    for n in "$surv" "$vict"; do self_dyndbg "$n" narrow || die "self death test: cannot narrow the debug sites on $n"; done

    out=$(ssh_n "$surv" "mkdir -p $MNT/sdeath/s && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/sdeath/s/f\$i; done && sync -f $MNT && cd $MNT/sdeath/s && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    ssum=$(tail -1 <<<"$out")
    out=$(ssh_n "$vict" "mkdir -p $MNT/sdeath/v && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/sdeath/v/f\$i; done && sync -f $MNT && cd $MNT/sdeath/v && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    vsum=$(tail -1 <<<"$out")
    [ ${#ssum} = 32 ] && [ ${#vsum} = 32 ] || die "self death test: could not record checksums ($ssum / $vsum)"

    # VM disks, written through once (an installed guest's image): two made by
    # the survivor, three by the victim.  Which node masters each image's lock
    # is a hash of its ledger page, so the survivor loads four of them, its own
    # and two of the victim's, to have images mastered by both nodes; the
    # victim's VM runs on the fifth.
    out=$(ssh_n "$surv" "for i in 1 2; do fio --name=fill --filename=$MNT/sdeath/img-s\$i.raw --size=256M --bs=1M --rw=write --direct=1 --ioengine=psync --output=/dev/null >/dev/null 2>&1 || { echo FILL_FAIL s\$i; exit 1; }; done; echo FILL_OK" 120)
    grep -q FILL_OK <<<"$out" || die "self death test: images on $surv: $out"
    out=$(ssh_n "$vict" "for i in 1 2 3; do fio --name=fill --filename=$MNT/sdeath/img-v\$i.raw --size=256M --bs=1M --rw=write --direct=1 --ioengine=psync --output=/dev/null >/dev/null 2>&1 || { echo FILL_FAIL v\$i; exit 1; }; done; echo FILL_OK" 120)
    grep -q FILL_OK <<<"$out" || die "self death test: images on $vict: $out"
    out=$(ssh_n "$surv" "stat -c '%i %n' $MNT/sdeath/img-*.raw" 20)
    echo "$out" > "$EVID/sdeath_inodes"
    say "  images: $(tr '\n' ' ' <<<"$out" | sed "s#$MNT/sdeath/##g")"

    say "  loads: VMs on img-s1 img-s2 img-v1 img-v2 on $surv, on img-v3 on $vict (${SELF_LOAD_S}s each); destroying $vict at +20 s"
    for i in s1 s2 v1 v2; do
        ( ssh_n "$surv" "$(self_load_cmd "$MNT/sdeath/img-$i.raw" "$SELF_LOAD_S" "$i")" $((SELF_LOAD_S + SELF_RECOVER_BUDGET + 60)) > "$EVID/sdeath_load.$i" ) &
        pids+=($!)
    done
    ( ssh_n "$vict" "$(self_load_cmd "$MNT/sdeath/img-v3.raw" "$SELF_LOAD_S" v3)" $((SELF_LOAD_S + 30)) > "$EVID/sdeath_load.v3" ) &
    sleep 20
    ssh_n "$surv" "dmesg -C; echo '<5>mxfs-test: self-death kill $vict' > /dev/kmsg" 10 >/dev/null
    t0=$(date +%s)
    timeout 60 virsh -c qemu:///system destroy "$vict" >/dev/null 2>&1 || die "self death test: virsh destroy $vict failed"
    say "  $vict destroyed (a crash: no unmount, no warning)"
    # A VM started on the survivor inside the recovery window, on the image the
    # dead node's VM was writing (an HA restart, or VM 104 on the PVE pair):
    # the dead node still holds that inode's grants, so its first I/O waits for
    # the recovery to release them, and none of it may fail.
    ( ssh_n "$surv" "$(self_load_cmd "$MNT/sdeath/img-v3.raw" "$TAKEOVER_LOAD_S" t3)" $((TAKEOVER_LOAD_S + SELF_RECOVER_BUDGET + 60)) > "$EVID/sdeath_load.t3" ) &
    pids+=($!)
    say "  takeover load started on $surv on $vict's image img-v3 (${TAKEOVER_LOAD_S}s)"

    out=$(ssh_n "$surv" "
        for i in \$(seq 1 $SELF_RECOVER_BUDGET); do
            dmesg | grep -q 'P163-RECOVERY-COMPLETE' && break
            sleep 1
        done
        dmesg | grep -aoE 'P238-DRBD-FENCE-[A-Z-]+|P236-FENCE-CERTIFIED|P-DRBD-CAS-PEER-[A-Z-]+|P163-RECOVERY-COMPLETE|P239-DRBD-EXCL-LAPSED|P238-FENCE-[A-Z-]+|P-RBLK-[A-Z-]+|P240-[A-Z-]+' | sort | uniq -c | tr '\n' ' '; echo
        dmesg | grep -q 'P163-RECOVERY-COMPLETE' && echo RECOVERED || echo NOT_RECOVERED" $((SELF_RECOVER_BUDGET + 20)))
    tk=$(( $(date +%s) - t0 ))
    echo "$out" > "$EVID/sdeath_recovery"
    ssh_n "$surv" "dmesg | grep -aE 'P238-DRBD|P236-FENCE|P-DRBD|P163|P239|P238-FENCE|P-RBLK|P240|P912|P-LKWAIT|P958|P-ACQ-LADDER|P960|mxfs-drbd-fence|no longer responding|P232-FREPLAY|elected' | sed 's/^\\(\\[[ 0-9.]*\\]\\).*\\(mxfs[-:]\\|XFS\\)/\\1 \\2/' | cut -c1-280" 20 > "$EVID/sdeath_kernlog"
    ssh_n "$surv" "tail -5 /var/lib/mxfs/drbd-fence.$RES 2>/dev/null; cat /var/lib/mxfs/drbd-inhibit.$RES.json 2>/dev/null | tr -d '\n'; echo; drbdadm cstate $RES; drbdadm dstate $RES" 20 > "$EVID/sdeath_authority"
    grep -q '^RECOVERED' <<<"$(tail -1 <<<"$out")" || die "self death test: $surv did not complete recovery in ${SELF_RECOVER_BUDGET}s: $(head -1 <<<"$out")"
    say "  $surv recovered $vict's slice in ${tk}s: $(head -1 <<<"$out" | cut -c1-220)"
    grep -q 'result=EXCLUDED .*agent=self participant=0' "$EVID/sdeath_authority" \
        || die "self death test: no EXCLUDED receipt from the built-in authority on $surv: $(head -3 "$EVID/sdeath_authority" | tr '\n' ' ')"
    grep -q 'P238-DRBD-FENCE-WITNESSED' "$EVID/sdeath_kernlog" || die "self death test: recovery completed without a DRBD witness"
    if grep -q 'P-RBLK-' "$EVID/sdeath_kernlog"; then
        die "self death test: $surv refused operations as RECOVERY_BLOCKED: $(grep -m2 'P-RBLK-' "$EVID/sdeath_kernlog" | cut -c1-200 | tr '\n' ' ')"
    fi

    wait "${pids[@]}"
    tags="s1 s2 v1 v2 t3"
    ssh_n "$surv" "set -- $tags; $SELF_LOAD_SUMMARY" 60 > "$EVID/sdeath_loads"
    i=0
    while read -r line; do
        say "    $surv ${line#LOAD }"
        case "$line" in
            "LOAD "*" error=0 "*) i=$((i + 1)) ;;
        esac
    done < <(grep -a '^LOAD ' "$EVID/sdeath_loads")
    [ "$i" = 5 ] || die "self death test: $((5 - i)) of the survivor's 5 VM loads (4 running through the death, 1 started on $vict's image at the kill) saw an I/O error or gave no result (evidence $EVID)"
    awk '/^LOAD / { for (f = 2; f <= NF; f++) if ($f ~ /^busy_s_after=/) { split($f, a, "="); if (a[2] + 0 < 20) bad = 1 } } END { exit bad }' "$EVID/sdeath_loads" \
        || die "self death test: a survivor load did not run on after its stall (busy_s_after < 20 s)"
    say "  every survivor VM load ran through the death with no I/O error and kept doing I/O after it; the load started on $vict's image at the kill did its first I/O at +$(sed -n 's/^LOAD t3 .* wait_s=\([0-9.-]*\) .*/\1/p' "$EVID/sdeath_loads") s"

    out=$(ssh_n "$surv" "cd $MNT/sdeath/s && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/sdeath/v && md5sum f* | sort -k2 | md5sum | cut -c1-32; touch $MNT/sdeath/after && rm $MNT/sdeath/after && echo FS_OK" 60)
    [ "$(sed -n 1p <<<"$out")" = "$ssum" ] || die "self death test: $surv's own files changed: $out"
    [ "$(sed -n 2p <<<"$out")" = "$vsum" ] || die "self death test: $vict's fsynced files are not intact on $surv: $out"
    grep -q FS_OK <<<"$out" || die "self death test: $surv cannot write after the recovery: $out"
    say "  every fsynced file of both nodes intact on $surv, which writes on"

    # The rejoin a PVE host goes through: the guard (the unit make install
    # enables) releases the dead node only on its own evidence, read over ssh
    # once the node is back: no MXFS superblock alive, DRBD not Primary.
    ep=$(sed -n 's/.*"episode": *"\([^"]*\)".*/\1/p' "$EVID/sdeath_authority" | head -1)
    [ -n "$ep" ] || die "self death test: no inhibit episode on $surv"
    ssh_n "$surv" "systemctl stop mxfs-rig-guard 2>/dev/null; systemd-run --unit=mxfs-rig-guard --collect /usr/sbin/mxfs-drbd-fence-self guard >/dev/null 2>&1 && echo GUARD_OK" 20 | grep -q GUARD_OK \
        || die "self death test: cannot start the guard on $surv"
    t0=$(date +%s)
    "$REPO/scripts/lab_power.sh" up "$vict" > "$EVID/sdeath_power" 2>&1 || die "self death test: $vict did not boot: $(tail -1 "$EVID/sdeath_power")"
    rel=$(ssh_n "$surv" "for i in \$(seq 1 60); do grep -qE 'result=RELEASED .*episode=$ep' /var/lib/mxfs/drbd-fence.$RES && { grep -E 'result=RELEASED .*episode=$ep' /var/lib/mxfs/drbd-fence.$RES | tail -1; exit 0; }; sleep 1; done; echo NOT_RELEASED" 75)
    echo "$rel" > "$EVID/sdeath_release"
    grep -q 'result=RELEASED' <<<"$rel" || die "self death test: the guard did not release $vict within 60 s of its boot"
    say "  guard released $vict $(( $(date +%s) - t0 ))s after it was started: ${rel##*result=RELEASED }"
    rejoin_node "$vict" "$surv"
    out=$(ssh_n "$vict" "cd $MNT/sdeath/s && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/sdeath/v && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    [ "$(sed -n 1p <<<"$out")" = "$ssum" ] && [ "$(sed -n 2p <<<"$out")" = "$vsum" ] \
        || die "self death test: the rejoined $vict reads different data: $out"
    say "  $vict rejoined and remounted in $(( $(date +%s) - t0 ))s, and reads both sets identically"
    ssh_n "$surv" "systemctl stop mxfs-rig-guard 2>/dev/null; echo" 20 >/dev/null

    self_dyndbg "$surv" all
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    out=$(ssh_n "$surv" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/sdeath_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "self death test: chk_mxfs after the recovery: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "  cold chk_mxfs clean"
    install_fencing
    say "self death test: passed (the rig's node fence is configured again; MXFS left unmounted)"
}

# A power cut of the pair under the built-in authority (agent=self), the
# physical PVE pair's setup: both nodes die at once with MXFS mounted and both
# slices dirty, and both come back through the program the mxfs-drbd@ unit runs
# at boot (`mxfs-drbd-fence-self boot`), as a Proxmox host does; nobody promotes
# or mounts by hand.  There is no node fence, so nothing powers either node
# off: the pair has to find its own way back.  The first node to mount proves
# each dead incarnation gone by its peer being DRBD Secondary on a Connected
# link with both disks UpToDate (fence kind 27), recovers both slices and ends
# the bootstrap; the other joins once it has.  Every file either node fsynced
# is intact on both, and a cold chk_mxfs is clean.
#   SELF_OUTAGE_HOLD_TICKET=1  participant 1 dies holding its swap lock, so its
#                              ticket is frozen on the platter when the pair
#                              comes back; the first swap after the outage has
#                              to set it aside, and may never write it.
#   SELF_OUTAGE_RESUME=1       participant 0's first mount fails at the
#                              bootstrap's completion, after the replay of the
#                              slice it adopted is on record (bootstrap_inject=4,
#                              TEST ONLY); the boot program's retry in the same
#                              boot must resume the term and finish it.
#   SELF_OUTAGE_PEER_PRIMARY=1 participant 1 comes back Primary without its boot
#                              program, so participant 0's first mount cannot
#                              prove it quiescent and is refused at the module's
#                              own bound (scan window + 120 s startup fence).  The
#                              boot program must report the module's reason, step
#                              down and retry; participant 1 is then demoted and
#                              its boot program started, and both must mount.
# The boot program runs as a transient unit (mxfs-rig-boot): the rig installs
# no units.
#
# From the start of the boot programs to both mounted: DRBD connects and
# resyncs the activity-log extents of two crashed primaries (the test reports
# when both disks are UpToDate), the first node's bootstrap reads the heartbeat
# table twice a dead window apart and recovers two slices (outage-test
# 2026-10-02: 137 s from its first read to P-BOOT-RECOVERY-COMPLETE), and the
# second node's ordinary join reads the table across one window (~70 s): ~210 s
# plus the resync, twice over.
SELF_OUTAGE_BUDGET=480
step_self_outage_test() {
    local out n p0 p1 a1 a2 n1sum n2sum t0 i st done_n m startup synced_at=""
    local -A mounted_at
    need_dual_primary
    a1=$(lab_addr "$N1"); a2=$(lab_addr "$N2")
    # participant 0 is the endpoint with the lower IPv4 address
    if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "$a1" "$a2"; then
        p0=$N1; p1=$N2
    else
        p0=$N2; p1=$N1
    fi
    step_mxfs
    install_self_authority
    say "self outage test: participant 0 $p0, participant 1 $p1; files fsynced and a writer left running on both"
    out=$(ssh_n "$N1" "mkdir -p $MNT/sout/n1 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/sout/n1/f\$i; done && sync -f $MNT && cd $MNT/sout/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32
        nohup setsid bash -c 'i=0; while :; do i=\$((i+1)); echo \$i > $MNT/sout/n1/live\$((i % 200)); done' >/dev/null 2>&1 < /dev/null &
        sleep 3; echo WRITER_UP" 60)
    n1sum=$(sed -n 1p <<<"$out")
    grep -q WRITER_UP <<<"$out" || die "self outage test: no writer on $N1: $out"
    out=$(ssh_n "$N2" "mkdir -p $MNT/sout/n2 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/sout/n2/f\$i; done && sync -f $MNT && cd $MNT/sout/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32
        nohup setsid bash -c 'i=0; while :; do i=\$((i+1)); echo \$i > $MNT/sout/n2/live\$((i % 200)); done' >/dev/null 2>&1 < /dev/null &
        sleep 3; echo WRITER_UP" 60)
    n2sum=$(sed -n 1p <<<"$out")
    grep -q WRITER_UP <<<"$out" || die "self outage test: no writer on $N2: $out"
    [ ${#n1sum} = 32 ] && [ ${#n2sum} = 32 ] || die "self outage test: could not record checksums ($n1sum / $n2sum)"
    if [ "${SELF_OUTAGE_HOLD_TICKET:-0}" = 1 ]; then
        out=$(ssh_n "$p1" "echo 60000 > /sys/module/mxfs/parameters/dbg_drbd_cas_hold_ms
            for i in \$(seq 1 40); do dmesg | grep -q P-DBG-DRBD-CAS-HOLD && { echo HOLDING; exit 0; }; sleep 0.5; done; echo NOT_HOLDING" 40)
        grep -q HOLDING <<<"$out" || die "self outage test: $p1 never took the swap lock to hold it: $out"
        say "  $p1 holds the swap lock (test hold): its ticket will be frozen on the platter"
    fi
    say "  sets $n1sum / $n2sum; destroying both nodes at once"
    local dpids=()
    for n in "${NODES[@]}"; do timeout 60 virsh -c qemu:///system destroy "$n" >/dev/null 2>&1 & dpids+=($!); done
    wait "${dpids[@]}"
    for n in "${NODES[@]}"; do
        [ "$(timeout 20 virsh -c qemu:///system domstate "$n")" = "shut off" ] || die "self outage test: $n is not off"
    done
    "$REPO/scripts/lab_power.sh" up "${NODES[@]}" > "$EVID/sout_power" 2>&1 || die "self outage test: boot: $(tail -1 "$EVID/sout_power")"
    # What a PVE host has at boot before mxfs-drbd@ starts: DRBD's resource up
    # (still Secondary), the module loaded, no mount.  Then the boot program on
    # both at once, as two hosts powered on together start it.
    local KO_MD5; KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}')
    local resume_args=""
    [ "${SELF_OUTAGE_RESUME:-0}" = 1 ] && resume_args=bootstrap_inject=4
    both soutprep "$NODE_DRBD_UP
        mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
        x=; [ \"\$(hostname)\" = $p0 ] && x='$resume_args'
        MXFS_EXTRA_MODARGS=\$x MXFS_NO_MOUNT=1 MXFS_DEV=$DRBD_DEV MXFS_KO_MD5=$KO_MD5 MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1 | grep -a NODE_PREP" 150
    for n in "${NODES[@]}"; do
        grep -aq '^NODE_PREP_OK' "$EVID/soutprep.$n" || die "self outage test: $n: $(tail -1 "$EVID/soutprep.$n")"
        self_dyndbg "$n" narrow || die "self outage test: cannot narrow the debug sites on $n"
    done
    local bootcmd="echo '<5>mxfs-test: self-outage boot' > /dev/kmsg
        systemctl reset-failed mxfs-rig-boot 2>/dev/null
        systemd-run --unit=mxfs-rig-boot --property=RemainAfterExit=yes --setenv=GUEST_WAIT=0 /usr/sbin/mxfs-drbd-fence-self boot $RES $MNT 2>&1 | tail -1
        echo \"BOOT_STARTED \$(drbdadm cstate $RES) \$(drbdadm dstate $RES) \$(drbdadm role $RES)\""
    if [ "${SELF_OUTAGE_PEER_PRIMARY:-0}" = 1 ]; then
        # The module's own refusal comes after the scan window (~64 s) and its
        # 120 s startup-fence bound; the step-down follows at once.
        local refuse_budget=240
        out=$(ssh_n "$p1" "for i in \$(seq 1 60); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && [ \"\$(drbdadm dstate $RES)\" = UpToDate/UpToDate ] && break; sleep 2; done
            drbdadm primary $RES 2>&1 | tail -1; drbdadm role $RES" 150)
        grep -q '^Primary/' <<<"$out" || die "self outage test: could not leave $p1 Primary: $out"
        say "  $p1 (participant 1) is Primary with no boot program; starting the boot program on $p0 alone"
        out=$(ssh_n "$p0" "$bootcmd" 30)
        grep -aq '^BOOT_STARTED' <<<"$out" || die "self outage test: $p0: the boot program did not start: $out"
        t0=$(date +%s)
        for i in $(seq 1 $((refuse_budget / 5))); do
            out=$(ssh_n "$p0" "journalctl -b 0 --no-pager -o cat -u mxfs-rig-boot | grep -aE 'failed \\(rc=|stepped down|mounted $DRBD_DEV' | cut -c1-400" 20)
            grep -q 'stepped down' <<<"$out" && break
            grep -q "mounted $DRBD_DEV" <<<"$out" && die "self outage test: $p0 mounted while $p1 was Primary: $out"
            sleep 5
        done
        echo "$out" > "$EVID/sout_peer_primary.$p0"
        grep -q 'stepped down' <<<"$out" \
            || die "self outage test: $p0's boot program did not step down within ${refuse_budget}s of its start: $(ssh_n "$p0" "systemctl is-active mxfs-rig-boot; journalctl -b 0 --no-pager -o cat -u mxfs-rig-boot | tail -3" 20 | tr '\n' ' ')"
        grep -q 'failed (rc=124' <<<"$out" && die "self outage test: $p0's mount ran past the boot program's bound instead of the module refusing: $out"
        say "  $p0 refused at +$(( $(date +%s) - t0 )) s and stepped down: $(grep -o 'failed (rc=.*' <<<"$out" | head -1 | cut -c1-240)"
        out=$(ssh_n "$p1" "drbdadm secondary $RES 2>&1 | tail -1; drbdadm role $RES" 30)
        grep -q '^Secondary/' <<<"$out" || die "self outage test: could not demote $p1: $out"
        out=$(ssh_n "$p1" "$bootcmd" 30)
        grep -aq '^BOOT_STARTED' <<<"$out" || die "self outage test: $p1: the boot program did not start: $out"
        say "  $p1 demoted and its boot program started"
    else
        both soutboot "$bootcmd" 30
        for n in "${NODES[@]}"; do
            grep -aq '^BOOT_STARTED' "$EVID/soutboot.$n" || die "self outage test: $n: the boot program did not start: $(tail -1 "$EVID/soutboot.$n")"
        done
        say "  both booted; the boot program started on both ($(grep -a '^BOOT_STARTED' "$EVID/soutboot.$p0" | cut -d' ' -f2-) on $p0)"
    fi
    t0=$(date +%s)
    for i in $(seq 1 $((SELF_OUTAGE_BUDGET / 5))); do
        both soutstate "echo \"\$(systemctl is-active mxfs-rig-boot 2>/dev/null) \$(drbdadm cstate $RES 2>/dev/null) \$(drbdadm dstate $RES 2>/dev/null) \$(drbdadm role $RES 2>/dev/null) MNT=\$(awk '\$3 == \"mxfs\" && \$1 == \"$DRBD_DEV\" {print \$2}' /proc/mounts | head -1)\"" 15
        done_n=0
        for n in "${NODES[@]}"; do
            st=$(cat "$EVID/soutstate.$n")
            [ -z "$synced_at" ] && grep -q ' Connected UpToDate/UpToDate ' <<<"$st" && synced_at=$(( $(date +%s) - t0 ))
            case "$st" in
                *" MNT=$MNT")
                    done_n=$((done_n + 1))
                    [ -n "${mounted_at[$n]:-}" ] || mounted_at[$n]=$(( $(date +%s) - t0 )) ;;
                failed*|inactive*) done_n=$((done_n + 1)) ;;
            esac
        done
        [ "$done_n" = 2 ] && break
        sleep 5
    done
    say "  DRBD Connected with both disks UpToDate at +${synced_at:-never} s"
    for n in "${NODES[@]}"; do
        ssh_n "$n" "grep -aE 'mxfs-test|P-BOOT-|P-DRBD-|P236-FENCE|P238-|P163-|P239-|P-RBLK-|mxfs-drbd-fence|P-DBG-DRBD|P-LOG-MOUNT-CANCEL|P-RMAN-|P-TAUTH-(IMPORT-RESIDUE|RETENTION|IMPORT-RETIRE|IMPORT-RETAINED|RETAINED-RELEASE)|Starting recovery|Ending recovery|Ending clean mount' /root/dmesg.stream | sed 's/^\\(\\[[ 0-9.]*\\]\\).*\\(mxfs[-:]\\|XFS\\)/\\1 \\2/' | cut -c1-300" 30 > "$EVID/sout_kernlog.$n"
        # base64: ssh_n filters lines, which a gzip stream would not survive
        ssh_n "$n" "gzip -c /root/dmesg.stream | base64 -w 76" 60 | base64 -d > "$EVID/sout_dmesg_stream.$n.gz"
        ssh_n "$n" "journalctl -b 0 --no-pager -o short-iso -u mxfs-rig-boot -t mxfs-drbd-fence | cut -c1-300 | tail -60; tail -5 /var/lib/mxfs/drbd-fence.$RES 2>/dev/null" 30 > "$EVID/sout_bootlog.$n"
    done
    for n in "${NODES[@]}"; do
        say "  $n: $(cat "$EVID/soutstate.$n")$([ -n "${mounted_at[$n]:-}" ] && echo ", mounted at +${mounted_at[$n]} s")"
    done
    for n in "${NODES[@]}"; do
        grep -q " MNT=$MNT\$" "$EVID/soutstate.$n" \
            || die "self outage test: $n did not mount within ${SELF_OUTAGE_BUDGET}s of the boot programs' start: $(grep -aoE 'P-DRBD-STARTUP-[A-Z-]+[^—]*|P-BOOT-[A-Z-]+ [^ ]*' "$EVID/sout_kernlog.$n" | tail -3 | tr '\n' ' ') (evidence $EVID)"
    done
    # The bootstrap's owner is whichever node passed its startup proof; every
    # victim it recovered was certified by the peer being Secondary (kind 27).
    startup=$(grep -l 'P-DRBD-STARTUP-PEER-SECONDARY' "$EVID"/sout_kernlog.* 2>/dev/null | head -1)
    [ -n "$startup" ] || die "self outage test: no node proved its peer quiescent at startup: $(grep -ahoE 'P-DRBD-STARTUP-[A-Z-]+' "$EVID"/sout_kernlog.* | sort | uniq -c | tr '\n' ' ')"
    m=${startup##*.}
    grep -q 'P-BOOT-RECOVERY-COMPLETE' "$EVID/sout_kernlog.$m" || die "self outage test: $m mounted without completing the bootstrap"
    out=$(grep -c 'P236-FENCE-CERTIFIED.*kind=DRBD_PEER_SECONDARY_V1' "$EVID/sout_kernlog.$m")
    [ "$out" -ge 2 ] || die "self outage test: $m certified $out victim(s) by kind 27, not both incarnations"
    say "  $m owned the bootstrap: $(grep -o 'P-DRBD-STARTUP-PEER-SECONDARY[^—]*' "$EVID/sout_kernlog.$m" | head -1)"
    # The adopted victim's records were kept on the owner's slot for the term
    # and released by its completion.
    grep -q 'P-TAUTH-RETENTION-BOOT-K-RELEASE' "$EVID/sout_kernlog.$m" \
        || die "self outage test: $m completed the term without releasing the adopted victim's records"
    say "  $(grep -o 'P-TAUTH-RETENTION-BOOT-K-RELEASE [^—]*' "$EVID/sout_kernlog.$m" | tail -1)"
    say "  $out victims certified kind DRBD_PEER_SECONDARY_V1; $([ "$m" = "$p0" ] && echo "participant 0 first, as the boot program orders it" || echo "participant 1 owned it")"
    if [ "${SELF_OUTAGE_HOLD_TICKET:-0}" = 1 ]; then
        grep -q 'P-DRBD-CAS-PEER-SET-ASIDE ' "$EVID/sout_kernlog.$m" \
            || die "self outage test: the ticket $p1 froze was never set aside on $m"
        grep -q 'P-DRBD-CAS-PEER-EXCLUDED\|P-DRBD-CAS-PEER-FENCED' "$EVID/sout_kernlog.$m" \
            && die "self outage test: $m wrote the peer's register under a peer-Secondary proof"
        say "  the frozen ticket of $p1 was set aside without writing it: $(grep -o 'P-DRBD-CAS-PEER-SET-ASIDE [^—]*' "$EVID/sout_kernlog.$m" | head -1)"
    fi
    if [ "${SELF_OUTAGE_RESUME:-0}" = 1 ]; then
        [ "$m" = "$p0" ] || die "self outage test: the resume arm armed $p0, but $m owned the bootstrap"
        grep -q 'P-BOOT-INJECT point=4' "$EVID/sout_kernlog.$m" \
            || die "self outage test: the fail point after K's replay never fired on $m"
        grep -q 'P-BOOT-ESCROW-K-REPLAY-OK' "$EVID/sout_kernlog.$m" \
            || die "self outage test: $m never recorded K's replay"
        grep -q 'P-BOOT-RESUME term=' "$EVID/sout_kernlog.$m" \
            || die "self outage test: $m mounted without resuming the term the fail point left"
        say "  $m failed after K's replay was recorded, then resumed the term in the same boot and finished it: $(grep -o 'P-LOG-MOUNT-CANCEL [^—]*' "$EVID/sout_kernlog.$m" | head -1)"
    fi
    if grep -q 'P-RBLK-' "$EVID"/sout_kernlog.*; then
        die "self outage test: an operation was refused as RECOVERY_BLOCKED: $(grep -ah 'P-RBLK-' "$EVID"/sout_kernlog.* | head -2 | cut -c1-200 | tr '\n' ' ')"
    fi
    # A sealed record found gone before a replay is a refused volume, even
    # when a later attempt mounted.
    if grep -q 'P-RMAN-POSTSEAL-MUTATION' "$EVID"/sout_kernlog.*; then
        die "self outage test: a replay found a sealed record gone: $(grep -ah 'P-RMAN-POSTSEAL-MUTATION' "$EVID"/sout_kernlog.* | head -2 | cut -c1-220 | tr '\n' ' ')"
    fi
    for n in "${NODES[@]}"; do
        out=$(ssh_n "$n" "cd $MNT/sout/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/sout/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32; touch $MNT/sout/after.$n && rm $MNT/sout/after.$n && echo FS_OK" 60)
        [ "$(sed -n 1p <<<"$out")" = "$n1sum" ] && [ "$(sed -n 2p <<<"$out")" = "$n2sum" ] \
            || die "self outage test: $n reads different data after the outage: $out"
        grep -q FS_OK <<<"$out" || die "self outage test: $n cannot write after the outage: $out"
    done
    say "  every fsynced file of both nodes intact on both, and both write"
    both soutstop "systemctl stop mxfs-rig-boot 2>/dev/null; systemctl reset-failed mxfs-rig-boot 2>/dev/null; $NODE_UNMOUNT; echo STOP_OK" 120
    for n in "${NODES[@]}"; do grep -aq '^STOP_OK' "$EVID/soutstop.$n" || die "self outage test: $n would not release mxfs: $(tail -1 "$EVID/soutstop.$n")"; done
    out=$(ssh_n "$N1" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/sout_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "self outage test: chk_mxfs after the recovery: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "  cold chk_mxfs clean"
    install_fencing
    say "self outage test: passed (the rig's node fence is configured again; MXFS left unmounted)"
}

# Both handlers race: delay 0 on both nodes, the link cut on both sides at
# once.  The fence authority must grant exactly one: one node off and
# inhibited, the other Primary with its peer Outdated, writing.  Then the loser
# is released, started and resynced.
step_split_test() {
    local n out t0 surv loser ep s1 s2
    need_dual_primary
    both nodelay "sed -i 's/^delay=.*/delay=0/' /etc/mxfs/drbd-fence.conf && grep -c '^delay=0' /etc/mxfs/drbd-fence.conf" 15
    say "split test: delay 0 on both nodes; cutting the replication link on both sides at once"
    t0=$(date +%s)
    both cut "iptables -I INPUT -p tcp --dport $DRBD_PORT -j DROP; iptables -I INPUT -p tcp --sport $DRBD_PORT -j DROP; echo CUT" 15
    surv=""
    for i in $(seq 1 "$FENCE_BUDGET"); do
        s1=$(timeout 25 "$REPO/tools/rig_fence_virsh.sh" status "$N1"); s2=$(timeout 25 "$REPO/tools/rig_fence_virsh.sh" status "$N2")
        case "$s1|$s2" in
            *"$N1 shut off"*"|"*"$N2 shut off"*) die "split test: BOTH nodes were powered off ($s1 / $s2)" ;;
            *"$N1 running"*"|"*"$N2 shut off inhibit="*) surv=$N1; loser=$N2; out=$s2; break ;;
            *"$N1 shut off inhibit="*"|"*"$N2 running"*) surv=$N2; loser=$N1; out=$s1; break ;;
        esac
        sleep 1
    done
    [ -n "$surv" ] || die "split test: no single winner within ${FENCE_BUDGET}s ($s1 / $s2)"
    ep=${out##*inhibit=}
    [ "$ep" != none ] || die "split test: $loser is off but not inhibited"
    say "  winner $surv, loser $loser off and inhibited (episode $ep) after $(( $(date +%s) - t0 ))s"
    # The cut was made on both sides; the loser's rules went with its power,
    # the survivor's would keep the loser from ever reconnecting.
    ssh_n "$surv" "iptables -D INPUT -p tcp --dport $DRBD_PORT -j DROP; iptables -D INPUT -p tcp --sport $DRBD_PORT -j DROP; echo UNCUT" 15 > "$EVID/uncut"
    out=$(ssh_n "$surv" "
        for i in \$(seq 1 30); do [ \"\$(drbdadm dstate $RES)\" = UpToDate/Outdated ] && break; sleep 1; done
        echo \"STATE \$(drbdadm role $RES) \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"
        timeout 10 dd if=/dev/urandom of=$DRBD_DEV bs=1M count=8 seek=200 oflag=direct 2>&1 | tail -1
        grep -a 'result=' /var/lib/mxfs/drbd-fence.$RES | tail -2" 50)
    echo "$out" > "$EVID/split_survivor"
    grep -q 'STATE Primary/Unknown UpToDate/Outdated' <<<"$out" || die "split test: survivor $surv state: $(head -1 <<<"$out")"
    grep -q copied <<<"$out" || die "split test: survivor $surv cannot write: $out"
    grep -q "result=STONITHED .*episode=$ep" <<<"$out" || die "split test: survivor has no STONITHED record for $ep: $out"
    say "  $surv: Primary/Unknown UpToDate/Outdated, writes, fence record names episode $ep"
    out=$("$REPO/tools/rig_fence_virsh.sh" release "$loser" "$ep" "$surv")
    [ "$out" = "RELEASED $loser episode=$ep" ] || die "split test: release: $out"
    "$REPO/scripts/lab_power.sh" up "$loser" > "$EVID/split_rejoin_power" 2>&1 || die "$loser did not boot"
    out=$(ssh_n "$loser" "$NODE_DRBD_UP
        for i in \$(seq 1 $REJOIN_BUDGET); do
            [ \"\$(drbdadm dstate $RES 2>/dev/null)\" = UpToDate/UpToDate ] && { drbdadm primary $RES 2>&1 | tail -1; echo \"REJOIN_OK \$(drbdadm role $RES)\"; exit 0; }
            sleep 1
        done
        echo \"REJOIN_TIMEOUT \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"" $((REJOIN_BUDGET + 20)))
    grep -q '^REJOIN_OK Primary/Primary' <<<"$out" || die "split test: $loser did not rejoin: $(tail -1 <<<"$out")"
    # back to the configured tiebreak delay on node 2
    ssh_n "$N2" "sed -i 's/^delay=.*/delay=$FENCE_DELAY/' /etc/mxfs/drbd-fence.conf" 15 >/dev/null
    say "  $loser released, rejoined: Primary/Primary UpToDate/UpToDate"
}

# Two fixes that a DRBD run never reaches by itself, exercised directly on $N1.
#
# 1. Passthrough resolution.  Every SCSI passthrough caller asks
#    mxfs_bdev_to_sdev which disk to send its command to;
#    /proc/fs/mxfs/sdev_resolve_probe asks it the same question for a named
#    device.  /dev/drbd0 must get none (its LBA 0 equals its backing disk's,
#    and a command sent there skips replication), and so must a dm device
#    stacked on /dev/drbd0.  The controls: the backing disk itself resolves,
#    and a dm device on a SCSI disk of its own (scsi_debug, the stand-in for a
#    multipath path) still resolves to that disk.
# 2. Compare-and-swap on a device with neither COMPARE AND WRITE nor the DRBD
#    emulator (a loop device).  A mount must refuse, and the device must be
#    byte-identical afterwards: a swap that falls back to a plain write would
#    change it.  Once as an ordinary TCP mount (the PR ledger's swap), once
#    with the fence-capability override and single-node exclusivity (the
#    bootstrap record's).
#
# The filesystem on /dev/drbd0 is unmounted on both nodes for the dm-on-DRBD
# case (a dm table cannot open a mounted device) and stays unmounted; `mxfs`
# mounts it again.
step_resolve_test() {
    local out sd sdh ko devt_scsi
    need_dual_primary
    need_mounted || die "resolve test: MXFS is not mounted on both nodes (scripts/drbd_rig.sh mxfs)"
    ko=$(modinfo -F srcversion "$REPO/mxfs.ko")
    out=$(ssh_n "$N1" "cat /sys/module/mxfs/srcversion; test -w /proc/fs/mxfs/sdev_resolve_probe && echo PROBE_OK" 15)
    [ "$(sed -n 1p <<<"$out")" = "$ko" ] || die "resolve test: $N1 runs $(sed -n 1p <<<"$out"), the tree is $ko (scripts/drbd_rig.sh mxfs)"
    grep -q PROBE_OK <<<"$out" || die "resolve test: $N1's module has no sdev_resolve_probe"
    say "resolve test on $N1, build $ko"

    probe() {  # <device> -> the probe's line for it
        ssh_n "$N1" "dmesg -C; echo $1 > /proc/fs/mxfs/sdev_resolve_probe; dmesg | grep -a 'P-SDEV-RESOLVE-PROBE\|P-MPATH-RESOLVE' | sed 's/^.*mxfs: //'" 30
    }
    out=$(probe "$DRBD_DEV"); echo "$out" > "$EVID/resolve_drbd"
    grep -q -- '-> none (bio path)' <<<"$out" || die "resolve test: $DRBD_DEV resolves to a SCSI disk: $out"
    grep -q 'P-MPATH-RESOLVE' <<<"$out" && die "resolve test: $DRBD_DEV went through the content scan: $out"
    say "  $DRBD_DEV: $(tail -1 <<<"$out")"

    sd=$(ssh_n "$N1" "drbdadm sh-ll-dev $RES" 15)
    out=$(probe "$sd"); echo "$out" > "$EVID/resolve_backing"
    grep -q -- '-> sdev ' <<<"$out" || die "resolve test: the backing disk $sd does not resolve (the probe is not answering): $out"
    say "  $sd (DRBD's backing disk, control): $(tail -1 <<<"$out")"

    # dm over a SCSI disk of its own: the multipath shape, which must resolve
    out=$(ssh_n "$N1" "modprobe scsi_debug dev_size_mb=16 num_tgts=1 max_luns=1 >/dev/null 2>&1 || { echo NO_SCSI_DEBUG; exit 0; }
        udevadm settle -t 10
        d=\$(ls /sys/bus/pseudo/drivers/scsi_debug/adapter0/host*/target*/*/block/ 2>/dev/null | head -1)
        [ -n \"\$d\" ] || { echo NO_SD_DISK; exit 0; }
        h=\$(basename \$(readlink -f /sys/block/\$d/device))
        head -c 512 /dev/urandom | dd of=/dev/\$d bs=512 count=1 oflag=direct 2>/dev/null
        timeout 20 dmsetup create mxfs_rt_scsi --table \"0 \$(blockdev --getsz /dev/\$d) linear /dev/\$d 0\" || { echo DM_FAIL; exit 0; }
        echo \"DISK \$d \$h\"" 60)
    echo "$out" > "$EVID/resolve_scsi_debug_setup"
    grep -q '^DISK ' <<<"$out" || die "resolve test: no scsi_debug dm control on $N1: $out"
    read -r _ sd sdh <<<"$(grep '^DISK ' <<<"$out")"
    out=$(probe /dev/mapper/mxfs_rt_scsi); echo "$out" > "$EVID/resolve_dm_scsi"
    # scsi_debug stays loaded: the dm device below takes this one's freed
    # number, and the cache entry this probe left must not be handed to it
    ssh_n "$N1" "timeout 20 dmsetup remove mxfs_rt_scsi && echo DM_REMOVED" 30 >> "$EVID/resolve_scsi_debug_setup"
    grep -qF -- "-> sdev $sdh" <<<"$out" || die "resolve test: dm over $sd ($sdh) does not resolve to it: $out"
    say "  dm over scsi_debug $sd (multipath shape, must resolve): $(tail -1 <<<"$out")"
    devt_scsi=$(sed -n 's/.* dev=\([0-9:]*\) .*/\1/p' <<<"$out" | tail -1)

    # dm over DRBD: matches the backing disk by content, must be refused
    both um "fuser -km $MNT 2>/dev/null; sleep 1; timeout 30 umount $MNT; mountpoint -q $MNT && echo UM_FAIL || echo UM_OK" 60
    for n in "${NODES[@]}"; do grep -q UM_OK "$EVID/um.$n" || die "resolve test: $n would not unmount: $(cat "$EVID/um.$n")"; done
    out=$(ssh_n "$N1" "timeout 20 dmsetup create mxfs_rt_drbd --table \"0 \$(blockdev --getsz $DRBD_DEV) linear $DRBD_DEV 0\" && echo DM_OK" 30)
    grep -q DM_OK <<<"$out" || die "resolve test: dm over $DRBD_DEV: $out"
    out=$(probe /dev/mapper/mxfs_rt_drbd); echo "$out" > "$EVID/resolve_dm_drbd"
    ssh_n "$N1" "timeout 20 dmsetup remove mxfs_rt_drbd; rmmod scsi_debug && echo SCSI_DEBUG_UNLOADED" 40 >> "$EVID/resolve_scsi_debug_setup"
    [ "$(sed -n 's/.* dev=\([0-9:]*\) .*/\1/p' <<<"$out" | tail -1)" = "$devt_scsi" ] \
        || die "resolve test: dm over $DRBD_DEV did not reuse $devt_scsi, so the stale-cache case was not exercised: $out"
    grep -q 'is not one of its slaves — re-resolving' <<<"$out" || die "resolve test: the cache entry for $devt_scsi was not refused: $out"
    grep -q 'P-MPATH-RESOLVE-REJECT' <<<"$out" || die "resolve test: dm over $DRBD_DEV was not refused by the slave check: $out"
    grep -q SCSI_DEBUG_UNLOADED "$EVID/resolve_scsi_debug_setup" || die "resolve test: scsi_debug is still referenced after the stale entry was dropped: $(tail -2 "$EVID/resolve_scsi_debug_setup")"
    grep -q -- '-> none (bio path)' <<<"$out" || die "resolve test: dm over $DRBD_DEV resolves to a SCSI disk: $out"
    say "  dm over $DRBD_DEV (must be refused): $(grep -a REJECT <<<"$out" | head -1 | cut -c1-160)"

    # compare-and-swap on a loop device, two arms
    cas_arm() {  # <label> <module args>
        local o
        o=$(ssh_n "$N1" "
            lsmod | grep -q '^mxfs ' && rmmod mxfs
            insmod /src/mxfs/mxfs.ko $2 || { echo INSMOD_FAIL; exit 0; }
            truncate -s 2G /root/mxfs_cas_test.img
            L=\$(losetup -f --show /root/mxfs_cas_test.img)
            if ! m=\$(/src/mxfs/tools/mkfs_mxfs -f -n $LOG_SLICES \$L 2>&1); then
                losetup -d \$L; rm -f /root/mxfs_cas_test.img
                echo \"MKFS_FAIL \$(echo \"\$m\" | tail -1)\"; exit 0
            fi
            b=\$(md5sum < \$L | cut -c1-32)
            mkdir -p /mnt/mxfs_cas_test; dmesg -C
            if timeout 60 mount -t mxfs \$L /mnt/mxfs_cas_test 2>/dev/null; then M=MOUNTED; timeout 30 umount /mnt/mxfs_cas_test; else M=REFUSED; fi
            a=\$(md5sum < \$L | cut -c1-32)
            losetup -d \$L; rm -f /root/mxfs_cas_test.img
            echo \"CAS \$M before=\$b after=\$a\"
            dmesg | grep -aE 'EOPNOTSUPP|-95|abort|refus|P303|P311|PR register|prledger|bootstrap' | sed 's/^.*mxfs: //' | cut -c1-220 | head -12" 180)
        echo "$o" > "$EVID/cas_$1"
        grep -q '^CAS REFUSED ' <<<"$o" || die "cas test ($1): a mount on a loop device was not refused: $(grep -E '^CAS|_FAIL' <<<"$o")"
        [ "$(sed -n 's/^CAS REFUSED before=\([^ ]*\) .*/\1/p' <<<"$o")" = "$(sed -n 's/^CAS REFUSED .* after=\(.*\)/\1/p' <<<"$o")" ] \
            || die "cas test ($1): the refused mount changed the device: $(grep '^CAS' <<<"$o")"
        say "  loop device, $1: refused, device byte-identical ($(sed -n 's/^CAS REFUSED before=\([^ ]*\) .*/\1/p' <<<"$o"))"
        grep -v '^CAS' <<<"$o" | sed 's/^/      kernel: /' | head -6
    }
    cas_arm tcp "force_transport=1"
    cas_arm override "force_transport=1 fence_capability_override=1 single_node_exclusive=1"
    ssh_n "$N1" "rmmod mxfs" 30 >/dev/null
    say "resolve test: passed (MXFS left unmounted; scripts/drbd_rig.sh mxfs mounts it)"
}

# A clean departure on DRBD retires itself: its RETIRE_PENDING record (written
# after its durable unmount record) carries the DRBD attachment marker, and the
# departing node publishes it EMPTY; a record a crash left RETIRE_PENDING is
# settled by the next DRBD mount by the same rule.  Without this no node could
# mount twice (D-DRBD-CLEAN-DEPARTURE-NEVER-SETTLES-SO-NO-NODE-CAN-REMOUNT).
#   1. $N2 unmounts and remounts three times with $N1 up; then $N1 once.
#   2. $N2's self-retire refused (debug mask bit 32, complete-self): the record
#      stays RETIRE_PENDING, and $N2's remount settles it.
#   3. both unmount; both mount again on the same filesystem, data intact.
# Every mount within REMOUNT_BUDGET, no stalled slot anywhere, cold chk clean.
REMOUNT_BUDGET=30   # a TCP mount on this rig takes 4-8 s
step_remount_test() {
    local out n c sum t0
    step_mxfs
    local PARAM=/sys/module/mxfs/parameters/dbg_cas_nocaw_ops
    ssh_n "$N1" "dmesg -C" 10 >/dev/null
    out=$(ssh_n "$N1" "mkdir -p $MNT/rm && head -c 4194304 /dev/urandom > $MNT/rm/blob && sync -f $MNT && md5sum < $MNT/rm/blob | cut -c1-32" 30)
    sum=$(tail -1 <<<"$out"); [ ${#sum} = 32 ] || die "remount test: no checksum: $out"
    remount() {  # <node> <label> [expect-self-retire: 1|0]
        local o s
        o=$(ssh_n "$1" "dmesg -C; timeout 30 umount $MNT; echo um_rc=\$?
            dmesg | grep -ac 'P304-RETIRE-COMPLETED-SELF.* rc=0'
            s=\$(date +%s%N); timeout $REMOUNT_BUDGET mount -t mxfs $DRBD_DEV $MNT; echo mount_rc=\$? ms=\$(( (\$(date +%s%N) - s) / 1000000 ))
            dmesg | grep -ac 'P304-RETIRE-DRBD-CLEAN.*EMPTY'
            md5sum < $MNT/rm/blob | cut -c1-32" $((REMOUNT_BUDGET + 40)))
        echo "$o" > "$EVID/remount_$2"
        grep -q '^um_rc=0' <<<"$o" || die "remount test $2: $1 would not unmount: $o"
        grep -q '^mount_rc=0 ' <<<"$o" || die "remount test $2: $1 did not remount within ${REMOUNT_BUDGET}s: $(grep mount_rc <<<"$o")"
        [ "$(tail -1 <<<"$o")" = "$sum" ] || die "remount test $2: $1 reads a different blob: $(tail -1 <<<"$o")"
        if [ "${3:-1}" = 1 ]; then
            [ "$(sed -n 2p <<<"$o")" -ge 1 ] 2>/dev/null || die "remount test $2: $1's departure did not retire itself: $o"
        fi
        say "  $2: $1 $(grep -o 'ms=[0-9]*' <<<"$o"), self-retired=$(sed -n 2p <<<"$o"), drbd-settled=$(sed -n 4p <<<"$o"), blob intact"
    }
    for c in 1 2 3; do remount "$N2" "cycle$c"; done
    remount "$N1" "n1"
    # 2: the departure's own EMPTY refused, so the record stays RETIRE_PENDING;
    # $N1's monitor or $N2's own remount settles it, whichever reads it first
    local c0 c1
    c0=$(ssh_n "$N1" "dmesg | grep -ac 'P304-RETIRE-DRBD-CLEAN.*EMPTY'" 15)
    ssh_n "$N2" "echo 32 > $PARAM" 10 >/dev/null
    out=$(ssh_n "$N2" "dmesg -C; timeout 30 umount $MNT; echo um_rc=\$?; echo 0 > $PARAM; dmesg | grep -ac 'P-DBG-CAS-NOCAW op=complete-self'" 50)
    echo "$out" > "$EVID/remount_crashcut_umount"
    grep -q '^um_rc=0' <<<"$out" && [ "$(tail -1 <<<"$out")" -ge 1 ] 2>/dev/null || die "remount test crash-cut: the self-retire was not refused: $out"
    out=$(ssh_n "$N2" "dmesg -C; timeout $REMOUNT_BUDGET mount -t mxfs $DRBD_DEV $MNT; echo mount_rc=\$?; dmesg | grep -ac 'P304-RETIRE-DRBD-CLEAN.*EMPTY'" $((REMOUNT_BUDGET + 20)))
    echo "$out" > "$EVID/remount_crashcut_mount"
    grep -q '^mount_rc=0' <<<"$out" || die "remount test crash-cut: $N2 did not remount over its own RETIRE_PENDING record: $out"
    c1=$(ssh_n "$N1" "dmesg | grep -ac 'P304-RETIRE-DRBD-CLEAN.*EMPTY'" 15)
    [ $(( c1 - c0 + $(tail -1 <<<"$out") )) -ge 1 ] 2>/dev/null || die "remount test crash-cut: the record was not settled by the DRBD rule ($N1 $c0->$c1, $N2: $out)"
    say "  crash-cut: $N2's record left RETIRE_PENDING, settled by the DRBD rule ($N1 monitor $((c1 - c0)), $N2 admission $(tail -1 <<<"$out")), $N2 mounted"
    # 3: whole-cluster restart after a clean shutdown, with $N2's record left
    # RETIRE_PENDING (its self-retire refused) and nobody mounted to settle it:
    # $N1's fresh mount must settle it in admission
    out=$(ssh_n "$N1" "timeout 30 umount $MNT; echo um_rc=\$?" 40)
    grep -q '^um_rc=0' <<<"$out" || die "remount test restart: $N1 would not unmount: $out"
    out=$(ssh_n "$N2" "echo 32 > $PARAM; timeout 30 umount $MNT; echo um_rc=\$?; echo 0 > $PARAM" 50)
    grep -q '^um_rc=0' <<<"$out" || die "remount test restart: $N2 would not unmount: $out"
    ssh_n "$N1" "dmesg -C" 10 >/dev/null
    t0=$(date +%s)
    for n in "$N1" "$N2"; do
        out=$(ssh_n "$n" "timeout $REMOUNT_BUDGET mount -t mxfs $DRBD_DEV $MNT; echo mount_rc=\$?; md5sum < $MNT/rm/blob | cut -c1-32" $((REMOUNT_BUDGET + 20)))
        echo "$out" > "$EVID/restart.$n"
        grep -q '^mount_rc=0' <<<"$out" || die "remount test restart: $n did not mount after a clean whole-cluster shutdown: $out"
        [ "$(tail -1 <<<"$out")" = "$sum" ] || die "remount test restart: $n reads a different blob"
    done
    out=$(ssh_n "$N1" "dmesg | grep -ac 'P304-RETIRE-DRBD-CLEAN.*EMPTY'" 15)
    [ "$out" -ge 1 ] 2>/dev/null || die "remount test restart: $N1's mount did not settle $N2's pending record by the DRBD rule"
    say "  whole-cluster restart, $N2's record left pending: $N1 settled it in admission, both mounted in $(( $(date +%s) - t0 ))s, blob intact"
    both stalled "dmesg | grep -ac 'P304-RETIRE-UNKNOWN-STALLED\|P-ADMIT-RETIRE-PENDING-HELD'" 15
    for n in "${NODES[@]}"; do [ "$(cat "$EVID/stalled.$n")" = 0 ] || die "remount test: $n logged $(cat "$EVID/stalled.$n") stalled-retirement lines"; done
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    out=$(ssh_n "$N1" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/remount_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "remount test: chk_mxfs: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "remount test: passed (no stalled retirement on either node; cold chk_mxfs clean)"
}

# Both nodes die at once with MXFS mounted (a power cut of the pair): nobody
# survives to fence, so nothing is inhibited, and the next mount is a
# whole-cluster bootstrap over two dead incarnations' slices.
#   A: $N1 mounts with every bootstrap swap refused (debug mask 4096|8192|16384,
#      as on a device without COMPARE AND WRITE): the mount must not succeed,
#      the swaps must have been attempted, and the record, takeover journal
#      and tombstones (bootstrap sectors 0, 31, 32-39) must be byte-identical.
#   B: the mask cleared: $N1 mounts, recovering both slices after startup
#      fencing (the authority holds $N2 off); $N2 is released and rejoins; every
#      fsynced file of both nodes intact on both; cold chk clean.
OUTAGE_MOUNT_BUDGET=180   # dead window 62 s + fence-free bootstrap + two slice replays, x2
step_outage_test() {
    local out n1sum n2sum bs_off sec h0 h1 n
    step_mxfs
    bs_off=$(sed -n 's/^ *Bootstrap: *\([0-9]*\) - .*/\1/p' "$EVID/mkfs" | head -1)
    [ -n "$bs_off" ] || die "outage test: no Bootstrap: line in the mkfs output"
    sec=$((bs_off / 512))
    # sectors 0, 31, 32-39 of the region; 48-50 (the swap's own registers) move on every swap
    local HASH="{ dd if=$DRBD_DEV iflag=direct bs=512 skip=$sec count=1 status=none; dd if=$DRBD_DEV iflag=direct bs=512 skip=$((sec + 31)) count=9 status=none; } | md5sum | cut -c1-32"
    out=$(ssh_n "$N1" "mkdir -p $MNT/out/n1 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/out/n1/f\$i; done && sync -f $MNT && cd $MNT/out/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    n1sum=$(tail -1 <<<"$out")
    out=$(ssh_n "$N2" "mkdir -p $MNT/out/n2 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/out/n2/f\$i; done && sync -f $MNT && cd $MNT/out/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    n2sum=$(tail -1 <<<"$out")
    [ ${#n1sum} = 32 ] && [ ${#n2sum} = 32 ] || die "outage test: could not record checksums ($n1sum / $n2sum)"
    say "outage test: files fsynced on both ($n1sum / $n2sum); destroying both nodes at once"
    local dpids=()
    for n in "${NODES[@]}"; do timeout 60 virsh -c qemu:///system destroy "$n" >/dev/null 2>&1 & dpids+=($!); done
    wait "${dpids[@]}"
    for n in "${NODES[@]}"; do
        [ "$(timeout 20 virsh -c qemu:///system domstate "$n")" = "shut off" ] || die "outage test: $n is not off"
        out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$n")
        [ "${out##*inhibit=}" = none ] || die "outage test: $n carries an inhibit after a pair outage: $out"
    done
    "$REPO/scripts/lab_power.sh" up "${NODES[@]}" > "$EVID/outage_power" 2>&1 || die "outage test: boot: $(tail -1 "$EVID/outage_power")"
    both drbdup "$NODE_DRBD_UP
        for i in \$(seq 1 $REJOIN_BUDGET); do [ \"\$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\" = 'Connected UpToDate/UpToDate' ] && break; sleep 1; done
        drbdadm primary $RES 2>&1 | tail -1
        mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }" $((REJOIN_BUDGET + 40))
    # roles read only after both promotions: each node's view of its peer lags its own
    need_dual_primary
    say "  both booted; DRBD Primary/Primary UpToDate/UpToDate Connected"
    local KO_MD5; KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}')
    local PREP="MXFS_DEV=$DRBD_DEV MXFS_KO_MD5=$KO_MD5 MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1"
    # ── A ──
    h0=$(ssh_n "$N1" "$HASH" 30)
    out=$(ssh_n "$N1" "dmesg -C; MXFS_EXTRA_MODARGS=dbg_cas_nocaw_ops=28672 $PREP | grep -a NODE_PREP | tail -1
        echo 0 > /sys/module/mxfs/parameters/dbg_cas_nocaw_ops 2>/dev/null
        mountpoint -q $MNT && echo STILL_MOUNTED
        echo \"injected=\$(dmesg | grep -ac 'P-DBG-CAS-NOCAW op=bootstrap')\"
        dmesg | grep -aoE 'P-DBG-CAS-NOCAW op=[a-z-]+|P-BOOT-[A-Z-]+' | sort | uniq -c | sort -rn | head -8 | tr '\n' ' '" $((OUTAGE_MOUNT_BUDGET + 30)))
    echo "$out" > "$EVID/outage_arm_a"
    h1=$(ssh_n "$N1" "$HASH" 30)
    grep -q STILL_MOUNTED <<<"$out" && die "outage test A: $N1 mounted with every bootstrap swap refused: $out"
    [ "$(sed -n 's/^injected=//p' <<<"$out")" -ge 1 ] 2>/dev/null || die "outage test A: no bootstrap swap was attempted, so nothing was exercised: $out"
    [ "$h0" = "$h1" ] || die "outage test A: the protected bootstrap sectors changed while every swap was refused: $h0 -> $h1"
    say "  A: mount refused with bootstrap swaps refused; $(grep '^injected' <<<"$out"); sectors 0/31/32-39 unchanged ($h0)"
    # ── A2 (OUTAGE_TOMB_ARM=1): only the tombstone swaps refused: the claim
    #     and seal land, the completion's tombstone write must not.  It leaves
    #     a term whose completion purged and then failed; B is then a
    #     same-boot RESUME of that term (its startup fence is A2's, still
    #     standing), which must finish it. ──
    if [ "${OUTAGE_TOMB_ARM:-0}" = 1 ]; then
    local TOMBHASH="dd if=$DRBD_DEV iflag=direct bs=512 skip=$((sec + 32)) count=8 status=none | md5sum | cut -c1-32"
    ssh_n "$N1" "umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null" 30 >/dev/null
    h0=$(ssh_n "$N1" "$TOMBHASH" 30)
    out=$(ssh_n "$N1" "dmesg -C; MXFS_EXTRA_MODARGS=dbg_cas_nocaw_ops=8192 $PREP | grep -a NODE_PREP | tail -1
        echo 0 > /sys/module/mxfs/parameters/dbg_cas_nocaw_ops 2>/dev/null
        mountpoint -q $MNT && echo MOUNTED
        echo \"injected=\$(dmesg | grep -ac 'P-DBG-CAS-NOCAW op=bootstrap-tomb')\"
        dmesg | grep -aoE 'P-BOOT-[A-Z-]+|P163-[A-Z-]+' | sort | uniq -c | sort -rn | head -8 | tr '\n' ' '" $((OUTAGE_MOUNT_BUDGET + 30)))
    echo "$out" > "$EVID/outage_arm_a2"
    ssh_n "$N1" "dmesg" 30 > "$EVID/kernlog_a2.$N1"
    h1=$(ssh_n "$N1" "$TOMBHASH" 30)
    [ "$(sed -n 's/^injected=//p' <<<"$out")" -ge 1 ] 2>/dev/null || die "outage test A2: no tombstone swap was attempted, so nothing was exercised: $out"
    [ "$h0" = "$h1" ] || die "outage test A2: the tombstone sectors changed while their swaps were refused: $h0 -> $h1"
    say "  A2: tombstone swaps refused: $(grep '^injected' <<<"$out"), sectors 32-39 unchanged ($h0); $(grep -c MOUNTED <<<"$out") mounted"
    fi
    # ── B ──
    ssh_n "$N1" "umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; dmesg -C" 30 >/dev/null
    out=$(ssh_n "$N1" "$PREP" $((OUTAGE_MOUNT_BUDGET + 30)))
    echo "$out" > "$EVID/outage_mount.$N1"
    ssh_n "$N1" "dmesg" 30 > "$EVID/kernlog_b.$N1"
    grep -aq '^NODE_PREP_OK' <<<"$out" || die "outage test B: $N1 did not mount after the pair outage: $(grep -a 'FAIL' <<<"$out" | tail -1)"
    ssh_n "$N1" "dmesg | grep -aE 'P-DRBD-STARTUP-FENCE|P-BOOT-(CLAIMED|SEALED|PHASE3-COMPLETE|RECOVERY-COMPLETE)' | sed 's/^.*mxfs: //' | cut -c1-200" 20 > "$EVID/outage_boot_kernlog"
    if [ "${OUTAGE_TOMB_ARM:-0}" = 1 ]; then
        # B resumed A2's term in the same boot: the fence is A2's
        grep -aq 'P-DRBD-STARTUP-FENCED' "$EVID/kernlog_a2.$N1" || die "outage test A2: $N1 claimed without a startup fence"
        grep -aq 'P-BOOT-RESUMED' "$EVID/kernlog_b.$N1" || die "outage test B: $N1 did not resume A2's term"
        grep -aq 'P-BOOT-RECOVERY-COMPLETE' "$EVID/kernlog_b.$N1" || die "outage test B: $N1 mounted without completing the resumed term"
        grep -ao 'P-DRBD-STARTUP-FENCED.*episode=[^ ]*' "$EVID/kernlog_a2.$N1" | tail -1 >> "$EVID/outage_boot_kernlog"
    else
        grep -q 'P-DRBD-STARTUP-FENCED' "$EVID/outage_boot_kernlog" || die "outage test B: $N1 mounted without a startup fence: $(cat "$EVID/outage_boot_kernlog")"
    fi
    out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$N2")
    case "$out" in "STATE $N2 shut off inhibit="*) [ "${out##*inhibit=}" != none ] ;; *) false ;; esac \
        || die "outage test B: startup fencing should have left $N2 off and inhibited: $out"
    say "  B: $N1 fenced $N2 at startup ($(grep -o 'episode=[^ ]*' "$EVID/outage_boot_kernlog" | head -1)) and recovered the pair; $N2 rejoins"
    rejoin_node "$N2" "$N1"
    for n in "${NODES[@]}"; do
        out=$(ssh_n "$n" "cd $MNT/out/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/out/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
        [ "$(sed -n 1p <<<"$out")" = "$n1sum" ] && [ "$(sed -n 2p <<<"$out")" = "$n2sum" ] || die "outage test B: $n reads different data after the outage: $out"
    done
    say "  B: $N1 recovered the pair, $N2 joined; every fsynced file of both nodes intact on both"
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    out=$(ssh_n "$N1" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/outage_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "outage test: chk_mxfs: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "outage test: passed (cold chk_mxfs clean; MXFS left unmounted)"
}

# A pair outage whose bootstrap owner fails mid-term, after it adopted a victim
# slot (K): the term must be taken over and finished, never left for an
# operator.  On DRBD the owner's startup fence left the peer's disk Outdated, so
# the term can be continued only where the data is current:
#   self     $N1's bootstrap is HELD right after K (bootstrap_inject=13, TEST
#            ONLY) and destroyed there; $N1 boots again, alone (its peer still
#            held off), and its new boot takes over its previous boot's term.
#   foreign  $N1's bootstrap FAILS right after K (bootstrap_inject=3): the mount
#            unwinds, the record stays RECOVERING, $N1 stays up.  $N2 is released
#            and resynced from $N1, and $N2 takes the term over, fencing $N1.
# TAKEOVER_NOCAW_ARM=1 first runs the contender once with the takeover-journal
# swaps refused (dbg_cas_nocaw_ops=16384, as on a device without COMPARE AND
# WRITE): the mount must not succeed, a swap must have been attempted, and the
# journal (bootstrap sector 31) must be byte-identical.  TAKEOVER_CLEAR_ARM=1
# then holds the contender right after its election (bootstrap_inject=15),
# refuses its journal swaps and releases it: the next stage swap and the clear
# of its own entry must both be refused with sector 31 unchanged, and the
# takeover that follows in the same boot must supersede that entry.  Then the contender
# mounts with the mask cleared: P-BOOT-TAKEOVER, P-BOOT-RECOVERY-COMPLETE; the
# other node rejoins; every fsynced file of both nodes intact on both; cold chk.
# Every kernel log is kept in the evidence directory.
TAKEOVER_MOUNT_BUDGET=240  # abandon window 6 s + startup fence (link loss, handler, authority ~10-20 s) + K fence + two-slice recovery (~90 s), twice over
step_takeover_test() {
    local arm=${1:-self} out n1sum n2sum bs_off sec h0 h1 n owner contender ep
    case "$arm" in self) owner=$N1; contender=$N1 ;; foreign) owner=$N1; contender=$N2 ;; *) die "takeover test: arm is self or foreign" ;; esac
    step_mxfs
    bs_off=$(sed -n 's/^ *Bootstrap: *\([0-9]*\) - .*/\1/p' "$EVID/mkfs" | head -1)
    [ -n "$bs_off" ] || die "takeover test: no Bootstrap: line in the mkfs output"
    sec=$((bs_off / 512))
    local TKHASH="dd if=$DRBD_DEV iflag=direct bs=512 skip=$((sec + 31)) count=1 status=none | md5sum | cut -c1-32"
    out=$(ssh_n "$N1" "mkdir -p $MNT/out/n1 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/out/n1/f\$i; done && sync -f $MNT && cd $MNT/out/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    n1sum=$(tail -1 <<<"$out")
    out=$(ssh_n "$N2" "mkdir -p $MNT/out/n2 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/out/n2/f\$i; done && sync -f $MNT && cd $MNT/out/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    n2sum=$(tail -1 <<<"$out")
    [ ${#n1sum} = 32 ] && [ ${#n2sum} = 32 ] || die "takeover test: could not record checksums ($n1sum / $n2sum)"
    say "takeover test ($arm): files fsynced on both ($n1sum / $n2sum); destroying both nodes at once"
    local dpids=()
    for n in "${NODES[@]}"; do timeout 60 virsh -c qemu:///system destroy "$n" >/dev/null 2>&1 & dpids+=($!); done
    wait "${dpids[@]}"
    for n in "${NODES[@]}"; do
        [ "$(timeout 20 virsh -c qemu:///system domstate "$n")" = "shut off" ] || die "takeover test: $n is not off"
    done
    "$REPO/scripts/lab_power.sh" up "${NODES[@]}" > "$EVID/outage_power" 2>&1 || die "takeover test: boot: $(tail -1 "$EVID/outage_power")"
    both drbdup "$NODE_DRBD_UP
        for i in \$(seq 1 $REJOIN_BUDGET); do [ \"\$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\" = 'Connected UpToDate/UpToDate' ] && break; sleep 1; done
        drbdadm primary $RES 2>&1 | tail -1
        mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }" $((REJOIN_BUDGET + 40))
    need_dual_primary
    local KO_MD5; KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}')
    local PREP="MXFS_DEV=$DRBD_DEV MXFS_KO_MD5=$KO_MD5 MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp"
    # ── the owner: claims (its startup fence holds $N2 off), seals, adopts K
    if [ "$arm" = self ]; then
        out=$(ssh_n "$owner" "dmesg -C; nohup env MXFS_EXTRA_MODARGS=bootstrap_inject=13 $PREP > /run/tk_owner.log 2>&1 < /dev/null &
            for i in \$(seq 1 $OUTAGE_MOUNT_BUDGET); do dmesg | grep -q 'P-BOOT-INJECT-HOLD point=13' && break; sleep 1; done
            dmesg | grep -q 'P-BOOT-INJECT-HOLD point=13' && echo HELD || echo NOT_HELD" $((OUTAGE_MOUNT_BUDGET + 30)))
        ssh_n "$owner" "dmesg" 30 > "$EVID/kernlog_owner.$owner"
        grep -q '^HELD' <<<"$out" || die "takeover test: $owner's bootstrap never reached the hold after K: $(grep -aoE 'P-BOOT-[A-Z-]+' "$EVID/kernlog_owner.$owner" | sort | uniq -c | tr '\n' ' ')"
        grep -q 'P-BOOT-ADOPT slot=' "$EVID/kernlog_owner.$owner" || die "takeover test: $owner is held but adopted no K"
        say "  $owner claimed, sealed and adopted K ($(grep -ao 'P-BOOT-ADOPT slot=[0-9]*' "$EVID/kernlog_owner.$owner" | head -1)); held there, destroying it"
        timeout 60 virsh -c qemu:///system destroy "$owner" >/dev/null 2>&1 || die "takeover test: virsh destroy $owner failed"
        out=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$N2")
        case "$out" in "STATE $N2 shut off inhibit="*) [ "${out##*inhibit=}" != none ] ;; *) false ;; esac \
            || die "takeover test: $owner's startup fence should have left $N2 off and inhibited: $out"
        "$REPO/scripts/lab_power.sh" up "$owner" > "$EVID/owner_power" 2>&1 || die "takeover test: $owner did not boot"
        out=$(ssh_n "$owner" "$NODE_DRBD_UP
            for i in \$(seq 1 $REJOIN_BUDGET); do case \"\$(drbdadm dstate $RES)\" in UpToDate/*) break ;; esac; sleep 1; done
            drbdadm primary $RES 2>&1 | tail -1
            mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
            echo \"ALONE \$(drbdadm role $RES) \$(drbdadm dstate $RES) \$(drbdadm cstate $RES)\"" $((REJOIN_BUDGET + 40)))
        grep -q '^ALONE Primary/' <<<"$out" || die "takeover test: $owner is not Primary alone after its reboot: $(tail -1 <<<"$out")"
        say "  $owner rebooted alone: $(grep '^ALONE' <<<"$out")"
    else
        out=$(ssh_n "$owner" "dmesg -C; MXFS_EXTRA_MODARGS=bootstrap_inject=3 $PREP 2>&1 | grep -a NODE_PREP | tail -1
            mountpoint -q $MNT && echo STILL_MOUNTED
            echo 0 > /sys/module/mxfs/parameters/bootstrap_inject 2>/dev/null" $((OUTAGE_MOUNT_BUDGET + 30)))
        ssh_n "$owner" "dmesg" 30 > "$EVID/kernlog_owner.$owner"
        grep -q STILL_MOUNTED <<<"$out" && die "takeover test: $owner mounted through the fail point"
        grep -q 'P-BOOT-INJECT point=3' "$EVID/kernlog_owner.$owner" || die "takeover test: $owner's fail point after K never fired: $(grep -aoE 'P-BOOT-[A-Z-]+' "$EVID/kernlog_owner.$owner" | sort | uniq -c | tr '\n' ' ')"
        say "  $owner claimed, sealed, adopted K and failed there (record left RECOVERING); $N2 is released and resynced"
        ep=$(timeout 30 "$REPO/tools/rig_fence_virsh.sh" status "$N2"); ep=${ep##*inhibit=}
        [ "$ep" != none ] && [ -n "$ep" ] || die "takeover test: $N2 is not inhibited after $owner's startup fence"
        out=$("$REPO/tools/rig_fence_virsh.sh" release "$N2" "$ep" "$owner")
        [ "$out" = "RELEASED $N2 episode=$ep" ] || die "takeover test: release: $out"
        "$REPO/scripts/lab_power.sh" up "$N2" > "$EVID/contender_power" 2>&1 || die "takeover test: $N2 did not boot"
        out=$(ssh_n "$N2" "$NODE_DRBD_UP
            for i in \$(seq 1 $REJOIN_BUDGET); do [ \"\$(drbdadm dstate $RES 2>/dev/null)\" = UpToDate/UpToDate ] && { drbdadm primary $RES 2>&1 | tail -1; break; }; sleep 1; done
            mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
            echo \"RESYNCED \$(drbdadm role $RES) \$(drbdadm dstate $RES)\"" $((REJOIN_BUDGET + 40)))
        grep -q '^RESYNCED Primary/Primary UpToDate/UpToDate' <<<"$out" || die "takeover test: $N2 did not resync to Primary/Primary: $(tail -1 <<<"$out")"
        say "  $N2 resynced from $owner, Primary/Primary"
    fi
    # ── TAKEOVER_NOCAW_ARM: the contender with its takeover-journal swaps refused
    if [ "${TAKEOVER_NOCAW_ARM:-0}" = 1 ]; then
        h0=$(ssh_n "$contender" "$TKHASH" 30)
        out=$(ssh_n "$contender" "dmesg -C; MXFS_EXTRA_MODARGS=dbg_cas_nocaw_ops=16384 $PREP 2>&1 | grep -a NODE_PREP | tail -1
            echo 0 > /sys/module/mxfs/parameters/dbg_cas_nocaw_ops 2>/dev/null
            mountpoint -q $MNT && echo STILL_MOUNTED
            echo \"injected=\$(dmesg | grep -ac 'P-DBG-CAS-NOCAW op=bootstrap-takeover')\"
            umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null" $((TAKEOVER_MOUNT_BUDGET + 30)))
        ssh_n "$contender" "dmesg" 30 > "$EVID/kernlog_nocaw.$contender"
        echo "$out" > "$EVID/takeover_nocaw"
        h1=$(ssh_n "$contender" "$TKHASH" 30)
        grep -q STILL_MOUNTED <<<"$out" && die "takeover test NOCAW: $contender mounted with every takeover-journal swap refused"
        [ "$(sed -n 's/^injected=//p' <<<"$out")" -ge 1 ] 2>/dev/null || die "takeover test NOCAW: no takeover-journal swap was attempted: $(grep -aoE 'P-BOOT-[A-Z-]+' "$EVID/kernlog_nocaw.$contender" | sort | uniq -c | tr '\n' ' ')"
        [ "$h0" = "$h1" ] && [ ${#h0} = 32 ] || die "takeover test NOCAW: the takeover journal changed while its swaps were refused: $h0 -> $h1"
        say "  NOCAW: $contender's takeover refused with its journal swaps refused ($(grep '^injected' <<<"$out")), sector 31 unchanged ($h0)"
    fi
    # ── TAKEOVER_CLEAR_ARM: the contender elected, then its journal swaps
    #    refused: its next stage swap fails, and the clear of its own entry on
    #    the way out must be refused too and leave sector 31 as it was.  The
    #    entry it leaves names this boot, so the takeover below must supersede
    #    it (P-BOOT-CONTENDER-OWN-BOOT) instead of refusing to fence itself.
    if [ "${TAKEOVER_CLEAR_ARM:-0}" = 1 ]; then
        local P=/sys/module/mxfs/parameters
        out=$(ssh_n "$contender" "dmesg -C; nohup env MXFS_EXTRA_MODARGS=bootstrap_inject=15 $PREP > /run/tk_clear.log 2>&1 < /dev/null &
            for i in \$(seq 1 $TAKEOVER_MOUNT_BUDGET); do dmesg | grep -q 'P-BOOT-INJECT-HOLD point=15' && break; sleep 1; done
            dmesg | grep -q 'P-BOOT-INJECT-HOLD point=15' || { echo NOT_ELECTED; exit 0; }
            echo 16384 > $P/dbg_cas_nocaw_ops; sleep 3
            echo \"H0=\$($TKHASH)\"
            echo 0 > $P/bootstrap_inject
            for i in \$(seq 1 $TAKEOVER_MOUNT_BUDGET); do grep -q NODE_PREP /run/tk_clear.log && break; sleep 1; done
            echo 0 > $P/dbg_cas_nocaw_ops
            echo \"H1=\$($TKHASH)\"
            mountpoint -q $MNT && echo STILL_MOUNTED
            echo \"clear_injected=\$(dmesg | grep -ac 'P-DBG-CAS-NOCAW op=bootstrap-takeover-clear')\"
            umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null" $((2 * TAKEOVER_MOUNT_BUDGET + 60)))
        ssh_n "$contender" "dmesg" 30 > "$EVID/kernlog_clear.$contender"
        echo "$out" > "$EVID/takeover_clear"
        grep -q NOT_ELECTED <<<"$out" && die "takeover test CLEAR: $contender was never elected: $(grep -aoE 'P-BOOT-[A-Z-]+' "$EVID/kernlog_clear.$contender" | sort | uniq -c | tr '\n' ' ')"
        grep -q STILL_MOUNTED <<<"$out" && die "takeover test CLEAR: $contender mounted with its journal swaps refused"
        [ "$(sed -n 's/^clear_injected=//p' <<<"$out")" -ge 1 ] 2>/dev/null || die "takeover test CLEAR: no journal clear was attempted: $(grep -aoE 'P-BOOT-TK-[A-Z-]+|P-DBG-CAS-NOCAW op=[a-z-]+' "$EVID/kernlog_clear.$contender" | sort | uniq -c | tr '\n' ' ')"
        h0=$(sed -n 's/^H0=//p' <<<"$out"); h1=$(sed -n 's/^H1=//p' <<<"$out")
        [ "$h0" = "$h1" ] && [ ${#h0} = 32 ] || die "takeover test CLEAR: the takeover journal changed while its swaps were refused: $h0 -> $h1"
        say "  CLEAR: $contender elected, then its stage swap and its journal clear refused ($(grep '^clear_injected' <<<"$out")), sector 31 unchanged ($h0); its entry is left naming this boot"
    fi
    # ── the takeover
    out=$(ssh_n "$contender" "dmesg -C; $PREP 2>&1" $((TAKEOVER_MOUNT_BUDGET + 30)))
    echo "$out" > "$EVID/takeover_mount.$contender"
    ssh_n "$contender" "dmesg" 30 > "$EVID/kernlog_takeover.$contender"
    grep -aq '^NODE_PREP_OK' <<<"$out" || die "takeover test: $contender did not mount: $(grep -aoE 'P-BOOT-[A-Z-]+ [^ ]*' "$EVID/kernlog_takeover.$contender" | tail -4 | tr '\n' ' ')"
    grep -q 'P-BOOT-TAKEOVER term=' "$EVID/kernlog_takeover.$contender" || die "takeover test: $contender mounted without a takeover"
    grep -q 'P-BOOT-RECOVERY-COMPLETE' "$EVID/kernlog_takeover.$contender" || die "takeover test: $contender mounted without completing the bootstrap"
    if [ "${TAKEOVER_CLEAR_ARM:-0}" = 1 ]; then
        grep -q 'P-BOOT-CONTENDER-OWN-BOOT' "$EVID/kernlog_takeover.$contender" || die "takeover test: the entry the CLEAR arm left was not superseded as this boot's own"
    fi
    say "  $contender took the term over and completed it: $(grep -ao 'P-BOOT-TAKEOVER term=[0-9]*->[0-9]* [^ ]* [^ ]* kind=[^ ]*' "$EVID/kernlog_takeover.$contender" | head -1)"
    # ── the other node rejoins; read-back on both
    if [ "$arm" = self ]; then rejoin_node "$N2" "$N1"; else rejoin_node "$N1" "$N2"; fi
    for n in "${NODES[@]}"; do
        out=$(ssh_n "$n" "cd $MNT/out/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/out/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
        [ "$(sed -n 1p <<<"$out")" = "$n1sum" ] && [ "$(sed -n 2p <<<"$out")" = "$n2sum" ] || die "takeover test: $n reads different data after the takeover: $out"
    done
    say "  both mounted; every fsynced file of both nodes intact on both"
    both stop "$NODE_UNMOUNT; echo STOP_OK" 120
    out=$(ssh_n "$N1" "/src/mxfs/tools/chk_mxfs $DRBD_DEV 2>&1 | tail -3; echo CHK_RC=\${PIPESTATUS[0]}" 120)
    echo "$out" > "$EVID/takeover_chk"
    grep -q 'CHK_RC=0' <<<"$out" || die "takeover test: chk_mxfs: $(tail -3 <<<"$out" | tr '\n' ' ')"
    say "takeover test ($arm): passed (cold chk_mxfs clean; MXFS left unmounted)"
}

step_status() {
    local n
    "$POOL" status | grep -E "^LUN|[ ,]($N1|$N2)[ ,]"
    both status "if drbdadm role $RES >/dev/null 2>&1; then drbdadm role $RES; drbdadm dstate $RES; drbdadm cstate $RES; else echo 'DRBD down'; fi; awk '\$3 == \"mxfs\" {print \"mxfs\", \$1, \$2}' /proc/mounts; cat /sys/module/mxfs/srcversion 2>/dev/null" 20
    for n in "${NODES[@]}"; do echo "$n: $(tr '\n' ' ' < "$EVID/status.$n")"; done
}

step_down() {
    local n id
    stop_nodes
    for n in "${NODES[@]}"; do
        id=$("$POOL" lookup --nodes "$n" | sed -n 's/.* id=\([^ ]*\).*/\1/p')
        [ -n "$id" ] && "$POOL" free "$id"
    done
    say "down: DRBD stopped and both LUNs returned"
}

case "$CMD" in
    up)     evid; take_locks; step_up; fio_json ;;
    mxfs)   evid; take_locks; hold_luns adopt; step_mxfs ;;
    suite)  evid; hold_luns adopt; step_suite "$@" ;;
    fio)    evid; take_locks; hold_luns adopt; step_fio; fio_json ;;
    status) evid; step_status ;;
    fence-setup) evid; fence_setup ;;
    hook-setup)  evid; hook_setup ;;
    reconfig)    evid; take_locks; hold_luns adopt; step_reconfig ;;
    fence-test)  evid; take_locks; hold_luns adopt; step_fence_test ;;
    split-test)  evid; take_locks; hold_luns adopt; step_split_test ;;
    death-test)  evid; take_locks; hold_luns adopt; step_death_test ;;
    self-death-test) evid; take_locks; hold_luns adopt; step_self_death_test ;;
    resolve-test) evid; take_locks; hold_luns adopt; step_resolve_test ;;
    remount-test) evid; take_locks; hold_luns adopt; step_remount_test ;;
    outage-test) evid; take_locks; hold_luns adopt; step_outage_test ;;
    self-outage-test) evid; take_locks; hold_luns adopt; step_self_outage_test ;;
    takeover-test) evid; take_locks; hold_luns adopt; step_takeover_test "$@" ;;
    rejoin)      # [node]: the node to bring back (default $N2); the other is its survivor
        evid; take_locks; hold_luns adopt
        rj=${1:-$N2}; [ "$rj" = "$N1" ] && rs=$N2 || rs=$N1
        rejoin_node "$rj" "$rs"; say "rejoin: $rj is back, DRBD Primary/Primary, MXFS mounted" ;;
    down)   evid; take_locks; step_down ;;
    all)
        # Steps 5 and 6 run in subshells so that a refusal there still leaves
        # step 7's raw DRBD numbers to be measured; the run then exits 1.
        evid
        take_locks; step_up; fio_json
        ( step_mxfs ); rc5=$?
        release_locks
        rc6=1; [ "$rc5" = 0 ] && { ( step_suite ); rc6=$?; }
        take_locks; step_fio; fio_json
        say "all: step 5 rc=$rc5, step 6 rc=$rc6$([ "$rc5" = 0 ] || echo ' (not run: no filesystem)'), step 7 done; evidence $EVID"
        [ "$rc5" = 0 ] && [ "$rc6" = 0 ] || exit 1 ;;
    *) sed -n '/^# Usage:/,/^# Env:/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
