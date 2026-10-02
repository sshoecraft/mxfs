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
#   scripts/drbd_rig.sh outage-test         both nodes die at once; a bootstrap with its swaps refused writes
#                                              nothing, then the pair recovers with every fsynced file
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
    out=$(ssh_n "$N2" "modprobe drbd && drbdadm up $RES 2>&1 | tail -1
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
    out=$(ssh_n "$node" "modprobe drbd && drbdadm up $RES 2>&1 | tail -1
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
    out=$(ssh_n "$loser" "modprobe drbd && drbdadm up $RES 2>&1 | tail -1
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
    both drbdup "modprobe drbd && drbdadm up $RES 2>&1 | tail -1
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
    #     a term whose completion purged and then failed, which a resume cannot
    #     finish yet (D-BOOTSTRAP-RESUME-AFTER-PARTIAL-COMPLETION-ABORTS),
    #     so B is expected to fail after it until that is fixed. ──
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
    h1=$(ssh_n "$N1" "$TOMBHASH" 30)
    [ "$(sed -n 's/^injected=//p' <<<"$out")" -ge 1 ] 2>/dev/null || die "outage test A2: no tombstone swap was attempted, so nothing was exercised: $out"
    [ "$h0" = "$h1" ] || die "outage test A2: the tombstone sectors changed while their swaps were refused: $h0 -> $h1"
    say "  A2: tombstone swaps refused: $(grep '^injected' <<<"$out"), sectors 32-39 unchanged ($h0); $(grep -c MOUNTED <<<"$out") mounted"
    fi
    # ── B ──
    ssh_n "$N1" "umount $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; dmesg -C" 30 >/dev/null
    out=$(ssh_n "$N1" "$PREP" $((OUTAGE_MOUNT_BUDGET + 30)))
    echo "$out" > "$EVID/outage_mount.$N1"
    grep -aq '^NODE_PREP_OK' <<<"$out" || die "outage test B: $N1 did not mount after the pair outage: $(grep -a 'FAIL' <<<"$out" | tail -1)"
    ssh_n "$N1" "dmesg | grep -aE 'P-DRBD-STARTUP-FENCE|P-BOOT-(CLAIMED|SEALED|PHASE3-COMPLETE|RECOVERY-COMPLETE)' | sed 's/^.*mxfs: //' | cut -c1-200" 20 > "$EVID/outage_boot_kernlog"
    grep -q 'P-DRBD-STARTUP-FENCED' "$EVID/outage_boot_kernlog" || die "outage test B: $N1 mounted without a startup fence: $(cat "$EVID/outage_boot_kernlog")"
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
    resolve-test) evid; take_locks; hold_luns adopt; step_resolve_test ;;
    remount-test) evid; take_locks; hold_luns adopt; step_remount_test ;;
    outage-test) evid; take_locks; hold_luns adopt; step_outage_test ;;
    rejoin)      evid; take_locks; hold_luns adopt; rejoin_node "$N2" "$N1"; say "rejoin: $N2 is back, DRBD Primary/Primary, MXFS mounted" ;;
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
