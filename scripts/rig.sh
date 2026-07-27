#!/bin/bash
# rig.sh — switch the test cluster between the four deployment-condition rigs
# (conditions.md; run.sh <dlm> axis) and verify the shared LUN is presented.
#
#   condition 1  tcp    LIO/tcm_loop commodity block: host /dev/mxfs-shared
#                       wired into VM XML (wire_vms.sh) -> guest /dev/sda
#                       (LIO-ORG).  mxfs runs force_transport=1.
#   condition 2  pass   CAW FC-fabric sim: SCST per-node targets, clyde
#                       loopback logins, by-path dev wired into VM XML
#                       (scst_wire_passthrough.sh) -> guest /dev/sda.
#   condition 3  direct CAW direct in-guest iSCSI: SCST :shared on portal .1
#                       only; every VM does its own iscsiadm login -> raw
#                       single-path sdX (stable by-path node used as MXFS_DEV).
#   condition 4  mpath  CAW over dm-multipath: SCST :shared on portals .1+.2,
#                       guests log into both -> /dev/mapper/mpatha (2 paths).
#                       Delegated to scripts/mpath_up.sh (the proven path).
#
# Usage:
#   scripts/rig.sh status
#   scripts/rig.sh {mpath|direct|pass|tcp} [N]     # default N=32
#
# Always cleans ALL 32 nodes' stale device plumbing (any node may hold state
# from the previous rig), then brings the target rig up on test1..testN.
# Leaves mxfs unmounted/unloaded everywhere (run.sh prep re-forms clusters).
# disk.img is preserved across every transition (both target teardowns
# guarantee that).  Exit 0 iff every node presents the expected device.
#
# RULE 3: this is cluster-management infrastructure; it lives in scripts/.

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
VIRSH="virsh -c qemu:///system"
PORTAL1=192.168.120.1
PORTAL2=192.168.120.2
TGT="iqn.2026-05.local.mxfs:shared"
BYPATH="/dev/disk/by-path/ip-${PORTAL1}:3260-iscsi-${TGT}-lun-0"
MAXNODE=32

MODE="${1:?usage: rig.sh status|mpath|direct|pass|tcp [N]}"
N="${2:-32}"
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] && [ "$N" -le "$MAXNODE" ] || { echo "N must be 1..$MAXNODE"; exit 2; }
mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
# ALLNODES drives the global cleanout.  Sweep only VMs that are actually
# RUNNING (plus the requested set): sweeping all 32 when test17-32 are
# destroyed marks them "bad", power-cycles them, and serially waits 180s
# each — a ~48min stall observed sess11 (ccloop c7ee71c6) wiring direct 16.
mapfile -t ALLNODES < <( { virsh -c qemu:///system list --name 2>/dev/null | grep -E '^test[0-9]+$'; seq 1 "$N" | sed 's/^/test/'; } | sort -u -V)

say() { echo "[rig] $*"; }
ssh_n() { timeout "${3:-30}" "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

# ---------------------------------------------------------------------------
# status: what is live right now (host stacks, wiring, one sample node).
# ---------------------------------------------------------------------------
rig_status() {
    echo "=== host target stacks ==="
    if [ -d /sys/kernel/scst_tgt/targets/iscsi ]; then
        echo "SCST: up — targets: $(ls /sys/kernel/scst_tgt/targets/iscsi/ 2>/dev/null | grep iqn | tr '\n' ' ')"
        local ap ap1 t="/sys/kernel/scst_tgt/targets/iscsi/$TGT"
        ap=$(head -1 "$t/allowed_portal" 2>/dev/null)
        ap1=$(head -1 "$t/allowed_portal1" 2>/dev/null)
        [ -d "$t" ] && echo "  :shared allowed_portal(s): ${ap:-<none>} ${ap1:-}"
        echo "  :shared sessions: $(ls "$t/sessions" 2>/dev/null | wc -l)"
    else
        echo "SCST: down"
    fi
    if [ -L /dev/mxfs-shared ] || lsmod | grep -q '^tcm_loop'; then
        echo "LIO/tcm_loop: up — /dev/mxfs-shared -> $(readlink -f /dev/mxfs-shared 2>/dev/null)"
    else
        echo "LIO/tcm_loop: down"
    fi
    echo "clyde iSCSI sessions: $(sudo iscsiadm -m session 2>/dev/null | grep -c iqn || echo 0)"
    echo "=== VM XML wiring (sda LUNs) ==="
    "$REPO/scripts/wire_vms.sh" status 2>/dev/null | grep -v '<no shared LUN>' | head -34
    "$REPO/scripts/scst_wire_passthrough.sh" status "$MAXNODE" 2>/dev/null | grep -iE "wired|by-path" | head -34
    echo "=== sample node (test1) ==="
    ssh_n test1 'echo "sessions: $(iscsiadm -m session 2>/dev/null | grep -c iqn)"; ls -l /dev/mapper/mpatha 2>/dev/null; lsblk -S -o NAME,VENDOR,MODEL,TRAN 2>/dev/null | grep -E "SCST|LIO" || echo "no shared LUN visible"' 45
}

# ---------------------------------------------------------------------------
# Node-side cleanout (ALL nodes, parallel): unmount mxfs, unload module, drop
# every iSCSI session/record, flush multipath maps, clear learned wwids so a
# later single-path rig is not auto-wrapped by multipathd.
# ---------------------------------------------------------------------------
NODE_CLEAN='
    for t in 1 2 3 4 5; do
        mountpoint -q /mnt/shared || break
        fuser -km /mnt/shared 2>/dev/null; sleep 1
        umount /mnt/shared 2>/dev/null && break
        timeout 20 umount -f /mnt/shared 2>/dev/null && break
        sleep 1
    done
    mountpoint -q /mnt/shared && umount -l /mnt/shared 2>/dev/null
    for t in 1 2 3 4 5; do lsmod | grep -q "^mxfs " || break; rmmod mxfs 2>/dev/null && break; sleep 2; done
    multipath -F >/dev/null 2>&1
    iscsiadm -m node -u >/dev/null 2>&1
    iscsiadm -m node -o delete >/dev/null 2>&1
    > /etc/multipath/wwids 2>/dev/null
    > /etc/multipath/bindings 2>/dev/null
    if lsmod | grep -q "^mxfs "; then echo CLEAN_STILL_LOADED; else echo CLEAN_OK; fi'
# CRITICAL: fuser -km on a NON-mountpoint directory resolves to the FS that
# CONTAINS it (the root fs) and kills every process on the node — sshd
# included.  The mountpoint -q gate above is load-bearing; never remove it
# (this exact bug power-cycled 30 idle nodes on 2026-07-18).

clean_all_nodes() {
    say "cleaning device plumbing on all $MAXNODE nodes (umount/rmmod/logout/mpath-flush)"
    local n pids=() td; td=$(mktemp -d)
    for n in "${ALLNODES[@]}"; do
        ( ssh_n "$n" "$NODE_CLEAN" 120 > "$td/$n" ) &
        pids+=($!)
    done
    wait
    local bad=""
    for n in "${ALLNODES[@]}"; do
        grep -q CLEAN_OK "$td/$n" 2>/dev/null || bad="$bad $n"
    done
    rm -rf "$td"
    if [ -n "$bad" ]; then
        say "WARN: nodes not clean (still-loaded mxfs or unreachable):$bad"
        say "      power-cycling them"
        local pcs=()
        for n in $bad; do
            ( $VIRSH destroy "$n" >/dev/null 2>&1; sleep 1; $VIRSH start "$n" >/dev/null 2>&1 ) &
            pcs+=($!)
        done
        wait
        # wait for ssh, then re-run the cleanout: a freshly booted node still
        # carries OLD iSCSI records (node.startup=automatic re-logs them) and
        # a learned-wwids file — both must go before a single-path rig.
        for n in $bad; do
            local dl=$(( SECONDS + 180 ))
            while [ "$SECONDS" -lt "$dl" ]; do
                ssh_n "$n" "echo SSH_UP" 10 | grep -q SSH_UP && break
                sleep 3
            done
            ssh_n "$n" "$NODE_CLEAN" 120 >/dev/null
        done
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Host-side unwiring of XML LUNs (pass/tcp rigs edit persistent VM XML; a rig
# that stops using them MUST detach, else a later teardown of the backing
# device leaves VMs pointing at a dead source and they fail to start).
# Detach is idempotent.  Returns the list of VMs whose XML changed (they need
# a power cycle to actually drop the guest disk).
# ---------------------------------------------------------------------------
unwire_xml() {
    local changed=""
    local before after n
    for n in "${ALLNODES[@]}"; do
        before=$($VIRSH dumpxml "$n" --inactive 2>/dev/null | grep -c "device='lun'")
        [ "${before:-0}" -gt 0 ] || continue
        # NOTE: a single NUMERIC arg to these scripts means "count 1..N";
        # pass the testN NAME so exactly this one node is detached.
        "$REPO/scripts/wire_vms.sh" detach "$n" >/dev/null 2>&1
        "$REPO/scripts/scst_wire_passthrough.sh" detach "$n" >/dev/null 2>&1
        after=$($VIRSH dumpxml "$n" --inactive 2>/dev/null | grep -c "device='lun'")
        [ "${after:-0}" -lt "${before:-0}" ] && changed="$changed $n"
    done
    echo "$changed"
}

# Power-cycle a set of VMs in parallel and wait for ssh.
cycle_vms() {  # node...
    [ "$#" -gt 0 ] || return 0
    say "power-cycling to apply XML changes: $*"
    local n pids=()
    for n in "$@"; do
        ( $VIRSH destroy "$n" >/dev/null 2>&1; sleep 1; $VIRSH start "$n" >/dev/null 2>&1 ) &
        pids+=($!)
    done
    wait
    local bad=""
    for n in "$@"; do
        local dl=$(( SECONDS + 240 ))
        local up=0
        while [ "$SECONDS" -lt "$dl" ]; do
            ssh_n "$n" "echo SSH_UP" 10 | grep -q SSH_UP && { up=1; break; }
            sleep 3
        done
        [ "$up" = 1 ] || bad="$bad $n"
    done
    [ -z "$bad" ] || { say "ERROR: VMs did not come back after cycle:$bad"; return 1; }
    # restore /src on the cycled nodes (NFS deliberately not an fstab automount)
    for n in "$@"; do
        ( ssh_n "$n" 'mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; mountpoint -q /src && echo SRC_OK' 60 | grep -q SRC_OK ) &
    done
    wait
    return 0
}

# ---------------------------------------------------------------------------
# Per-node verification: expected device present, readable, and (for iSCSI
# rigs) the SCSI serial matches across nodes -> same LUN.
# ---------------------------------------------------------------------------
# Remote snippet with a DEVPATH placeholder (same idiom as run.sh's TEARDOWN
# — the sshpass wrapper flattens args, so keep it one single-quoted block and
# substitute locally; no nested single quotes).
VERIFY_SNIPPET='
    d=$(readlink -f DEVPATH 2>/dev/null); [ -n "$d" ] || d=DEVPATH
    [ -b "$d" ] || { echo NODEV; exit 0; }
    dd if="$d" of=/dev/null bs=4096 count=1 iflag=direct >/dev/null 2>&1 || { echo NOREAD; exit 0; }
    s=$(sg_inq -p 0x80 "$d" 2>/dev/null | grep -i "unit serial number:" | sed "s/.*: *//" | tr -d " ")
    b=$(basename "$d")
    v=$(lsblk -S -n -o NAME,VENDOR 2>/dev/null | awk -v x="$b" "\$1==x{print \$2}")
    echo "OK serial=${s:-none} vendor=${v:-unknown}"'

verify_nodes() {  # devpath vendor_re
    local dev="$1" vre="$2" n serial="" ok=0 fail=""
    local td; td=$(mktemp -d)
    for n in "${NODES[@]}"; do
        ( ssh_n "$n" "${VERIFY_SNIPPET//DEVPATH/$dev}" 45 > "$td/$n" ) &
    done
    wait
    for n in "${NODES[@]}"; do
        local line; line=$(grep -E "^(OK|NODEV|NOREAD)" "$td/$n" 2>/dev/null | head -1)
        if [[ "$line" == OK* ]]; then
            ok=$((ok+1))
            local s; s=$(grep -oP 'serial=\K\S+' <<<"$line")
            [ -z "$serial" ] && serial="$s"
            [ "$s" = "$serial" ] || fail="$fail $n(serial=$s!=$serial)"
        else
            fail="$fail $n(${line:-unreachable})"
        fi
    done
    rm -rf "$td"
    say "verify: $ok/$N nodes see $dev (serial=$serial)"
    [ -z "$fail" ] || { say "verify FAIL:$fail"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------
# Rig bring-ups.
# ---------------------------------------------------------------------------
rig_mpath() {
    clean_all_nodes
    local changed; changed=$(unwire_xml)
    # leaving pass/tcp: their host stacks conflict with the dual-portal SCST
    # (mpath_up re-runs scst_setup itself; LIO must go first or scst_setup's
    # release_lio does it — either way harmless).  VMs whose XML changed must
    # cycle BEFORE mpath_up so their in-guest logins happen on clean boots.
    cycle_vms $changed || return 1
    say "delegating to mpath_up.sh up $N (dual portal + multipathd)"
    "$REPO/scripts/mpath_up.sh" up "$N" || return 1
    verify_nodes /dev/mapper/mpatha SCST_FIO
}

rig_direct() {
    clean_all_nodes
    local changed; changed=$(unwire_xml)
    cycle_vms $changed || return 1
    say "configuring SCST :shared on single portal $PORTAL1"
    MXFS_SCST_PORTAL_IP="$PORTAL1" "$REPO/scripts/scst_setup.sh" setup >/dev/null || { say "scst_setup failed"; return 1; }
    say "logging test1..test$N into $TGT via $PORTAL1 (clean cycle per node)"
    local n pids=() td; td=$(mktemp -d)
    for n in "${NODES[@]}"; do
        ( ssh_n "$n" '
            # single-path prod-correct policy: multipathd runs but must not
            # wrap a lone path; strict + cleared wwids guarantees that.
            mkdir -p /etc/multipath/conf.d
            printf "defaults {\n    find_multipaths strict\n}\n" > /etc/multipath/conf.d/mxfs.conf
            > /etc/multipath/wwids 2>/dev/null
            > /etc/multipath/bindings 2>/dev/null
            systemctl enable iscsid open-iscsi >/dev/null 2>&1
            systemctl restart multipathd >/dev/null 2>&1
            systemctl restart iscsid >/dev/null 2>&1
            for try in 1 2 3; do
                iscsiadm -m node -u >/dev/null 2>&1
                iscsiadm -m node -o delete >/dev/null 2>&1
                iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
                iscsiadm -m node -T iqn.2026-05.local.mxfs:shared -p 192.168.120.1:3260 --login >/dev/null 2>&1
                iscsiadm -m session --rescan >/dev/null 2>&1
                sleep 2
                [ -e /dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0 ] && { echo LOGIN_OK; exit 0; }
                sleep 3
            done
            echo LOGIN_FAIL' 120 > "$td/$n" ) &
        pids+=($!)
    done
    wait
    local bad=""
    for n in "${NODES[@]}"; do grep -q LOGIN_OK "$td/$n" 2>/dev/null || bad="$bad $n"; done
    rm -rf "$td"
    [ -z "$bad" ] || { say "direct login FAIL:$bad"; return 1; }
    verify_nodes "$BYPATH" SCST_FIO
}

rig_pass() {
    clean_all_nodes
    # tcp wiring must go (target sda collides); pass wiring is re-applied
    # fresh below anyway, so unwire everything first.
    local changed; changed=$(unwire_xml)
    say "configuring SCST (shared vdisk) + per-node passthrough targets"
    MXFS_SCST_PORTAL_IP="$PORTAL1" "$REPO/scripts/scst_setup.sh" setup >/dev/null || { say "scst_setup failed"; return 1; }
    "$REPO/scripts/scst_wire_passthrough.sh" attach "$N" || { say "passthrough attach failed"; return 1; }
    # every wired VM needs a restart for the --config attach to take effect
    cycle_vms "${NODES[@]}" || return 1
    verify_nodes /dev/sda SCST_FIO
}

rig_tcp() {
    clean_all_nodes
    local changed; changed=$(unwire_xml)
    say "tearing down SCST passthrough logins + configuring LIO/tcm_loop"
    "$REPO/scripts/lio_tcm_setup.sh" setup >/dev/null || { say "lio_tcm_setup failed"; return 1; }
    [ -L /dev/mxfs-shared ] || { say "no /dev/mxfs-shared after LIO setup"; return 1; }
    "$REPO/scripts/wire_vms.sh" attach "$N" || { say "wire_vms attach failed"; return 1; }
    cycle_vms "${NODES[@]}" || return 1
    verify_nodes /dev/sda LIO-ORG
}

case "$MODE" in
    status) rig_status ;;
    mpath)  rig_mpath  ;;
    direct) rig_direct ;;
    pass)   rig_pass   ;;
    tcp)    rig_tcp    ;;
    *) echo "usage: rig.sh {status|mpath|direct|pass|tcp} [N]"; exit 2 ;;
esac
