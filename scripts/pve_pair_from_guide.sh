#!/bin/bash
# pve_pair_from_guide.sh — set the physical Proxmox pair up from nothing by
# docs/drbd-setup.md, exactly as a user who clones the public repository would,
# and check the result.
#
# A user following an earlier README on these two hosts ended with DRBD over a
# loop file, no fencing and nothing that came back after a reboot.  The guide
# was written for that; this proves it, on the hardware it names, from a fresh
# clone of the public repository.
#
#   teardown  both hosts back to a Proxmox host with no MXFS on it: the unit
#             stopped and disabled (it unmounts and steps down), DRBD down, the
#             backing LV removed, every file `make install` writes removed (the
#             module, tools, helpers, units, /etc/mxfs, the module options and
#             auto-load, the udev rule, man pages), /var/lib/mxfs, any MXFS
#             nftables table, the Proxmox storage entry, and the source clone
#             moved to /root/mxfs.backup.  Refuses while anything other than
#             MXFS's own units holds the mount.
#   guide     sections 1-6 of the guide, in order, with its own commands: the
#             apt install, `git clone` + `make && make install`, the thin LV,
#             the resource file (taken from the guide's text), create-md / up,
#             the first sync, `primary` on node B, mkfs.mxfs on node A, the
#             mount settings, `systemctl enable --now mxfs-drbd@mxfs`, and the
#             Proxmox storage.  Node A is participant 0 (the lower address).
#   finish    the guide from the first sync onward (the wait, `primary` on
#             node B, sections 5 and 6), for a run that stopped during the
#             sync: the sync is DRBD's own and carries on without this script.
#   verify    both mounted, Primary/Primary, UpToDate/UpToDate, the live
#             connection on the guide's ping-int, the guard active, one MXFS
#             build on both, the storage online.
#   (default: teardown guide verify)
#
# Each command the guide prints is checked against docs/drbd-setup.md before it
# runs, so a guide edited out from under this script stops it instead of
# testing something else.  The guide's commands run as written; the only
# additions are what an unattended shell needs (apt's -y) and bounds.
#
# DESTRUCTIVE: everything on the MXFS volume is destroyed.  Run it on a pair
# whose /mnt/shared holds nothing you need.
#
# Usage: scripts/pve_pair_from_guide.sh [phase ...]
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), REPO_URL (default the
#        guide's), SYNC_BUDGET (seconds for the first sync, default 2700: on
#        pve1/pve2 it ran at 32 MB/s, held there by the SyncTarget's disk and
#        not by the guide's 110 MB/s c-max-rate, so 40 GiB takes ~22 min;
#        twice that, rounded up), MOUNT_BUDGET (seconds from `enable --now`
#        to both mounted, default 300)
#        FROM_TREE=1 builds and installs this working tree (packed and copied
#        to /root/mxfs-tree, as scripts/pve_pair_update.sh does) in place of
#        section 1's clone: a test build on a pair set up for testing.
#        LV_SIZE (default the guide's 40G): a nested pair's thin pool is ~23 GiB,
#        so pve9-1/pve9-2 carry a 12G volume.  Its first sync ran at 39 MB/s
#        on pve9-3/pve9-4 (DRBD's resync controller wanted 45 MB/s with the
#        receiver idle), ~5 min, so SYNC_BUDGET=630 there.
#        A pair other than the guide's pve1/pve2 gets the guide's resource with
#        its hosts' names and addresses in place of pve1/pve2's, and nothing else
#        changed.
# Evidence: tests/evidence/pve_pair_from_guide/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
GUIDE="$REPO/docs/drbd-setup.md"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_from_guide: PVE_PAIR must name two hosts"; exit 2; }
REPO_URL=${REPO_URL:-https://github.com/sshoecraft/mxfs}
SYNC_BUDGET=${SYNC_BUDGET:-2700}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
LV_SIZE=${LV_SIZE:-40G}
# A clone of the repository and a build of the module and tools on these
# hosts: measured 2-4 min each on the HP Z400s; twice the slow end.
BUILD_BUDGET=480
PHASES=("$@")
[ "${#PHASES[@]}" -gt 0 ] || PHASES=(teardown guide verify)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_pair_from_guide/$STAMP"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
die() { say "FAIL: $*"; exit 1; }
on() {  # <host> <cmd> [timeout] — output to stdout and to the host's log
    local out rc
    out=$(timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$')
    rc=${PIPESTATUS[0]}
    { echo "### [$(date +%H:%M:%S)] $1 (rc=$rc): $2"; echo "$out"; } >> "$EVID/host-$1.log"
    printf '%s\n' "$out"
    return "$rc"
}
both() {  # <cmd> [timeout] — on both hosts at once; fails if either does
    local h rc=0
    for h in "$P0" "$P1"; do
        on "$h" "$1" "${2:-60}" > "$EVID/both.$h" 2>&1 &
    done
    for h in "$P0" "$P1"; do wait -n || rc=1; done
    for h in "$P0" "$P1"; do sed "s|^|  $h: |" "$EVID/both.$h" | tail -5 | tee -a "$EVID/log"; done
    return "$rc"
}
# guide_has <text>: the guide still prints this command
guide_has() {
    grep -qF -- "$1" "$GUIDE" || die "docs/drbd-setup.md no longer contains: $1"
}

if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi

teardown() {
    say "== teardown: both hosts back to no MXFS"
    local h out
    for h in "$P0" "$P1"; do
        out=$(on "$h" "hostname; qm list 2>/dev/null | awk 'NR > 1 {print \$1}' | while read -r id; do qm config \$id 2>/dev/null | grep -qE '^[a-z]+[0-9]+:.*shared:' && echo SHARED_VM \$id; done; fuser -vm /mnt/shared 2>&1 | awk 'NR > 1 && \$0 !~ /kernel/ {print \"HOLDER\", \$0}'" 60)
        say "$h: $(echo "$out" | head -1)"
        if grep -qE '^(SHARED_VM|HOLDER)' <<<"$out"; then
            die "$h: something uses /mnt/shared: $(grep -E '^(SHARED_VM|HOLDER)' <<<"$out" | tr '\n' ' ')"
        fi
    done
    # Stopping the unit unmounts and steps down; one host at a time, so the
    # second sees an ordinary departure of the first.
    for h in "$P1" "$P0"; do
        on "$h" "systemctl disable --now mxfs-drbd@mxfs 2>&1; systemctl disable --now mxfs-drbd-guard 2>&1; awk '\$2 == \"/mnt/shared\"' /proc/mounts; drbdadm down mxfs 2>&1; cat /proc/drbd 2>/dev/null | grep -E '^ *0:' ; echo STOPPED" 300 | tail -3 | sed "s|^|  $h: |" | tee -a "$EVID/log"
        on "$h" "awk '\$2 == \"/mnt/shared\"' /proc/mounts | grep -q . && echo STILL_MOUNTED; grep -qE '^ *0:' /proc/drbd 2>/dev/null && echo DRBD_STILL_UP; true" 30 | grep -qE 'STILL_MOUNTED|DRBD_STILL_UP' \
            && die "$h: still mounted or DRBD still up after its unit stopped"
    done
    both "set -e
        lvs pve/mxfs >/dev/null 2>&1 && lvremove -y pve/mxfs >/dev/null
        rm -f /etc/drbd.d/mxfs.res
        rm -rf /etc/mxfs /var/lib/mxfs /usr/share/doc/mxfs
        rm -f /etc/modprobe.d/mxfs.conf /etc/modprobe.d/mxfs.conf.backup /etc/modules-load.d/mxfs.conf /etc/udev/rules.d/60-mxfs-blkid.rules
        rm -f /lib/systemd/system/mxfs-drbd@.service /lib/systemd/system/mxfs-drbd-guard.service
        rm -rf /etc/systemd/system/mxfs-drbd@.service.d /etc/systemd/system/mxfs-drbd-guard.service.d
        systemctl daemon-reload
        for f in /usr/sbin/*mxfs* /usr/share/man/man5/*mxfs* /usr/share/man/man8/*mxfs*; do [ -e \"\$f\" ] && rm -f \"\$f\"; done
        for t in \$(nft list tables 2>/dev/null | awk '\$3 ~ /mxfs/ {print \$2\" \"\$3}' | tr ' ' ':'); do nft delete table \${t%%:*} \${t#*:}; done
        if lsmod | grep -q '^mxfs '; then rmmod mxfs; fi
        find /lib/modules/\$(uname -r) -name 'mxfs.ko*' -delete
        depmod -a
        if [ -d /root/mxfs ]; then rm -rf /root/mxfs.backup; mv /root/mxfs /root/mxfs.backup; fi
        echo TORN_DOWN" 300 || die "teardown failed"
    on "$P0" "pvesm status 2>/dev/null | awk '\$1 == \"shared\"' | grep -q . && pvesm remove shared; pvesm status 2>/dev/null | awk '\$1 == \"shared\"' | grep -q . && echo STORAGE_LEFT; echo DONE" 60 | grep -q STORAGE_LEFT && die "the Proxmox storage 'shared' could not be removed"
    both "lsmod | grep -c '^mxfs ' ; ls /usr/sbin | grep -c mxfs; ls /etc/mxfs 2>&1 | head -1; lvs pve/mxfs 2>&1 | tail -1" 60
    say "teardown done"
}

guide() {
    say "== guide: docs/drbd-setup.md sections 1-6 from a fresh clone of $REPO_URL"
    local c
    # 1. Install (both nodes)
    for c in "apt install drbd-utils git build-essential proxmox-headers-\$(uname -r)" \
             "git clone https://github.com/sshoecraft/mxfs && cd mxfs" "make && make install"; do
        guide_has "$c"
    done
    local src="cd /root && git clone $REPO_URL > /dev/null 2>&1 && cd mxfs" h
    if [ "${FROM_TREE:-0}" = 1 ]; then
        # the sources `make install` reads, no build products
        tar -C "$REPO" -czf "$EVID/mxfs-tree.tar.gz" \
            --exclude='*.o' --exclude='*.ko' --exclude='*.mod' --exclude='*.mod.c' \
            --exclude='.*.cmd' --exclude='*.a' --exclude='modules.order' \
            --exclude='Module.symvers' --exclude='.tmp_versions' --exclude='__pycache__' \
            --exclude='tools/mkfs_mxfs' --exclude='tools/chk_mxfs' \
            --exclude='tools/resize_mxfs' --exclude='tools/mxfs_admin' \
            --exclude='tools/fua_verify' \
            Kbuild Makefile VERSION compat include xfs dlm pal mxfs_clayer packaging \
            tools docs/drbd-setup.md docs/man \
            || die "could not pack the working tree"
        for h in "$P0" "$P1"; do
            timeout 120 "$SSHP" "$h" SCP "$EVID/mxfs-tree.tar.gz" /root/mxfs-tree.tar.gz </dev/null >/dev/null 2>&1 \
                || die "$h: could not copy the tree's pack"
        done
        src="rm -rf /root/mxfs-tree && mkdir /root/mxfs-tree && tar -xzf /root/mxfs-tree.tar.gz -C /root/mxfs-tree && cd /root/mxfs-tree"
        say "1. install: apt, this working tree ($(cat "$REPO/VERSION")) in place of the clone, make && make install (both nodes)"
    else
        say "1. install: apt, clone, make && make install (both nodes)"
    fi
    both "DEBIAN_FRONTEND=noninteractive apt install -y drbd-utils git build-essential proxmox-headers-\$(uname -r) > /dev/null 2>&1 || exit 1
        $src && echo VERSION=\$(cat VERSION) && make > /root/mxfs-make.log 2>&1 && make install >> /root/mxfs-make.log 2>&1 && echo INSTALLED; tail -3 /root/mxfs-make.log; ls /usr/sbin | grep -c mxfs" "$BUILD_BUDGET" \
        || die "section 1 failed (see $EVID/host-*.log)"
    # 2. A backing device on each node
    c="lvcreate -V 40G -T pve/data -n mxfs"; guide_has "$c"
    c=${c/40G/$LV_SIZE}
    say "2. backing device: $c (both nodes)"
    both "$c && lvs --noheadings -o lv_name,lv_size,pool_lv pve/mxfs" 60 || die "section 2 failed"
    # 3. The DRBD resource, from the guide's own text
    local res n0 n1
    res=$(awk '/^## 3\./ {s = 1} s && /^```/ {if (in_block) exit; in_block = 1; next} in_block {print}' "$GUIDE")
    grep -q '^resource mxfs {' <<<"$res" && grep -q 'ping-int' <<<"$res" || die "could not take the resource file from section 3 of the guide"
    grep -q '^    on pve1 {' <<<"$res" && grep -q '^    on pve2 {' <<<"$res" && grep -q '192\.168\.1\.80:7788' <<<"$res" && grep -q '192\.168\.1\.81:7788' <<<"$res" \
        || die "section 3 of the guide no longer names pve1/pve2 at 192.168.1.80/.81"
    n0=$(on "$P0" hostname 20); n1=$(on "$P1" hostname 20)
    [ -n "$n0" ] && [ -n "$n1" ] || die "could not read the hosts' names"
    if [ "$n0 $P0 $n1 $P1" != "pve1 192.168.1.80 pve2 192.168.1.81" ]; then
        res=$(sed -e "s/^    on pve1 {/    on $n0 {/" -e "s/^    on pve2 {/    on $n1 {/" \
                  -e "s/192\.168\.1\.80:7788/$P0:7788/" -e "s/192\.168\.1\.81:7788/$P1:7788/" <<<"$res")
        say "3. the guide's resource with $n0 ($P0) for pve1 and $n1 ($P1) for pve2"
    fi
    echo "$res" > "$EVID/mxfs.res"
    say "3. resource file: $(wc -l <<<"$res") lines from the guide's section 3 (both nodes)"
    both "echo $(base64 -w0 <<<"$res") | base64 -d > /etc/drbd.d/mxfs.res && drbdadm dump mxfs > /dev/null && echo RES_OK" 30 || die "section 3 failed"
    # 4. First synchronisation
    for c in "drbdadm create-md mxfs && drbdadm up mxfs" "drbdadm primary --force mxfs" "drbdadm primary mxfs"; do guide_has "$c"; done
    say "4. first synchronisation: create-md + up (both), primary --force (node A = $P0)"
    both "drbdadm create-md mxfs < /dev/null && drbdadm up mxfs && echo UP" 120 || die "section 4 create-md/up failed"
    on "$P0" "drbdadm primary --force mxfs && echo PRIMARY" 60 | grep -q PRIMARY || die "section 4: primary --force on $P0 failed"
    finish
}

finish() {
    local c t0 st
    for c in "drbdadm primary mxfs" "mkfs.mxfs /dev/drbd0"; do guide_has "$c"; done
    say "4. waiting for the first sync to reach UpToDate/UpToDate (budget ${SYNC_BUDGET}s)"
    t0=$(date +%s)
    while :; do
        st=$(on "$P1" "grep -E '^ *0:' /proc/drbd; grep -oE 'sync.ed: *[0-9.]+%' /proc/drbd" 20 | tr '\n' ' ')
        grep -q 'ds:UpToDate/UpToDate' <<<"$st" && break
        [ $(( $(date +%s) - t0 )) -ge "$SYNC_BUDGET" ] && die "the first sync did not finish within ${SYNC_BUDGET}s: $st"
        sleep 20
    done
    say "   first sync done after $(( $(date +%s) - t0 ))s"
    on "$P1" "drbdadm primary mxfs && echo PRIMARY" 60 | grep -q PRIMARY || die "section 4: primary on $P1 failed"
    # 5. Format, once
    c="mkfs.mxfs /dev/drbd0"; guide_has "$c"
    say "5. format: $c (node A = $P0)"
    on "$P0" "$c < /dev/null 2>&1 | tail -4; echo MKFS_RC=\${PIPESTATUS[0]}" 300 | tee -a "$EVID/log" | grep -q 'MKFS_RC=0' || die "section 5 failed"
    # 6. Mount at boot
    for c in "echo MOUNTPOINT=/mnt/shared > /etc/mxfs/drbd-mxfs.conf" "systemctl enable --now mxfs-drbd@mxfs" \
             "pvesm add dir shared --path /mnt/shared --shared 1 --is_mountpoint yes"; do guide_has "$c"; done
    say "6. mount at boot: the conf file and enable --now (both nodes), the Proxmox storage (once)"
    t0=$(date +%s)
    both "echo MOUNTPOINT=/mnt/shared > /etc/mxfs/drbd-mxfs.conf && systemctl enable --now mxfs-drbd@mxfs; echo ENABLE_RC=\$?" "$MOUNT_BUDGET" || die "section 6: enable --now failed"
    say "   enable --now returned on both after $(( $(date +%s) - t0 ))s"
    on "$P0" "pvesm add dir shared --path /mnt/shared --shared 1 --is_mountpoint yes \\
      --content images,iso,vztmpl,backup,snippets && echo STORAGE_ADDED" 60 | grep -q STORAGE_ADDED || die "section 6: pvesm add failed"
    say "guide done"
}

verify() {
    say "== verify"
    local h s bad=0 builds=""
    for h in "$P0" "$P1"; do
        s=$(on "$h" "echo \"name=\$(hostname) mnt=\$(awk '\$2 == \"/mnt/shared\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts | head -1) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) ds=\$(drbdadm dstate mxfs 2>/dev/null) unit=\$(systemctl is-active mxfs-drbd@mxfs) guard=\$(systemctl is-active mxfs-drbd-guard) enabled=\$(systemctl is-enabled mxfs-drbd@mxfs) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) ping_int=\$(drbdsetup show mxfs | awk '\$1 == \"ping-int\" {gsub(\";\", \"\"); print \$2}') storage=\$(pvesm status 2>/dev/null | awk '\$1 == \"shared\" {print \$3}')\"" 30)
        say "$h: $s"
        case "$s" in
            *"mnt=/mnt/shared role=Primary/Primary cs=Connected ds=UpToDate/UpToDate unit=active guard=active enabled=enabled build="*" ping_int=3 storage=active"*) ;;
            *) bad=1 ;;
        esac
        builds="$builds $(sed -n 's/.*build=\([^ ]*\).*/\1/p' <<<"$s")"
    done
    # drbdsetup show prints only what differs from DRBD's defaults, so the
    # configured value above is what the next connection takes; the live
    # connection was made by `drbdadm up` from the same file.
    [ "$(tr ' ' '\n' <<<"$builds" | sort -u | grep -c .)" = 1 ] || { say "the hosts run different builds:$builds"; bad=1; }
    [ "$bad" = 0 ] || die "the pair is not what the guide promises"
    say "RESULT: PASS — both hosts set up from the guide, mounted, Primary/Primary, UpToDate"
}

for ph in "${PHASES[@]}"; do
    case "$ph" in
        teardown|guide|finish|verify) "$ph" ;;
        *) die "unknown phase $ph" ;;
    esac
done
say "evidence: $EVID"
