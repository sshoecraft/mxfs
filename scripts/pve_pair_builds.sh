#!/bin/bash
# pve_pair_builds.sh — run concurrent OS image builds on the two physical
# Proxmox hosts, with every build VM's disk on the shared MXFS storage, and
# time each one.  Eight of these at once (four per host) is the workload that
# shut both hosts' MXFS down on 2026-10-06; it is the pair's real load test.
#
# Each build is `mkosimage proxmox/<location>/<spec> <name>` run here: packer's
# proxmox-iso builder creates the VM on that host (4 cores, 4 GiB, a 16 GiB
# virtio disk on storage `shared`, cache=none), installs the OS from the ISO
# storage with a kickstart, and waits up to 45 min for it to come up.
#
# Usage: scripts/pve_pair_builds.sh [per-host] [spec]
#   per-host  builds per host (default 4); names <PREFIX>1..<PREFIX>2n, odd
#             ones on pve1, even ones on pve2
#   spec      default alma-9.7-x86_64
# Env:
#   PREFIX        build name prefix (default alma9-)
#   LOCATIONS     "pve1 pve2" (mkosimage locations, in host order)
#   HOSTS         "192.168.1.80 192.168.1.81" (the same hosts' addresses)
#   BUILD_BUDGET  seconds per build (default 3000: packer's own 45 min wait for
#                 the installed system, plus VM creation, boot and post-build)
#   CREATE_BUDGET seconds from a build's start to its VM created (default 60:
#                 ~10 s measured, the kickstart ISO built and uploaded first)
#   STORAGE       the Proxmox storage for the build VMs' disks instead of the
#                 location's own (`shared`): `local-lvm` gives the same builds
#                 on each host's own disk, the baseline MXFS is measured against
#   EVID          evidence directory (default tests/evidence/pve_pair_builds/<stamp>)
#
# The builds start one after another, each once the previous one has created
# its VM: packer asks the cluster for the next free VM id, and two builds that
# ask at once get the same one (2026-10-06: "unable to create VM 103 - can't
# lock file", and that build never ran).
#
# Before starting, a stopped VM on either host that is a leftover build (named
# packer-*, or one of this run's names) is destroyed with its disks: a failed
# build must be cleaned up before it is tried again.  A running VM of those
# names stops the run instead.  Nothing else on the hosts is touched.
#
# Output: one line per build (name, host, rc, wall), the summary in
# $EVID/summary.txt, each build's log in $EVID/<name>.log.  Exit 0 only when
# every build succeeded within its budget.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PER=${1:-4}
SPEC=${2:-alma-9.7-x86_64}
PREFIX=${PREFIX:-alma9-}
read -r -a LOCS <<<"${LOCATIONS:-pve1 pve2}"
read -r -a HOSTS <<<"${HOSTS:-192.168.1.80 192.168.1.81}"
BUILD_BUDGET=${BUILD_BUDGET:-3000}
CREATE_BUDGET=${CREATE_BUDGET:-60}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID=${EVID:-$REPO/tests/evidence/pve_pair_builds/$STAMP}
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
command -v mkosimage >/dev/null || { say "ABORT: no mkosimage here"; exit 1; }

NAMES=()
for i in $(seq 1 $(( PER * 2 ))); do NAMES+=("$PREFIX$i"); done
pat="^(packer-.*|$(IFS='|'; echo "${NAMES[*]}"))\$"

# Leftover build VMs: destroy the stopped ones, refuse on a running one.
for h in "${HOSTS[@]}"; do
    vms=$(on "$h" "qm list 2>/dev/null | awk 'NR > 1 {print \$1, \$2, \$3}'" 30)
    while read -r id name status; do
        [ -n "$id" ] || continue
        [[ "$name" =~ $pat ]] || continue
        if [ "$status" != stopped ]; then
            say "ABORT: $h has build VM $id ($name) $status; stop it first"
            exit 1
        fi
        out=$(on "$h" "qm destroy $id --purge 1 --destroy-unreferenced-disks 1 2>&1; echo DESTROY_RC=\$?" 120)
        say "$h: destroyed leftover build VM $id ($name): $(grep -o 'DESTROY_RC=[0-9]*' <<<"$out")"
    done <<<"$vms"
done

say "starting ${#NAMES[@]} builds of $SPEC: $PER per host, disks on storage ${STORAGE:-shared}, budget ${BUILD_BUDGET}s each"
T0=$(date +%s)
for i in "${!NAMES[@]}"; do
    n=${NAMES[$i]}
    loc=${LOCS[$(( i % 2 ))]}
    (
        t0=$(date +%s)
        timeout "$BUILD_BUDGET" mkosimage ${STORAGE:+-D "vm_storage_pool=$STORAGE"} "proxmox/$loc/$SPEC" "$n" > "$EVID/$n.log" 2>&1 </dev/null
        rc=$?
        echo "$n $loc rc=$rc wall=$(( $(date +%s) - t0 ))s" > "$EVID/$n.result"
    ) &
    tc=$(date +%s)
    until grep -a -q -E 'Starting VM|Error creating VM' "$EVID/$n.log" 2>/dev/null || [ -e "$EVID/$n.result" ]; do
        if [ $(( $(date +%s) - tc )) -ge "$CREATE_BUDGET" ]; then
            say "$n had not created its VM ${CREATE_BUDGET}s after its start (budget exceeded); starting the next build anyway"
            break
        fi
        sleep 2
    done
done
wait
for n in "${NAMES[@]}"; do
    r=$(cat "$EVID/$n.result" 2>/dev/null || echo "$n no result")
    say "$r"
done
say "all builds done in $(( $(date +%s) - T0 ))s"
for h in "${HOSTS[@]}"; do
    on "$h" "hostname; qm list 2>/dev/null" 30 | sed "s/^/  /" | tee -a "$SUM"
done
fails=$(grep -L ' rc=0 ' "$EVID"/*.result 2>/dev/null | wc -l)
missing=$(( ${#NAMES[@]} - $(ls "$EVID"/*.result 2>/dev/null | wc -l) ))
if [ "$fails" = 0 ] && [ "$missing" = 0 ]; then
    say "PASS: every build succeeded; evidence $EVID"
    exit 0
fi
say "FAIL: $fails build(s) did not succeed, $missing without a result; evidence $EVID"
exit 1
