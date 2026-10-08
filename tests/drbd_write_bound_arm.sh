#!/bin/bash
# drbd_write_bound_arm.sh — one arm of an A/B measurement of the DRBD write
# bound on a rig DRBD pair: load a given mxfs.ko, format and mount through
# scripts/drbd_rig.sh, set the kernel log to what a user's node prints (no
# debug sites but the DRBD bound's own and the platform log's), run
# tests/pve_pair_write_bound.sh against the pair, then unmount both nodes and
# keep the bound's end-of-mount account (P-DRBD-IOQ-DONE), which is printed
# only as the mount goes.
#
# The rig prints every mxfs debug site by default (tests/setup/prep_node.sh
# loads with dyndbg=+p): a line per iomap call under buffered writes, which
# both slows the writers and is not what a user's node does.  Both arms run
# with the same reduced set.
#
# Usage: tests/drbd_write_bound_arm.sh <label> <mxfs.ko>
# Env:
#   MXFS_NODES      "A B", the rig pair (default "test3 test4")
#   MXFS_NODE_REPO  the tree as the nodes see it over NFS; must be this
#                   script's tree (default /src/mxfs)
#   anything tests/pve_pair_write_bound.sh takes (LOAD_S, DIO_JOBS, BUF_JOBS,
#   BUF_MB, BUF_LOOPS, SAMPLE_MS ...), passed through
# Evidence: tests/evidence/drbd_write_bound_arm/<UTC stamp>-<label>/: the
# module's identity, the mount step's log, the dyndbg state, the harness's
# summary (its own evidence directory is named in it) and both nodes'
# P-DRBD-IOQ-DONE lines.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:?label}
KO=${2:?mxfs.ko}
export MXFS_NODES=${MXFS_NODES:-test3 test4}
export MXFS_NODE_REPO=${MXFS_NODE_REPO:-/src/mxfs}
read -r -a NODES <<<"$MXFS_NODES"
EVID="$REPO/tests/evidence/drbd_write_bound_arm/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/arm.log"; }
on() {  # <node> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$("$REPO/tools/mxfs_lab.sh" addr "$1")" "$2" </dev/null 2>&1 \
        | grep -avE '^Warning:|^Unauthorized|^If you|^$'
}

[ -s "$KO" ] || { say "ABORT: no module at $KO"; exit 1; }
if [ "$(readlink -f "$KO")" != "$(readlink -f "$REPO/mxfs.ko")" ]; then
    cp -f "$KO" "$REPO/mxfs.ko" || { say "ABORT: cannot install $KO as $REPO/mxfs.ko"; exit 1; }
fi
say "arm $LABEL: $(modinfo -F srcversion "$REPO/mxfs.ko") md5 $(md5sum "$REPO/mxfs.ko" | cut -c1-32) on ${NODES[*]} (nodes load from $MXFS_NODE_REPO)"

"$REPO/scripts/drbd_rig.sh" mxfs > "$EVID/mxfs.log" 2>&1 || { say "FAIL: drbd_rig.sh mxfs: $(tail -1 "$EVID/mxfs.log")"; exit 1; }
say "mounted: $(grep -a 'NODE_PREP_OK' "$EVID/mxfs.log" | cut -c1-140 | tr '\n' ' ')"

for n in "${NODES[@]}"; do
    out=$(on "$n" "c=/proc/dynamic_debug/control
        echo 'module mxfs -p' > \$c && echo 'module mxfs format \"P-DRBD\" +p' > \$c && echo 'module mxfs file kern.c +p' > \$c \
        && echo \"DYNDBG_OK on=\$(awk '\$2 ~ /^\\[mxfs\\]/ && \$3 == \"=p\" {n++} END {print n+0}' \$c) of=\$(awk '\$2 ~ /^\\[mxfs\\]/ {n++} END {print n+0}' \$c)\"" 30)
    echo "$n $out" >> "$EVID/dyndbg"
    grep -q DYNDBG_OK <<<"$out" || { say "FAIL: $n: could not set the kernel log's debug sites: $out"; exit 1; }
    say "$n debug sites: $(grep -o 'on=.*' <<<"$out")"
done

env PAIR_NAMES="$MXFS_NODES" "$REPO/tests/pve_pair_write_bound.sh" > "$EVID/harness.log" 2>&1
hrc=$?
say "harness rc=$hrc"
sed -n '/load:/,$p' "$EVID/harness.log" | tee -a "$EVID/arm.log" >/dev/null

for n in "${NODES[@]}"; do
    on "$n" "timeout 30 umount /mnt/shared; echo UMOUNT_RC=\$?; dmesg | grep -a 'P-DRBD-IOQ-DONE' | tail -1" 45 > "$EVID/done.$n"
    say "$n $(tr '\n' ' ' < "$EVID/done.$n" | sed 's/.*\(UMOUNT_RC=[0-9]*\)/\1/')"
done
exit "$hrc"
