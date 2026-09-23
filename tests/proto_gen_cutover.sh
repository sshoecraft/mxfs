#!/bin/bash
# proto_gen_cutover.sh — is a module built before the fence-class revocation
# actually kept off a filesystem stamped after it?
#
# WHAT THIS IS ABOUT.  0.89.16 retired fence kind 16 and 0.89.18 revoked kind
# 17: a corrected reader refuses both wherever a certificate authorises replay.
# Refusing the class at the corrected reader does nothing about the node that
# still MINTS it.  The direction that corrupts is an older, write-capable
# module JOINING beside a corrected one and minting kind 16 from a basis that
# was retired — the corrected build refuses that certificate, the old build
# honours its own, and replays a peer's slice on a retirement claim nobody
# proved.  So the old implementation has to be kept off the LUN entirely, and
# "the deployment was upgraded" is not a mechanism.
#
# The mechanism this project owns is the protocol generation: an exact-match
# gate in the mount path (-EPROTONOSUPPORT) plus the generation carried in the
# heartbeat feature block.  0.89.23 moves it 21 -> 22.  This lap measures that
# the gate actually excludes the binary that is RUNNING, on the LUN that ships.
#
# WHY IT DOES NOT PREP, AND MUST NOT.  The pre-cutover module is the one
# already loaded on the nodes.  A prep would replace it with the tree's build
# and there would be no old node left to exclude.  So this lap runs against
# the fleet as it stands and deploys nothing.  Run it BEFORE the cutover build
# is deployed; afterwards it reports VACUOUS and says why.
#
# WHY srcversion IS NOT THE BUILD IDENTITY HERE.  modpost folds only
# same-directory dependencies into srcversion, so a change to
# include/mxfs/mxfs_super.h — where MXFS_PROTO_GEN lives — leaves it
# byte-identical (measured 0.89.22 -> 0.89.23: A2ABA0E3B98727EFE11B6B9 both
# sides).  Every generation in this lap therefore comes from a line the
# running kernel printed: the envelope line at a successful mount names the
# volume's generation, and the refusal names the volume's AND the module's.
# That is strictly better evidence than a build hash would have been.
#
# THE ARMS, in order, because each one makes the next one mean something:
#
#   1. CONTROL — the fleet as it stands mounts.  Without it, the refusal below
#      is just a mount that failed, and any breakage would read as a pass.
#      The kernel's own envelope line gives the pre-cutover generation.
#   2. STAMP   — chk_mxfs -U writes the cutover generation into the envelope
#      (offline, both nodes unmounted, its own liveness re-read enforcing it).
#   3. REFUSAL — the same unchanged module, the same LUN, now refused on BOTH
#      nodes, naming both generations, with ZERO recovery lines: the exclusion
#      happens before the old build touches the log.
#
# VACUOUS IF the stamp does not move the generation — that means the volume
# was already at the cutover generation, so nothing about an upgrade was
# measured.
#
# THE BUDGET (derived, a timeout is a failure):
#   two unmounts 40 + the control mount 60 (a 2-node TCP join measures 10-25 s)
#   + its unmount 20 + chk -U 60 (a 3 s liveness re-read plus the sb copies)
#   + two refused mounts at 120 (a refusal returns fast, but its unwind runs
#   the cluster acquires and the SB summary sync) + four dmesg captures 60
#   = 480 s.  Caller bound 660 s (480 x 1.375).
#
# Usage: tests/proto_gen_cutover.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2), MXFS_TRANSPORT (tcp)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_protogen_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="PROTOGEN-MARK-$LABEL"
echo "=== proto_gen_cutover label=$LABEL A=$A B=$B $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# Multi-field lines are the norm here, so the match must not be anchored at ^.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# ---- 0. preconditions: both nodes up, and the module ALREADY loaded.  This
#         lap has nothing to measure against a fleet it would have to prep.
for n in "$A" "$B"; do
    st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
    [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
done
w=0
for n in "$A" "$B"; do
    until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
        w=$((w+1)); sleep 5
    done
done
echo "STAGE boot-wait polls=$w at +$(el)s"

for n in "$A" "$B"; do
    measure "$n" 30 "$OUT/${n}_pre.txt" '^LOADED ' "the loaded-module check on $n" \
        "echo LOADED sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null || echo none) mounted=\$(grep -c ' $MNT ' /proc/mounts)"
    sv=$(field "$OUT/${n}_pre.txt" sv)
    [ "$sv" != none ] || {
        echo "ABORT: mxfs is not loaded on $n, so there is no pre-cutover module here to exclude"
        echo "RESULT: ABORT label=$LABEL stage=precondition evidence=$OUT"; exit 2; }
    echo "STAGE $n module loaded srcversion=$sv mounted=$(field "$OUT/${n}_pre.txt" mounted)"
done

# Resolve the LUN by identity while a mount still names it (tests/lib/rig.sh
# ABORTs on anything that is not this rig's declared LUN; it never defaults).
mxfs_dev_resolve "$B"; DEV=$MXFS_DEV_RESOLVED
echo "STAGE device resolved $DEV at +$(el)s"

# ---- 1. quiesce: the stamp needs the LUN held by nobody, and chk_mxfs
#         enforces that itself (O_EXCL plus a 3 s heartbeat re-read).
for n in "$A" "$B"; do
    measure "$n" 60 "$OUT/${n}_umount.txt" '^UMOUNT rc=' "the unmount of $MNT on $n" \
        "rc=0; if grep -q ' $MNT ' /proc/mounts; then timeout 45 umount $MNT || rc=\$?; fi; echo UMOUNT rc=\$rc still=\$(grep -c ' $MNT ' /proc/mounts)"
    ck "$n released $MNT" "$(field "$OUT/${n}_umount.txt" still)" 0
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=quiesce evidence=$OUT"; exit 2; }
echo "STAGE both nodes unmounted at +$(el)s"

# ---- 2. THE CONTROL.  The fleet as it stands must mount.  This is also how
#         the pre-cutover generation is read: the kernel prints the envelope's
#         generation itself, so the number is the running module's reading of
#         the volume and not a userspace tool's.
rs 20 "$B" "echo $MARK > /dev/kmsg" >/dev/null
measure "$B" 120 "$OUT/B_ctrl_mount.txt" '^MOUNT rc=' "the control mount on $B" \
    "rc=0; timeout 90 mount -t mxfs $DEV $MNT || rc=\$?; echo MOUNT rc=\$rc mounted=\$(grep -c ' $MNT ' /proc/mounts)"
CRC=$(field "$OUT/B_ctrl_mount.txt" rc)
echo "STAGE control mount rc=$CRC mounted=$(field "$OUT/B_ctrl_mount.txt" mounted) at +$(el)s"
ck "the fleet as it stands still mounts (the control)" "$CRC" 0
ck "the control mount is in /proc/mounts" "$(field "$OUT/B_ctrl_mount.txt" mounted)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

measure "$B" 60 "$OUT/B_ctrl_dmesg.txt" 'MXFS envelope' "B's envelope line from the control mount" \
    "dmesg | sed -n '/$MARK/,\$p' | grep -a 'MXFS envelope\|C7 gate' | cut -c1-300; echo DMESG_END"
PREGEN=$(grep -aoE 'proto_gen=[0-9]+' "$OUT/B_ctrl_dmesg.txt" | tail -1 | cut -d= -f2)
echo "STAGE the volume's generation, as the running module read it: proto_gen=$PREGEN at +$(el)s"
ck "the control mount named the envelope's generation" "$([ -n "$PREGEN" ] && echo named || echo silent)" named
[ -n "$PREGEN" ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

measure "$B" 60 "$OUT/B_ctrl_umount.txt" '^UMOUNT rc=' "the control unmount on $B" \
    "rc=0; timeout 45 umount $MNT || rc=\$?; echo UMOUNT rc=\$rc still=\$(grep -c ' $MNT ' /proc/mounts)"
ck "the control mount was released again" "$(field "$OUT/B_ctrl_umount.txt" still)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

# ---- 3. THE STAMP.  chk_mxfs writes the generation its own build speaks.
mxfs_chk_on_node "$A" "$OUT/A_upgrade.txt" "the cutover stamp on $A" -U
grep -a 'upgrade:' "$OUT/A_upgrade.txt" | sed 's/^/    /' | cut -c1-200
NEWGEN=$(grep -aoE 'proto_gen=[0-9]+' "$OUT/A_upgrade.txt" | tail -1 | cut -d= -f2)
URC=$(mxfs_chk_rc "$OUT/A_upgrade.txt")
echo "STAGE stamp rc=$URC proto_gen=$NEWGEN at +$(el)s"
ck "the stamp completed" "$URC" 0
ck "the stamp reported the generation it wrote" "$([ -n "$NEWGEN" ] && echo named || echo silent)" named
ck "pre-gate kernels are declared excluded" "$(cnt "$OUT/A_upgrade.txt" 'pre-gate kernels can no longer mount')" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=stamp evidence=$OUT"; exit 2; }

if [ "$NEWGEN" = "$PREGEN" ]; then
    echo "  the volume was already at generation $NEWGEN, so no cutover was crossed and nothing about an upgrade was measured"
    echo "RESULT: VACUOUS label=$LABEL stage=stamp pre=$PREGEN new=$NEWGEN evidence=$OUT"
    exit 3
fi
echo "STAGE the cutover: the volume moved $PREGEN -> $NEWGEN while the modules did not move at all"

# ---- 4. THE MEASUREMENT.  The same unchanged modules, the same LUN, now on
#         the far side of the cutover.  Both nodes, because an exclusion that
#         holds on one node is not an exclusion.
for n in "$A" "$B"; do
    rs 20 "$n" "echo $MARK-REFUSE > /dev/kmsg" >/dev/null
    measure "$n" 180 "$OUT/${n}_refused.txt" '^MOUNT rc=' "the post-cutover mount attempt on $n" \
        "rc=0; timeout 150 mount -t mxfs $DEV $MNT || rc=\$?; echo MOUNT rc=\$rc mounted=\$(grep -c ' $MNT ' /proc/mounts)"
    RRC=$(field "$OUT/${n}_refused.txt" rc)
    echo "STAGE $n post-cutover mount rc=$RRC mounted=$(field "$OUT/${n}_refused.txt" mounted) at +$(el)s"
    ck "$n's pre-cutover module was REFUSED by the post-cutover volume" \
       "$([ -n "$RRC" ] && [ "$RRC" != 0 ] && echo refused || echo admitted)" refused
    ck "$n did not end up mounted" "$(field "$OUT/${n}_refused.txt" mounted)" 0

    measure "$n" 60 "$OUT/${n}_refuse_dmesg.txt" 'DMESG_END' "$n's journal across the refusal" \
        "dmesg | sed -n '/$MARK-REFUSE/,\$p' | cut -c1-400; echo DMESG_END"
    C7=$(grep -a 'C7 gate: filesystem cluster_proto_gen=' "$OUT/${n}_refuse_dmesg.txt" | tail -1)
    echo "    ${C7#*mxfs: }" | cut -c1-200
    printf '%s\n' "$C7" > "$OUT/${n}_c7.txt"
    # The refusal names BOTH sides: the volume's generation and the one this
    # loaded module speaks.  The second number is the build identity srcversion
    # could not give, printed by the kernel under test.
    SAWVOL=$(grep -aoE 'cluster_proto_gen=[0-9]+' "$OUT/${n}_c7.txt" | head -1 | cut -d= -f2)
    SAWMOD=$(grep -aoE 'this kernel speaks [0-9]+' "$OUT/${n}_c7.txt" | head -1 | awk '{print $NF}')
    ck "$n's refusal named the volume's generation" "$SAWVOL" "$NEWGEN"
    ck "$n's refusal named the generation its own loaded module speaks" "$SAWMOD" "$PREGEN"
    # Refused BEFORE the old build touches the log: the whole point of an
    # exclusion is that the excluded node changes nothing on the way out.
    ck "$n started no log recovery" "$(cnt "$OUT/${n}_refuse_dmesg.txt" 'Starting recovery')" 0
    ck "$n logged no BUG/Oops across the refusal" \
       "$(grep -ac 'BUG:\|Oops\|kernel NULL pointer' "$OUT/${n}_refuse_dmesg.txt")" 0
done

echo "STAGE done at +$(el)s"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 pre=$PREGEN new=$NEWGEN evidence=$OUT"
    exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails pre=$PREGEN new=$NEWGEN evidence=$OUT"
exit 1
