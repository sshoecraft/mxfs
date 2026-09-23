#!/bin/bash
# d0944_unpub_forms_probe.sh — which inode forms still log a metadata block
# while their inode holds only a local-only (deferred-publish) grant?
#
# D-0944.  A metadata block outside the inode core is authorized by the owning
# inode's EX grant and by nothing else.  While the inode is unpublished that
# grant has no on-disk slot and no durable epoch, so the image ships
# MXFS_AUTH_ST_AUTH_NOT_HELD; a peer replaying the node's slice after a death
# must refuse the whole transaction, which quarantines every AG it touched.
# 0.75.110 diverts such an inode to a real grant at its first exclusive modify
# (unpub_publish_owned_meta), which closes the bmap-btree case — measured 6662
# unreplayable images to 0.  This probe asks whether it closes the OTHERS.
#
# One form per stage, each on node A of a freshly prepped two-node TCP cluster:
#   bmbt      a fragmented file, the known population — the positive control;
#             if this does not come out clean the build or knob is wrong
#   symlink   a long target, so it does not fit in the inode core and the
#             target block is written INSIDE the create transaction
#   attr      enough extended attributes to push the fork past shortform
#   dir       a directory grown past shortform into block and leaf form
#
# THE INSTRUMENT is the producer, and it needs no death: every non-durable
# capture prints P239-OWNAUTH-NONDUR with its blft, its derived owner and its
# outcome, bounded at 48 per outcome per boot.  outcome=6 is UNPUB — an inode
# whose authority exists but was never published.  A form that produces none is
# clean; a form that produces them names itself by blft (4 btree, 9 symlink,
# 10-15 directory, 16-17 attr).  The stages run in a fixed order and the probe
# is cumulative, so each stage is reported as its own delta.
#
# derived time budget: prep 2 nodes measured ~50 s (bounded 300 s); the four stages
# are a few hundred file operations each, measured under 10 s together, bounded
# 60 s each; two dmesg captures ~4 s.  Healthy wall ~90 s.
#
# Usage: tests/d0944_unpub_forms_probe.sh <label>
# Env:   PREP=0 to reuse the current mount (the counters are then NOT this
#        run's alone and the deltas are the only readable number).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/unpubforms_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_unpubforms_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0944_unpub_forms_probe label=$LABEL A=$A B=$B sv=$SV $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ "${PREP:-1}" = 1 ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    [ $prc != 0 ] && { echo "RESULT: FAIL label=$LABEL prep rc=$prc"; tail -15 "$OUT/prep.log"; exit 2; }
fi
knob=$(rs 20 "$A" "cat /sys/module/mxfs/parameters/unpub_publish_owned_meta 2>/dev/null || echo absent")
echo "  INFO $A unpub_publish_owned_meta=$knob sv=$(rs 20 "$A" 'cat /sys/module/mxfs/srcversion')"
ck "both nodes mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"

# Cumulative count of UNPUB captures on A, by blft.  Read between stages so
# each stage's contribution is its own delta.
unpubcount() { rs 30 "$A" "dmesg | grep -ac 'P239-OWNAUTH-NONDUR .* outcome=6' || true" | tr -d '\n'; }
unpubblfts() { rs 30 "$A" "dmesg | grep -a 'P239-OWNAUTH-NONDUR .* outcome=6'" | grep -ao 'blft=[0-9]*' | sort | uniq -c | tr '\n' ' '; }

MK="UNPUBFORMS-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
rs 20 "$A" "mkdir -p $D" >/dev/null
prev=$(unpubcount); base=$prev
echo "  INFO baseline UNPUB captures on $A: $base"

stage() {   # stage <name> <bound> <remote command>
    local name=$1 bound=$2 cmd=$3 t0 now delta
    t0=$(date +%s)
    rs "$bound" "$A" "$cmd" > "$OUT/stage_$name.txt" 2>&1
    now=$(unpubcount); delta=$(( now - prev )); prev=$now
    echo "  STAGE $name wall=$(( $(date +%s) - t0 ))s unpub_new=$delta out=[$(tr '\n' ' ' < "$OUT/stage_$name.txt" | cut -c1-100)]"
    eval "DELTA_$name=$delta"
}

# 1. bmbt — the measured population, here as the positive control.
stage bmbt 60 "fallocate -l 8M $D/frag && sync -f $MNT; i=0; while [ \$i -lt 400 ]; do fallocate -p -o \$(( i * 8192 )) -l 4096 $D/frag; i=\$((i+1)); done; sync -f $MNT; echo bmbt_done ino=\$(stat -c %i $D/frag) extents=\$(filefrag -v $D/frag 2>/dev/null | grep -ac '^ *[0-9]*:')"

# 2. symlink — a target too long for the inode core but INSIDE
#    XFS_SYMLINK_MAXLEN (1024).  A 3000-character target is not a longer test,
#    it is no test at all: ln -s fails ENAMETOOLONG, and the first version of
#    this stage reported PASS having created zero symlinks.  900 characters is
#    comfortably past the inline capacity (a few hundred bytes of literal area)
#    so the target lands in a REMOTE block, which is the case under study.
stage symlink 60 "t=\$(head -c 900 /dev/zero | tr '\\0' 'a'); i=0; made=0; while [ \$i -lt 40 ]; do ln -s \"/\$t\$i\" $D/sl\$i 2>/dev/null && made=\$((made+1)); i=\$((i+1)); done; sync -f $MNT; echo symlink_done n=\$i made=\$made links=\$(find $D -maxdepth 1 -type l | wc -l) tgtlen=\$(readlink $D/sl0 2>/dev/null | wc -c) blocks=\$(stat -c %b $D/sl0 2>/dev/null)"

# 3. attr — enough xattrs on fresh files to push the attr fork past shortform.
stage attr 60 "i=0; err=0; while [ \$i -lt 40 ]; do f=$D/xa\$i; : > \$f; j=0; while [ \$j -lt 24 ]; do setfattr -n user.k\$j -v \"\$(head -c 200 /dev/zero | tr '\\0' 'v')\" \$f 2>/dev/null || err=\$((err+1)); j=\$((j+1)); done; i=\$((i+1)); done; sync -f $MNT; echo attr_done n=\$i setfattr_err=\$err attrs_on_xa0=\$(getfattr -d $D/xa0 2>/dev/null | grep -ac '^user\.')"

# 4. dir — new directories grown out of shortform into block and leaf form.
stage dir 90 "i=0; while [ \$i -lt 8 ]; do mkdir -p $D/d\$i; j=0; while [ \$j -lt 300 ]; do : > $D/d\$i/entry_with_a_long_name_\$j; j=\$((j+1)); done; i=\$((i+1)); done; sync -f $MNT; echo dir_done n=\$i entries_in_d0=\$(ls $D/d0 | wc -l) d0_blocks=\$(stat -c %b $D/d0)"

rs 40 "$A" "dmesg | grep -a 'P239-OWNAUTH-NONDUR\|P239-OWNAUTH n=\|P228-TOKCLASS\|P-UNPUB-OWNED-META'" > "$OUT/probe_$A.txt"
echo "  INFO UNPUB captures by blft on $A: $(unpubblfts)"
echo "  INFO diverts on $A: $(grep -ac 'P-UNPUB-OWNED-META' "$OUT/probe_$A.txt")"
own=$(grep -a 'P239-OWNAUTH n=' "$OUT/probe_$A.txt" | tail -1 | sed 's/^.*P239/P239/')
echo "  INFO $own"
grep -a 'P239-OWNAUTH-NONDUR .* outcome=6' "$OUT/probe_$A.txt" | sed 's/^.*P239/    /' | sort -u | head -12

total=$(( prev - base ))
echo "D0944-FORMS label=$LABEL knob=$knob bmbt=${DELTA_bmbt:-?} symlink=${DELTA_symlink:-?} attr=${DELTA_attr:-?} dir=${DELTA_dir:-?} total=$total wall=$(( $(date +%s) - s ))s"
ck "bmbt: no image logged without durable authority" "${DELTA_bmbt:-1}" "0"
ck "symlink: no image logged without durable authority" "${DELTA_symlink:-1}" "0"
ck "attr: no image logged without durable authority" "${DELTA_attr:-1}" "0"
ck "dir: no image logged without durable authority" "${DELTA_dir:-1}" "0"
# WINDOWED, and 'DLM shutting down' is not a fault.  Unwindowed, this counted
# every module unload in the node's whole ring — 13 hits on a lap that had none
# of its own, all of them the ordinary teardown message a prep prints.  A health
# assertion that fires on routine log lines trains the reader to ignore it.
window_into "$OUT/rv_hl_1.txt" "$A" 30 "$MK"; hl=$(cat "$OUT/rv_hl_1.txt" | grep -a 'corruption\|Filesystem has been shut down\|BUG:\|Oops\|EFSCORRUPTED' | grep -avc 'DLM shutting down' || true | tr -d '\n')
ck "$A: no corruption, shutdown or kernel fault line in this lap's window" "${hl:-0}" "0"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=$(( $(date +%s) - s ))s evidence=$OUT"
else echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(( $(date +%s) - s ))s evidence=$OUT"; fi
exit $(( fails > 0 ))
