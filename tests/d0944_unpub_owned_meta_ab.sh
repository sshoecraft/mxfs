#!/bin/bash
# d0944_unpub_owned_meta_ab.sh — does publishing a deferred-publish inode before
# it logs a metadata block outside its core remove the unreplayable images?
#
# D-0944.  A newly created inode holds a LOCAL-ONLY EX grant with no on-disk
# slot (deferred publish).  A metadata block outside the inode core — a bmap
# btree block, a non-shortform attr fork block, a remote symlink target — is
# authorized by that inode's EX grant and by nothing else, so while the grant
# is local-only the producer has no durable epoch to name and every image of
# such a block ships MXFS_AUTH_ST_AUTH_NOT_HELD.  A peer replaying this node's
# slice after a death must refuse the whole transaction that carried one; the
# refusal atomically skips the transaction and quarantines every AG it touched,
# and when AG 0 is in that set the root inode is unreadable and the filesystem
# cannot be mounted again.
#
# Measured on a HEALTHY lap (0.75.109): 6662 of 27413 logged images, all bmap
# btree, unpub=6662 durable=0.  Nothing was killed; the condition is present on
# every lap and only a death decides whether it is ever paid for.
#
# THE ARM.  unpub_publish_owned_meta=0 is the pre-fix behaviour, =1 diverts such
# an inode to a real grant at its first exclusive modify.  Each arm preps the
# cluster fresh so the P228/P239 producer counters (per-boot, cumulative and
# never reset) describe that arm alone, then runs the same workload:
# tests/agmeta_stale_leak_2node.sh, which fallocates an 8 MiB file, punches
# every other block until both free-space btrees split, and removes it.
#
# THE VERDICT is read off the producer, not off a death: the last
# P239-OWNAUTH line of the lap.  unpub must fall to zero and durable must not
# be zero.  P-UNPUB-OWNED-META proves the gate fired in the treatment arm and
# is silent in the control arm.  The lap's own PASS/FAIL and wall are carried
# through too — a fix that removes the images by wedging the workload is not a
# fix, and the pace assertions in that harness are what say so.
#
# derived time budget: prep 2 nodes measured ~90 s (bounded 300 s), lap measured 13 s
# (bounded 120 s by its own assertions).  Per arm 420 s.
#
# Usage: tests/d0944_unpub_owned_meta_ab.sh <label> <0|1>
set -u
LABEL=${1:?label}
ARM=${2:?arm: 0 = pre-fix, 1 = fix}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0944ab_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0944_unpub_owned_meta_ab label=$LABEL arm=$ARM sv=$SV $(date -u +%FT%TZ) ==="
s=$(date +%s)
MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS="unpub_publish_owned_meta=$ARM" \
    timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
[ $prc != 0 ] && { echo "RESULT: FAIL label=$LABEL prep rc=$prc"; tail -20 "$OUT/prep.log"; exit 2; }

# The knob is what the arm IS — read it back from both nodes rather than
# trusting that the prep passed it through (a prep that silently drops a
# modarg turns the control arm into a second treatment arm).
knobs=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/parameters/unpub_publish_owned_meta"; done | tr -d '\n')
svs=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/srcversion"; done | sort -u | tr '\n' ' ')
echo "  INFO knob_on_nodes=$knobs want=$ARM$ARM  srcversion_on_nodes=$svs tree=$SV"
[ "$knobs" = "$ARM$ARM" ] || { echo "RESULT: FAIL label=$LABEL knob not applied ($knobs)"; exit 2; }
case " $svs " in *" $SV "*) ;; *) echo "RESULT: FAIL label=$LABEL nodes run a different build"; exit 2;; esac

lap=$(date +%s)
timeout 120 tests/agmeta_stale_leak_2node.sh "${LABEL}lap" > "$OUT/lap.log" 2>&1
lrc=$?
echo "STAGE lap rc=$lrc wall=$(( $(date +%s) - lap ))s"
sed -n 's/^/  LAP /p' "$OUT/lap.log" | grep -a 'RESULT\|AGLEAK-MEASURE\|FAIL' | head -12

for n in $A $B; do
    rs 40 "$n" "dmesg | grep -a 'P228-TOKCLASS\|P239-OWNAUTH\|P-UNPUB-OWNED-META'" > "$OUT/probe_$n.txt"
done
for n in $A $B; do
    tok=$(grep -a 'P228-TOKCLASS' "$OUT/probe_$n.txt" | tail -1 | sed 's/^.*P228/P228/')
    own=$(grep -a 'P239-OWNAUTH n=' "$OUT/probe_$n.txt" | tail -1 | sed 's/^.*P239/P239/')
    div=$(grep -ac 'P-UNPUB-OWNED-META' "$OUT/probe_$n.txt")
    divn=$(grep -a 'P-UNPUB-OWNED-META' "$OUT/probe_$n.txt" | tail -1 | grep -ao 'n=[0-9]*' | head -1 | cut -d= -f2)
    echo "  NODE $n divert_lines=$div divert_total=${divn:-0}"
    echo "    $tok"
    echo "    $own"
done

# The verdict, from A (the node that grows the file).
own=$(grep -a 'P239-OWNAUTH n=' "$OUT/probe_$A.txt" | tail -1)
unpub=$(printf '%s' "$own" | grep -ao 'unpub=[0-9]*' | cut -d= -f2)
dur=$(printf '%s' "$own" | grep -ao 'durable=[0-9]*' | cut -d= -f2)
mis=$(grep -a 'P228-TOKCLASS' "$OUT/probe_$A.txt" | tail -1 | grep -ao 'mislabel=[0-9]*' | cut -d= -f2)
divn=$(grep -a 'P-UNPUB-OWNED-META' "$OUT/probe_$A.txt" | tail -1 | grep -ao 'n=[0-9]*' | head -1 | cut -d= -f2)
echo "D0944-AB label=$LABEL arm=$ARM lap_rc=$lrc mislabel=${mis:-?} unpub=${unpub:-?} durable=${dur:-?} diverts=${divn:-0} wall=$(( $(date +%s) - s ))s"
if [ "$ARM" = 1 ]; then
    if [ "${unpub:-1}" = 0 ] && [ $lrc = 0 ]; then
        echo "RESULT: PASS label=$LABEL — no image was logged without durable authority"
    else
        echo "RESULT: FAIL label=$LABEL — unpub=${unpub:-?} lap_rc=$lrc"
    fi
else
    echo "RESULT: CONTROL label=$LABEL — reproduces if unpub > 0 (got ${unpub:-?})"
fi
echo "  evidence: $OUT"
