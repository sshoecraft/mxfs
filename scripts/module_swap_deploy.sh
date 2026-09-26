#!/bin/bash
# module_swap_deploy.sh <n> [transport] — redeploy the tree's mxfs.ko to a
# running test1..testN fleet WITHOUT re-formatting the shared LUN.
#
# prep_cluster (run.sh) always runs tests/setup/prep_fs.sh (mkfs) before
# prep_node.sh, so a plain re-prep DESTROYS an aged filesystem.  Aged-fs
# state is a reproduction precondition for several defects (#17's OVERLAY
# preconditions, #18's reused-ino P95 context), so a build that only adds
# instrumentation must be deployable in place.  Sequence:
#   1. clean-slate ALL nodes in parallel (umount + rmmod, fs untouched)
#   2. prep_node.sh on node1 (forms the cluster on the EXISTING fs)
#   3. prep_node.sh on nodes 2..N in parallel (join)
#   4. rewrite .cluster_marker.json with the new srcversion so run.sh's
#      marker check accepts the fleet without demanding a re-prep
#
# Assumes the fleet was cleanly mounted (all slots release at umount).

set -u
N="${1:?node count required}"
TRANSPORT="${2:-caw}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
# THE MARKER KNOWS WHICH DEVICE THIS RIG IS ON; A HARDCODED DEFAULT DOES NOT.
# /dev/mapper/mpatha is the multipath rig's name and does not exist on the
# single-path QNAP rig, where the LUN is reached by-path.  Defaulting to it
# there fails at the first blockdev --flushbufs, AFTER every node has already
# unmounted and unloaded — so the cost of the wrong default is a torn-down
# cluster, not a clean refusal.  .cluster_marker.json records the device the
# cluster was last formed on; prefer it, and keep the multipath name only as
# the last resort for a rig that has never been formed.
DEV="${MXFS_DEV:-}"
if [ -z "$DEV" ] && [ -r "$(dirname "$0")/../.cluster_marker.json" ]; then
    DEV=$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("dev",""))
except Exception:
    print("")' "$(dirname "$0")/../.cluster_marker.json" 2>/dev/null)
fi
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$REPO/tests/lib/rig.sh"
MXFS_DEV=$DEV; mxfs_dev_resolve test1; DEV=$MXFS_DEV_RESOLVED
MNT=/mnt/shared

MODINFO=$(command -v modinfo || echo /usr/sbin/modinfo)
WANT_SV=$("$MODINFO" "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')
[ -n "$WANT_SV" ] || { echo "SWAP_FAIL: no srcversion in $REPO/mxfs.ko"; exit 1; }
KO_MD5=$(md5sum "$REPO/mxfs.ko" | awk '{print $1}')
echo "=== module swap deploy: $N nodes, transport=$TRANSPORT, sv=$WANT_SV ==="

# 1. Clean slate everywhere, in parallel.  fs stays formatted.
tmpd=$(mktemp -d)
for n in $(seq 1 "$N"); do
  (
    timeout 90 "$SSH" "test$n" "
      # -x (exact comm) — a -f pattern containing these names matches this
      # ssh session's own remote command line and kills the shell (rc=255)
      pkill -x rsync 2>/dev/null; pkill -x fio 2>/dev/null
      umount $MNT 2>/dev/null || timeout 25 umount -f $MNT 2>/dev/null || umount -l $MNT 2>/dev/null
      for i in 1 2 3 4 5 6 7 8; do
        lsmod | grep -q '^mxfs' || break
        rmmod mxfs 2>/dev/null && break
        sleep 5
      done
      lsmod | grep -q '^mxfs' && echo DOWN_FAIL || echo DOWN_OK
    " 2>/dev/null | grep -E 'DOWN_OK|DOWN_FAIL' > "$tmpd/down.$n"
  ) &
done
wait
bad=""
for n in $(seq 1 "$N"); do
  grep -q DOWN_OK "$tmpd/down.$n" 2>/dev/null || bad="$bad test$n"
done
[ -z "$bad" ] || { echo "SWAP_FAIL: clean-slate failed on:$bad"; exit 1; }
echo "--- all $N nodes down (fs preserved) ---"

# 1b. The prep script and mxfs.ko are read from /src on the node, which is
#     the NAS export and not in any node's fstab: a node that has rebooted
#     (a death lap's victim) comes back without it and its join fails with
#     nothing but "join failed" to show for it (three deploys in a row on
#     2026-09-12).  Mount it the way scripts/rig.sh and rig_recover.sh do.
for n in $(seq 1 "$N"); do
  (
    timeout 60 "$SSH" "test$n" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; test -f /src/mxfs/mxfs.ko && echo SRC_OK || echo SRC_FAIL" 2>/dev/null \
      | grep -E 'SRC_OK|SRC_FAIL' > "$tmpd/src.$n"
  ) &
done
wait
bad=""
for n in $(seq 1 "$N"); do
  grep -q SRC_OK "$tmpd/src.$n" 2>/dev/null || bad="$bad test$n"
done
[ -z "$bad" ] || { echo "SWAP_FAIL: /src/mxfs/mxfs.ko not reachable on:$bad"; exit 1; }

# 2. Form on node1.  The marker scopes the optional join wait below to this
#    form's kernel lines.
FORM_MARK="SWAPFORM-$$-$(date +%s)"
timeout 15 "$SSH" test1 "echo '$FORM_MARK' > /dev/kmsg" >/dev/null 2>&1
out=$(timeout 180 "$SSH" test1 "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh $TRANSPORT" 2>&1)
echo "$out" | grep -q NODE_PREP_OK || { echo "SWAP_FAIL (form test1): $out"; exit 1; }
echo "--- test1 formed on existing fs ---"

# 2b. Optionally hold the joiners until node1's kernel log shows a line
#     (MXFS_JOIN_WAIT_PATTERN, bound MXFS_JOIN_WAIT_S seconds, counted from
#     the form).  A bootstrap node that takes over a dead authority's pages
#     at its mount (an orphan sweep of ~15k pages runs ~150 s) answers a
#     joiner's root-inode lock request with remaster for the whole pass on
#     builds before 0.84.5; the joiner exhausted its 60 retries in ~18 s,
#     shut its filesystem down and withdrew (s588c), and the join failed.
#     0.84.5 serves the requested page on demand and waits progress-aware
#     otherwise (tests/join_during_takeover.sh measures it), so a join
#     inside the pass is expected to succeed.  The wait stays the DEFAULT
#     (set MXFS_JOIN_WAIT_PATTERN= empty to skip it) because a deploy's job
#     is to land a build, not to measure the join path: on a filesystem
#     whose last leaver served ~15k pages every bootstrap mount runs that
#     takeover-only pass (~3.5 min) before the sweep.  The sweep prints its
#     summary even when it takes nothing, so the wait is always met.
MXFS_JOIN_WAIT_PATTERN=${MXFS_JOIN_WAIT_PATTERN-P-TAUTH-ORPHAN-SWEEP by}
if [ -n "${MXFS_JOIN_WAIT_PATTERN:-}" ]; then
  jw=${MXFS_JOIN_WAIT_S:-600}
  jt0=$(date +%s); seen=""
  while [ $(( $(date +%s) - jt0 )) -lt "$jw" ]; do
    seen=$(timeout 20 "$SSH" test1 "dmesg | awk '/$FORM_MARK/{f=1} f' | grep -a '$MXFS_JOIN_WAIT_PATTERN' | tail -1" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr -d '\r')
    [ -n "$seen" ] && break
    sleep 5
  done
  echo "--- join wait '$MXFS_JOIN_WAIT_PATTERN': $([ -n "$seen" ] && echo "seen after $(( $(date +%s) - jt0 ))s: $(echo "$seen" | cut -c1-160)" || echo "NOT seen inside ${jw}s (joining anyway)") ---"
fi

# 3. Join the rest in parallel.
for n in $(seq 2 "$N"); do
  (
    # The whole prep output is kept: a join that fails with only "join
    # failed" to show for it (s588b, cause never established) costs a lap.
    timeout 180 "$SSH" "test$n" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh $TRANSPORT" > "$tmpd/join_full.$n" 2>&1
    echo "ssh_rc=$?" >> "$tmpd/join_full.$n"
    grep -E 'NODE_PREP_OK|NODE_PREP_FAIL' "$tmpd/join_full.$n" > "$tmpd/join.$n"
  ) &
done
wait
bad=""
for n in $(seq 2 "$N"); do
  grep -q NODE_PREP_OK "$tmpd/join.$n" 2>/dev/null || {
    bad="$bad test$n"
    echo "--- join output test$n (last 12 lines) ---"
    grep -av '^Unauthorized\|^Warning:\|^If you' "$tmpd/join_full.$n" | tail -12
  }
done
[ -z "$bad" ] || { echo "SWAP_FAIL: join failed on:$bad"; exit 1; }
echo "--- ${N}-node cluster reformed ---"

# 4. Verify live srcversion fleet-wide, then rewrite the marker.
for n in $(seq 1 "$N"); do
  (
    live=$(timeout 30 "$SSH" "test$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -d '\r' | tail -1)
    [ "$live" = "$WANT_SV" ] || echo "test$n=$live" > "$tmpd/sv.$n"
  ) &
done
wait
bad=$(cat "$tmpd"/sv.* 2>/dev/null | tr '\n' ' ')
[ -z "$bad" ] || { echo "SWAP_FAIL: srcversion mismatch: $bad (want $WANT_SV)"; exit 1; }

nl=$(seq -s, -f 'test%g' 1 "$N")
# THE MARKER MUST CARRY BACK THE DEVICE IT WAS READ FROM.  Omitting `dev` here
# made this script destroy the rig on its SECOND consecutive run: the first swap
# resolved the device from the marker and then rewrote the marker without it, so
# the next swap fell through to the /dev/mapper/mpatha last resort, which does
# not exist on this rig -- after it had already unmounted and unloaded every
# node.  The cost of dropping one field is a torn-down cluster that the script
# then refuses to rebuild.
#
# So do not rebuild the marker from a list of fields somebody remembered.  That
# list is what failed, and it failed again the moment `rig` was added to the
# marker: a swap would have dropped it and left the fio yardstick unselectable
# with nothing to say why.  MERGE what this swap actually changed into what is
# already there, and every field nobody thought about survives by default.
NEWF=$(jq -n --argjson n "$N" --arg d "$TRANSPORT" --arg s "$WANT_SV" --arg nl "$nl" \
  --arg dev "$DEV" --arg t "$(date -u +%FT%TZ)" \
  '{nodes:$n, dlm:$d, srcversion:$s, node_list:$nl, dev:$dev, iso:$t}')
MTMP=$(mktemp)
if [ -s "$REPO/.cluster_marker.json" ]; then
    jq --argjson new "$NEWF" '. + $new' "$REPO/.cluster_marker.json" > "$MTMP"
else
    printf '%s\n' "$NEWF" > "$MTMP"
fi
# The rig identity is what selects the per-rig performance yardsticks; resolve
# it once here if the marker predates the field, so a swapped cluster is not
# left unidentifiable until the next full prep.
RIG=$(jq -r '.rig // empty' "$MTMP" 2>/dev/null)
if [ -z "$RIG" ]; then
    RIG=$(MXFS_DEV="$DEV" "$REPO/tools/mxfs_rig_tag.sh" "$DEV" 2>/dev/null || true)
    [ -n "$RIG" ] && jq --arg r "$RIG" '. + {rig:$r}' "$MTMP" > "$MTMP.rig" \
        && mv "$MTMP.rig" "$MTMP"
fi
mv "$MTMP" "$REPO/.cluster_marker.json"
echo "SWAP_OK sv=$WANT_SV nodes=$N dev=$DEV rig=${RIG:-unresolved} marker updated"
