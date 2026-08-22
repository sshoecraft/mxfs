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
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
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

# 2. Form on node1.
out=$(timeout 180 "$SSH" test1 "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh $TRANSPORT" 2>&1)
echo "$out" | grep -q NODE_PREP_OK || { echo "SWAP_FAIL (form test1): $out"; exit 1; }
echo "--- test1 formed on existing fs ---"

# 3. Join the rest in parallel.
for n in $(seq 2 "$N"); do
  (
    timeout 180 "$SSH" "test$n" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh $TRANSPORT" 2>&1 \
      | grep -E 'NODE_PREP_OK|NODE_PREP_FAIL' > "$tmpd/join.$n"
  ) &
done
wait
bad=""
for n in $(seq 2 "$N"); do
  grep -q NODE_PREP_OK "$tmpd/join.$n" 2>/dev/null || bad="$bad test$n"
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
jq -n --argjson n "$N" --arg d "$TRANSPORT" --arg s "$WANT_SV" --arg nl "$nl" --arg t "$(date -u +%FT%TZ)" \
  '{nodes:$n, dlm:$d, srcversion:$s, node_list:$nl, iso:$t}' > "$REPO/.cluster_marker.json"
echo "SWAP_OK sv=$WANT_SV nodes=$N marker updated"
