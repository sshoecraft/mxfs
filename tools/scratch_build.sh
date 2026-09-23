#!/bin/bash
# scratch_build.sh — build mxfs.ko + the userspace tools from a SCRATCH COPY of
# the tree and freeze the result under tests/evidence/<label>_frozen_<ver>/,
# leaving /src/mxfs/mxfs.ko untouched (the rig preps insmod the TREE's .ko over
# NFS, so rebuilding in place while a chain is in flight splits that chain's
# srcversion — ccmemory trap-never-rebuild-mxfs-ko-while-rig-run-in-flight).
#
# Usage: tools/scratch_build.sh <label> [marker-string]
#   label          evidence prefix, e.g. sess475  (-> tests/evidence/sess475_frozen_06429)
#   marker-string  a string unique to this change; the frozen .ko must contain it
#                  (strings -a), because srcversion hashes SOURCES, not the linked
#                  objects — ccmemory trap-scratch-compile-rsync-copies-mxfs-mod-
#                  links-tree-objects.
# Env: SCRATCH_ROOT (default: the session scratchpad if CLAUDE_SCRATCHPAD is set,
#      else /tmp/claude-1000/mxfs_scratch), JOBS (default nproc),
#      KEEP_SCRATCH=1 to retain the scratch copy (default: removed after the
#      freeze; its build logs are copied into the frozen dir).
# Output (last lines): FROZEN <dir> sv=<srcversion> marker=<ok|MISSING>
# budget: a from-scratch build of the tree measured 3-5 min at -j$(nproc).
set -u
LABEL=${1:?usage: scratch_build.sh <label> [marker-string]}
MARK=${2:-}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
VER=$(tr -d '\n' < "$REPO/VERSION"); VTAG=$(echo "$VER" | tr -d '.')
ROOT=${SCRATCH_ROOT:-${CLAUDE_SCRATCHPAD:-/tmp/claude-1000/mxfs_scratch}}
S="$ROOT/mxfs_$VTAG"
FROZEN="$REPO/tests/evidence/${LABEL}_frozen_$VTAG"
JOBS=${JOBS:-$(nproc)}
mkdir -p "$S" "$FROZEN/tools"
echo "=== scratch_build $LABEL ver=$VER src=$REPO scratch=$S $(date -u +%FT%TZ) ==="
# never copy generated objects/kbuild lists (see the trap above) or the bulky
# evidence/memory/loop state; the copy is a build input only.
rsync -a --delete \
  --exclude '*.o' --exclude '*.cmd' --exclude '*.ko' --exclude '*.mod' \
  --exclude '*.mod.c' --exclude 'modules.order' --exclude 'Module.symvers' \
  --exclude '.tmp_*' --exclude 'tests/evidence' --exclude '.ccloop' \
  --exclude '.ccmemory' --exclude '.git' --exclude '*.a' \
  "$REPO/" "$S/" || { echo "ABORT: rsync rc=$?"; exit 1; }
rm -f "$S/mxfs.mod" "$S/mxfs.mod.c" "$S/mxfs.mod.o" "$S/Module.symvers" "$S/modules.order"
T0=$(date +%s)
( cd "$S" && make -j"$JOBS" modules ) > "$S/build_modules.log" 2>&1; rc=$?
echo "STAGE make_modules rc=$rc wall=$(( $(date +%s) - T0 ))s log=$S/build_modules.log"
[ $rc -eq 0 ] || { grep -n 'error:\|Error \|undefined' "$S/build_modules.log" | head -20; echo "ABORT: make modules failed"; exit 1; }
T1=$(date +%s)
( cd "$S" && make -j"$JOBS" tools ) > "$S/build_tools.log" 2>&1; rc=$?
echo "STAGE make_tools rc=$rc wall=$(( $(date +%s) - T1 ))s log=$S/build_tools.log"
[ $rc -eq 0 ] || { grep -n 'error:\|Error ' "$S/build_tools.log" | head -10; echo "ABORT: make tools failed"; exit 1; }
cp "$S/mxfs.ko" "$FROZEN/mxfs.ko" || exit 1
for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify caw_verify; do [ -f "$S/tools/$t" ] && cp "$S/tools/$t" "$FROZEN/tools/$t"; done
sv=$(modinfo "$FROZEN/mxfs.ko" | awk '/^srcversion:/{print $2}')
mk=ok
if [ -n "$MARK" ]; then strings -a "$FROZEN/mxfs.ko" | grep -qF -- "$MARK" || mk=MISSING; fi
# the linked object list must name the SCRATCH objects, never the tree's
# grep -c prints the count itself (0 included) and exits 1 on zero matches; an
# `|| echo 0` here made the variable "0\n0" and failed the final test below on
# every clean build (sess488: three good builds reported rc=1).
tree_objs=$(grep -c "^$REPO/" "$S/mxfs.mod" 2>/dev/null); tree_objs=${tree_objs:-0}
echo "FROZEN $FROZEN sv=$sv marker=$mk tree_objs_in_mod=$tree_objs wall_total=$(( $(date +%s) - T0 ))s"
# The scratch copy (600-700 MB) lives on clyde's root filesystem, the one that
# also carries the LUN and the guest images; eleven forgotten copies took the
# host below its preflight headroom floor and stopped the rig (sess492/493).
# Everything worth keeping is already frozen on NFS; keep only the build logs.
cp "$S/build_modules.log" "$S/build_tools.log" "$FROZEN/" 2>/dev/null
if [ "${KEEP_SCRATCH:-0}" != 1 ]; then
    case "$S" in "$ROOT"/mxfs_*) rm -rf -- "$S"; echo "SCRATCH removed $S (KEEP_SCRATCH=1 retains it)";; esac
fi
[ "$mk" = ok ] && [ "$tree_objs" = 0 ]
