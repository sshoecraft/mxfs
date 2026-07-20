#!/bin/bash
# dkms_install — DKMS add/build/install/remove of mxfs on this host (per-host
# infra). Mirrors packaging/mkdeb.sh staging: copy source to /usr/src/mxfs-$VER,
# substitute __VERSION__ in dkms.conf, then add/build/install, verify, remove.
SUITE_TEST_NAME=dkms_install
NODES="${MXFS_NODES:-1}"
REPO_SRC="${MXFS_REPO_SRC:-/src/mxfs}"
VER="$(cat "$REPO_SRC/VERSION" 2>/dev/null)"
SRCDIR="/usr/src/mxfs-$VER"
LOG="/tmp/dkms_install.$$"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
[ -n "$VER" ] || { emit FAIL setup "no VERSION file"; exit 1; }
command -v dkms >/dev/null 2>&1 || { emit SKIP dkms-absent "dkms not installed"; exit 0; }
KR=$(uname -r)
[ -d "/lib/modules/$KR/build" ] || { emit SKIP no-headers "linux-headers-$KR absent"; exit 0; }

dkms remove -m mxfs -v "$VER" --all >/dev/null 2>&1
rm -rf "$SRCDIR"; mkdir -p "$SRCDIR"
rsync -a --exclude='.git' --exclude='.ccloop' --exclude='.ccmemory' \
      --exclude='*.o' --exclude='*.ko' --exclude='*.mod' --exclude='*.mod.c' \
      --exclude='.*.cmd' --exclude='.tmp_versions' --exclude='Module.symvers' \
      --exclude='modules.order' \
      "$REPO_SRC/" "$SRCDIR/" >/dev/null 2>&1 || { emit FAIL stage "source rsync failed"; exit 1; }
sed "s/__VERSION__/$VER/" "$REPO_SRC/packaging/dkms.conf" > "$SRCDIR/dkms.conf"

dkms add     -m mxfs -v "$VER" >"$LOG" 2>&1;  add=$?
dkms build   -m mxfs -v "$VER" >>"$LOG" 2>&1; build=$?
dkms install -m mxfs -v "$VER" >>"$LOG" 2>&1; install=$?
dkms status -m mxfs -v "$VER" 2>/dev/null | grep -qi installed && installed=yes || installed=no
dkms remove  -m mxfs -v "$VER" --all >>"$LOG" 2>&1; remove=$?
[ -z "$(dkms status -m mxfs -v "$VER" 2>/dev/null)" ] && clean=yes || clean=no
rm -rf "$SRCDIR"

measured="add=$add build=$build install=$install installed=$installed remove=$remove clean=$clean"
if [ "$add" = 0 ] && [ "$build" = 0 ] && [ "$install" = 0 ] && [ "$installed" = yes ] && [ "$remove" = 0 ] && [ "$clean" = yes ]; then
  emit PASS "$measured"
else
  emit FAIL "$measured" "$(grep -iE 'error|Error|cannot|failed' "$LOG" | tail -3 | tr '\n' ';')"
fi
rm -f "$LOG"
