#!/bin/bash
#
# pve_dkms_rebuild.sh — rebuild + reinstall the MXFS DKMS module on THIS node
# from the current /src/mxfs source, WITHOUT rebuilding/reinstalling a .deb.
#
# Why this exists: on nodes whose kernel differs from the dev host's (Proxmox
# VE 9 = 6.17.2-1-pve vs clyde's 6.8.0-101-generic), the NFS-shared prebuilt
# mxfs.ko cannot be insmod'd — those nodes carry their own DKMS build, which
# IS the build under test there.  For instrument/fix iteration we need a fast
# local rebuild from the shared source tree.  Staging mirrors
# packaging/common.sh::mxfs_stage_kmod_source exactly.
#
# Run ON the node (it reads /src/mxfs over NFS and writes the node-local DKMS
# tree).  Invoke from the dev host as a SINGLE simple command so the sshpass
# wrapper's arg-flattening can't mangle it:
#   tools/mxfs_sshpass.sh <node> <passfile> "bash /src/mxfs/scripts/pve_dkms_rebuild.sh"
#
# Leaves the module BUILT + INSTALLED (not loaded — prep_node/run.sh loads it).
# Prints PVE_DKMS_OK <srcversion> on success, PVE_DKMS_FAIL: <reason> otherwise.
set -u

SRC=/src/mxfs
NFS_SERVER="${NFS_SERVER:-192.168.1.4:/src}"

fail() { echo "PVE_DKMS_FAIL: $*" >&2; exit 1; }

# Source of truth for the version (matches packaging/common.sh::mxfs_version).
mountpoint -q /src || {
	mkdir -p /src
	mount -t nfs "$NFS_SERVER" /src \
		-o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null \
		|| fail "NFS mount $NFS_SERVER -> /src failed"
}
[ -f "$SRC/VERSION" ] || fail "$SRC not visible (VERSION missing)"
VER=$(tr -d ' \t\r\n' < "$SRC/VERSION")
[ -n "$VER" ] || fail "empty VERSION"
DST="/usr/src/mxfs-${VER}"

echo "--- staging kmod source $SRC -> $DST (mxfs $VER, kernel $(uname -r)) ---"
mkdir -p "$DST" || fail "mkdir $DST"

# Same exclude set + directory list as mxfs_stage_kmod_source.
EXCL=(--exclude='*.o' --exclude='*.o.*' --exclude='.*.o.cmd'
      --exclude='.*.cmd' --exclude='*.ko' --exclude='*.mod'
      --exclude='*.mod.c' --exclude='*.mod.o' --exclude='modules.order'
      --exclude='Module.symvers' --exclude='*.symvers'
      --exclude='.tmp_versions/' --exclude='*.order')
for d in compat include xfs dlm pal mxfs_clayer; do
	[ -d "$SRC/$d" ] || continue
	mkdir -p "$DST/$d"
	rsync -a --delete "${EXCL[@]}" "$SRC/$d/" "$DST/$d/" \
		|| fail "rsync $d"
done
cp "$SRC/Kbuild" "$DST/"    || fail "cp Kbuild"
cp "$SRC/Makefile" "$DST/"  || fail "cp Makefile"
cp "$SRC/VERSION" "$DST/"   || fail "cp VERSION"
sed "s/__VERSION__/$VER/" "$SRC/packaging/dkms.conf" > "$DST/dkms.conf" \
	|| fail "write dkms.conf"

echo "--- dkms purge (all mxfs versions) + add/build/install ---"
# Purge EVERY registered mxfs version, not just $VER: a version bump
# (0.11.39 -> 0.11.40) otherwise leaves the old version's DKMS metadata behind.
# Full remove+add also re-snapshots the freshly-staged source into the build
# tree (dkms build reads its own snapshot, not /usr/src, so a plain rebuild
# would reuse stale source).
for ov in $(dkms status 2>/dev/null | sed -n 's/^mxfs[,/]\s*\([0-9][^,:]*\).*/\1/p' | sort -u); do
	dkms remove -m mxfs -v "$ov" --all >/dev/null 2>&1 || true
done
dkms remove -m mxfs -v "$VER" --all >/dev/null 2>&1 || true
dkms add    -m mxfs -v "$VER"            || fail "dkms add"
dkms build  -m mxfs -v "$VER"            || fail "dkms build (see /var/lib/dkms/mxfs/$VER/build/make.log)"
dkms install -m mxfs -v "$VER" --force   || fail "dkms install"

SRCVER=$(modinfo -F srcversion mxfs 2>/dev/null)
echo "PVE_DKMS_OK ${SRCVER:-unknown}"
