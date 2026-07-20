#!/bin/bash
# Criterion: DKMS clean install/uninstall.  Verifier: build a .deb via
# packaging/mkdeb.sh, install it on a node, verify mxfs.ko is present
# in /lib/modules/$(uname -r)/updates/fs/mxfs/, modprobe it, then purge
# and verify cleanup.  Threshold: install rc=0, modprobe rc=0, purge
# rc=0, post-purge module file absent.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "dkms_install"
# The DKMS postinst compiles the entire MXFS module (the full XFS fork,
# ~140K LOC) on the target node — that build alone is ~75-90s.  Allow
# headroom for apt-get dkms + build + modprobe + purge.
set_script_timeout 360

parse_common_args "$@"
NODE="${NODES[0]}"

# Build the .deb locally on the coordinator
cd "$MXFS_REPO" >/dev/null || result_fail "n/a" "build-ok" "cannot cd to repo"
# Clear out any old .debs so we can pick out the new one unambiguously
rm -f "$MXFS_REPO"/mxfs_*.deb
(cd "$MXFS_REPO" && bash packaging/mkdeb.sh) >/tmp/mkdeb.log 2>&1
DEB=$(ls -1t "$MXFS_REPO"/mxfs_*.deb 2>/dev/null | head -1)
[ -n "$DEB" ] && [ -f "$DEB" ] \
    || result_fail "n/a" "build-ok" "mkdeb.sh did not produce a .deb (see /tmp/mkdeb.log)"

# Ship .deb to the node, install
DEB_NAME=$(basename "$DEB")
scp_helper() {
    sshpass -p "$(cat "$MXFS_PASS")" scp -o StrictHostKeyChecking=no \
        "$@" >/dev/null 2>&1
}
scp_helper "$DEB" "root@${NODE}:/tmp/${DEB_NAME}" \
    || result_fail "n/a" "ship-ok" "scp .deb to $NODE failed"

# Make sure mxfs is not currently loaded
ssh_node_quiet "$NODE" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

# Install.  The dpkg postinst runs a full DKMS build (~75-90s), which
# exceeds the default 60s per-SSH timeout — give this call a long timeout
# so the build completes and INSTALL_RC is actually reported.
out=$(MXFS_SSH_TIMEOUT=300 ssh_node "$NODE" "
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dkms 2>/dev/null
    DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/${DEB_NAME} 2>&1
    echo INSTALL_RC=\$?
")
rc=$(echo "$out" | sed -n 's/^INSTALL_RC=//p' | tail -1)
[ "$rc" = "0" ] || result_fail "install_rc=$rc" "install=0,probe=0,purge=0" "dpkg install failed"

# Verify .ko present in dkms tree.  Modern Ubuntu/Debian compress kernel
# modules via zstd, so the on-disk filename may be mxfs.ko or mxfs.ko.zst.
ko_present=$(ssh_node "$NODE" "find /lib/modules/\$(uname -r) \\( -name 'mxfs.ko' -o -name 'mxfs.ko.zst' -o -name 'mxfs.ko.xz' -o -name 'mxfs.ko.gz' \\) 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
ko_present=${ko_present:-0}
[ "$ko_present" -ge 1 ] || result_fail "ko_present=$ko_present" "ko_present>=1" "mxfs.ko not installed by DKMS"

# Try modprobe
modprobe_rc=$(ssh_node "$NODE" "modprobe mxfs 2>&1; echo MOD_RC=\$?" | sed -n 's/^MOD_RC=//p' | tail -1)
[ "$modprobe_rc" = "0" ] || result_fail "modprobe_rc=$modprobe_rc" "probe=0" "modprobe mxfs failed"

# Unload, then purge.  The package built by packaging/mkdeb.sh is
# named "mxfs"; the older mkdeb_pve.sh path emitted "mxfs-dkms".  We
# purge whichever is actually installed (or both) and only fail if
# the FS package is still present after.
ssh_node_quiet "$NODE" "rmmod mxfs 2>/dev/null"
purge_out=$(ssh_node "$NODE" "
    for pkg in mxfs-dkms mxfs; do
        if dpkg -l \"\$pkg\" 2>/dev/null | grep -q '^ii'; then
            DEBIAN_FRONTEND=noninteractive dpkg --purge \"\$pkg\" 2>&1
        fi
    done
    echo PURGE_RC=\$?
")
purge_rc=$(echo "$purge_out" | sed -n 's/^PURGE_RC=//p' | tail -1)
[ "$purge_rc" = "0" ] || result_fail "purge_rc=$purge_rc" "purge=0" "dpkg purge failed"

# Post-purge: .ko (any compression variant) should be gone
ko_after=$(ssh_node "$NODE" "find /lib/modules/\$(uname -r) \\( -name 'mxfs.ko' -o -name 'mxfs.ko.zst' -o -name 'mxfs.ko.xz' -o -name 'mxfs.ko.gz' \\) 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
ko_after=${ko_after:-0}
[ "$ko_after" = "0" ] || result_fail "ko_after_purge=$ko_after" "ko_after_purge=0" "DKMS left .ko behind"

result_pass "install=0 probe=0 purge=0 clean=yes" "install=0,probe=0,purge=0,clean"
