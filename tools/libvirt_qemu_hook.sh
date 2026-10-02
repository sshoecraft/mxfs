#!/bin/bash
# libvirt_qemu_hook.sh — installed on the rig host as /etc/libvirt/hooks/qemu
# by `scripts/drbd_rig.sh hook-setup`.  It gives the rig fence authority
# (tools/rig_fence_virsh.sh) its continuing exclusion at the one place every
# start path passes through:
#
#   - a rig VM (test<N>) carrying an inhibit is never started, whichever tool
#     asks (lab_power.sh, run.sh's power-cycle, rig_recover.sh, a bare
#     `virsh start`).  The survivor's recovery relies on the fenced node staying
#     off until it releases it; a start path that does not ask the authority
#     would bring it back mid-recovery.
#   - a rig VM is never restored from saved memory (`virsh restore`, a managed
#     save): that resumes an old incarnation with its old mounts and its old
#     DRBD state, which the DRBD attachment's retirement rule excludes by
#     prohibition.
#
# Every other domain, and every other operation, passes untouched.  libvirt
# calls this hook with: <domain> <operation> <sub-operation> <extra>, the
# domain XML on stdin; a non-zero exit at "prepare begin" or "restore begin"
# aborts the start.
#
# Not covered here, because libvirt calls no hook for it: reverting a RUNNING
# domain to an internal snapshot.  scripts/drbd_rig.sh refuses to run while any
# rig VM has a snapshot.
STATE_DIR="@STATE_DIR@"
dom=${1:-}; op=${2:-}; sub=${3:-}
cat >/dev/null 2>&1    # the domain XML; unread input can block libvirtd's writer

[[ "$dom" =~ ^test[0-9]+$ ]] || exit 0
case "$op/$sub" in
    prepare/begin)
        f="$STATE_DIR/$dom.inhibit"
        if [ -e "$f" ]; then
            msg="mxfs rig fence: refusing to start $dom — it is inhibited ($(head -1 "$f")); its survivor releases it with rig_fence_virsh.sh release"
            logger -t mxfs-rig-fence "$msg"
            echo "$msg" >&2
            exit 1
        fi ;;
    restore/begin)
        msg="mxfs rig fence: refusing to restore $dom from saved memory — a rig node's old incarnation must never resume"
        logger -t mxfs-rig-fence "$msg"
        echo "$msg" >&2
        exit 1 ;;
esac
exit 0
