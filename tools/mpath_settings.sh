#!/bin/bash
# mpath_settings.sh — the multipath and iSCSI initiator settings the mpath
# attachment is verified with (docs/mpath-verification.md, T4).  The rig
# applies exactly this text to every node it logs in on two paths
# (tools/lun_pool.sh), and a release recommends exactly this text to a site;
# other settings are outside what was verified.
#
# The rule they satisfy: when a path is lost, I/O on it must fail over, or
# fail, in far less than MXFS's death window (about 60 s), after which peers
# declare a silent node dead and fence it.
#
#   detection   NOP-Out every 5 s, answer due in 5 s          <= 10 s
#   recovery    the session's recovery timeout, 5 s           <= 15 s
#               (fast_io_fail_tmo: multipathd sets it on each iSCSI session)
#   no paths    with every path gone, queue for 4 checker intervals of 5 s
#               and then fail the I/O (no_path_retry 4): a node that has lost
#               its storage stops, it does not hang holding its locks
#
# Usage:
#   tools/mpath_settings.sh multipath     the text of /etc/multipath/conf.d/mxfs.conf
#   tools/mpath_settings.sh iscsi         "<setting> <value>" per line, for
#                                         iscsiadm -m node --op update -n <setting> -v <value>
#   tools/mpath_settings.sh stall-bound   seconds: the longest I/O stall a single
#                                         path loss may cause (what a row fails on)
#
# MXFS_MPATH_POLICY (default failover) is the path grouping policy: failover
# keeps I/O on one path and the other standing by; multibus spreads it over
# every path.
set -u
POLICY=${MXFS_MPATH_POLICY:-failover}
case "$POLICY" in failover|multibus) ;; *) echo "MXFS_MPATH_POLICY is failover or multibus" >&2; exit 2 ;; esac
case "${1:-}" in
    multipath)
        cat <<EOF
defaults {
    find_multipaths yes
    polling_interval 5
    max_polling_interval 5
}
overrides {
    path_grouping_policy $POLICY
    failback manual
    fast_io_fail_tmo 5
    no_path_retry 4
}
EOF
        ;;
    iscsi)
        cat <<'EOF'
node.session.timeo.replacement_timeout 5
node.conn[0].timeo.noop_out_interval 5
node.conn[0].timeo.noop_out_timeout 5
EOF
        ;;
    stall-bound) echo 30 ;;
    *) sed -n '2,28p' "$0"; exit 2 ;;
esac
