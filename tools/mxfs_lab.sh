#!/bin/bash
# mxfs_lab.sh — resolve this site's test lab: which nodes verify each platform,
# their addresses, and the shared LUN they attach to.
#
# SOURCE OF TRUTH: ~/.config/mxfslab/lab  (override with $MXFS_LAB)
#   Every lab is different, so none of this lives in the repo; lab/README.md
#   says how to build the nodes, and this file says where they ended up.
#   Format (one key per line, same as the secrets store):
#     <key> field=value field=value ...
#
#   storage portal=<ip[:port]> target=<iqn> lun=/dev/disk/by-id/<id> [also=<n1,n2>]
#       the iSCSI LUN every pair shares.  also= names nodes outside the pairs
#       that attach to it (the rig), which must be unmounted before a format.
#   pair <platform>=<nodeA>,<nodeB> ...
#       a platform's verification pair, keyed as in data/platforms.json.
#   addr <node>=<ipv4> ...
#       a node no resolver knows.  peer= takes addresses, never names.
#   qemu monitor_dir=<dir>
#       for a guest that is not a libvirt domain: its QMP socket is
#       <dir>/<node>/<node>.monitor.
#   paths image=<file> delay_image=<file> vmdir=<dir> qemu_root=<dir>
#       this host's own files: the fileio image behind the SCST/LIO LUN, the
#       dm-delay rig's image, the VM directory and the qemu guests' root
#       (<qemu_root>/<vm>/<vm> is a guest's boot disk).
#
# Usage:
#   mxfs_lab.sh get <key> <field>    # print a field
#   mxfs_lab.sh pair <platform>      # print "A B"
#   mxfs_lab.sh addr <node>          # print its IPv4 address
#   mxfs_lab.sh lun-nodes            # every node that may attach to the LUN
#   . tools/mxfs_lab.sh              # SOURCE it to get the functions only
#
# Sourcing defines functions and nothing else: a sourced script sees the
# caller's positional parameters, so dispatching on them would run the CLI
# with the caller's arguments.
# The lab is the invoking user's, also under sudo, where $HOME is root's.
MXFS_LAB="${MXFS_LAB:-$(getent passwd "${SUDO_USER:-$(id -un)}" | cut -d: -f6)/.config/mxfslab/lab}"

lab_get() {  # <key> <field>
    [ -r "$MXFS_LAB" ] || { echo "mxfs_lab: $MXFS_LAB is missing (see lab/README.md)" >&2; return 1; }
    awk -v k="$1" -v f="$2" '
        $1==k { for(i=2;i<=NF;i++){ n=index($i,"=");
                if(n && substr($i,1,n-1)==f){ print substr($i,n+1); found=1; exit } } }
        END { exit(found?0:1) }
    ' "$MXFS_LAB"
}

lab_need() {  # <key> <field> — lab_get, or say which line is missing
    lab_get "$1" "$2" || { echo "mxfs_lab: no '$1 $2=' in $MXFS_LAB (see lab/README.md)" >&2; return 1; }
}

lab_pair() {  # <platform> -> "A B"
    local p
    p=$(lab_need pair "$1") || return 1
    case "$p" in
        *,*) echo "${p%%,*} ${p#*,}" ;;
        *) echo "mxfs_lab: pair $1=$p is not two nodes" >&2; return 1 ;;
    esac
}

lab_addr() {  # <node> -> IPv4: the lab file first, then the resolver
    local a
    a=$(lab_get addr "$1" 2>/dev/null) && { echo "$a"; return 0; }
    a=$(getent ahostsv4 "$1" | awk 'NR == 1 {print $1}')
    echo "${a:-$1}"
}

lab_lun_nodes() {  # every node named by a pair, plus storage also=
    [ -r "$MXFS_LAB" ] || { echo "mxfs_lab: $MXFS_LAB is missing (see lab/README.md)" >&2; return 1; }
    awk '$1=="pair" { for(i=2;i<=NF;i++){ n=index($i,"="); if(n) print substr($i,n+1) } }
         $1=="storage" { for(i=2;i<=NF;i++) if($i ~ /^also=/) print substr($i,6) }' "$MXFS_LAB" \
        | tr ',' '\n' | awk 'NF && !seen[$0]++'
}

mxfs_lab_dispatch() {
    case "${1:-}" in
        get)       lab_need "${2:?key}" "${3:?field}" ;;
        pair)      lab_pair "${2:?platform}" ;;
        addr)      lab_addr "${2:?node}" ;;
        lun-nodes) lab_lun_nodes ;;
        *) echo "usage: mxfs_lab.sh {get <key> <field>|pair <platform>|addr <node>|lun-nodes}" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -u
    mxfs_lab_dispatch "$@"
    exit $?
fi
