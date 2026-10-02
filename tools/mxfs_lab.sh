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
#   storage portal=<ip[:port]> [target=<iqn> lun=/dev/disk/by-id/<id>] [also=<n1,n2>]
#       the iSCSI portal, and in a lab file for one platform set the LUN that
#       set formats.  also= names nodes outside the set that attach to it,
#       which must be unmounted before a format.  On clyde the site's lab file
#       names only the portal: every LUN is borrowed from the pool
#       (tools/lun_pool.sh), and tests/full_verify.sh writes a lab file per
#       platform (~/.config/mxfslab/lab.<platform>) naming the one it borrowed.
#   nodes <platform>=<node1>,<node2>[,<node3>,...] ...
#       a platform's verification set, keyed as in data/platforms.json: every
#       node that verifies a release there, in the order the harnesses use
#       them (the first is where a round formats and checks).  A release for
#       N nodes needs N names here.
#   pair <platform>=<nodeA>,<nodeB> ...
#       the two-node form of the same line, kept for a lab that verifies only
#       two-node releases.  `nodes` wins when both are present; `pair` alone
#       is a set of two.
#   group <name>=<node1>,<node2>[,...] ...
#       a rig group: a disjoint slice of the rig's nodes, which borrows a LUN
#       from the pool for each run, so several configurations can run at once
#       (`run.sh <configuration> --group <name>`).  A group is not a
#       platform: nothing that walks the platform sets sees it.
#   addr <node>=<ipv4> ...
#       a node no resolver knows.  peer= takes addresses, never names.
#   qemu monitor_dir=<dir>
#       for a guest that is not a libvirt domain: its QMP socket is
#       <dir>/<node>/<node>.monitor.
#   paths pool=<dir> [image=<file>] delay_image=<file> vmdir=<dir> qemu_root=<dir>
#       this host's own files: the test LUN pool's directory
#       (tools/lun_pool.sh), a fixed fileio image for the scripts that still
#       export one (scripts/scst_setup.sh, scripts/lio_tcm_setup.sh), the
#       dm-delay rig's image, the VM directory and the qemu guests' root
#       (<qemu_root>/<vm>/<vm> is a guest's boot disk).
#
# Usage:
#   mxfs_lab.sh get <key> <field>    # print a field
#   mxfs_lab.sh nodes <platform>     # print the verification set, "A B C D"
#   mxfs_lab.sh pair <platform>      # print the first two of it, "A B"
#   mxfs_lab.sh addr <node>          # print its IPv4 address
#   mxfs_lab.sh lun-nodes            # every node that may attach to the LUN
#   mxfs_lab.sh group <name>         # print a rig group's nodes, "A B C D"
#   mxfs_lab.sh groups               # print every rig group's name
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

lab_nodes() {  # <platform> -> "A B [C D ...]": the `nodes` line, else the `pair` line
    local p
    p=$(lab_get nodes "$1" 2>/dev/null) || p=$(lab_get pair "$1" 2>/dev/null) \
        || { echo "mxfs_lab: no 'nodes $1=' or 'pair $1=' in $MXFS_LAB (see lab/README.md)" >&2; return 1; }
    case "$p" in
        *,*) echo "$p" | tr ',' ' ' | tr -s ' ' ;;
        *) echo "mxfs_lab: nodes $1=$p is not at least two nodes" >&2; return 1 ;;
    esac
}

lab_pair() {  # <platform> -> "A B": the first two of the verification set
    local n
    n=$(lab_nodes "$1") || return 1
    set -- $n
    echo "$1 $2"
}

lab_group() {  # <group> -> "A B [C D ...]": a rig group's nodes
    local g
    g=$(lab_get group "$1" 2>/dev/null) \
        || { echo "mxfs_lab: no 'group $1=' in $MXFS_LAB (see lab/README.md)" >&2; return 1; }
    echo "$g" | tr ',' ' ' | tr -s ' '
}

lab_groups() {  # every rig group's name, once each
    [ -r "$MXFS_LAB" ] || { echo "mxfs_lab: $MXFS_LAB is missing (see lab/README.md)" >&2; return 1; }
    awk '$1=="group" { for(i=2;i<=NF;i++){ n=index($i,"="); if(n) print substr($i,1,n-1) } }' "$MXFS_LAB" \
        | awk '!seen[$0]++'
}

lab_addr() {  # <node> -> IPv4: the lab file first, then the resolver
    local a
    a=$(lab_get addr "$1" 2>/dev/null) && { echo "$a"; return 0; }
    a=$(getent ahostsv4 "$1" | awk 'NR == 1 {print $1}')
    echo "${a:-$1}"
}

lab_lun_nodes() {  # every node named by a pair, plus storage also=
    [ -r "$MXFS_LAB" ] || { echo "mxfs_lab: $MXFS_LAB is missing (see lab/README.md)" >&2; return 1; }
    awk '$1=="pair" || $1=="nodes" { for(i=2;i<=NF;i++){ n=index($i,"="); if(n) print substr($i,n+1) } }
         $1=="storage" { for(i=2;i<=NF;i++) if($i ~ /^also=/) print substr($i,6) }' "$MXFS_LAB" \
        | tr ',' '\n' | awk 'NF && !seen[$0]++'
}

mxfs_lab_dispatch() {
    case "${1:-}" in
        get)       lab_need "${2:?key}" "${3:?field}" ;;
        nodes)     lab_nodes "${2:?platform}" ;;
        pair)      lab_pair "${2:?platform}" ;;
        addr)      lab_addr "${2:?node}" ;;
        lun-nodes) lab_lun_nodes ;;
        group)     lab_group "${2:?group}" ;;
        groups)    lab_groups ;;
        *) echo "usage: mxfs_lab.sh {get <key> <field>|nodes <platform>|pair <platform>|addr <node>|lun-nodes|group <name>|groups}" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -u
    mxfs_lab_dispatch "$@"
    exit $?
fi
