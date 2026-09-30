#!/bin/bash
#
# lab_power.sh — power whole verification sets on and off, so that only the
# guests a step needs are holding the host's memory while it runs.
#
# WHY.  An 8-node release is verified on eight nodes of every platform plus
# the 8-node rig: forty guests of 2-4 GiB each against a 94 GiB host.  They
# cannot all be up at once, and the rig suites grade pace, which a host short
# of memory fails for reasons that have nothing to do with the filesystem.
# So a chain powers a set up before its steps and down after them.
#
# A <set> is one of:
#   <platform>   a key of the lab file's `nodes` line (tools/mxfs_lab.sh):
#                every node of that platform's verification set
#   rig:<N>      the development rig's first N nodes, test1..testN
#   <domain>     one libvirt domain by name
#
# Usage: scripts/lab_power.sh up|down|state <set> [<set> ...]
#   up     start every domain of the sets that is not running, all at once,
#          then wait for each to answer ssh with its boot finished.  Exit 0
#          iff every node is up.
#   down   on every running domain of the sets: unmount its MXFS mounts, then
#          an ACPI shutdown, and a destroy for a guest still up past the
#          bound.  Exit 0 iff every domain is shut off.
#   state  one line per domain: its state and, when running, its memory.
#
# Budgets (derived): a lab guest boots to ssh in 20-120 s (scripts/vm_cycle.sh
# measured 60-120 s under load), a RHEL guest waits for an iSCSI login it may
# not get -> BOOT_S=240 per node, all nodes waited for in parallel, so a set
# is up within BOOT_S.  An idle guest honours ACPI in 5-10 s; one unmounting
# first gets 60 s per mount -> SHUTDOWN_S=90 then destroy.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
BOOT_S=240
SHUTDOWN_S=90

say() { echo "[$(date -u +%T)] $*"; }
state() { timeout 30 $VIRSH domstate "$1" 2>/dev/null | head -1; }

expand() {  # <set> -> its domains, one per line
    local s=$1 n i
    case "$s" in
        rig:*)
            n=${s#rig:}
            [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] || { echo "lab_power: bad rig size in '$s'" >&2; return 1; }
            for ((i = 1; i <= n; i++)); do echo "test$i"; done ;;
        *)
            if n=$(lab_nodes "$s" 2>/dev/null); then
                echo "$n" | tr ' ' '\n'
            elif [ -n "$(state "$s")" ]; then
                echo "$s"
            else
                echo "lab_power: '$s' is neither a platform in $MXFS_LAB nor a libvirt domain" >&2
                return 1
            fi ;;
    esac
}

wait_ssh() {  # <domain>: 0 once it answers ssh with its boot finished
    local d=$1 a dl
    a=$(lab_addr "$d")
    dl=$(( SECONDS + BOOT_S ))
    while [ "$SECONDS" -lt "$dl" ]; do
        # sshd answers before the boot is over; /run/nologin is there until
        # it is, and a command run before then carries pam's banner
        timeout 10 "$SSH" "$a" "test ! -e /run/nologin && echo SSH_UP" </dev/null 2>/dev/null | grep -q SSH_UP && return 0
        sleep 3
    done
    return 1
}

up_one() {
    local d=$1 t0=$SECONDS
    [ -n "$(state "$d")" ] || { say "$d: no such domain"; return 1; }
    if [ "$(state "$d")" != running ]; then
        timeout 60 $VIRSH start "$d" >/dev/null 2>&1 || { say "$d: did not start"; return 1; }
    fi
    if wait_ssh "$d"; then
        say "$d: up after $(( SECONDS - t0 )) s"
    else
        say "$d: NOT UP within $BOOT_S s"
        return 1
    fi
}

down_one() {
    local d=$1 a t0=$SECONDS
    # a set named in the lab file before its last nodes are built has
    # nothing to power off there
    [ -n "$(state "$d")" ] || { say "$d: no such domain, nothing to power off"; return 0; }
    [ "$(state "$d")" = "shut off" ] && { say "$d: already off"; return 0; }
    a=$(lab_addr "$d")
    timeout 75 "$SSH" "$a" 'for m in $(grep " mxfs " /proc/mounts | cut -d" " -f2); do timeout 60 umount $m; done' </dev/null >/dev/null 2>&1
    timeout 30 $VIRSH shutdown "$d" >/dev/null 2>&1
    while [ "$(state "$d")" != "shut off" ]; do
        if [ $(( SECONDS - t0 )) -ge $SHUTDOWN_S ]; then
            say "$d: still up after $SHUTDOWN_S s, destroying"
            timeout 60 $VIRSH destroy "$d" >/dev/null 2>&1
            break
        fi
        sleep 2
    done
    [ "$(state "$d")" = "shut off" ] || { say "$d: NOT OFF"; return 1; }
    say "$d: off after $(( SECONDS - t0 )) s"
}

state_one() {
    local d=$1 s
    s=$(state "$d")
    if [ "$s" = running ]; then
        echo "$d running $(timeout 30 $VIRSH domstats --balloon "$d" 2>/dev/null | awk -F= '/balloon.maximum=/ {m=$2} /balloon.rss=/ {r=$2} END {printf "max=%.1fG rss=%.1fG", m/1048576, r/1048576}')"
    else
        echo "$d ${s:-absent}"
    fi
}

verb=${1:-}
case "$verb" in up|down|state) shift ;; *) echo "usage: $0 up|down|state <set> [<set> ...]" >&2; exit 2 ;; esac
[ $# -ge 1 ] || { echo "usage: $0 up|down|state <set> [<set> ...]" >&2; exit 2; }

DOMS=()
for s in "$@"; do
    list=$(expand "$s") || exit 2
    for d in $list; do
        case " ${DOMS[*]:-} " in *" $d "*) ;; *) DOMS+=("$d") ;; esac
    done
done

if [ "$verb" = state ]; then
    for d in "${DOMS[@]}"; do state_one "$d"; done
    exit 0
fi

# every domain at once, each with its own exit code
PIDS=()
for d in "${DOMS[@]}"; do
    if [ "$verb" = up ]; then up_one "$d" & else down_one "$d" & fi
    PIDS+=($!)
done
rc=0
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" || { rc=1; say "${DOMS[$i]}: $verb FAILED"; }
done
say "$verb ${#DOMS[@]} domain(s): $([ $rc = 0 ] && echo ok || echo FAILED)"
exit $rc
