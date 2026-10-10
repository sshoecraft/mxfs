#!/bin/bash
# pve_read_stall_probe.sh — the fsynced-set read tests/pve_pair_failover.sh
# grades (the md5 of every f* in a directory), with a sampler that records
# where it waits once it has run longer than it should.
#
# Runs ON a Proxmox host, fed over ssh: neither pair mounts clyde's tree, so
# the harness sends this file as `bash -s` input instead of a path.
#
#   ssh <host> bash -s -- <dir> <sample_after_s> <limit_s> < pve_read_stall_probe.sh
#
# The read runs in the background.  From <sample_after_s> on, every 5 s, it
# prints one STALL line per task that is the reader or an MXFS kernel thread
# in an interesting state, and that task's kernel stack (STACK lines): the
# reader always; an mxfs-worker when it is runnable or in D state, or when
# its stack is in the ledger, a takeover or the DRBD swap.  The read is
# never killed before <limit_s>, so a slow read still reports how long it
# took; at the end it prints DONE_MS=<ms> (or DONE_MS=TIMEOUT) and SUM=<md5>.
# The caller grades the time: this only measures.
#
# /proc/<pid>/comm, stat, wchan and stack only: never cmdline, which takes the
# task's mmap_lock and hangs behind a task wedged holding it.
set -u
dir=$1 after=$2 limit=$3
cd "$dir" 2>/dev/null || { echo "NO_DIR $dir"; exit 1; }
out=$(mktemp)
t0=$(date +%s%3N)
( md5sum f* | sort -k2 | md5sum | cut -c1-32 > "$out" ) &
p=$!
next=$(( after * 1000 ))
el=0
while kill -0 "$p" 2>/dev/null; do
    el=$(( $(date +%s%3N) - t0 ))
    [ "$el" -ge $(( limit * 1000 )) ] && break
    if [ "$el" -ge "$next" ]; then
        next=$(( next + 5000 ))
        for d in /proc/[0-9]*; do
            c=$(cat "$d/comm" 2>/dev/null) || continue
            case "$c" in md5sum|mxfs-worker) ;; *) continue ;; esac
            st=$(cut -d' ' -f3 "$d/stat" 2>/dev/null)
            stack=$(cat "$d/stack" 2>/dev/null)
            if [ "$c" = mxfs-worker ]; then
                case "$st" in D|R) ;; *)
                    grep -qE 'tauth|takeover|ledger|drbd_cas|drbd_lock|page_handoff|process_remote' <<<"$stack" || continue ;;
                esac
            fi
            f=""
            [ "$c" = md5sum ] && f=$(readlink "$d/fd/3" 2>/dev/null)
            echo "STALL t_ms=$el pid=${d#/proc/} comm=$c state=$st wchan=$(cat "$d/wchan" 2>/dev/null) file=${f:-none}"
            sed 's/^/STACK /' <<<"$stack" | grep -v '^STACK $'
        done
    fi
    sleep 0.2
done
if kill -0 "$p" 2>/dev/null; then
    echo "DONE_MS=TIMEOUT after $el ms"
else
    wait "$p"
    echo "DONE_MS=$(( $(date +%s%3N) - t0 ))"
fi
echo "SUM=$(cat "$out")"
rm -f "$out"
