#!/bin/bash
#
# load_sampler.sh — what a node's path load is blocked in, sampled from clyde
# while a path row runs.
#
# Written for a 2/net/mesh/mpath symptom on 0.90.52: the victim's load stopped
# completing operations for ~70 s in every fault window and its ops.log reached
# the NFS server ~70 s late, yet no MXFS operation it logged took longer than
# 17 s; the loop was blocked somewhere it does not log (its own log fsyncs to
# NFS are the candidates).  Each sample: the pathload process's state, wchan
# and kernel stack, the node's Dirty/Writeback/NFS_Unstable counters, and every
# D-state task's comm.
#
# Usage: tests/mpath/load_sampler.sh <node> <seconds> <outfile>
#   Samples every 2 s for <seconds>; each sample's ssh is bounded at 8 s.
#   Reads /proc/<pid>/{stat,wchan,stack} and /proc/<pid>/comm only; never
#   cmdline or maps (a task wedged holding its mmap_lock makes those hang).
#
set -u
N="${1:?node}"; S="${2:?seconds}"; O="${3:?outfile}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
END=$(( $(date +%s) + S ))
: > "$O"
while [ "$(date +%s)" -lt "$END" ]; do
    {
        echo "=== $(date -u +%FT%T.%3NZ) $(date +%s%3N)"
        timeout 8 "$HERE/tools/mxfs_sshpass.sh" "$N" '
            for p in /proc/[0-9]*; do
                [ "$(cat $p/comm 2>/dev/null)" = python3 ] || continue
                st=$(cut -d" " -f3 $p/stat 2>/dev/null)
                echo "PY pid=${p#/proc/} state=$st wchan=$(cat $p/wchan 2>/dev/null)"
                sed "s/^/  STK /" $p/stack 2>/dev/null | head -14
            done
            grep -E "^(Dirty|Writeback|NFS_Unstable|WritebackTmp):" /proc/meminfo | tr -s " " | tr "\n" " "; echo
            for p in /proc/[0-9]*; do
                [ "$(cut -d" " -f3 $p/stat 2>/dev/null)" = D ] && echo "DTASK ${p#/proc/} $(cat $p/comm 2>/dev/null)"
            done' 2>/dev/null | grep -av 'Unauthorized\|disconnect immediately\|^$\|Warning: Permanently'
    } >> "$O"
    sleep 2
done
echo "=== done $(date -u +%FT%TZ)" >> "$O"
