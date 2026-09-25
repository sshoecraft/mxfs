#!/bin/bash
# mxfs_whohas.sh — which processes hold a file or device open, without the
# host-wedging walk that `fuser`, `lsof` and `pgrep -f` perform.
#
# WHY THIS EXISTS: `fuser` and `lsof` read /proc/<pid>/maps and `pgrep -f`
# reads /proc/<pid>/cmdline for EVERY process; both take the target task's
# mmap_lock, and one task wedged holding its own mmap_lock (a stuck bio, a
# THP compaction) turns each caller into a permanent uninterruptible task
# (2026-08-07: loadavg 583, manual host reset).  This reads only
# /proc/<pid>/stat (never touches the task's mm), skips any task in D state,
# and then readlinks /proc/<pid>/fd/* — a link read that goes through the
# file table, not the mm.  The command name comes from /proc/<pid>/comm.
#
# Usage:  mxfs_whohas.sh <extended-regex matched against the fd target>
#         mxfs_whohas.sh '~/disk-1.img'
#         mxfs_whohas.sh '/dev/sd[a-z]$|/dev/mapper/mpath'
# Prints: <pid> <state> <comm> <fd> -> <target> per match; exit 0 if any,
#         1 if none.  Tasks skipped for being in D state are listed on stderr.
set -u
pat="${1:?usage: mxfs_whohas.sh <extended-regex>}"
found=0
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    st=$(awk '{print $3}' "$d/stat" 2>/dev/null) || continue
    case "$st" in
        D) echo "skip pid $pid: D state (comm=$(cat "$d/comm" 2>/dev/null))" >&2; continue ;;
        '') continue ;;
    esac
    for fd in "$d"/fd/*; do
        t=$(readlink "$fd" 2>/dev/null) || continue
        if printf '%s' "$t" | grep -Eq "$pat"; then
            echo "$pid $st $(cat "$d/comm" 2>/dev/null) ${fd##*/} -> $t"
            found=1
        fi
    done
done
[ "$found" = 1 ]
