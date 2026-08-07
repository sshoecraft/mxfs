#!/bin/bash
# mxfs_pgrep.sh — a `pgrep -f` replacement that cannot wedge on a stuck task.
#
# WHY THIS EXISTS (2026-08-07, clyde load 583, manual host reset required)
# ----------------------------------------------------------------------
# `pgrep -f PATTERN` matches against the full command line, so it opens
# /proc/<pid>/cmdline for EVERY process on the host.  Reading cmdline goes
# through __access_remote_vm and takes the target task's mmap_lock.
#
# If any task on the box wedges while holding its own mmap_lock, every
# subsequent `pgrep -f` (and every `ps -e`/`ps aux`) blocks there forever in
# UNINTERRUPTIBLE sleep.  SIGKILL does nothing.  Each stuck caller adds 1 to
# loadavg permanently.
#
# That is exactly what happened on 2026-08-04: a stuck bio on the MXFS fence
# device (dm-delay `mxfsfencef` over loop0) wedged `mount` in
# jbd2_write_superblock; ffmpeg then walked into the locked buffer folio via THP
# direct compaction and blocked holding its mmap_lock; from that moment every
# `pgrep -f` in tests/drc_autocapture.sh and tests/drc_progress_watch.sh hung on
# its FIRST call.  Each ccloop session launched another watcher, each watcher
# contributed one more unkillable task, and clyde reached loadavg 583 with ~580
# stuck ps/pgrep tasks.  Only a manual host reset cleared it.
#
# THE GUARD: read /proc/<pid>/stat first — it reports task state and never
# touches the target's mm — and skip any task in D (uninterruptible) state
# BEFORE opening cmdline.  A wedged task is always in D, so it is never read.
#
# Prefer a pidfile over pattern matching where you control the launcher.  Use
# this only where you must match somebody else's command line.
#
# Usage:  mxfs_pgrep.sh <extended-regex>
#         prints matching PIDs one per line; exit 0 if any matched, else 1.

set -u

pat="${1:?usage: mxfs_pgrep.sh <extended-regex>}"
self=$$
found=1

for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = "$self" ] && continue

    # /proc/<pid>/stat: "<pid> (comm) <state> ...".  comm can contain spaces and
    # parens, so strip through the LAST ") " to reach the state field.
    st=$(cat "$d/stat" 2>/dev/null) || continue
    st=${st##*') '}
    case "$st" in
        D*) continue ;;   # uninterruptible — reading cmdline could block forever
    esac

    cl=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
    [ -z "$cl" ] && continue

    if printf '%s' "$cl" | grep -qE -- "$pat"; then
        echo "$pid"
        found=0
    fi
done

exit $found
