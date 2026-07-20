#!/bin/bash
#
# Usage: mxfs_sshpass.sh <host> <passfile> <command...>
#        mxfs_sshpass.sh <host> <passfile> SCP <src> <dst>
#
# No TTY required — works in background/subagent contexts.
#
HOST="$1"
PASSFILE="$2"
shift 2

if [ "$1" = "SCP" ]; then
    shift
    SRC="$1"
    DST="$2"
    sshpass -f "$PASSFILE" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -r "$SRC" "root@${HOST}:${DST}"
else
    CMD="$*"
    sshpass -f "$PASSFILE" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "root@${HOST}" "$CMD"
fi
