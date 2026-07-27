#!/bin/bash
#
# Usage: mxfs_sshpass.sh <host> [passfile] <command...>
#        mxfs_sshpass.sh <host> [passfile] SCP <src> <dst>
#
# No TTY required — works in background/subagent contexts.
#
HOST="$1"
shift

# The passfile arg is OPTIONAL, and recognizing it must never be a guess.
# Callers that omitted it (`mxfs_sshpass.sh test1 "cat /sys/...; uptime"`) used to
# have the whole remote command taken as the passfile path; the missing-file branch
# below then handed that string to secrets_passfile, which mkdir -p'd dirname() of
# it and wrote the node password into a file named after the command.  That littered
# the source tree with command-shaped dirs holding the lab password (repo root and
# tests/, cleaned 2026-07-26).  A passfile is always an absolute path with no shell
# metacharacters; anything else is the command, and the default passfile applies.
PASSFILE=
case "${1:-}" in
    /*[[:space:]\;\|\&\<\>\$\(\)\'\"]*) ;;
    /*) PASSFILE="$1"; shift ;;
esac
[ -n "$PASSFILE" ] || PASSFILE=/tmp/.mxfs_pass

# Source of truth for the node password is ~/.config/mxfslab/secrets (resolved by
# tools/mxfs_secrets.sh). If the caller's passfile is missing/empty, materialize it
# from the secrets store — so every caller works without a password in the tree.
if [ ! -s "$PASSFILE" ]; then
    __ms="$(dirname "$0")/mxfs_secrets.sh"
    [ -x "$__ms" ] && PASSFILE="$("$__ms" passfile "$PASSFILE" 2>/dev/null || printf '%s' "$PASSFILE")"
fi

if [ "$1" = "SCP" ]; then
    shift
    SRC="$1"
    DST="$2"
    sshpass -f "$PASSFILE" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -r "$SRC" "root@${HOST}:${DST}"
else
    CMD="$*"
    sshpass -f "$PASSFILE" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "root@${HOST}" "$CMD"
fi
