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
#
# sess452: the test is READABLE, not merely non-empty.  A sudo'd sweep
# (mpath_up.sh at 21:44Z, sess451) left /tmp/.mxfs_pass owned by root:600;
# `-s` was still true for the unprivileged caller, sshpass 1.09 printed
# "Failed to open password file" to stderr and then HUNG on the password
# prompt — every fleet ssh from the session stalled to its timeout (chain 70
# prep: 300 s, zero output).  mxfs_secrets.sh now materializes a per-uid
# sibling when the default path belongs to another uid, and this wrapper
# refuses (exit 96) rather than hand sshpass a file it cannot open.
if [ ! -r "$PASSFILE" ] || [ ! -s "$PASSFILE" ]; then
    __ms="$(dirname "$0")/mxfs_secrets.sh"
    [ -x "$__ms" ] && PASSFILE="$("$__ms" passfile "$PASSFILE" 2>/dev/null || printf '%s' "$PASSFILE")"
fi
if [ ! -r "$PASSFILE" ] || [ ! -s "$PASSFILE" ]; then
    echo "mxfs_sshpass: password file $PASSFILE is not readable by uid $(id -u) — refusing; sshpass would hang on the prompt" >&2
    exit 96
fi

if [ "$1" = "SCP" ]; then
    shift
    SRC="$1"
    DST="$2"
    sshpass -f "$PASSFILE" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -r "$SRC" "root@${HOST}:${DST}"
else
    CMD="$*"
    sshpass -f "$PASSFILE" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "root@${HOST}" "$CMD"
    rc=$?
    # Opt-in status record (MXFS_RS_STATUS=1): when the invocation returned
    # non-zero — the remote command, ssh itself (255) or sshpass — append ONE
    # line on stdout so a capture taken through a helper that discards
    # stderr is never silently empty.  It reports the observed status and
    # nothing else (no command text: it could carry any string a parser
    # recognizes); it means "the invocation returned non-zero", never "MXFS
    # failed".  The status is preserved.  Opt-in, because a remote command
    # that legitimately exits non-zero (a grep with no match) would otherwise
    # gain a line its caller's parse does not expect; tests/lib/rig.sh's rsx
    # emits the same record for its own callers and keeps stderr in a file.
    if [ "$rc" != 0 ] && [ "${MXFS_RS_STATUS:-0}" = 1 ]; then
        printf '\nMXFS-RS-STATUS v=1 host=%s rc=%s\n' "$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_')" "$rc" | sed '/^$/d'
    fi
    exit "$rc"
fi
