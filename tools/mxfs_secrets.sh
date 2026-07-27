#!/bin/bash
# mxfs_secrets.sh — resolve MXFS lab test credentials from the lab secrets store
# and materialize the sshpass passfile the harness authenticates with.
#
# SOURCE OF TRUTH: ~/.config/mxfslab/secrets  (override with $MXFS_SECRETS)
#   Format (one key per line):   <key> field=value field=value ...
#   The node SSH credential is:  node username=root password=<pw>
#
# Why: the harness SSHes into every node with `sshpass -f <passfile>`, which needs
# a file containing just the password. Rather than scatter that password across
# /tmp/.mxfs_pass etc., every script resolves it from ONE secrets file via this
# helper. The password never lives in the repo.
#
# Usage:
#   mxfs_secrets.sh get <key> [field]     # print a field (default: password)
#   mxfs_secrets.sh passfile [path]       # write node password to <path>
#                                         # (default /tmp/.mxfs_pass), print the path
set -u
MXFS_SECRETS="${MXFS_SECRETS:-$HOME/.config/mxfslab/secrets}"

secrets_get() {  # <key> <field>
    [ -r "$MXFS_SECRETS" ] || return 1
    awk -v k="$1" -v f="$2" '
        $1==k { for(i=2;i<=NF;i++){ n=index($i,"=");
                if(n && substr($i,1,n-1)==f){ print substr($i,n+1); found=1; exit } } }
        END { exit(found?0:1) }
    ' "$MXFS_SECRETS"
}

secrets_passfile() {  # [path]
    local path="${1:-/tmp/.mxfs_pass}" pw
    # Never materialize the password at a caller-supplied path that isn't a plain
    # absolute pathname.  A command string ("cat /sys/module/mxfs/x 2>/dev/null; uptime")
    # has a perfectly valid dirname(), so the mkdir -p below would happily build that
    # tree in $PWD and drop the password in it — which is how the repo accumulated
    # command-shaped directories full of the lab password.
    case "$path" in
        /*[[:space:]\;\|\&\<\>\$\(\)\'\"]*|[!/]*)
            echo "mxfs_secrets: refusing command-shaped passfile path: $path" >&2
            return 1 ;;
    esac
    pw=$(secrets_get node password) || return 1
    [ -n "$pw" ] || return 1
    mkdir -p "$(dirname "$path")" 2>/dev/null
    # only (re)write when the content differs — avoids churn and concurrent-write races
    if [ ! -s "$path" ] || [ "$(cat "$path" 2>/dev/null)" != "$pw" ]; then
        ( umask 077; printf '%s' "$pw" > "$path" )
    fi
    printf '%s\n' "$path"
}

case "${1:-passfile}" in
    get)      secrets_get "${2:?key}" "${3:-password}" ;;
    passfile) secrets_passfile "${2:-}" ;;
    *)        echo "usage: mxfs_secrets.sh {get <key> [field]|passfile [path]}" >&2; exit 2 ;;
esac
