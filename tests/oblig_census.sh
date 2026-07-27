#!/bin/bash
# oblig_census.sh — publication-obligation probe census across the fleet
# (ccloop c7ee71c6 sess18, D3 residual).
#
# The D3 residual is a PROTOCOL violation with a PROBABILISTIC observable:
# the release drain can report success while a committed inode-core change
# is still unlanded, and the loss only becomes visible when a peer happens
# to read the home location before some later opportunistic flush lands it.
# Green runs therefore prove nothing on their own (sess14-K: 116 P176 fires
# in a PASSING cache_coherency run).  Count the probes instead.
#
# Probes:
#   P176-OBLIGATION-OPEN         drain declaring success with pending!=durable
#     cls=INFLIGHT               image submitted, write not yet complete
#     cls=UNCOPIED               committed change never copied into an image
#                                (the real land-before-release violation)
#   P177-OBLIGATION-DROPPED-AT-ADOPT  reload adopted platter over an unlanded change
#   P146V-UNLANDED               clean-but-unlanded dinode, re-logging core
#   P31-RELFLUSH-SELF-SKIPPED    cluster flushed without this dinode
#   P26-IGET-FAIL                dirent resolves to a dead inode (loss symptom)
#
# Usage:  tests/oblig_census.sh [N]        (default 32)
#         tests/oblig_census.sh 32 save    (also dump matching lines to
#                                           tests/logs/oblig_<ts>/)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile)}"
N="${1:-32}"
SAVE="${2:-}"
DEST=""
if [ "$SAVE" = save ]; then
    DEST="$REPO/tests/logs/oblig_$(date -u +%Y%m%d_%H%M%S)"
    mkdir -p "$DEST"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for i in $(seq 1 "$N"); do
    (
        timeout 30 "$SSH" "test$i" "$PASS" 'dmesg' </dev/null 2>/dev/null \
            > "$tmp/test$i.dmesg"
        printf '%-7s P176=%-5s INFLIGHT=%-5s UNCOPIED=%-5s P177=%-4s P146V=%-4s P31skip=%-4s P26=%s\n' \
            "test$i" \
            "$(grep -c 'P176-OBLIGATION-OPEN'            "$tmp/test$i.dmesg")" \
            "$(grep -c 'P176-OBLIGATION-OPEN.*cls=INFLIGHT' "$tmp/test$i.dmesg")" \
            "$(grep -c 'P176-OBLIGATION-OPEN.*cls=UNCOPIED' "$tmp/test$i.dmesg")" \
            "$(grep -c 'P177-OBLIGATION-DROPPED'         "$tmp/test$i.dmesg")" \
            "$(grep -c 'P146V-UNLANDED'                  "$tmp/test$i.dmesg")" \
            "$(grep -c 'P31-RELFLUSH-SELF-SKIPPED'       "$tmp/test$i.dmesg")" \
            "$(grep -c 'P26-IGET-FAIL'                   "$tmp/test$i.dmesg")" \
            > "$tmp/test$i.row"
        if [ -n "$DEST" ]; then
            grep -E 'P176-OBLIGATION-OPEN|P177-OBLIGATION-DROPPED|P146V-UNLANDED|P31-RELFLUSH-SELF-SKIPPED|P26-IGET-FAIL' \
                "$tmp/test$i.dmesg" > "$DEST/test$i.probes" 2>/dev/null
        fi
    ) &
done
wait

for i in $(seq 1 "$N"); do cat "$tmp/test$i.row" 2>/dev/null; done | tee "$tmp/all.rows"

awk '{for(i=1;i<=NF;i++){n=index($i,"=");if(n){k=substr($i,1,n-1);v=substr($i,n+1)+0;s[k]+=v}}}
     END{printf "TOTAL   P176=%-5d INFLIGHT=%-5d UNCOPIED=%-5d P177=%-4d P146V=%-4d P31skip=%-4d P26=%d\n",
                s["P176"],s["INFLIGHT"],s["UNCOPIED"],s["P177"],s["P146V"],s["P31skip"],s["P26"]}' \
    "$tmp/all.rows" | tee "$tmp/total"

if [ -n "$DEST" ]; then
    cp "$tmp/all.rows" "$tmp/total" "$DEST/" 2>/dev/null
    echo "--- probe lines saved to $DEST"
fi

# NOTE: these counters come from pr_warn_ratelimited sites, so they are a
# LOWER BOUND on occurrences, never an exact count.  Absence of a probe in
# a 5s burst window is not absence of the event (a lesson that already cost
# one session a wrong conclusion — see CLAUDE.md standing lessons).
