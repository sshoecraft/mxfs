#!/bin/bash
# d0941_kmsg_verdict.sh — read one lap's per-node kmsg capture and say which of
# the reload's KEEP decisions fired, in the order the reload evaluates them.
#
# D-0941 is a peer's dirents staying visible across a barrier.  Every path that
# can produce it ends in the same place: mxfs_dlm_reload_inode decided to KEEP
# this node's in-core image instead of adopting the peer's.  There are four such
# decisions and each already prints, so the question is not "is there a probe"
# but "which of them fired, on which inode, in the failing lap".
#
#   P91-RELOAD-PROTECT          the cluster buffer carries this node's logged-
#                               but-uncheckpointed mods, so it was NOT staled
#                               and xfs_imap_to_bp cache-hits our own image.
#   P34E-FRESHSRC-SELFAHEAD-SKIP the private coherent re-read SUCCEEDED and was
#                               then rejected because our inode is pinned / has
#                               ili_fields / is in the AIL.  This line prints
#                               buf[size,nx] and fresh[size,nx] side by side —
#                               if they DIFFER, the image we refused was
#                               provably carrying state we do not have.
#   P3-REFUSE-OLDER-DISK        disk changecount below our in-core version, so
#                               the disk image was called a stale snapshot.
#   P-RELOAD-IDENTICAL          disk == in-core, keep the loaded fork.
#   P134-IDENTICAL-BUFSTALE     (0.75.98+) the identical verdict was issued on a
#                               buffer image that differs from the coherent
#                               medium.  Before 0.75.98 this compared only mode
#                               and gen and could not fire for a dirent change.
#
# And one layer down, on the dir DATA blocks rather than the inode core:
#   P68-EVDECIDE undurable=1    a cached dir block was KEPT (not evicted), so
#                               the lookup that follows reads our own base.
#
# Usage: tests/d0941_kmsg_verdict.sh <kmsg-file> [more...]
set -u
[ $# -ge 1 ] || { echo "usage: $0 <lapN_nodeX_kmsg.txt> [...]"; exit 2; }

for f in "$@"; do
    [ -r "$f" ] || { echo "== $f: UNREADABLE"; continue; }
    echo "== $f  ($(wc -l < "$f") lines)"
    for probe in P91-RELOAD-PROTECT P34E-FRESHSRC-SELFAHEAD-SKIP P3-REFUSE-OLDER-DISK \
                 P-RELOAD-IDENTICAL P134-IDENTICAL-BUFSTALE P127-DIRMISS \
                 P34D-RELOAD-FRESHSRC P36-RELOAD-SELFSKIP; do
        n=$(grep -ac -- "$probe" "$f")
        printf '   %-30s %s\n' "$probe" "$n"
    done
    printf '   %-30s %s\n' "P68-EVDECIDE undurable=1" \
        "$(grep -a 'P68-EVDECIDE' "$f" | grep -ac 'undurable=1')"

    # The SELFAHEAD line is the one that carries its own verdict: a refusal
    # where buf and fresh agree costs nothing, a refusal where they differ is
    # the loss.  Split them rather than reporting one count for both.
    same=0; diff=0
    while IFS= read -r l; do
        b=$(printf '%s' "$l" | sed -n 's/.*buf\[size=\([0-9-]*\) nx=\([0-9]*\)\].*/\1:\2/p')
        fr=$(printf '%s' "$l" | sed -n 's/.*fresh\[size=\([0-9-]*\) nx=\([0-9]*\)\].*/\1:\2/p')
        if [ -n "$b" ] && [ "$b" = "$fr" ]; then same=$((same+1)); else diff=$((diff+1)); fi
    done < <(grep -a 'P34E-FRESHSRC-SELFAHEAD-SKIP' "$f")
    echo "   SELFAHEAD refusals: buf==fresh=$same  buf!=fresh=$diff  <-- buf!=fresh is a refused newer image"
    grep -a 'P34E-FRESHSRC-SELFAHEAD-SKIP' "$f" | head -8 | sed 's/^/     /'
    grep -a 'P134-IDENTICAL-BUFSTALE' "$f" | head -8 | sed 's/^/     /'
done
