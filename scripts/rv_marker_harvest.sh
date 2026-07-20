#!/bin/bash
# rv_marker_harvest.sh — aggregate the tear-formation / keeper-mechanism kernel
# markers across test1..testN for a UTC time window (ccloop 46efd8b6 sess1).
#
# Companion to diag_rv_replay.sh: after each replay phase, run this to see
# WHICH keep-stale mechanism fired on which node and WHEN the first
# INCONSISTENT-AT-RELEASE (P60-RELAUDIT) appeared — discriminating the
# candidate keepers of a stale dir layout:
#   P34F-RELOAD-SELFAHEAD-SKIP  whole-reload skip (own undestaged core mods)
#   P14-DESTAGE-THEN-RELOAD/P14-STUCK-ILI  the gap>=3 destage escape hatch
#   P58-SELFSKIP-STALE-DIR      sess36/58/59 self-skip kept stale dir base
#   P36-RELOAD-SELFSKIP         (gated mxfs.dirwr/instr) same, detail
#   P91-RELOAD-PROTECT          cluster buf kept (co-resident in-flight mods)
#   P-RELOAD-IDENTICAL          sess8 identical-skip (changecount equality)
#   P59-BMBT-EVICT / P67-BMBT-EVICT-SKIP  bmbt leaf evict vs kept-dirty (P67 gated)
#   P33-FROMDISK-DIRSHRINK / P62-RELOAD-FORK-SHRINK  shrinking adopts
#   P63-HANDOFF / P65-EPOCH-ADOPT  genuine handoff/epoch adopts (baseline rates)
#   P60-RELAUDIT ... INCONSISTENT-AT-RELEASE  the tear itself (leafsum != nx)
#
# Usage: rv_marker_harvest.sh <N> <since-UTC "YYYY-MM-DD HH:MM:SS"> [ino]
#   [ino] additionally reports counts restricted to "ino=<ino>" (the hot dir).
set -u
N="${1:?usage: rv_marker_harvest.sh <N> <since-utc> [ino]}"
SINCE="${2:?since-utc}"
INO="${3:-}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass

MARKERS='P60-RELAUDIT|P34F-RELOAD-SELFAHEAD-SKIP|P14-DESTAGE-THEN-RELOAD|P14-STUCK-ILI|P58-SELFSKIP-STALE-DIR|P36-RELOAD-SELFSKIP|P91-RELOAD-PROTECT|P-RELOAD-IDENTICAL|P59-BMBT-EVICT|P67-BMBT-EVICT-SKIP|P33-FROMDISK-DIRSHRINK|P62-RELOAD-FORK-SHRINK|P63-HANDOFF|P65-EPOCH-ADOPT|P68-PREEVICT'

tmpd=$(mktemp -d)
for r in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$r" "$PF" \
        "journalctl -k --since '$SINCE' --no-pager 2>/dev/null | grep -E 'mxfs: (${MARKERS})'" \
        2>/dev/null > "$tmpd/$r" ) &
done
wait

echo "=== marker counts per node (since $SINCE UTC) ==="
printf '%-7s %6s %6s %5s %5s %5s %5s %5s %6s %5s %5s %5s %5s %5s %5s %6s\n' \
    node RELAUD INCONS P34F P14D P14S P58 P36 P91 IDENT BMEV BMSK P33 P62 P63 P65
for r in $(seq 1 "$N"); do
    f="$tmpd/$r"
    [ -s "$f" ] || { printf '%-7s (no markers)\n' "test$r"; continue; }
    printf '%-7s %6s %6s %5s %5s %5s %5s %5s %6s %5s %5s %5s %5s %5s %5s %6s\n' "test$r" \
        "$(grep -c 'P60-RELAUDIT' "$f")" \
        "$(grep -c 'INCONSISTENT-AT-RELEASE' "$f")" \
        "$(grep -c 'P34F-RELOAD-SELFAHEAD-SKIP' "$f")" \
        "$(grep -c 'P14-DESTAGE-THEN-RELOAD' "$f")" \
        "$(grep -c 'P14-STUCK-ILI' "$f")" \
        "$(grep -c 'P58-SELFSKIP-STALE-DIR' "$f")" \
        "$(grep -c 'P36-RELOAD-SELFSKIP' "$f")" \
        "$(grep -c 'P91-RELOAD-PROTECT' "$f")" \
        "$(grep -c 'P-RELOAD-IDENTICAL' "$f")" \
        "$(grep -c 'P59-BMBT-EVICT' "$f")" \
        "$(grep -c 'P67-BMBT-EVICT-SKIP' "$f")" \
        "$(grep -c 'P33-FROMDISK-DIRSHRINK' "$f")" \
        "$(grep -c 'P62-RELOAD-FORK-SHRINK' "$f")" \
        "$(grep -c 'P63-HANDOFF' "$f")" \
        "$(grep -c 'P65-EPOCH-ADOPT' "$f")"
done

echo
echo "=== first INCONSISTENT-AT-RELEASE per node ==="
for r in $(seq 1 "$N"); do
    l=$(grep 'INCONSISTENT-AT-RELEASE' "$tmpd/$r" 2>/dev/null | head -1)
    [ -n "$l" ] && echo "test$r: $l"
done

if [ -n "$INO" ]; then
    echo
    echo "=== ino=$INO focused counts (RELAUDIT-INCONS / P34F / P58 / P91 / IDENT / P33 / P62) ==="
    for r in $(seq 1 "$N"); do
        f="$tmpd/$r"
        [ -s "$f" ] || continue
        g() { grep "$1" "$f" | grep -c "ino=$INO"; }
        printf '%-7s incons=%s p34f=%s p58=%s p91=%s ident=%s p33=%s p62=%s\n' "test$r" \
            "$(g INCONSISTENT-AT-RELEASE)" "$(g P34F-RELOAD-SELFAHEAD-SKIP)" \
            "$(g P58-SELFSKIP-STALE-DIR)" "$(g P91-RELOAD-PROTECT)" \
            "$(g P-RELOAD-IDENTICAL)" "$(g P33-FROMDISK-DIRSHRINK)" \
            "$(g P62-RELOAD-FORK-SHRINK)"
    done
    echo
    echo "=== ino=$INO event timeline (all nodes merged, first 60) ==="
    for r in $(seq 1 "$N"); do
        sed "s/^/test$r /" "$tmpd/$r" 2>/dev/null
    done | grep "ino=$INO" | sort -k2,3 | head -60
fi

rm -rf "$tmpd"
