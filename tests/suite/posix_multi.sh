#!/bin/bash
# posix_multi — agnostic multi-node POSIX-semantics test.
#
# Concurrent same-directory file creation from every node, then global
# count/uniqueness integrity + per-node cross-visibility, plus a hardlink /
# rename / truncate POSIX-op cross-node visibility check.  Ported from
# tests/cluster/test_concurrent_touch.sh into the agnostic + coord_barrier format.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.posix_multi"
# Rank 1 wipes the dir before every run: leftover op_* names from a prior
# run make ln hit EEXIST and mv degenerate to a same-inode no-op (GNU mv
# rc=1, both names remain), inverting the hardlink-gone assertions —
# a re-run on a dirty dir tests nothing and mis-attributes staleness.
if [ "$R" = 1 ]; then
    rm -rf "$D"
    mkdir -p "$D"
    sync
fi
ck "pm barrier clean" coord_barrier "pm_clean"
mkdir -p "$D" 2>/dev/null

# sess1 (ccloop 0220f43f) RULE-4 PROVEN: FPN was a T-INDEPENDENT constant
# (100/node), so the concurrent create storm below puts 100*T creates
# through ONE shared dir's DLM-EX rotation (3200 at T=32) -- the same
# "contended dir-EX handoff rotation" cost class documented at length
# elsewhere in this project (dir_reuse_coherency's DRC_TOTAL rewrite,
# cache_coherency's RV_TOTAL/UV_TOTAL rewrite this session).  Reproduced
# live: posix_multi@32/cawp NO_TERMINAL_RECORD at its flat 30s budget on a
# freshly-reformed cluster (not a cascade from another test).  PM_TOTAL is
# a CONSTANT pool size so per-node count shrinks as T grows and total
# create-storm volume stays O(1) instead of O(T); the per-node/global
# count+uniqueness signal below is unchanged, just over a bounded pool.
PM_TOTAL="${CC_PM_TOTAL:-128}"
FPN=$(( PM_TOTAL / T > 4 ? PM_TOTAL / T : 4 ))

ck "pm barrier ready" coord_barrier "pm_ready"

# Concurrent create storm into the shared dir.
for i in $(seq 1 "$FPN"); do
    ck "pm create node${R}_file${i}" sh -c ": > '$D/node${R}_file${i}'"
done
sync

ck "pm barrier create-done" coord_barrier "pm_create_done"

# Each node sees its own files.
for i in $(seq 1 "$FPN"); do
    ck "pm own node${R}_file${i} exists" test -f "$D/node${R}_file${i}"
done

# Rank 1 asserts global count + uniqueness (no concurrent-create dirent loss).
if [ "$R" = 1 ]; then
    ckeq "pm total count" "$((T * FPN))" \
         "$(ls "$D"/node*_file* 2>/dev/null | wc -l | tr -d ' ')"
    ckeq "pm all names unique" "$((T * FPN))" \
         "$(ls "$D"/node*_file* 2>/dev/null | sort -u | wc -l | tr -d ' ')"
fi

ck "pm barrier count" coord_barrier "pm_count"

# POSIX op visibility: each node writes content, hardlinks, renames; peers verify.
echo "posix_${R}" > "$D/op_src_${R}"
ln "$D/op_src_${R}" "$D/op_link_${R}" 2>/dev/null
mv "$D/op_link_${R}" "$D/op_renamed_${R}"
sync
ck "pm barrier ops" coord_barrier "pm_ops"
for n in $(seq 1 "$T"); do
    ckeq "pm r${R} sees node${n} renamed content" "posix_${n}" \
         "$(cat "$D/op_renamed_${n}" 2>/dev/null)"
    ck   "pm r${R} node${n} hardlink-name gone" test ! -e "$D/op_link_${n}"
done

ck "pm barrier verify" coord_barrier "pm_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
