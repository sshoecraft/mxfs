#!/bin/bash
# d0963_sf_dirent_resurrect.sh — does a node that removes its own entries from
# a shortform directory resurrect one of them on the next modification?
#
# D-PEER-STATS-A-NAME-THE-DELETER-UNLINKED-AND-SYNCED-WHILE-ITS-DIRECTORY-
# PUBLICATION-IS-IN-FLIGHT-0963.  Measured once on the 0.84.17 board
# (tests/evidence/run_cache_coherency_20260912T161757Z): test2 removed its 64
# files from the unlink_visibility directory while test1 removed its own; the
# directory went shortform during the loop; test2's fork was stale-gen (a peer
# had modified the directory and the re-acquire reload was skipped for its own
# undestaged modifications), so every removal took the P174-STALEGEN-ADOPT
# three-way merge, and the first merge whose inputs differed re-added the entry
# just removed (P-SFMERGE 146 -> 166 bytes, the name moving from first to last
# in the write lists).  The resurrected entry was published, named a freed
# inode, and the peer could still stat it from its cache.
#
# Hypothesis under test (H1): the merge's BASE is captured only from disk
# images, so an entry THIS node created, destaged and then removed is present in
# THEIRS (our own destaged image), absent from OURS and absent from BASE, and the
# merge classifies it as a peer's fresh add (P-SFM-READD) and puts it back.
#
# Shape (both nodes, the unlink_visibility phase without the barriers): in a
# fresh directory A creates N files and B creates N files (no sync anywhere),
# A lists the directory with stat (as rank1's pre-delete check does, so A caches
# B's inodes), then BOTH nodes remove their own N files CONCURRENTLY, sync, and
# both nodes verify: `ls -A` must be empty (a dangling dirent lists even though
# it does not resolve), no name may still stat, and with sfm_dbg=1 armed on both
# nodes no P-SFM-READD may name an entry of this directory.  Laps repeat with a
# fresh directory until a hit or LAPS; a hit keeps both nodes' kernel-log
# windows and the listing and stops.
#
# MEASURED 0 of 20 (s604a, 0.84.17) and the reason is the shape, not the
# hypothesis: the pre-mutation platter adopt is skipped on the node that
# CREATED the directory (A here; the capture's creator was the other node),
# and the deleter's fork must stay stale-gen through its loop, which needs its
# re-acquire to skip the rebuild (the capture: pinned by its own unlogged
# removals) — this harness's handoffs forced the log at each release, so B
# rebuilt.  The deterministic reproduction, with the same chain made explicit
# by test knobs, is tests/d0963_sf_lagging_flush.sh (0.84.18).  Kept as the
# record of the negative result.
#
# Usage: tests/d0963_sf_dirent_resurrect.sh <label> [LAPS=20] [N=64]
# Exit 0 = LAPS clean laps (H1 not reproduced), 1 = reproduced (a FAIL is the
# measurement this harness exists for), 2 = ABORT.  sfm_dbg is restored at the
# end and on abort.
#
# derived time budget: 2N creates ~1 s, one listing ~0.2 s, two concurrent
# N-removal loops 1-2 s (measured 0.15 s per 64 in the board capture, but the
# stale-gen adopt path reads the platter per removal), sync ~0.5 s, verify ~1 s,
# ssh dispatch ~2 s => ~7 s per lap at N=64; 20 laps = 140 s, bounded at 300 s.
set -u
LABEL=${1:?label}
LAPS=${2:-20}
N=${3:-64}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0963sfres_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" </dev/null 2>/dev/null | filt; }
fld() { echo "$1" | grep -ao "$2=[0-9]*" | head -1 | cut -d= -f2; }
restore() { for n in $A $B; do rs 20 "$n" "echo 0 > $P/sfm_dbg" >/dev/null; done; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0963_sf_dirent_resurrect label=$LABEL laps=$LAPS n=$N sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) k=\$(test -w $P/sfm_dbg && echo 1 || echo 0)" | tr -d '\n')
    echo "  INFO $n $st"
    [[ "$st" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV ($st)"; exit 2; }
    [[ "$st" == *"mnt=1"* ]]  || { echo "ABORT: $n not mounted ($st)"; exit 2; }
    [[ "$st" == *"k=1"* ]]    || { echo "ABORT: $n has no writable sfm_dbg knob"; exit 2; }
    rs 20 "$n" "echo 1 > $P/sfm_dbg" >/dev/null
done
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0963probe.$$ 2>&1 && rmdir $MNT/.d0963probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
[[ "$wprobe" == *WRITABLE* ]] && [[ "$wprobe" != *NOTWRITABLE* ]] || { echo "ABORT: $A mounted but not writable: $wprobe"; restore; exit 2; }

BASEDIR=$MNT/d0963_$LABEL
hit=""
for r in $(seq 1 "$LAPS"); do
    D=$BASEDIR/lap$r
    MK="D0963-$LABEL-$$-r$r"
    for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
    # create: A then B, each N files, no sync (both forks stay undestaged)
    ca=$(rs 60 "$A" "mkdir -p $D || exit 1; e=0; for i in \$(seq 1 $N); do echo x > $D/nodeA_file\$i 2>/dev/null || e=\$((e+1)); done; echo CA cerr=\$e")
    cb=$(rs 60 "$B" "e=0; for i in \$(seq 1 $N); do echo x > $D/nodeB_file\$i 2>/dev/null || e=\$((e+1)); done; echo CB cerr=\$e")
    # A stats everything (rank1's pre-delete check): A now caches B's inodes
    la=$(rs 40 "$A" "echo LA present=\$(ls $D/node*_file* 2>/dev/null | wc -l)")
    # both remove their own N concurrently, then sync
    rs 90 "$A" "e=0; for i in \$(seq 1 $N); do rm -f $D/nodeA_file\$i 2>/dev/null || e=\$((e+1)); done; sync; echo RA derr=\$e" > "$OUT/lap${r}_rmA.txt" &
    pa=$!
    rb_out=$(rs 90 "$B" "e=0; for i in \$(seq 1 $N); do rm -f $D/nodeB_file\$i 2>/dev/null || e=\$((e+1)); done; sync; echo RB derr=\$e")
    wait $pa
    ra=$(cat "$OUT/lap${r}_rmA.txt")
    # verify on both nodes: listing count (a dangling dirent LISTS), stats, and
    # the merge's own re-add lines in this lap's window
    v=""
    for n in $A $B; do
        vv=$(rs 60 "$n" "cnt=\$(ls -A $D 2>/dev/null | wc -l); names=\$(ls -A $D 2>/dev/null | head -4 | tr '\n' ' '); g=0; for f in \$(seq 1 $N); do test -e $D/nodeA_file\$f && g=\$((g+1)); test -e $D/nodeB_file\$f && g=\$((g+1)); done
            dmesg | awk '/$MK/{f=1} f' > /tmp/d0963_win.txt
            echo V node=$n listed=\$cnt ghost_stat=\$g readd=\$(grep -ac 'P-SFM-READD' /tmp/d0963_win.txt) drop=\$(grep -ac 'P-SFM-DROP' /tmp/d0963_win.txt) sfmerge=\$(grep -ac 'P-SFMERGE' /tmp/d0963_win.txt) stalermw=\$(grep -ac 'P-SFDIR-STALE-RMW' /tmp/d0963_win.txt) stalegen=\$(grep -ac 'P174-STALEGEN-ADOPT' /tmp/d0963_win.txt) selfahead=\$(grep -ac 'P34F-RELOAD-SELFAHEAD-SKIP' /tmp/d0963_win.txt) igetfail=\$(grep -ac 'P26-IGET-FAIL' /tmp/d0963_win.txt) names=[\$names]
            grep -a 'P-SFM-READD\|P-SFMERGE' /tmp/d0963_win.txt | head -4 | cut -c1-200")
        v="$v"$'\n'"$vv"
    done
    echo "  --- lap $r at +$(el)s: $ca $cb $la $ra $rb_out"
    echo "$v" | grep -a . | sed 's/^/     /'
    { echo "$ca"; echo "$cb"; echo "$la"; echo "$ra"; echo "$rb_out"; echo "$v"; } > "$OUT/lap$r.txt"
    [ "$(fld "$ca" cerr)" = 0 ] && [ "$(fld "$cb" cerr)" = 0 ] && [ "$(fld "$la" present)" = "$((2*N))" ] || { echo "ABORT: lap $r setup did not produce $((2*N)) files ($ca $cb $la)"; restore; exit 2; }
    listed=0; ghost=0; readd=0
    for n in $A $B; do
        line=$(echo "$v" | grep -a "^V node=$n")
        listed=$(( listed + $(fld "$line" listed) ))
        ghost=$(( ghost + $(fld "$line" ghost_stat) ))
        readd=$(( readd + $(fld "$line" readd) ))
    done
    if [ "$listed" != 0 ] || [ "$ghost" != 0 ] || [ "$readd" != 0 ]; then
        hit=r$r
        echo "  FAIL lap $r: listed=$listed ghost_stat=$ghost readd=$readd — a removed entry survived (H1 REPRODUCED)"
        for n in $A $B; do
            rs 60 "$n" "dmesg | awk '/$MK/{f=1} f'" > "$OUT/dmesg_${n}_lap$r.txt"
            rs 30 "$n" "ls -Ail $D 2>&1 | head -20" > "$OUT/listing_${n}_lap$r.txt"
        done
        break
    fi
    echo "  PASS lap $r: both nodes list 0, ghost_stat=0, readd=0"
done
restore
if [ -z "$hit" ]; then
    rs 120 "$A" "rm -rf $BASEDIR; sync -f $MNT" >/dev/null
    echo "=== d0963_sf_dirent_resurrect $LABEL: NOT REPRODUCED in $LAPS laps (H1 not supported by this shape) wall=$(el)s out=$OUT ==="
    exit 0
fi
echo "  NOTE the directory of the hit is LEFT IN PLACE for inspection ($BASEDIR/lap${hit#r}); remove it by hand or re-prep."
echo "=== d0963_sf_dirent_resurrect $LABEL: REPRODUCED at $hit wall=$(el)s out=$OUT ==="
exit 1
