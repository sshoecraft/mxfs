#!/bin/bash
# Minimal cross-node rename+read coherency reproducer.
# Writer node (W) creates N files with content in a SHARED dir (forcing
# block-format dir with --big), renames each, syncs, signals via a marker.
# Reader node (R) waits for the marker, then for each file reports:
#   size=<stat size>  content=<first line or EMPTY>
# This distinguishes a stale INODE (size=0) from a stale DATA block
# (size>0 but content empty).
#
# Usage: tests/repro_rename_xnode.sh <writer> <reader> [N] [big]
set -u
W=${1:-test2}
R=${2:-test1}
N=${3:-20}
BIG=${4:-big}     # 'big' => pre-populate dir with 200 filler entries (block fmt)
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
DIR="$MNT/.mxfs_test/rxnode"
SSH="tools/mxfs_sshpass.sh"

run() { local node=$1; shift; timeout 60 $SSH "$node" "$PASS" "$@" 2>/dev/null; }

# Reset dir from writer
run "$W" "rm -rf $DIR; mkdir -p $DIR; sync"
if [ "$BIG" = big ]; then
  run "$W" "for i in \$(seq 1 200); do : > $DIR/filler_\$i; done; sync"
fi

# Writer: create N files with content, barrier-marker, rename, sync, done-marker
run "$W" "
for i in \$(seq 1 $N); do echo content_\$i > $DIR/w_before_\$i; done
sync
for i in \$(seq 1 $N); do mv $DIR/w_before_\$i $DIR/w_after_\$i; done
sync
echo DONE > $DIR/.writer_done
sync
"

# Reader: wait for writer_done to appear, then read each file
run "$R" "
for t in \$(seq 1 60); do [ -f $DIR/.writer_done ] && break; sleep 0.5; done
sleep 2
miss=0; empty=0; ok=0; staledirent=0
for i in \$(seq 1 $N); do
  f=$DIR/w_after_\$i
  if [ ! -e \"\$f\" ]; then echo \"i=\$i DIRENT-MISSING\"; miss=\$((miss+1)); continue; fi
  sz=\$(stat -c %s \"\$f\" 2>/dev/null)
  c=\$(cat \"\$f\" 2>/dev/null)
  if [ \"\$c\" = \"content_\$i\" ]; then ok=\$((ok+1));
  elif [ -z \"\$c\" ]; then echo \"i=\$i EMPTY size=\$sz\"; empty=\$((empty+1));
  else echo \"i=\$i WRONG size=\$sz content=\$c\"; fi
done
echo \"RESULT reader=$R ok=\$ok empty=\$empty dirent_missing=\$miss\"
"
