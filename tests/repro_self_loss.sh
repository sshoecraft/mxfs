#!/bin/bash
# Deterministic "node loses its OWN data after a peer BAST" reproducer.
# W creates N files w/ content, renames, syncs.  R then stats every file
# (forcing a BAST -> W releases the file inodes).  Then W RE-READS its own
# files.  If W now sees empty content, the bast_process release
# (filemap_write_and_wait + invalidate_inode_pages2, or di_size flush)
# dropped W's not-yet-durable data.  No concurrency race — isolates the
# release-durability path.
# Usage: tests/repro_self_loss.sh [W] [R] [N] [reps]
set -u
cd "$(dirname "$0")/.."
W=${1:-test1}; R=${2:-test2}; N=${3:-20}; REPS=${4:-3}
PASS=/tmp/.mxfs_pass; MNT=/mnt/shared; SSH=tools/mxfs_sshpass.sh
run(){ local n=$1; shift; timeout 80 $SSH "$n" "$PASS" "$@" 2>/dev/null; }

for rep in $(seq 1 $REPS); do
  DIR="$MNT/.mxfs_test/selfloss_$rep"
  run "$W" "rm -rf $DIR; mkdir -p $DIR; sync"
  # W: create + rename + sync
  run "$W" "for i in \$(seq 1 $N); do echo content_\$i > $DIR/f_b_\$i; done; sync
            for i in \$(seq 1 $N); do mv $DIR/f_b_\$i $DIR/f_a_\$i; done; sync"
  # R: stat+read every file (forces BAST on W's dir + file inodes)
  run "$R" "for i in \$(seq 1 $N); do cat $DIR/f_a_\$i >/dev/null 2>&1; done"
  sleep 1
  # W: re-read its OWN files
  out=$(run "$W" "ok=0; empty=0; miss=0; el=''
    for i in \$(seq 1 $N); do
      f=$DIR/f_a_\$i
      [ -e \"\$f\" ] || { miss=\$((miss+1)); continue; }
      sz=\$(stat -c %s \"\$f\"); c=\$(cat \"\$f\" 2>/dev/null)
      if [ \"\$c\" = \"content_\$i\" ]; then ok=\$((ok+1));
      elif [ -z \"\$c\" ]; then empty=\$((empty+1)); el=\"\$el \$i:sz\$sz\"; fi
    done
    echo \"W-self rep=$rep ok=\$ok empty=\$empty miss=\$miss [\$el ]\"")
  echo "$out"
done
