#!/bin/bash
# repro_dirent_capture.sh — run concurrent same-dir create rounds until the
# first dirent loss, then CAPTURE decisive evidence to classify it:
#   - drop_caches + re-lookup: reappears => coherency (stale dir cache);
#                              still gone => durable on-disk dir lost-update.
#   - dir inode number, ls from creator vs observer, dmesg of the dir ino.
# (sess49 ccloop 14d31183)
# Usage: tests/repro_dirent_capture.sh [N] [MAXR]   (default N=16 MAXR=20)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
N=${1:-16}
MAXR=${2:-20}
PASS=/tmp/.mxfs_pass
SSH="$SCRIPT_DIR/../tools/mxfs_sshpass.sh"
MNT=/mnt/shared
s() { timeout 25 "$SSH" "test$1" "$PASS" "$2" 2>/dev/null; }

# clear dmesg on all nodes first
for n in $(seq 1 "$N"); do s "$n" 'dmesg -C >/dev/null 2>&1' & done; wait

for r in $(seq 1 "$MAXR"); do
    D="$MNT/.repro_cap/round$r"
    B="$MNT/.repro_cap/bar$r"
    s 1 "mkdir -p $D $B; sync"
    for n in $(seq 1 "$N"); do
        s "$n" "until [ -d $D ]; do sleep 0.05; done; echo hello_from_$n > $D/f_$n; sync; : > $B/done_$n" &
    done
    wait
    s 1 "for i in \$(seq 1 200); do c=\$(ls $B 2>/dev/null | grep -c done_); [ \"\$c\" -ge $N ] && break; sleep 0.1; done"
    # find a missing file from any node
    missnode=""; missk=""
    for n in $(seq 1 "$N"); do
        out=$(s "$n" "for k in \$(seq 1 $N); do [ ! -f $D/f_\$k ] && echo \$k; done")
        if [ -n "$out" ]; then missnode="$n"; missk=$(echo "$out" | head -1); break; fi
    done
    if [ -z "$missnode" ]; then echo "round $r: clean"; continue; fi

    echo "================ DIRENT LOSS at round $r ================"
    echo "observer node$missnode reports f_$missk MISSING (created by node$missk)"
    echo "--- dir inode (creator node$missk) ---"
    s "$missk" "stat -c 'dir ino=%i' $D; echo -n 'creator-sees-own-file: '; [ -f $D/f_$missk ] && echo YES || echo NO; stat -c 'file ino=%i size=%s' $D/f_$missk 2>&1 | head -1"
    echo "--- observer node$missnode view BEFORE drop_caches ---"
    s "$missnode" "stat -c 'dir ino=%i' $D; echo -n 'ls count: '; ls $D | grep -c '^f_'; echo -n 'f_$missk present: '; [ -f $D/f_$missk ] && echo YES || echo NO"
    echo "--- observer node$missnode AFTER echo 3 > drop_caches ---"
    s "$missnode" "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sync; echo -n 'f_$missk present: '; [ -f $D/f_$missk ] && echo YES-REAPPEARED || echo NO-STILL-GONE; echo -n 'ls count: '; ls $D | grep -c '^f_'"
    echo "--- creator node$missk AFTER drop_caches (durability check) ---"
    s "$missk" "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sync; echo -n 'creator f_$missk present: '; [ -f $D/f_$missk ] && echo YES || echo NO-DURABLE-LOSS"
    DIRINO=$(s "$missk" "stat -c %i $D" | tr -d '[:space:]')
    echo "--- dmesg (creator node$missk) mentioning dir ino=$DIRINO (hex/dec) ---"
    HEXINO=$(printf '%x' "$DIRINO" 2>/dev/null)
    s "$missk" "dmesg | grep -iE 'lost|clobber|DIR-STALE|dirent|removename|$DIRINO|$HEXINO|P-NOINO|EVICT|reload' | tail -25"
    echo "--- dmesg (observer node$missnode) ---"
    s "$missnode" "dmesg | grep -iE 'lost|clobber|DIR-STALE|dirent|$DIRINO|$HEXINO|reload|inval' | tail -20"
    echo "================ end capture ================"
    exit 0
done
echo "no loss in $MAXR rounds"
